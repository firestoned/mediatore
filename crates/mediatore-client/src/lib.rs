// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The user side of the one mediatore binary (ADR-0014): log in at the issuer as mediatore's
//! own public client and hand the session to mediatore with a claim (ADR-0013 decision 3).
//!
//! `login` runs the authorization-code flow with PKCE (RFC 7636) and a loopback redirect
//! (RFC 8252), then keeps the ID token and the refresh token in a session file. `claim`
//! posts `/v1/claims` with the ID token as bearer and the refresh token delegated in the
//! body, and forgets the refresh token: the issuer rotates it, so after mediatore's first
//! refresh the copy here would be dead anyway. A second claim is a second login.

pub mod cli;
pub mod delegate;
pub mod logs;

use std::path::{Path, PathBuf};

use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use mediatore_proto::{ClaimRequest, ClaimResponse, Secret};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// What `login` keeps and `claim` spends.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// The issuer logged in at.
    pub issuer: String,
    /// The client the tokens were issued to.
    pub client_id: String,
    /// Who logged in (`preferred_username`, or `sub`), for display.
    pub login: String,
    /// The ID token: the bearer for mediatore's user API, until `expires_at`.
    pub id_token: String,
    /// The refresh token, until it is delegated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// The ID token's `exp`, as seconds since the epoch.
    pub expires_at: i64,
}

impl Session {
    /// Where the session lives: `$XDG_CONFIG_HOME/mediatore/session.json`, or
    /// `~/.config/mediatore/session.json`.
    pub fn default_path() -> anyhow::Result<PathBuf> {
        let base = match std::env::var_os("XDG_CONFIG_HOME") {
            Some(dir) if !dir.is_empty() => PathBuf::from(dir),
            _ => {
                let home = std::env::var_os("HOME")
                    .ok_or_else(|| anyhow::anyhow!("neither XDG_CONFIG_HOME nor HOME is set"))?;
                PathBuf::from(home).join(".config")
            }
        };
        Ok(base.join("mediatore").join("session.json"))
    }

    /// Read the session at `path`.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("{}: {e} (run `mediatore login`)", path.display()))?;
        Ok(serde_json::from_str(&text)?)
    }

    /// Write the session at `path`, owner-readable only, whatever was there before: the
    /// text goes to a new file of mode 0600 beside it, which is then renamed over `path`. A
    /// file left there with wider permissions is replaced, not reused, and a symlink there
    /// is replaced, not followed. A directory this creates is 0700.
    ///
    /// # Errors
    /// The directory or the file cannot be written.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let text = serde_json::to_string_pretty(self)?;
        #[cfg(unix)]
        write_owner_only(path, text.as_bytes())?;
        #[cfg(not(unix))]
        {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            std::fs::write(path, text)?;
        }
        Ok(())
    }

    /// True while the ID token is good for at least `margin_secs` more seconds.
    #[must_use]
    pub fn is_fresh(&self, margin_secs: i64) -> bool {
        self.expires_at - margin_secs > now_unix()
    }
}

/// Mode of the session file: its owner alone.
#[cfg(unix)]
const SESSION_FILE_MODE: u32 = 0o600;
/// Mode of a directory `save` creates for it.
#[cfg(unix)]
const SESSION_DIR_MODE: u32 = 0o700;

/// Put `bytes` at `path` through a temporary file in the same directory, created new (so
/// never an existing file or a symlink) with [`SESSION_FILE_MODE`], then renamed over
/// `path`. Missing directories are created with [`SESSION_DIR_MODE`]; one that exists keeps
/// its mode.
#[cfg(unix)]
fn write_owner_only(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};

    let name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("{}: not a file path", path.display()))?;
    let dir = match path.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(SESSION_DIR_MODE)
        .create(dir)
        .map_err(|e| anyhow::anyhow!("{}: {e}", dir.display()))?;
    let mut tmp_name = std::ffi::OsString::from(".");
    tmp_name.push(name);
    tmp_name.push(format!(".{}.tmp", random_token()?));
    let tmp = dir.join(tmp_name);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(SESSION_FILE_MODE)
        .open(&tmp)
        .map_err(|e| anyhow::anyhow!("{}: {e}", tmp.display()))?;
    let written = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .and_then(|()| std::fs::rename(&tmp, path));
    drop(file);
    if let Err(e) = written {
        // The temporary file is this call's own: do not leave a copy of the session behind.
        let _ = std::fs::remove_file(&tmp);
        anyhow::bail!("{}: {e}", path.display());
    }
    Ok(())
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// How to log in.
#[derive(Debug, Clone)]
pub struct LoginOptions {
    /// The OIDC issuer (`iss`), byte-for-byte as mediatore's config has it.
    pub issuer: String,
    /// The public client to log in as: mediatore's own.
    pub client_id: String,
    /// Scopes to request; `offline_access` is what yields the refresh token at Dex, Auth0
    /// and Entra. Google takes no such scope (see `extra_params`).
    pub scopes: Vec<String>,
    /// Extra query parameters on the authorization request, per issuer (ADR-0017):
    /// `access_type=offline` and `prompt=consent` for Google, `audience=...` for Auth0.
    pub extra_params: Vec<(String, String)>,
    /// A client secret the token endpoint wants even from this public client (Google's
    /// installed-app clients). Not a credential anyone relies on; never stored in the
    /// session file.
    pub client_secret: Option<String>,
    /// A login hint for the issuer, if any.
    pub login_hint: Option<String>,
    /// CA certificates (PEM) that sign the issuer's TLS certificate, for an issuer on a
    /// private PKI; when set, exactly those are trusted and not the public roots.
    pub ca_pem: Option<Vec<u8>>,
    /// Where the loopback listener the issuer redirects back to lives.
    pub redirect: Redirect,
}

/// The loopback redirect of a login.
///
/// Some issuers match a public client's redirect URIs exactly (Dex does), so a port the OS
/// picks at random cannot be registered. `ports` names the ones to try, in order; empty
/// means a port the OS chooses, which suits an issuer that accepts any loopback port. The
/// listener always binds `127.0.0.1`; `host` is only what the redirect URI says (`localhost`
/// when that is what the issuer has registered).
#[derive(Debug, Clone)]
pub struct Redirect {
    /// The host in the redirect URI.
    pub host: String,
    /// Fixed ports, tried in order; empty means one the OS chooses.
    pub ports: Vec<u16>,
    /// What follows the port in the redirect URI, `/callback` or empty. The listener
    /// answers any path.
    pub path: String,
}

impl Default for Redirect {
    /// A port the OS chooses at `http://127.0.0.1:<port>/callback`.
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            ports: vec![],
            path: "/callback".into(),
        }
    }
}

/// Bind the loopback listener for `redirect` and return it with the redirect URI to send.
async fn bind_loopback(redirect: &Redirect) -> anyhow::Result<(tokio::net::TcpListener, String)> {
    let uri = |port: u16| format!("http://{}:{port}{}", redirect.host, redirect.path);
    if redirect.ports.is_empty() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        return Ok((listener, uri(port)));
    }
    for &port in &redirect.ports {
        match tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
            Ok(listener) => return Ok((listener, uri(port))),
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {}
            Err(e) => return Err(anyhow::anyhow!("binding 127.0.0.1:{port}: {e}")),
        }
    }
    let ports: Vec<String> = redirect.ports.iter().map(ToString::to_string).collect();
    anyhow::bail!(
        "none of the redirect ports ({}) is free on 127.0.0.1: is another login running?",
        ports.join(", ")
    )
}

impl LoginOptions {
    /// The scopes ADR-0013 names.
    #[must_use]
    pub fn default_scopes() -> Vec<String> {
        ["openid", "profile", "email", "groups", "offline_access"]
            .into_iter()
            .map(ToOwned::to_owned)
            .collect()
    }
}

#[derive(Deserialize)]
struct Discovery {
    authorization_endpoint: String,
    token_endpoint: String,
}

#[derive(Deserialize)]
struct TokenReply {
    id_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
}

/// How long a connection to the broker or the issuer may take to open. There is no limit on
/// the whole request: `logs --follow` holds one answer open for as long as the claim runs.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

fn http() -> anyhow::Result<reqwest::Client> {
    mediatore_proto::tls::ensure_provider();
    Ok(reqwest::Client::builder()
        .tls_backend_preconfigured(mediatore_proto::tls::https_client_config())
        .connect_timeout(CONNECT_TIMEOUT)
        .build()?)
}

/// An HTTPS client trusting exactly the CA certificates in `pem`.
fn http_with_ca(pem: &[u8]) -> anyhow::Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .tls_backend_preconfigured(mediatore_proto::tls::https_client_config_with_ca(pem)?)
        .connect_timeout(CONNECT_TIMEOUT)
        .build()?)
}

fn random_token() -> anyhow::Result<String> {
    let mut bytes = [0u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("no randomness"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// The unverified payload of a JWT, for display and expiry only; mediatore verifies.
fn payload(token: &str) -> anyhow::Result<serde_json::Value> {
    let part = token
        .split('.')
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("not a JWT"))?;
    Ok(serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part)?)?)
}

/// Percent-encode a query value (RFC 3986 unreserved characters pass through).
fn encode(s: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(char::from(b));
            }
            _ => {
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

fn decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(v);
                    i += 3;
                    continue;
                }
                out.push(b'%');
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Accept one `GET /callback?code=...&state=...` on `listener`, answer it, and return the
/// code and state.
async fn accept_callback(listener: tokio::net::TcpListener) -> anyhow::Result<(String, String)> {
    let (mut stream, _) = listener.accept().await?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 64 * 1024 {
            break;
        }
    }
    let head = String::from_utf8_lossy(&buf);
    let line = head.lines().next().unwrap_or_default();
    let target = line.split_whitespace().nth(1).unwrap_or_default();
    let query = target.split_once('?').map_or("", |(_, q)| q);
    let mut code = None;
    let mut state = None;
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        match k {
            "code" => code = Some(decode(v)),
            "state" => state = Some(decode(v)),
            _ => {}
        }
    }
    let (status, body) = if code.is_some() {
        ("200 OK", "<p>Logged in. You can close this window.</p>")
    } else {
        ("400 Bad Request", "<p>No code in the callback.</p>")
    };
    let reply = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(reply.as_bytes()).await?;
    stream.shutdown().await.ok();
    Ok((
        code.ok_or_else(|| anyhow::anyhow!("the callback carried no code"))?,
        state.unwrap_or_default(),
    ))
}

/// Log in: discovery, PKCE, the loopback listener, the browser (through `open_url`, which
/// gets the authorization URL), the code exchange. Returns the session, unsaved.
pub async fn login(opts: &LoginOptions, open_url: impl FnOnce(&str)) -> anyhow::Result<Session> {
    let http = match &opts.ca_pem {
        Some(pem) => http_with_ca(pem)?,
        None => http()?,
    };
    let discovery: Discovery = http
        .get(format!(
            "{}/.well-known/openid-configuration",
            opts.issuer.trim_end_matches('/')
        ))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let verifier = random_token()?;
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    let state = random_token()?;
    let (listener, redirect_uri) = bind_loopback(&opts.redirect).await?;

    let mut url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
        discovery.authorization_endpoint,
        encode(&opts.client_id),
        encode(&redirect_uri),
        encode(&opts.scopes.join(" ")),
        encode(&state),
        encode(&challenge),
    );
    {
        use std::fmt::Write as _;
        if let Some(hint) = &opts.login_hint {
            let _ = write!(url, "&login_hint={}", encode(hint));
        }
        for (k, v) in &opts.extra_params {
            let _ = write!(url, "&{}={}", encode(k), encode(v));
        }
    }
    let callback = tokio::spawn(accept_callback(listener));
    open_url(&url);
    let (code, returned_state) = callback.await??;
    anyhow::ensure!(
        returned_state == state,
        "the callback's state does not match"
    );

    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code.as_str()),
        ("redirect_uri", redirect_uri.as_str()),
        ("client_id", opts.client_id.as_str()),
        ("code_verifier", verifier.as_str()),
    ];
    if let Some(secret) = &opts.client_secret {
        form.push(("client_secret", secret.as_str()));
    }
    let reply: TokenReply = http
        .post(&discovery.token_endpoint)
        .form(&form)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let claims = payload(&reply.id_token)?;
    let login = ["preferred_username", "email", "sub"]
        .iter()
        .find_map(|k| claims.get(*k).and_then(|v| v.as_str()))
        .unwrap_or("?")
        .to_owned();
    let expires_at = claims
        .get("exp")
        .and_then(serde_json::Value::as_i64)
        .unwrap_or(0);
    Ok(Session {
        issuer: opts.issuer.clone(),
        client_id: opts.client_id.clone(),
        login,
        id_token: reply.id_token,
        refresh_token: reply.refresh_token,
        expires_at,
    })
}

/// The user API's base URL as the client keeps it (no trailing `/`), once it is fit to carry
/// a credential: `https`, or `http` to this machine only (`localhost`, or a loopback address
/// such as `127.0.0.1` or `[::1]`), which is what a local run and the tests use. Every request
/// carries the ID token as its bearer and a claim carries the refresh token, so anything else
/// would put both on the network in the clear.
///
/// # Errors
/// Not a URL, or a scheme and host that are neither of those. The message names the scheme
/// and the host only, never the whole URL (it may hold userinfo).
fn checked_base(base: &str) -> anyhow::Result<String> {
    let url = reqwest::Url::parse(base)
        .map_err(|e| anyhow::anyhow!("--mediatore is not a URL ({e}); expected https://<host>"))?;
    let host = url.host_str().unwrap_or_default();
    let unbracketed = host.trim_start_matches('[').trim_end_matches(']');
    let loopback = unbracketed.eq_ignore_ascii_case("localhost")
        || unbracketed
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    let scheme = url.scheme();
    if scheme != "https" && !(scheme == "http" && loopback) {
        anyhow::bail!(
            "--mediatore {scheme}://{host} is refused: the ID token and the delegated refresh token are only sent over https (plain http is accepted for localhost and loopback addresses only)"
        );
    }
    Ok(base.trim_end_matches('/').to_owned())
}

/// mediatore's user API.
pub struct Api {
    base: String,
    http: reqwest::Client,
}

impl Api {
    /// A client for the user API at `base` (`https://mediatore.example`).
    ///
    /// # Errors
    /// A `base` that is not `https` and not on this machine ([`checked_base`]).
    pub fn new(base: &str) -> anyhow::Result<Self> {
        Ok(Self {
            base: checked_base(base)?,
            http: http()?,
        })
    }

    /// A client for the user API at `base` that trusts exactly the CA certificates in
    /// `pem` (a broker behind a private PKI).
    ///
    /// # Errors
    /// A `base` that is not `https` and not on this machine ([`checked_base`]), or a `pem`
    /// that holds no certificate.
    pub fn with_ca(base: &str, pem: &[u8]) -> anyhow::Result<Self> {
        Ok(Self {
            base: checked_base(base)?,
            http: http_with_ca(pem)?,
        })
    }

    /// A client for a user API served over plain `http` on another host: a test cluster
    /// whose user listener has no TLS in front of it. The ID token and anything delegated
    /// cross that hop in clear, so this is never a default and never taken from the URL
    /// alone: the caller asked for it by name (`--allow-plain-http`).
    ///
    /// # Errors
    /// A `base` that is not an `http` or `https` URL.
    pub fn plain_http(base: &str) -> anyhow::Result<Self> {
        let url = reqwest::Url::parse(base).map_err(|e| {
            anyhow::anyhow!("--mediatore is not a URL ({e}); expected http://<host>")
        })?;
        anyhow::ensure!(
            matches!(url.scheme(), "http" | "https"),
            "--mediatore must be an http or https URL"
        );
        Ok(Self {
            base: base.trim_end_matches('/').to_owned(),
            http: http()?,
        })
    }

    fn claim_url(&self, name: &str, namespace: Option<&str>) -> String {
        let base = format!("{}/v1/claims/{name}", self.base);
        match namespace {
            Some(ns) => format!("{base}?namespace={}", encode(ns)),
            None => base,
        }
    }

    /// `POST /v1/claims` with the session's ID token as bearer and its refresh token
    /// delegated in the body. On success the refresh token is spent: the session comes
    /// back without it.
    pub async fn claim(
        &self,
        session: &Session,
        request: &ClaimRequest,
    ) -> anyhow::Result<(ClaimResponse, Session)> {
        let mut request = request.clone();
        request.refresh_token = session.refresh_token.clone().map(Secret);
        let resp = self
            .http
            .post(format!("{}/v1/claims", self.base))
            .bearer_auth(&session.id_token)
            .json(&request)
            .send()
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!(
                "mediatore: {} {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            );
        }
        let claim: ClaimResponse = resp.json().await?;
        let mut spent = session.clone();
        spent.refresh_token = None;
        Ok((claim, spent))
    }

    /// `GET /v1/claims/{name}`, with `?namespace=` when one is given (ADR-0046 decision 5);
    /// without it nothing is sent and the broker's answer decides.
    pub async fn get(
        &self,
        session: &Session,
        name: &str,
        namespace: Option<&str>,
    ) -> anyhow::Result<ClaimResponse> {
        let resp = self
            .http
            .get(self.claim_url(name, namespace))
            .bearer_auth(&session.id_token)
            .send()
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!(
                "mediatore: {} {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            );
        }
        Ok(resp.json().await?)
    }

    /// `GET /v1/claims/{name}/logs` (ADR-0045 decision 9): the workload's stored output as
    /// NDJSON, to be read with [`logs::print_response`]. `?namespace=` as [`Self::get`]
    /// sends it; `follow` only when true, `since` and `tail` only when given.
    ///
    /// # Errors
    /// The request failing, or a non-success status (`501` when the broker stores no output,
    /// `403` another subject's claim, `404` no such claim), with the broker's body.
    pub async fn logs(
        &self,
        session: &Session,
        name: &str,
        namespace: Option<&str>,
        query: &logs::LogsQuery,
    ) -> anyhow::Result<reqwest::Response> {
        let mut url = format!("{}/v1/claims/{name}/logs", self.base);
        let mut params = vec![query.to_query()];
        if let Some(ns) = namespace {
            params.push(format!("namespace={}", encode(ns)));
        }
        let params: Vec<String> = params.into_iter().filter(|p| !p.is_empty()).collect();
        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }
        let resp = self
            .http
            .get(url)
            .bearer_auth(&session.id_token)
            .send()
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!(
                "mediatore: {} {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            );
        }
        Ok(resp)
    }

    /// `DELETE /v1/claims/{name}`, with `?namespace=` when one is given (ADR-0046 decision 5).
    pub async fn delete(
        &self,
        session: &Session,
        name: &str,
        namespace: Option<&str>,
    ) -> anyhow::Result<()> {
        let resp = self
            .http
            .delete(self.claim_url(name, namespace))
            .bearer_auth(&session.id_token)
            .send()
            .await?;
        if !resp.status().is_success() {
            anyhow::bail!(
                "mediatore: {} {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use mediatore_testkit::FakeIdp;

    use super::*;

    fn opts(idp: &FakeIdp) -> LoginOptions {
        LoginOptions {
            issuer: idp.issuer.clone(),
            client_id: "mediatore".into(),
            scopes: LoginOptions::default_scopes(),
            extra_params: vec![],
            client_secret: None,
            login_hint: Some("hexley".into()),
            ca_pem: None,
            redirect: Redirect::default(),
        }
    }

    /// The "browser": follows the authorization URL to the issuer, which redirects to the
    /// CLI's loopback listener.
    fn browser(url: &str) {
        let url = url.to_owned();
        tokio::spawn(async move {
            reqwest::Client::new().get(url).send().await.unwrap();
        });
    }

    #[tokio::test]
    async fn login_completes_the_pkce_flow_and_keeps_a_live_refresh_token() {
        let idp = FakeIdp::start().await;
        let session = login(&opts(&idp), browser).await.unwrap();
        assert_eq!(session.login, "hexley");
        assert_eq!(session.client_id, "mediatore");
        assert!(session.is_fresh(60));
        let claims = payload(&session.id_token).unwrap();
        assert_eq!(claims["aud"], "mediatore");
        assert!(idp.is_live(session.refresh_token.as_deref().unwrap()));
    }

    #[tokio::test]
    async fn the_extra_parameters_and_the_client_secret_reach_the_issuer() {
        use mediatore_testkit::Profile;
        // Google's shape: the refresh token needs access_type=offline, the token
        // endpoint the installed-app secret, and offline_access is not a scope it knows.
        let idp = FakeIdp::start_as(Profile::Google).await;
        idp.set_client_secret("mediatore", "GOCSPX-not-a-secret");
        let google =
            |extra: Vec<(&str, &str)>, secret: Option<&str>, scopes: &[&str]| LoginOptions {
                scopes: scopes.iter().map(|s| (*s).to_owned()).collect(),
                extra_params: extra
                    .into_iter()
                    .map(|(k, v)| (k.to_owned(), v.to_owned()))
                    .collect(),
                client_secret: secret.map(ToOwned::to_owned),
                ..opts(&idp)
            };
        let session = login(
            &google(
                vec![("access_type", "offline"), ("prompt", "consent")],
                Some("GOCSPX-not-a-secret"),
                &["openid", "email"],
            ),
            browser,
        )
        .await
        .unwrap();
        assert_eq!(
            session.login, "hexley@example.com",
            "email, Google has no username"
        );
        assert!(session.refresh_token.is_some());
        let session = login(
            &google(vec![], Some("GOCSPX-not-a-secret"), &["openid", "email"]),
            browser,
        )
        .await
        .unwrap();
        assert!(session.refresh_token.is_none(), "no access_type=offline");
        assert!(
            login(&google(vec![], None, &["openid", "email"]), browser)
                .await
                .is_err(),
            "the secret is required"
        );
        assert!(
            login(
                &google(
                    vec![],
                    Some("GOCSPX-not-a-secret"),
                    &["openid", "offline_access"]
                ),
                browser
            )
            .await
            .is_err(),
            "offline_access is not a Google scope"
        );
    }

    /// A port nothing listens on right now.
    fn free_port() -> u16 {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn fixed(ports: Vec<u16>) -> Redirect {
        Redirect {
            host: "localhost".into(),
            ports,
            path: String::new(),
        }
    }

    #[tokio::test]
    async fn a_fixed_redirect_uses_the_first_free_port_and_names_it_without_a_path() {
        let (busy, free) = (free_port(), free_port());
        let _hold = tokio::net::TcpListener::bind(("127.0.0.1", busy))
            .await
            .unwrap();
        let (_listener, uri) = bind_loopback(&fixed(vec![busy, free])).await.unwrap();
        assert_eq!(uri, format!("http://localhost:{free}"));
    }

    #[tokio::test]
    async fn a_fixed_redirect_with_every_port_busy_says_which() {
        let (a, b) = (free_port(), free_port());
        let _ha = tokio::net::TcpListener::bind(("127.0.0.1", a))
            .await
            .unwrap();
        let _hb = tokio::net::TcpListener::bind(("127.0.0.1", b))
            .await
            .unwrap();
        let err = bind_loopback(&fixed(vec![a, b])).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(&a.to_string()) && msg.contains(&b.to_string()),
            "{msg}"
        );
    }

    #[tokio::test]
    async fn the_default_redirect_keeps_a_port_the_os_chooses_and_the_callback_path() {
        let (_listener, uri) = bind_loopback(&Redirect::default()).await.unwrap();
        assert!(uri.starts_with("http://127.0.0.1:"), "{uri}");
        assert!(uri.ends_with("/callback"), "{uri}");
    }

    #[tokio::test]
    async fn login_on_a_fixed_redirect_sends_exactly_that_uri_and_completes() {
        let idp = FakeIdp::start().await;
        let port = free_port();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(String::new()));
        let seen_in = seen.clone();
        let session = login(
            &LoginOptions {
                redirect: fixed(vec![port]),
                ..opts(&idp)
            },
            move |url: &str| {
                *seen_in.lock().unwrap() = url.to_owned();
                browser(url);
            },
        )
        .await
        .unwrap();
        assert_eq!(session.login, "hexley");
        let url = seen.lock().unwrap().clone();
        assert!(
            url.contains(&format!("redirect_uri=http%3A%2F%2Flocalhost%3A{port}&")),
            "{url}"
        );
    }

    #[tokio::test]
    async fn a_callback_with_another_state_is_refused() {
        let idp = FakeIdp::start().await;
        let tampered = |url: &str| {
            // Replace the state the CLI chose with another before the issuer sees it.
            let url = url.to_owned();
            tokio::spawn(async move {
                let at = url.find("&state=").unwrap();
                let end = url[at + 7..].find('&').map_or(url.len(), |e| at + 7 + e);
                let forged = format!("{}&state=forged{}", &url[..at], &url[end..]);
                reqwest::Client::new().get(forged).send().await.unwrap();
            });
        };
        let err = login(&opts(&idp), tampered).await.unwrap_err();
        assert!(err.to_string().contains("state"), "{err}");
    }

    fn sample_session() -> Session {
        Session {
            issuer: "https://dex.home.example".into(),
            client_id: "mediatore".into(),
            login: "octocat".into(),
            id_token: "a.b.c".into(),
            refresh_token: Some("rt".into()),
            expires_at: 0,
        }
    }

    /// A directory of this test's own, not yet created.
    fn scratch_dir() -> PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target-test")
            .join(uuid::Uuid::new_v4().to_string())
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::symlink_metadata(path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    }

    // ----- the session file (red-team review 2026-11-19, A minor) -----

    #[cfg(unix)]
    #[test]
    fn a_session_file_left_world_readable_ends_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = scratch_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("session.json");
        std::fs::write(&path, "{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(mode_of(&path), 0o644);

        sample_session().save(&path).unwrap();
        assert_eq!(mode_of(&path), 0o600, "the old file's mode was kept");
        assert_eq!(Session::load(&path).unwrap().login, "octocat");
        // Saved again over its own file, and no temporary file is left beside it.
        sample_session().save(&path).unwrap();
        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_at_the_session_path_is_replaced_not_followed() {
        let dir = scratch_dir();
        std::fs::create_dir_all(&dir).unwrap();
        let elsewhere = dir.join("elsewhere.txt");
        std::fs::write(&elsewhere, "not a session").unwrap();
        let path = dir.join("session.json");
        std::os::unix::fs::symlink(&elsewhere, &path).unwrap();

        sample_session().save(&path).unwrap();
        let meta = std::fs::symlink_metadata(&path).unwrap();
        assert!(meta.file_type().is_file(), "the symlink is still there");
        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(
            std::fs::read_to_string(&elsewhere).unwrap(),
            "not a session",
            "the session was written through the symlink"
        );
        assert_eq!(Session::load(&path).unwrap().login, "octocat");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn a_directory_the_save_creates_is_the_owners_alone() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = scratch_dir();
        let path = dir.join("mediatore").join("session.json");
        sample_session().save(&path).unwrap();
        assert_eq!(mode_of(&dir.join("mediatore")), 0o700);
        assert_eq!(mode_of(&path), 0o600);

        // One that exists keeps its mode: it is not the CLI's to change.
        let shared = dir.join("shared");
        std::fs::create_dir_all(&shared).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755)).unwrap();
        sample_session().save(&shared.join("session.json")).unwrap();
        assert_eq!(mode_of(&shared), 0o755);
        assert_eq!(mode_of(&shared.join("session.json")), 0o600);
        std::fs::remove_dir_all(&dir).ok();
    }

    // ----- where the credentials may go (red-team review 2026-11-19, A minor) -----

    #[test]
    fn a_broker_url_that_is_not_https_is_refused_unless_it_is_this_machine() {
        for ok in [
            "https://mediatore.example",
            "https://mediatore.example:8443/",
            "https://192.0.2.10",
            "http://127.0.0.1:8080",
            "http://127.0.0.1:8080/",
            "http://localhost:8080",
            "http://LOCALHOST",
            "http://[::1]:8080",
        ] {
            let base = checked_base(ok).unwrap();
            assert_eq!(base, ok.trim_end_matches('/'));
            assert!(Api::new(ok).is_ok(), "{ok}");
        }
        for refused in [
            "http://mediatore.example",
            "http://192.0.2.10:8080",
            "http://localhost.example.com",
            "http://127.0.0.1.example.com",
            "http://[2001:db8::1]:8080",
            "ftp://localhost",
            "mediatore.example",
            "",
        ] {
            assert!(checked_base(refused).is_err(), "{refused:?} was accepted");
            assert!(Api::new(refused).is_err(), "{refused:?} was accepted");
            // Refused before the CA is even read.
            assert!(Api::with_ca(refused, b"").is_err(), "{refused:?}");
        }
        let e = checked_base("http://octocat@mediatore.example/x")
            .unwrap_err()
            .to_string();
        assert!(e.contains("https"), "{e}");
        assert!(e.contains("http://mediatore.example"), "{e}");
        assert!(!e.contains("octocat"), "the message carries the userinfo");
    }

    #[tokio::test]
    async fn the_session_file_round_trips_owner_only() {
        let dir = scratch_dir();
        let path = dir.join("session.json");
        let s = sample_session();
        s.save(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let back = Session::load(&path).unwrap();
        assert_eq!(back.login, "octocat");
        assert_eq!(back.refresh_token.as_deref(), Some("rt"));
        assert!(!back.is_fresh(0));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn query_encoding_round_trips() {
        let raw = "a b&c=d/é~";
        assert_eq!(decode(&encode(raw)), raw);
        assert_eq!(encode("abc-._~"), "abc-._~");
    }
}
