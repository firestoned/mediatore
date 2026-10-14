// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! mediatore-cli: log in at the issuer as mediatore's own public client and hand the
//! session to mediatore with a claim (ADR-0013 decision 3).
//!
//! `login` runs the authorization-code flow with PKCE (RFC 7636) and a loopback redirect
//! (RFC 8252), then keeps the ID token and the refresh token in a session file. `claim`
//! posts `/v1/claims` with the ID token as bearer and the refresh token delegated in the
//! body, and forgets the refresh token: the issuer rotates it, so after mediatore's first
//! refresh the copy here would be dead anyway. A second claim is a second login.

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
            .map_err(|e| anyhow::anyhow!("{}: {e} (run `mediatore-cli login`)", path.display()))?;
        Ok(serde_json::from_str(&text)?)
    }

    /// Write the session at `path`, owner-readable only.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let text = serde_json::to_string_pretty(self)?;
        #[cfg(unix)]
        {
            use std::io::Write as _;
            use std::os::unix::fs::OpenOptionsExt as _;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)?;
            f.write_all(text.as_bytes())?;
        }
        #[cfg(not(unix))]
        std::fs::write(path, text)?;
        Ok(())
    }

    /// True while the ID token is good for at least `margin_secs` more seconds.
    #[must_use]
    pub fn is_fresh(&self, margin_secs: i64) -> bool {
        self.expires_at - margin_secs > chrono_now()
    }
}

fn chrono_now() -> i64 {
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
    /// Scopes to request; `offline_access` is what yields the refresh token.
    pub scopes: Vec<String>,
    /// A login hint for the issuer, if any.
    pub login_hint: Option<String>,
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

fn http() -> anyhow::Result<reqwest::Client> {
    mediatore_proto::tls::ensure_provider();
    Ok(reqwest::Client::builder()
        .use_preconfigured_tls(mediatore_proto::tls::https_client_config())
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
    let http = http()?;
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
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let redirect_uri = format!(
        "http://127.0.0.1:{}/callback",
        listener.local_addr()?.port()
    );

    let mut url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
        discovery.authorization_endpoint,
        encode(&opts.client_id),
        encode(&redirect_uri),
        encode(&opts.scopes.join(" ")),
        encode(&state),
        encode(&challenge),
    );
    if let Some(hint) = &opts.login_hint {
        use std::fmt::Write as _;
        let _ = write!(url, "&login_hint={}", encode(hint));
    }
    let callback = tokio::spawn(accept_callback(listener));
    open_url(&url);
    let (code, returned_state) = callback.await??;
    anyhow::ensure!(
        returned_state == state,
        "the callback's state does not match"
    );

    let reply: TokenReply = http
        .post(&discovery.token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("client_id", opts.client_id.as_str()),
            ("code_verifier", verifier.as_str()),
        ])
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

/// mediatore's user API.
pub struct Api {
    base: String,
    http: reqwest::Client,
}

impl Api {
    /// A client for the user API at `base` (`https://mediatore.example`).
    pub fn new(base: &str) -> anyhow::Result<Self> {
        Ok(Self {
            base: base.trim_end_matches('/').to_owned(),
            http: http()?,
        })
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

    /// `GET /v1/claims/{name}`.
    pub async fn get(&self, session: &Session, name: &str) -> anyhow::Result<ClaimResponse> {
        let resp = self
            .http
            .get(format!("{}/v1/claims/{name}", self.base))
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

    /// `DELETE /v1/claims/{name}`.
    pub async fn delete(&self, session: &Session, name: &str) -> anyhow::Result<()> {
        let resp = self
            .http
            .delete(format!("{}/v1/claims/{name}", self.base))
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
            login_hint: Some("hexley".into()),
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

    #[tokio::test]
    async fn the_session_file_round_trips_owner_only() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target-test")
            .join(uuid::Uuid::new_v4().to_string());
        let path = dir.join("session.json");
        let s = Session {
            issuer: "https://dex.home.example".into(),
            client_id: "mediatore".into(),
            login: "octocat".into(),
            id_token: "a.b.c".into(),
            refresh_token: Some("rt".into()),
            expires_at: 0,
        };
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
