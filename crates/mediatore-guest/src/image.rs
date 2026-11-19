// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The workload rootfs: pulled from its OCI registry by the guest, as root, and unpacked
//! onto the sandbox tmpfs before the ruleset and the jail (ADR-0021).
//!
//! The guest speaks the distribution API itself, anonymously, following one bearer
//! challenge; every blob is verified against its digest, the manifest digest is what the
//! audit records. Layers are applied in order with whiteouts, and an entry that would land
//! outside the rootfs refuses the image.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::{Component, Path, PathBuf};

use mediatore_proto::image::{ImageReference, is_sha256_digest as is_digest};
use mediatore_proto::{RegistryCredential, Secret};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::AsyncWriteExt;

const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
const DOCKER_MANIFEST: &str = "application/vnd.docker.distribution.manifest.v2+json";
const DOCKER_MANIFEST_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";

/// What `Accept` says on a manifest request: both families, image and index.
const ACCEPT: &str = "application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json";

/// How much of a blob is gathered in memory before it is written to its staged file: 1 MiB, so a layer costs
/// one write per mebibyte and not one per network chunk.
const BLOB_WRITE_BUFFER: usize = 1 << 20;

/// The platform the guest selects from an index: `linux` and this machine's architecture
/// in the registry's spelling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Platform {
    /// `linux`.
    pub os: String,
    /// `amd64`, `arm64`, ...
    pub architecture: String,
}

impl Platform {
    /// This machine's.
    #[must_use]
    pub fn this() -> Self {
        let architecture = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            other => other,
        };
        Self {
            os: "linux".into(),
            architecture: architecture.into(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct Descriptor {
    #[serde(rename = "mediaType", default)]
    media_type: String,
    digest: String,
    size: u64,
    #[serde(default)]
    platform: Option<Platform>,
}

impl<'de> Deserialize<'de> for Platform {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            os: String,
            architecture: String,
        }
        let r = Raw::deserialize(d)?;
        Ok(Self {
            os: r.os,
            architecture: r.architecture,
        })
    }
}

#[derive(Debug, Deserialize)]
struct Manifest {
    #[serde(rename = "mediaType", default)]
    media_type: String,
    #[serde(default)]
    manifests: Vec<Descriptor>,
    #[serde(default)]
    layers: Vec<Descriptor>,
}

/// How a layer's bytes are read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LayerEncoding {
    Tar,
    Gzip,
}

fn layer_encoding(media_type: &str) -> anyhow::Result<LayerEncoding> {
    match media_type {
        "application/vnd.oci.image.layer.v1.tar"
        | "application/vnd.docker.image.rootfs.diff.tar" => Ok(LayerEncoding::Tar),
        "application/vnd.oci.image.layer.v1.tar+gzip"
        | "application/vnd.docker.image.rootfs.diff.tar.gzip" => Ok(LayerEncoding::Gzip),
        other => {
            anyhow::bail!("layer media type {other:?} is not supported (tar and tar+gzip are)")
        }
    }
}

/// What a pull produced, for the record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pulled {
    /// The manifest digest the reference resolved to: what ran.
    pub digest: String,
    /// Layers applied.
    pub layers: usize,
    /// Bytes fetched for the layers.
    pub bytes: u64,
}

/// One registry the pool reaches through a gateway's registry leg (ADR-0038 decision 2):
/// its name, as its certificate and its `Host` header know it, and the leg's port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayRegistry {
    /// The registry's name without a port, lower case: what its certificate carries.
    pub host: String,
    /// The relay's registry leg port on the gateway.
    pub port: u16,
}

/// `MEDIATORE_RELAY_REGISTRIES`: `host=port`, comma separated. A host has no port of its own
/// here (the name the certificate carries) and appears once; an entry half-read is an error.
///
/// # Errors
/// An entry that is not `name=port`, a name with a port, a space or no characters, a port
/// outside 1 to 65535, or a name listed twice.
pub fn parse_relay_registries(value: &str) -> anyhow::Result<Vec<RelayRegistry>> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(Vec::new());
    }
    let mut out: Vec<RelayRegistry> = Vec::new();
    for entry in value.split(',') {
        let entry = entry.trim();
        let (host, port) = entry.split_once('=').ok_or_else(|| {
            anyhow::anyhow!("MEDIATORE_RELAY_REGISTRIES: {entry:?} is not host=port")
        })?;
        let host = host.trim().to_ascii_lowercase();
        anyhow::ensure!(
            !host.is_empty()
                && host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'),
            "MEDIATORE_RELAY_REGISTRIES: {host:?} is not a registry host name (no port, no space)"
        );
        let port: u16 = port.trim().parse().map_err(|_| {
            anyhow::anyhow!("MEDIATORE_RELAY_REGISTRIES: {entry:?} has no valid port")
        })?;
        anyhow::ensure!(
            port != 0,
            "MEDIATORE_RELAY_REGISTRIES: {entry:?} has port 0"
        );
        anyhow::ensure!(
            !out.iter().any(|e| e.host == host),
            "MEDIATORE_RELAY_REGISTRIES: {host} is listed twice"
        );
        out.push(RelayRegistry { host, port });
    }
    Ok(out)
}

/// The gateway the registry legs are on, and each declared host's leg port.
#[derive(Debug, Clone)]
struct Relay {
    gateway: IpAddr,
    ports: BTreeMap<String, u16>,
}

/// Where a request goes: the URL to dial, the `Host` header to send in place of the URL's
/// authority, and whether it went through a registry leg.
#[derive(Debug)]
struct Routed {
    url: String,
    host_header: Option<String>,
    via_relay: bool,
}

/// The pull client: one per guest, anonymous, HTTPS unless the registry is listed as plain.
#[derive(Debug, Clone)]
pub struct Puller {
    http: reqwest::Client,
    /// The extra roots a registry on the operator's PKI chains to (`MEDIATORE_REGISTRY_CA`).
    registry_ca: Option<Vec<u8>>,
    /// The registries reached through a gateway's registry leg (ADR-0038), when any.
    relay: Option<Relay>,
    plain_http: BTreeSet<String>,
    platform: Platform,
    /// Never set outside tests: the fake registry speaks plain HTTP.
    plain_http_credentials: bool,
    /// The registry the gateway places a credential for (ADR-0043), pulled through the claim's egress proxy.
    placed: Option<Placed>,
}

/// A registry pulled through the claim's egress proxy on a loopback port that no jail rule lists (ADR-0043
/// decision 3). Requests go there as plain HTTP under `/<registry host>/`, carry no credential, answer no challenge
/// and follow no redirect: the gateway places what the registry accepts, and anything that would send the VM to
/// another host is refused.
#[derive(Debug, Clone)]
struct Placed {
    host: String,
    /// `http://<addr>/<host>`, the prefix of every URL of this registry.
    base: String,
    /// A client that follows no redirect and needs no TLS (the proxy is on loopback).
    http: reqwest::Client,
}

/// One pull's credentials: the operator's, when the claim carries one (ADR-0022), and the
/// bearer token the registry's challenge yields. Kept for the pull only.
#[derive(Default)]
struct Session {
    token: Option<String>,
    basic: Option<(String, Secret)>,
    /// The registry challenged with `Basic`: send the credential on the requests themselves.
    send_basic: bool,
}

impl Puller {
    /// A client for this platform; `plain_http` lists the registries (`host[:port]`)
    /// reached over HTTP instead of HTTPS.
    pub fn new(plain_http: &[String]) -> anyhow::Result<Self> {
        // TLS 1.3 over the Mozilla roots on aws-lc-rs (ADR-0007 decision 6): the registry
        // is a system we do not operate, so the far end keeps a classical fallback.
        let http = reqwest::Client::builder()
            .tls_backend_preconfigured(mediatore_proto::tls::https_client_config())
            .user_agent(concat!("mediatore-guest/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            http,
            registry_ca: None,
            relay: None,
            plain_http: plain_http.iter().cloned().collect(),
            platform: Platform::this(),
            plain_http_credentials: false,
            placed: None,
        })
    }

    /// Pull `host` through the claim's egress proxy at `proxy` (ADR-0043 decisions 2 and 3): the proxy sends each request
    /// to a gateway, which places the credential, so this client holds none, answers no challenge and follows no
    /// redirect for that registry. Every other registry is reached as before.
    ///
    /// # Errors
    /// The client cannot be built.
    pub fn with_placed_registry(
        mut self,
        host: &str,
        proxy: std::net::SocketAddr,
    ) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("mediatore-guest/", env!("CARGO_PKG_VERSION")))
            .build()?;
        self.placed = Some(Placed {
            host: host.to_owned(),
            base: format!("http://{proxy}/{host}"),
            http,
        });
        Ok(self)
    }

    /// Trust the CA certificates in `pem` beside the Mozilla roots, for a registry mirror
    /// on the operator's PKI (`MEDIATORE_REGISTRY_CA`, ADR-0029 decision 1). The client is
    /// rebuilt; an empty or unparsable PEM is an error, never the public roots alone in
    /// its place.
    ///
    /// # Errors
    /// `pem` holds no certificate, or the client cannot be built.
    pub fn with_registry_ca(mut self, pem: &[u8]) -> anyhow::Result<Self> {
        // Parsed once here so an unusable PEM is an error now, whatever order the builders run in.
        mediatore_proto::tls::https_client_config_with_extra_roots(pem)?;
        self.registry_ca = Some(pem.to_vec());
        self.http = build_client(self.registry_ca.as_deref(), self.relay.as_ref())?;
        Ok(self)
    }

    /// Reach the declared registries through the gateway's registry legs (ADR-0038
    /// decision 2): each declared name is dialled at `gateway` and its leg's port, and keeps
    /// its own TLS server name, certificate check and `Host` header. Redirects are then
    /// followed here, not by the client: one to a host that is not declared is refused.
    ///
    /// # Errors
    /// The client cannot be built.
    pub fn with_relay_registries(
        mut self,
        gateway: IpAddr,
        entries: &[RelayRegistry],
    ) -> anyhow::Result<Self> {
        self.relay = if entries.is_empty() {
            None
        } else {
            Some(Relay {
                gateway,
                ports: entries.iter().map(|e| (e.host.clone(), e.port)).collect(),
            })
        };
        self.http = build_client(self.registry_ca.as_deref(), self.relay.as_ref())?;
        Ok(self)
    }

    /// Select another platform from an index than this machine's. Tests only.
    #[cfg(test)]
    fn with_platform(mut self, p: Platform) -> Self {
        self.platform = p;
        self
    }

    /// Let a credential cross plain HTTP, because the fake registry has no TLS. Tests
    /// only; the refusal itself has its own test.
    #[cfg(test)]
    fn credentials_over_plain_http_for_tests(mut self) -> Self {
        self.plain_http_credentials = true;
        self
    }

    /// Where `url` is dialled: a declared registry goes to its leg's port (the name stays,
    /// for the TLS server name and the certificate), everything else as written.
    fn route(&self, url: &str) -> anyhow::Result<Routed> {
        let direct = || Routed {
            url: url.to_string(),
            host_header: None,
            via_relay: false,
        };
        let Some(relay) = &self.relay else {
            return Ok(direct());
        };
        let mut parsed = reqwest::Url::parse(url)?;
        let Some(host) = parsed.host_str().map(str::to_ascii_lowercase) else {
            return Ok(direct());
        };
        let Some(port) = relay.ports.get(&host) else {
            return Ok(direct());
        };
        let host_header = match parsed.port() {
            Some(p) => format!("{host}:{p}"),
            None => host,
        };
        parsed
            .set_port(Some(*port))
            .map_err(|()| anyhow::anyhow!("{url}: cannot set the leg's port"))?;
        Ok(Routed {
            url: parsed.to_string(),
            host_header: Some(host_header),
            via_relay: true,
        })
    }

    /// GET `url`. Without declared registries the client follows redirects as it always did.
    /// With them, redirects are followed here so each hop is routed again, and one that
    /// leaves a declared registry for a host that is not declared is refused (ADR-0038
    /// decision 2). `add` decorates each request; its flag says the hop is still on the
    /// original host, which is the only place a credential goes.
    async fn send_following(
        &self,
        url: &str,
        add: impl Fn(reqwest::RequestBuilder, bool) -> reqwest::RequestBuilder,
    ) -> anyhow::Result<reqwest::Response> {
        let Some(relay) = &self.relay else {
            return Ok(add(self.http.get(url), true).send().await?);
        };
        let origin = reqwest::Url::parse(url)?;
        let mut current = origin.clone();
        for _ in 0..10 {
            let routed = self.route(current.as_str())?;
            let mut req = self.http.get(&routed.url);
            if let Some(h) = &routed.host_header {
                req = req.header(reqwest::header::HOST, h);
            }
            let resp = add(req, current.host_str() == origin.host_str())
                .send()
                .await?;
            if !resp.status().is_redirection() {
                return Ok(resp);
            }
            let Some(location) = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
            else {
                return Ok(resp);
            };
            let next = current.join(location)?;
            let next_host = next.host_str().unwrap_or_default().to_ascii_lowercase();
            anyhow::ensure!(
                !routed.via_relay || relay.ports.contains_key(&next_host),
                "{url}: redirected to {next_host}, which is not declared in MEDIATORE_RELAY_REGISTRIES; refused (ADR-0038 decision 2)"
            );
            current = next;
        }
        anyhow::bail!("{url}: more than 10 redirects")
    }

    fn base(&self, reference: &ImageReference) -> String {
        if let Some(p) = &self.placed
            && p.host == reference.registry
        {
            return format!("{}/v2/{}", p.base, reference.repository);
        }
        let scheme = if self.plain_http.contains(&reference.registry) {
            "http"
        } else {
            "https"
        };
        format!(
            "{scheme}://{}/v2/{}",
            reference.registry, reference.repository
        )
    }

    /// GET `url`, answering one challenge: a bearer one with a token from its realm (the
    /// credential presented there, when there is one), a `Basic` one with the credential
    /// itself.
    async fn get(
        &self,
        session: &mut Session,
        url: &str,
        accept: Option<&str>,
    ) -> anyhow::Result<reqwest::Response> {
        if let Some(p) = &self.placed
            && url.starts_with(&format!("{}/", p.base))
        {
            // A placed registry (ADR-0043): no credential, no challenge, no redirect. The gateway placed what the
            // registry accepts, so a 401 is its refusal and is never answered from here (a token fetched here would
            // be a credential on the VM), and a redirect would send the VM to a host with no gateway in between.
            let mut req = p.http.get(url);
            if let Some(a) = accept {
                req = req.header(reqwest::header::ACCEPT, a);
            }
            let resp = req.send().await?;
            anyhow::ensure!(
                !resp.status().is_redirection(),
                "{url}: the registry redirected the request; a redirect would leave the gateway, refused (ADR-0043)"
            );
            anyhow::ensure!(
                resp.status() != reqwest::StatusCode::UNAUTHORIZED,
                "{url}: the registry refused the credential the gateway placed (401)"
            );
            return Ok(resp);
        }
        for attempt in 0..2 {
            let resp = self
                .send_following(url, |mut req, same_host| {
                    if let Some(a) = accept {
                        req = req.header(reqwest::header::ACCEPT, a);
                    }
                    if !same_host {
                        return req;
                    }
                    if let Some(t) = &session.token {
                        req = req.bearer_auth(t);
                    } else if session.send_basic
                        && let Some((user, password)) = &session.basic
                    {
                        req = req.basic_auth(user, Some(&password.0));
                    }
                    req
                })
                .await?;
            if resp.status() != reqwest::StatusCode::UNAUTHORIZED || attempt == 1 {
                return Ok(resp);
            }
            let header = resp
                .headers()
                .get(reqwest::header::WWW_AUTHENTICATE)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
                .ok_or_else(|| anyhow::anyhow!("{url}: 401 without a challenge"))?;
            match parse_challenge(&header) {
                Some(Challenge::Bearer(c)) => {
                    session.token = Some(self.token(&c, session.basic.as_ref()).await?);
                }
                Some(Challenge::Basic) => {
                    anyhow::ensure!(
                        session.basic.is_some(),
                        "{url}: the registry wants a credential and the claim carries none"
                    );
                    session.send_basic = true;
                }
                None => anyhow::bail!("{url}: 401 with an unsupported challenge"),
            }
        }
        unreachable!("two attempts, each returns");
    }

    async fn token(
        &self,
        c: &BearerChallenge,
        basic: Option<&(String, Secret)>,
    ) -> anyhow::Result<String> {
        #[derive(Deserialize)]
        struct TokenResponse {
            #[serde(default)]
            token: Option<String>,
            #[serde(default)]
            access_token: Option<String>,
        }
        let mut query = Vec::new();
        if let Some(s) = &c.service {
            query.push(("service", s.as_str()));
        }
        if let Some(s) = &c.scope {
            query.push(("scope", s.as_str()));
        }
        let mut realm = reqwest::Url::parse(&c.realm)?;
        realm.query_pairs_mut().extend_pairs(&query);
        let resp = self
            .send_following(realm.as_str(), |mut req, same_host| {
                if same_host && let Some((user, password)) = basic {
                    req = req.basic_auth(user, Some(&password.0));
                }
                req
            })
            .await?;
        anyhow::ensure!(
            resp.status().is_success(),
            "token endpoint {} refused: {}{}",
            c.realm,
            resp.status(),
            if basic.is_some() {
                " (the configured credential was presented)"
            } else {
                " (no credential configured for this registry)"
            }
        );
        let t: TokenResponse = resp.json().await?;
        t.token
            .or(t.access_token)
            .ok_or_else(|| anyhow::anyhow!("token endpoint {} returned no token", c.realm))
    }

    async fn manifest(
        &self,
        session: &mut Session,
        reference: &ImageReference,
        by: &str,
    ) -> anyhow::Result<(String, Manifest)> {
        let url = format!("{}/manifests/{by}", self.base(reference));
        let resp = self.get(session, &url, Some(ACCEPT)).await?;
        anyhow::ensure!(
            resp.status().is_success(),
            "{reference}: manifest {by} refused: {}",
            resp.status()
        );
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_string();
        let body = resp.bytes().await?;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&body)));
        if is_digest(by) {
            anyhow::ensure!(
                digest == by,
                "{reference}: manifest {by} hashes to {digest}; the registry served other bytes"
            );
        }
        let mut m: Manifest = serde_json::from_slice(&body)
            .map_err(|e| anyhow::anyhow!("{reference}: manifest {by} is not a manifest: {e}"))?;
        if m.media_type.is_empty() {
            m.media_type = content_type;
        }
        Ok((digest, m))
    }

    /// Pull `reference` into `rootfs`, staging each layer under `scratch` while it is
    /// hashed. `rootfs` and `scratch` exist and are empty. `credential`, when the claim
    /// carries one, is for this registry and goes over HTTPS only (ADR-0022 decision 3).
    pub async fn pull(
        &self,
        reference: &ImageReference,
        credential: Option<&RegistryCredential>,
        rootfs: &Path,
        scratch: &Path,
    ) -> anyhow::Result<Pulled> {
        let mut session = Session::default();
        if let Some(c) = credential {
            anyhow::ensure!(
                c.host == reference.registry,
                "{reference}: the credential is for {}, not this registry",
                c.host
            );
            anyhow::ensure!(
                self.plain_http_credentials || !self.plain_http.contains(&reference.registry),
                "{reference}: a credential never crosses plain HTTP, and {} is listed as plain",
                reference.registry
            );
            session.basic = Some((c.username.clone(), c.password.clone()));
        }
        let by = reference.manifest_reference();
        let (mut digest, mut manifest) = self.manifest(&mut session, reference, by).await?;
        if matches!(
            manifest.media_type.as_str(),
            OCI_INDEX | DOCKER_MANIFEST_LIST
        ) || (!manifest.manifests.is_empty() && manifest.layers.is_empty())
        {
            let want = &self.platform;
            let entry = manifest
                .manifests
                .iter()
                .find(|d| d.platform.as_ref() == Some(want))
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "{reference}: the index {digest} has no manifest for {}/{}",
                        want.os,
                        want.architecture
                    )
                })?;
            let d = entry.digest.clone();
            anyhow::ensure!(
                is_digest(&d),
                "{reference}: index entry digest {d:?} is not sha256"
            );
            (digest, manifest) = self.manifest(&mut session, reference, &d).await?;
        }
        anyhow::ensure!(
            matches!(manifest.media_type.as_str(), OCI_MANIFEST | DOCKER_MANIFEST)
                || (!manifest.layers.is_empty() && manifest.manifests.is_empty()),
            "{reference}: {digest} is a {:?}, not an image manifest",
            manifest.media_type
        );
        anyhow::ensure!(
            !manifest.layers.is_empty(),
            "{reference}: {digest} has no layers"
        );
        // Refuse before any byte is fetched: an image with one layer we cannot read is not
        // an image we half-run.
        let encodings = manifest
            .layers
            .iter()
            .map(|l| layer_encoding(&l.media_type))
            .collect::<anyhow::Result<Vec<_>>>()?;

        let mut bytes = 0;
        for (n, (layer, encoding)) in manifest.layers.iter().zip(encodings).enumerate() {
            anyhow::ensure!(
                is_digest(&layer.digest),
                "{reference}: layer {n} digest {:?} is not sha256",
                layer.digest
            );
            let staged = scratch.join(format!("layer-{n}"));
            let size = self
                .fetch_blob(&mut session, reference, layer, &staged)
                .await?;
            bytes += size;
            let rootfs = rootfs.to_path_buf();
            let staged_for_apply = staged.clone();
            let applied = tokio::task::spawn_blocking(move || {
                apply_layer(&staged_for_apply, encoding, &rootfs)
            })
            .await?;
            let _ = tokio::fs::remove_file(&staged).await;
            let applied = applied
                .map_err(|e| anyhow::anyhow!("{reference}: layer {n} ({}): {e}", layer.digest))?;
            tracing::debug!(
                layer = n,
                digest = %layer.digest,
                bytes = size,
                entries = applied.entries,
                skipped = applied.skipped,
                "layer applied"
            );
        }
        Ok(Pulled {
            digest,
            layers: manifest.layers.len(),
            bytes,
        })
    }

    /// Stream one blob to `dest`, hashing as it goes; the digest and size must match the
    /// descriptor or the file is removed and the pull fails.
    async fn fetch_blob(
        &self,
        session: &mut Session,
        reference: &ImageReference,
        d: &Descriptor,
        dest: &Path,
    ) -> anyhow::Result<u64> {
        let url = format!("{}/blobs/{}", self.base(reference), d.digest);
        let mut resp = self.get(session, &url, None).await?;
        anyhow::ensure!(
            resp.status().is_success(),
            "{reference}: blob {} refused: {}",
            d.digest,
            resp.status()
        );
        // Buffered: a network chunk is a few kibibytes, and each write to the file is a hop to the blocking pool.
        // The flush below empties the buffer into the file before the size and the digest are judged; on an
        // error the buffer is dropped with what it holds, and the file is removed.
        let mut file = tokio::io::BufWriter::with_capacity(
            BLOB_WRITE_BUFFER,
            tokio::fs::File::create(dest).await?,
        );
        let mut hasher = Sha256::new();
        let mut size = 0u64;
        let result: anyhow::Result<()> = async {
            while let Some(chunk) = resp.chunk().await? {
                size += chunk.len() as u64;
                anyhow::ensure!(
                    size <= d.size,
                    "blob {} exceeds its declared size {}",
                    d.digest,
                    d.size
                );
                hasher.update(&chunk);
                file.write_all(&chunk).await?;
            }
            file.flush().await?;
            anyhow::ensure!(
                size == d.size,
                "blob {} is {size} bytes, declared {}",
                d.digest,
                d.size
            );
            let got = format!("sha256:{}", hex::encode(hasher.finalize()));
            anyhow::ensure!(
                got == d.digest,
                "blob {} hashes to {got}; the registry served other bytes",
                d.digest
            );
            Ok(())
        }
        .await;
        if let Err(e) = result {
            drop(file);
            let _ = tokio::fs::remove_file(dest).await;
            return Err(anyhow::anyhow!("{reference}: {e}"));
        }
        Ok(size)
    }
}

/// A parsed `WWW-Authenticate`: the bearer form with its realm, or `Basic`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Challenge {
    Bearer(BearerChallenge),
    Basic,
}

/// `Bearer realm="…",service="…",scope="…"`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BearerChallenge {
    realm: String,
    service: Option<String>,
    scope: Option<String>,
}

/// The one client the puller uses: TLS 1.3 over the Mozilla roots (and the operator's CA
/// when given, ADR-0029), each declared relay registry pinned to its gateway, and redirects
/// left to the puller when there are any (ADR-0038).
fn build_client(pem: Option<&[u8]>, relay: Option<&Relay>) -> anyhow::Result<reqwest::Client> {
    let tls = match pem {
        Some(pem) => mediatore_proto::tls::https_client_config_with_extra_roots(pem)?,
        None => mediatore_proto::tls::https_client_config(),
    };
    let mut builder = reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .user_agent(concat!("mediatore-guest/", env!("CARGO_PKG_VERSION")));
    if let Some(relay) = relay {
        // Never an ambient proxy: a declared registry is dialled at its gateway by address, and a
        // proxy in the environment would carry the request somewhere else without saying so.
        builder = builder
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none());
        for host in relay.ports.keys() {
            builder = builder.resolve(host, SocketAddr::new(relay.gateway, 0));
        }
    }
    Ok(builder.build()?)
}

fn parse_challenge(header: &str) -> Option<Challenge> {
    let header = header.trim();
    if header == "Basic" || header.starts_with("Basic ") {
        return Some(Challenge::Basic);
    }
    parse_bearer_challenge(header).map(Challenge::Bearer)
}

fn parse_bearer_challenge(header: &str) -> Option<BearerChallenge> {
    let rest = header.trim().strip_prefix("Bearer ")?;
    let mut realm = None;
    let mut service = None;
    let mut scope = None;
    for part in rest.split(',') {
        let (k, v) = part.trim().split_once('=')?;
        let v = v.trim().trim_matches('"').to_string();
        match k.trim() {
            "realm" => realm = Some(v),
            "service" => service = Some(v),
            "scope" => scope = Some(v),
            _ => {}
        }
    }
    Some(BearerChallenge {
        realm: realm?,
        service,
        scope,
    })
}

/// What applying a layer did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct Applied {
    entries: usize,
    /// Device nodes, fifos and other entry types the rootfs does not take.
    skipped: usize,
}

/// A layer entry's path relative to the rootfs: `./` dropped, nothing but plain
/// components allowed. `..`, a root or a prefix refuses the layer.
fn relative(path: &Path) -> anyhow::Result<PathBuf> {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::Normal(n) => out.push(n),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                anyhow::bail!("entry {} escapes the rootfs", path.display())
            }
        }
    }
    Ok(out)
}

/// Remove whatever is at `p`, file, link or tree. Missing is fine.
fn remove_any(p: &Path) -> std::io::Result<()> {
    match std::fs::symlink_metadata(p) {
        Ok(m) if m.is_dir() => std::fs::remove_dir_all(p),
        Ok(_) => std::fs::remove_file(p),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Apply one layer onto `rootfs`: whiteouts first-class, no path out of the rootfs, no
/// setuid, no device nodes, no ownership, no xattrs (ADR-0021 decision 4).
fn apply_layer(staged: &Path, encoding: LayerEncoding, rootfs: &Path) -> anyhow::Result<Applied> {
    let file = std::fs::File::open(staged)?;
    let reader: Box<dyn Read> = match encoding {
        LayerEncoding::Tar => Box::new(file),
        LayerEncoding::Gzip => Box::new(flate2::read::GzDecoder::new(file)),
    };
    let mut archive = tar::Archive::new(reader);
    // The defaults, stated: mode bits beyond 0o777 dropped, no xattrs, no uid/gid.
    archive.set_preserve_permissions(false);
    archive.set_unpack_xattrs(false);
    archive.set_preserve_ownerships(false);
    archive.set_overwrite(true);
    let mut applied = Applied::default();
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let rel = relative(&path)?;
        let Some(name) = rel.file_name().and_then(|n| n.to_str()) else {
            // `./` alone: the root itself.
            continue;
        };
        let parent = rel
            .parent()
            .map_or_else(|| rootfs.to_path_buf(), |p| rootfs.join(p));
        if name == ".wh..wh..opq" {
            if let Ok(children) = std::fs::read_dir(&parent) {
                for c in children {
                    remove_any(&c?.path())?;
                }
            }
            applied.entries += 1;
            continue;
        }
        if let Some(target) = name.strip_prefix(".wh.") {
            remove_any(&parent.join(target))?;
            applied.entries += 1;
            continue;
        }
        let kind = entry.header().entry_type();
        let is_dir = kind.is_dir();
        if !matches!(
            kind,
            tar::EntryType::Regular
                | tar::EntryType::Continuous
                | tar::EntryType::Directory
                | tar::EntryType::Symlink
                | tar::EntryType::Link
        ) {
            tracing::debug!(entry = %path.display(), ?kind, "layer entry skipped");
            applied.skipped += 1;
            continue;
        }
        // Overlay semantics: a directory replaces a file or link and a file replaces a
        // tree, instead of writing through what the lower layer left there.
        let dest = rootfs.join(&rel);
        if let Ok(m) = std::fs::symlink_metadata(&dest) {
            if is_dir != m.is_dir() {
                remove_any(&dest)?;
            } else if !is_dir {
                std::fs::remove_file(&dest)?;
            }
        }
        anyhow::ensure!(
            entry.unpack_in(rootfs)?,
            "entry {} escapes the rootfs",
            path.display()
        );
        applied.entries += 1;
    }
    Ok(applied)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use mediatore_testkit::registry::{Compression, FakeRegistry, Image, Layer, digest};

    use super::*;

    fn r(s: &str) -> ImageReference {
        s.parse().unwrap()
    }

    /// A password minted per test: nothing a scanner can mistake for a secret in the
    /// source, and nothing two tests share.
    fn fresh_password() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    fn credential(reg: &FakeRegistry, user: &str, pass: &str) -> RegistryCredential {
        RegistryCredential {
            host: reg.host(),
            username: user.into(),
            password: Secret(pass.into()),
        }
    }

    #[test]
    fn the_bearer_challenge_is_parsed_and_a_non_bearer_one_is_not() {
        let c = parse_bearer_challenge(
            "Bearer realm=\"https://ghcr.io/token\",service=\"ghcr.io\",scope=\"repository:a/b:pull\"",
        )
        .unwrap();
        assert_eq!(c.realm, "https://ghcr.io/token");
        assert_eq!(c.service.as_deref(), Some("ghcr.io"));
        assert_eq!(c.scope.as_deref(), Some("repository:a/b:pull"));
        assert_eq!(parse_bearer_challenge("Basic realm=\"x\""), None);
        assert_eq!(parse_challenge("Basic realm=\"x\""), Some(Challenge::Basic));
        assert_eq!(parse_challenge("Digest realm=\"x\""), None);
        assert_eq!(
            parse_bearer_challenge("Bearer service=\"x\""),
            None,
            "no realm, no challenge"
        );
    }

    #[test]
    fn only_plain_components_are_relative_to_the_rootfs() {
        assert_eq!(
            relative(Path::new("./bin/sh")).unwrap(),
            PathBuf::from("bin/sh")
        );
        assert_eq!(
            relative(Path::new("bin/./sh")).unwrap(),
            PathBuf::from("bin/sh")
        );
        assert!(
            relative(Path::new("../x"))
                .unwrap_err()
                .to_string()
                .contains("escapes")
        );
        assert!(relative(Path::new("a/../../x")).is_err());
        assert!(relative(Path::new("/etc/passwd")).is_err());
    }

    struct Scratch {
        rootfs: PathBuf,
        scratch: PathBuf,
    }

    fn scratch() -> Scratch {
        let dir = mediatore_testkit::tempdir();
        let rootfs = dir.join("rootfs");
        let scratch = dir.join("layers");
        std::fs::create_dir_all(&rootfs).unwrap();
        std::fs::create_dir_all(&scratch).unwrap();
        Scratch { rootfs, scratch }
    }

    fn puller(reg: &FakeRegistry) -> Puller {
        Puller::new(&[reg.host()]).unwrap()
    }

    fn reference(reg: &FakeRegistry, rest: &str) -> ImageReference {
        r(&format!("{}/{rest}", reg.host()))
    }

    fn mode(p: &Path) -> u32 {
        std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
    }

    /// A one-layer image, small enough for the placed-registry tests.
    fn tiny() -> mediatore_testkit::registry::Built {
        Image::new()
            .layer(
                Layer::new().dir("bin", 0o755).file("bin/sh", 0o755, b"sh"),
                Compression::None,
            )
            .build()
    }

    fn placed_puller(proxy: &FakeRegistry) -> Puller {
        Puller::new(&[])
            .unwrap()
            .with_placed_registry("registry.home.example", proxy.host().parse().unwrap())
            .unwrap()
    }

    #[tokio::test]
    async fn a_placed_registry_is_pulled_through_the_proxy_with_no_credential_and_no_token_flow() {
        // ADR-0043 decision 2: the VM presents nothing and answers no challenge; the gateway places the credential.
        let proxy = FakeRegistry::start_under("registry.home.example").await;
        let want = proxy.push("team/tool", "v1", &tiny());
        let s = scratch();
        let got = placed_puller(&proxy)
            .pull(
                &r("registry.home.example/team/tool:v1"),
                None,
                &s.rootfs,
                &s.scratch,
            )
            .await
            .unwrap();
        assert_eq!(got.digest, want);
        assert_eq!(
            std::fs::read_to_string(s.rootfs.join("bin/sh")).unwrap(),
            "sh"
        );
        assert_eq!(proxy.bearer_seen(), 0, "no bearer");
        assert_eq!(proxy.basic_on_content(), 0, "no basic");
        assert_eq!(proxy.token_requests(), 0, "no realm call");
    }

    #[tokio::test]
    async fn a_placed_registrys_401_is_an_error_and_never_a_call_to_the_realm() {
        // The gateway placed what the registry accepts; a 401 means it refused it. The puller must not "fix" that by
        // fetching a token itself, which would make the VM call the realm and hold a credential.
        let proxy = FakeRegistry::start_under("registry.home.example").await;
        proxy.push("team/tool", "v1", &tiny());
        proxy.require_token(true);
        let s = scratch();
        let err = placed_puller(&proxy)
            .pull(
                &r("registry.home.example/team/tool:v1"),
                None,
                &s.rootfs,
                &s.scratch,
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("refused") && err.contains("gateway"), "{err}");
        assert_eq!(proxy.token_requests(), 0, "the realm was never called");
    }

    #[tokio::test]
    async fn a_placed_registrys_redirect_is_refused_not_followed_off_the_vm() {
        // A layer redirected to another host would be fetched by the VM itself, with no gateway in between.
        let proxy = FakeRegistry::start_under("registry.home.example").await;
        let other = FakeRegistry::start().await;
        proxy.push("team/tool", "v1", &tiny());
        proxy.redirect_blobs_to(&format!("http://{}", other.host()));
        let s = scratch();
        let err = placed_puller(&proxy)
            .pull(
                &r("registry.home.example/team/tool:v1"),
                None,
                &s.rootfs,
                &s.scratch,
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("redirect"), "{err}");
        assert_eq!(other.requests(), 0, "the other host was never contacted");
    }

    #[tokio::test]
    async fn layers_are_applied_in_order_with_whiteouts_and_replacements() {
        let reg = FakeRegistry::start().await;
        let lower = Layer::new()
            .dir("bin", 0o755)
            .file("bin/sh", 0o755, b"lower sh")
            .dir("etc", 0o755)
            .file("etc/old", 0o644, b"gone later")
            .file("etc/keep", 0o644, b"kept")
            .dir("var", 0o755)
            .file("var/a", 0o644, b"a")
            .file("var/b", 0o644, b"b")
            .file("conf", 0o644, b"a file that becomes a dir")
            .dir("tree", 0o755)
            .file("tree/leaf", 0o644, b"a tree that becomes a file")
            .symlink("link", "bin/sh");
        let upper = Layer::new()
            .file("bin/sh", 0o755, b"upper sh")
            .whiteout("etc/old")
            .opaque("var")
            .file("var/c", 0o644, b"c")
            .dir("conf", 0o755)
            .file("conf/x", 0o644, b"x")
            .file("tree", 0o644, b"now a file")
            .link("bin/sh-hard", "bin/sh")
            .dir("link", 0o755);
        let img = Image::new()
            .layer(lower, Compression::None)
            .layer(upper, Compression::Gzip)
            .build();
        let want = reg.push("team/tool", "v1", &img);
        let s = scratch();
        let got = puller(&reg)
            .pull(
                &reference(&reg, "team/tool:v1"),
                None,
                &s.rootfs,
                &s.scratch,
            )
            .await
            .unwrap();
        assert_eq!(
            got.digest, want,
            "a tag resolves to the manifest digest that ran"
        );
        assert_eq!(got.layers, 2);
        assert_eq!(
            got.bytes,
            img.layers.iter().map(|l| l.bytes.len() as u64).sum::<u64>()
        );
        let read = |p: &str| std::fs::read_to_string(s.rootfs.join(p)).unwrap();
        assert_eq!(read("bin/sh"), "upper sh");
        assert_eq!(read("bin/sh-hard"), "upper sh");
        assert!(
            !s.rootfs.join("etc/old").exists(),
            "whiteout removes the lower file"
        );
        assert!(
            !s.rootfs.join("etc/.wh.old").exists(),
            "the whiteout itself is not unpacked"
        );
        assert_eq!(read("etc/keep"), "kept");
        let mut var: Vec<String> = std::fs::read_dir(s.rootfs.join("var"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        var.sort();
        assert_eq!(var, ["c"], "an opaque whiteout empties the lower directory");
        assert_eq!(read("conf/x"), "x", "a directory replaces a file");
        assert_eq!(read("tree"), "now a file", "a file replaces a tree");
        assert!(
            s.rootfs.join("link").is_dir(),
            "a directory replaces a symlink"
        );
        assert!(
            !std::fs::symlink_metadata(s.rootfs.join("link"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(mode(&s.rootfs.join("bin/sh")), 0o755);
        assert!(
            std::fs::read_dir(&s.scratch).unwrap().next().is_none(),
            "staged layers are removed once applied"
        );
    }

    #[tokio::test]
    async fn docker_media_types_are_accepted_too() {
        let reg = FakeRegistry::start().await;
        let img = Image::new()
            .docker()
            .layer(
                Layer::new().file("hello", 0o644, b"hi"),
                Compression::DockerGzip,
            )
            .build();
        reg.push("team/tool", "v1", &img);
        let s = scratch();
        puller(&reg)
            .pull(
                &reference(&reg, "team/tool:v1"),
                None,
                &s.rootfs,
                &s.scratch,
            )
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(s.rootfs.join("hello")).unwrap(),
            "hi"
        );
    }

    #[tokio::test]
    async fn an_entry_that_escapes_by_dot_dot_refuses_the_image() {
        let reg = FakeRegistry::start().await;
        let img = Image::new()
            .layer(
                Layer::new()
                    .file("ok", 0o644, b"ok")
                    .raw_file("../escape", b"outside"),
                Compression::None,
            )
            .build();
        reg.push("team/tool", "v1", &img);
        let s = scratch();
        let err = puller(&reg)
            .pull(
                &reference(&reg, "team/tool:v1"),
                None,
                &s.rootfs,
                &s.scratch,
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("escapes the rootfs"), "{err}");
        assert!(!s.rootfs.parent().unwrap().join("escape").exists());
    }

    #[tokio::test]
    async fn an_entry_through_a_symlink_out_of_the_rootfs_refuses_the_image() {
        let reg = FakeRegistry::start().await;
        let outside = mediatore_testkit::tempdir();
        let img = Image::new()
            .layer(
                Layer::new()
                    .symlink("door", outside.to_str().unwrap())
                    .file("door/planted", 0o644, b"outside"),
                Compression::Gzip,
            )
            .build();
        reg.push("team/tool", "v1", &img);
        let s = scratch();
        let err = puller(&reg)
            .pull(
                &reference(&reg, "team/tool:v1"),
                None,
                &s.rootfs,
                &s.scratch,
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("outside") || err.contains("escapes"), "{err}");
        assert!(
            !outside.join("planted").exists(),
            "nothing landed outside the rootfs"
        );
    }

    #[tokio::test]
    async fn a_symlink_inside_the_rootfs_is_followed_and_an_absolute_one_kept_as_is() {
        let reg = FakeRegistry::start().await;
        let img = Image::new()
            .layer(
                Layer::new()
                    .dir("usr/bin", 0o755)
                    .symlink("bin", "usr/bin")
                    .file("bin/sh", 0o755, b"sh")
                    .symlink("sbin", "/usr/bin"),
                Compression::None,
            )
            .build();
        reg.push("team/tool", "v1", &img);
        let s = scratch();
        puller(&reg)
            .pull(
                &reference(&reg, "team/tool:v1"),
                None,
                &s.rootfs,
                &s.scratch,
            )
            .await
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(s.rootfs.join("usr/bin/sh")).unwrap(),
            "sh"
        );
        assert_eq!(
            std::fs::read_link(s.rootfs.join("sbin")).unwrap(),
            PathBuf::from("/usr/bin"),
            "an absolute link means inside the chroot"
        );
    }

    #[tokio::test]
    async fn setuid_bits_are_dropped_and_device_nodes_skipped() {
        let reg = FakeRegistry::start().await;
        let img = Image::new()
            .layer(
                Layer::new()
                    .file("suid", 0o4755, b"#!/bin/sh")
                    .file("sgid", 0o2755, b"#!/bin/sh")
                    .dir("sticky", 0o1777)
                    .device("dev/mem"),
                Compression::None,
            )
            .build();
        reg.push("team/tool", "v1", &img);
        let s = scratch();
        puller(&reg)
            .pull(
                &reference(&reg, "team/tool:v1"),
                None,
                &s.rootfs,
                &s.scratch,
            )
            .await
            .unwrap();
        assert_eq!(mode(&s.rootfs.join("suid")), 0o755);
        assert_eq!(mode(&s.rootfs.join("sgid")), 0o755);
        assert_eq!(mode(&s.rootfs.join("sticky")), 0o777);
        assert!(
            !s.rootfs.join("dev/mem").exists(),
            "no device nodes in the rootfs"
        );
    }

    #[tokio::test]
    async fn a_blob_whose_bytes_do_not_match_its_digest_is_refused() {
        let reg = FakeRegistry::start().await;
        let img = Image::new()
            .layer(Layer::new().file("a", 0o644, b"a"), Compression::None)
            .layer(Layer::new().file("b", 0o644, b"b"), Compression::Gzip)
            .build();
        reg.push("team/tool", "v1", &img);
        reg.tamper(&img.layers[1].digest());
        let s = scratch();
        let err = puller(&reg)
            .pull(
                &reference(&reg, "team/tool:v1"),
                None,
                &s.rootfs,
                &s.scratch,
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("served other bytes"), "{err}");
        assert!(
            std::fs::read_dir(&s.scratch).unwrap().next().is_none(),
            "the tampered blob is not left staged"
        );
    }

    #[tokio::test]
    async fn a_reference_pinned_by_digest_must_match_what_the_registry_serves() {
        let reg = FakeRegistry::start().await;
        let img = Image::new()
            .layer(Layer::new().file("a", 0o644, b"a"), Compression::None)
            .build();
        let d = reg.push("team/tool", "v1", &img);
        let other = digest(b"something else");
        // The registry answers the pinned digest with a manifest that hashes differently.
        reg.push("team/tool", &other, &img);
        let s = scratch();
        let err = puller(&reg)
            .pull(
                &reference(&reg, &format!("team/tool@{other}")),
                None,
                &s.rootfs,
                &s.scratch,
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("served other bytes"), "{err}");
        assert_eq!(
            reg.blob_requests(),
            0,
            "nothing fetched after a manifest mismatch"
        );
        let ok = puller(&reg)
            .pull(
                &reference(&reg, &format!("team/tool:v1@{d}")),
                None,
                &s.rootfs,
                &s.scratch,
            )
            .await
            .unwrap();
        assert_eq!(ok.digest, d);
    }

    #[tokio::test]
    async fn an_index_selects_this_platform_and_refuses_without_it() {
        let reg = FakeRegistry::start().await;
        let here = Image::new()
            .layer(Layer::new().file("arch", 0o644, b"here"), Compression::None)
            .build();
        let elsewhere = Image::new()
            .platform("s390x", "linux")
            .layer(
                Layer::new().file("arch", 0o644, b"elsewhere"),
                Compression::None,
            )
            .build();
        reg.push_index("team/tool", "multi", &[&elsewhere, &here]);
        reg.push_index("team/tool", "foreign", &[&elsewhere]);
        let s = scratch();
        let got = puller(&reg)
            .pull(
                &reference(&reg, "team/tool:multi"),
                None,
                &s.rootfs,
                &s.scratch,
            )
            .await
            .unwrap();
        assert_eq!(
            got.digest,
            here.manifest.digest(),
            "the digest is the image's, not the index's"
        );
        assert_eq!(
            std::fs::read_to_string(s.rootfs.join("arch")).unwrap(),
            "here"
        );
        let err = puller(&reg)
            .pull(
                &reference(&reg, "team/tool:foreign"),
                None,
                &s.rootfs,
                &s.scratch,
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("no manifest for linux/"), "{err}");
        let got = puller(&reg)
            .with_platform(Platform {
                os: "linux".into(),
                architecture: "s390x".into(),
            })
            .pull(
                &reference(&reg, "team/tool:foreign"),
                None,
                &s.rootfs,
                &s.scratch,
            )
            .await
            .unwrap();
        assert_eq!(got.digest, elsewhere.manifest.digest());
    }

    #[tokio::test]
    async fn an_unsupported_layer_is_refused_before_any_blob_is_fetched() {
        let reg = FakeRegistry::start().await;
        let img = Image::new()
            .layer(Layer::new().file("a", 0o644, b"a"), Compression::None)
            .layer(
                Layer::new().file("b", 0o644, b"b"),
                Compression::ZstdLabelled,
            )
            .build();
        reg.push("team/tool", "v1", &img);
        let s = scratch();
        let err = puller(&reg)
            .pull(
                &reference(&reg, "team/tool:v1"),
                None,
                &s.rootfs,
                &s.scratch,
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("tar+zstd") && err.contains("not supported"),
            "{err}"
        );
        assert_eq!(reg.blob_requests(), 0);
        assert!(!s.rootfs.join("a").exists());
    }

    #[tokio::test]
    async fn the_bearer_challenge_is_answered_once_and_the_token_reused() {
        let reg = FakeRegistry::start().await;
        reg.require_token(true);
        let img = Image::new()
            .layer(Layer::new().file("a", 0o644, b"a"), Compression::None)
            .layer(Layer::new().file("b", 0o644, b"b"), Compression::None)
            .build();
        reg.push("team/tool", "v1", &img);
        let s = scratch();
        puller(&reg)
            .pull(
                &reference(&reg, "team/tool:v1"),
                None,
                &s.rootfs,
                &s.scratch,
            )
            .await
            .unwrap();
        assert_eq!(reg.token_requests(), 1);
        assert_eq!(std::fs::read_to_string(s.rootfs.join("b")).unwrap(), "b");
    }

    #[tokio::test]
    async fn a_mirror_on_the_operators_pki_is_pulled_with_its_ca_and_refused_without() {
        let reg = FakeRegistry::start_tls().await;
        let img = Image::new()
            .layer(Layer::new().file("a", 0o644, b"a"), Compression::None)
            .build();
        let want = reg.push("team/tool", "v1", &img);
        let ca = reg.ca_pem().expect("a TLS registry has a CA");
        // Not listed as plain: HTTPS, which fails without the CA beside the Mozilla roots.
        let s = scratch();
        let err = Puller::new(&[])
            .unwrap()
            .pull(
                &reference(&reg, "team/tool:v1"),
                None,
                &s.rootfs,
                &s.scratch,
            )
            .await
            .unwrap_err();
        assert!(!format!("{err:#}").contains("http://"), "{err:#}");
        // With it: the pull succeeds (ADR-0029 decision 1, MEDIATORE_REGISTRY_CA).
        let s = scratch();
        let got = Puller::new(&[])
            .unwrap()
            .with_registry_ca(ca.as_bytes())
            .unwrap()
            .pull(
                &reference(&reg, "team/tool:v1"),
                None,
                &s.rootfs,
                &s.scratch,
            )
            .await
            .unwrap();
        assert_eq!(got.digest, want);
        assert_eq!(std::fs::read(s.rootfs.join("a")).unwrap(), b"a");
        // An empty PEM is an error, never the public roots alone in its place.
        assert!(Puller::new(&[]).unwrap().with_registry_ca(b"").is_err());
        assert!(
            Puller::new(&[])
                .unwrap()
                .with_registry_ca(
                    b"-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n"
                )
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_registry_not_listed_as_plain_is_reached_over_https_only() {
        let reg = FakeRegistry::start().await;
        let img = Image::new()
            .layer(Layer::new().file("a", 0o644, b"a"), Compression::None)
            .build();
        reg.push("team/tool", "v1", &img);
        let s = scratch();
        let err = Puller::new(&[])
            .unwrap()
            .pull(
                &reference(&reg, "team/tool:v1"),
                None,
                &s.rootfs,
                &s.scratch,
            )
            .await
            .unwrap_err();
        let chain = format!("{err:#}");
        assert!(
            !chain.contains("http://"),
            "the plain listener must not have been spoken to in the clear: {chain}"
        );
    }

    #[tokio::test]
    async fn a_credential_is_presented_at_the_token_endpoint_and_nowhere_else() {
        let reg = FakeRegistry::start().await;
        let password = fresh_password();
        reg.require_credential("octocat", &password);
        let img = Image::new()
            .layer(Layer::new().file("a", 0o644, b"a"), Compression::None)
            .build();
        reg.push("team/tool", "v1", &img);
        let s = scratch();
        let err = puller(&reg)
            .pull(
                &reference(&reg, "team/tool:v1"),
                None,
                &s.rootfs,
                &s.scratch,
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("no credential configured"), "{err}");
        let cred = credential(&reg, "octocat", &password);
        puller(&reg)
            .credentials_over_plain_http_for_tests()
            .pull(
                &reference(&reg, "team/tool:v1"),
                Some(&cred),
                &s.rootfs,
                &s.scratch,
            )
            .await
            .unwrap();
        assert_eq!(
            reg.token_requests(),
            2,
            "one refused anonymous, one with the credential"
        );
        assert_eq!(
            reg.basic_on_content(),
            0,
            "the credential goes to the realm, not the blobs"
        );
        assert_eq!(std::fs::read_to_string(s.rootfs.join("a")).unwrap(), "a");
    }

    #[tokio::test]
    async fn a_wrong_credential_is_refused_by_the_registry_not_retried() {
        let reg = FakeRegistry::start().await;
        let password = fresh_password();
        reg.require_credential("octocat", &password);
        let img = Image::new()
            .layer(Layer::new().file("a", 0o644, b"a"), Compression::None)
            .build();
        reg.push("team/tool", "v1", &img);
        let s = scratch();
        let wrong = fresh_password();
        let cred = credential(&reg, "octocat", &wrong);
        let err = puller(&reg)
            .credentials_over_plain_http_for_tests()
            .pull(
                &reference(&reg, "team/tool:v1"),
                Some(&cred),
                &s.rootfs,
                &s.scratch,
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("credential was presented"), "{err}");
        assert!(
            !err.contains("wrong"),
            "the password is not in the error: {err}"
        );
        assert_eq!(reg.token_requests(), 1);
    }

    #[tokio::test]
    async fn a_basic_challenge_gets_the_credential_directly() {
        let reg = FakeRegistry::start().await;
        let password = fresh_password();
        reg.basic_only("octocat", &password);
        let img = Image::new()
            .layer(Layer::new().file("a", 0o644, b"a"), Compression::None)
            .layer(Layer::new().file("b", 0o644, b"b"), Compression::Gzip)
            .build();
        reg.push("team/tool", "v1", &img);
        let s = scratch();
        let err = puller(&reg)
            .pull(
                &reference(&reg, "team/tool:v1"),
                None,
                &s.rootfs,
                &s.scratch,
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("carries none"), "{err}");
        let cred = credential(&reg, "octocat", &password);
        puller(&reg)
            .credentials_over_plain_http_for_tests()
            .pull(
                &reference(&reg, "team/tool:v1"),
                Some(&cred),
                &s.rootfs,
                &s.scratch,
            )
            .await
            .unwrap();
        assert_eq!(reg.token_requests(), 0);
        assert_eq!(std::fs::read_to_string(s.rootfs.join("b")).unwrap(), "b");
    }

    #[tokio::test]
    async fn a_credential_never_crosses_plain_http_and_never_goes_to_another_host() {
        let reg = FakeRegistry::start().await;
        let password = fresh_password();
        let img = Image::new()
            .layer(Layer::new().file("a", 0o644, b"a"), Compression::None)
            .build();
        reg.push("team/tool", "v1", &img);
        let s = scratch();
        let cred = credential(&reg, "octocat", &password);
        // The registry is listed as plain HTTP: the credential is refused before a request.
        let err = puller(&reg)
            .pull(
                &reference(&reg, "team/tool:v1"),
                Some(&cred),
                &s.rootfs,
                &s.scratch,
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("never crosses plain HTTP"), "{err}");
        assert_eq!(reg.requests(), 0, "nothing was asked");
        // A credential for another host is a broker bug, refused the same way.
        let other = RegistryCredential {
            host: "ghcr.io".into(),
            username: "octocat".into(),
            password: Secret(password.clone()),
        };
        let err = Puller::new(&[])
            .unwrap()
            .pull(
                &reference(&reg, "team/tool:v1"),
                Some(&other),
                &s.rootfs,
                &s.scratch,
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("is for ghcr.io"), "{err}");
        assert_eq!(reg.requests(), 0);
    }

    /// Pulls a real image from a real registry. Set `MEDIATORE_PULL_IMAGE` to a reference
    /// (`docker.io/library/busybox:1.37`); the test fails, never skips, without it.
    #[tokio::test]
    #[ignore = "needs the network: MEDIATORE_PULL_IMAGE=docker.io/library/busybox:1.37"]
    async fn a_real_image_pulls_from_its_registry() {
        let image = std::env::var("MEDIATORE_PULL_IMAGE").unwrap_or_else(|_| {
            panic!("set MEDIATORE_PULL_IMAGE to an image reference, e.g. docker.io/library/busybox:1.37")
        });
        let s = scratch();
        let got = Puller::new(&[])
            .unwrap()
            .pull(&r(&image), None, &s.rootfs, &s.scratch)
            .await
            .unwrap();
        assert!(is_digest(&got.digest));
        assert!(got.layers >= 1 && got.bytes > 0);
        assert!(
            std::fs::read_dir(&s.rootfs).unwrap().next().is_some(),
            "the rootfs has content"
        );
        eprintln!(
            "pulled {image} as {} ({} layers, {} bytes)",
            got.digest, got.layers, got.bytes
        );
    }

    // ----- the relay reach (ADR-0038): a declared registry is dialled at the gateway ---------------------------------

    const GATEWAY: &str = "127.0.0.1";

    fn relay_entry(host: &str, port: u16) -> RelayRegistry {
        RelayRegistry {
            host: host.into(),
            port,
        }
    }

    fn port_of(reg: &FakeRegistry) -> u16 {
        reg.host().rsplit(':').next().unwrap().parse().unwrap()
    }

    fn relay_puller(plain: &[&str], entries: &[RelayRegistry]) -> Puller {
        let plain: Vec<String> = plain.iter().map(|s| (*s).to_string()).collect();
        Puller::new(&plain)
            .unwrap()
            .with_relay_registries(GATEWAY.parse().unwrap(), entries)
            .unwrap()
    }

    fn one_layer_image() -> mediatore_testkit::registry::Built {
        Image::new()
            .layer(Layer::new().file("a", 0o644, b"a"), Compression::None)
            .build()
    }

    #[test]
    fn the_relay_registries_variable_is_host_equals_port_pairs() {
        let got = parse_relay_registries("registry.example=3132, Mirror.Example=3133").unwrap();
        assert_eq!(
            got,
            vec![
                relay_entry("registry.example", 3132),
                relay_entry("mirror.example", 3133)
            ],
            "hosts are lower-cased, whitespace around a pair is dropped"
        );
        assert_eq!(parse_relay_registries("").unwrap(), Vec::new());
        for bad in [
            "registry.example",
            "registry.example=",
            "=3132",
            "registry.example=0",
            "registry.example=70000",
            "registry.example=x",
            "registry.example:443=3132",
            "registry.example=3132,registry.example=3133",
            "a b=3132",
        ] {
            assert!(
                parse_relay_registries(bad).is_err(),
                "{bad:?} is refused, never half-read"
            );
        }
    }

    #[test]
    fn a_declared_host_is_routed_to_its_leg_port_and_keeps_its_own_name() {
        let p = relay_puller(&[], &[relay_entry("registry.example", 3132)]);
        let r = p
            .route("https://registry.example/v2/team/tool/manifests/v1?a=b")
            .unwrap();
        assert_eq!(
            r.url, "https://registry.example:3132/v2/team/tool/manifests/v1?a=b",
            "same name (the SNI and the certificate check), the leg's port"
        );
        assert_eq!(r.host_header.as_deref(), Some("registry.example"));
        assert!(r.via_relay);
        let r = p.route("https://Registry.Example:443/token").unwrap();
        assert_eq!(r.url, "https://registry.example:3132/token");
        assert_eq!(r.host_header.as_deref(), Some("registry.example"));
        let other = p.route("https://other.example/v2/").unwrap();
        assert_eq!(
            other.url, "https://other.example/v2/",
            "an undeclared host is dialled as before"
        );
        assert!(other.host_header.is_none() && !other.via_relay);
    }

    #[tokio::test]
    async fn a_declared_registry_is_pulled_through_the_gateway_with_its_own_host_header() {
        let reg = FakeRegistry::start().await;
        reg.require_token(true);
        reg.push("team/tool", "v1", &one_layer_image());
        let s = scratch();
        let puller = relay_puller(
            &["registry.relay.test"],
            &[relay_entry("registry.relay.test", port_of(&reg))],
        );
        puller
            .pull(
                &r("registry.relay.test/team/tool:v1"),
                None,
                &s.rootfs,
                &s.scratch,
            )
            .await
            .unwrap();
        assert_eq!(std::fs::read_to_string(s.rootfs.join("a")).unwrap(), "a");
        let seen = reg.hosts_seen();
        let by_name = seen.iter().filter(|h| *h == "registry.relay.test").count();
        assert!(
            by_name >= 3,
            "the manifest (twice, around the challenge) and the blobs carry the registry's own name: {seen:?}"
        );
        assert!(
            seen.iter()
                .all(|h| h == "registry.relay.test" || *h == reg.host()),
            "the one other request is the fake's token realm, which names itself: {seen:?}"
        );
    }

    #[tokio::test]
    async fn a_redirect_from_a_declared_host_to_an_undeclared_one_fails_the_pull() {
        let reg = FakeRegistry::start().await;
        reg.push("team/tool", "v1", &one_layer_image());
        reg.redirect_blobs_to("http://content.elsewhere.test");
        let s = scratch();
        let puller = relay_puller(
            &["registry.relay.test"],
            &[relay_entry("registry.relay.test", port_of(&reg))],
        );
        let err = puller
            .pull(
                &r("registry.relay.test/team/tool:v1"),
                None,
                &s.rootfs,
                &s.scratch,
            )
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("content.elsewhere.test")
                && err.contains("not declared")
                && err.contains("MEDIATORE_RELAY_REGISTRIES"),
            "the refusal names the host and the setting: {err}"
        );
    }

    #[tokio::test]
    async fn a_redirect_to_another_declared_host_is_followed_through_the_gateway_and_drops_the_token()
     {
        let reg = FakeRegistry::start().await;
        reg.require_token(true);
        let content = FakeRegistry::start().await;
        let img = one_layer_image();
        reg.push("team/tool", "v1", &img);
        content.push("team/tool", "v1", &img);
        reg.redirect_blobs_to("http://content.relay.test");
        let s = scratch();
        let puller = relay_puller(
            &["registry.relay.test", "content.relay.test"],
            &[
                relay_entry("registry.relay.test", port_of(&reg)),
                relay_entry("content.relay.test", port_of(&content)),
            ],
        );
        puller
            .pull(
                &r("registry.relay.test/team/tool:v1"),
                None,
                &s.rootfs,
                &s.scratch,
            )
            .await
            .unwrap();
        assert_eq!(std::fs::read_to_string(s.rootfs.join("a")).unwrap(), "a");
        assert!(
            content.blob_requests() >= 1,
            "the layer came from the content host"
        );
        assert_eq!(
            content.bearer_seen(),
            0,
            "the registry's token does not follow a redirect to another host"
        );
        assert!(
            content
                .hosts_seen()
                .iter()
                .all(|h| h == "content.relay.test"),
            "{:?}",
            content.hosts_seen()
        );
    }

    #[tokio::test]
    async fn a_registry_that_is_not_declared_is_pulled_as_before_redirects_included() {
        let reg = FakeRegistry::start().await;
        let content = FakeRegistry::start().await;
        let img = one_layer_image();
        reg.push("team/tool", "v1", &img);
        content.push("team/tool", "v1", &img);
        reg.redirect_blobs_to(&format!("http://{}", content.host()));
        let s = scratch();
        let puller = relay_puller(
            &[&reg.host(), &content.host()],
            &[relay_entry("registry.relay.test", 3132)],
        );
        puller
            .pull(
                &reference(&reg, "team/tool:v1"),
                None,
                &s.rootfs,
                &s.scratch,
            )
            .await
            .unwrap();
        assert!(
            content.blob_requests() >= 1,
            "the redirect was followed directly"
        );
    }
}
