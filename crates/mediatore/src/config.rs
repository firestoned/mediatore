// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Server configuration (`mediatore.yaml`).

use std::path::{Path, PathBuf};

use mediatore_entra::{Backend, IssuerConfig};
use mediatore_proto::image::canonical_registry;
use mediatore_proto::{Endpoint, EndpointRule};
use mediatore_store::seal::TransitConfig;
use serde::Deserialize;

/// One downstream audience and which backend serves it.
#[derive(Debug, Clone, Deserialize)]
pub struct AudienceConfig {
    /// Audience value as written into `aud`.
    pub name: String,
    /// Backend that mints for it.
    pub via: Backend,
    /// Maximum token lifetime in seconds (default 900).
    #[serde(default = "default_max_ttl")]
    pub max_ttl: i64,
    /// Where the workload reaches this audience's API from the jail: `host:port` pairs the
    /// guest admits for the sandbox uid, returned by `GET /v1/me` (ADR-0020). Empty means
    /// tokens with nowhere to spend them: the jail reaches the broker only.
    #[serde(default, deserialize_with = "endpoints")]
    pub egress: Vec<Endpoint>,
    /// What the workload may ask of this audience through the egress proxy (ADR-0025
    /// decision 4): `{ method, path }` rules in nono's `endpoint_rules` shape, `method` an
    /// HTTP method or `*`, `path` a glob (`*` one segment, `**` zero or more). Empty admits
    /// every method and path; once any rule exists, a request outside them is refused.
    #[serde(default)]
    pub rules: Vec<EndpointRule>,
    /// A PEM file of CA certificates the egress proxy trusts for this audience's endpoints
    /// instead of the Mozilla roots (ADR-0025 amended): an upstream on a private PKI. Read
    /// at start, refused if it holds no certificate, carried to the guest on the route.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
}

fn default_max_ttl() -> i64 {
    900
}

/// `host:port` strings into endpoints; one malformed entry fails the whole config.
fn endpoints<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<Endpoint>, D::Error> {
    let raw: Vec<String> = Vec::deserialize(d)?;
    raw.iter()
        .map(|s| s.parse::<Endpoint>().map_err(serde::de::Error::custom))
        .collect()
}

/// A registry the pool's images live in and the operator's credential for pulling from it
/// (ADR-0022): handed by `GET /v1/me` to the guest whose claim names that registry.
#[derive(Debug, Clone, Deserialize)]
pub struct RegistryConfig {
    /// The registry as a reference names it (`ghcr.io`, `registry.internal:5000`,
    /// `docker.io`).
    pub host: String,
    /// The login.
    pub username: String,
    /// File holding the password or token, read at start.
    pub password_file: PathBuf,
}

/// STS signing material.
#[derive(Debug, Clone, Deserialize)]
pub struct StsConfig {
    /// `iss` for self-issued tokens.
    pub issuer: String,
    /// Key id written into the JWS header.
    pub kid: String,
    /// PEM file with the EC P-256 private key. The public JWKS is derived from it.
    pub signing_key_file: PathBuf,
}

/// Listeners.
#[derive(Debug, Clone, Deserialize)]
pub struct ListenConfig {
    /// User-facing HTTPS (terminated upstream by Traefik) or plain HTTP in dev.
    #[serde(default = "default_user_addr")]
    pub user: String,
    /// Sandbox-facing mTLS listener.
    #[serde(default = "default_sandbox_addr")]
    pub sandbox: String,
}

fn default_user_addr() -> String {
    "0.0.0.0:8080".into()
}
fn default_sandbox_addr() -> String {
    "0.0.0.0:8443".into()
}

/// Where entries are declared (ADR-0006): the cluster that hosts the downstream SPIRE
/// server's controller manager.
#[derive(Debug, Clone, Deserialize)]
pub struct EntriesSection {
    /// `spec.className` on every `ClusterStaticEntry`; must equal the controller manager's
    /// class (the hardened chart ignores classless resources).
    pub class_name: String,
    /// Kubeconfig for that cluster; unset means in-cluster (the homelab collapse).
    #[serde(default)]
    pub kubeconfig: Option<PathBuf>,
    /// Seconds a declaration may take to become `set` before the bind fails (default 30).
    #[serde(default = "default_ready_timeout_secs")]
    pub ready_timeout_secs: u64,
    /// `x509SVIDTTL` on claim entries (default `1h`; admission caps it at `4h`).
    #[serde(default = "default_claim_svid_ttl")]
    pub claim_svid_ttl: String,
}

fn default_ready_timeout_secs() -> u64 {
    30
}
fn default_claim_svid_ttl() -> String {
    "1h".into()
}

impl From<&EntriesSection> for mediatore_spire::EntriesConfig {
    fn from(e: &EntriesSection) -> Self {
        Self {
            class_name: e.class_name.clone(),
            ready_timeout: std::time::Duration::from_secs(e.ready_timeout_secs),
            claim_svid_ttl: e.claim_svid_ttl.clone(),
        }
    }
}

/// SPIRE-facing configuration. Required outside `dev_mode`.
#[derive(Debug, Clone, Deserialize)]
pub struct SpireConfig {
    /// Workload API socket the broker fetches its own SVID from (ADR-0007), e.g.
    /// `unix:///run/spire/sockets/spire-agent.sock`.
    pub workload_api_socket: String,
    /// Registration entries.
    pub entries: EntriesSection,
}

/// The claim watcher (ADR-0011). Runs only outside `dev_mode`; every field has a default.
// The `_secs` suffix is the unit, part of the config file's contract (as in `EntriesSection`).
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, Deserialize)]
pub struct WatcherSection {
    /// Seconds between resyncs: records whose claim is gone are released and orphan
    /// entries swept (default 300).
    #[serde(default = "default_resync_secs")]
    pub resync_secs: u64,
    /// Seconds a `Bound` claim may stay unresolved (no certificate, no registered node)
    /// before it is failed and deleted (default 60).
    #[serde(default = "default_resolve_timeout_secs")]
    pub resolve_timeout_secs: u64,
    /// Lease duration in seconds for leader election; renewed every third (default 15).
    #[serde(default = "default_lease_duration_secs")]
    pub lease_duration_secs: u64,
}

fn default_resync_secs() -> u64 {
    300
}
fn default_resolve_timeout_secs() -> u64 {
    60
}
fn default_lease_duration_secs() -> u64 {
    15
}

impl Default for WatcherSection {
    fn default() -> Self {
        Self {
            resync_secs: default_resync_secs(),
            resolve_timeout_secs: default_resolve_timeout_secs(),
            lease_duration_secs: default_lease_duration_secs(),
        }
    }
}

/// `AgentSandbox` resources the user API creates (ADR-0008 decision 4).
#[derive(Debug, Clone, Deserialize)]
pub struct SandboxesSection {
    /// Namespace `POST /v1/claims` creates sandboxes in. The `VirtualMachinePool` a request
    /// names must live there (the claim's `poolRef` is a same-namespace reference).
    #[serde(default = "default_sandbox_namespace")]
    pub namespace: String,
}

fn default_sandbox_namespace() -> String {
    "sandboxes".into()
}

impl Default for SandboxesSection {
    fn default() -> Self {
        Self {
            namespace: default_sandbox_namespace(),
        }
    }
}

/// notaio's policy bundles, read, verified and compared with each sandbox in shadow
/// (ADR-0026). Absent, the broker reads no bundle and compares nothing.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicySection {
    /// The keys notaio signs bundles with (decision 2): from this file only, never from the
    /// cluster. List two versions of the key while notaio re-signs during a rotation.
    #[serde(default)]
    pub trusted_keys: Vec<mediatore_policy::TrustedKey>,
    /// Namespaces whose bundle `ConfigMap`s are read (decision 3). Empty means
    /// `[sandboxes.namespace]`, filled in at load.
    #[serde(default)]
    pub namespaces: Vec<String>,
}

/// The wrapping key for refresh material (ADR-0012 decision 3): exactly one of the local
/// key file (the homelab shape) or `OpenBao` transit (the work shape, ADR-0015).
#[derive(Debug, Clone, Deserialize)]
pub struct SealingSection {
    /// File holding the 32-byte key (raw, or 64 hex characters): a Secret volume. Read at
    /// startup; a missing or malformed key stops the process.
    #[serde(default)]
    pub key_file: Option<PathBuf>,
    /// `OpenBao` transit: the key stays there, the broker logs in as its `ServiceAccount`.
    #[serde(default)]
    pub transit: Option<TransitConfig>,
}

/// The claim store (ADR-0012). Outside `dev_mode` a URL is required; `MEDIATORE_STORE_URL`
/// in the environment overrides `url` so the PostgreSQL password can live in a Secret.
// The `_secs` suffix is the unit, part of the config file's contract (as in `EntriesSection`).
#[allow(clippy::struct_field_names)]
#[derive(Debug, Clone, Deserialize)]
pub struct StoreSection {
    /// `sqlite:///path/to/store.db?mode=rwc` (one replica only) or
    /// `postgres://user:password@host:5432/db?sslmode=verify-full`. Unset under `dev_mode`
    /// means the in-memory store.
    #[serde(default)]
    pub url: Option<String>,
    /// Seconds a claim row outlives its claim before the resync sweeps it into the audit
    /// table (default 3600).
    #[serde(default = "default_retention_secs")]
    pub retention_secs: u64,
    /// Connection pool size (default 8; a memory SQLite always gets 1).
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    /// The local sealer's key. Unset means refresh material cannot be persisted, which
    /// fails the claim that needs it rather than storing plaintext.
    #[serde(default)]
    pub sealing: Option<SealingSection>,
}

fn default_retention_secs() -> u64 {
    3600
}
fn default_max_connections() -> u32 {
    8
}

impl Default for StoreSection {
    fn default() -> Self {
        Self {
            url: None,
            retention_secs: default_retention_secs(),
            max_connections: default_max_connections(),
            sealing: None,
        }
    }
}

/// `POST /v1/token` limits (ADR-0013 decision 5).
#[derive(Debug, Clone, Deserialize)]
pub struct TokenSection {
    /// Issues one claim may ask for per minute, and the burst it may spend at once
    /// (default 10). Checked before any upstream refresh.
    #[serde(default = "default_rate_per_minute")]
    pub rate_per_minute: u32,
}

fn default_rate_per_minute() -> u32 {
    10
}

impl Default for TokenSection {
    fn default() -> Self {
        Self {
            rate_per_minute: default_rate_per_minute(),
        }
    }
}

/// Top-level config.
#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// SPIFFE trust domain.
    pub trust_domain: String,
    /// SPIRE: own identity and entries. Optional only in `dev_mode`.
    #[serde(default)]
    pub spire: Option<SpireConfig>,
    /// Trusted upstream issuers.
    pub issuers: Vec<IssuerConfig>,
    /// Audiences mediatore will mint for.
    pub audiences: Vec<AudienceConfig>,
    /// STS material; required when any audience uses `sts`.
    #[serde(default)]
    pub sts: Option<StsConfig>,
    /// Pull credentials, one per registry (ADR-0022). Empty means every pull is anonymous.
    #[serde(default)]
    pub registries: Vec<RegistryConfig>,
    /// Listeners.
    #[serde(default = "default_listen")]
    pub listen: ListenConfig,
    /// Accept a peer-identity header instead of mTLS and use the in-memory store.
    #[serde(default)]
    pub dev_mode: bool,
    /// Claim watcher timings (ADR-0011).
    #[serde(default)]
    pub watcher: WatcherSection,
    /// Where the user API's sandboxes go (ADR-0008).
    #[serde(default)]
    pub sandboxes: SandboxesSection,
    /// The claim store (ADR-0012).
    #[serde(default)]
    pub store: StoreSection,
    /// Token issuance limits (ADR-0013).
    #[serde(default)]
    pub token: TokenSection,
    /// notaio's policy bundles, in shadow (ADR-0026). Absent: none of it.
    #[serde(default)]
    pub policy: Option<PolicySection>,
}

fn default_listen() -> ListenConfig {
    ListenConfig {
        user: default_user_addr(),
        sandbox: default_sandbox_addr(),
    }
}

impl Config {
    /// The egress proxy chooses the token by the endpoint a request names (ADR-0025
    /// decision 4), so an endpoint may belong to one audience only; and a rule must be
    /// a method or `*` with an absolute path.
    fn check_routes(&self) -> anyhow::Result<()> {
        let mut owner: std::collections::BTreeMap<&Endpoint, &str> =
            std::collections::BTreeMap::new();
        for a in &self.audiences {
            for e in &a.egress {
                if let Some(other) = owner.insert(e, &a.name)
                    && other != a.name
                {
                    anyhow::bail!(
                        "egress endpoint {e} is declared by audiences {other:?} and {:?}: the egress proxy must choose one token per endpoint (ADR-0025)",
                        a.name
                    );
                }
            }
            for r in &a.rules {
                let method_ok = r.method == "*"
                    || (!r.method.is_empty() && r.method.chars().all(|c| c.is_ascii_alphabetic()));
                if !method_ok || !r.path.starts_with('/') {
                    anyhow::bail!(
                        "audience {:?}: rule {{ method: {:?}, path: {:?} }} needs an HTTP method or `*` and an absolute path glob",
                        a.name,
                        r.method,
                        r.path
                    );
                }
            }
        }
        Ok(())
    }

    /// One credential per registry host, Docker Hub's two names being one host.
    fn check_registries(&self) -> anyhow::Result<()> {
        let mut seen = std::collections::BTreeSet::new();
        for r in &self.registries {
            let host = r.host.trim();
            if host.is_empty() || host.contains('/') || host != r.host {
                anyhow::bail!(
                    "registries[].host must be a registry host (host[:port]), got {:?}",
                    r.host
                );
            }
            if r.username.trim().is_empty() {
                anyhow::bail!("registries[{host}].username must not be empty");
            }
            if !seen.insert(canonical_registry(host)) {
                anyhow::bail!(
                    "registries: {host} is listed twice (docker.io and registry-1.docker.io are one host)"
                );
            }
        }
        Ok(())
    }

    /// Load and sanity-check. `MEDIATORE_STORE_URL` in the environment overrides `store.url`.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Self::parse_with_store_url(&text, std::env::var("MEDIATORE_STORE_URL").ok())
    }

    /// Parse YAML and enforce the cross-field rules, with nothing from the environment.
    #[cfg(test)]
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        Self::parse_with_store_url(text, None)
    }

    /// [`Self::parse`] with `store_url` taking precedence over the file's `store.url`.
    pub fn parse_with_store_url(text: &str, store_url: Option<String>) -> anyhow::Result<Self> {
        let mut cfg: Self = serde_saphyr::from_str(text)?;
        if let Some(url) = store_url.filter(|u| !u.trim().is_empty()) {
            cfg.store.url = Some(url);
        }
        if cfg.audiences.iter().any(|a| a.via == Backend::Sts) && cfg.sts.is_none() {
            anyhow::bail!("an audience uses the sts backend but no `sts` section is configured");
        }
        cfg.check_registries()?;
        cfg.check_routes()?;
        cfg.check_entra()?;
        if !cfg.dev_mode && cfg.spire.is_none() {
            anyhow::bail!("`spire` (workload_api_socket, entries) is required outside dev_mode");
        }
        if cfg.dev_mode && !is_loopback(&cfg.listen.sandbox) {
            anyhow::bail!(
                "dev_mode accepts a peer-identity header, so listen.sandbox must be a loopback address (ADR-0007); got {}",
                cfg.listen.sandbox
            );
        }
        if cfg.watcher.resync_secs == 0
            || cfg.watcher.resolve_timeout_secs == 0
            || cfg.watcher.lease_duration_secs < 3
        {
            anyhow::bail!(
                "watcher.resync_secs and resolve_timeout_secs must be positive and lease_duration_secs at least 3"
            );
        }
        if cfg.sandboxes.namespace.trim().is_empty() {
            anyhow::bail!("sandboxes.namespace must not be empty");
        }
        if let Some(e) = cfg.spire.as_ref().map(|s| &s.entries) {
            if e.class_name.trim().is_empty() {
                anyhow::bail!("spire.entries.class_name must not be empty");
            }
            if e.ready_timeout_secs == 0 {
                anyhow::bail!("spire.entries.ready_timeout_secs must be positive");
            }
        }
        cfg.check_store()?;
        cfg.check_policy()?;
        if cfg.token.rate_per_minute == 0 {
            anyhow::bail!("token.rate_per_minute must be positive");
        }
        if let Some(i) = cfg
            .issuers
            .iter()
            .find(|i| i.session.is_some() || i.entra.is_some())
            && cfg.store.sealing.is_none()
        {
            anyhow::bail!(
                "issuer {} requires a delegated session, which is sealed before it is stored: set store.sealing.key_file or store.sealing.transit (ADR-0013, ADR-0015)",
                i.url
            );
        }
        if let Some(sealing) = &cfg.store.sealing {
            match (&sealing.key_file, &sealing.transit) {
                (Some(_), Some(_)) => {
                    anyhow::bail!("store.sealing takes key_file or transit, not both (ADR-0015)")
                }
                (None, None) => {
                    anyhow::bail!("store.sealing needs key_file or transit (ADR-0015)")
                }
                (None, Some(t)) if !cfg.dev_mode && !t.url.starts_with("https://") => {
                    anyhow::bail!(
                        "store.sealing.transit.url must be https outside dev_mode (ADR-0015); got {}",
                        t.url
                    );
                }
                _ => {}
            }
        }
        Ok(cfg)
    }
}

impl Config {
    /// ADR-0026 decisions 2 and 3: at least one key, every key a well-formed Ed25519 key with
    /// an id of its own, and namespaces that are Kubernetes names, listed once. Fills in the
    /// default namespace. A `policy` section without keys is refused rather than read as "off":
    /// leaving the section out is how the broker is told to read no bundle.
    fn check_policy(&mut self) -> anyhow::Result<()> {
        let default_ns = self.sandboxes.namespace.clone();
        let Some(policy) = self.policy.as_mut() else {
            return Ok(());
        };
        if policy.trusted_keys.is_empty() {
            anyhow::bail!(
                "policy.trusted_keys must list notaio's signing key; leave the `policy` section out to read no bundle (ADR-0026)"
            );
        }
        mediatore_policy::trusted_keys(&policy.trusted_keys)
            .map_err(|e| anyhow::anyhow!("policy.trusted_keys: {e} (ADR-0026)"))?;
        if policy.namespaces.is_empty() {
            policy.namespaces.push(default_ns);
        }
        let mut seen = std::collections::BTreeSet::new();
        for ns in &policy.namespaces {
            if !is_dns_label(ns) {
                anyhow::bail!("policy.namespaces: {ns:?} is not a Kubernetes namespace name");
            }
            if !seen.insert(ns.as_str()) {
                anyhow::bail!("policy.namespaces: {ns} is listed twice");
            }
        }
        Ok(())
    }

    /// ADR-0012 decision 2: a real store outside `dev_mode`, PostgreSQL only over TLS the
    /// client verifies, and no memory SQLite (as lossy as the in-memory store).
    fn check_store(&self) -> anyhow::Result<()> {
        use mediatore_store::sql::{Engine, is_memory_sqlite};
        if self.store.max_connections == 0 {
            anyhow::bail!("store.max_connections must be positive");
        }
        let Some(url) = self.store.url.as_deref() else {
            if self.dev_mode {
                return Ok(());
            }
            anyhow::bail!(
                "store.url (or MEDIATORE_STORE_URL) is required outside dev_mode: the in-memory store does not survive a restart (ADR-0012)"
            );
        };
        let Some(engine) = Engine::of(url) else {
            anyhow::bail!("store.url: unsupported scheme; use sqlite: or postgres:");
        };
        if self.dev_mode {
            return Ok(());
        }
        if is_memory_sqlite(url) {
            anyhow::bail!(
                "store.url: a memory SQLite is as lossy as the in-memory store; give it a file"
            );
        }
        if engine == Engine::Postgres && !url.contains("sslmode=verify-full") {
            anyhow::bail!(
                "store.url: PostgreSQL is reached only over TLS the client verifies; the URL must carry sslmode=verify-full (ADR-0012)"
            );
        }
        Ok(())
    }
}

impl Config {
    /// ADR-0016: an Entra issuer is `entra-obo` with an `entra` block and no `session`,
    /// its credential is exactly one of the three shapes, transit is `https` outside
    /// `dev_mode`, and an `entra-obo` audience has an Entra issuer to be minted from.
    fn check_entra(&self) -> anyhow::Result<()> {
        for issuer in &self.issuers {
            match (issuer.backend, &issuer.entra) {
                (Backend::EntraObo, None) => anyhow::bail!(
                    "issuer {}: the entra-obo backend needs an `entra` section (ADR-0016)",
                    issuer.url
                ),
                (Backend::Sts, Some(_)) => anyhow::bail!(
                    "issuer {}: an `entra` section needs backend entra-obo",
                    issuer.url
                ),
                _ => {}
            }
            let Some(entra) = &issuer.entra else {
                continue;
            };
            if issuer.session.is_some() {
                anyhow::bail!(
                    "issuer {}: `entra` and `session` are exclusive: the Entra session comes from the exchange, not from the caller",
                    issuer.url
                );
            }
            entra
                .validate()
                .map_err(|e| anyhow::anyhow!("issuer {}: entra: {e}", issuer.url))?;
            if let Some(t) = &entra.transit
                && !self.dev_mode
                && !t.url.starts_with("https://")
            {
                anyhow::bail!(
                    "issuer {}: entra.transit.url must be https outside dev_mode; got {}",
                    issuer.url,
                    t.url
                );
            }
        }
        if self.audiences.iter().any(|a| a.via == Backend::EntraObo)
            && !self.issuers.iter().any(|i| i.entra.is_some())
        {
            anyhow::bail!(
                "an audience uses the entra-obo backend but no issuer has an `entra` section"
            );
        }
        Ok(())
    }
}

/// An RFC 1123 label, which is what a namespace name must be.
fn is_dns_label(s: &str) -> bool {
    (1..=63).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !s.starts_with('-')
        && !s.ends_with('-')
}

/// True only for a literal loopback socket address: a hostname, even `localhost`, is not
/// enough to know where the listener ends up.
fn is_loopback(addr: &str) -> bool {
    addr.parse::<std::net::SocketAddr>()
        .is_ok_and(|a| a.ip().is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "trust_domain: sandbox.test
issuers: []
audiences: []
listen: { user: 127.0.0.1:8080, sandbox: 127.0.0.1:8443 }
";

    #[test]
    fn an_audience_declares_where_the_jail_reaches_it() {
        let cfg = Config::parse(
            "trust_domain: sandbox.test\nissuers: []\nlisten: { user: 127.0.0.1:8080, sandbox: 127.0.0.1:8443 }\ndev_mode: true\nsts: { issuer: https://mediatore.test, kid: k, signing_key_file: /k }\naudiences:\n  - { name: grafana.home.example, via: sts, egress: [\"grafana.home.example:443\", \"[2001:db8::1]:8443\"] }\n  - { name: api://trading-data, via: sts }\n",
        )
        .unwrap();
        let hosts: Vec<String> = cfg.audiences[0]
            .egress
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(hosts, ["grafana.home.example:443", "[2001:db8::1]:8443"]);
        assert_eq!(
            cfg.audiences[1].egress,
            Vec::<Endpoint>::new(),
            "no egress declared: the jail reaches the broker only"
        );
    }

    #[test]
    fn a_malformed_egress_entry_fails_the_config() {
        let err = Config::parse(
            "trust_domain: sandbox.test\nissuers: []\nlisten: { user: 127.0.0.1:8080, sandbox: 127.0.0.1:8443 }\ndev_mode: true\naudiences:\n  - { name: grafana.home.example, via: sts, egress: [\"grafana.home.example\"] }\n",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("host:port"), "{err}");
    }

    #[test]
    fn rules_are_parsed_per_audience_and_default_to_none() {
        let cfg = Config::parse(
            "trust_domain: sandbox.test\nissuers: []\nlisten: { user: 127.0.0.1:8080, sandbox: 127.0.0.1:8443 }\ndev_mode: true\nsts: { issuer: https://mediatore.test, kid: k, signing_key_file: /k }\naudiences:\n  - name: internal-git\n    via: sts\n    egress: [\"git.home.example:443\"]\n    rules:\n      - { method: GET, path: \"/platform/**\" }\n      - { method: \"*\", path: \"/platform/*/git-receive-pack\" }\n  - { name: grafana.home.example, via: sts, egress: [\"grafana.home.example:443\"] }\n",
        )
        .unwrap();
        assert_eq!(cfg.audiences[0].rules.len(), 2);
        assert_eq!(cfg.audiences[0].rules[0].method, "GET");
        assert_eq!(cfg.audiences[0].rules[1].method, "*");
        assert_eq!(
            cfg.audiences[1].rules,
            Vec::<EndpointRule>::new(),
            "no rules: every method and path at that audience's endpoints"
        );
    }

    #[test]
    fn an_audience_may_name_the_ca_file_of_its_private_pki() {
        let cfg = Config::parse(
            "trust_domain: sandbox.test\nissuers: []\nlisten: { user: 127.0.0.1:8080, sandbox: 127.0.0.1:8443 }\ndev_mode: true\nsts: { issuer: https://mediatore.test, kid: k, signing_key_file: /k }\naudiences:\n  - { name: internal-git, via: sts, egress: [\"git.home.example:443\"], ca_file: /etc/mediatore-cas/home.pem }\n  - { name: public, via: sts, egress: [\"api.example.com:443\"] }\n",
        )
        .unwrap();
        assert_eq!(
            cfg.audiences[0].ca_file.as_deref(),
            Some(std::path::Path::new("/etc/mediatore-cas/home.pem"))
        );
        assert_eq!(cfg.audiences[1].ca_file, None, "no file: the Mozilla roots");
    }

    #[test]
    fn a_rule_without_a_method_or_an_absolute_path_fails_the_config() {
        for bad in [
            "{ method: \"\", path: \"/x\" }",
            "{ method: GET, path: \"x\" }",
            "{ method: \"G ET\", path: \"/x\" }",
        ] {
            let err = Config::parse(&format!(
                "trust_domain: sandbox.test\nissuers: []\nlisten: {{ user: 127.0.0.1:8080, sandbox: 127.0.0.1:8443 }}\ndev_mode: true\nsts: {{ issuer: https://mediatore.test, kid: k, signing_key_file: /k }}\naudiences:\n  - {{ name: a, via: sts, egress: [\"a.home.example:443\"], rules: [{bad}] }}\n"
            ))
            .unwrap_err()
            .to_string();
            assert!(err.contains("absolute path glob"), "{bad}: {err}");
        }
    }

    #[test]
    fn an_endpoint_declared_by_two_audiences_fails_the_config() {
        let err = Config::parse(
            "trust_domain: sandbox.test\nissuers: []\nlisten: { user: 127.0.0.1:8080, sandbox: 127.0.0.1:8443 }\ndev_mode: true\nsts: { issuer: https://mediatore.test, kid: k, signing_key_file: /k }\naudiences:\n  - { name: a, via: sts, egress: [\"api.home.example:443\"] }\n  - { name: b, via: sts, egress: [\"api.home.example:443\", \"b.home.example:443\"] }\n",
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("api.home.example:443") && err.contains("ADR-0025"),
            "{err}"
        );
        // The same audience listing an endpoint twice is not a conflict.
        Config::parse(
            "trust_domain: sandbox.test\nissuers: []\nlisten: { user: 127.0.0.1:8080, sandbox: 127.0.0.1:8443 }\ndev_mode: true\nsts: { issuer: https://mediatore.test, kid: k, signing_key_file: /k }\naudiences:\n  - { name: a, via: sts, egress: [\"api.home.example:443\", \"api.home.example:443\"] }\n",
        )
        .unwrap();
    }

    #[test]
    fn dev_mode_needs_no_spire_section() {
        let cfg = Config::parse(&format!("{BASE}dev_mode: true\n")).unwrap();
        assert!(cfg.spire.is_none());
    }

    #[test]
    fn dev_mode_is_refused_off_loopback() {
        for addr in [
            "0.0.0.0:8443",
            "192.0.2.10:8443",
            "localhost:8443",
            "[::]:8443",
        ] {
            let err = Config::parse(&format!(
                "trust_domain: sandbox.test\nissuers: []\naudiences: []\nlisten: {{ user: 127.0.0.1:8080, sandbox: \"{addr}\" }}\ndev_mode: true\n"
            ))
            .unwrap_err();
            assert!(err.to_string().contains("loopback"), "{addr}: {err}");
        }
        for addr in ["127.0.0.1:8443", "[::1]:8443", "127.0.0.2:0"] {
            Config::parse(&format!(
                "trust_domain: sandbox.test\nissuers: []\naudiences: []\nlisten: {{ user: 127.0.0.1:8080, sandbox: \"{addr}\" }}\ndev_mode: true\n"
            ))
            .unwrap_or_else(|e| panic!("{addr}: {e}"));
        }
    }

    #[test]
    fn production_may_listen_anywhere() {
        Config::parse(
            "trust_domain: sandbox.test\nissuers: []\naudiences: []\nlisten: { user: 0.0.0.0:8080, sandbox: 0.0.0.0:8443 }\nspire:\n  workload_api_socket: unix:///run/spire/sockets/spire-agent.sock\n  entries:\n    class_name: spire-server-spire\nstore: { url: \"sqlite:///var/lib/mediatore/store.db\" }\n",
        )
        .unwrap();
    }

    #[test]
    fn production_refuses_to_start_without_spire() {
        let err = Config::parse(&format!("{BASE}dev_mode: false\n")).unwrap_err();
        assert!(err.to_string().contains("`spire`"), "{err}");
    }

    #[test]
    fn entries_section_has_bounded_defaults() {
        let cfg = Config::parse(&format!(
            "{BASE}spire:
  workload_api_socket: unix:///run/spire/sockets/spire-agent.sock
  entries:
    class_name: spire-server-spire
store: {{ url: \"sqlite:///var/lib/mediatore/store.db\" }}
"
        ))
        .unwrap();
        let e: mediatore_spire::EntriesConfig = (&cfg.spire.unwrap().entries).into();
        assert_eq!(e.class_name, "spire-server-spire");
        assert_eq!(e.ready_timeout, std::time::Duration::from_secs(30));
        assert_eq!(e.claim_svid_ttl, "1h");
    }

    #[test]
    fn watcher_timings_default_and_are_bounded() {
        let cfg = Config::parse(&format!("{BASE}dev_mode: true\n")).unwrap();
        assert_eq!(cfg.watcher.resync_secs, 300);
        assert_eq!(cfg.watcher.resolve_timeout_secs, 60);
        assert_eq!(cfg.watcher.lease_duration_secs, 15);
        let err = Config::parse(&format!(
            "{BASE}dev_mode: true\nwatcher: {{ lease_duration_secs: 1 }}\n"
        ))
        .unwrap_err();
        assert!(err.to_string().contains("lease_duration_secs"), "{err}");
        let err = Config::parse(&format!(
            "{BASE}dev_mode: true\nwatcher: {{ resolve_timeout_secs: 0 }}\n"
        ))
        .unwrap_err();
        assert!(err.to_string().contains("resolve_timeout_secs"), "{err}");
    }

    #[test]
    fn the_sandbox_namespace_defaults_and_must_not_be_empty() {
        let cfg = Config::parse(&format!("{BASE}dev_mode: true\n")).unwrap();
        assert_eq!(cfg.sandboxes.namespace, "sandboxes");
        let cfg = Config::parse(&format!(
            "{BASE}dev_mode: true\nsandboxes: {{ namespace: agents }}\n"
        ))
        .unwrap();
        assert_eq!(cfg.sandboxes.namespace, "agents");
        let err = Config::parse(&format!(
            "{BASE}dev_mode: true\nsandboxes: {{ namespace: \" \" }}\n"
        ))
        .unwrap_err();
        assert!(err.to_string().contains("sandboxes.namespace"), "{err}");
    }

    const SPIRE: &str = "spire:
  workload_api_socket: unix:///run/spire/sockets/spire-agent.sock
  entries:
    class_name: spire-server-spire
";

    #[test]
    fn the_store_defaults_to_memory_only_under_dev_mode() {
        let cfg = Config::parse(&format!("{BASE}dev_mode: true\n")).unwrap();
        assert_eq!(cfg.store.url, None);
        assert_eq!(cfg.store.retention_secs, 3600);
        assert_eq!(cfg.store.max_connections, 8);
        assert!(cfg.store.sealing.is_none());
        let err = Config::parse(&format!("{BASE}{SPIRE}")).unwrap_err();
        assert!(err.to_string().contains("store.url"), "{err}");
    }

    #[test]
    fn the_environment_overrides_the_store_url() {
        let cfg = Config::parse_with_store_url(
            &format!("{BASE}{SPIRE}store: {{ url: \"sqlite:///var/lib/mediatore/a.db\" }}\n"),
            Some("sqlite:///var/lib/mediatore/b.db".into()),
        )
        .unwrap();
        assert_eq!(
            cfg.store.url.as_deref(),
            Some("sqlite:///var/lib/mediatore/b.db")
        );
        let cfg = Config::parse_with_store_url(
            &format!("{BASE}{SPIRE}store: {{ url: \"sqlite:///var/lib/mediatore/a.db\" }}\n"),
            Some(String::new()),
        )
        .unwrap();
        assert_eq!(
            cfg.store.url.as_deref(),
            Some("sqlite:///var/lib/mediatore/a.db")
        );
    }

    #[test]
    fn a_production_store_is_a_file_or_tls_verified_postgres() {
        for (url, why) in [
            ("sqlite::memory:", "memory"),
            ("sqlite:file:x?mode=memory&cache=shared", "memory"),
            ("postgres://u:p@db.home.example/mediatore", "verify-full"),
            (
                "postgres://u:p@db.home.example/mediatore?sslmode=require",
                "verify-full",
            ),
            ("mysql://u:p@db/mediatore", "unsupported"),
        ] {
            let err =
                Config::parse(&format!("{BASE}{SPIRE}store: {{ url: \"{url}\" }}\n")).unwrap_err();
            assert!(err.to_string().contains(why), "{url}: {err}");
        }
        for url in [
            "sqlite:///var/lib/mediatore/store.db?mode=rwc",
            "postgres://u:p@db.home.example:5432/mediatore?sslmode=verify-full&sslrootcert=/etc/mediatore-pg/ca.pem",
        ] {
            Config::parse(&format!("{BASE}{SPIRE}store: {{ url: \"{url}\" }}\n"))
                .unwrap_or_else(|e| panic!("{url}: {e}"));
        }
        // dev_mode may point at any supported engine, memory included, but not an unknown one.
        Config::parse(&format!(
            "{BASE}dev_mode: true\nstore: {{ url: \"sqlite::memory:\" }}\n"
        ))
        .unwrap();
        let err = Config::parse(&format!(
            "{BASE}dev_mode: true\nstore: {{ url: \"mysql://x\" }}\n"
        ))
        .unwrap_err();
        assert!(err.to_string().contains("unsupported"), "{err}");
        let err = Config::parse(&format!(
            "{BASE}dev_mode: true\nstore: {{ max_connections: 0 }}\n"
        ))
        .unwrap_err();
        assert!(err.to_string().contains("max_connections"), "{err}");
    }

    #[test]
    fn a_session_issuer_needs_a_sealing_key_and_the_rate_limit_is_positive() {
        let issuer = "issuers:
  - url: https://dex.home.example
    backend: sts
    client_id: mediatore
    subject_claim: preferred_username
    session: { client_id: mediatore }
";
        let base = "trust_domain: sandbox.test\naudiences: []\nlisten: { user: 127.0.0.1:8080, sandbox: 127.0.0.1:8443 }\ndev_mode: true\n";
        let err = Config::parse(&format!("{base}{issuer}")).unwrap_err();
        assert!(err.to_string().contains("store.sealing"), "{err}");
        let cfg = Config::parse(&format!(
            "{base}{issuer}store: {{ sealing: {{ key_file: /etc/mediatore-sealing/key }} }}\n"
        ))
        .unwrap();
        assert_eq!(cfg.token.rate_per_minute, 10);
        assert_eq!(
            cfg.issuers[0].session.as_ref().unwrap().client_id,
            "mediatore"
        );
        let err = Config::parse(&format!(
            "{BASE}dev_mode: true\ntoken: {{ rate_per_minute: 0 }}\n"
        ))
        .unwrap_err();
        assert!(err.to_string().contains("rate_per_minute"), "{err}");
    }

    #[test]
    fn the_sealing_section_is_one_of_a_key_file_or_transit_and_transit_is_https_outside_dev_mode() {
        let transit = "store:\n  sealing:\n    transit: { url: https://openbao.home.example:8200, key: mediatore, role: mediatore }\n";
        let cfg = Config::parse(&format!("{BASE}dev_mode: true\n{transit}")).unwrap();
        let t = cfg.store.sealing.unwrap().transit.unwrap();
        assert_eq!((t.mount.as_str(), t.key.as_str()), ("transit", "mediatore"));
        for (yaml, want) in [
            (
                "store:\n  sealing:\n    key_file: /k\n    transit: { url: https://b, key: k, role: r }\n",
                "not both",
            ),
            ("store:\n  sealing: {}\n", "needs key_file or transit"),
        ] {
            let err = Config::parse(&format!("{BASE}dev_mode: true\n{yaml}")).unwrap_err();
            assert!(err.to_string().contains(want), "{err}");
        }
        // http reaches OpenBao only under dev_mode.
        let plain = "store:\n  url: \"sqlite::memory:\"\n  sealing:\n    transit: { url: http://127.0.0.1:8200, key: k, role: r }\n";
        assert!(Config::parse(&format!("{BASE}dev_mode: true\n{plain}")).is_ok());
        let prod = "trust_domain: sandbox.test\nissuers: []\naudiences: []\nlisten: { user: 0.0.0.0:8080, sandbox: 0.0.0.0:8443 }\nspire:\n  workload_api_socket: unix:///run/spire/sockets/spire-agent.sock\n  entries:\n    class_name: spire-server-spire\nstore:\n  url: \"sqlite:///var/lib/mediatore/store.db\"\n  sealing:\n    transit: { url: http://openbao.home.example:8200, key: k, role: r }\n";
        let err = Config::parse(prod).unwrap_err();
        assert!(err.to_string().contains("must be https"), "{err}");
    }

    #[test]
    fn an_empty_class_name_is_refused() {
        let err = Config::parse(&format!(
            "{BASE}spire:
  workload_api_socket: unix:///run/spire/sockets/spire-agent.sock
  entries:
    class_name: \"\"
"
        ))
        .unwrap_err();
        assert!(err.to_string().contains("class_name"), "{err}");
    }

    #[test]
    fn an_issuer_may_name_its_groups_claim_and_the_secret_its_token_endpoint_wants() {
        let cfg = Config::parse(
            "trust_domain: sandbox.test\naudiences: []\nlisten: { user: 127.0.0.1:8080, sandbox: 127.0.0.1:8443 }\ndev_mode: true\nstore: { sealing: { key_file: /k } }\nissuers:\n  - url: https://accounts.google.com\n    backend: sts\n    client_id: 1234.apps.googleusercontent.com\n    subject_claim: email\n    session: { client_id: 1234.apps.googleusercontent.com, client_secret_file: /etc/mediatore-google/secret }\n  - url: https://tenant.us.auth0.com/\n    backend: sts\n    client_id: abc\n    subject_claim: email\n    required_group: sandbox-users\n    groups_claim: https://example.com/groups\n    session: { client_id: abc }\n",
        )
        .unwrap();
        assert_eq!(
            cfg.issuers[0]
                .session
                .as_ref()
                .unwrap()
                .client_secret_file
                .as_deref(),
            Some(Path::new("/etc/mediatore-google/secret"))
        );
        assert!(cfg.issuers[0].groups_claim.is_none());
        assert_eq!(
            cfg.issuers[1].groups_claim.as_deref(),
            Some("https://example.com/groups")
        );
    }

    #[test]
    fn an_entra_issuer_has_a_credential_in_one_shape_and_no_session() {
        let base = "trust_domain: sandbox.test\naudiences: []\nlisten: { user: 127.0.0.1:8080, sandbox: 127.0.0.1:8443 }\ndev_mode: true\nstore: { sealing: { key_file: /etc/mediatore-sealing/key } }\n";
        let entra = |body: &str| {
            format!(
                "issuers:\n  - url: https://login.microsoftonline.com/tenant/v2.0\n    backend: entra-obo\n    client_id: broker-app-id\n{body}"
            )
        };
        let cfg = Config::parse(&format!(
            "{base}{}",
            entra("    entra: { certificate_file: /etc/mediatore-entra/cert.pem, key_file: /etc/mediatore-entra/key.pem }\n")
        ))
        .unwrap();
        let e = cfg.issuers[0].entra.as_ref().unwrap();
        assert_eq!(
            e.key_file.as_deref(),
            Some(Path::new("/etc/mediatore-entra/key.pem"))
        );
        assert_eq!(cfg.issuers[0].subject_claim, "oid");
        for (yaml, want) in [
            (entra(""), "needs an `entra` section"),
            (
                "issuers:\n  - url: https://dex.home.example\n    backend: sts\n    client_id: mediatore\n    entra: { token_file: /t }\n".to_owned(),
                "needs backend entra-obo",
            ),
            (
                entra("    session: { client_id: x }\n    entra: { token_file: /t }\n"),
                "exclusive",
            ),
            (
                entra("    entra: { key_file: /k }\n"),
                "certificate_file is required",
            ),
            (
                entra("    entra: { certificate_file: /c, key_file: /k, token_file: /t }\n"),
                "exactly one",
            ),
        ] {
            let err = Config::parse(&format!("{base}{yaml}")).unwrap_err();
            assert!(err.to_string().contains(want), "{yaml}: {err}");
        }
        // The Entra session is sealed like a delegated one: a sealer is required.
        let unsealed = "trust_domain: sandbox.test\naudiences: []\nlisten: { user: 127.0.0.1:8080, sandbox: 127.0.0.1:8443 }\ndev_mode: true\n";
        let err = Config::parse(&format!(
            "{unsealed}{}",
            entra("    entra: { token_file: /t }\n")
        ))
        .unwrap_err();
        assert!(err.to_string().contains("store.sealing"), "{err}");
        // An entra-obo audience needs an Entra issuer to be minted from.
        let err = Config::parse(
            "trust_domain: sandbox.test\nissuers: []\naudiences: [{ name: api://trading-data, via: entra-obo }]\nlisten: { user: 127.0.0.1:8080, sandbox: 127.0.0.1:8443 }\ndev_mode: true\n",
        )
        .unwrap_err();
        assert!(err.to_string().contains("entra-obo backend"), "{err}");
        // transit signs over https outside dev_mode, as the sealer does.
        let prod = format!(
            "trust_domain: sandbox.test\naudiences: []\nlisten: {{ user: 0.0.0.0:8080, sandbox: 0.0.0.0:8443 }}\nspire:\n  workload_api_socket: unix:///run/spire/sockets/spire-agent.sock\n  entries:\n    class_name: spire-server-spire\nstore:\n  url: \"sqlite:///var/lib/mediatore/store.db\"\n  sealing: {{ key_file: /k }}\n{}",
            entra(
                "    entra: { certificate_file: /c, transit: { url: http://openbao.home.example:8200, key: entra, role: mediatore } }\n"
            )
        );
        let err = Config::parse(&prod).unwrap_err();
        assert!(err.to_string().contains("must be https"), "{err}");
    }

    #[test]
    fn a_registry_credential_is_named_per_host_and_hosts_are_unique() {
        let base = "trust_domain: sandbox.test\nissuers: []\nlisten: { user: 127.0.0.1:8080, sandbox: 127.0.0.1:8443 }\ndev_mode: true\naudiences: []\n";
        let cfg = Config::parse(&format!(
            "{base}registries:\n  - {{ host: ghcr.io, username: octocat, password_file: /run/secrets/ghcr }}\n  - {{ host: docker.io, username: octocat, password_file: /run/secrets/hub }}\n"
        ))
        .unwrap();
        assert_eq!(cfg.registries.len(), 2);
        assert_eq!(cfg.registries[1].host, "docker.io");
        for (bad, why) in [
            (
                "registries:\n  - { host: docker.io, username: a, password_file: /x }\n  - { host: registry-1.docker.io, username: b, password_file: /y }\n",
                "listed twice",
            ),
            (
                "registries:\n  - { host: ghcr.io, username: \"\", password_file: /x }\n",
                "username must not be empty",
            ),
            (
                "registries:\n  - { host: ghcr.io/firestoned, username: a, password_file: /x }\n",
                "must be a registry host",
            ),
        ] {
            let err = Config::parse(&format!("{base}{bad}"))
                .unwrap_err()
                .to_string();
            assert!(err.contains(why), "{err}");
        }
        assert!(Config::parse(base).unwrap().registries.is_empty());
    }

    /// notaio's published conformance key: a real Ed25519 key, for tests only.
    fn conformance_key() -> String {
        sandboxpolicy_bundle::conformance::suite()
            .unwrap()
            .trusted_keys[0]
            .public_key
            .clone()
    }

    fn with_policy(policy: &str) -> anyhow::Result<Config> {
        Config::parse(&format!("{BASE}dev_mode: true\n{policy}"))
    }

    #[test]
    fn without_a_policy_section_no_bundle_is_read() {
        assert!(with_policy("").unwrap().policy.is_none());
    }

    #[test]
    fn the_policy_section_takes_keys_and_defaults_to_the_sandbox_namespace() {
        let k = conformance_key();
        let cfg = with_policy(&format!(
            "sandboxes: {{ namespace: team-a }}\npolicy:\n  trusted_keys:\n    - {{ id: \"notaio:v1\", public_key: \"{k}\" }}\n    - {{ id: \"notaio:v2\", public_key: \"{k}\" }}\n"
        ))
        .unwrap();
        let p = cfg.policy.unwrap();
        assert_eq!(p.trusted_keys.len(), 2, "two versions during a rotation");
        assert_eq!(p.namespaces, ["team-a"]);

        let cfg = with_policy(&format!(
            "policy:\n  trusted_keys: [{{ id: \"notaio:v1\", public_key: \"{k}\" }}]\n  namespaces: [sandboxes, team-b]\n"
        ))
        .unwrap();
        assert_eq!(cfg.policy.unwrap().namespaces, ["sandboxes", "team-b"]);
    }

    #[test]
    fn a_bad_policy_section_refuses_the_start() {
        let k = conformance_key();
        let key = format!("{{ id: \"notaio:v1\", public_key: \"{k}\" }}");
        for (policy, why) in [
            ("policy: { trusted_keys: [] }\n".to_string(), "must list"),
            (
                "policy: { namespaces: [sandboxes] }\n".to_string(),
                "must list",
            ),
            (
                "policy: { trusted_keys: [{ id: \"notaio:v1\", public_key: AAAA }] }\n".to_string(),
                "not 32",
            ),
            (
                format!("policy: {{ trusted_keys: [{key}, {key}] }}\n"),
                "twice",
            ),
            (
                format!("policy: {{ trusted_keys: [{key}], namespaces: [Team_A] }}\n"),
                "namespace name",
            ),
            (
                format!("policy: {{ trusted_keys: [{key}], namespaces: [a, a] }}\n"),
                "listed twice",
            ),
        ] {
            let err = with_policy(&policy).unwrap_err().to_string();
            assert!(err.contains(why), "expected {why:?} in: {err}");
        }
    }
}
