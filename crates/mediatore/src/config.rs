// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Server configuration (`mediatore.yaml`).

use std::path::{Path, PathBuf};

use mediatore_entra::{Backend, IssuerConfig};
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
}

fn default_max_ttl() -> i64 {
    900
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

/// The wrapping key for refresh material (ADR-0012 decision 3).
#[derive(Debug, Clone, Deserialize)]
pub struct SealingSection {
    /// File holding the 32-byte key (raw, or 64 hex characters): a Secret volume. Read at
    /// startup; a missing or malformed key stops the process.
    pub key_file: PathBuf,
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
}

fn default_listen() -> ListenConfig {
    ListenConfig {
        user: default_user_addr(),
        sandbox: default_sandbox_addr(),
    }
}

impl Config {
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
        Ok(cfg)
    }
}

impl Config {
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
}
