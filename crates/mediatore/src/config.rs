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
    /// Milliseconds between status reads while waiting (default 500).
    #[serde(default = "default_poll_interval_ms")]
    pub poll_interval_ms: u64,
    /// `x509SVIDTTL` on claim entries (default `1h`; admission caps it at `4h`).
    #[serde(default = "default_claim_svid_ttl")]
    pub claim_svid_ttl: String,
}

fn default_ready_timeout_secs() -> u64 {
    30
}
fn default_poll_interval_ms() -> u64 {
    500
}
fn default_claim_svid_ttl() -> String {
    "1h".into()
}

impl From<&EntriesSection> for mediatore_spire::EntriesConfig {
    fn from(e: &EntriesSection) -> Self {
        Self {
            class_name: e.class_name.clone(),
            ready_timeout: std::time::Duration::from_secs(e.ready_timeout_secs),
            poll_interval: std::time::Duration::from_millis(e.poll_interval_ms),
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
}

fn default_listen() -> ListenConfig {
    ListenConfig {
        user: default_user_addr(),
        sandbox: default_sandbox_addr(),
    }
}

impl Config {
    /// Load and sanity-check.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Self::parse(&text)
    }

    /// Parse YAML and enforce the cross-field rules.
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let cfg: Self = serde_yaml_ng::from_str(text)?;
        if cfg.audiences.iter().any(|a| a.via == Backend::Sts) && cfg.sts.is_none() {
            anyhow::bail!("an audience uses the sts backend but no `sts` section is configured");
        }
        if !cfg.dev_mode && cfg.spire.is_none() {
            anyhow::bail!("`spire` (workload_api_socket, entries) is required outside dev_mode");
        }
        if let Some(e) = cfg.spire.as_ref().map(|s| &s.entries) {
            if e.class_name.trim().is_empty() {
                anyhow::bail!("spire.entries.class_name must not be empty");
            }
            if e.ready_timeout_secs == 0 || e.poll_interval_ms == 0 {
                anyhow::bail!("spire.entries timeouts must be positive");
            }
        }
        Ok(cfg)
    }
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
"
        ))
        .unwrap();
        let e: mediatore_spire::EntriesConfig = (&cfg.spire.unwrap().entries).into();
        assert_eq!(e.class_name, "spire-server-spire");
        assert_eq!(e.ready_timeout, std::time::Duration::from_secs(30));
        assert_eq!(e.poll_interval, std::time::Duration::from_millis(500));
        assert_eq!(e.claim_svid_ttl, "1h");
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
