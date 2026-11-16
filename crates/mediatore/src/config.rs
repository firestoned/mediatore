// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Server configuration (`mediatore.yaml`).

use std::path::{Path, PathBuf};

use mediatore_entra::{Backend, IssuerConfig};
use mediatore_proto::image::canonical_registry;
use mediatore_proto::{
    Endpoint, EndpointRule, GATEWAY_CREDENTIAL_MAX_TTL_SECS, HeaderPair, InjectRoute,
};
use mediatore_store::seal::TransitConfig;
use serde::Deserialize;

/// Where an audience's credential is placed on the request (ADR-0040 decision 1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Inject {
    /// The guest's egress proxy places it, outside the jail (ADR-0025): today's behaviour, byte
    /// for byte, and the default.
    #[default]
    Proxy,
    /// The gateway places it (ADR-0040): `POST /v1/token` refuses the audience, the gateway's
    /// authorizer asks the broker for the credential and `envoy-inject` writes it, so the pool VM
    /// never holds it. Needs `gateways` and `gateway_inject_port`, `max_ttl` at most 300, exact
    /// `host:port` egress of one upstream and `rules`.
    Gateway,
}

/// What a `via: delegated` audience's credential is (ADR-0041 decision 1).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Credential {
    /// A bearer, placed as `Authorization: Bearer <token>` (ADR-0035): the default.
    #[default]
    Bearer,
    /// A user name and a secret (a password or a personal access token), placed as
    /// `Authorization: Basic base64(user:secret)`. Gateway-placed only: a password never reaches a
    /// pool VM (ADR-0041 decision 2).
    Basic,
}

/// One downstream audience and which backend serves it. An unknown key stops the start: the settings here decide where
/// a credential is placed, and a misspelled `inject` must not fall back to the default silently (ADR-0040).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AudienceConfig {
    /// Audience value as written into `aud`.
    pub name: String,
    /// Backend that mints for it; `none` for an audience reached without a credential
    /// (ADR-0025 decision 8): its route carries `credential: none`, `POST /v1/token`
    /// refuses it, and `egress`, `rules` and `ca_file` apply as for any other.
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
    /// `via: secret` (ADR-0032): the file holding the operator's credential for this
    /// audience and nothing else, a mounted Secret. Read once at start; missing or empty
    /// refuses the start. Required with `via: secret`, refused with any other backend.
    #[serde(default)]
    pub secret_file: Option<PathBuf>,
    /// `via: secret`: the request header the proxy sets, lowercase. `authorization` (the
    /// default) sends `Bearer <credential>`; any other name (`x-api-key`) sends the bare
    /// credential, and the proxy recognises the phantom in that header too.
    #[serde(default = "default_secret_header")]
    pub secret_header: String,
    /// `via: secret`: headers the proxy adds beside the credential on every credentialed
    /// request (Anthropic's `anthropic-beta: oauth-2025-04-20` for an OAuth token). Public
    /// material, carried to the proxy with the token.
    #[serde(default)]
    pub secret_extra_headers: Vec<HeaderPair>,
    /// `via: delegated` (ADR-0035): the request header the proxy sets for the caller's
    /// delegated credential, lowercase; `authorization` (the default) sends a bearer.
    #[serde(default = "default_secret_header")]
    pub header: String,
    /// `via: delegated`: headers the proxy adds beside the delegated credential (Anthropic's
    /// `anthropic-beta: oauth-2025-04-20` for a session token). Public material.
    #[serde(default)]
    pub extra_headers: Vec<HeaderPair>,
    /// `via: delegated`: how the broker renews the delegated bearer from its refresh token
    /// (ADR-0035 decision 5). Absent, the claim cannot outlast the bearer.
    #[serde(default)]
    pub refresh: Option<DelegationRefresh>,
    /// Where the credential is placed (ADR-0040): `proxy` (default) or `gateway`. For `gateway`
    /// the broker checks at start what decision 1 requires; the credential is bound to the exact
    /// authorities of this audience's `egress`.
    #[serde(default)]
    pub inject: Inject,
    /// What the delegated credential is (ADR-0041): `bearer` (default) or `basic`.
    #[serde(default)]
    pub credential: Credential,
}

impl AudienceConfig {
    /// The request header this audience's credential goes in, lowercase: `secret_header` for
    /// `via: secret`, `header` for `via: delegated`, `authorization` (a bearer) otherwise.
    fn credential_header(&self) -> &str {
        match self.via {
            Backend::Secret => &self.secret_header,
            Backend::Delegated => &self.header,
            _ => "authorization",
        }
    }

    /// The public headers placed beside the credential (`secret_extra_headers`, `extra_headers`).
    fn public_extra_headers(&self) -> &[HeaderPair] {
        match self.via {
            Backend::Secret => &self.secret_extra_headers,
            Backend::Delegated => &self.extra_headers,
            _ => &[],
        }
    }

    /// What the gateway places for this audience (ADR-0040 decisions 2 and 4): one route per
    /// exact authority of `egress`, with the rules, the credential header and the public extra
    /// headers. Empty unless the audience is `inject: gateway`. A credential is added only for a
    /// request whose authority is one of these and that one of the rules admits.
    #[must_use]
    pub fn inject_routes(&self) -> Vec<InjectRoute> {
        if self.inject != Inject::Gateway {
            return Vec::new();
        }
        self.egress
            .iter()
            .map(|e| InjectRoute {
                audience: self.name.clone(),
                endpoint: e.clone(),
                rules: self.rules.clone(),
                header: self.credential_header().to_owned(),
                extra_headers: self.public_extra_headers().to_vec(),
            })
            .collect()
    }
}

/// Where a delegated credential is refreshed (ADR-0035 decision 5): the operator's values,
/// never a default of the broker's.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct DelegationRefresh {
    /// The OAuth token endpoint; `https` outside `dev_mode`.
    pub token_endpoint: String,
    /// The public client the refresh token was issued to.
    pub client_id: String,
    /// The scope to ask for, if the endpoint wants one.
    #[serde(default)]
    pub scope: Option<String>,
}

fn default_secret_header() -> String {
    "authorization".to_owned()
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
/// (ADR-0022): handed by `GET /v1/me` to the guest whose claim names that registry. Since
/// ADR-0029 also where the pool reaches it from: with `gateways` set every entry needs a
/// `reach`, and an entry may carry no credential at all (an anonymous mirror on the
/// segment or behind a gateway's registry leg, ADR-0038), declared by its host and its reach
/// alone.
#[derive(Debug, Clone, Deserialize)]
pub struct RegistryConfig {
    /// The registry as a reference names it (`ghcr.io`, `registry.internal:5000`,
    /// `docker.io`).
    pub host: String,
    /// The login; with `password_file`, or neither.
    #[serde(default)]
    pub username: Option<String>,
    /// File holding the password or token, read at start; with `username`, or neither.
    #[serde(default)]
    pub password_file: Option<PathBuf>,
    /// How a gateway-era pool reaches this registry (ADR-0029 decision 2). Required once
    /// `gateways` is set; a claim naming a registry with none is refused.
    #[serde(default)]
    pub reach: Option<RegistryReach>,
}

/// Where a pool VM on the routeless sandbox segment finds a registry (ADR-0029 decision 1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RegistryReach {
    /// A registry or pull-through mirror with an address on the segment, reached at layer
    /// 2; the pool's host table admits its address (`/etc/mediatore/registries`).
    Segment,
    /// A registry behind a gateway's registry leg (ADR-0038): the guest dials the gateway at
    /// the leg's port with the registry's own name, `MEDIATORE_RELAY_REGISTRIES`, and the
    /// host table admits that destination to root alone. A credential may be carried: the TLS
    /// is the registry's, end to end.
    Relay,
}

impl RegistryConfig {
    /// The login and the password file, when the entry carries a credential.
    #[must_use]
    pub fn credential(&self) -> Option<(&str, &Path)> {
        match (&self.username, &self.password_file) {
            (Some(u), Some(p)) => Some((u.as_str(), p.as_path())),
            _ => None,
        }
    }
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
    /// `x509SVIDTTL` on claim entries, a Go duration (default `15m`, the most it may be:
    /// ADR-0027 decision 7; admission caps any entry at `4h`). Never more than the claim
    /// has left.
    #[serde(default = "default_claim_svid_ttl")]
    pub claim_svid_ttl: String,
}

fn default_ready_timeout_secs() -> u64 {
    30
}
fn default_claim_svid_ttl() -> String {
    "15m".into()
}

impl EntriesSection {
    /// The TTL parsed and bounded (ADR-0027 decision 7).
    ///
    /// # Errors
    /// Not a duration of hours, minutes and seconds, zero, or more than
    /// [`mediatore_spire::MAX_CLAIM_SVID_TTL`].
    pub fn claim_svid_ttl(&self) -> anyhow::Result<std::time::Duration> {
        let ttl = mediatore_spire::parse_go_duration(&self.claim_svid_ttl)
            .map_err(|e| anyhow::anyhow!("spire.entries.claim_svid_ttl: {e}"))?;
        anyhow::ensure!(
            ttl <= mediatore_spire::MAX_CLAIM_SVID_TTL,
            "spire.entries.claim_svid_ttl: {} is more than {}s, the most a claim SVID may live (ADR-0027 decision 7)",
            self.claim_svid_ttl,
            mediatore_spire::MAX_CLAIM_SVID_TTL.as_secs()
        );
        Ok(ttl)
    }
}

impl TryFrom<&EntriesSection> for mediatore_spire::EntriesConfig {
    type Error = anyhow::Error;

    fn try_from(e: &EntriesSection) -> anyhow::Result<Self> {
        Ok(Self {
            class_name: e.class_name.clone(),
            ready_timeout: std::time::Duration::from_secs(e.ready_timeout_secs),
            claim_svid_ttl: e.claim_svid_ttl()?,
        })
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
    /// Whether a bundle's direct `egress[]` reaches the gateway (ADR-0030 decision 4):
    /// `shadow` (the default) serves today's answer and logs the difference, `enforce`
    /// serves the union. Per broker deployment, so per environment.
    #[serde(default)]
    pub egress: mediatore_claims::policy::EgressMode,
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

/// The claim store (ADR-0012, ADR-0034): the Kubernetes API outside `dev_mode`, in memory
/// under it; nothing to point at. What remains to configure is how long an ended claim is
/// kept, and the sealer.
#[derive(Debug, Clone, Deserialize)]
pub struct StoreSection {
    /// Seconds an ended claim stays on its `AgentSandbox` before the resync sweeps it,
    /// logging the audit line (default 3600; ADR-0034 decision 4).
    #[serde(default = "default_retention_secs")]
    pub retention_secs: u64,
    /// Seconds a registered node is protected from collection (default 600; ADR-0039). The
    /// broker removes a `SandboxNode` once no banlieue VM publishes its EK hash, but never
    /// one younger than this: a registration may precede its VM's published certificate.
    #[serde(default = "default_node_grace_secs")]
    pub node_grace_secs: u64,
    /// The local sealer's key. Unset means refresh material cannot be persisted, which
    /// fails the claim that needs it rather than storing plaintext.
    #[serde(default)]
    pub sealing: Option<SealingSection>,
}

fn default_retention_secs() -> u64 {
    3600
}

fn default_node_grace_secs() -> u64 {
    600
}

impl Default for StoreSection {
    fn default() -> Self {
        Self {
            retention_secs: default_retention_secs(),
            node_grace_secs: default_node_grace_secs(),
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
    /// The egress gateways of this environment (ADR-0028 decision 6): each gateway's
    /// `sandbox` address and data-plane port, `host:port`, in the order `GET /v1/me` hands
    /// the guest. Addresses, not names: the segment has no resolver (ADR-0028 decision 7).
    /// Empty until the gateways exist; the jail then reaches `audiences[].egress` directly.
    #[serde(default, deserialize_with = "endpoints")]
    pub gateways: Vec<Endpoint>,
    /// The port of each gateway's `envoy-inject` listener, on the same addresses as `gateways`
    /// (ADR-0040 decision 3, `INJECT_PORT` on the gateway). Required by `inject: gateway`; its
    /// own port, never a gateway's data-plane port.
    #[serde(default)]
    pub gateway_inject_port: Option<u16>,
}

fn default_listen() -> ListenConfig {
    ListenConfig {
        user: default_user_addr(),
        sandbox: default_sandbox_addr(),
    }
}

impl Config {
    /// What `credential: basic` needs (ADR-0041 decisions 1, 2 and 8); nothing for a bearer.
    fn check_basic(a: &AudienceConfig) -> anyhow::Result<()> {
        if a.credential != Credential::Basic {
            return Ok(());
        }
        if a.via != Backend::Delegated {
            anyhow::bail!(
                "audience {:?}: `credential: basic` goes with via: delegated (ADR-0041 decision 1)",
                a.name
            );
        }
        if a.inject != Inject::Gateway {
            anyhow::bail!(
                "audience {:?}: `credential: basic` is placed at the gateway only, `inject: gateway`: a password never reaches a pool VM (ADR-0041 decision 2)",
                a.name
            );
        }
        if a.refresh.is_some() {
            anyhow::bail!(
                "audience {:?}: `credential: basic` has nothing to renew, so no `refresh` (ADR-0041 decision 1)",
                a.name
            );
        }
        if a.header != "authorization" {
            anyhow::bail!(
                "audience {:?}: `credential: basic` is the `authorization` header (ADR-0041 decision 8)",
                a.name
            );
        }

        Ok(())
    }

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
            if a.via == Backend::Secret && a.secret_file.is_none() {
                anyhow::bail!(
                    "audience {:?}: via: secret needs `secret_file`, the mounted Secret holding the credential (ADR-0032)",
                    a.name
                );
            }
            if a.via != Backend::Secret && a.secret_file.is_some() {
                anyhow::bail!(
                    "audience {:?}: `secret_file` goes with via: secret only (ADR-0032)",
                    a.name
                );
            }
            Self::check_basic(a)?;
            let header_ok = |h: &str| {
                !h.is_empty()
                    && h.chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            };
            if a.via != Backend::Delegated
                && (a.header != "authorization"
                    || !a.extra_headers.is_empty()
                    || a.refresh.is_some())
            {
                anyhow::bail!(
                    "audience {:?}: `header`, `extra_headers` and `refresh` go with via: delegated only (ADR-0035)",
                    a.name
                );
            }
            if !header_ok(&a.header) {
                anyhow::bail!(
                    "audience {:?}: header {:?} must be a lowercase header name (ADR-0035)",
                    a.name,
                    a.header
                );
            }
            if let Some(r) = &a.refresh
                && !self.dev_mode
                && !r.token_endpoint.starts_with("https://")
            {
                anyhow::bail!(
                    "audience {:?}: refresh.token_endpoint must be https outside dev_mode (ADR-0035 decision 5)",
                    a.name
                );
            }
            if !header_ok(&a.secret_header) {
                anyhow::bail!(
                    "audience {:?}: secret_header {:?} must be a lowercase header name (ADR-0032)",
                    a.name,
                    a.secret_header
                );
            }
            for h in &a.secret_extra_headers {
                if !header_ok(&h.name) || h.name == "authorization" || h.name == a.secret_header {
                    anyhow::bail!(
                        "audience {:?}: secret_extra_headers {:?} must be lowercase names other than the credential's (ADR-0032)",
                        a.name,
                        h.name
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

    /// The audiences declared `inject: gateway` (ADR-0040), in file order.
    #[must_use]
    pub fn gateway_placed(&self) -> Vec<&AudienceConfig> {
        self.audiences
            .iter()
            .filter(|a| a.inject == Inject::Gateway)
            .collect()
    }

    /// ADR-0040 decision 1, refused at start: the inject port is a real port of its own, and a
    /// gateway-placed audience has a credential to place, the gateways to place it at, a life
    /// of at most 300 seconds, exact `host:port` entries of one upstream and rules (under
    /// `proxy` no rules means every method and path; a placed credential does not get that).
    fn check_inject(&self) -> anyhow::Result<()> {
        if let Some(port) = self.gateway_inject_port {
            if port == 0 {
                anyhow::bail!("gateway_inject_port must be 1 to 65535 (ADR-0040 decision 3)");
            }
            if let Some(g) = self.gateways.iter().find(|g| g.port == port) {
                anyhow::bail!(
                    "gateway_inject_port {port} is the data-plane port of gateway {g}: the inject listener has a port of its own (ADR-0040 decision 3)"
                );
            }
        }
        for a in self.gateway_placed() {
            let name = &a.name;
            match a.via {
                Backend::Secret | Backend::Delegated | Backend::Sts => {}
                Backend::None | Backend::EntraObo => {
                    let via = if a.via == Backend::None {
                        "none"
                    } else {
                        "entra-obo"
                    };
                    anyhow::bail!(
                        "audience {name:?}: `inject: gateway` places a credential and via: {via} has none to place; it goes with via: secret, delegated or sts (ADR-0040 decision 1)"
                    );
                }
            }
            if self.gateways.is_empty() {
                anyhow::bail!(
                    "audience {name:?}: `inject: gateway` needs `gateways`, the addresses the gateways' inject listeners are on (ADR-0040 decision 1)"
                );
            }
            if self.gateway_inject_port.is_none() {
                anyhow::bail!(
                    "audience {name:?}: `inject: gateway` needs `gateway_inject_port`, the port of the gateways' inject listener (ADR-0040 decision 1)"
                );
            }
            if a.max_ttl > GATEWAY_CREDENTIAL_MAX_TTL_SECS {
                anyhow::bail!(
                    "audience {name:?}: max_ttl {} exceeds the {GATEWAY_CREDENTIAL_MAX_TTL_SECS} second cap on a credential the gateway places; set `max_ttl: {GATEWAY_CREDENTIAL_MAX_TTL_SECS}` or lower (ADR-0040 decision 1)",
                    a.max_ttl
                );
            }
            if a.egress.is_empty() {
                anyhow::bail!(
                    "audience {name:?}: `inject: gateway` needs `egress`, the exact host:port the credential is placed for (ADR-0040 decision 1)"
                );
            }
            if let Some(e) = a.egress.iter().find(|e| e.host.contains('*')) {
                anyhow::bail!(
                    "audience {name:?}: egress {e} is a wildcard; a placed credential is bound to exact host:port entries (ADR-0040 decision 1)"
                );
            }
            if let Some(e) = a.egress.iter().find(|e| {
                e.host
                    .trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .is_ok()
            }) {
                anyhow::bail!(
                    "audience {name:?}: egress {e} is an IP address; the gateway verifies the upstream's certificate by name, so a gateway-placed audience needs a host name (ADR-0040 decision 1)"
                );
            }
            let first = &a.egress[0].host;
            if a.egress.iter().any(|e| !e.host.eq_ignore_ascii_case(first)) {
                anyhow::bail!(
                    "audience {name:?}: egress names more than one upstream host; a gateway-placed audience has one upstream, and a credential is bound to the authority that needs it (ADR-0040 decision 1)"
                );
            }
            if a.rules.is_empty() {
                anyhow::bail!(
                    "audience {name:?}: `inject: gateway` needs `rules`; under proxy no rules means every method and path, and a placed credential does not get that default (ADR-0040 decision 1)"
                );
            }
        }
        Ok(())
    }

    /// Each gateway listed once: a repeated entry is a copy-paste, not a second gateway,
    /// and the forwarder's failover would retry the same one.
    fn check_gateways(&self) -> anyhow::Result<()> {
        let mut seen = std::collections::BTreeSet::new();
        for g in &self.gateways {
            if !seen.insert(g) {
                anyhow::bail!("gateways: {g} is listed twice (ADR-0028)");
            }
        }
        Ok(())
    }

    /// One entry per registry host, Docker Hub's two names being one host; a credential
    /// is a login and a file together or neither; with `gateways`, every entry says how
    /// the pool reaches it (ADR-0029 decision 2).
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
            match (&r.username, &r.password_file) {
                (Some(u), Some(_)) if u.trim().is_empty() => {
                    anyhow::bail!("registries[{host}].username must not be empty");
                }
                (Some(_), None) | (None, Some(_)) => {
                    anyhow::bail!(
                        "registries[{host}]: username and password_file go together (ADR-0022); leave both out for an anonymous registry"
                    );
                }
                _ => {}
            }
            if !self.gateways.is_empty() && r.reach.is_none() {
                anyhow::bail!(
                    "registries[{host}].reach is required once gateways are set: a gateway-era pool reaches a registry only where the environment put it, `segment` for a mirror on the sandbox segment (ADR-0029 decision 2) or `relay` for one behind a gateway's registry leg (ADR-0038)"
                );
            }
            if !seen.insert(canonical_registry(host)) {
                anyhow::bail!(
                    "registries: {host} is listed twice (docker.io and registry-1.docker.io are one host)"
                );
            }
        }
        Ok(())
    }

    /// The registries a claim's image may name, canonical hosts, when the environment
    /// has gateways (ADR-0029 decision 1); `None` without gateways, where nothing is
    /// restricted.
    #[must_use]
    pub fn reachable_registries(&self) -> Option<std::collections::BTreeSet<String>> {
        if self.gateways.is_empty() {
            return None;
        }
        Some(
            self.registries
                .iter()
                .filter(|r| r.reach.is_some())
                .map(|r| canonical_registry(&r.host))
                // A registry the gateway places a credential for is reached through the gateway (ADR-0043).
                .chain(self.placed_registries().into_keys())
                .collect(),
        )
    }

    /// The registries that are gateway-placed audiences (ADR-0043 decision 1), by the name a reference to an image
    /// on them carries (the host, with the port only when it is not 443), each with the audience that serves it. A
    /// claim naming an image there must name that audience and delegate a credential for it.
    #[must_use]
    pub fn placed_registries(&self) -> std::collections::BTreeMap<String, String> {
        self.audiences
            .iter()
            .filter(|a| a.inject == Inject::Gateway)
            .flat_map(|a| {
                a.egress.iter().map(move |e| {
                    let host = if e.port == 443 {
                        e.host.clone()
                    } else {
                        format!("{}:{}", e.host, e.port)
                    };
                    (host, a.name.clone())
                })
            })
            .collect()
    }

    /// Load and sanity-check.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)?;
        Self::parse(&text)
    }

    /// Parse YAML and enforce the cross-field rules.
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let mut cfg: Self = serde_saphyr::from_str(text)?;
        if cfg.audiences.iter().any(|a| a.via == Backend::Sts) && cfg.sts.is_none() {
            anyhow::bail!("an audience uses the sts backend but no `sts` section is configured");
        }
        cfg.check_registries()?;
        cfg.check_routes()?;
        cfg.check_inject()?;
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
            e.claim_svid_ttl()?;
        }
        // The store needs no URL since ADR-0034 (the Kubernetes API, or memory under
        // dev_mode), and any retention is valid: zero means an ended claim is swept at the
        // next resync, which is how the kind tiers run.
        cfg.check_policy()?;
        cfg.check_gateways()?;
        if cfg.store.node_grace_secs == 0 {
            anyhow::bail!(
                "store.node_grace_secs must be positive: a node registered before its VM's certificate is published would be collected at once (ADR-0039)"
            );
        }
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
                (Backend::None, _) => anyhow::bail!(
                    "issuer {}: backend none is an audience's (a route without a credential, ADR-0025 decision 8), never an issuer's",
                    issuer.url
                ),
                (Backend::Secret, _) => anyhow::bail!(
                    "issuer {}: backend secret is an audience's (an operator-held credential, ADR-0032), never an issuer's",
                    issuer.url
                ),
                (Backend::Delegated, _) => anyhow::bail!(
                    "issuer {}: backend delegated is an audience's (the caller's own credential, ADR-0035), never an issuer's",
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
    fn gateways_are_parsed_in_order_default_to_none_and_are_listed_once() {
        let cfg = Config::parse(&format!(
            "{BASE}dev_mode: true\ngateways: [\"198.51.100.2:3128\", \"[2001:db8::2]:3128\", \"198.51.100.3:3128\"]\n"
        ))
        .unwrap();
        let listed: Vec<String> = cfg.gateways.iter().map(ToString::to_string).collect();
        assert_eq!(
            listed,
            [
                "198.51.100.2:3128",
                "[2001:db8::2]:3128",
                "198.51.100.3:3128"
            ]
        );
        let cfg = Config::parse(&format!("{BASE}dev_mode: true\n")).unwrap();
        assert_eq!(cfg.gateways, Vec::<Endpoint>::new(), "no gateway yet");
        let err = Config::parse(&format!(
            "{BASE}dev_mode: true\ngateways: [\"198.51.100.2:3128\", \"198.51.100.2:3128\"]\n"
        ))
        .unwrap_err()
        .to_string();
        assert!(err.contains("listed twice"), "{err}");
        let err = Config::parse(&format!(
            "{BASE}dev_mode: true\ngateways: [\"198.51.100.2\"]\n"
        ))
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
    fn an_audience_via_none_is_reached_without_a_credential_and_an_issuer_cannot_be() {
        let cfg = Config::parse(
            "trust_domain: sandbox.test\nissuers: []\nlisten: { user: 127.0.0.1:8080, sandbox: 127.0.0.1:8443 }\ndev_mode: true\naudiences:\n  - name: api.example.com\n    via: none\n    egress: [\"api.example.com:443\"]\n    rules:\n      - { method: GET, path: \"/repos/**\" }\n",
        )
        .unwrap();
        assert_eq!(cfg.audiences[0].via, Backend::None);
        assert_eq!(cfg.audiences[0].rules.len(), 1, "the rules still apply");
        assert!(
            cfg.audiences.iter().all(|a| a.via != Backend::Sts),
            "no sts audience, so no sts section is needed"
        );
        let err = Config::parse(
            "trust_domain: sandbox.test\nlisten: { user: 127.0.0.1:8080, sandbox: 127.0.0.1:8443 }\ndev_mode: true\naudiences: []\nissuers:\n  - url: https://idp.example.com\n    backend: none\n    client_id: mediatore\n    subject_claim: email\n",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("never an issuer's"), "{err}");
    }

    #[test]
    fn an_audience_via_delegated_names_its_header_and_refresh_and_an_issuer_refuses_it() {
        let base = "trust_domain: sandbox.test\nissuers: []\nlisten: { user: 127.0.0.1:8080, sandbox: 127.0.0.1:8443 }\ndev_mode: true\nstore: { sealing: { key_file: /k } }\n";
        let cfg = Config::parse(&format!(
            "{base}audiences:\n  - name: anthropic\n    via: delegated\n    max_ttl: 900\n    egress: [\"api.anthropic.com:443\"]\n    extra_headers:\n      - {{ name: anthropic-beta, value: oauth-2025-04-20 }}\n    refresh: {{ token_endpoint: \"https://oauth.example/token\", client_id: cli }}\n  - name: plain\n    via: delegated\n    egress: [\"plain.example:443\"]\n"
        ))
        .unwrap();
        assert_eq!(cfg.audiences[0].via, Backend::Delegated);
        assert_eq!(
            cfg.audiences[0].header, "authorization",
            "a bearer by default"
        );
        assert_eq!(cfg.audiences[0].extra_headers[0].name, "anthropic-beta");
        assert_eq!(cfg.audiences[0].refresh.as_ref().unwrap().client_id, "cli");
        assert!(cfg.audiences[1].refresh.is_none());

        for (bad, needle) in [
            (
                "audiences:\n  - { name: a, via: sts, egress: [\"a.example.com:443\"], header: x-api-key }\nsts: { issuer: https://m, kid: k, signing_key_file: /s }\n",
                "via: delegated only",
            ),
            (
                "audiences:\n  - { name: a, via: delegated, egress: [\"a.example.com:443\"], header: \"X-Api-Key\" }\n",
                "lowercase header name",
            ),
        ] {
            let err = Config::parse(&format!("{base}{bad}"))
                .unwrap_err()
                .to_string();
            assert!(err.contains(needle), "{bad}: {err}");
        }
        let err = Config::parse(
            "trust_domain: sandbox.test\nissuers: []\nlisten: { user: 0.0.0.0:8080, sandbox: 0.0.0.0:8443 }\nspire:\n  workload_api_socket: unix:///run/spire/sockets/spire-agent.sock\n  entries:\n    class_name: spire-server-spire\nstore: { sealing: { key_file: /k } }\naudiences:\n  - { name: a, via: delegated, egress: [\"a.example.com:443\"], refresh: { token_endpoint: \"http://oauth.example/token\", client_id: cli } }\n",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("must be https"), "{err}");
        let err = Config::parse(
            "trust_domain: sandbox.test\nlisten: { user: 127.0.0.1:8080, sandbox: 127.0.0.1:8443 }\ndev_mode: true\naudiences: []\nissuers:\n  - { url: https://idp.example, backend: delegated, client_id: m }\n",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("never an issuer's"), "{err}");
    }

    #[test]
    fn an_audience_via_secret_names_its_file_and_header_and_nothing_else_may() {
        let cfg = Config::parse(
            "trust_domain: sandbox.test\nissuers: []\nlisten: { user: 127.0.0.1:8080, sandbox: 127.0.0.1:8443 }\ndev_mode: true\naudiences:\n  - name: anthropic\n    via: secret\n    secret_file: /etc/mediatore-audience-secrets/anthropic\n    secret_header: x-api-key\n    secret_extra_headers:\n      - { name: anthropic-beta, value: oauth-2025-04-20 }\n    egress: [\"api.anthropic.com:443\"]\n    rules:\n      - { method: POST, path: \"/v1/messages\" }\n  - name: bearer-api\n    via: secret\n    secret_file: /etc/mediatore-audience-secrets/bearer-api\n    egress: [\"api.example.com:443\"]\n",
        )
        .unwrap();
        assert_eq!(cfg.audiences[0].via, Backend::Secret);
        assert_eq!(cfg.audiences[0].secret_header, "x-api-key");
        assert_eq!(
            cfg.audiences[0].secret_extra_headers[0].name,
            "anthropic-beta"
        );
        assert_eq!(
            cfg.audiences[1].secret_header, "authorization",
            "the default header: a bearer"
        );
        let base = "trust_domain: sandbox.test\nissuers: []\nlisten: { user: 127.0.0.1:8080, sandbox: 127.0.0.1:8443 }\ndev_mode: true\nsts: { issuer: https://mediatore.test, kid: k, signing_key_file: /k }\naudiences:\n";
        for (bad, needle) in [
            (
                "  - { name: a, via: secret, egress: [\"a.example.com:443\"] }\n",
                "needs `secret_file`",
            ),
            (
                "  - { name: a, via: sts, secret_file: /s, egress: [\"a.example.com:443\"] }\n",
                "via: secret only",
            ),
            (
                "  - { name: a, via: secret, secret_file: /s, secret_header: \"X-Api-Key\" }\n",
                "lowercase header name",
            ),
            (
                "  - { name: a, via: secret, secret_file: /s, secret_header: x-api-key, secret_extra_headers: [{ name: x-api-key, value: v }] }\n",
                "other than the credential's",
            ),
        ] {
            let err = Config::parse(&format!("{base}{bad}"))
                .unwrap_err()
                .to_string();
            assert!(err.contains(needle), "{bad}: {err}");
        }
        let err = Config::parse(
            "trust_domain: sandbox.test\nlisten: { user: 127.0.0.1:8080, sandbox: 127.0.0.1:8443 }\ndev_mode: true\naudiences: []\nissuers:\n  - url: https://idp.example.com\n    backend: secret\n    client_id: mediatore\n    subject_claim: email\n",
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("never an issuer's"), "{err}");
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
            "trust_domain: sandbox.test\nissuers: []\naudiences: []\nlisten: { user: 0.0.0.0:8080, sandbox: 0.0.0.0:8443 }\nspire:\n  workload_api_socket: unix:///run/spire/sockets/spire-agent.sock\n  entries:\n    class_name: spire-server-spire\n",
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
"
        ))
        .unwrap();
        let e: mediatore_spire::EntriesConfig = (&cfg.spire.unwrap().entries).try_into().unwrap();
        assert_eq!(e.class_name, "spire-server-spire");
        assert_eq!(e.ready_timeout, std::time::Duration::from_secs(30));
        assert_eq!(
            e.claim_svid_ttl,
            std::time::Duration::from_mins(15),
            "ADR-0027 decision 7: 15 minutes unless told less"
        );
    }

    #[test]
    fn the_claim_svid_ttl_is_a_duration_of_at_most_fifteen_minutes() {
        let with = |ttl: &str| {
            Config::parse(&format!(
                "{BASE}spire:
  workload_api_socket: unix:///run/spire/sockets/spire-agent.sock
  entries:
    class_name: spire-server-spire
    claim_svid_ttl: {ttl:?}
"
            ))
        };
        let cfg = with("5m").unwrap();
        assert_eq!(
            cfg.spire.unwrap().entries.claim_svid_ttl().unwrap(),
            std::time::Duration::from_mins(5)
        );
        assert!(with("900s").is_ok());
        for (bad, why) in [
            ("1h", "more than"),
            ("16m", "more than"),
            ("0s", "zero"),
            ("soon", "not a duration"),
        ] {
            let err = with(bad).unwrap_err().to_string();
            assert!(
                err.contains("claim_svid_ttl") && err.contains(why),
                "{bad}: {err}"
            );
        }
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
    fn the_store_has_nothing_to_point_at_and_any_retention_is_valid() {
        // ADR-0034: the Kubernetes API outside dev_mode, memory under it; no URL anywhere.
        let cfg = Config::parse(&format!("{BASE}dev_mode: true\n")).unwrap();
        assert_eq!(cfg.store.retention_secs, 3600);
        assert!(cfg.store.sealing.is_none());
        // ADR-0039: a node is collected only ten minutes after its registration, by default.
        assert_eq!(cfg.store.node_grace_secs, 600);
        let cfg = Config::parse(&format!(
            "{BASE}{SPIRE}store: {{ node_grace_secs: 1800 }}\n"
        ))
        .unwrap();
        assert_eq!(cfg.store.node_grace_secs, 1800);
        // Zero would collect a registration before its VM's certificate is published.
        let err = Config::parse(&format!("{BASE}{SPIRE}store: {{ node_grace_secs: 0 }}\n"))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("node_grace_secs") && err.contains("ADR-0039"),
            "{err}"
        );
        let cfg =
            Config::parse(&format!("{BASE}{SPIRE}store: {{ retention_secs: 120 }}\n")).unwrap();
        assert_eq!(cfg.store.retention_secs, 120);
        // Zero: swept at the next resync, the kind tiers' setting.
        let cfg = Config::parse(&format!("{BASE}{SPIRE}store: {{ retention_secs: 0 }}\n")).unwrap();
        assert_eq!(cfg.store.retention_secs, 0);
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
        let plain =
            "store:\n  sealing:\n    transit: { url: http://127.0.0.1:8200, key: k, role: r }\n";
        assert!(Config::parse(&format!("{BASE}dev_mode: true\n{plain}")).is_ok());
        let prod = "trust_domain: sandbox.test\nissuers: []\naudiences: []\nlisten: { user: 0.0.0.0:8080, sandbox: 0.0.0.0:8443 }\nspire:\n  workload_api_socket: unix:///run/spire/sockets/spire-agent.sock\n  entries:\n    class_name: spire-server-spire\nstore:\n  sealing:\n    transit: { url: http://openbao.home.example:8200, key: k, role: r }\n";
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
            "trust_domain: sandbox.test\naudiences: []\nlisten: {{ user: 0.0.0.0:8080, sandbox: 0.0.0.0:8443 }}\nspire:\n  workload_api_socket: unix:///run/spire/sockets/spire-agent.sock\n  entries:\n    class_name: spire-server-spire\nstore:\n  sealing: {{ key_file: /k }}\n{}",
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
        assert_eq!(
            cfg.registries[0].credential(),
            Some(("octocat", Path::new("/run/secrets/ghcr")))
        );
        assert_eq!(cfg.registries[0].reach, None);
        assert_eq!(
            cfg.reachable_registries(),
            None,
            "no gateways: nothing is restricted"
        );
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

    #[test]
    fn a_registry_entry_may_carry_no_credential_but_never_half_of_one() {
        let base = format!("{BASE}dev_mode: true\n");
        let cfg = Config::parse(&format!(
            "{base}registries:\n  - {{ host: \"registry.internal:5000\" }}\n"
        ))
        .unwrap();
        assert_eq!(cfg.registries[0].credential(), None, "an anonymous mirror");
        for half in [
            "registries:\n  - { host: ghcr.io, username: octocat }\n",
            "registries:\n  - { host: ghcr.io, password_file: /x }\n",
        ] {
            let err = Config::parse(&format!("{base}{half}"))
                .unwrap_err()
                .to_string();
            assert!(err.contains("go together"), "{half}: {err}");
        }
    }

    #[test]
    fn with_gateways_every_registry_needs_a_reach_and_the_reachable_set_is_those_with_one() {
        let base = format!("{BASE}dev_mode: true\ngateways: [\"198.51.100.1:8443\"]\n");
        let err = Config::parse(&format!(
            "{base}registries:\n  - {{ host: ghcr.io, username: octocat, password_file: /x }}\n"
        ))
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("reach is required") && err.contains("ADR-0029"),
            "{err}"
        );
        let cfg = Config::parse(&format!(
            "{base}registries:\n  - {{ host: \"registry.internal:5000\", reach: segment }}\n  - {{ host: docker.io, username: octocat, password_file: /x, reach: segment }}\n"
        ))
        .unwrap();
        assert_eq!(cfg.registries[0].reach, Some(RegistryReach::Segment));
        assert_eq!(
            cfg.reachable_registries()
                .unwrap()
                .into_iter()
                .collect::<Vec<_>>(),
            vec![
                "registry-1.docker.io".to_string(),
                "registry.internal:5000".to_string()
            ],
            "canonical hosts, as a reference's registry is canonicalised"
        );
        // ADR-0038: `relay` is the second reach, a registry behind a gateway's registry leg; it is
        // reachable like a segment one, may carry a credential (the TLS is the registry's, end to
        // end) and is told apart from a typo.
        let both = Config::parse(&format!(
            "{base}registries:\n  - {{ host: \"registry.internal:5000\", reach: segment }}\n  - {{ host: artifactory.example, username: octocat, password_file: /x, reach: relay }}\n"
        ))
        .unwrap();
        assert_eq!(both.registries[1].reach, Some(RegistryReach::Relay));
        assert_eq!(
            both.reachable_registries()
                .unwrap()
                .into_iter()
                .collect::<Vec<_>>(),
            vec![
                "artifactory.example".to_string(),
                "registry.internal:5000".to_string()
            ],
            "a relay registry is a reachable one"
        );
        let err = Config::parse(&format!(
            "{base}registries:\n  - {{ host: ghcr.io, reach: tunnel }}\n"
        ))
        .unwrap_err()
        .to_string();
        assert!(err.contains("unknown variant"), "{err}");
        assert_eq!(
            Config::parse(&base).unwrap().reachable_registries(),
            Some(std::collections::BTreeSet::new()),
            "gateways and no registry: every image is unreachable, said at the claim"
        );
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
    fn the_policy_egress_switch_defaults_to_shadow_and_refuses_a_misspelling() {
        use mediatore_claims::policy::EgressMode;
        let k = conformance_key();
        let keys = format!("  trusted_keys: [{{ id: \"notaio:v1\", public_key: \"{k}\" }}]\n");
        let default = with_policy(&format!("policy:\n{keys}")).unwrap();
        assert_eq!(default.policy.unwrap().egress, EgressMode::Shadow);
        let on = with_policy(&format!("policy:\n{keys}  egress: enforce\n")).unwrap();
        assert_eq!(on.policy.unwrap().egress, EgressMode::Enforce);
        // Fail closed: a value the broker does not know is a refused start, not shadow.
        assert!(with_policy(&format!("policy:\n{keys}  egress: enforced\n")).is_err());
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

    // ----- ADR-0040: inject: gateway ------------------------------------------------------------------------------------

    const INJECT_BASE: &str = "trust_domain: sandbox.test\nissuers: []\nlisten: { user: 127.0.0.1:8080, sandbox: 127.0.0.1:8443 }\ndev_mode: true\nstore: { sealing: { key_file: /k } }\nsts: { issuer: https://mediatore.test, kid: k, signing_key_file: /k }\ngateways: [\"198.51.100.1:3128\", \"198.51.100.2:3128\"]\ngateway_inject_port: 3133\n";
    const INJECT_OK: &str = "  - name: anthropic\n    via: delegated\n    inject: gateway\n    max_ttl: 300\n    egress: [\"api.anthropic.example:443\"]\n    rules:\n      - { method: POST, path: \"/v1/messages\" }\n";

    fn inject_cfg(audiences: &str) -> String {
        format!("{INJECT_BASE}audiences:\n{audiences}")
    }

    fn inject_err(base: &str, audiences: &str) -> String {
        Config::parse(&format!("{base}audiences:\n{audiences}"))
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn a_placed_audiences_host_is_a_reachable_registry_and_names_its_audience() {
        // ADR-0043 decision 1: a registry the gateway places a credential for is reached through the gateway, so a claim
        // may name an image on it, and the broker knows which audience serves that registry.
        let cfg = Config::parse(&inject_cfg(INJECT_OK)).unwrap();
        assert!(
            cfg.reachable_registries()
                .unwrap()
                .contains("api.anthropic.example"),
            "the host of a gateway-placed audience is reachable"
        );
        assert_eq!(
            cfg.placed_registries()
                .get("api.anthropic.example")
                .map(String::as_str),
            Some("anthropic")
        );
        // A port other than 443 is part of the name, as an image reference carries it.
        let odd = INJECT_OK.replace("api.anthropic.example:443", "registry.home.example:5443");
        let cfg = Config::parse(&inject_cfg(&odd)).unwrap();
        assert!(
            cfg.reachable_registries()
                .unwrap()
                .contains("registry.home.example:5443")
        );
        assert_eq!(
            cfg.placed_registries()
                .get("registry.home.example:5443")
                .map(String::as_str),
            Some("anthropic")
        );
    }

    // ----- ADR-0041: credential: basic ----------------------------------------------------------------------------------

    #[test]
    fn a_basic_credential_is_gateway_placed_delegated_authorization_with_no_refresh() {
        let ok = INJECT_OK.replace("anthropic", "ldap") + "    credential: basic\n";
        let cfg = Config::parse(&inject_cfg(&ok)).expect("basic, delegated, gateway-placed");
        assert_eq!(cfg.audiences[0].credential, Credential::Basic);
        let bearer = Config::parse(&inject_cfg(INJECT_OK)).unwrap();
        assert_eq!(
            bearer.audiences[0].credential,
            Credential::Bearer,
            "absent is a bearer"
        );
        for (extra, why) in [
            ("    credential: basic\n    inject: proxy\n", "gateway only"),
            (
                "    credential: basic\n    header: x-auth\n",
                "authorization",
            ),
            (
                "    credential: basic\n    refresh: { token_endpoint: \"https://t.example/token\", client_id: c }\n",
                "nothing to renew",
            ),
        ] {
            let aud = INJECT_OK
                .replace("anthropic", "ldap")
                .replace("    inject: gateway\n", "")
                + "    inject: gateway\n"
                + extra;
            let aud = if extra.contains("inject: proxy") {
                INJECT_OK
                    .replace("anthropic", "ldap")
                    .replace("    inject: gateway\n", "")
                    + extra
            } else {
                aud
            };
            let err = inject_err(INJECT_BASE, &aud);
            assert!(err.contains(why), "expected {why:?} in: {err}");
        }
        let secret = "  - name: ldap\n    via: secret\n    secret_file: /s\n    credential: basic\n    egress: [\"h.example:443\"]\n";
        assert!(inject_err(INJECT_BASE, secret).contains("via: delegated"));
    }

    #[test]
    fn inject_defaults_to_proxy_and_a_proxy_audience_is_unchanged() {
        let cfg = Config::parse(
            "trust_domain: sandbox.test\nissuers: []\nlisten: { user: 127.0.0.1:8080, sandbox: 127.0.0.1:8443 }\ndev_mode: true\naudiences:\n  - name: a\n    via: secret\n    secret_file: /s\n    egress: [\"*.wild.example:443\", \"b.example:443\"]\n  - name: b\n    via: none\n    inject: proxy\n    egress: [\"c.example:443\"]\n"
        )
        .unwrap();
        assert_eq!(cfg.audiences[0].inject, Inject::Proxy, "absent means proxy");
        assert_eq!(cfg.audiences[1].inject, Inject::Proxy);
        assert!(cfg.audiences.iter().all(|a| a.inject_routes().is_empty()));
        assert_eq!(cfg.gateway_inject_port, None);
    }

    #[test]
    fn a_gateway_placed_audience_is_accepted_and_hands_the_gateway_its_exact_routes() {
        let cfg = Config::parse(&inject_cfg(INJECT_OK)).unwrap();
        assert_eq!(cfg.gateway_inject_port, Some(3133));
        let a = &cfg.audiences[0];
        assert_eq!(a.inject, Inject::Gateway);
        let routes = a.inject_routes();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].audience, "anthropic");
        assert_eq!(routes[0].endpoint.to_string(), "api.anthropic.example:443");
        assert_eq!(routes[0].rules.len(), 1);
        assert_eq!(
            routes[0].header, "authorization",
            "delegated: the audience's `header`"
        );
        assert_eq!(routes[0].extra_headers, Vec::<HeaderPair>::new());
        assert!(routes[0].matches_authority("api.anthropic.example", None));
        assert!(!routes[0].matches_authority("api.anthropic.example", Some(8443)));
        assert_eq!(cfg.gateway_placed().len(), 1);
    }

    #[test]
    fn each_credential_source_names_its_own_header_and_public_extras_on_the_route() {
        let cfg = Config::parse(&inject_cfg(
            "  - name: keyed\n    via: secret\n    secret_file: /s\n    secret_header: x-api-key\n    secret_extra_headers:\n      - { name: anthropic-version, value: \"2023-06-01\" }\n    inject: gateway\n    max_ttl: 300\n    egress: [\"keyed.example:443\"]\n    rules: [ { method: POST, path: \"/v1/**\" } ]\n  - name: signed\n    via: sts\n    inject: gateway\n    max_ttl: 120\n    egress: [\"signed.example:443\"]\n    rules: [ { method: GET, path: \"/**\" } ]\n  - name: session\n    via: delegated\n    header: x-session\n    extra_headers:\n      - { name: anthropic-beta, value: oauth-2025-04-20 }\n    inject: gateway\n    egress: [\"session.example:443\"]\n    max_ttl: 300\n    rules: [ { method: POST, path: \"/v1/messages\" } ]\n",
        ))
        .unwrap();
        let keyed = cfg.audiences[0].inject_routes();
        assert_eq!(keyed[0].header, "x-api-key");
        assert_eq!(keyed[0].extra_headers.len(), 1);
        assert_eq!(keyed[0].extra_headers[0].name, "anthropic-version");
        let signed = cfg.audiences[1].inject_routes();
        assert_eq!(signed[0].header, "authorization");
        assert_eq!(signed[0].extra_headers, Vec::<HeaderPair>::new());
        let session = cfg.audiences[2].inject_routes();
        assert_eq!(session[0].header, "x-session");
        assert_eq!(session[0].extra_headers[0].name, "anthropic-beta");
    }

    #[test]
    fn a_via_none_audience_has_no_credential_to_place() {
        let err = inject_err(
            INJECT_BASE,
            "  - name: open\n    via: none\n    inject: gateway\n    max_ttl: 300\n    egress: [\"open.example:443\"]\n    rules: [ { method: GET, path: \"/**\" } ]\n",
        );
        assert!(
            err.contains("\"open\"") && err.contains("via: none") && err.contains("ADR-0040"),
            "{err}"
        );
    }

    #[test]
    fn gateway_placement_needs_gateways_and_the_inject_port() {
        let no_gateways = INJECT_BASE.replace(
            "gateways: [\"198.51.100.1:3128\", \"198.51.100.2:3128\"]\n",
            "",
        );
        let err = inject_err(&no_gateways, INJECT_OK);
        assert!(
            err.contains("\"anthropic\"") && err.contains("`gateways`") && err.contains("ADR-0040"),
            "{err}"
        );
        let no_port = INJECT_BASE.replace("gateway_inject_port: 3133\n", "");
        let err = inject_err(&no_port, INJECT_OK);
        assert!(
            err.contains("`gateway_inject_port`") && err.contains("ADR-0040"),
            "{err}"
        );
    }

    #[test]
    fn the_inject_port_is_a_real_port_and_not_a_gateways_data_port() {
        let zero = INJECT_BASE.replace("gateway_inject_port: 3133", "gateway_inject_port: 0");
        let err = Config::parse(&format!("{zero}audiences: []\n"))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("gateway_inject_port") && err.contains("1 to 65535"),
            "{err}"
        );
        let clash = INJECT_BASE.replace("gateway_inject_port: 3133", "gateway_inject_port: 3128");
        let err = Config::parse(&format!("{clash}audiences: []\n"))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("gateway_inject_port") && err.contains("198.51.100.1:3128"),
            "{err}"
        );
    }

    #[test]
    fn max_ttl_is_capped_at_300_for_a_placed_credential() {
        // The default (900) is refused too: the cap is not a default to override quietly.
        let default_ttl = INJECT_OK.replace("    max_ttl: 300\n", "");
        let err = inject_err(INJECT_BASE, &default_ttl);
        assert!(
            err.contains("\"anthropic\"") && err.contains("max_ttl") && err.contains("300"),
            "{err}"
        );
        let over = INJECT_OK.replace("max_ttl: 300", "max_ttl: 301");
        assert!(inject_err(INJECT_BASE, &over).contains("300"));
        assert!(
            Config::parse(&inject_cfg(
                &INJECT_OK.replace("max_ttl: 300", "max_ttl: 60")
            ))
            .is_ok()
        );
        assert!(
            Config::parse(&inject_cfg(INJECT_OK)).is_ok(),
            "exactly 300 is the cap, allowed"
        );
    }

    #[test]
    fn an_unknown_audience_key_stops_the_start_so_a_typo_cannot_leave_a_credential_in_the_proxy() {
        // `injct: gateway` is `inject: gateway` misspelled. Ignored, the audience would be placed in the proxy, the
        // default, and the credential would reach the pool VM the operator meant to keep it from.
        let typo = INJECT_OK.replace("inject: gateway", "injct: gateway");
        assert!(typo != INJECT_OK, "the fixture has the key to misspell");
        let err = inject_err(INJECT_BASE, &typo);
        assert!(
            err.contains("unknown field") && err.contains("injct"),
            "{err}"
        );
        assert!(
            Config::parse(&inject_cfg(INJECT_OK)).is_ok(),
            "the spelled key stays fine"
        );
    }

    #[test]
    fn a_placed_credential_needs_a_host_name_to_verify_not_an_ip_literal() {
        // The gateway originates TLS to the upstream and verifies it by name; an address has no name to verify.
        for lit in ["192.0.2.10:443", "[2001:db8::1]:443"] {
            let ip = INJECT_OK.replace("api.anthropic.example:443", lit);
            let err = inject_err(INJECT_BASE, &ip);
            assert!(
                err.contains("\"anthropic\"")
                    && err.contains("IP address")
                    && err.contains("ADR-0040"),
                "{lit}: {err}"
            );
        }
        assert!(
            Config::parse(&inject_cfg(INJECT_OK)).is_ok(),
            "a host name stays fine"
        );
    }

    #[test]
    fn a_placed_credential_is_bound_to_exact_host_and_port_entries() {
        let wild = INJECT_OK.replace("api.anthropic.example:443", "*.anthropic.example:443");
        let err = inject_err(INJECT_BASE, &wild);
        assert!(
            err.contains("\"anthropic\"") && err.contains("wildcard") && err.contains("ADR-0040"),
            "{err}"
        );
        let partial = INJECT_OK.replace("api.anthropic.example:443", "api.*.example:443");
        assert!(inject_err(INJECT_BASE, &partial).contains("wildcard"));
        let none = INJECT_OK.replace("    egress: [\"api.anthropic.example:443\"]\n", "");
        let err = inject_err(INJECT_BASE, &none);
        assert!(
            err.contains("`egress`") && err.contains("ADR-0040"),
            "{err}"
        );
        // A bare host (no port) or a hostless entry cannot even be an endpoint.
        let bare = INJECT_OK.replace("api.anthropic.example:443", "api.anthropic.example");
        assert!(Config::parse(&inject_cfg(&bare)).is_err());
        let hostless = INJECT_OK.replace("api.anthropic.example:443", ":443");
        assert!(Config::parse(&inject_cfg(&hostless)).is_err());
    }

    #[test]
    fn a_placed_audience_has_one_upstream_though_it_may_name_several_ports_of_it() {
        let two_hosts = INJECT_OK.replace(
            "[\"api.anthropic.example:443\"]",
            "[\"api.anthropic.example:443\", \"other.example:443\"]",
        );
        let err = inject_err(INJECT_BASE, &two_hosts);
        assert!(
            err.contains("\"anthropic\"")
                && err.contains("one upstream")
                && err.contains("ADR-0040"),
            "{err}"
        );
        let two_ports = INJECT_OK.replace(
            "[\"api.anthropic.example:443\"]",
            "[\"api.anthropic.example:443\", \"API.Anthropic.Example:8443\"]",
        );
        let cfg = Config::parse(&inject_cfg(&two_ports)).unwrap();
        assert_eq!(
            cfg.audiences[0].inject_routes().len(),
            2,
            "one route per exact authority"
        );
    }

    #[test]
    fn a_placed_credential_does_not_get_the_proxys_empty_rules_default() {
        let no_rules = INJECT_OK.replace(
            "    rules:\n      - { method: POST, path: \"/v1/messages\" }\n",
            "",
        );
        let err = inject_err(INJECT_BASE, &no_rules);
        assert!(
            err.contains("\"anthropic\"") && err.contains("`rules`") && err.contains("ADR-0040"),
            "{err}"
        );
        // Under proxy the same audience, with no rules, still means every method and path.
        let proxy = no_rules.replace("inject: gateway", "inject: proxy");
        assert!(Config::parse(&inject_cfg(&proxy)).is_ok());
    }

    #[test]
    fn an_unknown_inject_value_is_refused_and_the_helpers_are_empty_without_gateway_placement() {
        let err = inject_err(
            INJECT_BASE,
            &INJECT_OK.replace("inject: gateway", "inject: sidecar"),
        );
        assert!(
            err.contains("unknown variant") && err.contains("sidecar"),
            "{err}"
        );
        let cfg = Config::parse(&inject_cfg(
            &INJECT_OK.replace("inject: gateway", "inject: proxy"),
        ))
        .unwrap();
        assert_eq!(cfg.audiences[0].inject_routes(), Vec::<InjectRoute>::new());
        assert_eq!(cfg.gateway_placed().len(), 0);
    }
}
