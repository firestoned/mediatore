// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Server configuration (`mediatore.yaml`).

use std::path::{Path, PathBuf};

use mediatore_api::Namespaces;
use mediatore_entra::{Backend, IssuerConfig};
use mediatore_proto::image::canonical_registry;
use mediatore_proto::{
    DEFAULT_LOG_MAX_BYTES, Endpoint, EndpointRule, GATEWAY_CREDENTIAL_MAX_TTL_SECS, HeaderPair,
    InjectRoute, LOG_MAX_BYTES_CEILING, LOG_SEGMENT_BYTES,
};
use mediatore_store::LogLimits;
use mediatore_store::seal::TransitConfig;
use serde::Deserialize;

/// What an audience is for (ADR-0063 decision 2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AudienceRole {
    /// An API the workload calls: today's audience, and the default.
    #[default]
    Api,
    /// An image registry the claim's image may be pulled from: its `egress` names the registries, its routes are
    /// pull-only (the guest's puller reaches them through the claim's proxy, the workload never does), and its
    /// `rules`, when any, admit only `GET` and `HEAD` under `/v2/`.
    Registry,
}

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
    /// What the audience is for (ADR-0063 decision 2): `api` (default) or `registry`, a registry the claim's image
    /// may be pulled from and nothing the workload may call.
    #[serde(default)]
    pub role: AudienceRole,
    /// What the delegated credential is (ADR-0041): `bearer` (default) or `basic`.
    #[serde(default)]
    pub credential: Credential,
    /// ADR-0053: the namespaces this audience is usable from, each with its own `rules`. Absent,
    /// the audience is usable from every namespace with the top-level `rules` (unchanged).
    /// Present, the map is the whole of where it is usable, and the top-level `rules` must be empty.
    #[serde(default)]
    pub namespaces: Option<std::collections::BTreeMap<String, NamespaceRules>>,
}

/// One namespace of an audience's `namespaces` (ADR-0053 decision 1). A typo in the field is a
/// start error, never an entry with no rules.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceRules {
    /// What the workload may ask of the audience from this namespace. Must be non-empty: an
    /// empty list means every method and path (ADR-0053 decision 3).
    #[serde(default)]
    pub rules: Vec<EndpointRule>,
}

impl AudienceConfig {
    /// The per-namespace rules of a scoped audience, `None` for an unscoped one (ADR-0053 decision 4). The one
    /// place the broker reads them from: the API, the proxy's routes, the gateway's routes and the watcher
    /// each hold this map and ask it for the claim's namespace; a namespace it lacks is not usable there.
    #[must_use]
    pub fn scoped_rules(&self) -> Option<std::collections::BTreeMap<String, Vec<EndpointRule>>> {
        self.namespaces.as_ref().map(|m| {
            m.iter()
                .map(|(ns, n)| (ns.clone(), n.rules.clone()))
                .collect()
        })
    }

    /// The request header this audience's credential goes in, lowercase: `secret_header` for
    /// `via: secret`, `header` for `via: delegated`, `authorization` (a bearer) otherwise.
    fn credential_header(&self) -> &str {
        match self.via {
            Backend::Secret => &self.secret_header,
            Backend::Delegated => &self.header,
            _ => "authorization",
        }
    }

    /// What the shadow comparison compares with a signed definition (ADR-0055 decision 8).
    #[must_use]
    pub fn shape(&self) -> mediatore_claims::audience::Shape {
        let backend = match self.via {
            Backend::Sts => "sts",
            Backend::Secret => "secret",
            Backend::Delegated => "delegated",
            Backend::EntraObo => "entra-obo",
            Backend::None => "none",
        };
        let placement = match self.inject {
            Inject::Proxy => "proxy",
            Inject::Gateway => "gateway",
        };
        let format = match (self.via, self.credential) {
            (Backend::Delegated, Credential::Basic) => "basic",
            _ => "bearer",
        };
        mediatore_claims::audience::Shape::new(
            backend,
            placement,
            format,
            self.credential_header(),
            self.public_extra_headers().iter().map(|h| h.name.clone()),
            self.egress.iter().map(ToString::to_string),
            self.rules
                .iter()
                .map(|r| (r.method.clone(), r.path.clone())),
            self.max_ttl,
        )
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

/// `AgentSandbox` resources the user API creates (ADR-0008 decision 4, ADR-0046).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxesSection {
    /// Namespace `POST /v1/claims` creates sandboxes in, the single-namespace form. The
    /// `VirtualMachinePool` a request names must live there (the claim's `poolRef` is a
    /// same-namespace reference). `None` is "not written": the default is `sandboxes`, and
    /// with `namespaces` set the key must not be written at all (ADR-0046 decisions 3, 14).
    #[serde(default)]
    pub namespace: Option<String>,
    /// Namespace to the groups whose members may create sandboxes there (ADR-0046 decision 3).
    /// Exclusive with `namespace`; with it set there is no default namespace.
    #[serde(default)]
    pub namespaces: Option<std::collections::BTreeMap<String, NamespaceEntry>>,
    /// The longest lifetime a claim may ask for, in seconds, through either front door
    /// (`ttl_seconds` on `POST /v1/claims`, `spec.ttlSeconds` on an `AgentSandbox`), with or
    /// without a policy: above it the API answers `400 ttl_exceeds_maximum` and the reconciler
    /// fails the sandbox, before anything exists (ADR-0008 decision 9, amended 2026-11-26). A
    /// policy's lease only narrows it. Positive. Default `86400`, one day: the same figure as
    /// the default of the gateways' tunnel cap (`TUNNEL_MAX_SECS`, `image/gateway/env.example`),
    /// which no tunnel outlives; raise the two together. Read at creation only: a claim already
    /// bound is not released when the key is lowered.
    #[serde(default = "default_max_ttl_seconds")]
    pub max_ttl_seconds: u32,
}

impl Default for SandboxesSection {
    fn default() -> Self {
        Self {
            namespace: None,
            namespaces: None,
            max_ttl_seconds: default_max_ttl_seconds(),
        }
    }
}

fn default_max_ttl_seconds() -> u32 {
    mediatore_proto::DEFAULT_MAX_TTL_SECONDS
}

/// One namespace of `sandboxes.namespaces`. A typo in the field is a start error, never an
/// entry with no groups (ADR-0046 decision 3).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamespaceEntry {
    /// Groups of which a caller must hold at least one, matched exactly (ADR-0046 decision 2).
    /// Required and non-empty.
    pub groups: Vec<String>,
}

fn default_sandbox_namespace() -> String {
    "sandboxes".into()
}

impl SandboxesSection {
    /// The single namespace: the one written, or `sandboxes`. Meaningful only without
    /// `namespaces`, which [`Config::parse`] guarantees by refusing both.
    #[must_use]
    pub fn single_namespace(&self) -> String {
        self.namespace
            .clone()
            .unwrap_or_else(default_sandbox_namespace)
    }

    /// What the user API serves (ADR-0046 decision 3): the map when `namespaces` is set,
    /// otherwise the single open namespace, exactly as before.
    #[must_use]
    pub fn resolve(&self) -> Namespaces {
        match &self.namespaces {
            Some(map) => Namespaces::Map(
                map.iter()
                    .map(|(ns, e)| (ns.clone(), e.groups.clone()))
                    .collect(),
            ),
            None => Namespaces::Single(self.single_namespace()),
        }
    }

    /// ADR-0046 decision 14, each refusal naming the key and the value; and the ceiling of
    /// ADR-0008 decision 9 (amended 2026-11-26), which zero would turn into "no claim at all".
    fn validate(&self) -> anyhow::Result<()> {
        if self.max_ttl_seconds == 0 {
            anyhow::bail!(
                "sandboxes.max_ttl_seconds must be positive: it is the longest lifetime a claim may ask for, in seconds (default {})",
                default_max_ttl_seconds()
            );
        }
        let Some(map) = &self.namespaces else {
            if self.single_namespace().trim().is_empty() {
                anyhow::bail!("sandboxes.namespace must not be empty");
            }
            return Ok(());
        };
        if let Some(ns) = &self.namespace {
            anyhow::bail!(
                "sandboxes.namespace ({ns:?}) is written together with sandboxes.namespaces: the two are exclusive, and with the map set there is no default namespace (ADR-0046 decision 3)"
            );
        }
        if map.is_empty() {
            anyhow::bail!(
                "sandboxes.namespaces is empty: list at least one namespace, or leave the key out for the single-namespace form (ADR-0046 decision 14)"
            );
        }
        for (ns, entry) in map {
            if !mediatore_proto::is_dns_label(ns) {
                anyhow::bail!(
                    "sandboxes.namespaces: key {ns:?} is not an RFC 1123 label (lowercase letters, digits and `-`, at most 63) (ADR-0046 decision 14)"
                );
            }
            if entry.groups.is_empty() {
                anyhow::bail!(
                    "sandboxes.namespaces.{ns}.groups is empty: list the groups whose members may claim there (ADR-0046 decision 14)"
                );
            }
            let mut seen = std::collections::BTreeSet::new();
            for g in &entry.groups {
                if g.trim().is_empty() || g.trim() != g {
                    anyhow::bail!(
                        "sandboxes.namespaces.{ns}.groups: {g:?} is empty or has leading or trailing whitespace (ADR-0046 decision 14)"
                    );
                }
                if !seen.insert(g.as_str()) {
                    anyhow::bail!(
                        "sandboxes.namespaces.{ns}.groups: {g:?} is listed twice (ADR-0046 decision 14)"
                    );
                }
            }
        }
        Ok(())
    }
}

/// notaio's policy bundles, read, verified and compared with each sandbox in shadow
/// (ADR-0026). Absent, the broker reads no bundle and compares nothing.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// Whether a claim must be under a verified bundle that grants what it asks for (ADR-0053
    /// decisions 9 to 16): `shadow` (the default) logs each refusal `enforce` would make,
    /// `enforce` refuses. Per broker deployment, so per environment.
    #[serde(default)]
    pub audiences: mediatore_claims::policy::EgressMode,
    /// Whether a running claim follows a newer bundle only while it is still inside it
    /// (ADR-0061 decision 5): `shadow` (the default) logs and records each refusal, `enforce`
    /// refuses, and only while `audiences` is `enforce` too.
    #[serde(default)]
    pub follow: mediatore_claims::policy::EgressMode,
    /// Sandbox namespace to the policy namespaces it draws from (ADR-0054 decision 2).
    /// Optional: a namespace with no entry finds a policy in itself and nowhere else, and an
    /// entry is the whole of that namespace's sources (its own included only if listed).
    /// `namespaces` above says where bundles are read; this says who may run under them.
    /// No mapping is spelled by leaving the key out: present and empty does not start.
    #[serde(default)]
    pub sources: Option<std::collections::BTreeMap<String, PolicySourceEntry>>,
    /// Where audience definitions come from (ADR-0055 decision 8). Absent means `config`:
    /// `audiences[]` in this file, and no audience bundle is read.
    #[serde(default)]
    pub audience_definitions: Option<AudienceDefinitionsSection>,
}

/// Where the broker's audience definitions come from (ADR-0055 decision 8).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AudienceMode {
    /// `audiences[]` in this file; audience bundles are not read. The default.
    #[default]
    Config,
    /// Both are read and the file serves; each audience's comparison is logged when it changes.
    Shadow,
    /// notaio's signed audience bundles serve; `audiences[]` must be empty.
    Bundles,
}

impl std::fmt::Display for AudienceMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Config => "config",
            Self::Shadow => "shadow",
            Self::Bundles => "bundles",
        })
    }
}

/// `policy.audience_definitions` (ADR-0055 decisions 1 and 10). A typo in a field is a start error.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AudienceDefinitionsSection {
    /// `config` (default), `shadow` or `bundles`.
    #[serde(default)]
    pub mode: AudienceMode,
    /// The namespace platform audiences live in: must match notaio's
    /// `NOTAIO_AUDIENCE_PLATFORM_NAMESPACE`. An RFC 1123 label; no default.
    pub platform_namespace: String,
    /// Between reads of an audience's credential source (decision 5); a failed read keeps the
    /// last good value for two of these.
    #[serde(default = "default_credential_refresh_secs")]
    pub credential_refresh_secs: u64,
    /// The platform's `OpenBao`, for platform audiences whose credential is a KV v2 path
    /// (decision 5), logged in to as the broker's `ServiceAccount`. Absent, such an audience has
    /// no credential and says so in the log.
    #[serde(default)]
    pub openbao: Option<mediatore_openbao::KvConfig>,
}

const fn default_credential_refresh_secs() -> u64 {
    60
}

/// One sandbox namespace of `policy.sources`. A struct, not a bare list, so a typo in the
/// field is a start error (ADR-0054 decision 2).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySourceEntry {
    /// The policy namespaces this sandbox namespace draws from: required, non-empty, each
    /// one of `policy.namespaces`, none listed twice.
    pub namespaces: Vec<String>,
}

/// ADR-0054 decision 8, each refusal naming the key and the value: `policy.sources` present
/// and empty, a key or a listed namespace that is not an RFC 1123 label, an empty list, a
/// namespace listed twice in one entry, and a listed namespace the reflector does not read
/// (`policy.namespaces`, already filled in and checked). A duplicate key, a missing
/// `namespaces` and an unknown field are refused by the parse.
fn check_policy_sources(policy: &PolicySection) -> anyhow::Result<()> {
    let Some(sources) = policy.sources.as_ref() else {
        return Ok(());
    };
    if sources.is_empty() {
        anyhow::bail!(
            "policy.sources is empty: list at least one sandbox namespace, or leave the key out so that each namespace draws its policies from itself (ADR-0054 decision 8)"
        );
    }
    for (ns, entry) in sources {
        if !mediatore_proto::is_dns_label(ns) {
            anyhow::bail!(
                "policy.sources: key {ns:?} is not an RFC 1123 label (lowercase letters, digits and `-`, at most 63) (ADR-0054 decision 8)"
            );
        }
        if entry.namespaces.is_empty() {
            anyhow::bail!(
                "policy.sources.{ns}.namespaces is empty: an empty list is neither \"no policies\" nor \"any\"; list the policy namespaces {ns} draws from, or remove the entry (ADR-0054 decision 8)"
            );
        }
        let mut seen = std::collections::BTreeSet::new();
        for source in &entry.namespaces {
            if !mediatore_proto::is_dns_label(source) {
                anyhow::bail!(
                    "policy.sources.{ns}.namespaces: {source:?} is not an RFC 1123 label (ADR-0054 decision 8)"
                );
            }
            if !seen.insert(source.as_str()) {
                anyhow::bail!(
                    "policy.sources.{ns}.namespaces: {source} is listed twice (ADR-0054 decision 8)"
                );
            }
            if !policy.namespaces.contains(source) {
                anyhow::bail!(
                    "policy.sources.{ns}.namespaces: {source} is not in policy.namespaces, so no bundle is read there and the entry could never resolve: add it to policy.namespaces (with its Role) or correct the name (ADR-0054 decision 8)"
                );
            }
        }
    }
    Ok(())
}

/// The wrapping key for refresh material (ADR-0012 decision 3): exactly one of the local
/// key file (the homelab shape) or `OpenBao` transit (the work shape, ADR-0015).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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

/// A workload's output at the broker (ADR-0045 decisions 4 and 11): whether it is stored at
/// all, how much of it, and for how long after the claim ends.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogsSection {
    /// Store and serve output (default `false`). Off, `POST /v1/me/logs` and
    /// `GET /v1/claims/{name}/logs` answer `501 not_implemented`, a claim with
    /// `workload.logs: true` is refused at creation, and the guest keeps the console copy.
    /// On, it needs `store.sealing`: the output is sealed per batch before it is stored and
    /// is never kept in clear (ADR-0052).
    #[serde(default)]
    pub enabled: bool,
    /// The newest output kept per claim, in bytes of record text plus 256 bytes per stored
    /// batch (default 1 MiB, ceiling 4 MiB, floor one 64 KiB segment); the oldest whole
    /// segments beyond it are dropped and their text counted (ADR-0045, ADR-0052).
    #[serde(default = "default_log_max_bytes")]
    pub max_bytes: usize,
    /// Seconds a claim's output outlives the claim's end before the resync sweeps it. Default:
    /// `store.retention_secs`, the ended claim's own window.
    #[serde(default)]
    pub retention_secs: Option<u64>,
}

fn default_log_max_bytes() -> usize {
    DEFAULT_LOG_MAX_BYTES
}

impl Default for LogsSection {
    fn default() -> Self {
        Self {
            enabled: false,
            max_bytes: default_log_max_bytes(),
            retention_secs: None,
        }
    }
}

/// `POST /v1/token` limits (ADR-0013 decision 5).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct Config {
    /// SPIFFE trust domain.
    pub trust_domain: String,
    /// SPIRE: own identity and entries. Optional only in `dev_mode`.
    #[serde(default)]
    pub spire: Option<SpireConfig>,
    /// Trusted upstream issuers.
    pub issuers: Vec<IssuerConfig>,
    /// Audiences mediatore will mint for. Absent is none: under
    /// `policy.audience_definitions.mode: bundles` the file lists none (ADR-0055 decision 8).
    #[serde(default)]
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
    /// A workload's output, stored and served to its owner (ADR-0045 decisions 4 and 11).
    /// Off by default: both routes answer `501` and a claim that opts in is refused.
    #[serde(default)]
    pub logs: LogsSection,
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
    /// The transition switch of ADR-0053 decision 7, for one release: when `true`, the
    /// sandbox listener's handshake and the two gateway routes also accept a peer presenting
    /// the gateways' listener identity, `spiffe://<td>/gateway`, as they did before the
    /// authorizer had `spiffe://<td>/gateway/authorizer`, and every such ask is a `warn`
    /// line. `false` by default and wherever the gateways' entries, their image and the
    /// broker change in one window. While it is `true` a gateway's listeners can ask the
    /// broker what only its authorizer should. The key is removed in the following release,
    /// where a config still carrying it is refused as an unknown field.
    #[serde(default)]
    pub accept_plain_gateway_identity: bool,
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
                    && !self.audiences_may_share(other, &a.name)
                {
                    anyhow::bail!(
                        "egress endpoint {e} is declared by audiences {other:?} and {:?}: the egress proxy must choose one token per endpoint (ADR-0025); two audiences may share one only when both are scoped by `namespaces` to disjoint sets and neither is `inject: gateway` (ADR-0053 decision 6)",
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
                Self::check_rule(&a.name, r)?;
            }
        }
        Ok(())
    }

    /// A rule is a method or `*` with an absolute path glob.
    fn check_rule(audience: &str, r: &EndpointRule) -> anyhow::Result<()> {
        let method_ok = r.method == "*"
            || (!r.method.is_empty() && r.method.chars().all(|c| c.is_ascii_alphabetic()));
        if !method_ok || !r.path.starts_with('/') {
            anyhow::bail!(
                "audience {audience:?}: rule {{ method: {:?}, path: {:?} }} needs an HTTP method or `*` and an absolute path glob",
                r.method,
                r.path
            );
        }
        if let Err(e) = r.validate() {
            anyhow::bail!(
                "audience {audience:?}: rule {{ method: {:?}, path: {:?} }}: {e}",
                r.method,
                r.path
            );
        }
        Ok(())
    }

    /// ADR-0053 decision 6: two audiences may declare one endpoint only when both are scoped to
    /// disjoint namespaces, so a claim never has two for one endpoint. A gateway-placed audience
    /// never shares: the registry-by-host map of ADR-0043 names one audience per host.
    fn audiences_may_share(&self, a: &str, b: &str) -> bool {
        let find = |n: &str| self.audiences.iter().find(|x| x.name == n);
        let (Some(a), Some(b)) = (find(a), find(b)) else {
            return false;
        };
        if a.inject == Inject::Gateway || b.inject == Inject::Gateway {
            return false;
        }
        match (&a.namespaces, &b.namespaces) {
            (Some(x), Some(y)) => x.keys().all(|k| !y.contains_key(k)),
            _ => false,
        }
    }

    /// ADR-0053 decisions 3 and 6, refused at start: the shape of every `namespaces`. The keys are
    /// checked against the claimable namespaces of `sandboxes` (the map's keys, or the one namespace).
    fn check_audience_scopes(&self) -> anyhow::Result<()> {
        let claimable: Vec<String> = match &self.sandboxes.namespaces {
            Some(m) => m.keys().cloned().collect(),
            None => vec![self.sandboxes.single_namespace()],
        };
        for a in &self.audiences {
            let Some(map) = &a.namespaces else { continue };
            let name = &a.name;
            if map.is_empty() {
                anyhow::bail!(
                    "audience {name:?}: `namespaces` is empty: list at least one namespace, or leave the key out for an audience usable from every namespace (ADR-0053 decision 3)"
                );
            }
            for (ns, entry) in map {
                if !mediatore_proto::is_dns_label(ns) {
                    anyhow::bail!(
                        "audience {name:?}: namespaces key {ns:?} is not an RFC 1123 label (ADR-0053 decision 6)"
                    );
                }
                if !claimable.contains(ns) {
                    anyhow::bail!(
                        "audience {name:?}: namespaces key {ns:?} is not a namespace `sandboxes` lets anyone claim in: a typo, not a policy (ADR-0053 decision 6)"
                    );
                }
                if entry.rules.is_empty() {
                    anyhow::bail!(
                        "audience {name:?}: namespaces.{ns}.rules is empty: an empty list admits every method and path; write `{{method: \"*\", path: \"/**\"}}` to say so (ADR-0053 decision 3)"
                    );
                }
                for r in &entry.rules {
                    Self::check_rule(name, r)?;
                    // The top-level `rules` is the platform's ceiling (ADR-0053 decision 3): a grant a
                    // ceiling does not cover is refused, so a mistaken or hostile grant is bounded. An
                    // empty ceiling is no ceiling, as an empty `rules` has always meant every path.
                    if !a.rules.is_empty()
                        && !a
                            .rules
                            .iter()
                            .any(|c| mediatore_claims::shadow::rule_covers(c, r))
                    {
                        anyhow::bail!(
                            "audience {name:?}: namespaces.{ns} rule {{ method: {:?}, path: {:?} }} is outside the audience's `rules`, its ceiling; widen the ceiling or narrow the grant (ADR-0053 decision 3)",
                            r.method,
                            r.path
                        );
                    }
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
            if a.rules.is_empty() && a.namespaces.is_none() {
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
            if !self.gateways.is_empty() {
                anyhow::bail!(
                    "registries[{host}]: with gateways set the pool pulls only through the claim's egress proxy and a gateway, so a registry is an audience with `role: registry`, granted per namespace; `registries[]` and its `reach` are refused (ADR-0063 decision 4)"
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

    /// Every registry some audience of `role: registry` serves, when the environment has gateways (ADR-0063); `None`
    /// without. Tests only: what a claim may pull is [`Self::granted_registries`], per audience.
    #[cfg(test)]
    fn reachable_registries(&self) -> Option<std::collections::BTreeSet<String>> {
        Some(self.granted_registries()?.into_values().flatten().collect())
    }

    /// [`Self::registry_audiences`] where it decides what a claim may pull: with gateways (ADR-0063 decision 4).
    /// `None` in a direct environment, which pulls as it always did and refuses nothing by registry.
    #[must_use]
    pub fn granted_registries(
        &self,
    ) -> Option<std::collections::BTreeMap<String, std::collections::BTreeSet<String>>> {
        (!self.gateways.is_empty()).then(|| self.registry_audiences())
    }

    /// Per audience of `role: registry` (ADR-0063 decision 2), the registries it serves, by the name a reference to
    /// an image on them carries (the host, with the port only when it is not 443). In force only with gateways
    /// ([`Self::granted_registries`]): a direct environment pulls as it always did (decision 4).
    #[must_use]
    fn registry_audiences(
        &self,
    ) -> std::collections::BTreeMap<String, std::collections::BTreeSet<String>> {
        {
            self.audiences
                .iter()
                .filter(|a| a.role == AudienceRole::Registry)
                .map(|a| {
                    (
                        a.name.clone(),
                        a.egress
                            .iter()
                            .map(mediatore_proto::image::registry_name)
                            .collect(),
                    )
                })
                .collect()
        }
    }

    /// An audience of `role: registry` (ADR-0063 decision 2) names at least one registry, and its rules, when it has
    /// any, admit only reading the registry API: `GET` and `HEAD` on a path under `/v2/`. A registry is pulled from,
    /// never written to.
    fn check_registry_audiences(&self) -> anyhow::Result<()> {
        for a in self
            .audiences
            .iter()
            .filter(|a| a.role == AudienceRole::Registry)
        {
            anyhow::ensure!(
                !a.egress.is_empty(),
                "audiences[{}]: role: registry names no registry in `egress` (ADR-0063 decision 2)",
                a.name
            );
            let scoped = a
                .namespaces
                .iter()
                .flat_map(|m| m.values().flat_map(|n| n.rules.iter()));
            for r in a.rules.iter().chain(scoped) {
                let method = r.method.to_ascii_uppercase();
                anyhow::ensure!(
                    (method == "GET" || method == "HEAD") && r.path.starts_with("/v2/"),
                    "audiences[{}]: role: registry admits only GET and HEAD under /v2/, got {} {} (ADR-0063 decision 2)",
                    a.name,
                    r.method,
                    r.path
                );
            }
        }
        Ok(())
    }

    /// The registries that are gateway-placed audiences (ADR-0043 decision 1), by the name a reference to an image
    /// on them carries (the host, with the port only when it is not 443), each with the audience that serves it. A
    /// claim naming an image there must name that audience and delegate a credential for it.
    #[must_use]
    pub fn placed_registries(&self) -> std::collections::BTreeMap<String, String> {
        self.audiences
            .iter()
            .filter(|a| a.inject == Inject::Gateway && a.role == AudienceRole::Registry)
            .flat_map(|a| {
                a.egress
                    .iter()
                    .map(move |e| (mediatore_proto::image::registry_name(e), a.name.clone()))
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
        cfg.check_registry_audiences()?;
        cfg.check_routes()?;
        cfg.check_inject()?;
        cfg.check_entra()?;
        cfg.check_gates()?;
        cfg.check_issuer_urls()?;
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
        cfg.sandboxes.validate()?;
        cfg.check_audience_scopes()?;
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
        cfg.check_logs()?;
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
    /// ADR-0046 decision 19: every issuer carries exactly one written gate. Refused at start
    /// with the issuer's `url` and the keys, never read as "no gate".
    fn check_gates(&self) -> anyhow::Result<()> {
        for issuer in &self.issuers {
            issuer.gate()?;
        }
        Ok(())
    }

    /// An issuer is reached over `https` outside `dev_mode`: its discovery document names the
    /// keys every login is verified with and the endpoint refresh tokens are posted to, so a
    /// plain `http` issuer hands both to whoever sits on the path.
    fn check_issuer_urls(&self) -> anyhow::Result<()> {
        for issuer in &self.issuers {
            if !self.dev_mode && !issuer.url.starts_with("https://") {
                anyhow::bail!("issuer {}: url must be https outside dev_mode", issuer.url);
            }
        }
        Ok(())
    }

    /// What the user API serves: the map, or the single open namespace (ADR-0046 decision 3).
    #[must_use]
    pub fn namespaces(&self) -> Namespaces {
        self.sandboxes.resolve()
    }

    /// ADR-0046 decision 15: a map is enforced by the broker's own Kubernetes front door. A
    /// build that has none (outside `dev_mode`) must not start with a map it cannot honour.
    ///
    /// # Errors
    /// When `sandboxes.namespaces` is set, the front is absent and this is not `dev_mode`.
    pub fn check_front(&self, front_present: bool) -> anyhow::Result<()> {
        if self.sandboxes.namespaces.is_some() && !front_present && !self.dev_mode {
            anyhow::bail!(
                "sandboxes.namespaces is set but this broker has no Kubernetes front: claim creation would answer 501 (ADR-0046 decision 15)"
            );
        }
        Ok(())
    }

    /// The startup lines (ADR-0046 decisions 14 and 18): one per issuer with its gate form,
    /// and the namespaces in force with their group values. Values are configuration, never a
    /// token.
    pub fn log_startup(&self) {
        if self.accept_plain_gateway_identity {
            tracing::warn!(
                "accept_plain_gateway_identity is on: the gateway routes also answer the gateways' listener identity (spiffe://<td>/gateway), so the authorizer's compartment is not in force; set it back to false once no gateway asks under that identity (ADR-0053 decision 7)"
            );
        }
        for issuer in &self.issuers {
            // `check_gates` ran at load; a gate that does not resolve is logged as such.
            let form = issuer
                .gate_form()
                .unwrap_or_else(|e| format!("invalid ({e})"));
            tracing::info!(issuer = %issuer.url, gate = %form, "issuer gate in force");
        }
        if self.logs.enabled {
            tracing::info!(
                max_bytes = self.logs.max_bytes,
                retention_secs = self.log_retention().as_secs(),
                "workload output stored and served to its owner (ADR-0045)"
            );
        } else {
            tracing::info!("workload output not stored: logs.enabled is false (ADR-0045)");
        }
        // ADR-0053 decision 7: a scoped audience says where it is usable; with the namespace map set, an
        // unscoped one is called out once, by name only.
        for a in &self.audiences {
            match &a.namespaces {
                Some(m) => {
                    let names = m.keys().cloned().collect::<Vec<_>>().join(", ");
                    tracing::info!(audience = %a.name, namespaces = %names, "audience scoped to namespaces");
                }
                None if self.sandboxes.namespaces.is_some() => {
                    tracing::warn!(audience = %a.name, "audience unscoped: usable from every namespace");
                }
                None => {}
            }
        }
        match self.namespaces() {
            Namespaces::Single(ns) => {
                tracing::info!(namespaces = %format!("single open namespace {ns}"), "sandbox namespaces in force");
            }
            Namespaces::Map(map) => {
                tracing::info!(
                    namespaces = %format!("map of {} namespaces", map.len()),
                    "sandbox namespaces in force"
                );
                for (ns, groups) in &map {
                    tracing::info!(namespace = %ns, groups = %groups.join(", "), "namespace groups");
                }
                tracing::info!(
                    "a namespace in the map that does not exist fails the create with the API server's error (502)"
                );
            }
        }
        tracing::info!(
            max_ttl_seconds = self.sandboxes.max_ttl_seconds,
            "longest lifetime a claim may ask for (sandboxes.max_ttl_seconds)"
        );
        self.log_policy_sources();
    }

    /// ADR-0045 decision 4: `logs.max_bytes` within its floor (one segment) and ceiling, checked
    /// whether or not the feature is on, so a typo is found before the switch is flipped.
    fn check_logs(&self) -> anyhow::Result<()> {
        // ADR-0052 decision 5: output is sealed before it is stored, so storing it needs a
        // sealer. dev_mode keeps its in-memory ring (memory, not a store at rest).
        if self.logs.enabled && !self.dev_mode && self.store.sealing.is_none() {
            anyhow::bail!(
                "logs.enabled needs store.sealing (key_file or transit): workload output is sealed per batch before it is stored and is never kept in clear (ADR-0052)"
            );
        }
        if self.logs.max_bytes > LOG_MAX_BYTES_CEILING {
            anyhow::bail!(
                "logs.max_bytes {} is over the ceiling of {LOG_MAX_BYTES_CEILING} bytes (ADR-0045 decision 4)",
                self.logs.max_bytes
            );
        }
        if self.logs.max_bytes < LOG_SEGMENT_BYTES {
            anyhow::bail!(
                "logs.max_bytes {} is under one segment of {LOG_SEGMENT_BYTES} bytes (ADR-0045 decision 6)",
                self.logs.max_bytes
            );
        }
        Ok(())
    }

    /// What bounds a claim's stored output, when output is stored at all (ADR-0045 decision 11):
    /// `None` is the feature off, and the API fails closed on it.
    #[must_use]
    pub fn log_limits(&self) -> Option<LogLimits> {
        self.logs.enabled.then_some(LogLimits {
            max_bytes: self.logs.max_bytes,
        })
    }

    /// How long a claim's output outlives the claim's end (ADR-0045 decision 4): `logs.retention_secs`,
    /// or the ended claim's own window.
    #[must_use]
    pub fn log_retention(&self) -> std::time::Duration {
        std::time::Duration::from_secs(
            self.logs
                .retention_secs
                .unwrap_or(self.store.retention_secs),
        )
    }

    /// ADR-0026 decisions 2 and 3: at least one key, every key a well-formed Ed25519 key with
    /// an id of its own, and namespaces that are Kubernetes names, listed once. Fills in the
    /// default namespace. A `policy` section without keys is refused rather than read as "off":
    /// leaving the section out is how the broker is told to read no bundle.
    fn check_policy(&mut self) -> anyhow::Result<()> {
        let single = self.sandboxes.namespaces.is_none();
        let default_ns = self.sandboxes.single_namespace();
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
            // With `sandboxes.namespaces` set there is no default namespace to fall back to
            // (ADR-0046 decision 3), and the map does not widen the policy namespaces
            // (decision 8): the operator lists them.
            if !single {
                anyhow::bail!(
                    "policy.namespaces must list the namespaces whose bundles are read: with sandboxes.namespaces set there is no default namespace (ADR-0046 decisions 3 and 8)"
                );
            }
            policy.namespaces.push(default_ns);
        }
        let mut seen = std::collections::BTreeSet::new();
        for ns in &policy.namespaces {
            if !mediatore_proto::is_dns_label(ns) {
                anyhow::bail!("policy.namespaces: {ns:?} is not a Kubernetes namespace name");
            }
            if !seen.insert(ns.as_str()) {
                anyhow::bail!("policy.namespaces: {ns} is listed twice");
            }
        }
        check_policy_sources(policy)?;
        self.check_audience_definitions()
    }

    /// ADR-0055 decision 10: a platform namespace that is an RFC 1123 label, a positive refresh,
    /// and under `bundles` no `audiences[]`. `trusted_keys` is already required by the section.
    fn check_audience_definitions(&self) -> anyhow::Result<()> {
        let Some(d) = self
            .policy
            .as_ref()
            .and_then(|p| p.audience_definitions.as_ref())
        else {
            return Ok(());
        };
        if !mediatore_proto::is_dns_label(&d.platform_namespace) {
            anyhow::bail!(
                "policy.audience_definitions.platform_namespace: {:?} is not an RFC 1123 label (ADR-0055 decision 10)",
                d.platform_namespace
            );
        }
        if let Some(o) = &d.openbao
            && !self.dev_mode
            && !o.url.starts_with("https://")
        {
            anyhow::bail!(
                "policy.audience_definitions.openbao.url must be https outside dev_mode (ADR-0055); got {}",
                o.url
            );
        }
        if d.credential_refresh_secs == 0 {
            anyhow::bail!(
                "policy.audience_definitions.credential_refresh_secs must be positive (ADR-0055 decision 5)"
            );
        }
        if d.mode == AudienceMode::Bundles && !self.audiences.is_empty() {
            anyhow::bail!(
                "policy.audience_definitions.mode is bundles but audiences[] lists {} audience(s): under bundles every definition comes from notaio; run shadow until no difference is logged, then remove audiences[] (ADR-0055 decision 8)",
                self.audiences.len()
            );
        }
        Ok(())
    }

    /// Where audience definitions come from: `config` without the section.
    #[must_use]
    pub fn audience_mode(&self) -> AudienceMode {
        self.policy
            .as_ref()
            .and_then(|p| p.audience_definitions.as_ref())
            .map_or(AudienceMode::Config, |d| d.mode)
    }

    /// The namespaces audience bundles are read in (ADR-0055 decision 1): the platform namespace,
    /// then every namespace a sandbox may live in and every policy namespace, each once. Empty
    /// without the section.
    #[must_use]
    pub fn audience_namespaces(&self) -> Vec<String> {
        let Some(d) = self
            .policy
            .as_ref()
            .and_then(|p| p.audience_definitions.as_ref())
        else {
            return Vec::new();
        };
        let mut out = vec![d.platform_namespace.clone()];
        let sandboxes = match self.namespaces() {
            Namespaces::Single(ns) => vec![ns],
            Namespaces::Map(m) => m.into_keys().collect(),
        };
        // A team audience is granted by a policy of its own namespace (decision 3), and the
        // watcher reconciles a sandbox in any namespace: the policy namespaces are read too.
        let policies = self
            .policy
            .as_ref()
            .map(|p| p.namespaces.clone())
            .unwrap_or_default();
        for ns in sandboxes.into_iter().chain(policies) {
            if !out.contains(&ns) {
                out.push(ns);
            }
        }
        out
    }

    /// The file's audiences as the shadow comparison sees them (ADR-0055 decision 8): what a
    /// definition can also say, never a credential or a file path.
    #[must_use]
    pub fn audience_shapes(
        &self,
    ) -> std::collections::BTreeMap<String, mediatore_claims::audience::Shape> {
        self.audiences
            .iter()
            .map(|a| (a.name.clone(), a.shape()))
            .collect()
    }

    /// `policy.sources` as the reconciler, the front door and the gateway answer read it
    /// (ADR-0054 decision 1). Without a `policy` section, or without the key, the mapping is
    /// empty: every namespace draws from itself alone.
    #[must_use]
    pub fn policy_sources(&self) -> mediatore_claims::policy::PolicySources {
        let entries = self
            .policy
            .as_ref()
            .and_then(|p| p.sources.as_ref())
            .map(|sources| {
                sources
                    .iter()
                    .map(|(ns, entry)| (ns.clone(), entry.namespaces.clone()))
                    .collect()
            })
            .unwrap_or_default();
        mediatore_claims::policy::PolicySources::new(entries)
    }

    /// The start lines of ADR-0054 decision 8: per namespace the broker knows (the claim
    /// map's, or the single namespace, and every `policy.sources` key), where it draws its
    /// policies from at `info`; and at `warn` each one whose sources include no watched
    /// namespace, since every `policyRef` there is refused under `enforce` and reported under
    /// `shadow`. A warning, never a refused start: a tenant with audiences and no policy is
    /// legitimate. Names from configuration, never a token. Nothing without a `policy`
    /// section.
    fn log_policy_sources(&self) {
        let Some(policy) = self.policy.as_ref() else {
            return;
        };
        let sources = self.policy_sources();
        let mut known: std::collections::BTreeSet<String> =
            sources.mapped().map(str::to_owned).collect();
        match self.namespaces() {
            Namespaces::Single(ns) => {
                known.insert(ns);
            }
            Namespaces::Map(map) => known.extend(map.into_keys()),
        }
        for ns in &known {
            let drawn = sources.sources_of(ns);
            tracing::info!(namespace = %ns, sources = %drawn.join(", "), "policy sources: where this namespace draws its policies from (ADR-0054)");
            if !drawn
                .iter()
                .any(|d| policy.namespaces.iter().any(|w| w == d))
            {
                tracing::warn!(namespace = %ns, sources = %drawn.join(", "), watched = %policy.namespaces.join(", "), mode = %policy.egress, "no policy source of this namespace is in policy.namespaces: every policyRef there is refused under enforce and reported (P011) under shadow; add a policy.sources entry for it, or watch its own namespace (ADR-0054)");
            }
        }
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
    fn accept_plain_gateway_identity_defaults_to_false() {
        // ADR-0053 decision 7: strict unless the operator says otherwise, in so many words.
        let cfg = Config::parse(&format!("{BASE}dev_mode: true\n")).unwrap();
        assert!(!cfg.accept_plain_gateway_identity, "off when absent");
        let cfg = Config::parse(&format!(
            "{BASE}dev_mode: true\naccept_plain_gateway_identity: false\n"
        ))
        .unwrap();
        assert!(!cfg.accept_plain_gateway_identity);
        let cfg = Config::parse(&format!(
            "{BASE}dev_mode: true\naccept_plain_gateway_identity: true\n"
        ))
        .unwrap();
        assert!(cfg.accept_plain_gateway_identity, "on only when written");
        // A key near it is refused, never read as the default: this is also how the key's
        // removal in the following release stops a broker that still carries it.
        for near in [
            "accept_plain_gateway_identities: true",
            "accept_plain_gateway_id: true",
            "accept_gateway_identity: true",
        ] {
            let err = Config::parse(&format!("{BASE}dev_mode: true\n{near}\n"))
                .unwrap_err()
                .to_string();
            assert!(err.contains("unknown field"), "{near}: {err}");
        }
        assert!(
            Config::parse(&format!(
                "{BASE}dev_mode: true\naccept_plain_gateway_identity: maybe\n"
            ))
            .is_err(),
            "a value that is not a boolean is refused, never read as a default"
        );
    }

    #[test]
    fn startup_warns_while_the_plain_gateway_identity_is_accepted_and_says_nothing_otherwise() {
        let on = Config::parse(&format!(
            "{BASE}dev_mode: true\naccept_plain_gateway_identity: true\n"
        ))
        .unwrap();
        let logs = startup_log(&on);
        assert!(
            logs.lines()
                .any(|l| l.contains("WARN") && l.contains("accept_plain_gateway_identity is on")),
            "{logs}"
        );
        let off = Config::parse(&format!("{BASE}dev_mode: true\n")).unwrap();
        let logs = startup_log(&off);
        assert!(!logs.contains("accept_plain_gateway_identity"), "{logs}");
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
    fn a_rule_with_two_double_stars_fails_the_config() {
        let err = Config::parse(
            "trust_domain: sandbox.test\nissuers: []\nlisten: { user: 127.0.0.1:8080, sandbox: 127.0.0.1:8443 }\ndev_mode: true\nsts: { issuer: https://mediatore.test, kid: k, signing_key_file: /k }\naudiences:\n  - { name: a, via: sts, egress: [\"a.home.example:443\"], rules: [{ method: GET, path: \"/a/**/b/**\" }] }\n",
        )
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("audience \"a\"") && err.contains("**"),
            "{err}"
        );
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
        assert_eq!(cfg.sandboxes.single_namespace(), "sandboxes");
        let cfg = Config::parse(&format!(
            "{BASE}dev_mode: true\nsandboxes: {{ namespace: agents }}\n"
        ))
        .unwrap();
        assert_eq!(cfg.sandboxes.single_namespace(), "agents");
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

    /// A sealer, as `store.sealing` configures one.
    const SEALED: &str = "store: { sealing: { key_file: /k } }\n";

    /// ADR-0052 decision 5: stored output is sealed, so keeping it needs a sealer; there is no
    /// option to keep it in clear. Off, nothing is asked of the operator.
    #[test]
    fn stored_output_needs_a_sealer_and_never_falls_back_to_clear() {
        let err = Config::parse(&format!("{BASE}{SPIRE}logs: {{ enabled: true }}\n"))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("logs.enabled")
                && err.contains("store.sealing")
                && err.contains("ADR-0052"),
            "{err}"
        );
        // A sealer makes it valid, either kind.
        Config::parse(&format!("{BASE}{SPIRE}{SEALED}logs: {{ enabled: true }}\n")).unwrap();
        Config::parse(&format!(
            "{BASE}{SPIRE}store:\n  sealing:\n    transit: {{ url: https://openbao.home.example:8200, key: mediatore, role: mediatore }}\nlogs: {{ enabled: true }}\n"
        ))
        .unwrap();
        // Off needs nothing; dev_mode keeps its in-memory ring, which is not a store at rest.
        Config::parse(&format!("{BASE}{SPIRE}logs: {{ enabled: false }}\n")).unwrap();
        Config::parse(&format!(
            "{BASE}dev_mode: true\nlogs: {{ enabled: true }}\n"
        ))
        .unwrap();
    }

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
    fn output_storage_is_off_by_default_and_bounded_when_on() {
        // ADR-0045 decision 11: nothing is stored unless the operator says so.
        let cfg = Config::parse(&format!("{BASE}dev_mode: true\n")).unwrap();
        assert!(!cfg.logs.enabled);
        assert_eq!(cfg.log_limits(), None, "off: the API fails closed on None");
        assert_eq!(cfg.logs.max_bytes, DEFAULT_LOG_MAX_BYTES);
        assert_eq!(
            cfg.log_retention().as_secs(),
            cfg.store.retention_secs,
            "the default retention is the ended claim's own window"
        );
        let cfg = Config::parse(&format!(
            "{BASE}{SPIRE}{SEALED}logs: {{ enabled: true, max_bytes: 131072, retention_secs: 60 }}\n"
        ))
        .unwrap();
        assert_eq!(cfg.log_limits(), Some(LogLimits { max_bytes: 131_072 }));
        assert_eq!(cfg.log_retention().as_secs(), 60);
        // Decision 4: a ceiling, and a floor of one segment, whether or not the feature is on.
        for (max, needle) in [
            (LOG_MAX_BYTES_CEILING + 1, "ceiling"),
            (LOG_SEGMENT_BYTES - 1, "under one segment"),
        ] {
            let err = Config::parse(&format!("{BASE}{SPIRE}logs: {{ max_bytes: {max} }}\n"))
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("logs.max_bytes") && err.contains(needle),
                "{max}: {err}"
            );
        }
        let cfg = Config::parse(&format!(
            "{BASE}{SPIRE}{SEALED}logs: {{ enabled: true, max_bytes: {LOG_MAX_BYTES_CEILING} }}\n"
        ))
        .unwrap();
        assert_eq!(
            cfg.logs.max_bytes, LOG_MAX_BYTES_CEILING,
            "the ceiling itself is valid"
        );
    }

    #[test]
    fn a_session_issuer_needs_a_sealing_key_and_the_rate_limit_is_positive() {
        let issuer = "issuers:
  - url: https://dex.home.example
    backend: sts
    client_id: mediatore
    subject_claim: preferred_username
    allow_any_authenticated: true
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
    fn an_issuer_url_is_https_outside_dev_mode() {
        let issuer = |url: &str| {
            format!(
                "issuers:\n  - url: {url}\n    backend: sts\n    client_id: mediatore\n    allow_any_authenticated: true\n"
            )
        };
        let prod = "trust_domain: sandbox.test\naudiences: []\nlisten: { user: 0.0.0.0:8080, sandbox: 0.0.0.0:8443 }\nspire:\n  workload_api_socket: unix:///run/spire/sockets/spire-agent.sock\n  entries:\n    class_name: spire-server-spire\n";
        let dev = "trust_domain: sandbox.test\naudiences: []\nlisten: { user: 127.0.0.1:8080, sandbox: 127.0.0.1:8443 }\ndev_mode: true\n";
        for plain in ["http://idp.example.com", "idp.example.com"] {
            let err = Config::parse(&format!("{prod}{}", issuer(plain))).unwrap_err();
            let err = err.to_string();
            assert!(
                err.contains(&format!("issuer {plain}")) && err.contains("must be https"),
                "{err}"
            );
        }
        let cfg = Config::parse(&format!("{prod}{}", issuer("https://idp.example.com"))).unwrap();
        assert_eq!(cfg.issuers[0].url, "https://idp.example.com");
        // http reaches an issuer only under dev_mode (the demo's fake one on loopback).
        let cfg = Config::parse(&format!("{dev}{}", issuer("http://127.0.0.1:18082"))).unwrap();
        assert_eq!(cfg.issuers[0].url, "http://127.0.0.1:18082");
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
            "trust_domain: sandbox.test\naudiences: []\nlisten: { user: 127.0.0.1:8080, sandbox: 127.0.0.1:8443 }\ndev_mode: true\nstore: { sealing: { key_file: /k } }\nissuers:\n  - url: https://accounts.google.com\n    backend: sts\n    client_id: 1234.apps.googleusercontent.com\n    subject_claim: email\n    allow_any_authenticated: true\n    session: { client_id: 1234.apps.googleusercontent.com, client_secret_file: /etc/mediatore-google/secret }\n  - url: https://tenant.us.auth0.com/\n    backend: sts\n    client_id: abc\n    subject_claim: email\n    required_group: sandbox-users\n    groups_claim: https://example.com/groups\n    session: { client_id: abc }\n",
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
                "issuers:\n  - url: https://login.microsoftonline.com/tenant/v2.0\n    backend: entra-obo\n    client_id: broker-app-id\n    allow_any_authenticated: true\n{body}"
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
        assert_eq!(Config::parse(base).unwrap().registries.len(), 0);
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
    fn with_gateways_the_registries_list_is_refused_at_start() {
        // ADR-0063 decision 4: with gateways, no registry is reached but through the claim's proxy and a gateway, so
        // neither reach (segment, relay) nor an operator's registry entry is accepted.
        let base = format!("{BASE}dev_mode: true\ngateways: [\"198.51.100.1:8443\"]\n");
        for entry in [
            "{ host: \"registry.internal:5000\", reach: segment }",
            "{ host: artifactory.example, username: octocat, password_file: /x, reach: relay }",
            "{ host: ghcr.io, username: octocat, password_file: /x }",
        ] {
            let err = Config::parse(&format!("{base}registries:\n  - {entry}\n"))
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("role: registry") && err.contains("ADR-0063"),
                "{entry}: {err}"
            );
        }
        assert_eq!(
            Config::parse(&base).unwrap().reachable_registries(),
            Some(std::collections::BTreeSet::new()),
            "gateways and no registry audience: every image is refused, said at the claim"
        );
        // Without gateways the list stands (a direct environment, decision 4).
        let direct = format!(
            "{BASE}dev_mode: true\nregistries:\n  - {{ host: \"registry.internal:5000\" }}\n"
        );
        let cfg = Config::parse(&direct).unwrap();
        assert_eq!(cfg.registries.len(), 1);
        assert_eq!(
            cfg.granted_registries(),
            None,
            "nothing is granted by registry"
        );
        assert_eq!(cfg.reachable_registries(), None);
    }

    const REGISTRY_BASE: &str = "trust_domain: sandbox.test\nissuers: []\nlisten: { user: 127.0.0.1:8080, sandbox: 127.0.0.1:8443 }\ndev_mode: true\ngateways: [\"198.51.100.1:8443\"]\n";

    #[test]
    fn an_audience_is_a_registry_by_its_role_and_names_the_registries_it_serves() {
        // ADR-0063 decision 2.
        let cfg = Config::parse(&format!(
            "{REGISTRY_BASE}audiences:\n  - {{ name: mirror, via: none, role: registry, egress: [\"registry.home.example:443\", \"odd.home.example:5443\"], rules: [{{ method: GET, path: \"/v2/**\" }}, {{ method: head, path: \"/v2/**\" }}] }}\n  - {{ name: api, via: none, egress: [\"api.home.example:443\"] }}\n"
        ))
        .unwrap();
        assert_eq!(cfg.audiences[0].role, AudienceRole::Registry);
        assert_eq!(cfg.audiences[1].role, AudienceRole::Api, "the default");
        let got = cfg.granted_registries().unwrap();
        assert_eq!(got, cfg.registry_audiences());
        assert_eq!(got.len(), 1, "an api audience serves no registry: {got:?}");
        assert_eq!(
            got["mirror"].iter().cloned().collect::<Vec<_>>(),
            vec![
                "odd.home.example:5443".to_string(),
                "registry.home.example".to_string()
            ],
            "the name an image reference carries: the port only when it is not 443"
        );
        assert!(
            cfg.reachable_registries()
                .unwrap()
                .contains("registry.home.example")
        );
        let err = Config::parse(&format!(
            "{REGISTRY_BASE}audiences:\n  - {{ name: mirror, via: none, role: mirror, egress: [\"registry.home.example:443\"] }}\n"
        ))
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("unknown variant"),
            "a typo is not an api audience: {err}"
        );
    }

    #[test]
    fn a_registry_audience_reads_the_registry_api_and_nothing_else() {
        for (audience, why) in [
            (
                "{ name: mirror, via: none, role: registry }",
                "names no registry",
            ),
            (
                "{ name: mirror, via: none, role: registry, egress: [\"registry.home.example:443\"], rules: [{ method: PUT, path: \"/v2/**\" }] }",
                "only GET and HEAD",
            ),
            (
                "{ name: mirror, via: none, role: registry, egress: [\"registry.home.example:443\"], rules: [{ method: \"*\", path: \"/v2/**\" }] }",
                "only GET and HEAD",
            ),
            (
                "{ name: mirror, via: none, role: registry, egress: [\"registry.home.example:443\"], rules: [{ method: GET, path: \"/api/**\" }] }",
                "under /v2/",
            ),
        ] {
            let err = Config::parse(&format!("{REGISTRY_BASE}audiences:\n  - {audience}\n"))
                .unwrap_err()
                .to_string();
            assert!(
                err.contains(why) && err.contains("ADR-0063"),
                "{audience}: {err}"
            );
        }
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
    fn the_policy_audiences_switch_defaults_to_shadow_and_is_independent_of_the_egress_switch() {
        use mediatore_claims::policy::EgressMode;
        let k = conformance_key();
        let keys = format!("  trusted_keys: [{{ id: \"notaio:v1\", public_key: \"{k}\" }}]\n");
        let default = with_policy(&format!("policy:\n{keys}"))
            .unwrap()
            .policy
            .unwrap();
        assert_eq!(default.audiences, EgressMode::Shadow);
        let on = with_policy(&format!("policy:\n{keys}  audiences: enforce\n"))
            .unwrap()
            .policy
            .unwrap();
        assert_eq!(
            (on.audiences, on.egress),
            (EgressMode::Enforce, EgressMode::Shadow)
        );
        // Fail closed: a value the broker does not know is a refused start, not shadow.
        assert!(with_policy(&format!("policy:\n{keys}  audiences: enforced\n")).is_err());
    }

    #[test]
    fn the_policy_follow_switch_defaults_to_shadow_and_refuses_an_unknown_value() {
        use mediatore_claims::policy::EgressMode;
        let k = conformance_key();
        let keys = format!("  trusted_keys: [{{ id: \"notaio:v1\", public_key: \"{k}\" }}]\n");
        let default = with_policy(&format!("policy:\n{keys}"))
            .unwrap()
            .policy
            .unwrap();
        assert_eq!(default.follow, EgressMode::Shadow);
        let on = with_policy(&format!("policy:\n{keys}  follow: enforce\n"))
            .unwrap()
            .policy
            .unwrap();
        assert_eq!(
            (on.follow, on.audiences),
            (EgressMode::Enforce, EgressMode::Shadow)
        );
        assert!(with_policy(&format!("policy:\n{keys}  follow: enforced\n")).is_err());
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
    fn a_placed_registry_audience_names_its_registry_and_an_api_one_does_not() {
        // ADR-0043 decision 1 under ADR-0063: a registry the gateway places a credential for is an audience of
        // `role: registry`; a placed API audience is not a registry, whatever host it names.
        let placed = "  - name: registry\n    via: delegated\n    credential: basic\n    inject: gateway\n    role: registry\n    max_ttl: 300\n    egress: [\"registry.home.example:5443\"]\n    rules:\n      - { method: GET, path: \"/v2/**\" }\n";
        let cfg = Config::parse(&inject_cfg(placed)).unwrap();
        assert!(
            cfg.reachable_registries()
                .unwrap()
                .contains("registry.home.example:5443")
        );
        assert_eq!(
            cfg.placed_registries()
                .get("registry.home.example:5443")
                .map(String::as_str),
            Some("registry")
        );
        let cfg = Config::parse(&inject_cfg(INJECT_OK)).unwrap();
        assert!(
            cfg.placed_registries().is_empty(),
            "an api audience is no registry"
        );
        assert!(cfg.reachable_registries().unwrap().is_empty());
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

    // ----- ADR-0046: namespaces, gates, unknown keys ----------------------------------------------------------

    const DEV: &str = "trust_domain: sandbox.test\nissuers: []\naudiences: []\nlisten: { user: 127.0.0.1:8080, sandbox: 127.0.0.1:8443 }\ndev_mode: true\n";

    fn with(extra: &str) -> anyhow::Result<Config> {
        Config::parse(&format!("{DEV}{extra}"))
    }

    fn refused(extra: &str) -> String {
        with(extra).unwrap_err().to_string()
    }

    #[test]
    fn a_config_without_namespaces_resolves_to_the_single_open_namespace() {
        assert_eq!(
            with("").unwrap().namespaces(),
            Namespaces::Single("sandboxes".into()),
            "neither key: the default, as before"
        );
        assert_eq!(
            with("sandboxes: { namespace: agents }\n")
                .unwrap()
                .namespaces(),
            Namespaces::Single("agents".into())
        );
    }

    #[test]
    fn namespaces_resolve_to_the_map_with_no_default() {
        let cfg = with("sandboxes:\n  namespaces:\n    infra: { groups: [\"example-org:APP_EXAMPLE_ADMIN\", APP_EXAMPLE_ADMIN] }\n    team-a: { groups: [APP_EXAMPLE_TEAM_A_USER] }\n").unwrap();
        let Namespaces::Map(m) = cfg.namespaces() else {
            panic!("a map was written");
        };
        assert_eq!(m.len(), 2);
        assert_eq!(m["team-a"], ["APP_EXAMPLE_TEAM_A_USER"]);
        assert_eq!(m["infra"].len(), 2);
    }

    #[test]
    fn a_namespaces_map_with_an_empty_groups_list_refuses_to_start() {
        let err = refused("sandboxes:\n  namespaces:\n    team-a: { groups: [] }\n");
        assert!(err.contains("sandboxes.namespaces.team-a.groups"), "{err}");
        let err = refused("sandboxes:\n  namespaces: {}\n");
        assert!(err.contains("sandboxes.namespaces is empty"), "{err}");
        let err = refused("sandboxes:\n  namespaces:\n    team-a: {}\n");
        assert!(err.contains("groups"), "an entry with no groups key: {err}");
        for bad in ["\"\"", "\" \"", "\" x\"", "\"x \""] {
            let err = refused(&format!(
                "sandboxes:\n  namespaces:\n    team-a: {{ groups: [{bad}] }}\n"
            ));
            assert!(
                err.contains("team-a") && err.contains("whitespace"),
                "{bad}: {err}"
            );
        }
        let err = refused("sandboxes:\n  namespaces:\n    team-a: { groups: [G, G] }\n");
        assert!(err.contains("listed twice"), "{err}");
    }

    #[test]
    fn a_namespaces_map_with_a_duplicate_key_refuses_to_start() {
        let err = refused(
            "sandboxes:\n  namespaces:\n    team-a: { groups: [A] }\n    team-a: { groups: [B] }\n",
        );
        assert!(
            err.contains("team-a") || err.to_lowercase().contains("duplicate"),
            "{err}"
        );
    }

    #[test]
    fn a_namespaces_map_with_a_non_dns_label_key_refuses_to_start() {
        for bad in ["Team-A", "team_a", "-a", "a-", "\"\"", "team.a"] {
            let err = refused(&format!(
                "sandboxes:\n  namespaces:\n    {bad}: {{ groups: [G] }}\n"
            ));
            assert!(err.contains("RFC 1123"), "{bad}: {err}");
        }
    }

    #[test]
    fn a_namespaces_map_together_with_sandboxes_namespace_refuses_to_start() {
        let err = refused(
            "sandboxes:\n  namespace: sandboxes\n  namespaces:\n    team-a: { groups: [G] }\n",
        );
        assert!(
            err.contains("sandboxes.namespace") && err.contains("exclusive"),
            "{err}"
        );
    }

    #[test]
    fn a_namespaces_map_with_a_typo_in_an_entry_field_refuses_to_start() {
        let err = refused("sandboxes:\n  namespaces:\n    team-a: { group: [G] }\n");
        assert!(err.contains("group"), "{err}");
        let err = refused("sandboxes:\n  namespaces:\n    team-a: { groups: [G], extra: 1 }\n");
        assert!(err.contains("extra"), "{err}");
    }

    #[test]
    fn a_group_in_two_namespaces_is_accepted() {
        let cfg = with("sandboxes:\n  namespaces:\n    team-a: { groups: [SHARED] }\n    infra: { groups: [SHARED] }\n").unwrap();
        let Namespaces::Map(m) = cfg.namespaces() else {
            panic!("a map was written");
        };
        assert_eq!(m["team-a"], m["infra"]);
    }

    #[test]
    fn a_namespace_map_without_the_kubernetes_front_refuses_to_start() {
        let cfg = with("sandboxes:\n  namespaces:\n    team-a: { groups: [G] }\n").unwrap();
        assert!(cfg.check_front(true).is_ok());
        let mut prod = cfg.clone();
        prod.dev_mode = false;
        let err = prod.check_front(false).unwrap_err().to_string();
        assert!(err.contains("no Kubernetes front"), "{err}");
        assert!(prod.check_front(true).is_ok());
        assert!(
            cfg.check_front(false).is_ok(),
            "dev_mode has the dev store and the same checks (decision 12)"
        );
        let single = with("").unwrap();
        let mut prod = single;
        prod.dev_mode = false;
        assert!(prod.check_front(false).is_ok(), "no map, nothing to refuse");
    }

    #[test]
    fn the_policy_namespaces_have_no_default_once_the_map_is_set() {
        let k = conformance_key();
        let err = refused(&format!(
            "sandboxes:\n  namespaces:\n    team-a: {{ groups: [G] }}\npolicy:\n  trusted_keys: [{{ id: \"notaio:v1\", public_key: \"{k}\" }}]\n"
        ));
        assert!(err.contains("policy.namespaces must list"), "{err}");
        let cfg = with(&format!("sandboxes:\n  namespaces:\n    team-a: {{ groups: [G] }}\npolicy:\n  trusted_keys: [{{ id: \"notaio:v1\", public_key: \"{k}\" }}]\n  namespaces: [team-a]\n")).unwrap();
        assert_eq!(cfg.policy.unwrap().namespaces, ["team-a"]);
    }

    const GATELESS: &str =
        "issuers:\n  - url: https://idp.example.com\n    backend: sts\n    client_id: mediatore\n";

    fn issuer_cfg(extra: &str) -> String {
        format!(
            "trust_domain: sandbox.test\naudiences: []\nlisten: {{ user: 127.0.0.1:8080, sandbox: 127.0.0.1:8443 }}\ndev_mode: true\n{GATELESS}{extra}"
        )
    }

    #[test]
    fn an_issuer_with_no_gate_key_refuses_to_start() {
        let err = Config::parse(&issuer_cfg("")).unwrap_err().to_string();
        assert!(
            err.contains("https://idp.example.com")
                && err.contains("required_group")
                && err.contains("required_groups")
                && err.contains("allow_any_authenticated"),
            "{err}"
        );
        // `false` counts as absent.
        let err = Config::parse(&issuer_cfg("    allow_any_authenticated: false\n"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("no login gate"), "{err}");
        // One gate is enough, in each of its three spellings; two are refused.
        for ok in [
            "    required_group: G\n",
            "    required_groups: [G, H]\n",
            "    allow_any_authenticated: true\n",
        ] {
            assert!(Config::parse(&issuer_cfg(ok)).is_ok(), "{ok}");
        }
        let err = Config::parse(&issuer_cfg(
            "    required_group: G\n    required_groups: [G]\n",
        ))
        .unwrap_err()
        .to_string();
        assert!(err.contains("more than one"), "{err}");
        let err = Config::parse(&issuer_cfg("    required_groups: []\n"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("required_groups"), "{err}");
    }

    #[test]
    fn a_google_issuer_needs_the_explicit_marker() {
        let google = "issuers:\n  - url: https://accounts.google.com\n    backend: sts\n    client_id: 1234.apps.googleusercontent.com\n    subject_claim: email\n    session: { client_id: 1234.apps.googleusercontent.com, client_secret_file: /etc/mediatore-google/secret }\n";
        let base = "trust_domain: sandbox.test\naudiences: []\nlisten: { user: 127.0.0.1:8080, sandbox: 127.0.0.1:8443 }\ndev_mode: true\nstore: { sealing: { key_file: /k } }\n";
        let err = Config::parse(&format!("{base}{google}"))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("accounts.google.com") && err.contains("allow_any_authenticated"),
            "{err}"
        );
        let marked = google.replace(
            "    session:",
            "    allow_any_authenticated: true\n    session:",
        );
        assert!(Config::parse(&format!("{base}{marked}")).is_ok());
    }

    #[test]
    fn an_issuer_with_an_unknown_key_refuses_to_start() {
        for key in ["required_groupz: [G]", "allow_any_authenticated_: true"] {
            let err = Config::parse(&issuer_cfg(&format!("    required_group: G\n    {key}\n")))
                .unwrap_err()
                .to_string();
            assert!(
                err.contains("required_groupz") || err.contains("allow_any_authenticated_"),
                "{err}"
            );
        }
    }

    #[test]
    fn a_top_level_unknown_key_refuses_to_start() {
        let err = refused("unknown_top_level: 1\n");
        assert!(err.contains("unknown_top_level"), "{err}");
    }

    #[test]
    fn the_longest_claim_lifetime_defaults_to_one_day_and_must_be_a_positive_number() {
        // Absent section, and a section that says something else: one day either way.
        assert_eq!(with("").unwrap().sandboxes.max_ttl_seconds, 86_400);
        assert_eq!(
            with("sandboxes: { namespace: agents }\n")
                .unwrap()
                .sandboxes
                .max_ttl_seconds,
            86_400
        );
        assert_eq!(SandboxesSection::default().max_ttl_seconds, 86_400);
        assert_eq!(mediatore_proto::DEFAULT_MAX_TTL_SECONDS, 86_400);
        // Written, beside either form of the namespaces.
        assert_eq!(
            with("sandboxes: { max_ttl_seconds: 3600 }\n")
                .unwrap()
                .sandboxes
                .max_ttl_seconds,
            3600
        );
        let mapped = with(
            "sandboxes:\n  max_ttl_seconds: 172800\n  namespaces:\n    team-a: { groups: [G] }\n",
        )
        .unwrap();
        assert_eq!(mapped.sandboxes.max_ttl_seconds, 172_800);
        // Zero is "no claim at all", refused by name; and so is anything that is not a number
        // of seconds, a negative one or a misspelt key.
        let err = refused("sandboxes: { max_ttl_seconds: 0 }\n");
        assert!(
            err.contains("sandboxes.max_ttl_seconds must be positive"),
            "{err}"
        );
        let err = refused(
            "sandboxes:\n  max_ttl_seconds: 0\n  namespaces:\n    team-a: { groups: [G] }\n",
        );
        assert!(err.contains("sandboxes.max_ttl_seconds"), "{err}");
        for bad in ["one-day", "24h", "-1", "1.5", "[86400]", "4294967296"] {
            assert!(
                with(&format!("sandboxes: {{ max_ttl_seconds: {bad} }}\n")).is_err(),
                "{bad} is not a number of seconds"
            );
        }
        let err = refused("sandboxes: { max_ttl_secs: 3600 }\n");
        assert!(err.contains("max_ttl_secs"), "{err}");
    }

    #[test]
    fn startup_logs_the_longest_claim_lifetime() {
        let logs = startup_log(&two_issuers(""));
        let line = logs
            .lines()
            .find(|l| l.contains("longest lifetime a claim may ask for"))
            .unwrap_or_else(|| panic!("a line for the ceiling in {logs}"));
        assert!(line.contains("max_ttl_seconds=86400"), "{line}");
        let logs = startup_log(&two_issuers("sandboxes: { max_ttl_seconds: 3600 }\n"));
        assert!(logs.contains("max_ttl_seconds=3600"), "{logs}");
    }

    #[test]
    fn a_misspelled_sandboxes_section_refuses_to_start() {
        let err = refused("sandbox: { namespace: team-a }\n");
        assert!(err.contains("sandbox"), "{err}");
        let err = refused("sandboxes: { namespce: team-a }\n");
        assert!(err.contains("namespce"), "{err}");
    }

    #[test]
    fn every_section_rejects_an_unknown_key() {
        for extra in [
            "listen: { user: 127.0.0.1:1, sandbox: 127.0.0.1:2, typo: 1 }\n".to_owned(),
            "watcher: { typo: 1 }\n".into(),
            "store: { typo: 1 }\n".into(),
            "token: { typo: 1 }\n".into(),
            "logs: { typo: 1 }\n".into(),
            "registries: [{ host: ghcr.io, typo: 1 }]\n".into(),
            "sts: { issuer: https://m, kid: k, signing_key_file: /k, typo: 1 }\n".into(),
            "policy: { typo: 1 }\n".into(),
        ] {
            let yaml = format!(
                "trust_domain: sandbox.test\nissuers: []\naudiences: []\ndev_mode: true\n{extra}"
            );
            let yaml = if extra.starts_with("listen") {
                yaml
            } else {
                yaml.replacen(
                    "dev_mode: true\n",
                    "dev_mode: true\nlisten: { user: 127.0.0.1:8080, sandbox: 127.0.0.1:8443 }\n",
                    1,
                )
            };
            let err = Config::parse(&yaml).unwrap_err().to_string();
            assert!(err.contains("typo"), "{extra}: {err}");
        }
    }

    // ----- the startup log (ADR-0046 decisions 14 and 18) ---------------------------------------------------

    // One process-wide subscriber writing into a buffer per thread, as in mediatore-api's tests: a
    // scoped `set_default` is not reliable under the parallel runner.
    thread_local! {
        static LOGS: std::cell::RefCell<Vec<u8>> = const { std::cell::RefCell::new(Vec::new()) };
    }

    struct ThreadLogs;

    impl std::io::Write for ThreadLogs {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            LOGS.with(|l| l.borrow_mut().extend_from_slice(buf));
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn startup_log(cfg: &Config) -> String {
        static INSTALL: std::sync::Once = std::sync::Once::new();
        INSTALL.call_once(|| {
            let _ = tracing::subscriber::set_global_default(
                tracing_subscriber::fmt()
                    .with_writer(|| ThreadLogs)
                    .with_max_level(tracing::Level::TRACE)
                    .with_ansi(false)
                    .finish(),
            );
        });
        LOGS.with(|l| l.borrow_mut().clear());
        cfg.log_startup();
        LOGS.with(|l| String::from_utf8_lossy(&l.borrow()).into_owned())
    }

    fn two_issuers(extra: &str) -> Config {
        let dev = if extra.contains("audiences:") {
            DEV.replace("audiences: []\n", "")
        } else {
            DEV.to_owned()
        };
        Config::parse(&format!(
            "{dev}issuers:\n  - {{ url: \"https://dex.example.com\", backend: sts, client_id: m, required_groups: [\"example-org:APP_EXAMPLE_ADMIN\", APP_EXAMPLE_ADMIN] }}\n  - {{ url: \"https://accounts.example.com\", backend: sts, client_id: m, allow_any_authenticated: true }}\n  - {{ url: \"https://old.example.com\", backend: sts, client_id: m, required_group: LEGACY }}\n{extra}"
        ).replace("issuers: []\n", ""))
        .unwrap()
    }

    // ----- ADR-0054: policy.sources ---------------------------------------------------------------------------------

    /// A `policy` section reading `watched`, with `rest` appended under it (two-space indent).
    fn policy_reading(watched: &str, rest: &str) -> String {
        format!(
            "policy:\n  trusted_keys: [{{ id: \"notaio:v1\", public_key: \"{}\" }}]\n  namespaces: [{watched}]\n{rest}",
            conformance_key()
        )
    }

    const TENANTS: &str = "sandboxes:\n  namespaces:\n    infra: { groups: [ADMIN] }\n    team-a: { groups: [A] }\n    team-b: { groups: [B] }\n";

    #[test]
    fn a_config_without_policy_sources_draws_each_namespace_from_itself() {
        let cfg = with(&policy_reading("sandboxes, team-b", "")).unwrap();
        assert!(cfg.policy.as_ref().unwrap().sources.is_none());
        let sources = cfg.policy_sources();
        assert_eq!(sources, mediatore_claims::policy::PolicySources::default());
        assert_eq!(sources.sources_of("sandboxes"), ["sandboxes"]);
        assert_eq!(sources.sources_of("team-b"), ["team-b"]);
        assert!(!sources.draws_from("sandboxes", "team-b"));
        // And without a policy section at all there is nothing to draw from or to map.
        assert_eq!(
            with("").unwrap().policy_sources(),
            mediatore_claims::policy::PolicySources::default()
        );
    }

    #[test]
    fn a_policy_sources_entry_is_the_whole_of_that_namespaces_sources() {
        let cfg = with(&format!(
            "{TENANTS}{}",
            policy_reading(
                "team-a, team-b, infra-policies",
                "  egress: enforce\n  sources:\n    infra:\n      namespaces: [infra-policies]\n"
            )
        ))
        .unwrap();
        let sources = cfg.policy_sources();
        assert_eq!(sources.sources_of("infra"), ["infra-policies"]);
        assert!(!sources.draws_from("infra", "infra"));
        assert_eq!(sources.sources_of("team-a"), ["team-a"]);
        // Where bundles are read is unchanged by the mapping.
        assert_eq!(
            cfg.policy.unwrap().namespaces,
            ["team-a", "team-b", "infra-policies"]
        );
    }

    #[test]
    fn policy_sources_naming_an_unwatched_namespace_refuses_to_start() {
        let err = refused(&policy_reading(
            "sandboxes",
            "  sources:\n    sandboxes: { namespaces: [infra-policies] }\n",
        ));
        assert!(
            err.contains("policy.sources.sandboxes.namespaces")
                && err.contains("infra-policies")
                && err.contains("policy.namespaces"),
            "{err}"
        );
        // The default watched namespace (filled in at load) counts as watched.
        let cfg = with(&format!(
            "policy:\n  trusted_keys: [{{ id: \"notaio:v1\", public_key: \"{}\" }}]\n  sources:\n    pool-ns: {{ namespaces: [sandboxes] }}\n",
            conformance_key()
        ))
        .unwrap();
        assert_eq!(cfg.policy_sources().sources_of("pool-ns"), ["sandboxes"]);
    }

    // ADR-0055 decisions 8 and 10.

    fn audience_definitions(body: &str) -> String {
        policy_reading("sandboxes", &format!("  audience_definitions:\n{body}"))
    }

    #[test]
    fn without_audience_definitions_the_file_serves_and_no_audience_bundle_is_read() {
        let cfg = with(&policy_reading("sandboxes", "")).unwrap();
        assert_eq!(cfg.audience_mode(), AudienceMode::Config);
        assert_eq!(cfg.audience_namespaces(), Vec::<String>::new());
        assert_eq!(with("").unwrap().audience_mode(), AudienceMode::Config);
    }

    #[test]
    fn shadow_reads_the_platform_namespace_and_every_sandbox_namespace() {
        let cfg = with(&format!(
            "{TENANTS}{}",
            policy_reading(
                "infra, team-a",
                "  audience_definitions: { mode: shadow, platform_namespace: sandbox-platform }\n"
            )
        ))
        .unwrap();
        assert_eq!(cfg.audience_mode(), AudienceMode::Shadow);
        assert_eq!(
            cfg.audience_namespaces(),
            ["sandbox-platform", "infra", "team-a", "team-b"]
        );
        // A policy namespace is read too: a team audience is granted by a policy of its own
        // namespace (ADR-0055 decision 3), and the watcher reconciles sandboxes anywhere.
        let cfg = with(&policy_reading(
            "sandboxes, team-x",
            "  audience_definitions: { mode: shadow, platform_namespace: sandbox-platform }\n",
        ))
        .unwrap();
        assert_eq!(
            cfg.audience_namespaces(),
            ["sandbox-platform", "sandboxes", "team-x"]
        );
        let d = cfg.policy.unwrap().audience_definitions.unwrap();
        assert_eq!(d.credential_refresh_secs, 60);

        // The platform namespace may also be a sandbox namespace; it is read once.
        let cfg = with(&audience_definitions(
            "    mode: shadow\n    platform_namespace: sandboxes\n",
        ))
        .unwrap();
        assert_eq!(cfg.audience_namespaces(), ["sandboxes"]);
    }

    #[test]
    fn audience_definitions_refuse_a_bad_platform_namespace_a_zero_refresh_or_a_typo() {
        let err = refused(&audience_definitions(
            "    mode: shadow\n    platform_namespace: Sandbox_Platform\n",
        ));
        assert!(err.contains("platform_namespace"), "{err}");
        let err = refused(&audience_definitions(
            "    mode: shadow\n    platform_namespace: p\n    credential_refresh_secs: 0\n",
        ));
        assert!(err.contains("credential_refresh_secs"), "{err}");
        assert!(
            with(&audience_definitions(
                "    mode: shadow\n    platform_namespce: p\n"
            ))
            .is_err()
        );
        assert!(
            with(&audience_definitions(
                "    mode: bundle\n    platform_namespace: p\n"
            ))
            .is_err()
        );
        assert!(
            with(&audience_definitions("    mode: shadow\n")).is_err(),
            "no default namespace"
        );
    }

    #[test]
    fn the_audience_openbao_is_https_outside_dev_mode_and_refuses_a_typo() {
        let body = "    mode: shadow\n    platform_namespace: p\n    openbao: { url: \"http://openbao.home.example:8200\", role: mediatore }\n";
        // DEV is dev_mode: plain http is allowed there.
        let cfg = with(&audience_definitions(body)).unwrap();
        let o = cfg
            .policy
            .clone()
            .unwrap()
            .audience_definitions
            .unwrap()
            .openbao
            .unwrap();
        assert_eq!(
            (o.role.as_str(), o.auth_mount.as_str()),
            ("mediatore", "kubernetes")
        );
        let mut cfg = with(&audience_definitions(body)).unwrap();
        cfg.dev_mode = false;
        let err = cfg.check_audience_definitions().unwrap_err().to_string();
        assert!(err.contains("must be https outside dev_mode"), "{err}");
        assert!(
            with(&audience_definitions(
                "    mode: shadow\n    platform_namespace: p\n    openbao: { url: \"https://o\", role: r, key: k }\n"
            ))
            .is_err(),
            "a transit key has no place here"
        );
    }

    #[test]
    fn a_configuration_without_an_audiences_key_parses_as_one_with_none() {
        // ADR-0055 decision 8: the migration ends by removing `audiences[]` from the file.
        let cfg = Config::parse(&format!(
            "{}{}",
            DEV.replace("audiences: []\n", ""),
            audience_definitions("    mode: bundles\n    platform_namespace: p\n")
        ))
        .unwrap();
        assert!(cfg.audiences.is_empty());
        assert_eq!(cfg.audience_mode(), AudienceMode::Bundles);
    }

    #[test]
    fn bundles_refuses_an_audiences_list_and_starts_without_one() {
        let body = "    mode: bundles\n    platform_namespace: p\n";
        let err = Config::parse(&format!(
            "{}audiences:\n  - {{ name: a, via: none }}\n{}",
            DEV.replace("audiences: []\n", ""),
            audience_definitions(body)
        ))
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("audiences[]") && err.contains("shadow"),
            "{err}"
        );
        let cfg = with(&audience_definitions(body)).unwrap();
        assert_eq!(cfg.audience_mode(), AudienceMode::Bundles);
    }

    #[test]
    fn a_file_audience_has_the_shape_a_definition_of_it_would_have() {
        use mediatore_claims::audience::{differences, shape_of};
        use mediatore_policy::types::{
            AudienceCredential, AudienceDefinition, Backend as B, CredentialFormat,
            CredentialSource, HeaderPair as H, Placement, SecretRef,
        };
        let cfg = Config::parse(
            "trust_domain: sandbox.test\nissuers: []\nlisten: { user: 127.0.0.1:8080, sandbox: 127.0.0.1:8443 }\ndev_mode: true\naudiences:\n  - name: anthropic\n    via: secret\n    secret_file: /s\n    secret_header: x-api-key\n    secret_extra_headers:\n      - { name: anthropic-version, value: \"2023-06-01\" }\n    egress: [\"api.anthropic.com:443\"]\n    rules:\n      - { method: POST, path: \"/v1/messages\" }\n",
        )
        .unwrap();
        let file = &cfg.audience_shapes()["anthropic"];
        let signed = AudienceDefinition {
            credential: AudienceCredential {
                backend: B::Secret,
                placement: Placement::Proxy,
                format: CredentialFormat::Bearer,
                source: Some(CredentialSource::SecretRef(SecretRef {
                    name: "anthropic".into(),
                    token_key: "key".into(),
                    username_key: None,
                })),
                header: Some("x-api-key".into()),
                extra_headers: vec![H {
                    name: "anthropic-version".into(),
                    value: "2023-06-01".into(),
                }],
                refresh: None,
            },
            endpoints: vec!["api.anthropic.com:443".into()],
            rules: vec![mediatore_policy::types::EndpointRule {
                method: "post".into(),
                path: "/v1/messages".into(),
            }],
            max_ttl_seconds: 900,
            ca_ref: None,
        };
        assert_eq!(differences(file, &shape_of(&signed)), Vec::<&str>::new());
    }

    #[test]
    fn policy_sources_present_and_empty_refuses_to_start() {
        let err = refused(&policy_reading("sandboxes", "  sources: {}\n"));
        assert!(err.contains("policy.sources is empty"), "{err}");
    }

    #[test]
    fn a_sources_entry_with_an_empty_list_refuses_to_start() {
        let err = refused(&policy_reading(
            "sandboxes",
            "  sources:\n    sandboxes: { namespaces: [] }\n",
        ));
        assert!(
            err.contains("policy.sources.sandboxes.namespaces is empty"),
            "{err}"
        );
        // No `namespaces` key at all is not an empty entry either: the parse refuses it.
        assert!(
            with(&policy_reading(
                "sandboxes",
                "  sources:\n    sandboxes: {}\n"
            ))
            .is_err(),
            "an entry without namespaces does not start"
        );
    }

    #[test]
    fn a_sources_entry_with_a_duplicate_namespace_refuses_to_start() {
        let err = refused(&policy_reading(
            "sandboxes, team-b",
            "  sources:\n    sandboxes: { namespaces: [team-b, team-b] }\n",
        ));
        assert!(
            err.contains("policy.sources.sandboxes.namespaces") && err.contains("listed twice"),
            "{err}"
        );
    }

    #[test]
    fn a_sources_entry_with_a_non_dns_label_refuses_to_start() {
        for bad in ["Team_A", "team.a", "-a"] {
            let err = refused(&policy_reading(
                "sandboxes",
                &format!("  sources:\n    \"{bad}\": {{ namespaces: [sandboxes] }}\n"),
            ));
            assert!(
                err.contains("policy.sources: key") && err.contains("RFC 1123"),
                "key {bad}: {err}"
            );
            let err = refused(&policy_reading(
                "sandboxes",
                &format!("  sources:\n    sandboxes: {{ namespaces: [\"{bad}\"] }}\n"),
            ));
            assert!(
                err.contains("policy.sources.sandboxes.namespaces") && err.contains("RFC 1123"),
                "listed {bad}: {err}"
            );
        }
    }

    #[test]
    fn a_sources_entry_with_a_duplicate_key_refuses_to_start() {
        let err = refused(&policy_reading(
            "sandboxes, team-b",
            "  sources:\n    sandboxes: { namespaces: [sandboxes] }\n    sandboxes: { namespaces: [team-b] }\n",
        ));
        assert!(
            err.contains("sandboxes") || err.to_lowercase().contains("duplicate"),
            "{err}"
        );
    }

    #[test]
    fn a_sources_entry_with_a_typo_in_an_entry_field_refuses_to_start() {
        for entry in [
            "{ namespace: [sandboxes] }",
            "{ namespaces: [sandboxes], names: [agent] }",
        ] {
            assert!(
                with(&policy_reading(
                    "sandboxes",
                    &format!("  sources:\n    sandboxes: {entry}\n")
                ))
                .is_err(),
                "{entry} does not start"
            );
        }
        // A bare list is not the entry's shape either.
        assert!(
            with(&policy_reading(
                "sandboxes",
                "  sources:\n    sandboxes: [sandboxes]\n"
            ))
            .is_err(),
            "a bare list does not start"
        );
    }

    #[test]
    fn startup_logs_where_each_namespace_draws_its_policies_from_and_warns_on_none() {
        // team-a draws from itself (watched); infra from infra-policies (mapped, watched);
        // team-b has no entry and is not watched: every policyRef there will be refused.
        let cfg = with(&format!(
            "{TENANTS}{}",
            policy_reading(
                "team-a, infra-policies",
                "  egress: enforce\n  sources:\n    infra: { namespaces: [infra-policies] }\n"
            )
        ))
        .unwrap();
        let logs = startup_log(&cfg);
        let line = |level: &str, ns: &str| -> Option<String> {
            logs.lines()
                .find(|l| {
                    l.contains(level)
                        && l.contains(&format!("namespace={ns} "))
                        && l.contains("sources=")
                })
                .map(str::to_owned)
        };
        let infra = line("INFO", "infra").expect("an info line for infra");
        assert!(infra.contains("sources=infra-policies"), "{infra}");
        let own = line("INFO", "team-a").expect("an info line for team-a");
        assert!(own.contains("sources=team-a"), "{own}");
        let unwatched = line("INFO", "team-b").expect("an info line for team-b");
        assert!(unwatched.contains("sources=team-b"), "{unwatched}");
        let warned = line("WARN", "team-b").expect("a warning for team-b");
        assert!(
            warned.contains("no policy source of this namespace is in policy.namespaces")
                && warned.contains("mode=enforce"),
            "{warned}"
        );
        assert!(line("WARN", "infra").is_none(), "{logs}");
        assert!(line("WARN", "team-a").is_none(), "{logs}");
        // A warning, never a refused start (open question 4): the config above parsed.
        // The single-namespace form with its default policy namespace warns about nothing,
        // and without a policy section nothing is said at all.
        let logs = startup_log(&with(&policy_reading("sandboxes", "")).unwrap());
        assert!(
            logs.contains("namespace=sandboxes sources=sandboxes"),
            "{logs}"
        );
        assert!(
            !logs.contains("no policy source of this namespace"),
            "{logs}"
        );
        let logs = startup_log(&with("").unwrap());
        assert!(!logs.contains("policy sources"), "{logs}");
        // Nothing shaped like a credential in what the start logs. The markers are compared to
        // a bool first, so a failure prints neither the marker nor the log.
        let credential_free = ["eyJ", "Bearer", "client_secret", "refresh_token"]
            .iter()
            .all(|marker| !logs.contains(marker));
        assert!(
            credential_free,
            "the startup log carries a credential marker"
        );
    }

    #[test]
    fn startup_logs_the_gate_form_per_issuer() {
        let logs = startup_log(&two_issuers(""));
        let line = |url: &str| -> String {
            logs.lines()
                .find(|l| l.contains(url))
                .unwrap_or_else(|| panic!("a line for {url} in {logs}"))
                .to_owned()
        };
        let l = line("https://dex.example.com");
        assert!(
            l.contains("required_groups (example-org:APP_EXAMPLE_ADMIN, APP_EXAMPLE_ADMIN)"),
            "{l}"
        );
        assert!(line("https://accounts.example.com").contains("none (explicit)"));
        assert!(line("https://old.example.com").contains("required_group (LEGACY)"));
    }

    #[test]
    fn startup_logs_single_open_namespace_without_a_map() {
        let logs = startup_log(&two_issuers("sandboxes: { namespace: agents }\n"));
        assert!(logs.contains("single open namespace agents"), "{logs}");
        let logs = startup_log(&two_issuers(""));
        assert!(logs.contains("single open namespace sandboxes"), "{logs}");
        assert!(!logs.contains("map of"), "{logs}");
    }

    #[test]
    fn startup_logs_the_namespace_names_and_no_token() {
        let logs = startup_log(&two_issuers(
            "sandboxes:\n  namespaces:\n    infra: { groups: [\"example-org:APP_EXAMPLE_ADMIN\", APP_EXAMPLE_ADMIN] }\n    team-a: { groups: [APP_EXAMPLE_TEAM_A_USER] }\n",
        ));
        assert!(logs.contains("map of 2 namespaces"), "{logs}");
        let infra = logs
            .lines()
            .find(|l| l.contains("namespace=infra"))
            .unwrap_or_else(|| panic!("an infra line in {logs}"));
        assert!(
            infra.contains("example-org:APP_EXAMPLE_ADMIN, APP_EXAMPLE_ADMIN"),
            "{infra}"
        );
        assert!(logs.contains("APP_EXAMPLE_TEAM_A_USER"), "{logs}");
        assert!(!logs.contains("single open namespace"), "{logs}");
        // Compared to a bool first, so a failure prints neither a marker nor the log.
        let credential_free = ["eyJ", "Bearer", "client_secret", "refresh_token"]
            .iter()
            .all(|marker| !logs.contains(marker));
        assert!(
            credential_free,
            "the startup log carries a credential marker"
        );
    }

    #[test]
    fn startup_names_each_unscoped_audience_when_the_namespace_map_is_set() {
        // ADR-0053 decision 7: names only, no rules and no host.
        let map = "sandboxes:\n  namespaces:\n    team-a: { groups: [ga] }\n";
        let two = "audiences:\n  - { name: open-one, via: none, egress: [\"open.example.test:443\"] }\n  - name: locked\n    via: none\n    egress: [\"locked.example.test:443\"]\n    namespaces:\n      team-a:\n        rules:\n          - { method: GET, path: \"/a/**\" }\n";
        let logs = startup_log(&two_issuers(&format!("{map}{two}")));
        let warn = logs
            .lines()
            .find(|l| l.contains("audience unscoped"))
            .unwrap_or_else(|| panic!("an unscoped line in {logs}"));
        assert!(
            warn.contains("open-one") && !warn.contains("locked"),
            "{warn}"
        );
        assert!(logs.contains("audience scoped to namespaces") && logs.contains("locked"));
        assert!(
            !logs.contains("/a/**") && !logs.contains("example.test"),
            "{logs}"
        );
        // Without the map there is one namespace and nothing to say.
        let logs = startup_log(&two_issuers(&format!(
            "sandboxes: {{ namespace: team-a }}\n{two}"
        )));
        assert!(!logs.contains("audience unscoped"), "{logs}");
    }

    // ----- what ships still parses (ADR-0046 decision 17) -----------------------------------------------------

    fn repo_root() -> std::path::PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap()
    }

    /// Every `*.yaml` under `dir` (relative to the repo root) that declares `issuers:` at the top
    /// level, which is what a broker config does and a Kubernetes manifest does not.
    fn config_files(dir: &str, out: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(repo_root().join(dir)) else {
            return;
        };
        for e in entries.flatten() {
            let path = e.path();
            if path.is_dir() {
                config_files(
                    path.strip_prefix(repo_root()).unwrap().to_str().unwrap(),
                    out,
                );
            } else if path.extension().is_some_and(|x| x == "yaml" || x == "yml")
                && std::fs::read_to_string(&path)
                    .is_ok_and(|t| t.lines().any(|l| l.starts_with("issuers:")))
            {
                out.push(path);
            }
        }
    }

    /// A fenced yaml block of a doc that is, or is a fragment of, a broker config: its top-level
    /// keys are all keys of `Config` and it names at least one of the keys this ADR is about.
    /// The keys a fragment lacks are filled in with the smallest valid value.
    fn doc_configs(doc: &str) -> Vec<String> {
        const KEYS: [&str; 16] = [
            "trust_domain",
            "spire",
            "issuers",
            "audiences",
            "sts",
            "registries",
            "listen",
            "dev_mode",
            "watcher",
            "sandboxes",
            "store",
            "token",
            "policy",
            "gateways",
            "gateway_inject_port",
            "accept_plain_gateway_identity",
        ];
        let mut out = Vec::new();
        let mut rest = doc;
        while let Some(i) = rest.find("```yaml\n").or_else(|| rest.find("```yml\n")) {
            let body_start = rest[i..].find('\n').unwrap() + i + 1;
            let Some(len) = rest[body_start..].find("```") else {
                break;
            };
            let block = &rest[body_start..body_start + len];
            rest = &rest[body_start + len + 3..];
            let top: Vec<&str> = block
                .lines()
                .filter(|l| !l.starts_with([' ', '#', '-']) && l.contains(':'))
                .map(|l| l.split(':').next().unwrap())
                .collect();
            let is_config = top
                .iter()
                .any(|k| ["issuers", "sandboxes", "trust_domain"].contains(k))
                && top.iter().all(|k| KEYS.contains(k));
            if !is_config {
                continue;
            }
            let has = |k: &str| top.contains(&k);
            let mut text = block.to_owned();
            if !has("trust_domain") {
                text.push_str("trust_domain: sandbox.test\n");
            }
            if !has("issuers") {
                text.push_str("issuers: []\n");
            }
            if !has("audiences") {
                text.push_str("audiences: []\n");
            }
            if !has("listen") {
                text.push_str("listen: { user: 127.0.0.1:8080, sandbox: 127.0.0.1:8443 }\n");
            }
            if !has("spire") && !has("dev_mode") {
                text.push_str("dev_mode: true\n");
            }
            if !has("sts") {
                text.push_str(
                    "sts: { issuer: https://mediatore.test, kid: k, signing_key_file: /k }\n",
                );
            }
            if !has("store") {
                text.push_str("store: { sealing: { key_file: /k } }\n");
            }
            out.push(text);
        }
        out
    }

    #[test]
    fn every_issuer_in_the_shipped_examples_and_guides_parses() {
        // Whole files: every broker config under deploy/, dev/ and examples/.
        let mut files = Vec::new();
        for dir in ["deploy", "dev", "examples"] {
            config_files(dir, &mut files);
        }
        assert!(
            files.len() >= 4,
            "the shipped broker configs were found: {files:?}"
        );
        for f in &files {
            let text = std::fs::read_to_string(f).unwrap();
            if let Err(e) = Config::parse(&text) {
                panic!("{} does not parse: {e}", f.display());
            }
        }
        // Fenced yaml blocks in the guides and the design docs that are a config or a fragment of one.
        let (mut blocks, mut skipped) = (0, 0);
        for doc in std::fs::read_dir(repo_root().join("docs/guides"))
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .chain([
                repo_root().join("docs/design/configuration.md"),
                repo_root().join("docs/design/issuers-and-audiences.md"),
            ])
            .filter(|p| p.extension().is_some_and(|x| x == "md"))
        {
            let text = std::fs::read_to_string(&doc).unwrap();
            for block in doc_configs(&text) {
                // A block that elides a value with `[...]` is a sketch, not a config.
                if block.contains("[...]") {
                    skipped += 1;
                    continue;
                }
                blocks += 1;
                // The docs spell the public key as a `<placeholder>`: a real one stands in.
                let block = block
                    .replace(
                        "<base64 of a 32-byte Ed25519 public key>",
                        &conformance_key(),
                    )
                    .replace("<base64 Ed25519 public key>", &conformance_key());
                if let Err(e) = Config::parse(&block) {
                    panic!("a block in {} does not parse: {e}\n{block}", doc.display());
                }
            }
        }
        assert!(blocks >= 5, "the doc blocks were found, got {blocks}");
        assert!(
            skipped <= 1,
            "only the elided sketch is skipped, got {skipped}"
        );
    }

    // ADR-0053: an audience scoped to namespaces, each with its own rules.

    const SCOPED_SANDBOXES: &str =
        "sandboxes: { namespaces: { team-a: { groups: [ga] }, team-b: { groups: [gb] } } }\n";
    const SCOPED_OK: &str = "  - name: repo\n    via: none\n    egress: [\"repo.example.test:443\"]\n    namespaces:\n      team-a:\n        rules:\n          - { method: GET, path: \"/a/**\" }\n      team-b:\n        rules:\n          - { method: GET, path: \"/b/**\" }\n";

    fn scoped_cfg(audiences: &str) -> String {
        format!("{INJECT_BASE}{SCOPED_SANDBOXES}audiences:\n{audiences}")
    }

    fn scoped_err(audiences: &str) -> String {
        Config::parse(&scoped_cfg(audiences))
            .unwrap_err()
            .to_string()
    }

    #[test]
    fn an_audience_without_namespaces_behaves_as_before() {
        let cfg = Config::parse(&inject_cfg(INJECT_OK)).unwrap();
        let a = &cfg.audiences[0];
        assert!(a.namespaces.is_none());
        assert!(
            a.scoped_rules().is_none(),
            "unscoped: usable from every namespace"
        );
        assert_eq!(a.rules.len(), 1);
    }

    #[test]
    fn scoped_rules_hold_the_namespaces_own_rules_and_nothing_for_an_unlisted_one() {
        let cfg = Config::parse(&scoped_cfg(SCOPED_OK)).unwrap();
        let per = cfg.audiences[0].scoped_rules().expect("scoped");
        assert_eq!(per["team-a"][0].path, "/a/**");
        assert_eq!(per["team-b"][0].path, "/b/**");
        assert!(!per.contains_key("team-c"), "unlisted is not usable");
        assert!(!per.contains_key(""));
    }

    #[test]
    fn top_level_rules_with_namespaces_are_the_ceiling_and_grants_inside_it_start() {
        let ceiling = SCOPED_OK.replace(
            "    namespaces:",
            "    rules:\n      - { method: GET, path: \"/**\" }\n    namespaces:",
        );
        assert!(Config::parse(&scoped_cfg(&ceiling)).is_ok());
        // `*` covers any method; a path glob covers what it matches.
        let any = SCOPED_OK.replace(
            "    namespaces:",
            "    rules:\n      - { method: \"*\", path: \"/*/**\" }\n    namespaces:",
        );
        assert!(Config::parse(&scoped_cfg(&any)).is_ok());
    }

    #[test]
    fn a_grant_outside_the_ceiling_refuses_to_start() {
        // The grant's path is outside the ceiling.
        let narrow = SCOPED_OK.replace(
            "    namespaces:",
            "    rules:\n      - { method: GET, path: \"/a/**\" }\n    namespaces:",
        );
        let err = scoped_err(&narrow);
        assert!(
            err.contains("namespaces.team-b") && err.contains("ceiling") && err.contains("/b/**"),
            "{err}"
        );
        // The grant's method is outside the ceiling.
        let method = SCOPED_OK.replace(
            "    namespaces:",
            "    rules:\n      - { method: HEAD, path: \"/**\" }\n    namespaces:",
        );
        assert!(scoped_err(&method).contains("ceiling"));
        // A grant wider than the ceiling in the same namespace (`**` against `*`) is not provable.
        let wider = "  - name: repo\n    via: none\n    egress: [\"repo.example.test:443\"]\n    rules:\n      - { method: GET, path: \"/a/*\" }\n    namespaces:\n      team-a:\n        rules:\n          - { method: GET, path: \"/a/**\" }\n";
        assert!(scoped_err(wider).contains("ceiling"));
    }

    #[test]
    fn with_no_top_level_rules_there_is_no_ceiling() {
        // As an empty `rules` has always meant every path: a grant is then bounded only by itself.
        assert!(Config::parse(&scoped_cfg(SCOPED_OK)).is_ok());
    }

    #[test]
    fn an_empty_namespaces_map_refuses_to_start() {
        let empty = "  - name: repo\n    via: none\n    egress: [\"repo.example.test:443\"]\n    namespaces: {}\n";
        let err = scoped_err(empty);
        assert!(err.contains("\"repo\"") && err.contains("empty"), "{err}");
    }

    #[test]
    fn a_namespace_entry_with_no_rules_refuses_to_start() {
        let none = SCOPED_OK.replace(
            "        rules:\n          - { method: GET, path: \"/b/**\" }\n",
            "        rules: []\n",
        );
        assert!(none != SCOPED_OK);
        let err = scoped_err(&none);
        assert!(
            err.contains("namespaces.team-b.rules") && err.contains("every method"),
            "{err}"
        );
        let missing = SCOPED_OK.replace(
            "        rules:\n          - { method: GET, path: \"/b/**\" }\n",
            "        {}\n",
        );
        assert!(scoped_err(&missing).contains("namespaces.team-b.rules"));
    }

    #[test]
    fn a_misspelled_rules_key_in_a_namespace_refuses_to_start() {
        let typo = SCOPED_OK.replace(
            "        rules:\n          - { method: GET, path: \"/b/**\" }",
            "        rule:\n          - { method: GET, path: \"/b/**\" }",
        );
        let err = scoped_err(&typo);
        assert!(
            err.contains("unknown field") && err.contains("rule"),
            "{err}"
        );
    }

    #[test]
    fn a_rule_under_a_namespace_gets_the_same_checks_as_a_top_level_one() {
        let bad = SCOPED_OK.replace("/a/**", "a/**");
        let err = scoped_err(&bad);
        assert!(err.contains("absolute path"), "{err}");
    }

    #[test]
    fn a_namespace_key_that_is_not_a_label_refuses_to_start() {
        let bad = SCOPED_OK.replace("      team-a:", "      Team_A:");
        let err = scoped_err(&bad);
        assert!(err.contains("RFC 1123") && err.contains("Team_A"), "{err}");
    }

    #[test]
    fn a_namespace_key_outside_sandboxes_namespaces_refuses_to_start() {
        let outside = SCOPED_OK.replace("      team-a:", "      team-z:");
        let err = scoped_err(&outside);
        assert!(
            err.contains("team-z") && err.contains("claim in") && err.contains("ADR-0053"),
            "{err}"
        );
        // The single-namespace form: the key must be that namespace.
        let single = format!(
            "{INJECT_BASE}sandboxes: {{ namespace: team-a }}\naudiences:\n{}",
            SCOPED_OK.replace("      team-b:", "      team-c:")
        );
        let err = Config::parse(&single).unwrap_err().to_string();
        assert!(err.contains("team-c"), "{err}");
        let ok = format!(
            "{INJECT_BASE}sandboxes: {{ namespace: team-a }}\naudiences:\n  - name: repo\n    via: none\n    egress: [\"repo.example.test:443\"]\n    namespaces:\n      team-a:\n        rules:\n          - {{ method: GET, path: \"/a/**\" }}\n"
        );
        assert!(Config::parse(&ok).is_ok());
    }

    #[test]
    fn scoped_audiences_sharing_an_endpoint_in_overlapping_namespaces_refuse_to_start() {
        let second = "  - name: repo2\n    via: none\n    egress: [\"repo.example.test:443\"]\n    namespaces:\n      team-b:\n        rules:\n          - { method: GET, path: \"/b2/**\" }\n";
        let err = scoped_err(&format!("{SCOPED_OK}{second}"));
        assert!(
            err.contains("repo.example.test:443") && err.contains("ADR-0053"),
            "{err}"
        );
    }

    #[test]
    fn scoped_audiences_sharing_a_host_in_disjoint_namespaces_start() {
        let one = "  - name: repo-a\n    via: none\n    egress: [\"repo.example.test:443\"]\n    namespaces:\n      team-a:\n        rules:\n          - { method: GET, path: \"/a/**\" }\n";
        let two = "  - name: repo-b\n    via: none\n    egress: [\"repo.example.test:443\"]\n    namespaces:\n      team-b:\n        rules:\n          - { method: GET, path: \"/b/**\" }\n";
        assert!(Config::parse(&scoped_cfg(&format!("{one}{two}"))).is_ok());
        // One of them unscoped: it is usable in team-a too, so the endpoint has two audiences there.
        let open = "  - name: repo-open\n    via: none\n    egress: [\"repo.example.test:443\"]\n";
        assert!(Config::parse(&scoped_cfg(&format!("{one}{open}"))).is_err());
    }

    #[test]
    fn two_gateway_placed_audiences_never_share_a_host_even_in_disjoint_namespaces() {
        let placed = |name: &str, ns: &str| {
            format!(
                "  - name: {name}\n    via: delegated\n    inject: gateway\n    max_ttl: 300\n    egress: [\"api.example.test:443\"]\n    namespaces:\n      {ns}:\n        rules:\n          - {{ method: GET, path: \"/{ns}/**\" }}\n"
            )
        };
        let err = scoped_err(&format!(
            "{}{}",
            placed("p-a", "team-a"),
            placed("p-b", "team-b")
        ));
        assert!(err.contains("api.example.test:443"), "{err}");
    }

    #[test]
    fn a_scoped_gateway_placed_audience_needs_no_top_level_rules() {
        let placed = "  - name: reg\n    via: delegated\n    credential: basic\n    inject: gateway\n    max_ttl: 300\n    egress: [\"reg.example.test:443\"]\n    namespaces:\n      team-a:\n        rules:\n          - { method: GET, path: \"/v2/team-a/**\" }\n";
        let cfg = Config::parse(&scoped_cfg(placed)).unwrap();
        assert_eq!(cfg.gateway_placed().len(), 1);
        // The placed audience still needs rules: an entry without them is the start error of decision 3.
        let empty = placed.replace(
            "        rules:\n          - { method: GET, path: \"/v2/team-a/**\" }\n",
            "        rules: []\n",
        );
        assert!(scoped_err(&empty).contains("namespaces.team-a.rules"));
    }
}
