// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! HTTP surface.
//!
//! Two routers, meant to be served on two listeners:
//! * [`user_router`]: `POST/GET/DELETE /v1/claims`, authenticated by an upstream bearer token.
//!   Outside `dev_mode` the record of a request is an `AgentSandbox` resource (ADR-0008):
//!   `POST` creates one with the token's subject, `GET` answers from its status, `DELETE`
//!   deletes it and the reconciler's finalizer does the rest.
//! * [`sandbox_router`]: `POST /v1/nodes`, `GET /v1/me`, `POST /v1/token`, authenticated by
//!   the peer's SPIFFE ID from mTLS, and the gateway's two routes, `GET /v1/gateway/claims/{uid}`
//!   and `POST /v1/gateway/claims/{uid}/credential` (ADR-0028, ADR-0040), which only the
//!   gateway identity may call.
//!
//! The sandbox router takes the peer identity from the [`PeerSpiffeId`] extension that
//! `mediatore_tls::serve` attaches after verifying the client certificate (ADR-0007). Only a
//! `dev_mode` server, on a plain loopback listener, reads it from `x-mediatore-peer-spiffe-id`
//! instead.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use banlieue_api::common::LocalObjectReference;
use base64::Engine as _;
use jiff::{SignedDuration, Timestamp};
use mediatore_claims::Reconciler;
use mediatore_claims::sandbox::{
    AgentSandbox, AgentSandboxSpec, FrontDoorError, SandboxFrontDoor, SandboxSubject,
    SandboxWorkload, claim_selection_of, label_selector_of,
};
use mediatore_entra::{IdpError, Validated, Validator};
use mediatore_proto::ek::is_ek_hash;
use mediatore_proto::image::ImageReference;
use mediatore_proto::{
    ClaimEgress, ClaimPhase, ClaimReport, ClaimRequest, ClaimResponse, Credential, Delegation,
    DelegationPlain, Endpoint, EndpointRule, ErrorBody, GatewayCredential,
    GatewayCredentialRequest, GuestExit, GuestReport, HeaderPair, HostTable, InjectRoute,
    LOG_KEEPALIVE_SECS, LOG_RETRY_AFTER_SECS, LogBatch, LogEnd, LogEndLine, LogEntry, LogGap,
    LogHeader, MAX_LOG_BATCH_BYTES, Me, NodeRegistered, NodeRegistration, RegistryCredential,
    Route, Secret, Subject, TokenRequest, TokenResponse, WorkloadExit, error_code,
};
use mediatore_spire::{EntryManager, Naming};
use mediatore_store::seal::{FORMAT_BARE_UID, SealError, Sealed, Sealer, Slot};
use mediatore_store::{
    ClaimRecord, ClaimStore, DelegatedSession, LogLimits, Modified, NodeRecord, SessionRecord,
    StoreError, modify_claim,
};
use mediatore_sts::{MintRequest, Sts};
use mediatore_tls::PeerSpiffeId;
use uuid::Uuid;

/// Hex characters of the claim UID used in the generated object name.
const CLAIM_NAME_SUFFIX_LEN: usize = 8;

/// Everything a handler needs.
pub struct AppState {
    /// Persistence.
    pub store: Arc<dyn ClaimStore>,
    /// SPIRE entries.
    pub spire: Arc<dyn EntryManager>,
    /// SPIFFE naming.
    pub naming: Naming,
    /// Upstream token validation.
    pub validator: Validator,
    /// Self-issued tokens, when the `sts` backend is configured.
    pub sts: Option<Sts>,
    /// Audiences we are allowed to serve, from config.
    pub audiences: Vec<String>,
    /// The subset of `audiences` served by Entra On-Behalf-Of (ADR-0016): a token for one
    /// is Entra's, minted from the claim's Entra session, never the STS's.
    pub obo_audiences: Vec<String>,
    /// Per audience, where the workload reaches its API from the jail (`audiences[].egress`);
    /// `GET /v1/me` returns the union over the claim's audiences (ADR-0020).
    pub egress: BTreeMap<String, Vec<Endpoint>>,
    /// Per audience, the egress proxy's rules (`audiences[].rules`, ADR-0025); `GET /v1/me`
    /// returns one route per audience and endpoint of the claim, carrying them.
    pub rules: BTreeMap<String, Vec<EndpointRule>>,
    /// ADR-0053: for an audience scoped to namespaces (`audiences[].namespaces`), its rules per
    /// namespace. An audience in this map is usable only from a namespace it lists, with that
    /// namespace's rules; one absent from it is unscoped and uses `rules`/`inject` as before.
    pub scopes: BTreeMap<String, BTreeMap<String, Vec<EndpointRule>>>,
    /// Per audience, the PEM of the CA the egress proxy trusts for its endpoints
    /// (`audiences[].ca_file`, ADR-0025 amended); absent, the Mozilla roots. Public material,
    /// validated at start, carried on the route.
    pub cas: BTreeMap<String, String>,
    /// The audiences declared `via: none` (ADR-0025 decision 8): their routes carry
    /// `credential: none` and `POST /v1/token` refuses them.
    pub no_credential: std::collections::BTreeSet<String>,
    /// The audiences declared `via: secret` (ADR-0032): the operator's credential, read from
    /// the mounted Secret at start, handed to the proxy by `POST /v1/token` with the header
    /// it goes in. Prints redacted; never written anywhere.
    pub secrets: BTreeMap<String, AudienceSecret>,
    /// The audiences served from the caller's own credential, delegated with the claim
    /// (`via: delegated`, ADR-0035): the header it goes in and what travels beside it.
    pub delegated: BTreeMap<String, DelegatedAudience>,
    /// Per registry host (as the API reaches it), the operator's pull credential
    /// (`registries[]`); `GET /v1/me` hands the guest the one its claim's image names
    /// (ADR-0022).
    pub registries: BTreeMap<String, RegistryCredential>,
    /// The registries a gateway-era pool can reach, canonical hosts (`registries[].reach`,
    /// ADR-0029 decision 1): a claim whose image names another is refused. `None` in an
    /// environment without gateways, where nothing is restricted.
    pub reachable_registries: Option<std::collections::BTreeSet<String>>,
    /// The verified bundles and the `policy.egress` switch (ADR-0030): a claim's direct
    /// egress joins its allowlist in `enforce`. `None` without a `policy` section, or under
    /// `dev_mode`, where no bundle is read: the audience endpoints alone.
    pub policy_egress: Option<PolicyEgress>,
    /// `AgentSandbox` resources through the Kubernetes API (ADR-0008); `None` under
    /// `dev_mode`, where the store and the dev binder stand in. Absent outside `dev_mode`,
    /// the claim endpoints fail closed with `501`.
    pub sandboxes: Option<Arc<dyn SandboxFrontDoor>>,
    /// Where `POST /v1/claims` may create sandboxes, and who may reach them (ADR-0046); the
    /// pool must live in the resolved namespace.
    pub namespaces: Namespaces,
    /// Seals refresh material before it reaches the store (ADR-0012 decision 3); `None`
    /// until `store.sealing` is configured. Roadmap 04 brings its first caller.
    pub sealer: Option<Arc<dyn Sealer>>,
    /// Per-claim limit on `POST /v1/token` (ADR-0013 decision 5).
    pub limiter: Limiter,
    /// Accept a peer-identity header instead of mTLS. Never in production.
    pub dev_mode: bool,
    /// The environment's egress gateways in the broker's order (`gateways`, ADR-0028
    /// decision 6), handed to every guest on `GET /v1/me`.
    pub gateways: Vec<Endpoint>,
    /// The audiences declared `inject: gateway` (ADR-0040): per audience, the routes the
    /// gateway places, one per exact upstream authority, with the rules it enforces and the
    /// header names it writes (`AudienceConfig::inject_routes()`). An audience in this map has
    /// its credential placed at the gateway: `POST /v1/token` refuses it (`placed_at_gateway`),
    /// its routes on `GET /v1/me` say `credential: gateway`, and the gateway asks for it on
    /// `POST /v1/gateway/claims/{uid}/credential`. Empty: every audience is placed in the proxy.
    pub inject: BTreeMap<String, Vec<InjectRoute>>,
    /// `gateway_inject_port` (ADR-0040 decision 7): the port of the gateways' inject listener,
    /// carried on every route of a gateway-placed audience on `GET /v1/me`.
    pub inject_port: Option<u16>,
    /// A workload's output at the broker (ADR-0045 decisions 4 and 11): the cap of each claim's
    /// ring when `logs.enabled`, `None` when it is not. `None` fails closed: `POST /v1/me/logs`
    /// and `GET /v1/claims/{name}/logs` answer `501`, and a claim with `workload.logs: true` is
    /// refused at creation.
    pub logs: Option<LogLimits>,
    /// One batch per second per claim on `POST /v1/me/logs` (ADR-0045 decision 4), so a
    /// workload cannot turn the broker into a write amplifier; `429` with `Retry-After` beyond it.
    pub log_limiter: Limiter,
    /// `accept_plain_gateway_identity` (ADR-0053 decision 7): for one release, the two gateway
    /// routes also answer a peer presenting the listeners' ID, `spiffe://<td>/gateway`, each
    /// ask a `warn` line. `false` everywhere but an environment in the middle of moving its
    /// gateways' entries; with it on, the compartment of ADR-0053 is not in force.
    pub accept_plain_gateway_identity: bool,
}

impl AppState {
    /// ADR-0053 decision 4: may a claim in `namespace` use `audience`? An unscoped audience is usable
    /// from every namespace; a scoped one only from a namespace it lists. Whether the audience exists
    /// is a separate question (`audiences`).
    #[must_use]
    pub fn scope_allows(&self, audience: &str, namespace: &str) -> bool {
        self.scopes
            .get(audience)
            .is_none_or(|per| per.contains_key(namespace))
    }

    /// The rules the proxy applies to `audience` for a claim in `namespace`: the namespace's own
    /// for a scoped audience, the audience's for an unscoped one.
    #[must_use]
    pub fn rules_in(&self, audience: &str, namespace: &str) -> Vec<EndpointRule> {
        match self.scopes.get(audience) {
            Some(per) => per.get(namespace).cloned().unwrap_or_default(),
            None => self.rules.get(audience).cloned().unwrap_or_default(),
        }
    }
}

/// Whether `policy.audiences` is `enforce` and there is a `policy` section to enforce
/// (ADR-0053 decision 9).
fn enforcing(st: &AppState) -> Option<&PolicyEgress> {
    st.policy_egress
        .as_ref()
        .filter(|pe| pe.audiences == mediatore_claims::policy::EgressMode::Enforce)
}

/// ADR-0053 decision 10: what `POST /v1/claims` requires under `policy.audiences: enforce`, after the
/// namespace check of ADR-0046. Returns the policy's `uid` to record (the dev path writes the record
/// itself; the reconciler records it for a sandbox), `None` when nothing is enforced.
///
/// - the claim names a policy (`400 policy_required`);
/// - every watched namespace has completed its first list, or `503 policy_not_synced` and nothing is
///   created: "no bundle yet" is never read as "no policy";
/// - the policy resolves to a verified, unexpired bundle (`400 unknown_policy`);
/// - the bundle grants every audience asked for, in a way the ceiling leaves usable (`400
///   unknown_audience`, the same answer as an audience that does not exist);
/// - `ttl_seconds` fits the bundle's lease (`400 ttl_exceeds_policy`).
fn admit_under_policy(
    st: &AppState,
    req: &ClaimRequest,
    namespace: &str,
) -> Result<Option<String>, ApiError> {
    let Some(pe) = enforcing(st) else {
        return Ok(None);
    };
    let Some(name) = req.policy_ref.as_deref() else {
        return Err(ApiError::bad_request(
            "policy_required",
            "name the policy this sandbox is under (policy_ref)",
        ));
    };
    if !pe.bundles.synced_all() {
        return Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "policy_not_synced",
            Some("the policy bundles have not all been read yet; try again shortly".to_owned()),
        ));
    }
    let Some(bundle) = pe.bundles.resolve(namespace, name, Timestamp::now()) else {
        return Err(ApiError::bad_request("unknown_policy", name.to_owned()));
    };
    if let Some(bad) = req
        .audiences
        .iter()
        .find(|a| effective_in(st, namespace, a, Some(&bundle)).is_none())
    {
        tracing::info!(%namespace, policy = name, audience = %bad, "claim refused: the policy does not grant the audience (ADR-0053)");
        return Err(ApiError::bad_request("unknown_audience", bad.clone()));
    }
    if i64::from(req.ttl_seconds) > i64::from(bundle.content.lease.max_duration_seconds) {
        tracing::info!(%namespace, policy = name, "claim refused: ttl above the policy's lease (ADR-0053)");
        return Err(ApiError::bad_request(
            "ttl_exceeds_policy",
            "ttl_seconds is above the policy's lease",
        ));
    }
    Ok(Some(bundle.content.policy.uid.clone()))
}

/// What a claim in `namespace` may do with `audience` (ADR-0053 decisions 4, 5 and 11): `None`
/// when it may not use it. Without `enforce` that is the namespace's scope (phase 1); under
/// `enforce` it is also the bundle's grant, bounded by the audience's own `rules` (the ceiling),
/// and `bundle` is the claim's verified bundle, `None` when it has none or it is unusable now.
fn effective_in(
    st: &AppState,
    namespace: &str,
    audience: &str,
    bundle: Option<&mediatore_policy::BundlePayload>,
) -> Option<mediatore_claims::policy::EffectiveAudience> {
    if !st.scope_allows(audience, namespace) {
        return None;
    }
    let egress = st.egress.get(audience).map_or(&[][..], Vec::as_slice);
    if enforcing(st).is_none() {
        return Some(mediatore_claims::policy::EffectiveAudience {
            rules: st.rules_in(audience, namespace),
            egress: egress.to_vec(),
            ttl_cap: None,
        });
    }
    let grant = bundle?
        .content
        .audiences
        .iter()
        .find(|g| g.name == audience)?;
    let ceiling = st.rules.get(audience).map_or(&[][..], Vec::as_slice);
    let file = st
        .scopes
        .get(audience)
        .and_then(|per| per.get(namespace))
        .map(Vec::as_slice);
    mediatore_claims::policy::effective_grant(ceiling, file, egress, grant)
}

/// The claim's current verified bundle (ADR-0053 decision 12): found by the policy `uid` the
/// record holds, never the version it was created under; `None` for a claim with no policy and
/// for a bundle that is missing, expired or no longer verified.
fn claim_bundle(st: &AppState, rec: &ClaimRecord) -> Option<Arc<mediatore_policy::BundlePayload>> {
    let pe = enforcing(st)?;
    pe.bundles
        .by_uid(rec.policy_uid.as_deref()?, Timestamp::now())
}

/// What the claim may do with `audience` now: [`effective_in`] on its own namespace and its
/// current bundle.
fn effective(
    st: &AppState,
    rec: &ClaimRecord,
    audience: &str,
) -> Option<mediatore_claims::policy::EffectiveAudience> {
    effective_in(
        st,
        &rec.namespace,
        audience,
        claim_bundle(st, rec).as_deref(),
    )
}

/// The audiences a claim may use now: the ones it names that its namespace lists and, under
/// `enforce`, its bundle grants (ADR-0053 decisions 4 and 12). Every mint, route and allowlist
/// for a claim reads this, never `rec.audiences` directly.
fn claim_audiences<'a>(st: &'a AppState, rec: &'a ClaimRecord) -> impl Iterator<Item = &'a String> {
    let bundle = claim_bundle(st, rec);
    rec.audiences
        .iter()
        .filter(move |a| effective_in(st, &rec.namespace, a, bundle.as_deref()).is_some())
}

/// Which namespaces the user API serves and who may use each (ADR-0046 decisions 3 to 5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Namespaces {
    /// Today's form: `sandboxes.namespace` only; every caller who passed the issuer gate may
    /// claim here.
    Single(String),
    /// `sandboxes.namespaces`: namespace -> groups (any-of, exact). With the map set there is
    /// no default namespace.
    Map(BTreeMap<String, Vec<String>>),
}

/// Why a namespace was refused. One rendering per variant, so the response carries nothing
/// that separates an unlisted namespace from an unqualified one (ADR-0046 decision 6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NsDenied {
    /// A map is set and the request named no namespace: `400 namespace_required`.
    Required,
    /// Not an RFC 1123 label: `400 invalid_namespace`.
    Invalid,
    /// Create only: unlisted or unqualified, carrying the value the caller sent: `403`.
    Forbidden(String),
    /// Get and delete only: unlisted or unqualified, the answer for "no such sandbox": `404`.
    NotFound,
}

impl NsDenied {
    /// The `4xx` answer.
    fn into_error(self) -> ApiError {
        match self {
            Self::Required => ApiError::bad_request(
                error_code::NAMESPACE_REQUIRED,
                "this broker needs a namespace; send `namespace`",
            ),
            Self::Invalid => ApiError::bad_request(
                error_code::INVALID_NAMESPACE,
                "namespace must be a lowercase RFC 1123 label",
            ),
            Self::Forbidden(ns) => ApiError::forbidden(format!(
                "not permitted to create sandboxes in namespace {ns}"
            )),
            Self::NotFound => ApiError::not_found("no such sandbox"),
        }
    }
}

impl Namespaces {
    /// The namespace a create targets (decision 4). A malformed name is refused first, from
    /// the string alone.
    ///
    /// # Errors
    /// [`NsDenied`] when the name is malformed, missing with a map, unlisted, or the groups
    /// do not intersect the namespace's.
    pub fn resolve_for_create(
        &self,
        requested: Option<&str>,
        groups: &[String],
    ) -> Result<String, NsDenied> {
        if let Some(r) = requested
            && !mediatore_proto::is_dns_label(r)
        {
            return Err(NsDenied::Invalid);
        }
        match (self, requested) {
            (Self::Single(ns), None) => Ok(ns.clone()),
            (Self::Single(ns), Some(r)) if r == ns => Ok(ns.clone()),
            (Self::Single(_), Some(r)) => Err(NsDenied::Forbidden(r.to_owned())),
            (Self::Map(_), None) => Err(NsDenied::Required),
            (Self::Map(_), Some(r)) => {
                if self.matched_group(r, groups).is_some() {
                    Ok(r.to_owned())
                } else {
                    Err(NsDenied::Forbidden(r.to_owned()))
                }
            }
        }
    }

    /// The namespace an existing claim is looked up in (decision 5): the same resolution, but
    /// unlisted and unqualified are both [`NsDenied::NotFound`].
    ///
    /// # Errors
    /// [`NsDenied`] as for a create, with `NotFound` in place of `Forbidden`.
    pub fn authorise_existing(
        &self,
        requested: Option<&str>,
        groups: &[String],
    ) -> Result<String, NsDenied> {
        self.resolve_for_create(requested, groups)
            .map_err(|d| match d {
                NsDenied::Forbidden(_) => NsDenied::NotFound,
                other => other,
            })
    }

    /// The listed group of `namespace` the caller holds, for the audit line: a configuration
    /// value, never the caller's group list. `None` when unlisted or unqualified, and for the
    /// single form, which has no listed group.
    #[must_use]
    pub fn matched_group<'a>(&'a self, namespace: &str, groups: &[String]) -> Option<&'a str> {
        match self {
            Self::Single(_) => None,
            Self::Map(m) => m
                .get(namespace)?
                .iter()
                .find(|l| mediatore_entra::groups_intersect(groups, std::slice::from_ref(l)))
                .map(String::as_str),
        }
    }
}

/// The per-claim gate on `POST /v1/token`: a token bucket (`per_minute` issues a minute,
/// the same number as the burst) and a lock that serialises the upstream refresh, since
/// the issuer rotates the refresh token and two concurrent issues must not both spend
/// the same one. In process memory, per replica.
pub struct Limiter {
    /// The bucket's capacity, also the burst.
    cap: u32,
    /// Seconds in which the bucket refills from empty to `cap`.
    period_secs: f64,
    buckets: std::sync::Mutex<Pruned<(f64, std::time::Instant)>>,
    locks: std::sync::Mutex<Pruned<Arc<tokio::sync::Mutex<()>>>>,
}

/// A per-claim table and when it was last pruned, under one mutex.
struct Pruned<V> {
    map: HashMap<Uuid, V>,
    last_pruned: std::time::Instant,
}

impl<V> Pruned<V> {
    fn new(now: std::time::Instant) -> Self {
        Self {
            map: HashMap::new(),
            last_pruned: now,
        }
    }

    /// Whether to prune now: past [`BUCKET_PRUNE_AT`] entries and [`BUCKET_PRUNE_EVERY`] since
    /// the last prune, which it records. A table that stays over the threshold after a prune
    /// (every entry still live) is then walked once an interval, not on every call.
    fn prune_due(&mut self, now: std::time::Instant) -> bool {
        if self.map.len() <= BUCKET_PRUNE_AT
            || now.saturating_duration_since(self.last_pruned) < BUCKET_PRUNE_EVERY
        {
            return false;
        }
        self.last_pruned = now;
        true
    }
}

/// Buckets idle this long are dropped when the table is pruned.
const BUCKET_IDLE: std::time::Duration = std::time::Duration::from_secs(600);
/// Prune the table past this many claims.
const BUCKET_PRUNE_AT: usize = 4096;
/// The least time between two prunes of one table.
const BUCKET_PRUNE_EVERY: std::time::Duration = std::time::Duration::from_secs(5);

impl Limiter {
    /// `per_minute` issues a minute per claim (at least 1).
    #[must_use]
    pub fn new(per_minute: u32) -> Self {
        Self::with_period(per_minute, 60.0)
    }

    /// `per_second` calls a second per claim (at least 1), the burst the same: the shape of
    /// the batch limit of ADR-0045 decision 4.
    #[must_use]
    pub fn per_second(per_second: u32) -> Self {
        Self::with_period(per_second, 1.0)
    }

    fn with_period(cap: u32, period_secs: f64) -> Self {
        let now = std::time::Instant::now();
        Self {
            cap: cap.max(1),
            period_secs,
            buckets: std::sync::Mutex::new(Pruned::new(now)),
            locks: std::sync::Mutex::new(Pruned::new(now)),
        }
    }

    /// The lock a refresh for `claim_uid` runs under.
    pub fn refresh_lock(&self, claim_uid: Uuid) -> Arc<tokio::sync::Mutex<()>> {
        self.refresh_lock_at(claim_uid, std::time::Instant::now())
    }

    /// [`Self::refresh_lock`] at `now`, which only the prune reads.
    fn refresh_lock_at(
        &self,
        claim_uid: Uuid,
        now: std::time::Instant,
    ) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self
            .locks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if locks.prune_due(now) {
            locks.map.retain(|_, l| Arc::strong_count(l) > 1);
        }
        locks.map.entry(claim_uid).or_default().clone()
    }

    /// Spend one issue for `claim_uid` if the bucket has it.
    pub fn allow(&self, claim_uid: Uuid) -> bool {
        self.allow_at(claim_uid, std::time::Instant::now())
    }

    /// [`Self::allow`] at `now`.
    fn allow_at(&self, claim_uid: Uuid, now: std::time::Instant) -> bool {
        let cap = f64::from(self.cap);
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if buckets.prune_due(now) {
            buckets
                .map
                .retain(|_, (_, last)| now.saturating_duration_since(*last) < BUCKET_IDLE);
        }
        let (tokens, last) = buckets.map.entry(claim_uid).or_insert((cap, now));
        let refill = now.saturating_duration_since(*last).as_secs_f64() / self.period_secs * cap;
        *tokens = (*tokens + refill).min(cap);
        *last = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Shared handle.
pub type Shared = Arc<AppState>;

/// Error type that renders as `{ "error": ..., "detail": ... }`.
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    body: ErrorBody,
}

impl ApiError {
    fn new(status: StatusCode, error: &str, detail: impl Into<Option<String>>) -> Self {
        Self {
            status,
            body: ErrorBody {
                error: error.to_owned(),
                detail: detail.into(),
            },
        }
    }
    fn unauthorized(detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            Some(detail.into()),
        )
    }
    fn forbidden(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", Some(detail.into()))
    }
    fn bad_request(error: &str, detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, error, Some(detail.into()))
    }
    fn not_implemented(what: &str) -> Self {
        Self::new(
            StatusCode::NOT_IMPLEMENTED,
            "not_implemented",
            Some(what.to_owned()),
        )
    }
    fn internal(detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal",
            Some(detail.into()),
        )
    }
    fn not_found(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", Some(detail.into()))
    }
    /// The store could not be read: never a stale or partial success (ADR-0045 decision 7).
    fn unavailable(detail: impl Into<String>) -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            Some(detail.into()),
        )
    }
    /// The error code, for a refusal's audit line.
    fn code(&self) -> &str {
        &self.body.error
    }
}

impl From<FrontDoorError> for ApiError {
    fn from(e: FrontDoorError) -> Self {
        match e {
            FrontDoorError::Conflict(d) => Self::new(StatusCode::CONFLICT, "conflict", Some(d)),
            FrontDoorError::Denied(d) => Self::forbidden(d),
            FrontDoorError::Invalid(d) => Self::bad_request("invalid_request", d),
            FrontDoorError::Api(d) => Self::internal(d),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(self.body)).into_response()
    }
}

/// Health for probes: a broker that cannot reach its store is not ready (ADR-0012).
async fn healthz(State(st): State<Shared>) -> Result<&'static str, ApiError> {
    st.store.ping().await.map_err(|e| {
        tracing::warn!(error = %e, "store unreachable");
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "store_unavailable",
            Some("store unreachable".to_owned()),
        )
    })?;
    Ok("ok")
}

/// Public JWKS for the STS backend.
async fn jwks(State(st): State<Shared>) -> Result<Json<serde_json::Value>, ApiError> {
    st.sts
        .as_ref()
        .map(|s| Json(s.jwks().clone()))
        .ok_or_else(|| ApiError::not_implemented("sts backend not configured"))
}

fn bearer(headers: &HeaderMap) -> Result<&str, ApiError> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .ok_or_else(|| ApiError::unauthorized("missing bearer token"))
}

/// Peer SPIFFE ID from mTLS (or the dev header).
/// The caller's SPIFFE ID. On an mTLS connection it is the verified client certificate's
/// URI SAN, attached by the listener as a [`PeerSpiffeId`] extension; the header is never
/// consulted then. Without one, only a `dev_mode` server reads the header (ADR-0007
/// decision 3); anything else has no peer identity and is refused.
fn peer_spiffe_id(
    st: &AppState,
    peer: Option<&PeerSpiffeId>,
    headers: &HeaderMap,
) -> Result<String, ApiError> {
    if let Some(peer) = peer {
        return Ok(peer.0.clone());
    }
    if st.dev_mode {
        return headers
            .get("x-mediatore-peer-spiffe-id")
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned)
            .ok_or_else(|| ApiError::unauthorized("no peer identity (dev header missing)"));
    }
    Err(ApiError::unauthorized(
        "no peer identity: not an mTLS connection",
    ))
}

/// Who may complete a handshake with the sandbox listener: node and claim identities of
/// this trust domain, parsed by the same rules the handlers apply, and the gateway
/// authorizer's identity, `spiffe://<td>/gateway/authorizer` (ADR-0053 decision 3, amending
/// ADR-0028 decision 4 and ADR-0007 decision 2), and nothing else, not even another broker.
/// The listeners' identity, `spiffe://<td>/gateway`, is a name the sandboxes verify and no
/// peer of the broker: it is admitted only while `accept_plain_gateway_identity` is on
/// (ADR-0053 decision 7). Which routes each may use is the handlers' business: the
/// authorizer reaches its own two routes and nothing a node or a claim reaches.
pub fn sandbox_authorizer(
    naming: Naming,
    accept_plain_gateway_identity: bool,
) -> mediatore_tls::Authorizer {
    Arc::new(move |id: &mediatore_tls::SpiffeId| {
        let id = id.to_string();
        naming.node_ek_from(&id).is_some()
            || naming.claim_uid_from(&id).is_some()
            || naming.is_gateway_authorizer(&id)
            || (accept_plain_gateway_identity && naming.is_gateway(&id))
    })
}

/// The guard of the two gateway routes (ADR-0053 decision 3): the peer must be the gateway
/// authorizer's identity, exactly. Anything else, the listeners' `spiffe://<td>/gateway`
/// included, is `403 forbidden`, and the caller runs this before it parses or looks up the
/// claim, so a refusal says nothing about whether a claim exists. With
/// `accept_plain_gateway_identity` on (decision 7) the listeners' ID is answered too, and
/// every such ask is a `warn` line naming the peer, the route and the claim UID as asked.
fn require_gateway_authorizer(
    st: &AppState,
    peer: &str,
    route: &'static str,
    claim_uid: &str,
) -> Result<(), ApiError> {
    if st.naming.is_gateway_authorizer(peer) {
        return Ok(());
    }
    if st.accept_plain_gateway_identity && st.naming.is_gateway(peer) {
        tracing::warn!(
            %peer,
            route,
            claim_uid,
            "a gateway asked under the listeners' identity, accepted because accept_plain_gateway_identity is on: move this gateway's authorizer entry to the authorizer's ID (ADR-0053 decision 7)"
        );
        return Ok(());
    }
    Err(ApiError::forbidden(
        "peer is not the gateway authorizer's identity",
    ))
}

// ---------- user-facing ----------

/// Validate the caller's bearer token.
///
/// The answer to a caller who is not yet anyone carries fixed text only: the validator's
/// error names the issuer's discovery URL and quotes the HTTP and JWT libraries, and that goes
/// to the log. An issuer that did not answer is `503 upstream_unavailable` (the caller's token
/// may be good; try again), a token that did not validate is `401`.
async fn caller(st: &AppState, headers: &HeaderMap) -> Result<Validated, ApiError> {
    let token = bearer(headers)?;
    st.validator.validate(token).await.map_err(|e| match e {
        IdpError::Forbidden(d) => ApiError::forbidden(d),
        IdpError::NotImplemented(w) => ApiError::not_implemented(w),
        IdpError::Upstream(why) => {
            tracing::warn!(error = %why, "login refused: the identity provider did not answer");
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "upstream_unavailable",
                Some("the identity provider did not answer".to_owned()),
            )
        }
        IdpError::Credential(why) => {
            tracing::error!(error = %why, "login refused: the broker's issuer configuration is unusable");
            ApiError::internal("the broker could not validate the token")
        }
        // Whatever an unauthenticated caller sent: said at `debug`, so it cannot fill the log.
        refused @ (IdpError::UnknownIssuer
        | IdpError::Invalid(_)
        | IdpError::SessionRevoked(_)) => {
            tracing::debug!(error = %refused, "login refused: the bearer token did not validate");
            ApiError::unauthorized("invalid token")
        }
    })
}

/// The reconciler over this state's store and SPIRE boundary.
fn reconciler(st: &AppState) -> Reconciler {
    Reconciler {
        store: st.store.clone(),
        spire: st.spire.clone(),
        naming: st.naming.clone(),
    }
}

/// A registered, unbanned node with no live claim bound to it.
async fn free_node(st: &AppState) -> Result<Option<NodeRecord>, ApiError> {
    let nodes = st
        .store
        .list_nodes()
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    for node in nodes {
        if node.banned {
            continue;
        }
        match st.store.get_claim_by_node(&node.node_id).await {
            Err(StoreError::NotFound(_)) => return Ok(Some(node)),
            Err(e) => return Err(ApiError::internal(e.to_string())),
            Ok(_) => {}
        }
    }
    Ok(None)
}

/// Phase as mirrored to the caller.
fn phase_of(rec: &ClaimRecord) -> ClaimPhase {
    if rec.revoked_at.is_some() {
        return ClaimPhase::Releasing;
    }
    if rec.entry_id.is_some() {
        ClaimPhase::Bound
    } else {
        ClaimPhase::Pending
    }
}

async fn create_claim(
    State(st): State<Shared>,
    headers: HeaderMap,
    Json(req): Json<ClaimRequest>,
) -> Result<(StatusCode, Json<ClaimResponse>), ApiError> {
    let bearer_token = bearer(&headers)?.to_owned();
    let validated = caller(&st, &headers).await?;
    // The namespace first (ADR-0046 decision 4): nothing is parked or written for a refusal.
    // In `dev_mode` the same check runs on the dev token's groups (decision 12): the testkit's
    // fake IdP puts the groups it was given in the token, and no header supplies any.
    let namespace = resolve_create(&st, &validated, req.namespace.as_deref())?;
    // Exactly one of pool_ref and pool_selector (ADR-0044 decision 2): the CRD would refuse
    // the sandbox; say so now, and never read "neither" as "any pool".
    req.pool()
        .map_err(|e| ApiError::bad_request("invalid_pool", e.to_string()))?;
    // An audience this namespace may not use is answered as one that does not exist (ADR-0053
    // decision 4): the response does not say which audiences exist elsewhere.
    if let Some(bad) = req
        .audiences
        .iter()
        .find(|a| !st.audiences.contains(a) || !st.scope_allows(a, &namespace))
    {
        return Err(ApiError::bad_request("unknown_audience", bad.clone()));
    }
    // ADR-0053 decision 10: under `policy.audiences: enforce`, a verified bundle that grants it all.
    admit_under_policy(&st, &req, &namespace)?;
    // The guest would refuse it at bind (ADR-0021); say so now (ADR-0022 decision 4).
    let image = req
        .workload
        .image
        .parse::<ImageReference>()
        .map_err(|e| ApiError::bad_request("invalid_workload_image", e))?;
    // A gateway-era pool reaches its declared registries and no other (ADR-0029).
    if let Some(reason) =
        mediatore_proto::image::unreachable_registry(st.reachable_registries.as_ref(), &image)
    {
        return Err(ApiError::bad_request("unreachable_registry", reason));
    }
    // The requester asked for the workload's output and this broker stores none (ADR-0045
    // decision 11): refused before anything exists, never a claim whose output is silently
    // dropped.
    if req.workload.logs && st.logs.is_none() {
        return Err(ApiError::not_implemented(
            "logs are not enabled on this broker",
        ));
    }
    let session = session_for(&st, &validated, &req, &bearer_token).await?;
    let delegations = delegations_for(&st, &req)?;
    let sealer = match (
        session.is_some() || !delegations.is_empty(),
        st.sealer.as_ref(),
    ) {
        (true, None) => return Err(ApiError::not_implemented("sealing")),
        (true, Some(s)) => Some(s.clone()),
        (false, _) => None,
    };
    if req.ttl_seconds == 0 {
        return Err(ApiError::bad_request(
            "invalid_ttl",
            "ttl_seconds must be positive",
        ));
    }
    let name = format!(
        "sandbox-{}",
        &Uuid::new_v4().simple().to_string()[..CLAIM_NAME_SUFFIX_LEN]
    );
    if !st.dev_mode {
        return create_sandbox(
            &st,
            &validated,
            &name,
            &namespace,
            &req,
            sealer.as_deref(),
            session.as_ref(),
            &delegations,
        )
        .await;
    }

    dev_claim(
        &st,
        &validated,
        &req,
        name,
        namespace,
        sealer.as_deref(),
        session.as_ref(),
        &delegations,
    )
    .await
}

/// Resolve a create's namespace and write the audit line (ADR-0046 decision 13): subject,
/// issuer, requested (`omitted` when none), resolved, decision and the listed group matched.
/// Never a token and never the caller's group list.
fn resolve_create(
    st: &AppState,
    validated: &Validated,
    requested: Option<&str>,
) -> Result<String, ApiError> {
    let result = st
        .namespaces
        .resolve_for_create(requested, &validated.groups);
    let shown = requested.unwrap_or("omitted");
    match &result {
        Ok(ns) => {
            let matched = st
                .namespaces
                .matched_group(ns, &validated.groups)
                .unwrap_or("open");
            tracing::info!(subject = %validated.subject.id, issuer = %validated.subject.issuer, requested = %shown, namespace = %ns, decision = "allowed", matched_group = %matched, "namespace decision");
        }
        Err(_) => {
            tracing::info!(subject = %validated.subject.id, issuer = %validated.subject.issuer, requested = %shown, decision = "denied", "namespace decision");
        }
    }
    result.map_err(NsDenied::into_error)
}

/// The namespace of an existing claim, for `GET` and `DELETE` (decision 5), before any read.
fn resolve_existing(
    st: &AppState,
    validated: &Validated,
    requested: Option<&str>,
) -> Result<String, ApiError> {
    st.namespaces
        .authorise_existing(requested, &validated.groups)
        .map_err(NsDenied::into_error)
}

/// `?namespace=` on `GET` and `DELETE /v1/claims/{name}`.
#[derive(serde::Deserialize, Default)]
struct NamespaceQuery {
    namespace: Option<String>,
}

/// Which pool a validated request asks for, for the log line (ADR-0044 decision 5): a name,
/// a selector in `kubectl` spelling, or `any pool`. Pools are not secrets.
fn pool_of(req: &ClaimRequest) -> String {
    req.pool().map_or_else(|e| e.to_string(), |p| p.to_string())
}

/// Which strategy a request asks for, for the log line (ADR-0047 decision 5): the value as
/// written, or `default` when absent. Strategies are not secrets.
fn strategy_of(req: &ClaimRequest) -> String {
    req.selection
        .map_or_else(|| "default".to_owned(), |s| s.strategy.to_string())
}

/// `dev_mode`: the record written by the API itself and bound by the dev binder, no
/// resource; the envelopes bind to the record's UID.
// One argument over the limit: the resolved namespace joins the request's parts.
#[allow(clippy::too_many_arguments)]
async fn dev_claim(
    st: &AppState,
    validated: &Validated,
    req: &ClaimRequest,
    name: String,
    namespace: String,
    sealer: Option<&dyn Sealer>,
    session: Option<&Secret>,
    delegations: &[Delegation],
) -> Result<(StatusCode, Json<ClaimResponse>), ApiError> {
    let uid = Uuid::new_v4();
    // The record carries the policy the claim was admitted under, as the reconciler writes it for a
    // sandbox (ADR-0026 decision 6); the check is the same and cheap.
    let policy_uid = admit_under_policy(st, req, &namespace)?;
    // The dev binder writes the record itself, so the envelope binds to the record's UID.
    let refresh = match (sealer, session) {
        (Some(sealer), Some(token)) => Some(
            sealer
                .seal_session(Slot::Issuer, uid, token.0.as_bytes())
                .await
                .map_err(seal_error)?,
        ),
        _ => None,
    };
    let mut dev_delegations = BTreeMap::new();
    if let Some(sealer) = sealer {
        for d in delegations {
            let sealed_until = parked_expiry(d.expires_at, Timestamp::now(), req.ttl_seconds);
            dev_delegations.insert(
                d.audience.clone(),
                DelegatedSession {
                    envelope: seal_delegation(sealer, uid, d, sealed_until).await?,
                    expires_at: d.expires_at,
                },
            );
        }
    }
    st.store
        .put_claim(ClaimRecord {
            uid,
            name: name.clone(),
            subject: validated.subject.clone(),
            entry_id: None,
            node_id: None,
            audiences: req.audiences.clone(),
            workload: req.workload.clone(),
            ttl_seconds: req.ttl_seconds,
            refresh,
            created_at: Timestamp::now(),
            expires_at: None,
            revoked_at: None,
            sandbox_uid: None,
            policy_uid,
            bundle_version: None,
            report: None,
            exit: None,
            delegations: dev_delegations,
            namespace,
            version: None,
        })
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    tracing::info!(subject = %validated.subject.id, pool = %pool_of(req), strategy = %strategy_of(req), %uid, "claim created");

    // Dev binder: stands in for banlieue's claim controller and pool. A registered free
    // node is "Ready pool member"; binding is immediate.
    if let Some(node) = free_node(st).await? {
        reconciler(st)
            .bind(uid, &node.ek_hash)
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    }

    let rec = st
        .store
        .get_claim(uid)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok((StatusCode::CREATED, Json(record_response(&rec))))
}

/// The response for a claim the store alone describes (`dev_mode`): no addresses, since
/// no pool binds a member there; the report and the exit as the record holds them.
fn record_response(rec: &ClaimRecord) -> ClaimResponse {
    ClaimResponse {
        name: rec.name.clone(),
        uid: Some(rec.uid),
        phase: phase_of(rec),
        ready: rec.entry_id.is_some() && rec.revoked_at.is_none(),
        pool: None,
        expires_at: rec.expires_at,
        addresses: vec![],
        report: rec.report.clone(),
        exit: rec.exit.clone(),
        sandbox_uid: rec.sandbox_uid,
        namespace: Some(rec.namespace.clone()),
    }
}

/// The session a claim is created with (ADR-0013 decision 1, ADR-0016 decision 1): a
/// session issuer requires the caller's delegated refresh token and any other refuses
/// one; an Entra issuer delegates nothing, the bearer is exchanged On-Behalf-Of for the
/// first audience Entra serves, else for mediatore itself. An audience Entra serves needs
/// an Entra login.
async fn session_for(
    st: &AppState,
    validated: &Validated,
    req: &ClaimRequest,
    bearer_token: &str,
) -> Result<Option<Secret>, ApiError> {
    match (&validated.issuer.session, &req.refresh_token) {
        (Some(_), None) => {
            return Err(ApiError::bad_request(
                "session_required",
                "this issuer requires a refresh_token to be delegated with the claim",
            ));
        }
        (None, Some(_)) => {
            return Err(ApiError::bad_request(
                "session_unexpected",
                "this issuer takes no refresh_token",
            ));
        }
        _ => {}
    }
    if validated.issuer.entra.is_none() {
        if let Some(bad) = req.audiences.iter().find(|a| st.obo_audiences.contains(a)) {
            return Err(ApiError::bad_request(
                "audience_needs_entra",
                format!("audience {bad} is served On-Behalf-Of and needs an Entra login"),
            ));
        }
        return Ok(req.refresh_token.clone());
    }
    let resource = req
        .audiences
        .iter()
        .find(|a| st.obo_audiences.contains(a))
        .cloned()
        .unwrap_or_else(|| validated.issuer.client_id.clone());
    let refresh = st
        .validator
        .exchange(&validated.issuer, bearer_token, &resource)
        .await
        .map_err(|e| exchange_error(validated, &resource, &e))?;
    tracing::info!(subject = %validated.subject.id, %resource, "session obtained on behalf of the caller");
    Ok(Some(refresh))
}

/// The delegations a claim carries, checked against the audiences it names (ADR-0035
/// decision 2): a `delegated` audience needs exactly one with a bearer, nothing else may
/// carry one, a bearer the caller says dies before the claim's deadline is refused, and a
/// pending one (the transit shape) is not served yet.
fn delegations_for(st: &AppState, req: &ClaimRequest) -> Result<Vec<Delegation>, ApiError> {
    let mut out = Vec::new();
    for d in &req.delegations {
        if !st.delegated.contains_key(&d.audience) || !req.audiences.contains(&d.audience) {
            return Err(ApiError::bad_request(
                "delegation_refused",
                format!(
                    "audience {} takes no delegation: it is not a via: delegated audience of this claim",
                    d.audience
                ),
            ));
        }
        if out.iter().any(|o: &Delegation| o.audience == d.audience) {
            return Err(ApiError::bad_request(
                "delegation_refused",
                format!("audience {} is delegated twice", d.audience),
            ));
        }
        if d.pending {
            return Err(ApiError::not_implemented(
                "a pending delegation (the envelope sealed on the caller's machine)",
            ));
        }
        if d.token.as_ref().is_none_or(|t| t.0.is_empty()) {
            return Err(ApiError::bad_request(
                "delegation_required",
                format!("audience {} is delegated without a token", d.audience),
            ));
        }
        if st.delegated.get(&d.audience).is_some_and(|a| a.basic)
            && let Some(t) = d.token.as_ref()
            && let Err(why) = basic_parts(&t.0)
        {
            return Err(ApiError::bad_request(
                "delegation_refused",
                format!(
                    "audience {} takes a user name and a secret: {why}",
                    d.audience
                ),
            ));
        }
        if let Some(expires_at) = d.expires_at
            && expires_at < Timestamp::now() + SignedDuration::from_secs(i64::from(req.ttl_seconds))
        {
            return Err(ApiError::bad_request(
                "delegation_expires_first",
                format!(
                    "the credential delegated for {} expires at {expires_at}, before a claim of {} s would",
                    d.audience, req.ttl_seconds
                ),
            ));
        }
        out.push(d.clone());
    }
    if let Some(missing) = req
        .audiences
        .iter()
        .find(|a| st.delegated.contains_key(*a) && !out.iter().any(|d| &d.audience == *a))
    {
        return Err(ApiError::bad_request(
            "delegation_required",
            format!(
                "audience {missing} is served from your own credential: delegate it with the claim"
            ),
        ));
    }
    Ok(out)
}

/// The user name and secret of a `credential: basic` delegation, which carries them as
/// `user:secret` (ADR-0041 decision 3). The user name has no `:` (RFC 7617: it ends at the first),
/// neither part is empty and neither holds a control character, so a value that could split the
/// header or be dropped by Envoy never leaves here. The message names the rule, never the value.
fn basic_parts(token: &str) -> Result<(&str, &str), &'static str> {
    let Some((user, secret)) = token.split_once(':') else {
        return Err("the token must be user:secret");
    };
    if user.is_empty() || secret.is_empty() {
        return Err("the user name and the secret must not be empty");
    }
    if token.chars().any(char::is_control) {
        return Err("the user name and the secret must not hold a control character");
    }
    Ok((user, secret))
}

/// Seal a delegation's plaintext for `binding` (ADR-0035 decision 3), under its audience's
/// slot (ADR-0057 decision 9), so it opens as that audience's and as nothing else, with
/// `expires_at` inside (decision 11): the instant the issue path bounds the credential by,
/// whatever is kept in clear beside the envelope.
async fn seal_delegation(
    sealer: &dyn Sealer,
    binding: Uuid,
    d: &Delegation,
    expires_at: Timestamp,
) -> Result<Sealed, ApiError> {
    let plain = DelegationPlain {
        token: d.token.clone().unwrap_or_else(|| Secret(String::new())),
        refresh_token: d.refresh_token.clone(),
        expires_at: Some(expires_at),
    };
    let bytes = serde_json::to_vec(&plain).map_err(|e| ApiError::internal(e.to_string()))?;
    sealer
        .seal_session(Slot::Delegation(&d.audience), binding, &bytes)
        .await
        .map_err(seal_error)
}

/// The production front door (ADR-0008 decision 4): the request becomes an `AgentSandbox`
/// in the configured namespace, `spec.subject` from the validated token. mediatore's
/// `ServiceAccount` is exempt from the subject admission check for exactly this, so the
/// token validation above is the control.
// One argument over the limit: the resolved namespace joins the request's parts.
#[allow(clippy::too_many_arguments)]
async fn create_sandbox(
    st: &AppState,
    validated: &Validated,
    name: &str,
    namespace: &str,
    req: &ClaimRequest,
    sealer: Option<&dyn Sealer>,
    session: Option<&Secret>,
    delegations: &[Delegation],
) -> Result<(StatusCode, Json<ClaimResponse>), ApiError> {
    let Some(front) = st.sandboxes.as_ref() else {
        return Err(ApiError::not_implemented(
            "claim creation via the kubernetes api",
        ));
    };
    let mut sandbox = AgentSandbox::new(
        name,
        AgentSandboxSpec {
            subject: SandboxSubject::from(&validated.subject),
            pool_ref: req
                .pool_ref
                .clone()
                .map(|name| LocalObjectReference { name }),
            pool_selector: req.pool_selector.as_ref().map(label_selector_of),
            selection: req.selection.as_ref().map(claim_selection_of),
            ttl_seconds: req.ttl_seconds,
            audiences: req.audiences.clone(),
            workload: SandboxWorkload::from(&req.workload),
            policy_ref: req
                .policy_ref
                .clone()
                .map(|name| LocalObjectReference { name }),
        },
    );
    sandbox.metadata.namespace = Some(namespace.to_owned());
    let created = front.create(sandbox).await?;
    tracing::info!(subject = %validated.subject.id, pool = %pool_of(req), strategy = %strategy_of(req), sandbox = %name, %namespace, "sandbox created");
    // ADR-0013 decision 2: the session is parked under the sandbox's UID, sealed with it,
    // before the caller hears back; a failure here undoes the resource. ADR-0035: each
    // delegation the same way, one Secret per audience.
    let parked = match (sealer, session) {
        (Some(sealer), Some(token)) => park_session(st, sealer, &created, validated, token).await,
        _ => Ok(()),
    };
    let parked = match (parked, sealer) {
        (Ok(()), Some(sealer)) => {
            park_delegations(st, sealer, &created, validated, delegations).await
        }
        (r, _) => r,
    };
    if let Err(e) = parked {
        tracing::warn!(sandbox = %name, error = %e, "session not parked; sandbox withdrawn");
        if let Err(d) = front.delete(namespace, name).await {
            tracing::warn!(sandbox = %name, error = %d, "sandbox withdrawal failed");
        }
        return Err(match e.downcast::<SealError>() {
            Ok(seal) => seal_error(seal),
            Err(_) => ApiError::internal("session could not be stored"),
        });
    }
    let mut resp = response_of(&created);
    resp.namespace = Some(namespace.to_owned());
    Ok((StatusCode::CREATED, Json(resp)))
}

/// When a parked delegation's envelope stops being stored (the operator's rule, 2026-11-15, ADR-0043
/// decision 4): the least of the credential's own expiry, when the caller said one, and the claim's creation plus
/// its TTL. The sweep removes an envelope past this, so a secret is never stored longer than the claim it was
/// delegated for, and a use after it is refused (the credential route checks the same instant).
fn parked_expiry(
    credential_expires_at: Option<Timestamp>,
    created_at: Timestamp,
    ttl_seconds: u32,
) -> Timestamp {
    let claim_end = created_at + SignedDuration::from_secs(i64::from(ttl_seconds));
    credential_expires_at.map_or(claim_end, |e| e.min(claim_end))
}

/// Seal each delegation with the sandbox's UID and park it, one Secret per audience, until
/// the reconciler creates the record (ADR-0035 decision 3).
async fn park_delegations(
    st: &AppState,
    sealer: &dyn Sealer,
    created: &AgentSandbox,
    validated: &Validated,
    delegations: &[Delegation],
) -> anyhow::Result<()> {
    let sandbox_uid = created
        .metadata
        .uid
        .as_deref()
        .and_then(|u| Uuid::parse_str(u).ok())
        .ok_or_else(|| anyhow::anyhow!("the created sandbox has no UUID uid"))?;
    for d in delegations {
        let created_at = Timestamp::now();
        let expires_at = parked_expiry(d.expires_at, created_at, created.spec.ttl_seconds);
        // The same instant inside the envelope and in clear beside it: the issue path
        // believes the sealed one, the sweep reads the clear one (ADR-0057 decision 11).
        let refresh = seal_delegation(sealer, sandbox_uid, d, expires_at)
            .await
            .map_err(|e| anyhow::anyhow!("sealing the delegation failed: {}", e.body.error))?;
        st.store
            .put_session(SessionRecord {
                sandbox_uid,
                subject: validated.subject.clone(),
                issuer: String::new(),
                refresh,
                created_at,
                audience: Some(d.audience.clone()),
                expires_at: Some(expires_at),
            })
            .await?;
        tracing::info!(%sandbox_uid, subject = %validated.subject.id, audience = %d.audience, %expires_at, "delegation parked");
    }
    Ok(())
}

/// Seal `token` with the sandbox's UID and park it until the reconciler creates the record. Parked with an expiry
/// like a delegation (ADR-0043 decision 4): the claim's creation plus its TTL, so the sweep removes the envelope
/// of a sandbox that never got a record. Once the claim is bound the store keeps it to the claim's own deadline.
async fn park_session(
    st: &AppState,
    sealer: &dyn Sealer,
    created: &AgentSandbox,
    validated: &Validated,
    token: &Secret,
) -> anyhow::Result<()> {
    let sandbox_uid = created
        .metadata
        .uid
        .as_deref()
        .and_then(|u| Uuid::parse_str(u).ok())
        .ok_or_else(|| anyhow::anyhow!("the created sandbox has no UUID uid"))?;
    let refresh = sealer
        .seal_session(Slot::Issuer, sandbox_uid, token.0.as_bytes())
        .await?;
    let created_at = Timestamp::now();
    let expires_at = parked_expiry(None, created_at, created.spec.ttl_seconds);
    st.store
        .put_session(SessionRecord {
            sandbox_uid,
            subject: validated.subject.clone(),
            issuer: validated.issuer.url.clone(),
            refresh,
            created_at,
            audience: None,
            expires_at: Some(expires_at),
        })
        .await?;
    tracing::info!(%sandbox_uid, subject = %validated.subject.id, %expires_at, "session parked");
    Ok(())
}

/// What the user sees of a sandbox: its status, mirrored from the claim (decision 11).
fn response_of(sb: &AgentSandbox) -> ClaimResponse {
    let st = sb.status.clone().unwrap_or_default();
    ClaimResponse {
        name: sb.metadata.name.clone().unwrap_or_default(),
        uid: st
            .claim_uid
            .as_deref()
            .and_then(|u| Uuid::parse_str(u).ok()),
        phase: st.phase.into(),
        ready: st.ready,
        pool: st.pool_ref.map(|p| p.name),
        expires_at: st.expires_at.as_ref().map(|t| t.0),
        addresses: st.addresses,
        report: None,
        exit: None,
        sandbox_uid: sb
            .metadata
            .uid
            .as_deref()
            .and_then(|u| Uuid::parse_str(u).ok()),
        namespace: sb.metadata.namespace.clone(),
    }
}

/// The `{name}` of a claims route, checked from the string alone before anything is asked
/// about it. A sandbox's name is an RFC 1123 label; anything else (a `/`, a `?`, a `%`) would
/// choose the path and the query of a Kubernetes API request made with the broker's own
/// account. Refused as a name nobody has (`404`), and never echoed.
fn require_sandbox_name(name: &str) -> Result<(), ApiError> {
    if mediatore_proto::is_dns_label(name) {
        Ok(())
    } else {
        Err(NsDenied::NotFound.into_error())
    }
}

/// Fetch a sandbox by name in its namespace and require the caller to be in that namespace's
/// groups and to be its subject (ADR-0046 decision 5). A name that is not an RFC 1123 label
/// and a namespace the caller may not use are `404`, before any read; a sandbox that does not
/// exist and one that belongs to someone else are told apart (404 / 403): the names are random
/// and the subject check is the control.
async fn owned_sandbox(
    st: &AppState,
    headers: &HeaderMap,
    namespace: Option<&str>,
    name: &str,
) -> Result<(String, AgentSandbox), ApiError> {
    let validated = caller(st, headers).await?;
    require_sandbox_name(name)?;
    let namespace = resolve_existing(st, &validated, namespace)?;
    let Some(front) = st.sandboxes.as_ref() else {
        return Err(ApiError::not_implemented(
            "claim lookup via the kubernetes api",
        ));
    };
    let sb = front
        .get(&namespace, name)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no sandbox named {name}")))?;
    if sb.spec.subject.issuer != validated.subject.issuer
        || sb.spec.subject.id != validated.subject.id
    {
        return Err(ApiError::forbidden("claim belongs to another subject"));
    }
    Ok((namespace, sb))
}

/// `dev_mode`: the same checks over the store's record.
async fn owned_claim(
    st: &AppState,
    headers: &HeaderMap,
    namespace: Option<&str>,
    name: &str,
) -> Result<ClaimRecord, ApiError> {
    let validated = caller(st, headers).await?;
    require_sandbox_name(name)?;
    let namespace = resolve_existing(st, &validated, namespace)?;
    let rec = st
        .store
        .get_claim_by_name(&namespace, name)
        .await
        .map_err(|e| ApiError::not_found(e.to_string()))?;
    if rec.subject.issuer != validated.subject.issuer || rec.subject.id != validated.subject.id {
        return Err(ApiError::forbidden("claim belongs to another subject"));
    }
    Ok(rec)
}

async fn get_claim(
    State(st): State<Shared>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(q): Query<NamespaceQuery>,
) -> Result<Json<ClaimResponse>, ApiError> {
    if !st.dev_mode {
        let (namespace, sb) = owned_sandbox(&st, &headers, q.namespace.as_deref(), &name).await?;
        let mut resp = response_of(&sb);
        resp.namespace = Some(namespace.clone());
        // The guest's report lives on the record (ADR-0029 decision 5), not on the
        // resource; a record not yet written is simply no report.
        if let Ok(rec) = st.store.get_claim_by_name(&namespace, &name).await {
            resp.report = rec.report;
            resp.exit = rec.exit;
        }
        return Ok(Json(resp));
    }
    let rec = owned_claim(&st, &headers, q.namespace.as_deref(), &name).await?;
    Ok(Json(record_response(&rec)))
}

async fn delete_claim(
    State(st): State<Shared>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(q): Query<NamespaceQuery>,
) -> Result<StatusCode, ApiError> {
    if !st.dev_mode {
        let (namespace, sb) = owned_sandbox(&st, &headers, q.namespace.as_deref(), &name).await?;
        // The reconciler's finalizer retracts the entry, revokes the record and deletes
        // the claim (ADR-0008 decision 10); the API only asks.
        st.sandboxes
            .as_ref()
            .ok_or_else(|| ApiError::not_implemented("claim deletion via the kubernetes api"))?
            .delete(&namespace, &name)
            .await?;
        tracing::info!(sandbox = %name, %namespace, subject = %sb.spec.subject.id, "sandbox deleted by its subject");
        return Ok(StatusCode::NO_CONTENT);
    }
    let rec = owned_claim(&st, &headers, q.namespace.as_deref(), &name).await?;
    reconciler(&st)
        .release(rec.uid)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    tracing::info!(uid = %rec.uid, namespace = %rec.namespace, "claim released by its subject");
    Ok(StatusCode::NO_CONTENT)
}

/// Router for humans and agents.
pub fn user_router(state: Shared) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/.well-known/jwks.json", get(jwks))
        .route("/v1/claims", post(create_claim))
        .route("/v1/claims/{name}", get(get_claim).delete(delete_claim))
        .route("/v1/claims/{name}/logs", get(read_logs))
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}

// ---------- the workload's output (ADR-0045) ----------

/// `?follow=&since=&tail=&namespace=` on `GET /v1/claims/{name}/logs` (ADR-0045 decision 9).
#[derive(serde::Deserialize, Default)]
struct LogsQuery {
    namespace: Option<String>,
    #[serde(default)]
    follow: bool,
    since: Option<u64>,
    tail: Option<usize>,
}

/// Between two reads of the store while following (ADR-0045 decision 9, amended: a bounded
/// poll of the store, the guest's batch cadence, in place of a watch on the segments).
const LOG_FOLLOW_POLL: std::time::Duration = std::time::Duration::from_secs(2);

/// One NDJSON line, terminated.
fn ndjson_line<T: serde::Serialize>(value: &T) -> axum::body::Bytes {
    let mut text = serde_json::to_vec(value).unwrap_or_default();
    text.push(b'\n');
    axum::body::Bytes::from(text)
}

/// The claim behind `GET /v1/claims/{name}/logs`: the same owner check as `GET
/// /v1/claims/{name}` (ADR-0045 decision 5), the record (the claim UID the output is keyed by)
/// and the phase the header reports. Outside `dev_mode` a sandbox whose claim never bound has
/// no record and no output: `None`.
async fn owned_record_for_logs(
    st: &AppState,
    headers: &HeaderMap,
    namespace: Option<&str>,
    name: &str,
) -> Result<(Option<ClaimRecord>, ClaimPhase, Subject), ApiError> {
    if st.dev_mode {
        let rec = owned_claim(st, headers, namespace, name).await?;
        let phase = phase_of(&rec);
        let subject = rec.subject.clone();
        return Ok((Some(rec), phase, subject));
    }
    let (namespace, sb) = owned_sandbox(st, headers, namespace, name).await?;
    let phase = response_of(&sb).phase;
    let subject = Subject::from(&sb.spec.subject);
    match st.store.get_claim_by_name(&namespace, name).await {
        Ok(rec) => Ok((Some(rec), phase, subject)),
        Err(StoreError::NotFound(_)) => Ok((None, phase, subject)),
        Err(e) => Err(ApiError::unavailable(e.to_string())),
    }
}

/// Whether a claim's output can still grow: its record is live and bound.
fn claim_has_ended(rec: &ClaimRecord, phase: ClaimPhase) -> bool {
    rec.revoked_at.is_some() || matches!(phase, ClaimPhase::Releasing | ClaimPhase::Failed)
}

/// A store error as the API answers it: an outage of something the store depends on (the
/// sealer's `OpenBao`, ADR-0052) is `503`, which the guest retries and the owner can retry;
/// anything else is `500`.
fn store_error(e: StoreError) -> ApiError {
    match e {
        StoreError::Unavailable(_) => ApiError::unavailable(e.to_string()),
        other => ApiError::internal(other.to_string()),
    }
}

/// One read's outgoing side: the channel the body drains, and what went down it for the audit
/// line (decision 10): counts, never content.
struct Outgoing {
    tx: tokio::sync::mpsc::Sender<Result<axum::body::Bytes, std::convert::Infallible>>,
    bytes: u64,
    records: u64,
}

impl Outgoing {
    /// Send one line; `false` once the reader is gone.
    async fn emit<T: serde::Serialize>(&mut self, value: &T) -> bool {
        // Serialised before the first await: the future holds the line, not the value.
        let line = ndjson_line(value);
        self.emit_raw(line).await
    }

    /// Send one raw line, waiting for room in the channel: a full channel is a reader that
    /// has not caught up, not a reader that left. `false` only once the receiver is dropped,
    /// which is the body being dropped, which is the reader gone.
    async fn emit_raw(&mut self, line: axum::body::Bytes) -> bool {
        self.bytes += line.len() as u64;
        self.tx.send(Ok(line)).await.is_ok()
    }

    /// Send every entry, counting the records; `false` once the reader is gone.
    async fn emit_entries(&mut self, entries: &[LogEntry]) -> bool {
        for e in entries {
            if e.seq().is_some() {
                self.records += 1;
            }
            if !self.emit(e).await {
                return false;
            }
        }
        true
    }

    /// The last line, and why.
    async fn end(&mut self, reason: LogEnd) -> LogEnd {
        self.emit(&LogEndLine::new(reason)).await;
        reason
    }
}

/// `GET /v1/claims/{name}/logs` (ADR-0045 decisions 5, 7, 9 and 10): the claim's stored output
/// to its owner, as NDJSON: a `LogHeader`, each record or gap on its own line, and a last line
/// `{"end": true, "reason": ...}`. With `follow` the broker keeps reading the store every
/// [`LOG_FOLLOW_POLL`] until the claim ends (`claim_ended`), its record is swept (`ttl`) or the
/// reader goes (`client`, logged, not sent), with an empty line every [`LOG_KEEPALIVE_SECS`]
/// of silence. Without it the stored output is sent and the stream ends: `claim_ended` for a
/// claim that has ended, `client` for a live one, whose output may still grow.
///
/// Only the claim's owner reads (the same check as `GET /v1/claims/{name}`); there is no role
/// that widens it. `501` when the broker stores no output, `503` when the store cannot be read.
/// Every read is one audit line before the first byte and one at the end, with counts and never
/// a byte of the output (decision 10).
async fn read_logs(
    State(st): State<Shared>,
    headers: HeaderMap,
    Path(name): Path<String>,
    Query(q): Query<LogsQuery>,
) -> Result<Response, ApiError> {
    if st.logs.is_none() {
        tracing::warn!(%name, reason = "not_implemented", "workload output read refused");
        return Err(ApiError::not_implemented(
            "logs are not enabled on this broker",
        ));
    }
    let (rec, phase, subject) =
        match owned_record_for_logs(&st, &headers, q.namespace.as_deref(), &name).await {
            Ok(found) => found,
            Err(e) => {
                tracing::warn!(%name, reason = %e.code(), "workload output read refused");
                return Err(e);
            }
        };
    let claim_uid = rec.as_ref().map(|r| r.uid);
    let shown_uid = claim_uid.map_or_else(|| "-".to_owned(), |u| u.to_string());
    let started = std::time::Instant::now();
    tracing::info!(
        claim_uid = %shown_uid,
        subject = %subject.id,
        %name,
        follow = q.follow,
        since = ?q.since,
        tail = ?q.tail,
        "workload output read"
    );
    // The first read before the response starts, so a store that cannot be read is a `503`,
    // never a stream that ends in nothing (decision 7).
    let first = match (claim_uid, q.tail) {
        // With a tail the store reads from the newest, so a long ring is not unsealed whole.
        (Some(uid), Some(n)) => st.store.read_logs_tail(uid, q.since, n).await,
        (Some(uid), None) => st.store.read_logs(uid, q.since).await,
        (None, _) => Ok(mediatore_store::LogChunk::default()),
    }
    .map_err(|e| ApiError::unavailable(e.to_string()))?;
    let (tx, rx) =
        tokio::sync::mpsc::channel::<Result<axum::body::Bytes, std::convert::Infallible>>(32);
    let state = st.clone();
    tokio::spawn(async move {
        let (reason, out) = stream_logs(&state, tx, rec, phase, first, &q).await;
        tracing::info!(
            claim_uid = %shown_uid,
            subject = %subject.id,
            %name,
            bytes_sent = out.bytes,
            records_sent = out.records,
            duration_ms = started.elapsed().as_millis(),
            reason = ?reason,
            "workload output read ended"
        );
    });
    let body = axum::body::Body::from_stream(futures::stream::unfold(rx, |mut rx| async {
        rx.recv().await.map(|item| (item, rx))
    }));
    Ok(([(header::CONTENT_TYPE, "application/x-ndjson")], body).into_response())
}

/// The lines of one read, sent as produced; returns why it ended and what was sent.
async fn stream_logs(
    st: &AppState,
    tx: tokio::sync::mpsc::Sender<Result<axum::body::Bytes, std::convert::Infallible>>,
    rec: Option<ClaimRecord>,
    phase: ClaimPhase,
    first: mediatore_store::LogChunk,
    q: &LogsQuery,
) -> (LogEnd, Outgoing) {
    let mut out = Outgoing {
        tx,
        bytes: 0,
        records: 0,
    };
    let header = LogHeader {
        truncated_before: first.truncated_before,
        claim_phase: format!("{phase:?}"),
    };
    if !out.emit(&header).await {
        return (LogEnd::Client, out);
    }
    let entries = match q.tail {
        Some(n) => mediatore_store::tail_entries(first.entries, n),
        None => first.entries,
    };
    if !out.emit_entries(&entries).await {
        return (LogEnd::Client, out);
    }
    let Some(rec) = rec else {
        // No record: the claim never bound, nothing can arrive.
        let reason = out.end(LogEnd::ClaimEnded).await;
        return (reason, out);
    };
    let ended = claim_has_ended(&rec, phase);
    if !q.follow || ended {
        let reason = out
            .end(if ended {
                LogEnd::ClaimEnded
            } else {
                LogEnd::Client
            })
            .await;
        return (reason, out);
    }
    // Following: the cursor is the ring's highest seq, whatever `tail` cut.
    let cursor = first.last_seq.or(q.since);
    let reason = follow_logs(st, &mut out, rec, cursor, first.truncated_before).await;
    (reason, out)
}

/// The `follow` loop (decision 9): read the store every [`LOG_FOLLOW_POLL`] from `cursor`, send
/// what is new, end with the claim (`claim_ended`), with its record's sweep (`ttl`) or with the
/// reader (`client`, not sent); an empty line every [`LOG_KEEPALIVE_SECS`] of silence.
async fn follow_logs(
    st: &AppState,
    out: &mut Outgoing,
    mut rec: ClaimRecord,
    mut cursor: Option<u64>,
    mut truncated: u64,
) -> LogEnd {
    let mut last_sent = std::time::Instant::now();
    loop {
        tokio::time::sleep(LOG_FOLLOW_POLL).await;
        if out.tx.is_closed() {
            return LogEnd::Client;
        }
        rec = match st.store.get_claim(rec.uid).await {
            Ok(r) => r,
            Err(StoreError::NotFound(_)) => {
                // Swept while being followed: the retention ran out (decision 7).
                return out.end(LogEnd::Ttl).await;
            }
            Err(e) => {
                tracing::warn!(claim_uid = %rec.uid, error = %e, "store unreadable while following output");
                continue;
            }
        };
        let ended = claim_has_ended(&rec, phase_of(&rec));
        let chunk = match st.store.read_logs(rec.uid, cursor).await {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(claim_uid = %rec.uid, error = %e, "store unreadable while following output");
                continue;
            }
        };
        // The ring dropped stored records since the last read, and the first new record is
        // not the cursor's successor: records this follower never saw are gone. The count is
        // what the ring dropped in between, an upper bound on what was missed.
        let first_seq = chunk.entries.iter().find_map(LogEntry::seq);
        if chunk.truncated_before > truncated
            && let (Some(c), Some(f)) = (cursor, first_seq)
            && f > c + 1
        {
            let gap = LogGap {
                lost_stdout: chunk.truncated_before - truncated,
                lost_stderr: 0,
                unreadable: 0,
            };
            if !out.emit(&LogEntry::Gap(gap)).await {
                return LogEnd::Client;
            }
            tracing::info!(claim_uid = %rec.uid, dropped = gap.lost_stdout, "a follower missed output the ring dropped");
        }
        truncated = chunk.truncated_before;
        if !chunk.entries.is_empty() {
            if !out.emit_entries(&chunk.entries).await {
                return LogEnd::Client;
            }
            last_sent = std::time::Instant::now();
        }
        if let Some(l) = chunk.last_seq {
            cursor = Some(cursor.map_or(l, |c| c.max(l)));
        }
        if ended {
            return out.end(LogEnd::ClaimEnded).await;
        }
        if last_sent.elapsed() >= std::time::Duration::from_secs(LOG_KEEPALIVE_SECS) {
            if !out.emit_raw(axum::body::Bytes::from_static(b"\n")).await {
                return LogEnd::Client;
            }
            last_sent = std::time::Instant::now();
        }
    }
}

/// `POST /v1/me/logs` (ADR-0045 decisions 4, 8 and 9): the claim's node, over the node SVID,
/// ships a batch of the workload's output, redacted in the VM. The broker re-validates the
/// shape and the sizes and does not redact again: it cannot know which secrets the jail was
/// given, so redaction is the guest's, before the output left the VM. A node with no live
/// claim (the guest flushing after the claim ended) is `204` and the batch is dropped, as a
/// late exit is. `501` when the broker stores no output; `400 logs_not_requested` for a claim
/// that did not opt in; `413` over [`MAX_LOG_BATCH_BYTES`]; `429` with `Retry-After` beyond one
/// batch a second. The text is never logged, only counts.
async fn ingest_logs(
    State(st): State<Shared>,
    headers: HeaderMap,
    peer: Option<Extension<PeerSpiffeId>>,
    Json(body): Json<LogBatch>,
) -> Result<Response, ApiError> {
    let Some(limits) = st.logs else {
        return Err(ApiError::not_implemented(
            "logs are not enabled on this broker",
        ));
    };
    let rec = match claim_of_node_peer(&st, &headers, peer.as_ref().map(|e| &e.0)).await {
        Ok(rec) => rec,
        Err(e) if e.status == StatusCode::NOT_FOUND => {
            tracing::debug!("a node shipped output with no live claim bound; dropped");
            return Ok(StatusCode::NO_CONTENT.into_response());
        }
        Err(e) => return Err(e),
    };
    if !rec.workload.logs {
        return Err(ApiError::bad_request(
            "logs_not_requested",
            "this claim did not opt in to output capture (workload.logs)",
        ));
    }
    body.validate()
        .map_err(|e| ApiError::bad_request("invalid_log_batch", e))?;
    let bytes = body.text_bytes();
    if bytes > MAX_LOG_BATCH_BYTES {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "batch_too_large",
            Some(format!(
                "{bytes} bytes of record text, over the {MAX_LOG_BATCH_BYTES} limit"
            )),
        ));
    }
    if !st.log_limiter.allow(rec.uid) {
        tracing::info!(claim_uid = %rec.uid, records = body.records.len(), bytes, "output batch rate-limited (ADR-0045 decision 4)");
        return Ok((
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, LOG_RETRY_AFTER_SECS.to_string())],
            Json(ErrorBody {
                error: "too_many_batches".into(),
                detail: Some("one batch per second per claim".into()),
            }),
        )
            .into_response());
    }
    // The store logs a ring that dropped its oldest records (decision 4): it knows without
    // reading the ring again.
    let outcome = st
        .store
        .append_logs(&rec, &body, &limits)
        .await
        .map_err(store_error)?;
    tracing::debug!(
        claim_uid = %rec.uid,
        records = body.records.len(),
        stored = outcome.stored,
        ignored = outcome.ignored,
        bytes,
        dropped_stdout = body.dropped_stdout,
        dropped_stderr = body.dropped_stderr,
        "output batch stored"
    );
    Ok(StatusCode::NO_CONTENT.into_response())
}

// ---------- sandbox-facing ----------

async fn register_node(
    State(st): State<Shared>,
    headers: HeaderMap,
    peer: Option<Extension<PeerSpiffeId>>,
    Json(reg): Json<NodeRegistration>,
) -> Result<Json<NodeRegistered>, ApiError> {
    let peer = peer_spiffe_id(&st, peer.as_ref().map(|e| &e.0), &headers)?;
    if !is_ek_hash(&reg.ek_hash) {
        return Err(ApiError::bad_request(
            "invalid_ek_hash",
            "ek_hash must be 64 lowercase hex characters",
        ));
    }
    let expected = st.naming.node_id(&reg.ek_hash);
    if peer != expected {
        return Err(ApiError::forbidden(format!(
            "peer {peer} may not register {expected}"
        )));
    }
    // The node's SPIRE *agent* ID is what parents its entries and keys claim lookups.
    let agent_id = st.naming.agent_id(&reg.ek_hash);
    st.store
        .put_node(NodeRecord {
            ek_hash: reg.ek_hash.clone(),
            node_id: agent_id.clone(),
            dmi_uuid: reg.dmi_uuid,
            hostname: reg.hostname,
            provider: reg.provider,
            banned: false,
            registered_at: Timestamp::now(),
        })
        .await
        .map_err(|e| match e {
            StoreError::Conflict(d) => ApiError::new(StatusCode::CONFLICT, "duplicate_ek", Some(d)),
            other => ApiError::internal(other.to_string()),
        })?;

    // Dev binder, other direction: a pending claim may have been waiting for a node.
    if st.dev_mode
        && st.store.get_claim_by_node(&agent_id).await.is_err()
        && let Ok(claims) = st.store.list_claims().await
        && let Some(pending) = claims
            .iter()
            .filter(|c| c.entry_id.is_none() && c.revoked_at.is_none())
            .min_by_key(|c| c.created_at)
        && let Err(e) = reconciler(&st).bind(pending.uid, &reg.ek_hash).await
    {
        tracing::warn!(uid = %pending.uid, error = %e, "dev bind on registration failed");
    }

    Ok(Json(NodeRegistered { node_id: agent_id }))
}

/// The live claim bound to the node the peer is: the node identity, registered, with a
/// claim (`GET /v1/me` and `POST /v1/me/report` share it).
async fn claim_of_node_peer(
    st: &AppState,
    headers: &HeaderMap,
    peer: Option<&PeerSpiffeId>,
) -> Result<ClaimRecord, ApiError> {
    let peer = peer_spiffe_id(st, peer, headers)?;
    let ek_hash = st
        .naming
        .node_ek_from(&peer)
        .ok_or_else(|| ApiError::forbidden("peer is not a node identity"))?;
    let node = st
        .store
        .get_node(&ek_hash)
        .await
        .map_err(|_| ApiError::forbidden("node not registered"))?;
    st.store
        .get_claim_by_node(&node.node_id)
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "no_claim",
                Some("no live claim bound to this node".into()),
            )
        })
}

/// The per-claim limit on what a node writes to its claim's record with `POST /v1/me/report`:
/// each is a store write and a log line, so it spends from the claim's bucket, the one
/// `POST /v1/token` spends from, and is `429 rate_limited` beyond it. `POST /v1/me/exit` is
/// not limited: the guest sends it once, a refused one would leave the claim to its deadline,
/// and it releases the claim, so a second one finds no live claim.
fn node_report_allowed(st: &AppState, claim_uid: Uuid) -> Result<(), ApiError> {
    if st.limiter.allow(claim_uid) {
        return Ok(());
    }
    Err(ApiError::new(
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limited",
        Some("too many reports for this claim".to_owned()),
    ))
}

/// `POST /v1/me/exit` (ADR-0033 decision 2): the guest, over the node SVID, says the
/// workload exited and its restart policy ends the claim. The exit goes on the record (and
/// the audit line with it), and the claim is released as `DELETE /v1/claims/{name}` releases
/// it: through the `AgentSandbox` with a cluster, directly in `dev_mode`. A node with no
/// live claim (the guest late, the claim already released) is `204` all the same.
async fn exit(
    State(st): State<Shared>,
    headers: HeaderMap,
    peer: Option<Extension<PeerSpiffeId>>,
    Json(body): Json<GuestExit>,
) -> Result<StatusCode, ApiError> {
    let rec = match claim_of_node_peer(&st, &headers, peer.as_ref().map(|e| &e.0)).await {
        Ok(rec) => rec,
        Err(e) if e.status == StatusCode::NOT_FOUND => {
            tracing::debug!("a node reported an exit with no live claim bound; nothing to end");
            return Ok(StatusCode::NO_CONTENT);
        }
        Err(e) => return Err(e),
    };
    tracing::info!(
        claim_uid = %rec.uid,
        subject = %rec.subject.id,
        code = ?body.code,
        signal = ?body.signal,
        restarts = body.restarts,
        restart = %rec.workload.restart,
        "workload exited and its restart policy ends the claim (ADR-0033)"
    );
    let exited = WorkloadExit {
        exited_at: Timestamp::now(),
        exit: body,
    };
    // The exit is put on the record as it is when it is written (ADR-0057 decision 5), and
    // nothing else of the copy read above is carried over.
    let written = modify_claim(st.store.as_ref(), rec.uid, |mut fresh| {
        fresh.exit = Some(exited.clone());
        Some(fresh)
    })
    .await;
    match written {
        Ok(Modified::Written | Modified::Unchanged) => {}
        Ok(Modified::Released) | Err(StoreError::NotFound(_)) => {
            // Ended already: the exit is in the line above and not on the record.
            tracing::debug!(claim_uid = %rec.uid, "exit for a claim that has ended already; nothing to end");
            return Ok(StatusCode::NO_CONTENT);
        }
        Err(e) => {
            // The record was busy, or the write failed. The release goes ahead all the
            // same: a claim is never left to its deadline because its record could not
            // take the exit. A release carries no precondition.
            tracing::warn!(claim_uid = %rec.uid, error = %e, "the exit could not be put on the record; the claim is released all the same");
        }
    }
    if st.dev_mode {
        reconciler(&st)
            .release(rec.uid)
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    } else {
        st.sandboxes
            .as_ref()
            .ok_or_else(|| ApiError::not_implemented("claim release via the kubernetes api"))?
            .delete(&rec.namespace, &rec.name)
            .await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// `POST /v1/me/report` (ADR-0029 decision 5): the guest, over the node SVID, says what it
/// pulled and loaded before the workload started; kept on the claim's record, shown to the
/// subject on `GET /v1/claims/{name}`, logged in the audit line when the claim is swept. One line
/// per report; a host table missing where gateways exist is said at `warn`.
async fn report(
    State(st): State<Shared>,
    headers: HeaderMap,
    peer: Option<Extension<PeerSpiffeId>>,
    Json(body): Json<GuestReport>,
) -> Result<StatusCode, ApiError> {
    let rec = claim_of_node_peer(&st, &headers, peer.as_ref().map(|e| &e.0)).await?;
    node_report_allowed(&st, rec.uid)?;
    body.validate()
        .map_err(|e| ApiError::bad_request("invalid_report", e))?;
    if body.host_table == HostTable::Missing {
        tracing::warn!(claim_uid = %rec.uid, "the guest found no host table where the environment has gateways (ADR-0029)");
    }
    tracing::info!(
        claim_uid = %rec.uid,
        image_digest = %body.image_digest,
        sandbox_ruleset_sha256 = %body.sandbox_ruleset_sha256,
        host_table = ?body.host_table,
        "guest report recorded"
    );
    let report = ClaimReport {
        reported_at: Timestamp::now(),
        report: body,
    };
    // The report is put on the record as it is when it is written (ADR-0057 decision 5);
    // nothing else of the copy read above is carried over.
    let written = modify_claim(st.store.as_ref(), rec.uid, |mut fresh| {
        fresh.report = Some(report.clone());
        Some(fresh)
    })
    .await;
    match written {
        Ok(Modified::Written | Modified::Unchanged) => Ok(StatusCode::NO_CONTENT),
        // Released or gone since the lookup: what a node with no live claim is told.
        Ok(Modified::Released) | Err(StoreError::NotFound(_)) => Err(ApiError::new(
            StatusCode::NOT_FOUND,
            "no_claim",
            Some("no live claim bound to this node".into()),
        )),
        // Every attempt lost to another write: nothing was written, the guest may send it
        // again.
        Err(StoreError::Conflict(_)) => Err(ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "record_busy",
            Some("the claim's record is being written; send the report again".into()),
        )),
        Err(e) => Err(store_error(e)),
    }
}

async fn me(
    State(st): State<Shared>,
    headers: HeaderMap,
    peer: Option<Extension<PeerSpiffeId>>,
) -> Result<Json<Me>, ApiError> {
    let rec = claim_of_node_peer(&st, &headers, peer.as_ref().map(|e| &e.0)).await?;
    let expires_at = rec
        .expires_at
        .ok_or_else(|| ApiError::internal("bound claim has no deadline".to_owned()))?;
    // The destinations are the claim's audiences' (ADR-0020 decision 2): an audience that
    // declares none contributes none, and the jail reaches the broker only. Plus, in
    // `policy.egress: enforce`, the direct egress of its bundle the gateway serves
    // (ADR-0030), the same list the gateway is given.
    let audience_endpoints = audience_egress(&st, &rec);
    let direct = served_direct_egress(&st, &rec, &audience_endpoints);
    let mut egress = audience_endpoints;
    egress.extend(direct.iter().cloned());
    egress.sort();
    egress.dedup();
    // The proxy's routes (ADR-0025 decision 4): the same destinations, each with its
    // audience and that audience's rules; the config guarantees one audience per endpoint.
    // A direct entry gets a route with no audience and no credential (decision 8): the
    // proxy forwards bare, and the gateway, not the proxy, is what admits it.
    let mut routes: Vec<Route> = claim_audiences(&st, &rec)
        .flat_map(|a| {
            let eff = effective(&st, &rec, a).unwrap_or_else(|| unreachable!("filtered"));
            let rules = eff.rules;
            eff.egress.into_iter().map(move |e| (a, e, rules.clone()))
        })
        .map(|(a, e, rules)| Route {
            audience: Some(a.clone()),
            endpoint: e,
            rules,
            ca_pem: st.cas.get(a).cloned(),
            credential: if st.no_credential.contains(a) {
                Credential::None
            } else if st.inject.contains_key(a) {
                // ADR-0040: the gateway places it; the proxy never asks for a token.
                Credential::Gateway
            } else {
                Credential::Token
            },
            // ADR-0032 decision 2 and ADR-0035: where a `via: secret` or a delegated
            // credential goes, when not `Authorization`; the proxy owns that header on
            // every route (ADR-0025 decision 3).
            credential_header: st
                .secrets
                .get(a)
                .filter(|sec| sec.header != "authorization")
                .map(|sec| sec.header.clone())
                .or_else(|| {
                    st.delegated
                        .get(a)
                        .filter(|d| d.header != "authorization")
                        .map(|d| d.header.clone())
                }),
            // ADR-0040: the gateways' inject port, on the routes of an audience placed
            // there; every other route is placed by the proxy.
            inject_port: st
                .inject
                .contains_key(a)
                .then_some(st.inject_port)
                .flatten(),
        })
        .chain(direct.into_iter().map(|e| Route {
            audience: None,
            endpoint: e,
            rules: vec![],
            ca_pem: None,
            credential: Credential::None,
            credential_header: None,
            inject_port: None,
        }))
        .collect();
    routes.sort_by(|a, b| {
        a.endpoint
            .cmp(&b.endpoint)
            .then(a.audience.cmp(&b.audience))
    });
    routes.dedup();
    // The credential for the registry the image names, and no other (ADR-0022 decision 2).
    let registry_credential = rec
        .workload
        .image
        .parse::<ImageReference>()
        .ok()
        .and_then(|r| st.registries.get(&r.registry).cloned());
    if let Some(c) = &registry_credential {
        tracing::debug!(claim_uid = %rec.uid, registry = %c.host, "registry credential attached");
    }
    Ok(Json(Me {
        claim_uid: rec.uid,
        subject: rec.subject,
        expires_at,
        workload: rec.workload,
        egress,
        routes,
        registry_credential,
        gateways: st.gateways.clone(),
    }))
}

/// An operator-held credential for an audience `via: secret` (ADR-0032), as the broker
/// holds it in memory: the value, where the proxy puts it, what travels beside it, and how
/// long a proxy may keep its copy (`max_ttl`).
#[derive(Clone, Debug)]
pub struct AudienceSecret {
    /// The credential; `Debug` prints `[redacted]`.
    pub value: Secret,
    /// The request header, lowercase: `authorization` sends `Bearer <value>`, any other
    /// name the bare value (decision 2).
    pub header: String,
    /// Headers the proxy adds beside the credential; public material.
    pub extra_headers: Vec<HeaderPair>,
    /// How long the proxy may keep its copy before asking again (decision 4).
    pub ttl: SignedDuration,
}

/// How a `via: delegated` audience's credential is handed to the proxy (ADR-0035 decision 4).
#[derive(Clone, Debug)]
pub struct DelegatedAudience {
    /// The request header, lowercase: `authorization` sends `Bearer <value>`, any other
    /// name the bare value.
    pub header: String,
    /// Headers the proxy adds beside the credential; public material.
    pub extra_headers: Vec<HeaderPair>,
    /// How long the proxy may keep its copy before asking again.
    pub ttl: SignedDuration,
    /// The credential is a user name and a secret (`user:secret` in the delegation's token), placed
    /// as `Authorization: Basic` at the gateway (ADR-0041); false for a bearer.
    pub basic: bool,
}

impl AudienceSecret {
    /// The answer to `POST /v1/token` for this audience: the credential as it is, the
    /// header it goes in (absent for `authorization`, a bearer), what travels beside it,
    /// and an expiry `ttl` from now so the proxy asks again.
    #[must_use]
    pub fn response(&self, audience: String, subject: mediatore_proto::Subject) -> TokenResponse {
        let bearer = self.header == "authorization";
        TokenResponse {
            access_token: self.value.0.clone(),
            token_type: if bearer { "Bearer" } else { "Header" }.into(),
            expires_at: Timestamp::now() + self.ttl,
            audience,
            subject,
            header: (!bearer).then(|| self.header.clone()),
            extra_headers: self.extra_headers.clone(),
        }
    }
}

/// What the broker needs to serve a policy's direct egress (ADR-0030).
#[derive(Clone)]
pub struct PolicyEgress {
    /// The reflector's cache of verified bundles (ADR-0026).
    pub bundles: Arc<mediatore_claims::policy::BundleCache>,
    /// `policy.egress`.
    pub mode: mediatore_claims::policy::EgressMode,
    /// `policy.audiences` (ADR-0053 decisions 9 to 16): under `Enforce` a claim is admitted, minted
    /// for and routed only under a verified bundle that grants what it uses.
    pub audiences: mediatore_claims::policy::EgressMode,
}

/// The `host:port` pairs a claim may reach: the union of its audiences' `egress` and, when
/// `policy.egress` is `enforce`, the direct egress of its policy's verified, unexpired bundle
/// (ADR-0030), sorted and deduplicated. The same list for the guest's ruleset and for the
/// gateway's answer. A claim with no policy, or whose bundle is missing, expired or not
/// verified, gets the audience endpoints only.
fn egress_of(st: &AppState, rec: &ClaimRecord) -> Vec<Endpoint> {
    let mut egress = audience_egress(st, rec);
    let direct = served_direct_egress(st, rec, &egress);
    egress.extend(direct);
    // A policy's direct egress must not bring a placed host back into the tunnel list.
    let placed = placed_endpoints(st, rec);
    egress.retain(|e| !placed.contains(e));
    egress.sort();
    egress.dedup();
    egress
}

/// The direct egress of the claim's bundle that the broker serves beyond `audience`
/// (ADR-0030 decisions 1 to 4): in `enforce`, the servable entries not already an
/// audience's, sorted; in `shadow`, none, with the log line saying what enforce would add.
/// Empty without a `policy` section, a policy on the record or a usable bundle.
fn served_direct_egress(st: &AppState, rec: &ClaimRecord, audience: &[Endpoint]) -> Vec<Endpoint> {
    let Some(pe) = st.policy_egress.as_ref() else {
        return vec![];
    };
    let Some(uid) = rec.policy_uid.as_deref() else {
        return vec![];
    };
    let Some(bundle) = pe.bundles.by_uid(uid, Timestamp::now()) else {
        return vec![];
    };
    let direct = mediatore_claims::policy::direct_egress(&bundle);
    for n in &direct.not_served {
        tracing::debug!(claim_uid = %rec.uid, policy_uid = uid, endpoint = %n.endpoint, reason = n.reason, "direct egress not served");
    }
    let added: Vec<Endpoint> = direct
        .served
        .into_iter()
        .filter(|e| !audience.contains(e))
        .collect();
    match pe.mode {
        mediatore_claims::policy::EgressMode::Enforce => added,
        mediatore_claims::policy::EgressMode::Shadow => {
            if !added.is_empty() {
                tracing::info!(
                    claim_uid = %rec.uid,
                    policy_uid = uid,
                    bundle_version = bundle.meta.version,
                    would_add = %added.iter().map(ToString::to_string).collect::<Vec<_>>().join(","),
                    "policy.egress is shadow: direct egress not served"
                );
            }
            vec![]
        }
    }
}

/// The endpoints of the claim's gateway-placed audiences (ADR-0040): reachable through the
/// inject listener, where the rules are enforced and the credential is placed, and through no
/// other path.
fn placed_endpoints(st: &AppState, rec: &ClaimRecord) -> Vec<Endpoint> {
    claim_audiences(st, rec)
        .filter_map(|a| st.inject.get(a).map(|routes| (a, routes)))
        .flat_map(|(a, routes)| {
            let allowed = effective(st, rec, a).map(|e| e.egress).unwrap_or_default();
            routes
                .iter()
                .map(|r| r.endpoint.clone())
                .filter(move |e| allowed.contains(e))
        })
        .collect()
}

/// The union of the claim's audiences' `egress`, sorted and deduplicated, without the hosts a
/// gateway-placed audience binds to the inject path: a `CONNECT` tunnel to such a host would go
/// around the rules the inject listener enforces (ADR-0040). Under `enforce` an audience's
/// endpoints are those its bundle grants (ADR-0053 decision 11).
fn audience_egress(st: &AppState, rec: &ClaimRecord) -> Vec<Endpoint> {
    let placed = placed_endpoints(st, rec);
    let mut egress: Vec<Endpoint> = claim_audiences(st, rec)
        .filter_map(|a| effective(st, rec, a))
        .flat_map(|e| e.egress)
        .filter(|e| !placed.contains(e))
        .collect();
    egress.sort();
    egress.dedup();
    egress
}

/// `GET /v1/gateway/claims/{uid}`: what a gateway may let the claim reach (ADR-0028
/// decision 4). The peer must be the gateway authorizer's identity,
/// `spiffe://<td>/gateway/authorizer` (ADR-0053 decision 3): a node, a claim, even the claim
/// asked about, and the gateway's own listeners are `403`. A claim the store does not know, one not
/// bound (no deadline yet, so no identity for a tunnel to carry), one released or past its
/// deadline is `404`, the one answer the gateway takes as "deny, and drop what was cached".
async fn claim_egress(
    State(st): State<Shared>,
    headers: HeaderMap,
    peer: Option<Extension<PeerSpiffeId>>,
    Path(uid): Path<String>,
) -> Result<Json<ClaimEgress>, ApiError> {
    let peer = peer_spiffe_id(&st, peer.as_ref().map(|e| &e.0), &headers)?;
    require_gateway_authorizer(&st, &peer, "GET /v1/gateway/claims/{uid}", &uid)?;
    let uid = Uuid::parse_str(&uid)
        .map_err(|_| ApiError::bad_request("invalid_claim_uid", "claim uid must be a UUID"))?;
    let unknown = || ApiError::not_found("no live claim with this uid");
    let rec = st.store.get_claim(uid).await.map_err(|e| match e {
        StoreError::NotFound(_) => unknown(),
        other => ApiError::internal(other.to_string()),
    })?;
    let now = Timestamp::now();
    let Some(expires_at) = rec.expires_at.filter(|_| rec.is_live(now)) else {
        tracing::debug!(claim_uid = %uid, "gateway asked about a claim that is not live");
        return Err(unknown());
    };
    let egress = egress_of(&st, &rec);
    tracing::debug!(claim_uid = %uid, endpoints = egress.len(), "claim egress answered to the gateway");
    Ok(Json(ClaimEgress {
        claim_uid: uid,
        expires_at,
        egress,
        inject: inject_of(&st, &rec),
    }))
}

/// The claim's gateway-placed routes (ADR-0040 decision 2): one per exact upstream authority
/// of each audience it names that is declared `inject: gateway`, sorted by audience then
/// endpoint. Empty for a claim with no such audience. Carries no credential.
fn inject_of(st: &AppState, rec: &ClaimRecord) -> Vec<InjectRoute> {
    // A scoped audience's routes carry the rules of the claim's namespace, and under `enforce` the
    // bundle's grant bounded by the ceiling; only the endpoints the grant lists are routed
    // (ADR-0053 decisions 5 and 11).
    let rewrite = enforcing(st).is_some();
    let mut routes: Vec<InjectRoute> = claim_audiences(st, rec)
        .filter_map(|a| st.inject.get(a).map(|rs| (a, rs)))
        .flat_map(|(a, rs)| {
            let eff = effective(st, rec, a).unwrap_or_else(|| unreachable!("filtered"));
            let scoped = rewrite || st.scopes.contains_key(a);
            rs.iter()
                .filter(|r| !rewrite || eff.egress.contains(&r.endpoint))
                .map(|r| {
                    let mut r = r.clone();
                    if scoped {
                        r.rules.clone_from(&eff.rules);
                    }
                    r
                })
                .collect::<Vec<_>>()
        })
        .collect();
    routes.sort_by(|a, b| {
        a.audience
            .cmp(&b.audience)
            .then_with(|| a.endpoint.cmp(&b.endpoint))
    });
    routes.dedup();
    routes
}

/// What the issuer answered a refresh with: the refresh token to keep, the validated
/// identity when the fresh token is one mediatore can read, the token for an audience
/// Entra serves.
type RefreshOutcome = (String, Option<Validated>, Option<(Secret, Timestamp)>);

/// What a refresh left for the issue: the groups to mint (empty when the fresh token was
/// not one mediatore can read), and for an audience Entra serves, its token.
struct Fresh {
    groups: Vec<String>,
    obo: Option<(Secret, Timestamp)>,
}

/// Refresh the session behind `rec` and re-seal the rotated token into it. On the Dex
/// path the fresh ID token is validated like a login (ADR-0013 decision 4); on the Entra
/// path the session is refreshed for `audience`'s resource when Entra serves it (`obo`),
/// else for mediatore's own, whose token is validated like a login (ADR-0016 decision 2).
/// A refusal upstream, a fresh token that fails the gate or names another subject
/// releases the claim (entry retracted, record revoked) and answers `403`; an issuer
/// outage answers `503` and releases nothing.
async fn refresh_session(
    st: &AppState,
    rec: &ClaimRecord,
    issuer: &mediatore_entra::IssuerConfig,
    audience: &str,
    obo: bool,
) -> Result<Fresh, ApiError> {
    let Some(envelope) = rec.refresh.as_ref() else {
        return Err(ApiError::forbidden("no delegated session for this claim"));
    };
    let Some(sealer) = st.sealer.as_ref() else {
        return Err(ApiError::not_implemented("sealing"));
    };
    let plaintext = sealer
        .unseal_session(Slot::Issuer, rec.seal_binding(), envelope)
        .await
        .map_err(|e| {
            // An outage at the sealer is an outage: the envelope stays, nothing is revoked.
            if let SealError::Unavailable(_) = e {
                tracing::warn!(claim_uid = %rec.uid, error = %e, "sealer unavailable");
                seal_error(e)
            } else {
                tracing::warn!(claim_uid = %rec.uid, error = %e, "session envelope did not open");
                ApiError::forbidden("delegated session unreadable")
            }
        })?;
    let token = std::str::from_utf8(&plaintext)
        .map_err(|_| ApiError::forbidden("delegated session unreadable"))?;
    let outcome: Result<RefreshOutcome, IdpError> = if issuer.entra.is_some() {
        let resource = if obo {
            audience
        } else {
            issuer.client_id.as_str()
        };
        st.validator
            .refresh_entra(issuer, token, resource)
            .await
            .map(|r| {
                let obo = obo.then_some((r.access_token, r.expires_at));
                (r.refresh_token.0, r.validated, obo)
            })
    } else {
        st.validator
            .refresh(issuer, token)
            .await
            .map(|r| (r.refresh_token, Some(r.validated), None))
    };
    let (refresh_token, validated, obo) = match outcome {
        Ok(out) => out,
        Err(IdpError::SessionRevoked(why) | IdpError::Forbidden(why)) => {
            tracing::warn!(claim_uid = %rec.uid, subject = %rec.subject.id, %why, "upstream session refused; claim released");
            release_quietly(st, rec.uid).await;
            return Err(session_revoked());
        }
        Err(e) => {
            tracing::warn!(claim_uid = %rec.uid, error = %e, "upstream refresh unavailable");
            return Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "upstream_unavailable",
                Some("the identity provider did not answer the refresh".to_owned()),
            ));
        }
    };
    if let Some(v) = &validated
        && v.subject.id != rec.subject.id
    {
        tracing::warn!(claim_uid = %rec.uid, "refreshed session names another subject; claim released");
        release_quietly(st, rec.uid).await;
        return Err(session_revoked());
    }
    // Sealed again at every refresh, always as format 2 (ADR-0057 decision 10): a session
    // stored as format 1 becomes 2 here.
    let envelope = sealer
        .seal_session(Slot::Issuer, rec.seal_binding(), refresh_token.as_bytes())
        .await
        .map_err(seal_error)?;
    store_refreshed(st, rec.uid, &envelope).await?;
    Ok(Fresh {
        groups: validated.map(|v| v.groups).unwrap_or_default(),
        obo,
    })
}

/// Put a freshly sealed session envelope on the record of claim `claim_uid` as it is when it
/// is written (ADR-0057 decision 5). A claim released or gone in the meantime gets the answer
/// a released claim gets: the envelope is dropped unstored and the caller mints nothing. When
/// every attempt lost to another write the answer is `503`, nothing is minted and the
/// envelope is dropped; the rotated token it held is then not stored anywhere.
async fn store_refreshed(
    st: &AppState,
    claim_uid: Uuid,
    envelope: &Sealed,
) -> Result<(), ApiError> {
    let written = modify_claim(st.store.as_ref(), claim_uid, |mut fresh| {
        fresh.refresh = Some(envelope.clone());
        Some(fresh)
    })
    .await;
    match written {
        Ok(Modified::Written | Modified::Unchanged) => Ok(()),
        Ok(Modified::Released) | Err(StoreError::NotFound(_)) => {
            tracing::info!(%claim_uid, "claim released during a session refresh; nothing stored, nothing minted");
            Err(ApiError::forbidden("claim revoked or expired"))
        }
        Err(StoreError::Conflict(_)) => {
            tracing::warn!(%claim_uid, "the refreshed session could not be stored: the record was busy; nothing minted");
            Err(ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "record_busy",
                Some("the claim's record is being written; ask again".to_owned()),
            ))
        }
        Err(e) => Err(store_error(e)),
    }
}

/// A failed On-Behalf-Of exchange at claim creation (ADR-0016 decision 1): Entra's
/// refusal is `403 session_refused` with its code, anything else is the broker's or
/// Entra's problem and `503`.
fn exchange_error(validated: &Validated, resource: &str, e: &IdpError) -> ApiError {
    match e {
        IdpError::SessionRevoked(code) => {
            tracing::warn!(subject = %validated.subject.id, %resource, %code, "on-behalf-of exchange refused");
            ApiError::new(
                StatusCode::FORBIDDEN,
                "session_refused",
                Some(format!(
                    "the identity provider refused the exchange: {code}"
                )),
            )
        }
        other => {
            tracing::warn!(subject = %validated.subject.id, %resource, error = %other, "on-behalf-of exchange unavailable");
            ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "upstream_unavailable",
                Some("the identity provider did not answer the exchange".to_owned()),
            )
        }
    }
}

/// `403 session_revoked`: the delegated session is gone and so is the claim.
/// A sealing failure as an API error: the sealer's backend being away is `503
/// sealer_unavailable` (ADR-0015), anything else is the broker's own fault.
fn seal_error(e: SealError) -> ApiError {
    match e {
        SealError::Unavailable(why) => ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "sealer_unavailable",
            Some(format!("the sealer did not answer: {why}")),
        ),
        other => ApiError::internal(other.to_string()),
    }
}

fn session_revoked() -> ApiError {
    ApiError::new(
        StatusCode::FORBIDDEN,
        "session_revoked",
        Some("the upstream session was refused; the claim is released".to_owned()),
    )
}

/// `Reconciler::release` for a refusal, logged rather than surfaced: the caller is told
/// `403` either way, and a store or entry error here must not hide the revocation.
async fn release_quietly(st: &AppState, claim_uid: Uuid) {
    if let Err(e) = reconciler(st).release(claim_uid).await {
        tracing::error!(%claim_uid, error = %e, "release after an upstream refusal failed");
    }
}

async fn token(
    State(st): State<Shared>,
    headers: HeaderMap,
    peer: Option<Extension<PeerSpiffeId>>,
    Json(req): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, ApiError> {
    let (peer, claim_uid, rec) =
        token_claim(&st, peer.as_ref().map(|e| &e.0), &headers, &req.audience).await?;
    issue_token(&st, &peer, claim_uid, rec, req.audience, Placement::Proxy)
        .await
        .map(Json)
}

/// Where an issued credential is going (ADR-0040): to the proxy on the pool VM, which gets it
/// as the `POST /v1/token` answer and for which each backend logs its own audit line, or to the
/// gateway, whose route logs one line of its own once the credential is built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Placement {
    Proxy,
    Gateway,
}

/// The backend that serves `audience`, for the audit line, in the order `issue_token` tries them.
fn backend_of(st: &AppState, audience: &str) -> &'static str {
    if st.delegated.contains_key(audience) {
        "delegated"
    } else if st.secrets.contains_key(audience) {
        "secret"
    } else if st.obo_audiences.iter().any(|a| a == audience) {
        "entra-obo"
    } else {
        "sts"
    }
}

/// A claim outlives the configuration it was made under: an operator who removes an issuer
/// (a compromised one, say) or an audience expects the claims that rest on it to get nothing
/// more. The issuer the claim's subject logged in at, when it is still configured and the
/// audience still is; `403` otherwise, before any backend is looked at.
fn still_configured<'a>(
    st: &'a AppState,
    rec: &ClaimRecord,
    audience: &str,
    claim_uid: Uuid,
) -> Result<&'a mediatore_entra::IssuerConfig, ApiError> {
    let Some(issuer) = st.validator.issuer_named(&rec.subject.issuer) else {
        tracing::warn!(%claim_uid, %audience, issuer = %rec.subject.issuer, "token refused: the claim's issuer is no longer configured");
        return Err(ApiError::forbidden(
            "the claim's issuer is no longer configured",
        ));
    };
    if !st.audiences.iter().any(|a| a == audience) {
        tracing::warn!(%claim_uid, %audience, "token refused: the audience is no longer configured");
        return Err(ApiError::forbidden("the audience is no longer configured"));
    }
    Ok(issuer)
}

/// A credential's stated expiry, never later than the claim's own deadline: nothing the
/// broker hands out for a claim is said to outlive it. A claim with no deadline (never bound)
/// has nothing to clamp to.
fn within_claim(expires_at: Timestamp, claim_end: Option<Timestamp>) -> Timestamp {
    claim_end.map_or(expires_at, |end| expires_at.min(end))
}

/// A claim's credential for `audience`, once the claim has passed its gate: the one
/// per-backend code (delegated, secret, Entra On-Behalf-Of, STS) that `POST /v1/token` and the
/// gateway's credential route both run (ADR-0040 decision 2). `actor` is the SPIFFE ID the
/// token is minted for: the claim identity on `/v1/token`, and the same claim identity when the
/// gateway asks, so an STS token carries the same `act` either way.
async fn issue_token(
    st: &AppState,
    actor: &str,
    claim_uid: Uuid,
    rec: ClaimRecord,
    audience: String,
    placement: Placement,
) -> Result<TokenResponse, ApiError> {
    // ADR-0053 decision 11: under `enforce` a credential lives at most the bundle grant's
    // `ttlSeconds`. The STS mints with it; every other backend's expiry is the proxy's or the
    // gateway's cache bound, so it is clamped on the way out.
    let cap = effective(st, &rec, &audience)
        .and_then(|e| e.ttl_cap)
        .map(SignedDuration::from_secs);
    let mut issued =
        issue_token_capped(st, actor, claim_uid, rec, audience, placement, cap).await?;
    if let Some(cap) = cap {
        issued.expires_at = issued.expires_at.min(Timestamp::now() + cap);
    }
    Ok(issued)
}

async fn issue_token_capped(
    st: &AppState,
    actor: &str,
    claim_uid: Uuid,
    rec: ClaimRecord,
    audience: String,
    placement: Placement,
    cap: Option<SignedDuration>,
) -> Result<TokenResponse, ApiError> {
    // Before any backend, the operator's `via: secret` included: nothing is handed to a claim
    // whose issuer or audience has left the configuration.
    let issuer = still_configured(st, &rec, &audience, claim_uid)?;
    // No backend states an expiry later than the claim's own deadline.
    let claim_end = rec.expires_at;
    // ADR-0035: the caller's own credential, opened from the record's envelope for this
    // audience, handed with the header it goes in; it dies with the credential, the claim or
    // `max_ttl`, whichever is first.
    if let Some(d) = st.delegated.get(&audience) {
        return delegated_token(st, &rec, d, audience, claim_uid, placement).await;
    }
    // ADR-0032: an operator-held credential is handed as it is, with the header it goes in;
    // the proxy keeps it for `max_ttl` and asks again, through this same gate.
    if let Some(sec) = st.secrets.get(&audience) {
        if placement == Placement::Proxy {
            tracing::info!(%claim_uid, %audience, subject = %rec.subject.id, backend = "secret", header = %sec.header, "token issued");
        }
        let mut answer = sec.response(audience, rec.subject);
        answer.expires_at = within_claim(answer.expires_at, claim_end);
        return Ok(answer);
    }
    // ADR-0013 decision 4, ADR-0016 decision 2: a session issuer's record is refreshed
    // upstream first, for the audience's resource. One refresh at a time per claim, over
    // the record as it is once the lock is held: the previous one may have rotated the
    // envelope, or released the claim.
    let obo = st.obo_audiences.iter().any(|a| a == &audience);
    if obo && issuer.entra.is_none() {
        return Err(ApiError::forbidden(
            "audience is served On-Behalf-Of and this claim has no Entra session",
        ));
    }
    let fresh = if issuer.session.is_some() || issuer.entra.is_some() {
        let lock = st.limiter.refresh_lock(claim_uid);
        let _held = lock.lock().await;
        let rec = st
            .store
            .get_claim(claim_uid)
            .await
            .map_err(|_| ApiError::forbidden("unknown claim"))?;
        if !rec.is_live(Timestamp::now()) {
            return Err(ApiError::forbidden("claim revoked or expired"));
        }
        refresh_session(st, &rec, issuer, &audience, obo).await?
    } else {
        Fresh {
            groups: vec![],
            obo: None,
        }
    };
    if let Some((token, expires_at)) = fresh.obo {
        // Entra's token lives as long as Entra says; what the proxy is told to keep it for
        // ends with the claim.
        let expires_at = within_claim(expires_at, claim_end);
        if placement == Placement::Proxy {
            tracing::info!(%claim_uid, %audience, subject = %rec.subject.id, %expires_at, "token issued on behalf of the subject");
        }
        return Ok(TokenResponse {
            access_token: token.0,
            token_type: "Bearer".into(),
            expires_at,
            audience,
            subject: rec.subject,
            header: None,
            extra_headers: vec![],
        });
    }
    let Some(sts) = st.sts.as_ref() else {
        return Err(ApiError::not_implemented("sts backend not configured"));
    };
    // The first of fifteen minutes, this audience's own maximum and the time the claim has
    // left, measured and minted at the same instant so the token's `exp` is never past the
    // claim's deadline.
    let now = Timestamp::now();
    let mut ttl = SignedDuration::from_mins(15).min(sts.max_ttl_for(&audience));
    if let Some(cap) = cap {
        ttl = ttl.min(cap);
    }
    if let Some(end) = claim_end {
        ttl = ttl.min(end.duration_since(now));
    }
    if ttl <= SignedDuration::ZERO {
        return Err(ApiError::forbidden("claim revoked or expired"));
    }
    let minted = sts
        .mint_at(
            &MintRequest {
                subject: &rec.subject,
                actor_spiffe_id: actor,
                claim_uid,
                audience: &audience,
                groups: fresh.groups,
                ttl,
            },
            now,
        )
        .map_err(|e| ApiError::internal(e.to_string()))?;
    if placement == Placement::Proxy {
        tracing::info!(%claim_uid, %audience, subject = %rec.subject.id, "token issued");
    }
    Ok(TokenResponse {
        access_token: minted.token,
        token_type: "Bearer".into(),
        expires_at: minted.expires_at,
        audience,
        subject: rec.subject,
        header: None,
        extra_headers: vec![],
    })
}

/// What every token request establishes first: the peer is a claim identity, the claim is
/// live, it names the audience, the audience is served with a credential, and the claim
/// is under its rate limit.
async fn token_claim(
    st: &AppState,
    peer: Option<&PeerSpiffeId>,
    headers: &HeaderMap,
    audience: &str,
) -> Result<(String, Uuid, ClaimRecord), ApiError> {
    let peer = peer_spiffe_id(st, peer, headers)?;
    let claim_uid = st
        .naming
        .claim_uid_from(&peer)
        .ok_or_else(|| ApiError::forbidden("peer is not a claim identity"))?;
    let rec = st
        .store
        .get_claim(claim_uid)
        .await
        .map_err(|_| ApiError::forbidden("unknown claim"))?;
    if !rec.is_live(Timestamp::now()) {
        return Err(ApiError::forbidden("claim revoked or expired"));
    }
    if !claim_audiences(st, &rec).any(|a| a == audience) {
        return Err(ApiError::bad_request(
            "unknown_audience",
            audience.to_owned(),
        ));
    }
    // ADR-0025 decision 8: an audience reached without a credential has no token to give;
    // the proxy never asks, and nothing else holding the claim SVID gets one either.
    if st.no_credential.contains(audience) {
        tracing::debug!(%claim_uid, audience = %audience.to_owned(), "token refused: the audience is served without a credential");
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "no_credential",
            Some("the audience is reached without a credential (via: none)".to_owned()),
        ));
    }
    // ADR-0040 decision 2: an audience whose credential the gateway places is not the pool
    // VM's to hold, so the claim SVID that is asking gets none, however the proxy is built.
    // Refused before the rate limit: a refusal spends no token.
    if st.inject.contains_key(audience) {
        tracing::debug!(%claim_uid, audience = %audience.to_owned(), "token refused: the credential is placed at the gateway");
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            error_code::PLACED_AT_GATEWAY,
            Some("the credential for this audience is placed at the gateway".to_owned()),
        ));
    }
    if !st.limiter.allow(claim_uid) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            Some("too many token requests for this claim".to_owned()),
        ));
    }
    Ok((peer, claim_uid, rec))
}

/// A `via: delegated` audience's credential (ADR-0035 decision 4), for `POST /v1/token` and,
/// placed at the gateway, for its credential route (ADR-0040).
async fn delegated_token(
    st: &AppState,
    rec: &ClaimRecord,
    d: &DelegatedAudience,
    audience: String,
    claim_uid: Uuid,
    placement: Placement,
) -> Result<TokenResponse, ApiError> {
    let Some(sealer) = st.sealer.as_ref() else {
        return Err(ApiError::not_implemented("sealing"));
    };
    let Some(held) = rec.delegations.get(&audience) else {
        return Err(ApiError::forbidden(
            "no credential was delegated for this audience, or it was revoked",
        ));
    };
    // Opened under the audience that was asked for (ADR-0057 decision 9): nothing in clear
    // chooses the context, so an envelope of another audience of this sandbox, or its
    // issuer's session, put in this one's place does not open.
    let plain = sealer
        .unseal_session(Slot::Delegation(&audience), rec.seal_binding(), &held.envelope)
        .await
        .map_err(|e| {
            if let SealError::Unavailable(_) = e {
                return seal_error(e);
            }
            tracing::warn!(%claim_uid, %audience, error = %e, "delegation envelope did not open for this audience");
            ApiError::forbidden("the delegated credential does not open for this audience")
        })?;
    let plain: DelegationPlain = serde_json::from_slice(&plain)
        .map_err(|_| ApiError::internal("the delegation envelope is not what was sealed"))?;
    // The expiry that bounds the credential (decision 11): the one sealed with it. No clear
    // value is read for a format 2 envelope, and one that carries no expiry inside is not
    // what this broker seals: refused. A format 1 envelope has none inside and keeps the
    // clear value, as it was issued from before, until its claim ends.
    let stored_expiry = if held.envelope.format == FORMAT_BARE_UID {
        held.expires_at
    } else {
        Some(
            plain
                .expires_at
                .ok_or_else(|| ApiError::internal("the delegation envelope carries no expiry"))?,
        )
    };
    let now = Timestamp::now();
    let mut expires_at = now + d.ttl;
    if let Some(e) = stored_expiry {
        expires_at = expires_at.min(e);
    }
    if let Some(e) = rec.expires_at {
        expires_at = expires_at.min(e);
    }
    if expires_at <= now {
        return Err(ApiError::forbidden("the delegated credential has expired"));
    }
    if d.basic {
        // ADR-0041 decision 8: `Authorization: Basic base64(user:secret)`, whole, so the gateway places
        // it as it is (a response with a header carries the value bare).
        basic_parts(&plain.token.0).map_err(|_| {
            ApiError::internal("the delegation envelope is not a user name and a secret")
        })?;
        let value = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(plain.token.0.as_bytes())
        );
        return Ok(TokenResponse {
            access_token: value,
            token_type: "Header".into(),
            expires_at,
            audience,
            subject: rec.subject.clone(),
            header: Some("authorization".into()),
            extra_headers: d.extra_headers.clone(),
        });
    }
    let bearer = d.header == "authorization";
    if placement == Placement::Proxy {
        tracing::info!(%claim_uid, %audience, subject = %rec.subject.id, backend = "delegated", header = %d.header, %expires_at, "token issued");
    }
    Ok(TokenResponse {
        access_token: plain.token.0,
        token_type: if bearer { "Bearer" } else { "Header" }.into(),
        expires_at,
        audience,
        subject: rec.subject.clone(),
        header: (!bearer).then(|| d.header.clone()),
        extra_headers: d.extra_headers.clone(),
    })
}

/// Whether the claim's policy admits `audience` for a gateway-placed credential (ADR-0040
/// decision 2). Without a `policy` section there is nothing to compare. Under
/// `policy.egress: enforce` the claim must name a policy whose verified, unexpired bundle
/// lists the audience, and fails closed otherwise (no policy on the claim, no bundle, or an
/// audience the bundle omits); under `shadow` the gap is logged and nothing is refused.
fn policy_admits(st: &AppState, rec: &ClaimRecord, audience: &str) -> Result<(), ApiError> {
    let Some(pe) = st.policy_egress.as_ref() else {
        return Ok(());
    };
    let admitted = rec
        .policy_uid
        .as_deref()
        .and_then(|uid| pe.bundles.by_uid(uid, Timestamp::now()))
        .is_some_and(|b| b.content.audiences.iter().any(|g| g.name == audience));
    match pe.mode {
        mediatore_claims::policy::EgressMode::Enforce if !admitted => {
            tracing::warn!(claim_uid = %rec.uid, %audience, "gateway credential refused: the claim's policy does not admit the audience");
            Err(ApiError::forbidden(
                "the claim's policy does not admit this audience",
            ))
        }
        mediatore_claims::policy::EgressMode::Shadow if !admitted => {
            tracing::info!(claim_uid = %rec.uid, %audience, "policy.egress is shadow: the bundle would not admit this audience for the gateway credential");
            Ok(())
        }
        _ => Ok(()),
    }
}

/// `POST /v1/gateway/claims/{uid}/credential`: the credential of a gateway-placed audience, for
/// the gateway's authorizer alone (ADR-0040 decision 2). The peer must be the authorizer's
/// identity (ADR-0053 decision 3), as for `GET /v1/gateway/claims/{uid}`: a node, a claim, even
/// the claim asked about, and a gateway's listener are `403`. A claim that is unknown, unbound, released or past its deadline is `404`, the answer
/// the gateway takes as "drop what was cached". The gate then is `POST /v1/token`'s (the claim
/// names the audience, the per-claim rate limit) plus the policy bundle under `enforce`, the
/// audience must be gateway-placed, and the credential comes from the same per-backend code.
/// It is built for this answer and kept nowhere; each issue is one audit line that names the
/// claim, audience, subject, backend, expiry and the peer that asked, never the credential.
async fn gateway_credential(
    State(st): State<Shared>,
    headers: HeaderMap,
    peer: Option<Extension<PeerSpiffeId>>,
    Path(uid): Path<String>,
    Json(req): Json<GatewayCredentialRequest>,
) -> Result<Json<GatewayCredential>, ApiError> {
    let peer = peer_spiffe_id(&st, peer.as_ref().map(|e| &e.0), &headers)?;
    require_gateway_authorizer(&st, &peer, "POST /v1/gateway/claims/{uid}/credential", &uid)?;
    let claim_uid = Uuid::parse_str(&uid)
        .map_err(|_| ApiError::bad_request("invalid_claim_uid", "claim uid must be a UUID"))?;
    let unknown = || ApiError::not_found("no live claim with this uid");
    let rec = st.store.get_claim(claim_uid).await.map_err(|e| match e {
        StoreError::NotFound(_) => unknown(),
        other => ApiError::internal(other.to_string()),
    })?;
    if rec.expires_at.is_none() || !rec.is_live(Timestamp::now()) {
        tracing::debug!(%claim_uid, "gateway asked for a credential of a claim that is not live");
        return Err(unknown());
    }
    let audience = req.audience;
    if !claim_audiences(&st, &rec).any(|a| a == &audience) {
        return Err(ApiError::bad_request("unknown_audience", audience));
    }
    if !st.inject.contains_key(&audience) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            error_code::NOT_PLACED_AT_GATEWAY,
            Some("the audience's credential is placed in the proxy, not at the gateway".to_owned()),
        ));
    }
    policy_admits(&st, &rec, &audience)?;
    if !st.limiter.allow(claim_uid) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            Some("too many credential requests for this claim".to_owned()),
        ));
    }
    let backend = backend_of(&st, &audience);
    let actor = st.naming.claim_id(claim_uid);
    let issued = issue_token(&st, &actor, claim_uid, rec, audience, Placement::Gateway).await?;
    let credential = GatewayCredential::from_token_response(issued, Timestamp::now());
    tracing::info!(%claim_uid, audience = %credential.audience, subject = %credential.subject.id, backend, expires_at = %credential.expires_at, %peer, "gateway credential issued");
    Ok(Json(credential))
}

/// Router for attested VMs and their jailed workloads.
pub fn sandbox_router(state: Shared) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/nodes", post(register_node))
        .route("/v1/me", get(me))
        .route("/v1/me/report", post(report))
        .route("/v1/me/exit", post(exit))
        .route("/v1/me/logs", post(ingest_logs))
        .route("/v1/token", post(token))
        .route("/v1/gateway/claims/{uid}", get(claim_egress))
        .route(
            "/v1/gateway/claims/{uid}/credential",
            post(gateway_credential),
        )
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_limiter_allows_the_burst_then_refuses_per_claim() {
        let l = Limiter::new(3);
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        assert!(l.allow(a) && l.allow(a) && l.allow(a));
        assert!(!l.allow(a), "the burst is spent");
        assert!(l.allow(b), "another claim has its own bucket");
        assert!(
            Limiter::new(0).allow(a),
            "zero means one a minute, never none"
        );
    }

    #[test]
    fn the_per_second_limiter_takes_one_batch_and_refuses_the_next_within_the_second() {
        // ADR-0045 decision 4: one batch per second per claim, the burst the same.
        let l = Limiter::per_second(1);
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        assert!(l.allow(a));
        assert!(!l.allow(a), "the second batch within the second is refused");
        assert!(l.allow(b), "another claim has its own bucket");
        assert!(
            Limiter::per_second(0).allow(a),
            "zero means one a second, never none"
        );
    }

    #[test]
    fn the_tables_are_pruned_past_the_threshold_and_no_more_than_once_an_interval() {
        let l = Limiter::new(3);
        let size = |l: &Limiter| l.locks.lock().unwrap().map.len();
        let fill = |l: &Limiter, at: std::time::Instant| {
            for _ in 0..=BUCKET_PRUNE_AT {
                // The handle is dropped at once: nothing holds the lock, it may be pruned.
                drop(l.refresh_lock_at(Uuid::new_v4(), at));
            }
        };
        let t0 = l.locks.lock().unwrap().last_pruned;
        fill(&l, t0);
        assert_eq!(size(&l), BUCKET_PRUNE_AT + 1, "over the threshold");
        drop(l.refresh_lock_at(Uuid::new_v4(), t0));
        assert_eq!(
            size(&l),
            BUCKET_PRUNE_AT + 2,
            "within the interval nothing is pruned"
        );
        let t1 = t0 + BUCKET_PRUNE_EVERY;
        let held = l.refresh_lock_at(Uuid::new_v4(), t1);
        assert_eq!(size(&l), 1, "the interval passed: the unheld locks went");
        fill(&l, t1);
        assert_eq!(
            size(&l),
            BUCKET_PRUNE_AT + 2,
            "over the threshold again, and the prune waits for its interval"
        );
        drop(l.refresh_lock_at(Uuid::new_v4(), t1 + BUCKET_PRUNE_EVERY));
        assert_eq!(size(&l), 2, "the held lock survives the next prune");
        drop(held);

        // The buckets: an idle one goes with the prune, and never before its interval.
        let b = Limiter::new(3);
        let buckets = |b: &Limiter| b.buckets.lock().unwrap().map.len();
        let t0 = b.buckets.lock().unwrap().last_pruned;
        for _ in 0..=BUCKET_PRUNE_AT {
            assert!(b.allow_at(Uuid::new_v4(), t0));
        }
        assert!(b.allow_at(Uuid::new_v4(), t0 + BUCKET_PRUNE_EVERY));
        assert_eq!(
            buckets(&b),
            BUCKET_PRUNE_AT + 2,
            "a prune that finds no idle bucket drops none"
        );
        assert!(b.allow_at(Uuid::new_v4(), t0 + BUCKET_IDLE + BUCKET_PRUNE_EVERY));
        assert_eq!(buckets(&b), 1, "the idle buckets went with the prune");
    }

    // ---------- ADR-0040: the gateway places an audience's credential ----------

    use axum::body::Body;
    use axum::http::Request;
    use mediatore_proto::{
        GatewayCredential, GatewayCredentialRequest, InjectRoute, Workload, error_code,
    };
    use tower::ServiceExt as _;

    const TD: &str = "sandbox.test";
    const SECRET_VALUE: &str = "sk-ant-SECRETVALUE-0123456789";
    const SESSION_TOKEN: &str = "claude-session-TOKEN-9876543210";

    fn naming() -> Naming {
        Naming {
            trust_domain: TD.into(),
        }
    }

    fn pair(name: &str, value: &str) -> HeaderPair {
        HeaderPair {
            name: name.into(),
            value: value.into(),
        }
    }

    fn inject_route(audience: &str, host: &str, header: &str) -> InjectRoute {
        InjectRoute {
            audience: audience.into(),
            endpoint: Endpoint {
                host: host.into(),
                port: 443,
            },
            rules: vec![EndpointRule {
                method: "POST".into(),
                path: "/v1/messages".into(),
            }],
            header: header.into(),
            extra_headers: if header == "x-api-key" {
                vec![pair("anthropic-version", "2023-06-01")]
            } else {
                vec![]
            },
        }
    }

    /// A state with nothing configured; `dev_mode` so the tests name the peer in a header.
    fn base_state() -> AppState {
        AppState {
            store: mediatore_store::MemoryStore::shared(),
            spire: Arc::new(mediatore_spire::MemoryEntries::default()),
            naming: naming(),
            validator: Validator::new(vec![subject_issuer()]),
            sts: None,
            audiences: vec![],
            obo_audiences: vec![],
            egress: BTreeMap::new(),
            rules: BTreeMap::new(),
            cas: BTreeMap::new(),
            no_credential: std::collections::BTreeSet::new(),
            secrets: BTreeMap::new(),
            delegated: BTreeMap::new(),
            registries: BTreeMap::new(),
            reachable_registries: None,
            policy_egress: None,
            sandboxes: None,
            namespaces: Namespaces::Single("sandboxes".into()),
            sealer: None,
            limiter: Limiter::new(10),
            dev_mode: true,
            gateways: vec![],
            inject: BTreeMap::new(),
            inject_port: None,
            logs: None,
            log_limiter: Limiter::per_second(1),
            accept_plain_gateway_identity: false,
            scopes: std::collections::BTreeMap::new(),
        }
    }

    /// The broker as ADR-0040 configures it: `anthropic` (a `via: secret` audience, header
    /// `x-api-key`) and `claude` (delegated, `authorization`) placed at the gateway, `sts-gw`
    /// (minted) placed at the gateway, and `grafana` (secret) and `grafana-sts` placed in the
    /// proxy as before.
    fn placed_state() -> AppState {
        let mut st = base_state();
        st.audiences = ["anthropic", "claude", "sts-gw", "grafana", "grafana-sts"]
            .map(String::from)
            .to_vec();
        for (a, host) in [
            ("anthropic", "api.anthropic.example"),
            ("claude", "api.claude.example"),
            ("sts-gw", "api.sts-gw.example"),
            ("grafana", "grafana.example"),
            ("grafana-sts", "grafana-sts.example"),
        ] {
            st.egress
                .insert(a.into(), vec![format!("{host}:443").parse().unwrap()]);
        }
        st.secrets.insert(
            "anthropic".into(),
            AudienceSecret {
                value: Secret(SECRET_VALUE.into()),
                header: "x-api-key".into(),
                extra_headers: vec![pair("anthropic-version", "2023-06-01")],
                ttl: SignedDuration::from_mins(15),
            },
        );
        st.secrets.insert(
            "grafana".into(),
            AudienceSecret {
                value: Secret("grafana-key".into()),
                header: "authorization".into(),
                extra_headers: vec![],
                ttl: SignedDuration::from_mins(15),
            },
        );
        st.delegated.insert(
            "claude".into(),
            DelegatedAudience {
                header: "authorization".into(),
                extra_headers: vec![],
                ttl: SignedDuration::from_mins(15),
                basic: false,
            },
        );
        st.sts = Some(
            Sts::new(
                "https://mediatore.test",
                "t-1",
                // A key made for this test: no key lives in the source (the testkit's generator).
                mediatore_testkit::entra::fresh_p256_key_pem().as_bytes(),
                SignedDuration::from_mins(15),
            )
            .expect("sts"),
        );
        st.inject.insert(
            "anthropic".into(),
            vec![inject_route(
                "anthropic",
                "api.anthropic.example",
                "x-api-key",
            )],
        );
        st.inject.insert(
            "claude".into(),
            vec![inject_route(
                "claude",
                "api.claude.example",
                "authorization",
            )],
        );
        st.inject.insert(
            "sts-gw".into(),
            vec![inject_route(
                "sts-gw",
                "api.sts-gw.example",
                "authorization",
            )],
        );
        st.inject_port = Some(3133);
        st
    }

    fn subject() -> mediatore_proto::Subject {
        mediatore_proto::Subject {
            issuer: "https://idp.example".into(),
            id: "octocat".into(),
            display: None,
        }
    }

    /// The issuer [`subject`] logged in at, as the configuration names it. No session, so an
    /// issue asks nothing upstream.
    fn subject_issuer() -> IssuerConfig {
        IssuerConfig {
            url: subject().issuer,
            backend: Backend::Sts,
            client_id: "mediatore".into(),
            subject_claim: "preferred_username".into(),
            required_group: None,
            required_groups: None,
            allow_any_authenticated: true,
            session: None,
            ca_file: None,
            entra: None,
            groups_claim: None,
        }
    }

    fn claim(audiences: &[&str], node_id: Option<String>) -> ClaimRecord {
        let uid = Uuid::new_v4();
        ClaimRecord {
            uid,
            name: format!("claim-{uid}"),
            subject: subject(),
            entry_id: Some("entry-1".into()),
            node_id,
            audiences: audiences.iter().map(|a| (*a).to_owned()).collect(),
            workload: Workload::default(),
            ttl_seconds: 900,
            refresh: None,
            created_at: Timestamp::now(),
            expires_at: Some(Timestamp::now() + SignedDuration::from_mins(15)),
            revoked_at: None,
            sandbox_uid: None,
            policy_uid: None,
            bundle_version: None,
            report: None,
            exit: None,
            delegations: BTreeMap::new(),
            namespace: "sandboxes".into(),
            version: None,
        }
    }

    async fn stored(st: &Shared, rec: ClaimRecord) -> ClaimRecord {
        st.store.put_claim(rec.clone()).await.expect("put claim");
        rec
    }

    /// One request through the sandbox router; the body as JSON (null when it is not) and as text.
    async fn call(
        st: &Shared,
        method: &str,
        uri: &str,
        peer: Option<&str>,
        body: serde_json::Value,
    ) -> (StatusCode, serde_json::Value, String) {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(p) = peer {
            req = req.header("x-mediatore-peer-spiffe-id", p);
        }
        let resp = sandbox_router(st.clone())
            .oneshot(req.body(Body::from(body.to_string())).unwrap())
            .await
            .unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        (
            status,
            serde_json::from_str(&text).unwrap_or(serde_json::Value::Null),
            text,
        )
    }

    /// The one peer of the gateway routes: the authorizer's identity (ADR-0053 decision 3).
    fn gateway_peer() -> String {
        naming().gateway_authorizer_id()
    }

    /// `POST /v1/gateway/claims/{uid}/credential` as `peer`.
    async fn ask(
        st: &Shared,
        uid: impl std::fmt::Display,
        peer: Option<&str>,
        audience: &str,
    ) -> (StatusCode, serde_json::Value, String) {
        call(
            st,
            "POST",
            &format!("/v1/gateway/claims/{uid}/credential"),
            peer,
            serde_json::to_value(GatewayCredentialRequest {
                audience: audience.into(),
            })
            .unwrap(),
        )
        .await
    }

    fn code(body: &serde_json::Value) -> &str {
        body["error"].as_str().unwrap_or_default()
    }

    // ----- the route: what it hands the gateway -----

    #[tokio::test]
    async fn the_gateway_gets_a_secret_audiences_credential_whole_with_its_headers_and_a_capped_expiry()
     {
        let st: Shared = Arc::new(placed_state());
        let rec = stored(&st, claim(&["anthropic"], None)).await;
        let before = Timestamp::now();
        let (status, body, _) = ask(&st, rec.uid, Some(&gateway_peer()), "anthropic").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let c: GatewayCredential = serde_json::from_value(body).unwrap();
        assert_eq!(c.audience, "anthropic");
        assert_eq!(c.subject.id, "octocat");
        assert_eq!(c.header, "x-api-key");
        assert_eq!(
            c.value.0, SECRET_VALUE,
            "a non-authorization header gets the bare value"
        );
        assert_eq!(
            c.extra_headers,
            vec![pair("anthropic-version", "2023-06-01")]
        );
        let cap = mediatore_proto::GATEWAY_CREDENTIAL_MAX_TTL_SECS;
        assert!(
            c.expires_at > before
                && c.expires_at <= Timestamp::now() + SignedDuration::from_secs(cap),
            "the 15 minute secret ttl is cut to the 300 second cap: {}",
            c.expires_at
        );
    }

    #[tokio::test]
    async fn a_delegated_credential_is_opened_from_its_envelope_for_the_gateway_with_a_bearer() {
        let mut st = placed_state();
        let sealer: Arc<dyn Sealer> = Arc::new(mediatore_store::seal::LocalKeySealer::new([7; 32]));
        let mut rec = claim(&["claude"], None);
        let plain = serde_json::to_vec(&DelegationPlain {
            token: Secret(SESSION_TOKEN.into()),
            refresh_token: None,
            expires_at: Some(Timestamp::now() + SignedDuration::from_hours(1)),
        })
        .unwrap();
        let envelope = sealer
            .seal_session(Slot::Delegation("claude"), rec.seal_binding(), &plain)
            .await
            .unwrap();
        rec.delegations.insert(
            "claude".into(),
            DelegatedSession {
                envelope,
                expires_at: Some(Timestamp::now() + SignedDuration::from_hours(1)),
            },
        );
        st.sealer = Some(sealer);
        let st: Shared = Arc::new(st);
        let rec = stored(&st, rec).await;
        let (status, body, _) = ask(&st, rec.uid, Some(&gateway_peer()), "claude").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let c: GatewayCredential = serde_json::from_value(body).unwrap();
        assert_eq!(c.header, "authorization");
        assert_eq!(c.value.0, format!("Bearer {SESSION_TOKEN}"));
        assert!(c.expires_at <= Timestamp::now() + SignedDuration::from_secs(300));
    }

    #[tokio::test]
    async fn a_basic_delegation_is_placed_as_authorization_basic_of_user_colon_secret() {
        use base64::Engine as _;
        let mut st = placed_state();
        st.delegated.insert(
            "claude".into(),
            DelegatedAudience {
                header: "authorization".into(),
                extra_headers: vec![],
                ttl: SignedDuration::from_mins(15),
                basic: true,
            },
        );
        let sealer: Arc<dyn Sealer> = Arc::new(mediatore_store::seal::LocalKeySealer::new([7; 32]));
        let mut rec = claim(&["claude"], None);
        let plain = serde_json::to_vec(&DelegationPlain {
            token: Secret("alice:p@ss:word".into()),
            refresh_token: None,
            expires_at: Some(Timestamp::now() + SignedDuration::from_hours(1)),
        })
        .unwrap();
        let envelope = sealer
            .seal_session(Slot::Delegation("claude"), rec.seal_binding(), &plain)
            .await
            .unwrap();
        rec.delegations.insert(
            "claude".into(),
            DelegatedSession {
                envelope,
                expires_at: None,
            },
        );
        st.sealer = Some(sealer);
        let st: Shared = Arc::new(st);
        let rec = stored(&st, rec).await;
        let (status, body, _) = ask(&st, rec.uid, Some(&gateway_peer()), "claude").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let c: GatewayCredential = serde_json::from_value(body).unwrap();
        assert_eq!(c.header, "authorization");
        let want = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("alice:p@ss:word")
        );
        assert_eq!(
            c.value.0, want,
            "the user ends at the first colon; the secret may hold more"
        );
        assert!(c.expires_at <= Timestamp::now() + SignedDuration::from_secs(300));
    }

    #[test]
    fn a_parked_credential_never_outlives_the_claims_ttl() {
        // The operator's rule, 2026-11-15: a delegated secret is stored no longer than the claim's TTL. The envelope's own
        // expiry is the least of the credential's (when the caller knows it) and the claim's creation plus its TTL.
        let created = Timestamp::from_second(1_800_000_000).unwrap();
        let ttl_end = created + SignedDuration::from_secs(900);
        assert_eq!(
            parked_expiry(None, created, 900),
            ttl_end,
            "no expiry known: the claim's TTL"
        );
        assert_eq!(
            parked_expiry(Some(created + SignedDuration::from_hours(5)), created, 900),
            ttl_end,
            "a credential that outlives the claim is still stored only that long"
        );
        let sooner = created + SignedDuration::from_secs(300);
        assert_eq!(
            parked_expiry(Some(sooner), created, 900),
            sooner,
            "a credential that dies first is stored only until it does"
        );
    }

    #[tokio::test]
    async fn the_issuers_session_is_parked_with_the_claims_ttl_as_its_expiry() {
        // The issuer's session is an envelope like a delegation: parked open-ended, the sweep would never remove
        // it when its sandbox went away without a release.
        let st = base_state();
        let sealer = mediatore_store::seal::LocalKeySealer::new([7; 32]);
        let mut created = sandbox_in("team-a", "sb-1");
        let sandbox_uid = Uuid::new_v4();
        created.metadata.uid = Some(sandbox_uid.to_string());
        let ttl = SignedDuration::from_secs(i64::from(created.spec.ttl_seconds));
        let validated = Validated {
            subject: subject(),
            issuer: subject_issuer(),
            groups: vec![],
            expires_at: Timestamp::now(),
        };
        let token = Secret("refresh-material-placeholder".into());
        let before = Timestamp::now();
        park_session(&st, &sealer, &created, &validated, &token)
            .await
            .expect("parked");
        let after = Timestamp::now();
        let parked = st.store.take_session(sandbox_uid).await.unwrap();
        let is_the_issuers = parked.as_ref().is_some_and(|s| s.audience.is_none());
        assert!(is_the_issuers, "one session, the issuer's");
        let bounded = parked
            .and_then(|s| s.expires_at)
            .is_some_and(|e| e >= before + ttl && e <= after + ttl);
        assert!(
            bounded,
            "stored until the claim's creation plus its TTL, no longer"
        );
    }

    #[test]
    fn a_basic_token_is_a_user_a_colon_and_a_secret_with_no_control_character() {
        assert_eq!(basic_parts("alice:s3cret"), Ok(("alice", "s3cret")));
        assert_eq!(basic_parts("alice:a:b"), Ok(("alice", "a:b")));
        for bad in [
            "nocolon",
            ":secret",
            "user:",
            "us\ner:secret",
            "user:sec\r\nret",
            "user:sec\0ret",
        ] {
            assert!(basic_parts(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[tokio::test]
    async fn an_audience_minted_by_the_sts_is_minted_for_the_claim_and_placed_at_the_gateway() {
        let st: Shared = Arc::new(placed_state());
        let rec = stored(&st, claim(&["sts-gw"], None)).await;
        let (status, body, _) = ask(&st, rec.uid, Some(&gateway_peer()), "sts-gw").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let c: GatewayCredential = serde_json::from_value(body).unwrap();
        assert_eq!(c.header, "authorization");
        let jwt = c.value.0.strip_prefix("Bearer ").expect("a bearer");
        assert_eq!(jwt.split('.').count(), 3, "a compact JWT: {jwt}");
        assert!(c.expires_at <= Timestamp::now() + SignedDuration::from_secs(300));
    }

    #[tokio::test]
    async fn issuing_stores_nothing_the_record_is_unchanged() {
        let st: Shared = Arc::new(placed_state());
        let rec = stored(&st, claim(&["anthropic"], None)).await;
        let (status, ..) = ask(&st, rec.uid, Some(&gateway_peer()), "anthropic").await;
        assert_eq!(status, StatusCode::OK);
        let after = st.store.get_claim(rec.uid).await.unwrap();
        assert_eq!(
            serde_json::to_value(&after).unwrap(),
            serde_json::to_value(&rec).unwrap(),
            "the credential is never cached or stored"
        );
    }

    // ----- who may ask, and for what -----

    #[tokio::test]
    async fn only_the_authorizers_identity_may_ask_and_a_refusal_never_carries_the_credential() {
        let st: Shared = Arc::new(placed_state());
        let rec = stored(&st, claim(&["anthropic"], None)).await;
        let n = naming();
        let not_authorizers = [
            n.claim_id(rec.uid),
            n.node_id("ekhash"),
            n.broker_id(),
            n.gateway_id(),
            "spiffe://other.test/gateway".to_owned(),
            "spiffe://other.test/gateway/authorizer".to_owned(),
            format!("spiffe://{TD}/gateway/extra"),
            format!("spiffe://{TD}/gateway/authorizer/extra"),
        ];
        for peer in &not_authorizers {
            let (status, body, text) = ask(&st, rec.uid, Some(peer), "anthropic").await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{peer}: {text}");
            assert_eq!(code(&body), "forbidden", "{peer}");
            assert!(!text.contains(SECRET_VALUE), "{peer}: {text}");
        }
        let (status, _, text) = ask(&st, rec.uid, None, "anthropic").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "no peer identity: {text}");
        assert!(!text.contains(SECRET_VALUE));
        let (status, _, text) = ask(&st, rec.uid, Some(&gateway_peer()), "anthropic").await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the authorizer is answered: {status}"
        );
        assert!(text.contains(SECRET_VALUE), "and with the credential");
    }

    /// `GET /v1/gateway/claims/{uid}` as `peer`.
    async fn ask_egress(
        st: &Shared,
        uid: impl std::fmt::Display,
        peer: &str,
    ) -> (StatusCode, serde_json::Value, String) {
        call(
            st,
            "GET",
            &format!("/v1/gateway/claims/{uid}"),
            Some(peer),
            serde_json::Value::Null,
        )
        .await
    }

    #[tokio::test]
    async fn the_plain_gateway_identity_is_refused_on_both_gateway_routes_before_the_claim_is_looked_up()
     {
        // ADR-0053 decision 3: a listener's name gets the one answer whatever it asks about, a
        // live claim, a UID the store never held, or text that is no UID at all. The
        // authorizer's answers to the same three differ (200, 404, 400), so the refusal comes
        // before the claim is parsed or read and says nothing about whether it exists.
        let st: Shared = Arc::new(placed_state());
        let live = stored(&st, claim(&["anthropic"], None)).await;
        let plain = naming().gateway_id();
        let authorizer = gateway_peer();
        let asked = [
            (live.uid.to_string(), StatusCode::OK),
            (Uuid::new_v4().to_string(), StatusCode::NOT_FOUND),
            ("not-a-uuid".to_owned(), StatusCode::BAD_REQUEST),
        ];
        for (uid, as_authorizer) in &asked {
            let (status, body, text) = ask(&st, uid, Some(&plain), "anthropic").await;
            assert_eq!(status, StatusCode::FORBIDDEN, "credential, {uid}: {text}");
            assert_eq!(code(&body), "forbidden", "credential, {uid}");
            assert!(!text.contains(SECRET_VALUE), "credential, {uid}");
            let (status, body, text) = ask_egress(&st, uid, &plain).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "egress, {uid}: {text}");
            assert_eq!(code(&body), "forbidden", "egress, {uid}");
            let (status, _, _) = ask(&st, uid, Some(&authorizer), "anthropic").await;
            assert_eq!(
                status, *as_authorizer,
                "the authorizer's credential ask, {uid}"
            );
            let (status, _, _) = ask_egress(&st, uid, &authorizer).await;
            assert_eq!(status, *as_authorizer, "the authorizer's egress ask, {uid}");
        }
    }

    #[test]
    fn the_sandbox_listener_admits_the_authorizer_and_no_longer_the_plain_gateway_identity() {
        // ADR-0053 decision 3, the outer refusal: the handshake's list.
        let n = naming();
        let id = |s: &str| mediatore_tls::SpiffeId::new(s).expect("a SPIFFE ID");
        let strict = sandbox_authorizer(n.clone(), false);
        assert!(strict(&id(&n.gateway_authorizer_id())));
        assert!(strict(&id(&n.node_id("ekhash"))));
        assert!(strict(&id(&n.claim_id(Uuid::new_v4()))));
        for stranger in [
            n.gateway_id(),
            n.broker_id(),
            format!("spiffe://{TD}/gateway/authorizer/extra"),
            format!("spiffe://{TD}/gateway/extra"),
            "spiffe://other.test/gateway/authorizer".to_owned(),
        ] {
            assert!(!strict(&id(&stranger)), "{stranger}");
        }
        // Decision 7: the switch widens the list by the listeners' ID and by nothing else.
        let lenient = sandbox_authorizer(n.clone(), true);
        assert!(lenient(&id(&n.gateway_id())));
        assert!(lenient(&id(&n.gateway_authorizer_id())));
        assert!(!lenient(&id(&n.broker_id())));
        assert!(!lenient(&id(&format!("spiffe://{TD}/gateway/extra"))));
    }

    #[tokio::test]
    async fn the_transition_switch_is_off_by_default_and_when_on_admits_the_plain_identity_with_a_warning()
     {
        capture_logs();
        assert!(
            !placed_state().accept_plain_gateway_identity,
            "off unless a test turns it on"
        );
        let mut st = placed_state();
        st.accept_plain_gateway_identity = true;
        let st: Shared = Arc::new(st);
        let rec = stored(&st, claim(&["anthropic"], None)).await;
        let plain = naming().gateway_id();
        let (status, _, text) = ask_egress(&st, rec.uid, &plain).await;
        assert_eq!(status, StatusCode::OK, "egress under the switch: {text}");
        let (status, _, _) = ask(&st, rec.uid, Some(&plain), "anthropic").await;
        assert_eq!(status, StatusCode::OK, "credential under the switch");
        let logs = captured();
        let warned: Vec<&str> = logs
            .lines()
            .filter(|l| l.contains("WARN") && l.contains("accept_plain_gateway_identity"))
            .collect();
        assert_eq!(warned.len(), 2, "one warning per ask: {logs}");
        let uid_text = rec.uid.to_string();
        for (line, route) in warned.iter().zip([
            "GET /v1/gateway/claims/{uid}",
            "POST /v1/gateway/claims/{uid}/credential",
        ]) {
            for needle in [plain.as_str(), route, uid_text.as_str()] {
                assert!(line.contains(needle), "{needle} in {line}");
            }
        }
        assert!(!logs.contains(SECRET_VALUE), "no credential in a log line");
        // The authorizer's own asks are not warnings, and the switch admits nothing else.
        capture_logs();
        let (status, _, _) = ask_egress(&st, rec.uid, &gateway_peer()).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            !captured().contains("accept_plain_gateway_identity"),
            "the authorizer's ask is no warning"
        );
        let (status, _, _) = ask_egress(&st, rec.uid, &naming().claim_id(rec.uid)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "a claim is still no gateway");
    }

    #[tokio::test]
    async fn the_audit_line_names_the_peer_that_asked() {
        capture_logs();
        let st: Shared = Arc::new(placed_state());
        let rec = stored(&st, claim(&["anthropic"], None)).await;
        let gw = gateway_peer();
        let (status, _, _) = ask(&st, rec.uid, Some(&gw), "anthropic").await;
        assert_eq!(status, StatusCode::OK);
        let logs = captured();
        let line = logs
            .lines()
            .find(|l| l.contains("gateway credential issued") && l.contains(&rec.uid.to_string()))
            .unwrap_or_else(|| panic!("no audit line in: {logs}"));
        assert!(line.contains(&gw), "the peer's SPIFFE ID in {line}");
        assert!(!logs.contains(SECRET_VALUE), "and never the credential");
    }

    #[tokio::test]
    async fn a_claim_that_is_unknown_revoked_expired_or_unbound_is_404_and_a_bad_uid_is_400() {
        let st: Shared = Arc::new(placed_state());
        let gw = gateway_peer();
        let (status, body, _) = ask(&st, Uuid::new_v4(), Some(&gw), "anthropic").await;
        assert_eq!(
            (status, code(&body)),
            (StatusCode::NOT_FOUND, "not_found"),
            "unknown"
        );
        let mut revoked = claim(&["anthropic"], None);
        revoked.revoked_at = Some(Timestamp::now());
        let revoked = stored(&st, revoked).await;
        let mut expired = claim(&["anthropic"], None);
        expired.expires_at = Some(Timestamp::now() - SignedDuration::from_secs(1));
        let expired = stored(&st, expired).await;
        let mut unbound = claim(&["anthropic"], None);
        unbound.expires_at = None;
        let unbound = stored(&st, unbound).await;
        for (what, uid) in [
            ("revoked", revoked.uid),
            ("expired", expired.uid),
            ("unbound", unbound.uid),
        ] {
            let (status, _, text) = ask(&st, uid, Some(&gw), "anthropic").await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{what}: {text}");
            assert!(!text.contains(SECRET_VALUE), "{what}");
        }
        let (status, body, _) = ask(&st, "not-a-uuid", Some(&gw), "anthropic").await;
        assert_eq!(
            (status, code(&body)),
            (StatusCode::BAD_REQUEST, "invalid_claim_uid")
        );
    }

    #[tokio::test]
    async fn an_audience_the_claim_does_not_name_is_unknown_audience() {
        let st: Shared = Arc::new(placed_state());
        let rec = stored(&st, claim(&["grafana"], None)).await;
        let (status, body, text) = ask(&st, rec.uid, Some(&gateway_peer()), "anthropic").await;
        assert_eq!(
            (status, code(&body)),
            (StatusCode::BAD_REQUEST, "unknown_audience")
        );
        assert!(!text.contains(SECRET_VALUE));
    }

    #[tokio::test]
    async fn an_audience_placed_in_the_proxy_is_not_placed_at_the_gateway() {
        let st: Shared = Arc::new(placed_state());
        let rec = stored(&st, claim(&["grafana", "grafana-sts"], None)).await;
        for a in ["grafana", "grafana-sts"] {
            let (status, body, _) = ask(&st, rec.uid, Some(&gateway_peer()), a).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{a}");
            assert_eq!(code(&body), error_code::NOT_PLACED_AT_GATEWAY, "{a}");
        }
    }

    // ----- a credential never outlives its claim, an STS token never its audience's maximum -----

    /// A claim for `audiences` with a minute left, stored, and when it ends.
    async fn claim_with_a_minute_left(st: &Shared, audiences: &[&str]) -> (ClaimRecord, Timestamp) {
        let dies_at = Timestamp::now() + SignedDuration::from_secs(60);
        let mut rec = claim(audiences, None);
        rec.expires_at = Some(dies_at);
        (stored(st, rec).await, dies_at)
    }

    /// The `expires_at` of a `200` from `POST /v1/token`; the body is never printed.
    async fn issued_until(st: &Shared, rec: &ClaimRecord, audience: &str) -> Timestamp {
        let (status, body, _) = token_for(st, rec, audience).await;
        assert_eq!(status, StatusCode::OK, "{audience}");
        let answer: TokenResponse = serde_json::from_value(body).expect("a token response");
        answer.expires_at
    }

    #[tokio::test]
    async fn an_sts_token_expires_no_later_than_a_claim_with_a_minute_left() {
        let st: Shared = Arc::new(placed_state());
        let (rec, dies_at) = claim_with_a_minute_left(&st, &["grafana-sts", "sts-gw"]).await;
        let expires_at = issued_until(&st, &rec, "grafana-sts").await;
        assert!(expires_at <= dies_at, "the token outlives its claim");
        assert!(
            expires_at > Timestamp::now(),
            "and it is still a usable one"
        );
        // The same minting code behind the gateway's route.
        let (status, body, _) = ask(&st, rec.uid, Some(&gateway_peer()), "sts-gw").await;
        assert_eq!(status, StatusCode::OK);
        let c: GatewayCredential = serde_json::from_value(body).unwrap();
        assert!(c.expires_at <= dies_at, "the credential outlives its claim");
    }

    #[tokio::test]
    async fn an_operator_secrets_expiry_is_clamped_to_the_claims() {
        let st: Shared = Arc::new(placed_state());
        let (rec, dies_at) = claim_with_a_minute_left(&st, &["grafana", "anthropic"]).await;
        assert!(issued_until(&st, &rec, "grafana").await <= dies_at);
        let (status, body, _) = ask(&st, rec.uid, Some(&gateway_peer()), "anthropic").await;
        assert_eq!(status, StatusCode::OK);
        let c: GatewayCredential = serde_json::from_value(body).unwrap();
        assert!(c.expires_at <= dies_at, "the credential outlives its claim");
        // A claim with longer left than the audience's `max_ttl` is told `max_ttl`, as before.
        let mut long = claim(&["grafana"], None);
        long.expires_at = Some(Timestamp::now() + SignedDuration::from_hours(1));
        let long = stored(&st, long).await;
        let expires_at = issued_until(&st, &long, "grafana").await;
        assert!(expires_at > Timestamp::now() + SignedDuration::from_mins(14));
        assert!(expires_at <= Timestamp::now() + SignedDuration::from_mins(15));
    }

    #[tokio::test]
    async fn an_audiences_own_maximum_bounds_its_sts_token_beside_a_longer_one() {
        let mut st = placed_state();
        st.audiences.push("other-sts".into());
        st.sts = st
            .sts
            .map(|sts| sts.with_audience_max_ttl("grafana-sts", SignedDuration::from_mins(2)));
        let st: Shared = Arc::new(st);
        let rec = stored(&st, claim(&["grafana-sts", "other-sts"], None)).await;
        let short = issued_until(&st, &rec, "grafana-sts").await;
        assert!(short <= Timestamp::now() + SignedDuration::from_mins(2));
        let other = issued_until(&st, &rec, "other-sts").await;
        assert!(
            other > Timestamp::now() + SignedDuration::from_mins(10),
            "the other audience keeps the longer lifetime"
        );
        assert!(other <= Timestamp::now() + SignedDuration::from_mins(15));
    }

    // ----- what an unauthenticated caller is told -----

    /// `GET /v1/claims/sandbox-x` on the user router with `bearer`.
    async fn as_user(st: &Shared, bearer: &str) -> (StatusCode, serde_json::Value, String) {
        let req = Request::builder()
            .method("GET")
            .uri("/v1/claims/sandbox-x")
            .header("authorization", format!("Bearer {bearer}"))
            .body(Body::empty())
            .unwrap();
        let resp = user_router(st.clone()).oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        (
            status,
            serde_json::from_str(&text).unwrap_or(serde_json::Value::Null),
            text,
        )
    }

    #[tokio::test]
    async fn an_issuer_outage_at_login_is_503_and_says_nothing_of_the_issuer() {
        // An issuer on a port nothing listens on: its discovery fetch is refused at once.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let down = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let mut issuer = subject_issuer();
        issuer.url.clone_from(&down);
        let mut st = base_state();
        st.validator = Validator::new(vec![issuer]);
        let st: Shared = Arc::new(st);
        let bearer = mediatore_testkit::mint(
            &down,
            serde_json::json!({ "aud": "mediatore", "preferred_username": "octocat" }),
        );
        let (status, body, text) = as_user(&st, &bearer).await;
        assert_eq!(
            (status, code(&body)),
            (StatusCode::SERVICE_UNAVAILABLE, "upstream_unavailable")
        );
        assert_eq!(body["detail"], "the identity provider did not answer");
        for internal in [
            "127.0.0.1",
            "openid-configuration",
            "discovery",
            "error sending",
        ] {
            assert!(
                !text.contains(internal),
                "the answer carries the validator's own error text"
            );
        }
    }

    #[tokio::test]
    async fn a_bearer_that_does_not_validate_is_401_with_fixed_text() {
        let st: Shared = Arc::new(base_state());
        let elsewhere = mediatore_testkit::mint(
            "https://elsewhere.example",
            serde_json::json!({ "aud": "mediatore", "preferred_username": "octocat" }),
        );
        for bearer in ["not-a-jwt", "a.b.c", elsewhere.as_str()] {
            let (status, body, _) = as_user(&st, bearer).await;
            assert_eq!(
                (status, code(&body)),
                (StatusCode::UNAUTHORIZED, "unauthorized")
            );
            assert_eq!(body["detail"], "invalid token");
        }
    }

    // ----- the node's writes to its claim are rate limited -----

    #[tokio::test]
    async fn a_burst_of_reports_from_a_node_is_rate_limited_per_claim_and_its_exit_is_not() {
        let mut st = placed_state();
        st.limiter = Limiter::new(2);
        let st: Shared = Arc::new(st);
        let node = st.naming.node_id("ek1");
        st.store
            .put_node(NodeRecord {
                ek_hash: "ek1".into(),
                node_id: node.clone(),
                dmi_uuid: Uuid::new_v4(),
                hostname: "pool-1".into(),
                provider: None,
                banned: false,
                registered_at: Timestamp::now(),
            })
            .await
            .unwrap();
        let rec = stored(&st, claim(&["grafana"], Some(node.clone()))).await;
        let report = serde_json::to_value(GuestReport {
            image_digest: format!("sha256:{}", "a".repeat(64)),
            sandbox_ruleset_sha256: "b".repeat(64),
            host_table: HostTable::NotLoaded,
        })
        .unwrap();
        for _ in 0..2 {
            let (status, ..) =
                call(&st, "POST", "/v1/me/report", Some(&node), report.clone()).await;
            assert_eq!(status, StatusCode::NO_CONTENT);
        }
        let (status, body, _) = call(&st, "POST", "/v1/me/report", Some(&node), report).await;
        assert_eq!(
            (status, code(&body)),
            (StatusCode::TOO_MANY_REQUESTS, "rate_limited")
        );
        // The exit is sent once and must land: a spent bucket does not refuse it.
        let (status, ..) = call(
            &st,
            "POST",
            "/v1/me/exit",
            Some(&node),
            serde_json::json!({ "code": 0, "restarts": 0 }),
        )
        .await;
        assert_ne!(status, StatusCode::TOO_MANY_REQUESTS);
        let ended = st.store.get_claim(rec.uid).await.expect("the claim");
        assert!(ended.exit.is_some());
    }

    #[tokio::test]
    async fn the_claims_rate_limit_applies_and_a_refused_ask_does_not_spend_it() {
        let mut st = placed_state();
        st.limiter = Limiter::new(2);
        let st: Shared = Arc::new(st);
        let rec = stored(&st, claim(&["anthropic", "grafana"], None)).await;
        let gw = gateway_peer();
        for _ in 0..3 {
            let (status, ..) = ask(&st, rec.uid, Some(&gw), "grafana").await;
            assert_eq!(
                status,
                StatusCode::FORBIDDEN,
                "not placed: refused before the limit"
            );
        }
        assert_eq!(
            ask(&st, rec.uid, Some(&gw), "anthropic").await.0,
            StatusCode::OK
        );
        assert_eq!(
            ask(&st, rec.uid, Some(&gw), "anthropic").await.0,
            StatusCode::OK
        );
        let (status, body, _) = ask(&st, rec.uid, Some(&gw), "anthropic").await;
        assert_eq!(
            (status, code(&body)),
            (StatusCode::TOO_MANY_REQUESTS, "rate_limited")
        );
    }

    #[tokio::test]
    async fn a_delegated_credential_that_expired_or_was_never_delegated_is_refused() {
        let mut st = placed_state();
        let sealer: Arc<dyn Sealer> = Arc::new(mediatore_store::seal::LocalKeySealer::new([7; 32]));
        let mut expired = claim(&["claude"], None);
        let plain = serde_json::to_vec(&DelegationPlain {
            token: Secret(SESSION_TOKEN.into()),
            refresh_token: None,
            expires_at: Some(Timestamp::now() - SignedDuration::from_secs(5)),
        })
        .unwrap();
        expired.delegations.insert(
            "claude".into(),
            DelegatedSession {
                envelope: sealer
                    .seal_session(Slot::Delegation("claude"), expired.seal_binding(), &plain)
                    .await
                    .unwrap(),
                expires_at: Some(Timestamp::now() - SignedDuration::from_secs(5)),
            },
        );
        st.sealer = Some(sealer);
        let st: Shared = Arc::new(st);
        let expired = stored(&st, expired).await;
        let none = stored(&st, claim(&["claude"], None)).await;
        let gw = gateway_peer();
        for (what, uid) in [("expired", expired.uid), ("never delegated", none.uid)] {
            let (status, body, text) = ask(&st, uid, Some(&gw), "claude").await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{what}: {text}");
            assert_eq!(code(&body), "forbidden", "{what}");
            assert!(!text.contains(SESSION_TOKEN), "{what}");
        }
    }

    #[tokio::test]
    async fn a_delegated_audience_without_a_sealer_fails_closed_501() {
        let st: Shared = Arc::new(placed_state());
        let rec = stored(&st, claim(&["claude"], None)).await;
        let (status, ..) = ask(&st, rec.uid, Some(&gateway_peer()), "claude").await;
        assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
    }

    // ----- the policy bundle under `policy.egress: enforce` -----

    /// An admitted bundle for the conformance policy listing exactly `audiences`, and the policy's uid.
    async fn bundle_for(
        audiences: &[&str],
        mode: mediatore_claims::policy::EgressMode,
    ) -> (PolicyEgress, String) {
        let now = Timestamp::now();
        let base = mediatore_testkit::policy::fresh_bundle(now, 1).payload;
        let mut content = base.content.clone();
        content
            .audiences
            .retain(|a| audiences.contains(&a.name.as_str()));
        let signed = mediatore_testkit::policy::signed_bundle(now, 2, content);
        let uid = signed.payload.content.policy.uid.clone();
        let namespace = signed.payload.content.policy.namespace.clone();
        let reflector = mediatore_claims::policy::BundleReflector::new(
            mediatore_store::MemoryStore::shared(),
            signed.keys,
            vec![namespace.clone()],
        );
        let cm = mediatore_testkit::policy::bundle_configmap(
            &namespace,
            "agent-bundle",
            &signed.envelope,
        );
        let outcome = reflector.applied_at(&cm, now).await;
        assert!(
            matches!(outcome, mediatore_claims::policy::Outcome::Admitted { .. }),
            "{outcome:?}"
        );
        (
            PolicyEgress {
                bundles: reflector.cache(),
                mode,
                audiences: mediatore_claims::policy::EgressMode::Shadow,
            },
            uid,
        )
    }

    /// `internal-git` is the audience the conformance bundle lists; make it a placed secret one.
    fn placed_internal_git(mut st: AppState) -> AppState {
        st.audiences.push("internal-git".into());
        st.egress.insert(
            "internal-git".into(),
            vec!["git.example:443".parse().unwrap()],
        );
        st.secrets.insert(
            "internal-git".into(),
            AudienceSecret {
                value: Secret(SECRET_VALUE.into()),
                header: "x-api-key".into(),
                extra_headers: vec![],
                ttl: SignedDuration::from_mins(5),
            },
        );
        st.inject.insert(
            "internal-git".into(),
            vec![inject_route("internal-git", "git.example", "x-api-key")],
        );
        st
    }

    #[tokio::test]
    async fn under_enforce_the_claims_bundle_must_admit_the_audience() {
        use mediatore_claims::policy::EgressMode;
        let gw = gateway_peer();
        // The bundle lists the audience: allowed.
        let (pe, uid) = bundle_for(&["internal-git"], EgressMode::Enforce).await;
        let mut st = placed_internal_git(placed_state());
        st.policy_egress = Some(pe);
        let st: Shared = Arc::new(st);
        let mut rec = claim(&["internal-git"], None);
        rec.policy_uid = Some(uid.clone());
        let rec = stored(&st, rec).await;
        assert_eq!(
            ask(&st, rec.uid, Some(&gw), "internal-git").await.0,
            StatusCode::OK,
            "admitted by the bundle"
        );
        // A claim naming no policy, under enforce: refused, fail closed.
        let nopolicy = stored(&st, claim(&["internal-git"], None)).await;
        let (status, body, text) = ask(&st, nopolicy.uid, Some(&gw), "internal-git").await;
        assert_eq!((status, code(&body)), (StatusCode::FORBIDDEN, "forbidden"));
        assert!(!text.contains(SECRET_VALUE));
        // A policy whose bundle does not list the audience: refused.
        let (pe, uid) = bundle_for(&[], EgressMode::Enforce).await;
        let mut st = placed_internal_git(placed_state());
        st.policy_egress = Some(pe);
        let st: Shared = Arc::new(st);
        let mut rec = claim(&["internal-git"], None);
        rec.policy_uid = Some(uid);
        let rec = stored(&st, rec).await;
        let (status, body, text) = ask(&st, rec.uid, Some(&gw), "internal-git").await;
        assert_eq!((status, code(&body)), (StatusCode::FORBIDDEN, "forbidden"));
        assert!(!text.contains(SECRET_VALUE));
        // A policy uid with no cached bundle (expired, deleted): refused.
        let mut gone = claim(&["internal-git"], None);
        gone.policy_uid = Some("no-such-policy-uid".into());
        let gone = stored(&st, gone).await;
        assert_eq!(
            ask(&st, gone.uid, Some(&gw), "internal-git").await.0,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn in_shadow_or_without_a_policy_section_the_bundle_refuses_nothing() {
        use mediatore_claims::policy::EgressMode;
        let gw = gateway_peer();
        let (pe, uid) = bundle_for(&[], EgressMode::Shadow).await;
        let mut st = placed_internal_git(placed_state());
        st.policy_egress = Some(pe);
        let st: Shared = Arc::new(st);
        let mut rec = claim(&["internal-git"], None);
        rec.policy_uid = Some(uid);
        let rec = stored(&st, rec).await;
        assert_eq!(
            ask(&st, rec.uid, Some(&gw), "internal-git").await.0,
            StatusCode::OK,
            "shadow logs the gap and refuses nothing"
        );
        let st: Shared = Arc::new(placed_internal_git(placed_state()));
        let rec = stored(&st, claim(&["internal-git"], None)).await;
        assert_eq!(
            ask(&st, rec.uid, Some(&gw), "internal-git").await.0,
            StatusCode::OK,
            "no policy section, nothing to compare"
        );
    }

    // ----- POST /v1/token for a placed audience -----

    #[tokio::test]
    async fn the_pool_vm_cannot_get_a_placed_audiences_credential_from_token_but_a_proxy_audience_is_unchanged()
     {
        let mut st = placed_state();
        st.limiter = Limiter::new(1);
        let st: Shared = Arc::new(st);
        let rec = stored(
            &st,
            claim(&["anthropic", "claude", "sts-gw", "grafana"], None),
        )
        .await;
        let claim_peer = naming().claim_id(rec.uid);
        for a in ["anthropic", "claude", "sts-gw"] {
            let (status, body, text) = call(
                &st,
                "POST",
                "/v1/token",
                Some(&claim_peer),
                serde_json::json!({ "audience": a }),
            )
            .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{a}: {text}");
            assert_eq!(code(&body), error_code::PLACED_AT_GATEWAY, "{a}");
            assert!(!text.contains(SECRET_VALUE), "{a}");
        }
        // The three refusals spent no token: the one-a-minute bucket is still full for a proxy audience.
        let (status, body, _) = call(
            &st,
            "POST",
            "/v1/token",
            Some(&claim_peer),
            serde_json::json!({ "audience": "grafana" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["access_token"], "grafana-key");
    }

    // ----- a claim whose issuer or audience left the configuration -----

    /// `POST /v1/token` as the claim's own identity.
    async fn token_for(
        st: &Shared,
        rec: &ClaimRecord,
        audience: &str,
    ) -> (StatusCode, serde_json::Value, String) {
        call(
            st,
            "POST",
            "/v1/token",
            Some(&naming().claim_id(rec.uid)),
            serde_json::json!({ "audience": audience }),
        )
        .await
    }

    #[tokio::test]
    async fn a_claim_whose_issuer_left_the_configuration_gets_no_credential_from_any_backend() {
        // The claim was made while its issuer was configured, and issues.
        let configured: Shared = Arc::new(placed_state());
        let rec = stored(
            &configured,
            claim(&["anthropic", "grafana", "grafana-sts"], None),
        )
        .await;
        for a in ["grafana", "grafana-sts"] {
            assert_eq!(
                token_for(&configured, &rec, a).await.0,
                StatusCode::OK,
                "{a}"
            );
        }
        // The operator removes the issuer: the same record, in the same store, gets nothing.
        let mut st = placed_state();
        st.store = configured.store.clone();
        st.validator = Validator::new(vec![]);
        let st: Shared = Arc::new(st);
        // The operator's secret, the STS, and the secret the gateway places.
        for a in ["grafana", "grafana-sts"] {
            let (status, body, text) = token_for(&st, &rec, a).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{a}: {body}");
            assert_eq!(code(&body), "forbidden", "{a}");
            assert!(body.get("access_token").is_none(), "{a}");
            assert!(!text.contains("grafana-key"), "{a}");
        }
        let (status, body, text) = ask(&st, rec.uid, Some(&gateway_peer()), "anthropic").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(code(&body), "forbidden");
        assert!(!text.contains(SECRET_VALUE));
    }

    #[tokio::test]
    async fn a_claim_naming_an_audience_that_left_the_configuration_gets_no_credential() {
        let configured: Shared = Arc::new(placed_state());
        let rec = stored(
            &configured,
            claim(&["anthropic", "grafana", "grafana-sts"], None),
        )
        .await;
        // The operator removes three audiences; the record still names them. `grafana` leaves
        // with its secret, so what is left to serve it is the STS, which must not mint;
        // `anthropic` leaves the list alone, so the secret is still at hand and must not be
        // given.
        let mut st = placed_state();
        st.store = configured.store.clone();
        st.audiences.retain(|a| a == "claude" || a == "sts-gw");
        st.secrets.remove("grafana");
        let st: Shared = Arc::new(st);
        for a in ["grafana", "grafana-sts"] {
            let (status, body, text) = token_for(&st, &rec, a).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{a}: {body}");
            assert_eq!(code(&body), "forbidden", "{a}");
            assert!(body.get("access_token").is_none(), "{a}");
            assert!(!text.contains("grafana-key"), "{a}");
        }
        let (status, body, text) = ask(&st, rec.uid, Some(&gateway_peer()), "anthropic").await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(code(&body), "forbidden");
        assert!(!text.contains(SECRET_VALUE));
    }

    // ----- ADR-0053: an audience scoped to namespaces, each with its own rules -----

    fn rule(method: &str, path: &str) -> EndpointRule {
        EndpointRule {
            method: method.into(),
            path: path.into(),
        }
    }

    /// `placed_state()` with `anthropic` scoped to `team-a` and `team-b`, each with its own rules.
    fn scoped_state() -> AppState {
        let mut st = placed_state();
        st.scopes.insert(
            "anthropic".into(),
            [
                ("team-a".to_owned(), vec![rule("GET", "/a/**")]),
                ("team-b".to_owned(), vec![rule("GET", "/b/**")]),
            ]
            .into_iter()
            .collect(),
        );
        st
    }

    fn claim_in(namespace: &str, audiences: &[&str], node: Option<String>) -> ClaimRecord {
        let mut c = claim(audiences, node);
        c.namespace = namespace.into();
        c
    }

    async fn gateway_answer(st: &Shared, uid: Uuid) -> mediatore_proto::ClaimEgress {
        let (status, body, text) = call(
            st,
            "GET",
            &format!("/v1/gateway/claims/{uid}"),
            Some(&gateway_peer()),
            serde_json::Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{text}");
        serde_json::from_value(body).unwrap()
    }

    #[tokio::test]
    async fn the_gateways_claim_answer_carries_the_rules_of_the_claims_namespace() {
        let st: Shared = Arc::new(scoped_state());
        let a = stored(&st, claim_in("team-a", &["anthropic"], None)).await;
        let b = stored(&st, claim_in("team-b", &["anthropic"], None)).await;
        let a = gateway_answer(&st, a.uid).await;
        let b = gateway_answer(&st, b.uid).await;
        assert_eq!(a.inject.len(), 1);
        assert_eq!(a.inject[0].rules, vec![rule("GET", "/a/**")]);
        assert_eq!(b.inject[0].rules, vec![rule("GET", "/b/**")]);
    }

    #[tokio::test]
    async fn a_claim_in_a_namespace_the_audience_does_not_list_gets_nothing_of_it() {
        // ADR-0053 decision 4: a claim that was bound before the entry was removed (or whose record names it
        // some other way) loses the audience at the gateway and at the mint, and its host leaves the allowlist.
        let st: Shared = Arc::new(scoped_state());
        let rec = stored(&st, claim_in("team-c", &["anthropic", "grafana"], None)).await;
        let answer = gateway_answer(&st, rec.uid).await;
        assert!(answer.inject.is_empty(), "no placed route: {answer:?}");
        let hosts: Vec<&str> = answer.egress.iter().map(|e| e.host.as_str()).collect();
        assert_eq!(
            hosts,
            ["grafana.example"],
            "only the unscoped audience's host"
        );
        let (status, body, text) = ask(&st, rec.uid, Some(&gateway_peer()), "anthropic").await;
        assert_eq!(
            (status, code(&body)),
            (StatusCode::BAD_REQUEST, "unknown_audience"),
            "the gateway's credential ask is refused: {text}"
        );
        assert!(!text.contains(SECRET_VALUE));
    }

    #[tokio::test]
    async fn a_scoped_audiences_credential_is_still_placed_for_a_listed_namespace() {
        let st: Shared = Arc::new(scoped_state());
        let rec = stored(&st, claim_in("team-b", &["anthropic"], None)).await;
        let (status, body, _) = ask(&st, rec.uid, Some(&gateway_peer()), "anthropic").await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }

    #[tokio::test]
    async fn an_unscoped_audience_is_unchanged_in_every_namespace() {
        let st: Shared = Arc::new(scoped_state());
        for ns in ["sandboxes", "team-a", "team-z"] {
            let rec = stored(&st, claim_in(ns, &["claude"], None)).await;
            let answer = gateway_answer(&st, rec.uid).await;
            assert_eq!(answer.inject.len(), 1, "{ns}");
            assert_eq!(answer.inject[0].audience, "claude", "{ns}");
        }
    }

    #[tokio::test]
    async fn me_routes_carry_the_rules_of_the_claims_namespace() {
        let st = Arc::new(scoped_state());
        let node = st.naming.node_id("ek1");
        st.store
            .put_node(NodeRecord {
                ek_hash: "ek1".into(),
                node_id: node.clone(),
                dmi_uuid: Uuid::new_v4(),
                hostname: "pool-1".into(),
                provider: None,
                banned: false,
                registered_at: Timestamp::now(),
            })
            .await
            .unwrap();
        let st: Shared = st;
        stored(&st, claim_in("team-b", &["anthropic"], Some(node))).await;
        let (status, body, _) = call(
            &st,
            "GET",
            "/v1/me",
            Some(&st.naming.node_id("ek1")),
            serde_json::Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let me: Me = serde_json::from_value(body).unwrap();
        let route = me
            .routes
            .iter()
            .find(|r| r.audience.as_deref() == Some("anthropic"))
            .expect("the anthropic route");
        assert_eq!(route.rules, vec![rule("GET", "/b/**")]);
    }

    // ----- ADR-0053 phase 2: the verified bundle as the source of the grants -----

    fn grant_of(
        rules: &[(&str, &str)],
        endpoints: &[&str],
        ttl: Option<u32>,
    ) -> mediatore_policy::types::AudienceGrant {
        let mut g = mediatore_testkit::policy::fresh_bundle(Timestamp::now(), 1)
            .payload
            .content
            .audiences[0]
            .clone();
        g.name = "internal-git".into();
        g.rules = rules
            .iter()
            .map(|(m, p)| mediatore_policy::types::EndpointRule {
                method: (*m).into(),
                path: (*p).into(),
            })
            .collect();
        g.endpoints = endpoints.iter().map(|e| (*e).to_owned()).collect();
        g.ttl_seconds = ttl;
        g
    }

    /// A reflector holding one bundle (policy uid returned) whose only grant is `grant`, the
    /// first list of its namespace done, and the state `placed_internal_git` under `enforce`
    /// with `ceiling` as the audience's own rules.
    struct Enforced {
        st: AppState,
        uid: String,
        reflector: mediatore_claims::policy::BundleReflector,
        payload: mediatore_policy::BundlePayload,
        namespace: String,
    }

    impl Enforced {
        async fn new(
            ceiling: &[(&str, &str)],
            grant: mediatore_policy::types::AudienceGrant,
            mode: mediatore_claims::policy::EgressMode,
        ) -> Self {
            let now = Timestamp::now();
            let mut content = mediatore_testkit::policy::fresh_bundle(now, 1)
                .payload
                .content;
            content.audiences = vec![grant];
            let signed = mediatore_testkit::policy::signed_bundle(now, 2, content);
            let uid = signed.payload.content.policy.uid.clone();
            let namespace = signed.payload.content.policy.namespace.clone();
            let reflector = mediatore_claims::policy::BundleReflector::new(
                mediatore_store::MemoryStore::shared(),
                signed.keys,
                vec![namespace.clone()],
            );
            reflector.resynced(&namespace, &std::collections::HashSet::new());
            let cm = mediatore_testkit::policy::bundle_configmap(
                &namespace,
                "agent-bundle",
                &signed.envelope,
            );
            let outcome = reflector.applied_at(&cm, now).await;
            assert!(
                matches!(outcome, mediatore_claims::policy::Outcome::Admitted { .. }),
                "{outcome:?}"
            );
            let mut st = placed_internal_git(placed_state());
            st.rules.insert(
                "internal-git".into(),
                ceiling.iter().map(|(m, p)| rule(m, p)).collect(),
            );
            st.policy_egress = Some(PolicyEgress {
                bundles: reflector.cache(),
                mode: mediatore_claims::policy::EgressMode::Shadow,
                audiences: mode,
            });
            Self {
                st,
                uid,
                reflector,
                payload: signed.payload,
                namespace,
            }
        }

        /// The same policy at `version`, `grant` replacing the old one.
        async fn tighten(&self, version: u64, grant: mediatore_policy::types::AudienceGrant) {
            let mut content = self.payload.content.clone();
            content.audiences = vec![grant];
            let now = Timestamp::now();
            let signed = mediatore_testkit::policy::signed_bundle(now, version, content);
            let cm = mediatore_testkit::policy::bundle_configmap(
                &self.namespace,
                "agent-bundle",
                &signed.envelope,
            );
            let outcome = self.reflector.applied_at(&cm, now).await;
            assert!(
                matches!(outcome, mediatore_claims::policy::Outcome::Admitted { .. }),
                "{outcome:?}"
            );
        }
    }

    fn under(uid: &str) -> ClaimRecord {
        let mut rec = claim(&["internal-git"], None);
        rec.policy_uid = Some(uid.to_owned());
        rec
    }

    #[tokio::test]
    async fn the_effective_rules_are_the_bundles_inside_the_ceiling_on_the_gateways_answer() {
        use mediatore_claims::policy::EgressMode::Enforce;
        let grant = grant_of(
            &[("GET", "/repos/team-a/**"), ("GET", "/other/**")],
            &["git.example:443"],
            None,
        );
        let e = Enforced::new(&[("GET", "/repos/**")], grant, Enforce).await;
        let uid = e.uid.clone();
        let st: Shared = Arc::new(e.st);
        let rec = stored(&st, under(&uid)).await;
        let answer = gateway_answer(&st, rec.uid).await;
        assert_eq!(answer.inject.len(), 1);
        assert_eq!(
            answer.inject[0].rules,
            vec![rule("GET", "/repos/team-a/**")],
            "the rule the ceiling does not cover is dropped"
        );
    }

    #[tokio::test]
    async fn a_grant_none_of_whose_rules_survive_the_ceiling_leaves_the_audience_unusable() {
        use mediatore_claims::policy::EgressMode::Enforce;
        let grant = grant_of(&[("GET", "/other/**")], &["git.example:443"], None);
        let e = Enforced::new(&[("GET", "/repos/**")], grant, Enforce).await;
        let uid = e.uid.clone();
        let st: Shared = Arc::new(e.st);
        let rec = stored(&st, under(&uid)).await;
        let answer = gateway_answer(&st, rec.uid).await;
        assert!(
            answer.inject.is_empty(),
            "never an empty (every path) rule list: {answer:?}"
        );
        let (status, body, _) = ask(&st, rec.uid, Some(&gateway_peer()), "internal-git").await;
        assert_eq!(
            (status, code(&body)),
            (StatusCode::BAD_REQUEST, "unknown_audience")
        );
    }

    #[tokio::test]
    async fn an_endpoint_the_grant_omits_is_not_routed_and_not_in_the_allowlist() {
        use mediatore_claims::policy::EgressMode::Enforce;
        let grant = grant_of(&[("GET", "/repos/**")], &["elsewhere.example:443"], None);
        let e = Enforced::new(&[], grant, Enforce).await;
        let uid = e.uid.clone();
        let st: Shared = Arc::new(e.st);
        let rec = stored(&st, under(&uid)).await;
        let answer = gateway_answer(&st, rec.uid).await;
        assert!(answer.inject.is_empty(), "{answer:?}");
        assert!(answer.egress.is_empty(), "{answer:?}");
    }

    #[tokio::test]
    async fn a_credential_lives_at_most_the_grants_ttl() {
        use mediatore_claims::policy::EgressMode::Enforce;
        let grant = grant_of(&[("GET", "/repos/**")], &["git.example:443"], Some(60));
        let e = Enforced::new(&[], grant, Enforce).await;
        let uid = e.uid.clone();
        let st: Shared = Arc::new(e.st);
        let rec = stored(&st, under(&uid)).await;
        let (status, body, _) = ask(&st, rec.uid, Some(&gateway_peer()), "internal-git").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let c: GatewayCredential = serde_json::from_value(body).unwrap();
        assert!(
            c.expires_at <= Timestamp::now() + SignedDuration::from_secs(61),
            "the 5 minute secret ttl is cut to the grant's 60 seconds: {}",
            c.expires_at
        );
    }

    #[tokio::test]
    async fn a_tightened_bundle_narrows_a_running_claims_routes_at_its_next_ask() {
        use mediatore_claims::policy::EgressMode::Enforce;
        let wide = grant_of(&[("GET", "/repos/**")], &["git.example:443"], None);
        let e = Enforced::new(&[], wide, Enforce).await;
        let uid = e.uid.clone();
        e.tighten(
            3,
            grant_of(&[("GET", "/repos/team-a/**")], &["git.example:443"], None),
        )
        .await;
        // The claim was created under version 2; the current bundle is version 3.
        let st: Shared = Arc::new(e.st);
        let rec = stored(&st, under(&uid)).await;
        let answer = gateway_answer(&st, rec.uid).await;
        assert_eq!(
            answer.inject[0].rules,
            vec![rule("GET", "/repos/team-a/**")]
        );
    }

    #[tokio::test]
    async fn an_expired_or_missing_bundle_takes_the_audiences_away() {
        use mediatore_claims::policy::EgressMode::Enforce;
        let grant = grant_of(&[("GET", "/repos/**")], &["git.example:443"], None);
        let e = Enforced::new(&[], grant, Enforce).await;
        let uid = e.uid.clone();
        // Expired: the sweep drops it for every reader at once.
        let dropped = e
            .reflector
            .sweep(Timestamp::now() + SignedDuration::from_hours(2));
        assert_eq!(dropped, 1);
        let st: Shared = Arc::new(e.st);
        let expired = stored(&st, under(&uid)).await;
        assert_eq!(gateway_answer(&st, expired.uid).await.inject, vec![]);
        let (status, body, _) = ask(&st, expired.uid, Some(&gateway_peer()), "internal-git").await;
        assert_eq!(
            (status, code(&body)),
            (StatusCode::BAD_REQUEST, "unknown_audience")
        );
        // No policy on the claim: the same.
        let none = stored(&st, claim(&["internal-git"], None)).await;
        assert_eq!(gateway_answer(&st, none.uid).await.inject, vec![]);
    }

    #[tokio::test]
    async fn shadow_serves_phase_1_whatever_the_bundle_says() {
        use mediatore_claims::policy::EgressMode::Shadow;
        let grant = grant_of(
            &[("GET", "/other/**")],
            &["elsewhere.example:443"],
            Some(60),
        );
        let e = Enforced::new(&[("GET", "/repos/**")], grant, Shadow).await;
        let st: Shared = Arc::new(e.st);
        let rec = stored(&st, claim(&["internal-git"], None)).await; // no policy at all
        let answer = gateway_answer(&st, rec.uid).await;
        assert_eq!(answer.inject.len(), 1, "unchanged: {answer:?}");
        let (status, ..) = ask(&st, rec.uid, Some(&gateway_peer()), "internal-git").await;
        assert_eq!(status, StatusCode::OK);
    }

    // ----- what the guest and the gateway are told -----

    #[tokio::test]
    async fn me_carries_credential_gateway_and_the_inject_port_on_a_placed_audiences_routes_only() {
        let st = Arc::new(placed_state());
        let node = st.naming.node_id("ek1");
        st.store
            .put_node(NodeRecord {
                ek_hash: "ek1".into(),
                node_id: node.clone(),
                dmi_uuid: Uuid::new_v4(),
                hostname: "pool-1".into(),
                provider: None,
                banned: false,
                registered_at: Timestamp::now(),
            })
            .await
            .unwrap();
        let st: Shared = st;
        let rec = stored(&st, claim(&["anthropic", "grafana"], Some(node))).await;
        let (status, body, _) = call(
            &st,
            "GET",
            "/v1/me",
            Some(&st.naming.node_id("ek1")),
            serde_json::Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let me: Me = serde_json::from_value(body).unwrap();
        assert_eq!(me.claim_uid, rec.uid);
        let anthropic = me
            .routes
            .iter()
            .find(|r| r.audience.as_deref() == Some("anthropic"))
            .expect("the anthropic route");
        assert_eq!(anthropic.credential, Credential::Gateway);
        assert!(anthropic.placed_at_gateway());
        assert_eq!(anthropic.inject_port, Some(3133));
        let grafana = me
            .routes
            .iter()
            .find(|r| r.audience.as_deref() == Some("grafana"))
            .expect("the grafana route");
        assert_eq!(
            grafana.credential,
            Credential::Token,
            "placed in the proxy, as before"
        );
        assert_eq!(grafana.inject_port, None);
    }

    #[tokio::test]
    async fn the_gateways_claim_answer_lists_the_inject_routes_of_the_claims_placed_audiences_only()
    {
        let st: Shared = Arc::new(placed_state());
        let both = stored(&st, claim(&["claude", "anthropic", "grafana"], None)).await;
        let none = stored(&st, claim(&["grafana"], None)).await;
        let (status, body, _) = call(
            &st,
            "GET",
            &format!("/v1/gateway/claims/{}", both.uid),
            Some(&gateway_peer()),
            serde_json::Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let egress: mediatore_proto::ClaimEgress = serde_json::from_value(body).unwrap();
        let audiences: Vec<&str> = egress.inject.iter().map(|r| r.audience.as_str()).collect();
        assert_eq!(
            audiences,
            ["anthropic", "claude"],
            "sorted, only the claim's placed audiences"
        );
        let anthropic = &egress.inject[0];
        assert_eq!(anthropic.endpoint.host, "api.anthropic.example");
        assert_eq!(anthropic.header, "x-api-key");
        assert_eq!(
            anthropic.extra_headers,
            vec![pair("anthropic-version", "2023-06-01")]
        );
        assert!(!anthropic.rules.is_empty(), "a placed route carries rules");
        let (_, body, text) = call(
            &st,
            "GET",
            &format!("/v1/gateway/claims/{}", none.uid),
            Some(&gateway_peer()),
            serde_json::Value::Null,
        )
        .await;
        assert!(
            body.get("inject").is_none(),
            "absent on the wire when empty: {text}"
        );
        assert!(
            !text.contains(SECRET_VALUE),
            "the answer carries no credential"
        );
    }

    #[tokio::test]
    async fn a_placed_audiences_host_is_not_in_the_tunnel_lists_only_the_injecting_path_reaches_it()
    {
        // ADR-0040: a host bound to the rule-enforcing inject path must not also be reachable through a CONNECT
        // tunnel the claim's SVID could open, or the rules and the placement are decorative for that host.
        let st: Shared = Arc::new(placed_state());
        let rec = stored(&st, claim(&["anthropic", "grafana"], None)).await;
        let (status, body, _) = call(
            &st,
            "GET",
            &format!("/v1/gateway/claims/{}", rec.uid),
            Some(&gateway_peer()),
            serde_json::Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let egress: mediatore_proto::ClaimEgress = serde_json::from_value(body).unwrap();
        let hosts: Vec<&str> = egress.egress.iter().map(|e| e.host.as_str()).collect();
        assert!(
            !hosts.contains(&"api.anthropic.example"),
            "the placed host is not tunnelable: {hosts:?}"
        );
        assert!(
            hosts.contains(&"grafana.example"),
            "a proxy-placed audience keeps its tunnel entry: {hosts:?}"
        );
        assert_eq!(
            egress
                .inject
                .iter()
                .map(|r| r.audience.as_str())
                .collect::<Vec<_>>(),
            ["anthropic"],
            "and the placed host is reachable through its inject route"
        );
    }

    // ----- the audit line, and only the audit line -----

    // One process-wide subscriber, installed once, writing into a buffer per thread: a scoped
    // `set_default` is not reliable under the parallel test runner, because tracing caches each
    // callsite's interest and another test's first event, with no subscriber, can disable it. Each
    // `#[tokio::test]` runs on its own thread, so a thread-local buffer isolates the tests.
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

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for ThreadLogs {
        type Writer = ThreadLogs;
        fn make_writer(&'a self) -> ThreadLogs {
            ThreadLogs
        }
    }

    /// Start capturing this thread's log lines from nothing.
    fn capture_logs() {
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
    }

    /// What this thread has logged since [`capture_logs`].
    fn captured() -> String {
        LOGS.with(|l| String::from_utf8_lossy(&l.borrow()).into_owned())
    }

    #[tokio::test]
    async fn each_issue_is_one_audit_line_with_claim_audience_subject_backend_and_expiry_and_never_the_credential()
     {
        capture_logs();
        let mut st = placed_state();
        let sealer: Arc<dyn Sealer> = Arc::new(mediatore_store::seal::LocalKeySealer::new([7; 32]));
        let mut delegated = claim(&["claude"], None);
        let plain = serde_json::to_vec(&DelegationPlain {
            token: Secret(SESSION_TOKEN.into()),
            refresh_token: None,
            expires_at: Some(Timestamp::now() + SignedDuration::from_hours(1)),
        })
        .unwrap();
        delegated.delegations.insert(
            "claude".into(),
            DelegatedSession {
                envelope: sealer
                    .seal_session(Slot::Delegation("claude"), delegated.seal_binding(), &plain)
                    .await
                    .unwrap(),
                expires_at: Some(Timestamp::now() + SignedDuration::from_hours(1)),
            },
        );
        st.sealer = Some(sealer);
        let st: Shared = Arc::new(st);
        let secret = stored(&st, claim(&["anthropic"], None)).await;
        let minted = stored(&st, claim(&["sts-gw"], None)).await;
        let delegated = stored(&st, delegated).await;
        let gw = gateway_peer();
        let mut jwt = String::new();
        for (rec, audience, backend) in [
            (&secret, "anthropic", "secret"),
            (&minted, "sts-gw", "sts"),
            (&delegated, "claude", "delegated"),
        ] {
            let (status, body, _) = ask(&st, rec.uid, Some(&gw), audience).await;
            assert_eq!(status, StatusCode::OK, "{audience}: {body}");
            if audience == "sts-gw" {
                jwt = body["value"].as_str().unwrap().replace("Bearer ", "");
            }
            let logs = captured();
            let issued: Vec<&str> = logs
                .lines()
                .filter(|l| {
                    l.contains("gateway credential issued") && l.contains(&rec.uid.to_string())
                })
                .collect();
            assert_eq!(issued.len(), 1, "one audit line for {audience}: {logs}");
            let line = issued[0];
            for needle in [audience, "octocat", backend, "expires_at"] {
                assert!(line.contains(needle), "{needle} in {line}");
            }
        }
        let logs = captured();
        assert_ne!(jwt, "", "the minted token was captured for the check");
        for secret_bytes in [SECRET_VALUE, SESSION_TOKEN, jwt.as_str()] {
            assert!(
                !logs.contains(secret_bytes),
                "the credential must never reach a log line, found {secret_bytes:?} in:\n{logs}"
            );
        }
    }

    // ----- ADR-0046: who may claim where --------------------------------------------------------------------------

    use mediatore_claims::sandbox::SandboxFrontDoor;
    use mediatore_entra::{Backend, IssuerConfig};
    use mediatore_testkit::FakeIdp;
    use mediatore_testkit::sandboxes::MemorySandboxes;

    const TEAM_A: &str = "APP_EXAMPLE_TEAM_A_USER";
    const ADMIN: &str = "example-org:APP_EXAMPLE_ADMIN";

    fn tenant_map() -> Namespaces {
        Namespaces::Map(BTreeMap::from([
            ("infra".to_owned(), vec![ADMIN.to_owned()]),
            ("team-a".to_owned(), vec![TEAM_A.to_owned()]),
        ]))
    }

    /// A front door that counts the reads it is asked for and forwards to the in-memory API.
    struct Counting {
        inner: Arc<MemorySandboxes>,
        gets: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl SandboxFrontDoor for Counting {
        async fn create(&self, sandbox: AgentSandbox) -> Result<AgentSandbox, FrontDoorError> {
            self.inner.create(sandbox).await
        }
        async fn get(&self, ns: &str, name: &str) -> Result<Option<AgentSandbox>, FrontDoorError> {
            self.gets.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.get(ns, name).await
        }
        async fn delete(&self, ns: &str, name: &str) -> Result<(), FrontDoorError> {
            self.inner.delete(ns, name).await
        }
    }

    struct Broker {
        idp: FakeIdp,
        st: Shared,
        front: Arc<MemorySandboxes>,
        counting: Arc<Counting>,
    }

    async fn broker(namespaces: Namespaces, dev_mode: bool) -> Broker {
        broker_with_logs(namespaces, dev_mode, None).await
    }

    /// [`broker`] with the output store on or off (ADR-0045 decision 11).
    async fn broker_with_logs(
        namespaces: Namespaces,
        dev_mode: bool,
        logs: Option<LogLimits>,
    ) -> Broker {
        let idp = FakeIdp::start().await;
        let front = Arc::new(MemorySandboxes::default());
        let counting = Arc::new(Counting {
            inner: front.clone(),
            gets: std::sync::atomic::AtomicUsize::new(0),
        });
        let mut st = base_state();
        st.validator = Validator::new(vec![IssuerConfig {
            url: idp.issuer.clone(),
            backend: Backend::Sts,
            client_id: "mediatore".into(),
            subject_claim: "preferred_username".into(),
            required_group: None,
            required_groups: None,
            allow_any_authenticated: true,
            session: None,
            ca_file: None,
            entra: None,
            groups_claim: None,
        }]);
        st.namespaces = namespaces;
        st.dev_mode = dev_mode;
        st.logs = logs;
        if !dev_mode {
            st.sandboxes = Some(counting.clone());
        }
        Broker {
            idp,
            st: Arc::new(st),
            front,
            counting,
        }
    }

    impl Broker {
        fn token(&self, login: &str, groups: &[&str]) -> String {
            self.idp.token(serde_json::json!({
                "aud": "mediatore",
                "sub": login,
                "preferred_username": login,
                "groups": groups,
            }))
        }

        fn reads(&self) -> usize {
            self.counting.gets.load(std::sync::atomic::Ordering::SeqCst)
        }

        async fn user(
            &self,
            method: &str,
            uri: &str,
            token: &str,
            extra: &[(&str, &str)],
            body: serde_json::Value,
        ) -> (StatusCode, serde_json::Value, String) {
            let mut req = Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json")
                .header("authorization", format!("Bearer {token}"));
            for (k, v) in extra {
                req = req.header(*k, *v);
            }
            let resp = user_router(self.st.clone())
                .oneshot(req.body(Body::from(body.to_string())).unwrap())
                .await
                .unwrap();
            let status = resp.status();
            let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
                .await
                .unwrap();
            let text = String::from_utf8_lossy(&bytes).into_owned();
            (
                status,
                serde_json::from_str(&text).unwrap_or(serde_json::Value::Null),
                text,
            )
        }

        async fn create(
            &self,
            token: &str,
            namespace: Option<&str>,
        ) -> (StatusCode, serde_json::Value, String) {
            self.user("POST", "/v1/claims", token, &[], request(namespace))
                .await
        }

        async fn get(
            &self,
            token: &str,
            name: &str,
            namespace: Option<&str>,
        ) -> (StatusCode, serde_json::Value, String) {
            self.user(
                "GET",
                &claim_uri(name, namespace),
                token,
                &[],
                serde_json::Value::Null,
            )
            .await
        }

        async fn delete(
            &self,
            token: &str,
            name: &str,
            namespace: Option<&str>,
        ) -> (StatusCode, serde_json::Value, String) {
            self.user(
                "DELETE",
                &claim_uri(name, namespace),
                token,
                &[],
                serde_json::Value::Null,
            )
            .await
        }
    }

    fn claim_uri(name: &str, namespace: Option<&str>) -> String {
        namespace.map_or_else(
            || format!("/v1/claims/{name}"),
            |ns| format!("/v1/claims/{name}?namespace={ns}"),
        )
    }

    fn request(namespace: Option<&str>) -> serde_json::Value {
        request_for_pool(
            namespace,
            None,
            Some(mediatore_proto::PoolSelector::default()),
        )
    }

    fn request_for_pool(
        namespace: Option<&str>,
        pool_ref: Option<&str>,
        pool_selector: Option<mediatore_proto::PoolSelector>,
    ) -> serde_json::Value {
        serde_json::to_value(ClaimRequest {
            namespace: namespace.map(str::to_owned),
            pool_ref: pool_ref.map(str::to_owned),
            pool_selector,
            selection: None,
            ttl_seconds: 600,
            audiences: vec![],
            workload: mediatore_proto::Workload {
                image: "registry.example/sandbox:1".into(),
                ..mediatore_proto::Workload::default()
            },
            refresh_token: None,
            policy_ref: None,
            delegations: vec![],
        })
        .unwrap()
    }

    /// The name of the claim a `201` answered.
    fn created(r: &(StatusCode, serde_json::Value, String)) -> String {
        assert_eq!(r.0, StatusCode::CREATED, "{}", r.2);
        r.1["name"].as_str().unwrap().to_owned()
    }

    // ----- Namespaces, on their own -----

    #[test]
    fn the_single_form_resolves_an_omitted_or_equal_namespace_and_refuses_any_other() {
        let n = Namespaces::Single("sandboxes".into());
        assert_eq!(n.resolve_for_create(None, &[]).as_deref(), Ok("sandboxes"));
        assert_eq!(
            n.resolve_for_create(Some("sandboxes"), &[]).as_deref(),
            Ok("sandboxes")
        );
        assert_eq!(
            n.resolve_for_create(Some("team-a"), &[]),
            Err(NsDenied::Forbidden("team-a".into()))
        );
        assert_eq!(n.authorise_existing(None, &[]).as_deref(), Ok("sandboxes"));
        assert_eq!(
            n.authorise_existing(Some("team-a"), &[]),
            Err(NsDenied::NotFound)
        );
    }

    #[test]
    fn the_map_form_needs_a_named_listed_namespace_and_a_listed_group() {
        let n = tenant_map();
        let held = |g: &[&str]| g.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert_eq!(
            n.resolve_for_create(None, &held(&[TEAM_A])),
            Err(NsDenied::Required)
        );
        assert_eq!(
            n.resolve_for_create(Some("team-a"), &held(&[TEAM_A]))
                .as_deref(),
            Ok("team-a")
        );
        assert_eq!(
            n.resolve_for_create(Some("team-a"), &held(&[ADMIN])),
            Err(NsDenied::Forbidden("team-a".into()))
        );
        assert_eq!(
            n.resolve_for_create(Some("Team_A"), &held(&[TEAM_A])),
            Err(NsDenied::Invalid)
        );
        assert_eq!(
            n.matched_group("team-a", &held(&["x", TEAM_A])),
            Some(TEAM_A)
        );
        assert_eq!(n.matched_group("team-a", &held(&["x"])), None);
        assert_eq!(
            n.authorise_existing(None, &held(&[TEAM_A])),
            Err(NsDenied::Required)
        );
        assert_eq!(
            n.authorise_existing(Some("infra"), &held(&[TEAM_A])),
            Err(NsDenied::NotFound)
        );
    }

    // ----- create -----

    #[tokio::test]
    async fn omitting_namespace_without_a_map_targets_the_single_namespace() {
        let b = broker(Namespaces::Single("sandboxes".into()), false).await;
        let t = b.token("alice", &[]);
        let r = b.create(&t, None).await;
        created(&r);
        assert_eq!(r.1["namespace"], "sandboxes");
        assert_eq!(
            b.front.all()[0].metadata.namespace.as_deref(),
            Some("sandboxes")
        );
        // The one namespace may also be named; any other is the 403 of decision 6.
        created(&b.create(&t, Some("sandboxes")).await);
        let (status, body, _) = b.create(&t, Some("team-a")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(code(&body), "forbidden");
        assert_eq!(b.front.all().len(), 2, "the refused request wrote nothing");
    }

    // ADR-0046 decision 8. The broker does not match pools (banlieue does, in the sandbox's own
    // namespace, ADR-0132 there): what it controls, and what these two tests pin, is that the
    // `AgentSandbox` it writes lands in the one resolved namespace and carries the pool fields
    // exactly as sent, so a selector or a name can only ever be read against that namespace.

    #[tokio::test]
    async fn a_selector_in_team_a_matches_only_team_as_pools() {
        let b = broker(tenant_map(), false).await;
        let selector = mediatore_proto::PoolSelector {
            match_labels: BTreeMap::from([("tier".to_owned(), "gpu".to_owned())]),
            match_expressions: vec![],
        };
        let r = b
            .user(
                "POST",
                "/v1/claims",
                &b.token("alice", &[TEAM_A, ADMIN]),
                &[],
                request_for_pool(Some("team-a"), None, Some(selector.clone())),
            )
            .await;
        created(&r);
        let all = b.front.all();
        assert_eq!(all.len(), 1);
        let sb = &all[0];
        assert_eq!(sb.metadata.namespace.as_deref(), Some("team-a"));
        assert_eq!(sb.spec.pool_selector, Some(label_selector_of(&selector)));
        assert!(sb.spec.pool_ref.is_none());
        assert!(
            b.front
                .all()
                .iter()
                .all(|s| s.metadata.namespace.as_deref() != Some("infra")),
            "nothing was written for the other listed namespace"
        );
    }

    #[tokio::test]
    async fn a_pool_ref_naming_another_namespaces_pool_is_carried_as_a_plain_name_in_the_resolved_namespace_only()
     {
        // The broker has no pool lookup: a name is a plain `LocalObjectReference`, resolved by
        // banlieue in the sandbox's namespace, where a pool that exists only elsewhere is its
        // `PoolNotFound`. So a name that tries to reach across (`team-b/pool`, `pool.team-b`)
        // is carried verbatim into team-a and nowhere else; the broker writes nothing in team-b.
        let b = broker(tenant_map(), false).await;
        let t = b.token("alice", &[TEAM_A, ADMIN]);
        for name in ["pool-b", "team-b/pool", "pool.team-b"] {
            let r = b
                .user(
                    "POST",
                    "/v1/claims",
                    &t,
                    &[],
                    request_for_pool(Some("team-a"), Some(name), None),
                )
                .await;
            created(&r);
        }
        let all = b.front.all();
        assert_eq!(all.len(), 3);
        for sb in &all {
            assert_eq!(sb.metadata.namespace.as_deref(), Some("team-a"));
            assert!(sb.spec.pool_selector.is_none());
        }
        let mut names: Vec<_> = all
            .iter()
            .map(|s| s.spec.pool_ref.clone().unwrap().name)
            .collect();
        names.sort();
        assert_eq!(names, ["pool-b", "pool.team-b", "team-b/pool"]);
    }

    // ADR-0046 decision 14: the broker cannot know a listed namespace exists; the API server's
    // refusal of the create is what says so. The real mapping (`front_door_error`) sends a 404
    // to `FrontDoorError::Api`, which is a `500 internal`, not a `502` (the ADR said 502; the
    // ADR text is corrected).

    /// An API server for which the listed namespace does not exist.
    struct NamespaceMissing;

    #[async_trait::async_trait]
    impl SandboxFrontDoor for NamespaceMissing {
        async fn create(&self, _: AgentSandbox) -> Result<AgentSandbox, FrontDoorError> {
            Err(FrontDoorError::Api(
                "ApiError: namespaces \"team-a\" not found: NotFound (404)".into(),
            ))
        }
        async fn get(&self, _: &str, _: &str) -> Result<Option<AgentSandbox>, FrontDoorError> {
            Ok(None)
        }
        async fn delete(&self, _: &str, _: &str) -> Result<(), FrontDoorError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn a_listed_namespace_that_does_not_exist_fails_the_create_and_parks_nothing() {
        let mut b = broker(tenant_map(), false).await;
        {
            let st = Arc::get_mut(&mut b.st).expect("the state is not shared yet");
            st.sandboxes = Some(Arc::new(NamespaceMissing));
            st.sealer = Some(Arc::new(mediatore_store::seal::LocalKeySealer::new(
                [3; 32],
            )));
            // A session issuer, so the create has a refresh token to park were it to get that far.
            st.validator = Validator::new(vec![IssuerConfig {
                url: b.idp.issuer.clone(),
                backend: Backend::Sts,
                client_id: "mediatore".into(),
                subject_claim: "preferred_username".into(),
                required_group: None,
                required_groups: None,
                allow_any_authenticated: true,
                session: Some(mediatore_entra::SessionConfig {
                    client_id: "mediatore".into(),
                    client_secret_file: None,
                }),
                ca_file: None,
                entra: None,
                groups_claim: None,
            }]);
        }
        let mut body = request(Some("team-a"));
        body["refresh_token"] = serde_json::json!("refresh-material-placeholder");
        let (status, resp, text) = b
            .user(
                "POST",
                "/v1/claims",
                &b.token("alice", &[TEAM_A]),
                &[],
                body,
            )
            .await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{text}");
        assert_eq!(code(&resp), "internal");
        assert!(!text.contains("refresh-material-placeholder"), "{text}");
        // Nothing parked: the sandbox never got a UID for a session to be sealed under.
        let far = Timestamp::now() + SignedDuration::from_hours(24);
        assert_eq!(
            b.st.store.sweep_sessions(far).await.unwrap(),
            0,
            "no session or delegation Secret is left behind"
        );
        assert_eq!(b.front.all().len(), 0);
    }

    #[tokio::test]
    async fn omitting_namespace_with_a_map_is_400_namespace_required() {
        let b = broker(tenant_map(), false).await;
        let (status, body, _) = b.create(&b.token("alice", &[TEAM_A]), None).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(code(&body), "namespace_required");
        assert_eq!(b.front.all().len(), 0);
    }

    #[tokio::test]
    async fn the_400_for_a_missing_namespace_names_no_namespace() {
        let b = broker(tenant_map(), false).await;
        let (_, _, text) = b.create(&b.token("alice", &[TEAM_A, ADMIN]), None).await;
        for listed in ["infra", "team-a", TEAM_A, ADMIN] {
            assert!(!text.contains(listed), "{listed} in {text}");
        }
    }

    #[tokio::test]
    async fn a_caller_in_two_namespaces_must_name_one() {
        let b = broker(tenant_map(), false).await;
        let t = b.token("alice", &[TEAM_A, ADMIN]);
        assert_eq!(b.create(&t, None).await.0, StatusCode::BAD_REQUEST);
        let r = b.create(&t, Some("team-a")).await;
        created(&r);
        assert_eq!(r.1["namespace"], "team-a");
        let r = b.create(&t, Some("infra")).await;
        created(&r);
        assert_eq!(r.1["namespace"], "infra");
        let mut at: Vec<_> = b
            .front
            .all()
            .iter()
            .map(|s| s.metadata.namespace.clone().unwrap())
            .collect();
        at.sort();
        assert_eq!(at, ["infra", "team-a"]);
    }

    #[tokio::test]
    async fn a_namespace_outside_the_map_is_403_whatever_the_groups() {
        let b = broker(tenant_map(), false).await;
        let t = b.token("alice", &[TEAM_A, ADMIN]);
        for ns in ["kube-system", "sandboxes", "team-b"] {
            let (status, body, _) = b.create(&t, Some(ns)).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{ns}");
            assert_eq!(code(&body), "forbidden");
        }
        assert_eq!(b.front.all().len(), 0);
    }

    #[tokio::test]
    async fn a_namespace_value_that_is_not_a_dns_label_is_400() {
        let b = broker(tenant_map(), false).await;
        let t = b.token("alice", &[TEAM_A]);
        for bad in ["Team_A", "", "a/b", "-a", &"a".repeat(64)] {
            let (status, body, _) = b.create(&t, Some(bad)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{bad:?}");
            assert_eq!(code(&body), "invalid_namespace");
            let (status, body, _) = b.get(&t, "sandbox-x", Some(bad)).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "get {bad:?}");
            assert_eq!(code(&body), "invalid_namespace");
        }
        assert_eq!(
            b.reads(),
            0,
            "a malformed name is refused before any lookup"
        );
    }

    #[tokio::test]
    async fn the_403_for_an_unlisted_namespace_equals_the_403_for_an_unqualified_one() {
        // "infra" is listed here and the caller does not qualify ...
        let unqualified = broker(tenant_map(), false).await;
        let a = unqualified
            .create(&unqualified.token("alice", &[TEAM_A]), Some("infra"))
            .await;
        // ... and not listed here.
        let only_a = Namespaces::Map(BTreeMap::from([(
            "team-a".to_owned(),
            vec![TEAM_A.to_owned()],
        )]));
        let unlisted = broker(only_a, false).await;
        let b = unlisted
            .create(&unlisted.token("alice", &[TEAM_A, ADMIN]), Some("infra"))
            .await;
        assert_eq!(a.0, StatusCode::FORBIDDEN);
        assert_eq!(a.0, b.0);
        assert_eq!(a.2, b.2, "byte-equal bodies");
        assert_eq!(
            a.1["detail"],
            "not permitted to create sandboxes in namespace infra"
        );
    }

    #[tokio::test]
    async fn the_403_body_contains_no_group_and_no_other_namespace() {
        let b = broker(tenant_map(), false).await;
        let (status, _, text) = b
            .create(&b.token("alice", &["SOME_OTHER_GROUP"]), Some("infra"))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        for leak in [TEAM_A, ADMIN, "SOME_OTHER_GROUP", "team-a"] {
            assert!(!text.contains(leak), "{leak} in {text}");
        }
    }

    // ----- get and delete -----

    #[tokio::test]
    async fn get_and_delete_find_a_claim_in_its_own_namespace() {
        let b = broker(tenant_map(), false).await;
        let t = b.token("alice", &[TEAM_A]);
        let name = created(&b.create(&t, Some("team-a")).await);
        let (status, body, _) = b.get(&t, &name, Some("team-a")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["namespace"], "team-a");
        // The same name in a namespace it is not in is not found, even for a caller who qualifies.
        let both = b.token("alice", &[TEAM_A, ADMIN]);
        assert_eq!(
            b.get(&both, &name, Some("infra")).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            b.delete(&t, &name, Some("team-a")).await.0,
            StatusCode::NO_CONTENT
        );
        assert_eq!(b.front.all().len(), 0);
    }

    #[tokio::test]
    async fn get_without_a_namespace_and_no_map_reads_the_single_namespace() {
        let b = broker(Namespaces::Single("sandboxes".into()), false).await;
        let t = b.token("alice", &[]);
        let name = created(&b.create(&t, None).await);
        assert_eq!(b.get(&t, &name, None).await.0, StatusCode::OK);
        assert_eq!(b.delete(&t, &name, None).await.0, StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn get_without_namespace_with_a_map_is_400_namespace_required() {
        let b = broker(tenant_map(), false).await;
        let t = b.token("alice", &[TEAM_A]);
        let name = created(&b.create(&t, Some("team-a")).await);
        for r in [
            b.get(&t, &name, None).await,
            b.delete(&t, &name, None).await,
        ] {
            assert_eq!(r.0, StatusCode::BAD_REQUEST);
            assert_eq!(code(&r.1), "namespace_required");
        }
        assert_eq!(b.reads(), 0);
        assert_eq!(b.front.all().len(), 1);
    }

    #[tokio::test]
    async fn another_subject_in_the_same_namespace_is_403() {
        let b = broker(tenant_map(), false).await;
        let name = created(&b.create(&b.token("alice", &[TEAM_A]), Some("team-a")).await);
        let bob = b.token("bob", &[TEAM_A]);
        for r in [
            b.get(&bob, &name, Some("team-a")).await,
            b.delete(&bob, &name, Some("team-a")).await,
        ] {
            assert_eq!(r.0, StatusCode::FORBIDDEN);
            assert_eq!(r.1["detail"], "claim belongs to another subject");
        }
        assert_eq!(b.front.all().len(), 1);
    }

    #[tokio::test]
    async fn a_caller_who_left_the_group_can_no_longer_read_or_delete_their_claim() {
        let b = broker(tenant_map(), false).await;
        let name = created(&b.create(&b.token("alice", &[TEAM_A]), Some("team-a")).await);
        let left = b.token("alice", &["SOME_OTHER_GROUP"]);
        b.counting
            .gets
            .store(0, std::sync::atomic::Ordering::SeqCst);
        for r in [
            b.get(&left, &name, Some("team-a")).await,
            b.delete(&left, &name, Some("team-a")).await,
        ] {
            assert_eq!(r.0, StatusCode::NOT_FOUND);
            assert_eq!(code(&r.1), "not_found");
        }
        assert_eq!(
            b.reads(),
            0,
            "no read is issued for a namespace the caller may not use"
        );
        assert_eq!(b.front.all().len(), 1, "the claim is still there");
    }

    #[tokio::test]
    async fn a_namespace_outside_the_map_is_404_on_get_and_delete() {
        let b = broker(tenant_map(), false).await;
        let t = b.token("alice", &[TEAM_A, ADMIN]);
        let unlisted = [
            b.get(&t, "sandbox-x", Some("team-z")).await,
            b.delete(&t, "sandbox-x", Some("team-z")).await,
        ];
        // The same answer as a listed namespace with no such sandbox.
        let absent = [
            b.get(&t, "sandbox-x", Some("team-a")).await,
            b.delete(&t, "sandbox-x", Some("team-a")).await,
        ];
        // Delete of a listed namespace with nothing there is the existing owner-lookup 404.
        for (u, a) in unlisted.iter().zip(&absent) {
            assert_eq!(u.0, StatusCode::NOT_FOUND);
            assert_eq!(code(&u.1), "not_found");
            assert_eq!(u.0, a.0);
            assert_eq!(code(&u.1), code(&a.1));
        }
    }

    /// Path segments that decode to something other than an RFC 1123 label: a `/`, a `?`, a
    /// `%`, uppercase, a leading hyphen, and one byte over the longest label.
    fn not_sandbox_names() -> Vec<String> {
        vec![
            "a%2Fb".to_owned(),
            "..%2F..%2Fsecrets".to_owned(),
            "a%3Fwatch=1".to_owned(),
            "a%25b".to_owned(),
            "Sandbox-X".to_owned(),
            "-sandbox".to_owned(),
            "a".repeat(64),
        ]
    }

    #[tokio::test]
    async fn a_name_that_is_not_a_dns_label_is_404_and_never_reaches_the_front_door() {
        let b = broker_with_logs(
            tenant_map(),
            false,
            Some(LogLimits {
                max_bytes: mediatore_proto::DEFAULT_LOG_MAX_BYTES,
            }),
        )
        .await;
        let t = b.token("alice", &[TEAM_A]);
        created(&b.create(&t, Some("team-a")).await);
        for name in not_sandbox_names() {
            let logs = format!("/v1/claims/{name}/logs?namespace=team-a");
            let answers = [
                b.get(&t, &name, Some("team-a")).await,
                b.delete(&t, &name, Some("team-a")).await,
                b.user("GET", &logs, &t, &[], serde_json::Value::Null).await,
            ];
            for (status, body, _) in &answers {
                assert_eq!(*status, StatusCode::NOT_FOUND, "{name}");
                assert_eq!(code(body), "not_found", "{name}");
                assert_eq!(body["detail"], "no such sandbox", "{name}");
            }
        }
        // No name at all is no route.
        let empty = b
            .user(
                "GET",
                "/v1/claims/?namespace=team-a",
                &t,
                &[],
                serde_json::Value::Null,
            )
            .await;
        assert_eq!(empty.0, StatusCode::NOT_FOUND);
        assert_eq!(b.reads(), 0, "no read is issued for a name that is not one");
        assert_eq!(b.front.all().len(), 1, "the claim is still there");
        // A caller with no token learns nothing from the name: `401` first.
        let anonymous = b.get("not-a-token", "a%2Fb", Some("team-a")).await;
        assert_eq!(anonymous.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn dev_mode_refuses_a_name_that_is_not_a_dns_label_the_same_way() {
        let b = broker(Namespaces::Single("sandboxes".into()), true).await;
        let t = b.token("alice", &[]);
        for name in not_sandbox_names() {
            for (status, body, _) in [
                b.get(&t, &name, None).await,
                b.delete(&t, &name, None).await,
            ] {
                assert_eq!(status, StatusCode::NOT_FOUND, "{name}");
                assert_eq!(code(&body), "not_found", "{name}");
                assert_eq!(body["detail"], "no such sandbox", "{name}");
            }
        }
    }

    #[tokio::test]
    async fn an_admin_namespace_member_cannot_get_or_delete_a_tenants_claim() {
        let b = broker(tenant_map(), false).await;
        let name = created(&b.create(&b.token("alice", &[TEAM_A]), Some("team-a")).await);
        // An infra admin who is not in team-a's groups: not found, as for any unqualified caller.
        let admin = b.token("carol", &[ADMIN]);
        assert_eq!(
            b.get(&admin, &name, Some("team-a")).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            b.delete(&admin, &name, Some("team-a")).await.0,
            StatusCode::NOT_FOUND
        );
        // One who is in both is qualified for team-a and is still not the claim's subject.
        let both = b.token("carol", &[ADMIN, TEAM_A]);
        assert_eq!(
            b.get(&both, &name, Some("team-a")).await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            b.delete(&both, &name, Some("team-a")).await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(b.front.all().len(), 1, "the claim still exists");
    }

    // ----- exit: the claim's own namespace -----

    fn sandbox_in(namespace: &str, name: &str) -> AgentSandbox {
        let mut sb = AgentSandbox::new(
            name,
            AgentSandboxSpec {
                subject: SandboxSubject::from(&subject()),
                pool_ref: None,
                pool_selector: Some(label_selector_of(&mediatore_proto::PoolSelector::default())),
                selection: None,
                ttl_seconds: 600,
                audiences: vec![],
                workload: SandboxWorkload::from(&mediatore_proto::Workload {
                    image: "registry.example/sandbox:1".into(),
                    ..mediatore_proto::Workload::default()
                }),
                policy_ref: None,
            },
        );
        sb.metadata.namespace = Some(namespace.into());
        sb
    }

    #[tokio::test]
    async fn exit_releases_a_claim_through_the_records_namespace() {
        let b = broker(tenant_map(), false).await;
        let ek = "ab".repeat(32);
        b.st.store
            .put_node(NodeRecord {
                ek_hash: ek.clone(),
                node_id: b.st.naming.node_id(&ek),
                dmi_uuid: Uuid::new_v4(),
                hostname: "vm".into(),
                provider: None,
                banned: false,
                registered_at: Timestamp::now(),
            })
            .await
            .unwrap();
        // The same name in two namespaces: only the record's namespace is released.
        b.front
            .create(sandbox_in("team-a", "sandbox-x"))
            .await
            .unwrap();
        b.front
            .create(sandbox_in("infra", "sandbox-x"))
            .await
            .unwrap();
        let mut rec = claim(&[], Some(b.st.naming.node_id(&ek)));
        rec.name = "sandbox-x".into();
        rec.namespace = "team-a".into();
        stored(&b.st, rec).await;
        let mut req = Request::builder()
            .method("POST")
            .uri("/v1/me/exit")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({"code": 0, "restarts": 0}).to_string(),
            ))
            .unwrap();
        req.extensions_mut()
            .insert(PeerSpiffeId(b.st.naming.node_id(&ek)));
        let resp = sandbox_router(b.st.clone()).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        let left: Vec<_> = b
            .front
            .all()
            .iter()
            .map(|s| s.metadata.namespace.clone().unwrap())
            .collect();
        assert_eq!(
            left,
            ["infra"],
            "team-a's sandbox was released, infra's was not"
        );
    }

    // ----- dev_mode -----

    #[tokio::test]
    async fn dev_mode_enforces_the_namespace_groups() {
        let b = broker(tenant_map(), true).await;
        let (status, _, _) = b
            .create(&b.token("alice", &["SOME_OTHER_GROUP"]), Some("team-a"))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(
            b.create(&b.token("alice", &[TEAM_A]), None).await.0,
            StatusCode::BAD_REQUEST
        );
        let t = b.token("alice", &[TEAM_A]);
        let r = b.create(&t, Some("team-a")).await;
        let name = created(&r);
        assert_eq!(r.1["namespace"], "team-a");
        let rec = b.st.store.get_claim_by_name("team-a", &name).await.unwrap();
        assert_eq!(rec.namespace, "team-a");
        assert_eq!(b.get(&t, &name, Some("team-a")).await.0, StatusCode::OK);
        assert_eq!(b.get(&t, &name, None).await.0, StatusCode::BAD_REQUEST);
        let left = b.token("alice", &["SOME_OTHER_GROUP"]);
        assert_eq!(
            b.get(&left, &name, Some("team-a")).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            b.delete(&left, &name, Some("team-a")).await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            b.delete(&t, &name, Some("team-a")).await.0,
            StatusCode::NO_CONTENT
        );
    }

    #[tokio::test]
    async fn no_header_can_select_a_namespace_or_supply_groups() {
        let b = broker(tenant_map(), true).await;
        let t = b.token("alice", &["SOME_OTHER_GROUP"]);
        let headers = [
            ("x-mediatore-namespace", "team-a"),
            ("x-mediatore-groups", TEAM_A),
            ("x-mediatore-peer-spiffe-id", "spiffe://sandbox.test/x"),
        ];
        let r = b
            .user("POST", "/v1/claims", &t, &headers, request(None))
            .await;
        assert_eq!(
            r.0,
            StatusCode::BAD_REQUEST,
            "a header names no namespace: {}",
            r.2
        );
        let r = b
            .user("POST", "/v1/claims", &t, &headers, request(Some("team-a")))
            .await;
        assert_eq!(
            r.0,
            StatusCode::FORBIDDEN,
            "a header supplies no groups: {}",
            r.2
        );
    }

    // ----- the audit line -----

    /// ADR-0052 decision 7 (a defect the first live run found): the stored output is sent
    /// through a channel the body drains, and a stored ring larger than the channel was cut
    /// where the channel filled and reported as a departed reader.
    #[tokio::test]
    async fn a_read_of_more_records_than_the_channel_holds_returns_every_one() {
        let b = broker_with_logs(
            Namespaces::Single("sandboxes".into()),
            true,
            Some(LogLimits {
                max_bytes: mediatore_proto::DEFAULT_LOG_MAX_BYTES,
            }),
        )
        .await;
        let mut rec = claim(&[], None);
        rec.subject = Subject {
            issuer: b.idp.issuer.clone(),
            id: "alice".into(),
            display: None,
        };
        rec.workload.logs = true;
        let rec = stored(&b.st, rec).await;
        let batch = LogBatch {
            records: (1..=500u64)
                .map(|seq| mediatore_proto::LogRecord {
                    seq,
                    stream: mediatore_proto::LogStream::Stdout,
                    ts: Timestamp::now(),
                    text: format!("line-{seq}"),
                })
                .collect(),
            ..LogBatch::default()
        };
        b.st.store
            .append_logs(&rec, &batch, &b.st.logs.unwrap())
            .await
            .unwrap();
        let token = b.token("alice", &[]);
        let (status, _, text) = b
            .user(
                "GET",
                &format!("/v1/claims/{}/logs", rec.name),
                &token,
                &[],
                serde_json::Value::Null,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{text}");
        let lines: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
        let records: Vec<&&str> = lines.iter().filter(|l| l.contains("\"seq\"")).collect();
        assert_eq!(records.len(), 500, "every record, not the first 31");
        assert!(records[499].contains("line-500"));
        assert!(
            lines.last().unwrap().contains("\"end\""),
            "the stream ends with its end line: {}",
            lines.last().unwrap()
        );
    }

    /// ADR-0052 decision 4: a store that cannot reach its sealer is a `503` the owner can
    /// retry, and the guest's retry on ingest, never a `500` and never a partial answer.
    #[test]
    fn a_store_outage_is_a_503_and_other_store_errors_are_not() {
        let outage = store_error(StoreError::Unavailable("sealer: connection refused".into()));
        assert_eq!(outage.status, StatusCode::SERVICE_UNAVAILABLE);
        let other = store_error(StoreError::Backend("boom".into()));
        assert_eq!(other.status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    /// ADR-0045 decision 10: a read of a workload's output is one line before the first byte
    /// and one at the end, with the claim UID, the subject and counts, and never a byte of the
    /// output; a refusal is one `warn` line with its reason.
    #[tokio::test]
    async fn a_read_of_workload_output_logs_the_claim_and_the_subject_and_never_the_text() {
        const PRINTED: &str = "the-workload-printed-this-s3cret-looking-line";
        capture_logs();
        let b = broker_with_logs(
            Namespaces::Single("sandboxes".into()),
            true,
            Some(LogLimits {
                max_bytes: mediatore_proto::DEFAULT_LOG_MAX_BYTES,
            }),
        )
        .await;
        let mut rec = claim(&[], None);
        rec.subject = Subject {
            issuer: b.idp.issuer.clone(),
            id: "alice".into(),
            display: None,
        };
        rec.workload.logs = true;
        let rec = stored(&b.st, rec).await;
        let batch = LogBatch {
            records: vec![mediatore_proto::LogRecord {
                seq: 1,
                stream: mediatore_proto::LogStream::Stdout,
                ts: Timestamp::now(),
                text: PRINTED.into(),
            }],
            ..LogBatch::default()
        };
        b.st.store
            .append_logs(&rec, &batch, &b.st.logs.unwrap())
            .await
            .unwrap();
        let token = b.token("alice", &[]);
        let (status, _, text) = b
            .user(
                "GET",
                &format!("/v1/claims/{}/logs?tail=1", rec.name),
                &token,
                &[],
                serde_json::Value::Null,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{text}");
        assert!(text.contains(PRINTED), "the owner gets the output: {text}");
        // The end line is written by the streaming task: give it a moment.
        let mut logs = String::new();
        for _ in 0..50 {
            logs = captured();
            if logs.contains("workload output read ended") {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let start = logs
            .lines()
            .find(|l| l.contains("workload output read") && !l.contains("ended"))
            .expect("the line before the first byte");
        // The needles are never printed: a failure names the line, which carries no secret.
        for needle in [&rec.uid.to_string(), "alice", &rec.name, "tail=Some(1)"] {
            assert!(start.contains(needle), "a field is missing from {start}");
        }
        let end = logs
            .lines()
            .find(|l| l.contains("workload output read ended"))
            .expect("the line at the end");
        for needle in [
            &rec.uid.to_string(),
            "alice",
            "records_sent=1",
            "bytes_sent=",
            "duration_ms=",
        ] {
            assert!(end.contains(needle), "a field is missing from {end}");
        }
        assert!(
            !logs.contains(PRINTED) && !logs.contains("s3cret"),
            "no byte of the output reaches a log line"
        );
        assert!(!logs.contains(token.as_str()), "a token reached a log line");
        // A refusal: another subject, one warn line with the reason.
        let other = b.token("mallory", &[]);
        let (status, _, _) = b
            .user(
                "GET",
                &format!("/v1/claims/{}/logs", rec.name),
                &other,
                &[],
                serde_json::Value::Null,
            )
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let refused = captured()
            .lines()
            .find(|l| l.contains("workload output read refused"))
            .map(str::to_owned)
            .expect("a refusal line");
        assert!(
            refused.contains("WARN") && refused.contains("reason=forbidden"),
            "{refused}"
        );
    }

    /// ADR-0045 decision 9: a read sends every stored record and then the end line, however
    /// many there are. The lines go down a bounded channel; a full channel is a reader that
    /// has not caught up, never a reader that left.
    #[tokio::test]
    async fn a_read_of_more_lines_than_the_channel_holds_sends_them_all_and_the_end_line() {
        const RECORDS: u64 = 40;
        let b = broker_with_logs(
            Namespaces::Single("sandboxes".into()),
            true,
            Some(LogLimits {
                max_bytes: mediatore_proto::DEFAULT_LOG_MAX_BYTES,
            }),
        )
        .await;
        let mut rec = claim(&[], None);
        rec.subject = Subject {
            issuer: b.idp.issuer.clone(),
            id: "alice".into(),
            display: None,
        };
        rec.workload.logs = true;
        let rec = stored(&b.st, rec).await;
        let batch = LogBatch {
            records: (1..=RECORDS)
                .map(|seq| mediatore_proto::LogRecord {
                    seq,
                    stream: mediatore_proto::LogStream::Stdout,
                    ts: Timestamp::now(),
                    text: format!("output line {seq}"),
                })
                .collect(),
            ..LogBatch::default()
        };
        b.st.store
            .append_logs(&rec, &batch, &b.st.logs.unwrap())
            .await
            .unwrap();
        let token = b.token("alice", &[]);
        let (status, _, text) = b
            .user(
                "GET",
                &format!("/v1/claims/{}/logs", rec.name),
                &token,
                &[],
                serde_json::Value::Null,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        let lines: Vec<serde_json::Value> = text
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| serde_json::from_str(l).expect("every line is JSON"))
            .collect();
        let seqs: Vec<u64> = lines
            .iter()
            .filter_map(|l| l.get("seq").and_then(serde_json::Value::as_u64))
            .collect();
        assert_eq!(
            seqs,
            (1..=RECORDS).collect::<Vec<u64>>(),
            "every stored record is sent, in order"
        );
        let last = lines.last().expect("at least the end line");
        assert_eq!(
            last.get("end").and_then(serde_json::Value::as_bool),
            Some(true),
            "the stream ends with its end line"
        );
        assert_eq!(
            lines.len(),
            seqs.len() + 2,
            "the header, the records and the end line"
        );
    }

    #[tokio::test]
    async fn a_create_logs_subject_namespace_and_decision_and_never_a_token() {
        capture_logs();
        let b = broker(tenant_map(), false).await;
        let ok = b.token("alice", &[TEAM_A, "SOME_OTHER_GROUP"]);
        created(&b.create(&ok, Some("team-a")).await);
        let line_for = |decision: &str| {
            captured()
                .lines()
                .find(|l| l.contains("namespace decision") && l.contains(decision))
                .map(str::to_owned)
        };
        let allowed = line_for("allowed").expect("an allowed line");
        for needle in ["alice", "team-a", &b.idp.issuer, TEAM_A] {
            assert!(allowed.contains(needle), "{needle} in {allowed}");
        }
        assert!(!allowed.contains("SOME_OTHER_GROUP"), "{allowed}");

        let denied_token = b.token("mallory", &["SOME_OTHER_GROUP"]);
        assert_eq!(
            b.create(&denied_token, Some("infra")).await.0,
            StatusCode::FORBIDDEN
        );
        let omitted = b.token("mallory", &[]);
        assert_eq!(b.create(&omitted, None).await.0, StatusCode::BAD_REQUEST);
        let logs = captured();
        let denied = line_for("denied").expect("a denied line");
        for needle in ["mallory", "infra"] {
            assert!(denied.contains(needle), "{needle} in {denied}");
        }
        assert!(
            logs.contains("omitted"),
            "an omitted namespace is logged as omitted"
        );
        assert!(
            !logs.contains("SOME_OTHER_GROUP"),
            "the caller's groups are not logged"
        );
        for token in [&ok, &denied_token, &omitted] {
            assert!(!logs.contains(token.as_str()), "a token reached a log line");
        }
    }

    // ----- ADR-0057: compare-and-set callers, the slot, the sealed expiry -----

    /// A store whose records are contended: every `update_claim` meets `on_update`, and
    /// everything else is the in-memory store's.
    mod contended {
        use super::*;
        use mediatore_store::{LogAppend, LogChunk, LogStore, MemoryStore, PolicyFloor};

        /// What a contended record does to an update (ADR-0057 decision 5).
        #[derive(Clone, Copy)]
        pub(super) enum OnUpdate {
            /// Every update loses to another write.
            Conflict,
            /// A release lands first, and the update is then refused.
            Release,
        }

        pub(super) struct Contended {
            pub(super) inner: Arc<MemoryStore>,
            pub(super) on_update: OnUpdate,
        }

        #[async_trait::async_trait]
        impl LogStore for Contended {
            async fn append_logs(
                &self,
                rec: &ClaimRecord,
                batch: &LogBatch,
                limits: &LogLimits,
            ) -> Result<LogAppend, StoreError> {
                self.inner.append_logs(rec, batch, limits).await
            }
            async fn read_logs(
                &self,
                claim_uid: Uuid,
                since: Option<u64>,
            ) -> Result<LogChunk, StoreError> {
                self.inner.read_logs(claim_uid, since).await
            }
            async fn delete_logs(&self, claim_uid: Uuid) -> Result<(), StoreError> {
                self.inner.delete_logs(claim_uid).await
            }
            async fn sweep_logs(&self, before: Timestamp) -> Result<usize, StoreError> {
                self.inner.sweep_logs(before).await
            }
        }

        #[async_trait::async_trait]
        impl ClaimStore for Contended {
            async fn put_claim(&self, rec: ClaimRecord) -> Result<(), StoreError> {
                self.inner.put_claim(rec).await
            }
            async fn get_claim(&self, uid: Uuid) -> Result<ClaimRecord, StoreError> {
                self.inner.get_claim(uid).await
            }
            async fn get_claim_by_name(
                &self,
                namespace: &str,
                name: &str,
            ) -> Result<ClaimRecord, StoreError> {
                self.inner.get_claim_by_name(namespace, name).await
            }
            async fn update_claim(&self, rec: ClaimRecord) -> Result<(), StoreError> {
                if let OnUpdate::Release = self.on_update {
                    self.inner.revoke_claim(rec.uid, Timestamp::now()).await?;
                }
                Err(StoreError::Conflict("contended".into()))
            }
            async fn revoke_claim(&self, uid: Uuid, at: Timestamp) -> Result<(), StoreError> {
                self.inner.revoke_claim(uid, at).await
            }
            async fn get_claim_by_node(&self, node_id: &str) -> Result<ClaimRecord, StoreError> {
                self.inner.get_claim_by_node(node_id).await
            }
            async fn list_claims(&self) -> Result<Vec<ClaimRecord>, StoreError> {
                self.inner.list_claims().await
            }
            async fn put_node(&self, rec: NodeRecord) -> Result<(), StoreError> {
                self.inner.put_node(rec).await
            }
            async fn get_node(&self, ek_hash: &str) -> Result<NodeRecord, StoreError> {
                self.inner.get_node(ek_hash).await
            }
            async fn get_node_by_dmi(&self, dmi_uuid: Uuid) -> Result<NodeRecord, StoreError> {
                self.inner.get_node_by_dmi(dmi_uuid).await
            }
            async fn ban_node(&self, ek_hash: &str) -> Result<(), StoreError> {
                self.inner.ban_node(ek_hash).await
            }
            async fn list_nodes(&self) -> Result<Vec<NodeRecord>, StoreError> {
                self.inner.list_nodes().await
            }
            async fn delete_node(&self, ek_hash: &str) -> Result<(), StoreError> {
                self.inner.delete_node(ek_hash).await
            }
            async fn sweep(&self, before: Timestamp) -> Result<usize, StoreError> {
                self.inner.sweep(before).await
            }
            async fn put_session(&self, rec: SessionRecord) -> Result<(), StoreError> {
                self.inner.put_session(rec).await
            }
            async fn take_session(
                &self,
                sandbox_uid: Uuid,
            ) -> Result<Option<SessionRecord>, StoreError> {
                self.inner.take_session(sandbox_uid).await
            }
            async fn take_delegations(
                &self,
                sandbox_uid: Uuid,
            ) -> Result<Vec<SessionRecord>, StoreError> {
                self.inner.take_delegations(sandbox_uid).await
            }
            async fn delete_session(&self, sandbox_uid: Uuid) -> Result<(), StoreError> {
                self.inner.delete_session(sandbox_uid).await
            }
            async fn sweep_sessions(&self, before: Timestamp) -> Result<usize, StoreError> {
                self.inner.sweep_sessions(before).await
            }
            async fn get_policy_floor(
                &self,
                namespace: &str,
                name: &str,
            ) -> Result<Option<PolicyFloor>, StoreError> {
                self.inner.get_policy_floor(namespace, name).await
            }
            async fn advance_policy_floor(
                &self,
                held: Option<&PolicyFloor>,
                next: PolicyFloor,
            ) -> Result<(), StoreError> {
                self.inner.advance_policy_floor(held, next).await
            }
            async fn ping(&self) -> Result<(), StoreError> {
                self.inner.ping().await
            }
        }
    }

    /// A broker over a contended store, with one registered node and its bound, live claim:
    /// the state, the store beneath it, the node's SPIFFE ID and the claim's record.
    async fn contended_broker(
        on_update: contended::OnUpdate,
    ) -> (
        Shared,
        Arc<mediatore_store::MemoryStore>,
        String,
        ClaimRecord,
    ) {
        let inner = mediatore_store::MemoryStore::shared();
        let mut st = placed_state();
        st.store = Arc::new(contended::Contended {
            inner: inner.clone(),
            on_update,
        });
        let st: Shared = Arc::new(st);
        let node = st.naming.node_id("ek1");
        st.store
            .put_node(NodeRecord {
                ek_hash: "ek1".into(),
                node_id: node.clone(),
                dmi_uuid: Uuid::new_v4(),
                hostname: "pool-1".into(),
                provider: None,
                banned: false,
                registered_at: Timestamp::now(),
            })
            .await
            .unwrap();
        let rec = stored(&st, claim(&["grafana"], Some(node.clone()))).await;
        (st, inner, node, rec)
    }

    fn a_guest_report() -> serde_json::Value {
        serde_json::to_value(GuestReport {
            image_digest: format!("sha256:{}", "a".repeat(64)),
            sandbox_ruleset_sha256: "b".repeat(64),
            host_table: HostTable::NotLoaded,
        })
        .unwrap()
    }

    #[tokio::test]
    async fn a_report_after_a_release_is_no_claim_and_writes_nothing() {
        // Released between the lookup of the node's claim and the write of the report.
        let (st, inner, node, rec) = contended_broker(contended::OnUpdate::Release).await;
        let (status, body, _) =
            call(&st, "POST", "/v1/me/report", Some(&node), a_guest_report()).await;
        assert_eq!(
            (status, code(&body)),
            (StatusCode::NOT_FOUND, "no_claim"),
            "what a node with no live claim is told"
        );
        let after = inner.get_claim(rec.uid).await.unwrap();
        let untouched = after.revoked_at.is_some() && after.report.is_none();
        assert!(untouched, "released, and no report was written");
        // Released before the report arrives: the same answer.
        let (status, body, _) =
            call(&st, "POST", "/v1/me/report", Some(&node), a_guest_report()).await;
        assert_eq!((status, code(&body)), (StatusCode::NOT_FOUND, "no_claim"));

        // A record too busy to take it: 503, nothing written, to be sent again.
        let (st, inner, node, rec) = contended_broker(contended::OnUpdate::Conflict).await;
        let (status, body, _) =
            call(&st, "POST", "/v1/me/report", Some(&node), a_guest_report()).await;
        assert_eq!(
            (status, code(&body)),
            (StatusCode::SERVICE_UNAVAILABLE, "record_busy")
        );
        let after = inner.get_claim(rec.uid).await.unwrap();
        let untouched = after.revoked_at.is_none() && after.report.is_none();
        assert!(
            untouched,
            "nothing was written, and the claim is still live"
        );
    }

    #[tokio::test]
    async fn an_exit_whose_record_write_conflicts_still_releases_the_claim() {
        let the_exit = || serde_json::json!({ "code": 0, "restarts": 0 });
        let (st, inner, node, rec) = contended_broker(contended::OnUpdate::Conflict).await;
        let (status, ..) = call(&st, "POST", "/v1/me/exit", Some(&node), the_exit()).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let ended = inner.get_claim(rec.uid).await.unwrap();
        assert!(
            ended.revoked_at.is_some(),
            "the claim is released though its record never took the exit"
        );
        assert!(
            ended.exit.is_none(),
            "the exit is in the log line, not on the record"
        );

        // An exit that finds the claim released under it has nothing left to end: 204.
        let (st, inner, node, rec) = contended_broker(contended::OnUpdate::Release).await;
        let (status, ..) = call(&st, "POST", "/v1/me/exit", Some(&node), the_exit()).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let ended = inner.get_claim(rec.uid).await.unwrap();
        let released_once = ended.revoked_at.is_some() && ended.exit.is_none();
        assert!(released_once, "ended already; nothing was written over it");
    }

    /// A claim under `claude` whose delegation is sealed as the claim API seals one, with
    /// `inside` as the expiry in the envelope and `clear` as the one kept beside it.
    async fn delegated_claim(
        sealer: &dyn Sealer,
        inside: Option<Timestamp>,
        clear: Timestamp,
    ) -> ClaimRecord {
        let mut rec = claim(&["claude"], None);
        let plain = serde_json::to_vec(&DelegationPlain {
            token: Secret(SESSION_TOKEN.into()),
            refresh_token: None,
            expires_at: inside,
        })
        .unwrap();
        let envelope = sealer
            .seal_session(Slot::Delegation("claude"), rec.seal_binding(), &plain)
            .await
            .unwrap();
        rec.delegations.insert(
            "claude".into(),
            DelegatedSession {
                envelope,
                expires_at: Some(clear),
            },
        );
        rec
    }

    #[tokio::test]
    async fn a_delegation_presented_under_another_audience_of_its_sandbox_is_refused() {
        let mut st = placed_state();
        let sealer: Arc<dyn Sealer> = Arc::new(mediatore_store::seal::LocalKeySealer::new([7; 32]));
        st.sealer = Some(sealer.clone());
        let d = st.delegated["claude"].clone();
        let until = Timestamp::now() + SignedDuration::from_hours(1);
        let mut rec = delegated_claim(sealer.as_ref(), Some(until), until).await;
        let uid = rec.uid;
        let own = delegated_token(&st, &rec, &d, "claude".into(), uid, Placement::Gateway).await;
        assert!(own.is_ok(), "its own audience opens it");

        // The contents of `claude`'s Secret put where another audience's are read from.
        let moved = rec.delegations["claude"].clone();
        rec.delegations.insert("other".into(), moved);
        let other = delegated_token(&st, &rec, &d, "other".into(), uid, Placement::Gateway).await;
        let refused = other.is_err_and(|e| e.status == StatusCode::FORBIDDEN);
        assert!(
            refused,
            "another audience of the same sandbox does not open it"
        );

        // The issuer's session put where a delegation is read from.
        let session = sealer
            .seal_session(Slot::Issuer, rec.seal_binding(), b"refresh-token")
            .await
            .unwrap();
        rec.delegations.insert(
            "claude".into(),
            DelegatedSession {
                envelope: session,
                expires_at: Some(until),
            },
        );
        let as_session =
            delegated_token(&st, &rec, &d, "claude".into(), uid, Placement::Gateway).await;
        let refused = as_session.is_err_and(|e| e.status == StatusCode::FORBIDDEN);
        assert!(refused, "the issuer's session is no delegation");
    }

    #[tokio::test]
    async fn a_delegations_clear_expiry_moved_later_issues_nothing_past_the_sealed_one() {
        let mut st = placed_state();
        let sealer: Arc<dyn Sealer> = Arc::new(mediatore_store::seal::LocalKeySealer::new([7; 32]));
        st.sealer = Some(sealer.clone());
        let d = st.delegated["claude"].clone();
        // The clear expiry, on the Secret and the status, says an hour from now.
        let clear = Timestamp::now() + SignedDuration::from_hours(1);

        // Sealed with a minute left: the credential is bounded by that minute.
        let soon = Timestamp::now() + SignedDuration::from_mins(1);
        let rec = delegated_claim(sealer.as_ref(), Some(soon), clear).await;
        let issued =
            delegated_token(&st, &rec, &d, "claude".into(), rec.uid, Placement::Gateway).await;
        let bounded = issued.is_ok_and(|t| t.expires_at <= soon);
        assert!(bounded, "bounded by the sealed expiry, not the clear one");

        // Sealed expiry passed: nothing is issued, whatever the clear one says.
        let past = Timestamp::now() - SignedDuration::from_secs(5);
        let rec = delegated_claim(sealer.as_ref(), Some(past), clear).await;
        let issued =
            delegated_token(&st, &rec, &d, "claude".into(), rec.uid, Placement::Gateway).await;
        let refused = issued.is_err_and(|e| e.status == StatusCode::FORBIDDEN);
        assert!(refused, "the sealed expiry has passed");

        // A format 2 envelope with no expiry inside is not one this broker sealed: never
        // issued from, and the clear value is not read in its place.
        let rec = delegated_claim(sealer.as_ref(), None, clear).await;
        let issued =
            delegated_token(&st, &rec, &d, "claude".into(), rec.uid, Placement::Gateway).await;
        assert!(issued.is_err(), "no expiry inside: fail closed");
    }
}
