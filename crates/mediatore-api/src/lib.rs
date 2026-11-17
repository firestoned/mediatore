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
use chrono::{DateTime, Duration, Utc};
use mediatore_claims::Reconciler;
use mediatore_claims::sandbox::{
    AgentSandbox, AgentSandboxSpec, FrontDoorError, SandboxFrontDoor, SandboxSubject,
    SandboxWorkload, chrono_of, label_selector_of,
};
use mediatore_entra::{IdpError, Validated, Validator};
use mediatore_proto::ek::is_ek_hash;
use mediatore_proto::image::ImageReference;
use mediatore_proto::{
    ClaimEgress, ClaimPhase, ClaimReport, ClaimRequest, ClaimResponse, Credential, Delegation,
    DelegationPlain, Endpoint, EndpointRule, ErrorBody, GatewayCredential,
    GatewayCredentialRequest, GuestExit, GuestReport, HeaderPair, HostTable, InjectRoute, Me,
    NodeRegistered, NodeRegistration, RegistryCredential, Route, Secret, TokenRequest,
    TokenResponse, WorkloadExit, error_code,
};
use mediatore_spire::{EntryManager, Naming};
use mediatore_store::seal::{SealError, Sealed, Sealer};
use mediatore_store::{
    ClaimRecord, ClaimStore, DelegatedSession, NodeRecord, SessionRecord, StoreError,
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
    per_minute: u32,
    buckets: std::sync::Mutex<HashMap<Uuid, (f64, std::time::Instant)>>,
    locks: std::sync::Mutex<HashMap<Uuid, Arc<tokio::sync::Mutex<()>>>>,
}

/// Buckets idle this long are dropped when the table is pruned.
const BUCKET_IDLE: std::time::Duration = std::time::Duration::from_secs(600);
/// Prune the table past this many claims.
const BUCKET_PRUNE_AT: usize = 4096;

impl Limiter {
    /// `per_minute` issues a minute per claim (at least 1).
    #[must_use]
    pub fn new(per_minute: u32) -> Self {
        Self {
            per_minute: per_minute.max(1),
            buckets: std::sync::Mutex::new(HashMap::new()),
            locks: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// The lock a refresh for `claim_uid` runs under.
    pub fn refresh_lock(&self, claim_uid: Uuid) -> Arc<tokio::sync::Mutex<()>> {
        let mut locks = self
            .locks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if locks.len() > BUCKET_PRUNE_AT {
            locks.retain(|_, l| Arc::strong_count(l) > 1);
        }
        locks.entry(claim_uid).or_default().clone()
    }

    /// Spend one issue for `claim_uid` if the bucket has it.
    pub fn allow(&self, claim_uid: Uuid) -> bool {
        let now = std::time::Instant::now();
        let cap = f64::from(self.per_minute);
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if buckets.len() > BUCKET_PRUNE_AT {
            buckets.retain(|_, (_, last)| now.duration_since(*last) < BUCKET_IDLE);
        }
        let (tokens, last) = buckets.entry(claim_uid).or_insert((cap, now));
        let refill = now.duration_since(*last).as_secs_f64() / 60.0 * cap;
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
/// identity (ADR-0028 decision 4, amending ADR-0007 decision 2), and nothing else, not
/// even another broker. Which routes each may use is the handlers' business: the gateway
/// reaches its own route and nothing a node or a claim reaches.
pub fn sandbox_authorizer(naming: Naming) -> mediatore_tls::Authorizer {
    Arc::new(move |id: &mediatore_tls::SpiffeId| {
        let id = id.to_string();
        naming.node_ek_from(&id).is_some()
            || naming.claim_uid_from(&id).is_some()
            || naming.is_gateway(&id)
    })
}

// ---------- user-facing ----------

/// Validate the caller's bearer token.
async fn caller(st: &AppState, headers: &HeaderMap) -> Result<Validated, ApiError> {
    let token = bearer(headers)?;
    st.validator.validate(token).await.map_err(|e| match e {
        mediatore_entra::IdpError::Forbidden(d) => ApiError::forbidden(d),
        mediatore_entra::IdpError::NotImplemented(w) => ApiError::not_implemented(w),
        other => ApiError::unauthorized(other.to_string()),
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
    if let Some(bad) = req.audiences.iter().find(|a| !st.audiences.contains(a)) {
        return Err(ApiError::bad_request("unknown_audience", bad.clone()));
    }
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
    // The dev binder writes the record itself, so the envelope binds to the record's UID.
    let refresh = match (sealer, session) {
        (Some(sealer), Some(token)) => Some(
            sealer
                .seal(uid, token.0.as_bytes())
                .await
                .map_err(seal_error)?,
        ),
        _ => None,
    };
    let mut dev_delegations = BTreeMap::new();
    if let Some(sealer) = sealer {
        for d in delegations {
            dev_delegations.insert(
                d.audience.clone(),
                DelegatedSession {
                    envelope: seal_delegation(sealer, uid, d).await?,
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
            created_at: Utc::now(),
            expires_at: None,
            revoked_at: None,
            sandbox_uid: None,
            policy_uid: None,
            bundle_version: None,
            report: None,
            exit: None,
            delegations: dev_delegations,
            namespace,
        })
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    tracing::info!(subject = %validated.subject.id, pool = %pool_of(req), %uid, "claim created");

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
            && expires_at < Utc::now() + Duration::seconds(i64::from(req.ttl_seconds))
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

/// Seal a delegation's plaintext for `binding` (ADR-0035 decision 3).
async fn seal_delegation(
    sealer: &dyn Sealer,
    binding: Uuid,
    d: &Delegation,
) -> Result<Sealed, ApiError> {
    let plain = DelegationPlain {
        token: d.token.clone().unwrap_or_else(|| Secret(String::new())),
        refresh_token: d.refresh_token.clone(),
    };
    let bytes = serde_json::to_vec(&plain).map_err(|e| ApiError::internal(e.to_string()))?;
    sealer.seal(binding, &bytes).await.map_err(seal_error)
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
    tracing::info!(subject = %validated.subject.id, pool = %pool_of(req), sandbox = %name, %namespace, "sandbox created");
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
    credential_expires_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    ttl_seconds: u32,
) -> DateTime<Utc> {
    let claim_end = created_at + Duration::seconds(i64::from(ttl_seconds));
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
        let refresh = seal_delegation(sealer, sandbox_uid, d)
            .await
            .map_err(|e| anyhow::anyhow!("sealing the delegation failed: {}", e.body.error))?;
        let created_at = Utc::now();
        let expires_at = parked_expiry(d.expires_at, created_at, created.spec.ttl_seconds);
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

/// Seal `token` with the sandbox's UID and park it until the reconciler creates the record.
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
    let refresh = sealer.seal(sandbox_uid, token.0.as_bytes()).await?;
    st.store
        .put_session(SessionRecord {
            sandbox_uid,
            subject: validated.subject.clone(),
            issuer: validated.issuer.url.clone(),
            refresh,
            created_at: Utc::now(),
            audience: None,
            expires_at: None,
        })
        .await?;
    tracing::info!(%sandbox_uid, subject = %validated.subject.id, "session parked");
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
        expires_at: st.expires_at.as_ref().and_then(chrono_of),
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

/// Fetch a sandbox by name in its namespace and require the caller to be in that namespace's
/// groups and to be its subject (ADR-0046 decision 5). A namespace the caller may not use is
/// `404`, before any read; a sandbox that does not exist and one that belongs to someone else
/// are told apart (404 / 403): the names are random and the subject check is the control.
async fn owned_sandbox(
    st: &AppState,
    headers: &HeaderMap,
    namespace: Option<&str>,
    name: &str,
) -> Result<(String, AgentSandbox), ApiError> {
    let validated = caller(st, headers).await?;
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
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .with_state(state)
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
            registered_at: Utc::now(),
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
    let mut rec = match claim_of_node_peer(&st, &headers, peer.as_ref().map(|e| &e.0)).await {
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
    rec.exit = Some(WorkloadExit {
        exited_at: Utc::now(),
        exit: body,
    });
    st.store
        .update_claim(rec.clone())
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
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
    let mut rec = claim_of_node_peer(&st, &headers, peer.as_ref().map(|e| &e.0)).await?;
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
    rec.report = Some(ClaimReport {
        reported_at: Utc::now(),
        report: body,
    });
    st.store
        .update_claim(rec)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(StatusCode::NO_CONTENT)
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
    let mut routes: Vec<Route> = rec
        .audiences
        .iter()
        .flat_map(|a| {
            st.egress.get(a).into_iter().flatten().map(|e| Route {
                audience: Some(a.clone()),
                endpoint: e.clone(),
                rules: st.rules.get(a).cloned().unwrap_or_default(),
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
    pub ttl: Duration,
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
    pub ttl: Duration,
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
            expires_at: Utc::now() + self.ttl,
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
    let Some(bundle) = pe.bundles.by_uid(uid, Utc::now()) else {
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
    rec.audiences
        .iter()
        .filter_map(|a| st.inject.get(a))
        .flatten()
        .map(|r| r.endpoint.clone())
        .collect()
}

/// The union of the claim's audiences' `egress`, sorted and deduplicated, without the hosts a
/// gateway-placed audience binds to the inject path: a `CONNECT` tunnel to such a host would go
/// around the rules the inject listener enforces (ADR-0040).
fn audience_egress(st: &AppState, rec: &ClaimRecord) -> Vec<Endpoint> {
    let placed = placed_endpoints(st, rec);
    let mut egress: Vec<Endpoint> = rec
        .audiences
        .iter()
        .filter_map(|a| st.egress.get(a))
        .flatten()
        .filter(|e| !placed.contains(e))
        .cloned()
        .collect();
    egress.sort();
    egress.dedup();
    egress
}

/// `GET /v1/gateway/claims/{uid}`: what a gateway may let the claim reach (ADR-0028
/// decision 4). The peer must be the gateway identity, `spiffe://<td>/gateway`: a node, a
/// claim, even the claim asked about, is `403`. A claim the store does not know, one not
/// bound (no deadline yet, so no identity for a tunnel to carry), one released or past its
/// deadline is `404`, the one answer the gateway takes as "deny, and drop what was cached".
async fn claim_egress(
    State(st): State<Shared>,
    headers: HeaderMap,
    peer: Option<Extension<PeerSpiffeId>>,
    Path(uid): Path<String>,
) -> Result<Json<ClaimEgress>, ApiError> {
    let peer = peer_spiffe_id(&st, peer.as_ref().map(|e| &e.0), &headers)?;
    if !st.naming.is_gateway(&peer) {
        return Err(ApiError::forbidden("peer is not the gateway identity"));
    }
    let uid = Uuid::parse_str(&uid)
        .map_err(|_| ApiError::bad_request("invalid_claim_uid", "claim uid must be a UUID"))?;
    let unknown = || ApiError::not_found("no live claim with this uid");
    let rec = st.store.get_claim(uid).await.map_err(|e| match e {
        StoreError::NotFound(_) => unknown(),
        other => ApiError::internal(other.to_string()),
    })?;
    let now = Utc::now();
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
    let mut routes: Vec<InjectRoute> = rec
        .audiences
        .iter()
        .filter_map(|a| st.inject.get(a))
        .flatten()
        .cloned()
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
type RefreshOutcome = (String, Option<Validated>, Option<(Secret, DateTime<Utc>)>);

/// What a refresh left for the issue: the groups to mint (empty when the fresh token was
/// not one mediatore can read), and for an audience Entra serves, its token.
struct Fresh {
    groups: Vec<String>,
    obo: Option<(Secret, DateTime<Utc>)>,
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
        .unseal(rec.seal_binding(), envelope)
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
    let envelope = sealer
        .seal(rec.seal_binding(), refresh_token.as_bytes())
        .await
        .map_err(seal_error)?;
    let mut updated = rec.clone();
    updated.refresh = Some(envelope);
    st.store
        .update_claim(updated)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(Fresh {
        groups: validated.map(|v| v.groups).unwrap_or_default(),
        obo,
    })
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
        return Ok(sec.response(audience, rec.subject));
    }
    // ADR-0013 decision 4, ADR-0016 decision 2: a session issuer's record is refreshed
    // upstream first, for the audience's resource. One refresh at a time per claim, over
    // the record as it is once the lock is held: the previous one may have rotated the
    // envelope, or released the claim.
    let obo = st.obo_audiences.iter().any(|a| a == &audience);
    let issuer = st.validator.issuer_named(&rec.subject.issuer);
    if obo && issuer.is_none_or(|i| i.entra.is_none()) {
        return Err(ApiError::forbidden(
            "audience is served On-Behalf-Of and this claim has no Entra session",
        ));
    }
    let fresh = match issuer {
        Some(issuer) if issuer.session.is_some() || issuer.entra.is_some() => {
            let lock = st.limiter.refresh_lock(claim_uid);
            let _held = lock.lock().await;
            let rec = st
                .store
                .get_claim(claim_uid)
                .await
                .map_err(|_| ApiError::forbidden("unknown claim"))?;
            if !rec.is_live(Utc::now()) {
                return Err(ApiError::forbidden("claim revoked or expired"));
            }
            refresh_session(st, &rec, issuer, &audience, obo).await?
        }
        _ => Fresh {
            groups: vec![],
            obo: None,
        },
    };
    if let Some((token, expires_at)) = fresh.obo {
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
    let minted = sts
        .mint(&MintRequest {
            subject: &rec.subject,
            actor_spiffe_id: actor,
            claim_uid,
            audience: &audience,
            groups: fresh.groups,
            ttl: Duration::minutes(15).min(sts.max_ttl()),
        })
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
    if !rec.is_live(Utc::now()) {
        return Err(ApiError::forbidden("claim revoked or expired"));
    }
    if !rec.audiences.iter().any(|a| a == audience) {
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
    let now = Utc::now();
    let mut expires_at = now + d.ttl;
    if let Some(e) = held.expires_at {
        expires_at = expires_at.min(e);
    }
    if let Some(e) = rec.expires_at {
        expires_at = expires_at.min(e);
    }
    if expires_at <= now {
        return Err(ApiError::forbidden("the delegated credential has expired"));
    }
    let plain = sealer
        .unseal(rec.seal_binding(), &held.envelope)
        .await
        .map_err(seal_error)?;
    let plain: DelegationPlain = serde_json::from_slice(&plain)
        .map_err(|_| ApiError::internal("the delegation envelope is not what was sealed"))?;
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
        .and_then(|uid| pe.bundles.by_uid(uid, Utc::now()))
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
/// the gateway's authorizer alone (ADR-0040 decision 2). The peer must be the gateway
/// identity, as for `GET /v1/gateway/claims/{uid}`: a node, a claim, even the claim asked about,
/// is `403`. A claim that is unknown, unbound, released or past its deadline is `404`, the answer
/// the gateway takes as "drop what was cached". The gate then is `POST /v1/token`'s (the claim
/// names the audience, the per-claim rate limit) plus the policy bundle under `enforce`, the
/// audience must be gateway-placed, and the credential comes from the same per-backend code.
/// It is built for this answer and kept nowhere; each issue is one audit line that names the
/// claim, audience, subject, backend and expiry, never the credential.
async fn gateway_credential(
    State(st): State<Shared>,
    headers: HeaderMap,
    peer: Option<Extension<PeerSpiffeId>>,
    Path(uid): Path<String>,
    Json(req): Json<GatewayCredentialRequest>,
) -> Result<Json<GatewayCredential>, ApiError> {
    let peer = peer_spiffe_id(&st, peer.as_ref().map(|e| &e.0), &headers)?;
    if !st.naming.is_gateway(&peer) {
        return Err(ApiError::forbidden("peer is not the gateway identity"));
    }
    let claim_uid = Uuid::parse_str(&uid)
        .map_err(|_| ApiError::bad_request("invalid_claim_uid", "claim uid must be a UUID"))?;
    let unknown = || ApiError::not_found("no live claim with this uid");
    let rec = st.store.get_claim(claim_uid).await.map_err(|e| match e {
        StoreError::NotFound(_) => unknown(),
        other => ApiError::internal(other.to_string()),
    })?;
    if rec.expires_at.is_none() || !rec.is_live(Utc::now()) {
        tracing::debug!(%claim_uid, "gateway asked for a credential of a claim that is not live");
        return Err(unknown());
    }
    let audience = req.audience;
    if !rec.audiences.iter().any(|a| a == &audience) {
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
    let credential = GatewayCredential::from_token_response(issued, Utc::now());
    tracing::info!(%claim_uid, audience = %credential.audience, subject = %credential.subject.id, backend, expires_at = %credential.expires_at, "gateway credential issued");
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
            validator: Validator::new(vec![]),
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
                ttl: Duration::minutes(15),
            },
        );
        st.secrets.insert(
            "grafana".into(),
            AudienceSecret {
                value: Secret("grafana-key".into()),
                header: "authorization".into(),
                extra_headers: vec![],
                ttl: Duration::minutes(15),
            },
        );
        st.delegated.insert(
            "claude".into(),
            DelegatedAudience {
                header: "authorization".into(),
                extra_headers: vec![],
                ttl: Duration::minutes(15),
                basic: false,
            },
        );
        st.sts = Some(
            Sts::new(
                "https://mediatore.test",
                "t-1",
                // A key made for this test: no key lives in the source (the testkit's generator).
                mediatore_testkit::entra::fresh_p256_key_pem().as_bytes(),
                Duration::minutes(15),
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
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + Duration::minutes(15)),
            revoked_at: None,
            sandbox_uid: None,
            policy_uid: None,
            bundle_version: None,
            report: None,
            exit: None,
            delegations: BTreeMap::new(),
            namespace: "sandboxes".into(),
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

    fn gateway_peer() -> String {
        naming().gateway_id()
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
        let before = Utc::now();
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
            c.expires_at > before && c.expires_at <= Utc::now() + Duration::seconds(cap),
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
        })
        .unwrap();
        let envelope = sealer.seal(rec.seal_binding(), &plain).await.unwrap();
        rec.delegations.insert(
            "claude".into(),
            DelegatedSession {
                envelope,
                expires_at: Some(Utc::now() + Duration::hours(1)),
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
        assert!(c.expires_at <= Utc::now() + Duration::seconds(300));
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
                ttl: Duration::minutes(15),
                basic: true,
            },
        );
        let sealer: Arc<dyn Sealer> = Arc::new(mediatore_store::seal::LocalKeySealer::new([7; 32]));
        let mut rec = claim(&["claude"], None);
        let plain = serde_json::to_vec(&DelegationPlain {
            token: Secret("alice:p@ss:word".into()),
            refresh_token: None,
        })
        .unwrap();
        let envelope = sealer.seal(rec.seal_binding(), &plain).await.unwrap();
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
        assert!(c.expires_at <= Utc::now() + Duration::seconds(300));
    }

    #[test]
    fn a_parked_credential_never_outlives_the_claims_ttl() {
        use chrono::TimeZone;
        // The operator's rule, 2026-11-15: a delegated secret is stored no longer than the claim's TTL. The envelope's own
        // expiry is the least of the credential's (when the caller knows it) and the claim's creation plus its TTL.
        let created = Utc.timestamp_opt(1_800_000_000, 0).unwrap();
        let ttl_end = created + Duration::seconds(900);
        assert_eq!(
            parked_expiry(None, created, 900),
            ttl_end,
            "no expiry known: the claim's TTL"
        );
        assert_eq!(
            parked_expiry(Some(created + Duration::hours(5)), created, 900),
            ttl_end,
            "a credential that outlives the claim is still stored only that long"
        );
        let sooner = created + Duration::seconds(300);
        assert_eq!(
            parked_expiry(Some(sooner), created, 900),
            sooner,
            "a credential that dies first is stored only until it does"
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
        assert!(c.expires_at <= Utc::now() + Duration::seconds(300));
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
    async fn only_the_gateway_identity_may_ask_and_a_refusal_never_carries_the_credential() {
        let st: Shared = Arc::new(placed_state());
        let rec = stored(&st, claim(&["anthropic"], None)).await;
        let n = naming();
        let not_gateways = [
            n.claim_id(rec.uid),
            n.node_id("ekhash"),
            n.broker_id(),
            "spiffe://other.test/gateway".to_owned(),
            format!("spiffe://{TD}/gateway/extra"),
        ];
        for peer in &not_gateways {
            let (status, body, text) = ask(&st, rec.uid, Some(peer), "anthropic").await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{peer}: {text}");
            assert_eq!(code(&body), "forbidden", "{peer}");
            assert!(!text.contains(SECRET_VALUE), "{peer}: {text}");
        }
        let (status, _, text) = ask(&st, rec.uid, None, "anthropic").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "no peer identity: {text}");
        assert!(!text.contains(SECRET_VALUE));
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
        revoked.revoked_at = Some(Utc::now());
        let revoked = stored(&st, revoked).await;
        let mut expired = claim(&["anthropic"], None);
        expired.expires_at = Some(Utc::now() - Duration::seconds(1));
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
        })
        .unwrap();
        expired.delegations.insert(
            "claude".into(),
            DelegatedSession {
                envelope: sealer.seal(expired.seal_binding(), &plain).await.unwrap(),
                expires_at: Some(Utc::now() - Duration::seconds(5)),
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
        let now = Utc::now();
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
                ttl: Duration::minutes(5),
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
                registered_at: Utc::now(),
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
        })
        .unwrap();
        delegated.delegations.insert(
            "claude".into(),
            DelegatedSession {
                envelope: sealer.seal(delegated.seal_binding(), &plain).await.unwrap(),
                expires_at: Some(Utc::now() + Duration::hours(1)),
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
        let far = Utc::now() + Duration::days(1);
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
                registered_at: Utc::now(),
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
}
