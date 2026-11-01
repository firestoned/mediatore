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
//!   the peer's SPIFFE ID from mTLS.
//!
//! The sandbox router takes the peer identity from the [`PeerSpiffeId`] extension that
//! `mediatore_tls::serve` attaches after verifying the client certificate (ADR-0007). Only a
//! `dev_mode` server, on a plain loopback listener, reads it from `x-mediatore-peer-spiffe-id`
//! instead.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use banlieue_api::common::LocalObjectReference;
use chrono::{DateTime, Duration, Utc};
use mediatore_claims::Reconciler;
use mediatore_claims::sandbox::{
    AgentSandbox, AgentSandboxSpec, FrontDoorError, SandboxFrontDoor, SandboxSubject,
    SandboxWorkload, chrono_of,
};
use mediatore_entra::{IdpError, Validated, Validator};
use mediatore_proto::ek::is_ek_hash;
use mediatore_proto::image::ImageReference;
use mediatore_proto::{
    ClaimPhase, ClaimRequest, ClaimResponse, Endpoint, EndpointRule, ErrorBody, Me, NodeRegistered,
    NodeRegistration, RegistryCredential, Route, Secret, TokenRequest, TokenResponse,
};
use mediatore_spire::{EntryManager, Naming};
use mediatore_store::seal::{SealError, Sealer};
use mediatore_store::{ClaimRecord, ClaimStore, NodeRecord, SessionRecord, StoreError};
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
    /// Per registry host (as the API reaches it), the operator's pull credential
    /// (`registries[]`); `GET /v1/me` hands the guest the one its claim's image names
    /// (ADR-0022).
    pub registries: BTreeMap<String, RegistryCredential>,
    /// `AgentSandbox` resources through the Kubernetes API (ADR-0008); `None` under
    /// `dev_mode`, where the store and the dev binder stand in. Absent outside `dev_mode`,
    /// the claim endpoints fail closed with `501`.
    pub sandboxes: Option<Arc<dyn SandboxFrontDoor>>,
    /// Namespace `POST /v1/claims` creates sandboxes in; the pool must live there.
    pub sandbox_namespace: String,
    /// Seals refresh material before it reaches the store (ADR-0012 decision 3); `None`
    /// until `store.sealing` is configured. Roadmap 04 brings its first caller.
    pub sealer: Option<Arc<dyn Sealer>>,
    /// Per-claim limit on `POST /v1/token` (ADR-0013 decision 5).
    pub limiter: Limiter,
    /// Accept a peer-identity header instead of mTLS. Never in production.
    pub dev_mode: bool,
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
/// this trust domain, parsed by the same rules the handlers apply, and nothing else, not
/// even another broker (ADR-0007 decision 2).
pub fn sandbox_authorizer(naming: Naming) -> mediatore_tls::Authorizer {
    Arc::new(move |id: &mediatore_tls::SpiffeId| {
        let id = id.to_string();
        naming.node_ek_from(&id).is_some() || naming.claim_uid_from(&id).is_some()
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
    if let Some(bad) = req.audiences.iter().find(|a| !st.audiences.contains(a)) {
        return Err(ApiError::bad_request("unknown_audience", bad.clone()));
    }
    // The guest would refuse it at bind (ADR-0021); say so now (ADR-0022 decision 4).
    req.workload
        .image
        .parse::<ImageReference>()
        .map_err(|e| ApiError::bad_request("invalid_workload_image", e))?;
    let session = session_for(&st, &validated, &req, &bearer_token).await?;
    let sealer = match (session.is_some(), st.sealer.as_ref()) {
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
            &req,
            sealer.as_deref(),
            session.as_ref(),
        )
        .await;
    }

    let uid = Uuid::new_v4();
    // The dev binder writes the record itself, so the envelope binds to the record's UID.
    let refresh = match (sealer.as_deref(), &session) {
        (Some(sealer), Some(token)) => Some(
            sealer
                .seal(uid, token.0.as_bytes())
                .await
                .map_err(seal_error)?,
        ),
        _ => None,
    };
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
        })
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    tracing::info!(subject = %validated.subject.id, pool = %req.pool_ref, %uid, "claim created");

    // Dev binder: stands in for banlieue's claim controller and pool. A registered free
    // node is "Ready pool member"; binding is immediate.
    if let Some(node) = free_node(&st).await? {
        reconciler(&st)
            .bind(uid, &node.ek_hash)
            .await
            .map_err(|e| ApiError::internal(e.to_string()))?;
    }

    let rec = st
        .store
        .get_claim(uid)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok((
        StatusCode::CREATED,
        Json(ClaimResponse {
            name,
            uid: Some(uid),
            phase: phase_of(&rec),
            ready: rec.entry_id.is_some() && rec.revoked_at.is_none(),
            expires_at: rec.expires_at,
            addresses: vec![],
        }),
    ))
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

/// The production front door (ADR-0008 decision 4): the request becomes an `AgentSandbox`
/// in the configured namespace, `spec.subject` from the validated token. mediatore's
/// `ServiceAccount` is exempt from the subject admission check for exactly this, so the
/// token validation above is the control.
async fn create_sandbox(
    st: &AppState,
    validated: &Validated,
    name: &str,
    req: &ClaimRequest,
    sealer: Option<&dyn Sealer>,
    session: Option<&Secret>,
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
            pool_ref: LocalObjectReference {
                name: req.pool_ref.clone(),
            },
            ttl_seconds: req.ttl_seconds,
            audiences: req.audiences.clone(),
            workload: SandboxWorkload::from(&req.workload),
            policy_ref: req
                .policy_ref
                .clone()
                .map(|name| LocalObjectReference { name }),
        },
    );
    sandbox.metadata.namespace = Some(st.sandbox_namespace.clone());
    let created = front.create(sandbox).await?;
    tracing::info!(subject = %validated.subject.id, pool = %req.pool_ref, sandbox = %name, namespace = %st.sandbox_namespace, "sandbox created");
    // ADR-0013 decision 2: the session is parked under the sandbox's UID, sealed with it,
    // before the caller hears back; a failure here undoes the resource.
    if let (Some(sealer), Some(token)) = (sealer, session)
        && let Err(e) = park_session(st, sealer, &created, validated, token).await
    {
        tracing::warn!(sandbox = %name, error = %e, "session not parked; sandbox withdrawn");
        if let Err(d) = front.delete(&st.sandbox_namespace, name).await {
            tracing::warn!(sandbox = %name, error = %d, "sandbox withdrawal failed");
        }
        return Err(match e.downcast::<SealError>() {
            Ok(seal) => seal_error(seal),
            Err(_) => ApiError::internal("session could not be stored"),
        });
    }
    Ok((StatusCode::CREATED, Json(response_of(&created))))
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
        expires_at: st.expires_at.as_ref().and_then(chrono_of),
        addresses: st.addresses,
    }
}

/// Fetch a sandbox by name and require the caller to be its subject. A sandbox that does
/// not exist and one that belongs to someone else are told apart (404 / 403): the names
/// are random and the subject check is the control, not obscurity.
async fn owned_sandbox(
    st: &AppState,
    headers: &HeaderMap,
    name: &str,
) -> Result<AgentSandbox, ApiError> {
    let validated = caller(st, headers).await?;
    let Some(front) = st.sandboxes.as_ref() else {
        return Err(ApiError::not_implemented(
            "claim lookup via the kubernetes api",
        ));
    };
    let sb = front
        .get(&st.sandbox_namespace, name)
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no sandbox named {name}")))?;
    if sb.spec.subject.issuer != validated.subject.issuer
        || sb.spec.subject.id != validated.subject.id
    {
        return Err(ApiError::forbidden("claim belongs to another subject"));
    }
    Ok(sb)
}

/// Fetch a claim by name and require the caller to be its subject.
async fn owned_claim(
    st: &AppState,
    headers: &HeaderMap,
    name: &str,
) -> Result<ClaimRecord, ApiError> {
    let validated = caller(st, headers).await?;
    let rec = st
        .store
        .get_claim_by_name(name)
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
) -> Result<Json<ClaimResponse>, ApiError> {
    if !st.dev_mode {
        let sb = owned_sandbox(&st, &headers, &name).await?;
        return Ok(Json(response_of(&sb)));
    }
    let rec = owned_claim(&st, &headers, &name).await?;
    Ok(Json(ClaimResponse {
        name: rec.name.clone(),
        uid: Some(rec.uid),
        phase: phase_of(&rec),
        ready: rec.entry_id.is_some() && rec.revoked_at.is_none(),
        expires_at: rec.expires_at,
        addresses: vec![],
    }))
}

async fn delete_claim(
    State(st): State<Shared>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    if !st.dev_mode {
        let sb = owned_sandbox(&st, &headers, &name).await?;
        // The reconciler's finalizer retracts the entry, revokes the record and deletes
        // the claim (ADR-0008 decision 10); the API only asks.
        st.sandboxes
            .as_ref()
            .ok_or_else(|| ApiError::not_implemented("claim deletion via the kubernetes api"))?
            .delete(&st.sandbox_namespace, &name)
            .await?;
        tracing::info!(sandbox = %name, subject = %sb.spec.subject.id, "sandbox deleted by its subject");
        return Ok(StatusCode::NO_CONTENT);
    }
    let rec = owned_claim(&st, &headers, &name).await?;
    reconciler(&st)
        .release(rec.uid)
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    tracing::info!(uid = %rec.uid, "claim released by its subject");
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

async fn me(
    State(st): State<Shared>,
    headers: HeaderMap,
    peer: Option<Extension<PeerSpiffeId>>,
) -> Result<Json<Me>, ApiError> {
    let peer = peer_spiffe_id(&st, peer.as_ref().map(|e| &e.0), &headers)?;
    let ek_hash = st
        .naming
        .node_ek_from(&peer)
        .ok_or_else(|| ApiError::forbidden("peer is not a node identity"))?;
    let node = st
        .store
        .get_node(&ek_hash)
        .await
        .map_err(|_| ApiError::forbidden("node not registered"))?;
    let rec = st
        .store
        .get_claim_by_node(&node.node_id)
        .await
        .map_err(|_| {
            ApiError::new(
                StatusCode::NOT_FOUND,
                "no_claim",
                Some("no live claim bound to this node".into()),
            )
        })?;
    let expires_at = rec
        .expires_at
        .ok_or_else(|| ApiError::internal("bound claim has no deadline".to_owned()))?;
    // The destinations are the claim's audiences' (ADR-0020 decision 2): an audience that
    // declares none contributes none, and the jail reaches the broker only.
    let mut egress: Vec<Endpoint> = rec
        .audiences
        .iter()
        .filter_map(|a| st.egress.get(a))
        .flatten()
        .cloned()
        .collect();
    egress.sort();
    egress.dedup();
    // The proxy's routes (ADR-0025 decision 4): the same destinations, each with its
    // audience and that audience's rules; the config guarantees one audience per endpoint.
    let mut routes: Vec<Route> = rec
        .audiences
        .iter()
        .flat_map(|a| {
            st.egress.get(a).into_iter().flatten().map(|e| Route {
                audience: a.clone(),
                endpoint: e.clone(),
                rules: st.rules.get(a).cloned().unwrap_or_default(),
                ca_pem: st.cas.get(a).cloned(),
            })
        })
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
    }))
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
    let peer = peer_spiffe_id(&st, peer.as_ref().map(|e| &e.0), &headers)?;
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
    if !rec.audiences.iter().any(|a| a == &req.audience) {
        return Err(ApiError::bad_request("unknown_audience", req.audience));
    }
    if !st.limiter.allow(claim_uid) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
            Some("too many token requests for this claim".to_owned()),
        ));
    }
    // ADR-0013 decision 4, ADR-0016 decision 2: a session issuer's record is refreshed
    // upstream first, for the audience's resource. One refresh at a time per claim, over
    // the record as it is once the lock is held: the previous one may have rotated the
    // envelope, or released the claim.
    let obo = st.obo_audiences.iter().any(|a| a == &req.audience);
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
            refresh_session(&st, &rec, issuer, &req.audience, obo).await?
        }
        _ => Fresh {
            groups: vec![],
            obo: None,
        },
    };
    if let Some((token, expires_at)) = fresh.obo {
        tracing::info!(%claim_uid, audience = %req.audience, subject = %rec.subject.id, %expires_at, "token issued on behalf of the subject");
        return Ok(Json(TokenResponse {
            access_token: token.0,
            token_type: "Bearer".into(),
            expires_at,
            audience: req.audience,
            subject: rec.subject,
        }));
    }
    let Some(sts) = st.sts.as_ref() else {
        return Err(ApiError::not_implemented("sts backend not configured"));
    };
    let minted = sts
        .mint(&MintRequest {
            subject: &rec.subject,
            actor_spiffe_id: &peer,
            claim_uid,
            audience: &req.audience,
            groups: fresh.groups,
            ttl: Duration::minutes(15).min(sts.max_ttl()),
        })
        .map_err(|e| ApiError::internal(e.to_string()))?;
    tracing::info!(%claim_uid, audience = %req.audience, subject = %rec.subject.id, "token issued");
    Ok(Json(TokenResponse {
        access_token: minted.token,
        token_type: "Bearer".into(),
        expires_at: minted.expires_at,
        audience: req.audience,
        subject: rec.subject,
    }))
}

/// Router for attested VMs and their jailed workloads.
pub fn sandbox_router(state: Shared) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/nodes", post(register_node))
        .route("/v1/me", get(me))
        .route("/v1/token", post(token))
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
}
