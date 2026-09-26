//! HTTP surface.
//!
//! Two routers, meant to be served on two listeners:
//! * [`user_router`]: `POST/GET/DELETE /v1/claims`, authenticated by an upstream bearer token.
//! * [`sandbox_router`]: `POST /v1/nodes`, `GET /v1/me`, `POST /v1/token`, authenticated by
//!   the peer's SPIFFE ID from mTLS.
//!
//! mTLS termination with SPIFFE X.509 SVIDs is the next step; until then the sandbox router
//! reads the peer identity from `x-mediatore-peer-spiffe-id`, and only when `dev_mode` is on.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{Duration, Utc};
use mediatore_claims::Reconciler;
use mediatore_entra::{Validated, Validator};
use mediatore_proto::{
    ClaimPhase, ClaimRequest, ClaimResponse, ErrorBody, Me, NodeRegistered, NodeRegistration,
    TokenRequest, TokenResponse,
};
use mediatore_spire::{EntryManager, Naming};
use mediatore_store::{ClaimRecord, ClaimStore, NodeRecord, StoreError};
use mediatore_sts::{MintRequest, Sts};
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
    /// Accept a peer-identity header instead of mTLS. Never in production.
    pub dev_mode: bool,
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
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(self.body)).into_response()
    }
}

/// Health for probes.
async fn healthz() -> &'static str {
    "ok"
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
fn peer_spiffe_id(st: &AppState, headers: &HeaderMap) -> Result<String, ApiError> {
    if st.dev_mode {
        return headers
            .get("x-mediatore-peer-spiffe-id")
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned)
            .ok_or_else(|| ApiError::unauthorized("no peer identity (dev header missing)"));
    }
    Err(ApiError::not_implemented("SPIFFE mTLS peer identity"))
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
    let validated = caller(&st, &headers).await?;
    if let Some(bad) = req.audiences.iter().find(|a| !st.audiences.contains(a)) {
        return Err(ApiError::bad_request("unknown_audience", bad.clone()));
    }
    if req.ttl_seconds == 0 {
        return Err(ApiError::bad_request(
            "invalid_ttl",
            "ttl_seconds must be positive",
        ));
    }
    if !st.dev_mode {
        // Next: create the VirtualMachineClaim via kube-rs and let the watcher bind it.
        return Err(ApiError::not_implemented(
            "claim creation via the kubernetes api",
        ));
    }

    let uid = Uuid::new_v4();
    let name = format!(
        "claim-{}",
        &uid.simple().to_string()[..CLAIM_NAME_SUFFIX_LEN]
    );
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
            refresh_ciphertext: None,
            created_at: Utc::now(),
            expires_at: None,
            revoked_at: None,
        })
        .await
        .map_err(|e| ApiError::internal(e.to_string()))?;
    tracing::info!(subject = %validated.subject.id, pool = %req.pool_ref, %uid, "claim created");

    // Dev binder: stands in for banlieue's claim controller and pool. A registered free
    // node is "Ready pool member"; binding is immediate.
    if let Some(node) = free_node(&st).await? {
        reconciler(&st)
            .bind(uid, &node.node_id)
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
            expires_at: rec.expires_at,
            addresses: vec![],
        }),
    ))
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
        .map_err(|e| ApiError::new(StatusCode::NOT_FOUND, "not_found", Some(e.to_string())))?;
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
    let rec = owned_claim(&st, &headers, &name).await?;
    Ok(Json(ClaimResponse {
        name: rec.name.clone(),
        uid: Some(rec.uid),
        phase: phase_of(&rec),
        expires_at: rec.expires_at,
        addresses: vec![],
    }))
}

async fn delete_claim(
    State(st): State<Shared>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
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
    Json(reg): Json<NodeRegistration>,
) -> Result<Json<NodeRegistered>, ApiError> {
    let peer = peer_spiffe_id(&st, &headers)?;
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
        && let Err(e) = reconciler(&st).bind(pending.uid, &agent_id).await
    {
        tracing::warn!(uid = %pending.uid, error = %e, "dev bind on registration failed");
    }

    Ok(Json(NodeRegistered { node_id: agent_id }))
}

async fn me(State(st): State<Shared>, headers: HeaderMap) -> Result<Json<Me>, ApiError> {
    let peer = peer_spiffe_id(&st, &headers)?;
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
    Ok(Json(Me {
        claim_uid: rec.uid,
        subject: rec.subject,
        expires_at,
        workload: rec.workload,
    }))
}

async fn token(
    State(st): State<Shared>,
    headers: HeaderMap,
    Json(req): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, ApiError> {
    let peer = peer_spiffe_id(&st, &headers)?;
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
    let Some(sts) = st.sts.as_ref() else {
        return Err(ApiError::not_implemented("entra-obo backend"));
    };
    let minted = sts
        .mint(&MintRequest {
            subject: &rec.subject,
            actor_spiffe_id: &peer,
            claim_uid,
            audience: &req.audience,
            groups: vec![],
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
