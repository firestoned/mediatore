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
use mediatore_entra::Validator;
use mediatore_proto::{
    ClaimRequest, ClaimResponse, ErrorBody, Me, NodeRegistered, NodeRegistration, TokenRequest,
    TokenResponse,
};
use mediatore_spire::{EntryManager, Naming};
use mediatore_store::ClaimStore;
use mediatore_sts::{MintRequest, Sts};

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
        Self { status, body: ErrorBody { error: error.to_owned(), detail: detail.into() } }
    }
    fn unauthorized(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", Some(detail.into()))
    }
    fn forbidden(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "forbidden", Some(detail.into()))
    }
    fn bad_request(error: &str, detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, error, Some(detail.into()))
    }
    fn not_implemented(what: &str) -> Self {
        Self::new(StatusCode::NOT_IMPLEMENTED, "not_implemented", Some(what.to_owned()))
    }
    fn internal(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", Some(detail.into()))
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
    st.sts.as_ref().map(|s| Json(s.jwks().clone())).ok_or_else(|| ApiError::not_implemented("sts backend not configured"))
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

async fn create_claim(
    State(st): State<Shared>,
    headers: HeaderMap,
    Json(req): Json<ClaimRequest>,
) -> Result<(StatusCode, Json<ClaimResponse>), ApiError> {
    let token = bearer(&headers)?;
    let validated = st.validator.validate(token).await.map_err(|e| match e {
        mediatore_entra::IdpError::Forbidden(d) => ApiError::forbidden(d),
        mediatore_entra::IdpError::NotImplemented(w) => ApiError::not_implemented(w),
        other => ApiError::unauthorized(other.to_string()),
    })?;
    if let Some(bad) = req.audiences.iter().find(|a| !st.audiences.contains(a)) {
        return Err(ApiError::bad_request("unknown_audience", bad.clone()));
    }
    tracing::info!(subject = %validated.subject.id, pool = %req.pool_ref, "creating claim");
    // Next: create the VirtualMachineClaim via kube-rs, persist a ClaimRecord, first OBO exchange.
    Err(ApiError::not_implemented("claim creation"))
}

async fn get_claim(
    State(st): State<Shared>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Result<Json<ClaimResponse>, ApiError> {
    let _token = bearer(&headers)?;
    let rec = st.store.get_claim_by_name(&name).await.map_err(|e| ApiError::new(StatusCode::NOT_FOUND, "not_found", Some(e.to_string())))?;
    // Next: enforce caller's subject == rec.subject, mirror phase/addresses from the CR.
    Ok(Json(ClaimResponse {
        name: rec.name,
        uid: Some(rec.uid),
        phase: if rec.entry_id.is_some() { mediatore_proto::ClaimPhase::Bound } else { mediatore_proto::ClaimPhase::Pending },
        expires_at: rec.expires_at,
        addresses: vec![],
    }))
}

async fn delete_claim(
    State(_st): State<Shared>,
    headers: HeaderMap,
    Path(_name): Path<String>,
) -> Result<StatusCode, ApiError> {
    let _token = bearer(&headers)?;
    Err(ApiError::not_implemented("claim deletion"))
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
        return Err(ApiError::forbidden(format!("peer {peer} may not register {expected}")));
    }
    st.store
        .put_node(mediatore_store::NodeRecord {
            ek_hash: reg.ek_hash.clone(),
            node_id: expected.clone(),
            dmi_uuid: reg.dmi_uuid,
            hostname: reg.hostname,
            provider: reg.provider,
            banned: false,
            registered_at: Utc::now(),
        })
        .await
        .map_err(|e| match e {
            mediatore_store::StoreError::Conflict(d) => ApiError::new(StatusCode::CONFLICT, "duplicate_ek", Some(d)),
            other => ApiError::internal(other.to_string()),
        })?;
    Ok(Json(NodeRegistered { node_id: expected }))
}

async fn me(State(st): State<Shared>, headers: HeaderMap) -> Result<Json<Me>, ApiError> {
    let peer = peer_spiffe_id(&st, &headers)?;
    // Peer is a node identity; find the live claim bound to that node.
    let _ = peer;
    Err(ApiError::not_implemented("claim lookup by node"))
}

async fn token(
    State(st): State<Shared>,
    headers: HeaderMap,
    Json(req): Json<TokenRequest>,
) -> Result<Json<TokenResponse>, ApiError> {
    let peer = peer_spiffe_id(&st, &headers)?;
    let claim_uid = st.naming.claim_uid_from(&peer).ok_or_else(|| ApiError::forbidden("peer is not a claim identity"))?;
    let rec = st.store.get_claim(claim_uid).await.map_err(|_| ApiError::forbidden("unknown claim"))?;
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
