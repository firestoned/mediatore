// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Test-only helpers. Never a dependency of a shipped binary.
//!
//! [`FakeIdp`] plays the part of Dex or Entra in tests: it serves OIDC discovery and a JWKS
//! over a real HTTP listener, mints ES256 tokens with whatever claims a test asks for, and
//! since ADR-0013 runs the authorization-code flow with PKCE and the `refresh_token` grant
//! with rotation, with hooks to change a user's groups, revoke a session or take the
//! issuer down. [`TestCa`] plays the part of the SPIRE server's CA: it mints SPIFFE-shaped
//! X.509 SVIDs that the real mTLS verifiers accept, and [`MemoryMaterial`] stands in for
//! the Workload API so rotation can be driven by hand. [`MemorySandboxes`] stands in for
//! the Kubernetes API behind the user API's `AgentSandbox` front door.

pub mod ek;
pub mod sandboxes;
pub mod svid;

pub use sandboxes::MemorySandboxes;
pub use svid::{MemoryMaterial, TestCa};

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::{Form, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::pkcs8::DecodePrivateKey;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// Default lifetime of a minted test token.
const TEST_TOKEN_TTL_MINUTES: i64 = 5;

/// Key id the fixed test key is published under.
const TEST_KID: &str = "test-1";

/// Groups a user has until a test says otherwise.
pub const DEFAULT_GROUPS: &[&str] = &["firestoned:sandbox-users"];

/// Fixed throwaway P-256 key for the fake issuer. Test material only; never reuse.
const IDP_TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgrhNnnYdeXEjxagP5
BxtNbemcWCB16Xj/4jAOKGjlneChRANCAATwTU0Is+XLXuVw1S7cYHSjxzVYamsp
A+cAOHS5TsO7u6ChTcvHBecD+F7/j/ckAn5UHCjH9AYZ0qdljaXLdUMe
-----END PRIVATE KEY-----
";

#[derive(Clone)]
struct User {
    groups: Vec<String>,
    revoked: bool,
}

#[derive(Clone)]
struct PendingCode {
    login: String,
    client_id: String,
    redirect_uri: String,
    challenge: String,
}

#[derive(Default)]
struct IdpState {
    users: HashMap<String, User>,
    codes: HashMap<String, PendingCode>,
    /// refresh token → (login, `client_id`)
    sessions: HashMap<String, (String, String)>,
    refreshes: usize,
    down: bool,
}

impl IdpState {
    fn user(&mut self, login: &str) -> &mut User {
        self.users.entry(login.to_owned()).or_insert_with(|| User {
            groups: DEFAULT_GROUPS.iter().map(|g| (*g).to_owned()).collect(),
            revoked: false,
        })
    }

    fn new_session(&mut self, login: &str, client_id: &str) -> String {
        let token = format!("rt-{}", Uuid::new_v4().simple());
        self.sessions
            .insert(token.clone(), (login.to_owned(), client_id.to_owned()));
        token
    }
}

/// A minimal OIDC issuer bound to an ephemeral local port.
pub struct FakeIdp {
    /// Issuer URL (`http://127.0.0.1:<port>`), to be used verbatim in `IssuerConfig.url`.
    pub issuer: String,
    state: Arc<Mutex<IdpState>>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for FakeIdp {
    fn drop(&mut self) {
        self.server.abort();
    }
}

#[derive(Clone)]
struct Shared {
    issuer: String,
    state: Arc<Mutex<IdpState>>,
}

fn s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn error(status: StatusCode, code: &str) -> Response {
    (status, axum::Json(serde_json::json!({ "error": code }))).into_response()
}

/// `GET /auth`: the authorization endpoint. Auto-approves as the `login_hint` user
/// (`octocat` by default) and redirects back with a code bound to the PKCE challenge.
async fn authorize(State(st): State<Shared>, Query(q): Query<HashMap<String, String>>) -> Response {
    let (Some(client_id), Some(redirect_uri), Some(challenge)) = (
        q.get("client_id"),
        q.get("redirect_uri"),
        q.get("code_challenge"),
    ) else {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    };
    if q.get("code_challenge_method").map(String::as_str) != Some("S256") {
        return error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let login = q
        .get("login_hint")
        .cloned()
        .unwrap_or_else(|| "octocat".to_owned());
    let code = format!("code-{}", Uuid::new_v4().simple());
    {
        let mut st = st.state.lock().unwrap();
        st.user(&login);
        st.codes.insert(
            code.clone(),
            PendingCode {
                login,
                client_id: client_id.clone(),
                redirect_uri: redirect_uri.clone(),
                challenge: challenge.clone(),
            },
        );
    }
    let sep = if redirect_uri.contains('?') { '&' } else { '?' };
    let state = q
        .get("state")
        .map(|s| format!("&state={s}"))
        .unwrap_or_default();
    Redirect::to(&format!("{redirect_uri}{sep}code={code}{state}")).into_response()
}

/// `POST /token`: `authorization_code` (PKCE S256 verified) and `refresh_token` (rotated)
/// grants. A revoked user, an unknown or already-rotated refresh token, or a code that
/// does not match its verifier is `invalid_grant`; a down issuer is 503.
async fn token(State(st): State<Shared>, Form(f): Form<HashMap<String, String>>) -> Response {
    let mut state = st.state.lock().unwrap();
    if state.down {
        return error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    }
    let client_id = f.get("client_id").cloned().unwrap_or_default();
    let login = match f.get("grant_type").map(String::as_str) {
        Some("authorization_code") => {
            let (Some(code), Some(verifier)) = (f.get("code"), f.get("code_verifier")) else {
                return error(StatusCode::BAD_REQUEST, "invalid_request");
            };
            let Some(pending) = state.codes.remove(code) else {
                return error(StatusCode::BAD_REQUEST, "invalid_grant");
            };
            if pending.client_id != client_id
                || pending.challenge != s256(verifier)
                || f.get("redirect_uri")
                    .is_some_and(|r| *r != pending.redirect_uri)
            {
                return error(StatusCode::BAD_REQUEST, "invalid_grant");
            }
            pending.login
        }
        Some("refresh_token") => {
            let Some(old) = f.get("refresh_token") else {
                return error(StatusCode::BAD_REQUEST, "invalid_request");
            };
            let Some((login, issued_to)) = state.sessions.remove(old) else {
                return error(StatusCode::BAD_REQUEST, "invalid_grant");
            };
            if issued_to != client_id {
                return error(StatusCode::BAD_REQUEST, "invalid_grant");
            }
            login
        }
        _ => return error(StatusCode::BAD_REQUEST, "unsupported_grant_type"),
    };
    let user = state.user(&login).clone();
    if user.revoked {
        return error(StatusCode::BAD_REQUEST, "invalid_grant");
    }
    if f.get("grant_type").map(String::as_str) == Some("refresh_token") {
        state.refreshes += 1;
    }
    let refresh_token = state.new_session(&login, &client_id);
    let id_token = mint(
        &st.issuer,
        serde_json::json!({
            "aud": client_id,
            "sub": login,
            "preferred_username": login,
            "email": format!("{login}@example.com"),
            "groups": user.groups,
        }),
    );
    axum::Json(serde_json::json!({
        "access_token": format!("at-{}", Uuid::new_v4().simple()),
        "token_type": "bearer",
        "expires_in": TEST_TOKEN_TTL_MINUTES * 60,
        "id_token": id_token,
        "refresh_token": refresh_token,
    }))
    .into_response()
}

impl FakeIdp {
    /// Like [`FakeIdp::start`], on an ephemeral port.
    ///
    /// # Panics
    /// On any setup failure; this is test scaffolding.
    pub async fn start() -> Self {
        Self::start_on("127.0.0.1:0").await
    }

    /// Bind `addr` and serve `/.well-known/openid-configuration`, `/jwks`, `/auth` and
    /// `/token`, signing with the fixed test key.
    ///
    /// # Panics
    /// On any setup failure; this is test scaffolding.
    pub async fn start_on(addr: &str) -> Self {
        let secret = p256::SecretKey::from_pkcs8_pem(IDP_TEST_KEY).expect("test key");

        let point = secret.public_key().to_sec1_point(false);
        let jwk = serde_json::json!({
            "kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": TEST_KID,
            "x": URL_SAFE_NO_PAD.encode(point.x().expect("x")),
            "y": URL_SAFE_NO_PAD.encode(point.y().expect("y")),
        });

        let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
        let issuer = format!("http://{}", listener.local_addr().expect("addr"));

        let discovery = serde_json::json!({
            "issuer": issuer,
            "jwks_uri": format!("{issuer}/jwks"),
            "authorization_endpoint": format!("{issuer}/auth"),
            "token_endpoint": format!("{issuer}/token"),
            "code_challenge_methods_supported": ["S256"],
        });
        let jwks = serde_json::json!({ "keys": [jwk] });
        let state = Arc::new(Mutex::new(IdpState::default()));
        let shared = Shared {
            issuer: issuer.clone(),
            state: state.clone(),
        };
        let app = axum::Router::new()
            .route(
                "/.well-known/openid-configuration",
                axum::routing::get(move || {
                    let d = discovery.clone();
                    async move { axum::Json(d) }
                }),
            )
            .route(
                "/jwks",
                axum::routing::get(move || {
                    let j = jwks.clone();
                    async move { axum::Json(j) }
                }),
            )
            .route("/auth", axum::routing::get(authorize))
            .route("/token", axum::routing::post(token))
            .with_state(shared);
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        Self {
            issuer,
            state,
            server,
        }
    }

    /// Mint a token: `iss`, `iat`, `nbf` and a default `exp` are filled in, then `claims`
    /// are merged over them (so a test can override `exp`, set `aud`, `groups`, anything).
    ///
    /// # Panics
    /// On encoding failure; this is test scaffolding.
    #[must_use]
    pub fn token(&self, claims: serde_json::Value) -> String {
        mint(&self.issuer, claims)
    }

    /// A logged-in session for `login` as `client_id` without the browser flow: the ID
    /// token (with the user's current groups) and a live refresh token.
    ///
    /// # Panics
    /// On a poisoned lock; this is test scaffolding.
    #[must_use]
    pub fn session(&self, login: &str, client_id: &str) -> (String, String) {
        let mut st = self.state.lock().unwrap();
        let groups = st.user(login).groups.clone();
        let refresh = st.new_session(login, client_id);
        let id_token = mint(
            &self.issuer,
            serde_json::json!({
                "aud": client_id,
                "sub": login,
                "preferred_username": login,
                "email": format!("{login}@example.com"),
                "groups": groups,
            }),
        );
        (id_token, refresh)
    }

    /// Set the groups `login` carries from now on (in fresh tokens and refreshes).
    ///
    /// # Panics
    /// On a poisoned lock; this is test scaffolding.
    pub fn set_groups(&self, login: &str, groups: &[&str]) {
        self.state.lock().unwrap().user(login).groups =
            groups.iter().map(|g| (*g).to_owned()).collect();
    }

    /// Revoke every session of `login`: refreshes answer `invalid_grant` from now on.
    ///
    /// # Panics
    /// On a poisoned lock; this is test scaffolding.
    pub fn revoke(&self, login: &str) {
        self.state.lock().unwrap().user(login).revoked = true;
    }

    /// Take the token endpoint down (503) or bring it back.
    ///
    /// # Panics
    /// On a poisoned lock; this is test scaffolding.
    pub fn set_down(&self, down: bool) {
        self.state.lock().unwrap().down = down;
    }

    /// How many refresh grants succeeded so far.
    ///
    /// # Panics
    /// On a poisoned lock; this is test scaffolding.
    #[must_use]
    pub fn refreshes(&self) -> usize {
        self.state.lock().unwrap().refreshes
    }

    /// Whether `refresh_token` is still live (not rotated away, not revoked).
    ///
    /// # Panics
    /// On a poisoned lock; this is test scaffolding.
    #[must_use]
    pub fn is_live(&self, refresh_token: &str) -> bool {
        let st = self.state.lock().unwrap();
        st.sessions
            .get(refresh_token)
            .is_some_and(|(login, _)| !st.users.get(login).is_some_and(|u| u.revoked))
    }
}

/// Mint a token signed with the fixed test key for `issuer`, without a running server.
/// Works because the key never changes; the `fake-idp` binary relies on this.
///
/// # Panics
/// On encoding failure; this is test scaffolding.
#[must_use]
pub fn mint(issuer: &str, mut claims: serde_json::Value) -> String {
    let key = EncodingKey::from_ec_pem(IDP_TEST_KEY.as_bytes()).expect("test key");
    let now = Utc::now();
    if let Some(obj) = claims.as_object_mut() {
        let defaults = [
            ("iss", serde_json::json!(issuer)),
            ("iat", serde_json::json!(now.timestamp())),
            ("nbf", serde_json::json!(now.timestamp())),
            (
                "exp",
                serde_json::json!((now + Duration::minutes(TEST_TOKEN_TTL_MINUTES)).timestamp()),
            ),
        ];
        for (k, v) in defaults {
            obj.entry(k).or_insert(v);
        }
    }
    let header = Header {
        alg: Algorithm::ES256,
        kid: Some(TEST_KID.to_owned()),
        ..Default::default()
    };
    jsonwebtoken::encode(&header, &claims, &key).expect("encode test token")
}
