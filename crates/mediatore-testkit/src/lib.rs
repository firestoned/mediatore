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
pub mod entra;
pub mod https;
pub mod pem;
pub mod policy;
pub mod registry;
pub mod sandboxes;
pub mod svid;
pub mod transit;

pub use entra::tempdir;
pub use https::TlsUpstream;
pub use pem::fixture_ca_pem;
pub use sandboxes::MemorySandboxes;
pub use svid::{MemoryMaterial, TestCa};
pub use transit::FakeTransit;

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use axum::extract::{Form, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header};
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

/// The fake issuer's signing key: one per process, generated on first use unless
/// [`use_idp_key`] installed one. Never embedded: a key in source is a key in every
/// clone, and the secret scanners say so.
static IDP_KEY: std::sync::OnceLock<String> = std::sync::OnceLock::new();

fn idp_test_key() -> &'static str {
    IDP_KEY.get_or_init(entra::fresh_p256_key_pem)
}

/// The issuer key this process signs with, PKCS#8 PEM, for handing to another process
/// (the `fake-idp` binary writes it to a file its `token` command reads).
#[must_use]
pub fn idp_key_pem() -> &'static str {
    idp_test_key()
}

/// Sign with `pem` (a PKCS#8 P-256 key) instead of a fresh key, so a token minted here
/// verifies against a fake issuer running elsewhere with the same key. Must come
/// before the first issuer start or [`mint`] in this process.
///
/// # Errors
/// When a key is already in use; `pem` is handed back.
pub fn use_idp_key(pem: String) -> Result<(), String> {
    IDP_KEY.set(pem)
}

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
    /// `access_type=offline` was on the authorization request (the Google shape).
    offline: bool,
}

/// Which real issuer this fake plays (ADR-0017): the shape of the identity it mints,
/// how a refresh token is asked for, and whether the token endpoint wants a client secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Profile {
    /// Dex (and Entra for the claims a login carries): `preferred_username`, `email`,
    /// `groups`; `offline_access` yields a refresh token.
    #[default]
    Dex,
    /// Google: `sub` a numeric string, `email`, no username and no groups;
    /// `offline_access` is an invalid scope, `access_type=offline` on the authorization
    /// request yields the refresh token; the token endpoint wants the client secret of
    /// an installed-app client.
    Google,
    /// Auth0: `sub` `auth0|<id>`, `email`, groups under a namespaced claim
    /// (`https://example.com/groups`), no username; `offline_access` yields a refresh token.
    Auth0,
}

/// The namespaced groups claim the Auth0 profile emits.
pub const AUTH0_GROUPS_CLAIM: &str = "https://example.com/groups";

/// A federated credential registered for a confidential client (ADR-0016 decision 4): a
/// token from `issuer` for `subject` with audience `audience` authenticates the client.
struct Federated {
    issuer: String,
    subject: String,
    audience: String,
}

/// What authenticates a confidential client: certificates by `x5t#S256` thumbprint, or
/// federated credentials. A client with neither is public (the Dex shape).
#[derive(Default)]
struct ClientAuth {
    certificates: HashMap<String, DecodingKey>,
    federated: Vec<Federated>,
    jtis: HashSet<String>,
}

#[derive(Default)]
struct IdpState {
    users: HashMap<String, User>,
    codes: HashMap<String, PendingCode>,
    /// refresh token → (login, `client_id`)
    sessions: HashMap<String, (String, String)>,
    clients: HashMap<String, ClientAuth>,
    /// Public clients whose token endpoint calls must carry this `client_secret`.
    client_secrets: HashMap<String, String>,
    profile: Profile,
    /// Logins whose next grant answers `interaction_required` (a Conditional Access step).
    interaction_required: HashSet<String>,
    refreshes: usize,
    exchanges: usize,
    refresh_scopes: Vec<String>,
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
    /// Verifies what this issuer (or any fake sharing the fixed key) signed.
    verify: DecodingKey,
    state: Arc<Mutex<IdpState>>,
}

fn s256(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn error(status: StatusCode, code: &str) -> Response {
    (status, axum::Json(serde_json::json!({ "error": code }))).into_response()
}

/// An OAuth error reply, before it is a `Response`: the status and the `error` code.
type Refusal = (StatusCode, &'static str);

/// The verifying half of the process's issuer key.
fn test_decoding_key() -> DecodingKey {
    let secret = p256::SecretKey::from_pkcs8_pem(idp_test_key()).expect("test key");
    let point = secret.public_key().to_sec1_point(false);
    DecodingKey::from_ec_components(
        &URL_SAFE_NO_PAD.encode(point.x().expect("x")),
        &URL_SAFE_NO_PAD.encode(point.y().expect("y")),
    )
    .expect("test public key")
}

/// Seconds an access token minted for a confidential client lives, as Entra's do.
const ENTRA_ACCESS_TTL_SECS: i64 = 3600;

/// The OIDC scopes that name no resource.
const OIDC_SCOPES: &[&str] = &["openid", "offline_access", "profile", "email", "groups"];

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
    let scopes: Vec<&str> = q
        .get("scope")
        .map(|s| s.split(' ').collect())
        .unwrap_or_default();
    let offline = q.get("access_type").map(String::as_str) == Some("offline");
    {
        let mut st = st.state.lock().unwrap();
        // Google has no offline_access scope: the request is refused, not ignored, and
        // as the OAuth error flow has it the browser is sent back to the client with
        // the error, so a CLI waiting on its loopback listener hears about it.
        if st.profile == Profile::Google && scopes.contains(&"offline_access") {
            let sep = if redirect_uri.contains('?') { '&' } else { '?' };
            let state = q
                .get("state")
                .map(|s| format!("&state={s}"))
                .unwrap_or_default();
            return Redirect::to(&format!("{redirect_uri}{sep}error=invalid_scope{state}"))
                .into_response();
        }
        st.user(&login);
        st.codes.insert(
            code.clone(),
            PendingCode {
                login,
                client_id: client_id.clone(),
                redirect_uri: redirect_uri.clone(),
                challenge: challenge.clone(),
                offline: offline || scopes.contains(&"offline_access"),
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

/// Authenticate a confidential client by its `client_assertion` (ADR-0016 decision 4):
/// PS256 against a certificate registered for it, `aud` this issuer's token endpoint,
/// `iss` and `sub` the client, a `jti` never seen before; or a federated token from a
/// registered issuer for the registered subject and audience. A public client (nothing
/// registered) needs nothing and may present nothing.
fn authenticate_client(
    shared: &Shared,
    state: &mut IdpState,
    client_id: &str,
    f: &HashMap<String, String>,
) -> Result<bool, Refusal> {
    const INVALID: Refusal = (StatusCode::UNAUTHORIZED, "invalid_client");
    let assertion = f.get("client_assertion");
    let Some(auth) = state.clients.get_mut(client_id) else {
        if assertion.is_some() {
            return Err(INVALID);
        }
        // A public client whose token endpoint still wants a secret (Google's
        // installed-app clients): the secret must be there and match.
        if let Some(secret) = state.client_secrets.get(client_id)
            && f.get("client_secret") != Some(secret)
        {
            return Err(INVALID);
        }
        return Ok(false);
    };
    let (Some(assertion), Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")) = (
        assertion,
        f.get("client_assertion_type").map(String::as_str),
    ) else {
        return Err(INVALID);
    };
    let header = jsonwebtoken::decode_header(assertion).map_err(|_| INVALID)?;
    if let Some(thumbprint) = header.x5t_s256.as_deref() {
        let Some(key) = auth.certificates.get(thumbprint) else {
            return Err(INVALID);
        };
        if header.alg != Algorithm::PS256 {
            return Err(INVALID);
        }
        let mut validation = jsonwebtoken::Validation::new(Algorithm::PS256);
        validation.set_audience(&[format!("{}/token", shared.issuer)]);
        validation.set_issuer(&[client_id]);
        validation.set_required_spec_claims(&["exp", "aud", "iss", "sub", "jti"]);
        let claims = jsonwebtoken::decode::<serde_json::Value>(assertion, key, &validation)
            .map_err(|_| INVALID)?
            .claims;
        if claims.get("sub").and_then(|v| v.as_str()) != Some(client_id) {
            return Err(INVALID);
        }
        let jti = claims
            .get("jti")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_owned();
        if !auth.jtis.insert(jti) {
            return Err(INVALID);
        }
        return Ok(true);
    }
    // A federated token: signed by its issuer (every fake shares the fixed key).
    let mut validation = jsonwebtoken::Validation::new(Algorithm::ES256);
    validation.validate_aud = false;
    let claims = jsonwebtoken::decode::<serde_json::Value>(assertion, &shared.verify, &validation)
        .map_err(|_| INVALID)?
        .claims;
    let claim = |k: &str| claims.get(k).and_then(|v| v.as_str()).unwrap_or_default();
    let aud_ok = |cred: &Federated| match claims.get("aud") {
        Some(serde_json::Value::String(a)) => *a == cred.audience,
        Some(serde_json::Value::Array(a)) => a.iter().any(|v| v.as_str() == Some(&cred.audience)),
        _ => false,
    };
    if auth
        .federated
        .iter()
        .any(|c| c.issuer == claim("iss") && c.subject == claim("sub") && aud_ok(c))
    {
        return Ok(true);
    }
    Err(INVALID)
}

/// The resource a `scope` names (`<resource>/.default` or a bare scope outside OIDC's),
/// and whether `offline_access` and `openid` are asked for. More than one resource is
/// `invalid_scope`, as at Entra.
fn parse_scope(scope: Option<&str>) -> Result<(Option<String>, bool, bool), Refusal> {
    let mut resource = None;
    let mut offline = false;
    let mut openid = false;
    for part in scope.unwrap_or_default().split_whitespace() {
        match part {
            "offline_access" => offline = true,
            "openid" => openid = true,
            p if OIDC_SCOPES.contains(&p) => {}
            p => {
                let r = p.strip_suffix("/.default").unwrap_or(p).to_owned();
                if resource.replace(r).is_some() {
                    return Err((StatusCode::BAD_REQUEST, "invalid_scope"));
                }
            }
        }
    }
    Ok((resource, offline, openid))
}

/// Who the grant is for: the login behind a code, a refresh token or an On-Behalf-Of
/// assertion, each checked as the issuer would.
fn grant_login(
    st: &Shared,
    state: &mut IdpState,
    client_id: &str,
    confidential: bool,
    f: &HashMap<String, String>,
) -> Result<(String, bool), Refusal> {
    const INVALID_GRANT: Refusal = (StatusCode::BAD_REQUEST, "invalid_grant");
    const INVALID_REQUEST: Refusal = (StatusCode::BAD_REQUEST, "invalid_request");
    match f.get("grant_type").map(String::as_str) {
        Some("authorization_code") => {
            let (Some(code), Some(verifier)) = (f.get("code"), f.get("code_verifier")) else {
                return Err(INVALID_REQUEST);
            };
            let pending = state.codes.remove(code).ok_or(INVALID_GRANT)?;
            if pending.client_id != client_id
                || pending.challenge != s256(verifier)
                || f.get("redirect_uri")
                    .is_some_and(|r| *r != pending.redirect_uri)
            {
                return Err(INVALID_GRANT);
            }
            Ok((pending.login, pending.offline))
        }
        Some("refresh_token") => {
            let old = f.get("refresh_token").ok_or(INVALID_REQUEST)?;
            let (login, issued_to) = state.sessions.remove(old).ok_or(INVALID_GRANT)?;
            if issued_to != client_id {
                return Err(INVALID_GRANT);
            }
            Ok((login, true))
        }
        Some("urn:ietf:params:oauth:grant-type:jwt-bearer") => {
            // On-Behalf-Of: the assertion is an access token this issuer signed for the
            // client, and only a confidential client may exchange one.
            if !confidential
                || f.get("requested_token_use").map(String::as_str) != Some("on_behalf_of")
            {
                return Err(INVALID_REQUEST);
            }
            let assertion = f.get("assertion").ok_or(INVALID_REQUEST)?;
            let mut validation = jsonwebtoken::Validation::new(Algorithm::ES256);
            validation.set_audience(&[client_id]);
            validation.set_issuer(&[&st.issuer]);
            let data =
                jsonwebtoken::decode::<serde_json::Value>(assertion, &st.verify, &validation)
                    .map_err(|_| INVALID_GRANT)?;
            ["oid", "sub", "preferred_username"]
                .iter()
                .find_map(|k| data.claims.get(*k).and_then(|v| v.as_str()))
                .map(|login| (login.to_owned(), true))
                .ok_or(INVALID_GRANT)
        }
        _ => Err((StatusCode::BAD_REQUEST, "unsupported_grant_type")),
    }
}

/// `POST /token`: `authorization_code` (PKCE S256 verified) and `refresh_token` (rotated)
/// grants as Dex serves them to a public client, and for a confidential client (ADR-0016)
/// the `jwt-bearer` On-Behalf-Of exchange and the `refresh_token` grant naming a resource
/// in `scope`, both behind client authentication. A revoked user, an unknown or already
/// rotated refresh token, a code that does not match its verifier or an assertion not
/// issued here is `invalid_grant`; a down issuer is 503.
async fn token(State(st): State<Shared>, Form(f): Form<HashMap<String, String>>) -> Response {
    let mut state = st.state.lock().unwrap();
    if state.down {
        return error(StatusCode::SERVICE_UNAVAILABLE, "temporarily_unavailable");
    }
    let client_id = f.get("client_id").cloned().unwrap_or_default();
    let confidential = match authenticate_client(&st, &mut state, &client_id, &f) {
        Ok(c) => c,
        Err((status, code)) => return error(status, code),
    };
    let grant = f.get("grant_type").map(String::as_str);
    let (login, offline_granted) = match grant_login(&st, &mut state, &client_id, confidential, &f)
    {
        Ok(out) => out,
        Err((status, code)) => return error(status, code),
    };
    let user = state.user(&login).clone();
    if user.revoked {
        return error(StatusCode::BAD_REQUEST, "invalid_grant");
    }
    if state.interaction_required.contains(&login) {
        return error(StatusCode::BAD_REQUEST, "interaction_required");
    }
    let (resource, offline, openid) = match parse_scope(f.get("scope").map(String::as_str)) {
        Ok(p) => p,
        Err((status, code)) => return error(status, code),
    };
    match grant {
        Some("refresh_token") => {
            state.refreshes += 1;
            state
                .refresh_scopes
                .push(f.get("scope").cloned().unwrap_or_default());
        }
        Some("urn:ietf:params:oauth:grant-type:jwt-bearer") => state.exchanges += 1,
        _ => {}
    }
    let identity = identity(state.profile, &login, &client_id, &user.groups);
    if !confidential {
        // A public client: an opaque access token, a signed ID token, and a session
        // when the login asked for one (Dex and Auth0 by `offline_access`, Google by
        // `access_type=offline`; a refresh keeps it).
        let mut reply = serde_json::json!({
            "access_token": format!("at-{}", Uuid::new_v4().simple()),
            "token_type": "bearer",
            "expires_in": TEST_TOKEN_TTL_MINUTES * 60,
            "id_token": mint(&st.issuer, identity),
        });
        if offline_granted {
            reply["refresh_token"] = serde_json::json!(state.new_session(&login, &client_id));
        }
        return axum::Json(reply).into_response();
    }
    // The Entra shape: a token for the client's own resource is one this issuer signs
    // and the client can validate; a token for any other resource is not the client's
    // to read; a refresh token only with offline_access; an ID token only with openid.
    let access_token = match resource.as_deref() {
        None | Some("") => identity_access_token(&st.issuer, &identity, &client_id),
        Some(r) if r == client_id => identity_access_token(&st.issuer, &identity, &client_id),
        Some(_) => format!("at-{}", Uuid::new_v4().simple()),
    };
    let mut reply = serde_json::json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": ENTRA_ACCESS_TTL_SECS,
        "scope": f.get("scope").cloned().unwrap_or_default(),
    });
    if offline {
        reply["refresh_token"] = serde_json::json!(state.new_session(&login, &client_id));
    }
    if openid {
        reply["id_token"] = serde_json::json!(mint(&st.issuer, identity));
    }
    axum::Json(reply).into_response()
}

/// The claims an identity carries in this fake's profile.
fn identity(
    profile: Profile,
    login: &str,
    client_id: &str,
    groups: &[String],
) -> serde_json::Value {
    match profile {
        Profile::Dex => serde_json::json!({
            "aud": client_id,
            "sub": login,
            "oid": login,
            "preferred_username": login,
            "email": format!("{login}@example.com"),
            "groups": groups,
        }),
        Profile::Google => serde_json::json!({
            "aud": client_id,
            "sub": format!("1{:020}", u64::from_le_bytes(Sha256::digest(login.as_bytes())[..8].try_into().expect("8 bytes")) % 10_000_000_000_000_000_000),
            "email": format!("{login}@example.com"),
            "email_verified": true,
        }),
        Profile::Auth0 => serde_json::json!({
            "aud": client_id,
            "sub": format!("auth0|{login}"),
            "email": format!("{login}@example.com"),
            AUTH0_GROUPS_CLAIM: groups,
        }),
    }
}

/// An access token for the client's own API, as Entra mints for `scope=<client_id>/.default`.
fn identity_access_token(issuer: &str, identity: &serde_json::Value, client_id: &str) -> String {
    let mut claims = identity.clone();
    claims["scp"] = serde_json::json!("sandbox.access");
    claims["azp"] = serde_json::json!(client_id);
    claims["exp"] =
        serde_json::json!((Utc::now() + Duration::seconds(ENTRA_ACCESS_TTL_SECS)).timestamp());
    mint(issuer, claims)
}

impl FakeIdp {
    /// Like [`FakeIdp::start`], on an ephemeral port.
    ///
    /// # Panics
    /// On any setup failure; this is test scaffolding.
    pub async fn start() -> Self {
        Self::start_on("127.0.0.1:0").await
    }

    /// Like [`FakeIdp::start`], playing `profile` (ADR-0017).
    ///
    /// # Panics
    /// On any setup failure; this is test scaffolding.
    pub async fn start_as(profile: Profile) -> Self {
        let idp = Self::start_on("127.0.0.1:0").await;
        idp.state.lock().unwrap().profile = profile;
        idp
    }

    /// Require `secret` as `client_secret` on every token endpoint call by the public
    /// client `client_id`, as Google does for an installed-app client.
    ///
    /// # Panics
    /// On a poisoned lock; this is test scaffolding.
    pub fn set_client_secret(&self, client_id: &str, secret: &str) {
        self.state
            .lock()
            .unwrap()
            .client_secrets
            .insert(client_id.to_owned(), secret.to_owned());
    }

    /// Bind `addr` and serve `/.well-known/openid-configuration`, `/jwks`, `/auth` and
    /// `/token`, signing with the process's issuer key.
    ///
    /// # Panics
    /// On any setup failure; this is test scaffolding.
    pub async fn start_on(addr: &str) -> Self {
        let secret = p256::SecretKey::from_pkcs8_pem(idp_test_key()).expect("test key");

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
            verify: test_decoding_key(),
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
            identity(st.profile, login, client_id, &groups),
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

    /// An access token for `login` with audience `client_id`, as Entra issues to a client
    /// calling mediatore's API: `oid`, `sub`, `preferred_username`, the user's groups.
    ///
    /// # Panics
    /// On a poisoned lock; this is test scaffolding.
    #[must_use]
    pub fn access_token(&self, login: &str, client_id: &str) -> String {
        let mut st = self.state.lock().unwrap();
        let groups = st.user(login).groups.clone();
        identity_access_token(
            &self.issuer,
            &identity(st.profile, login, client_id, &groups),
            client_id,
        )
    }

    /// Register `cert_pem` as a certificate credential of `client_id`, which becomes a
    /// confidential client: every token call must now carry a `client_assertion` signed
    /// by that certificate's key (PS256, `x5t#S256`) or a registered federated token.
    ///
    /// # Panics
    /// On a certificate that does not parse, or a poisoned lock; this is test scaffolding.
    pub fn register_client_certificate(&self, client_id: &str, cert_pem: &str) {
        let cert = mediatore_proto::cert::ClientCertificate::from_pem(cert_pem.as_bytes())
            .expect("a client certificate");
        let thumbprint = URL_SAFE_NO_PAD.encode(cert.thumbprint_s256());
        self.state
            .lock()
            .unwrap()
            .clients
            .entry(client_id.to_owned())
            .or_default()
            .certificates
            .insert(
                thumbprint,
                DecodingKey::from_rsa_der(cert.rsa_public_key_der()),
            );
    }

    /// Register a federated credential of `client_id` (workload identity federation): a
    /// token from `issuer` for `subject` with audience `audience` authenticates it.
    ///
    /// # Panics
    /// On a poisoned lock; this is test scaffolding.
    pub fn register_federated_credential(
        &self,
        client_id: &str,
        issuer: &str,
        subject: &str,
        audience: &str,
    ) {
        self.state
            .lock()
            .unwrap()
            .clients
            .entry(client_id.to_owned())
            .or_default()
            .federated
            .push(Federated {
                issuer: issuer.to_owned(),
                subject: subject.to_owned(),
                audience: audience.to_owned(),
            });
    }

    /// Every grant for `login` answers `interaction_required` from now on (a Conditional
    /// Access policy that needs the user), or stops doing so.
    ///
    /// # Panics
    /// On a poisoned lock; this is test scaffolding.
    pub fn set_interaction_required(&self, login: &str, required: bool) {
        let mut st = self.state.lock().unwrap();
        if required {
            st.interaction_required.insert(login.to_owned());
        } else {
            st.interaction_required.remove(login);
        }
    }

    /// How many On-Behalf-Of exchanges succeeded so far.
    ///
    /// # Panics
    /// On a poisoned lock; this is test scaffolding.
    #[must_use]
    pub fn exchanges(&self) -> usize {
        self.state.lock().unwrap().exchanges
    }

    /// The `scope` of every successful refresh so far, in order.
    ///
    /// # Panics
    /// On a poisoned lock; this is test scaffolding.
    #[must_use]
    pub fn refresh_scopes(&self) -> Vec<String> {
        self.state.lock().unwrap().refresh_scopes.clone()
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

/// Mint a token for `issuer` with the process's issuer key, without a running server.
/// It verifies at a fake issuer in another process only when both share the key
/// ([`use_idp_key`]); the `fake-idp` binary passes it through a file.
///
/// # Panics
/// On encoding failure; this is test scaffolding.
#[must_use]
pub fn mint(issuer: &str, mut claims: serde_json::Value) -> String {
    let key = EncodingKey::from_ec_pem(idp_test_key().as_bytes()).expect("test key");
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
