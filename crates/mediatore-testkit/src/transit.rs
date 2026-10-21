// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! A fake `OpenBao` for the transit sealer (ADR-0015): the Kubernetes login and the transit
//! `encrypt` and `decrypt` calls over a real HTTP listener, as strict as `OpenBao` is. A
//! derived key refuses a call without a `context` and a non-derived key refuses one with
//! it; a ciphertext decrypts only under the context it was encrypted with; every transit
//! call needs a token this fake issued, and a revoked or expired one is 403. Hooks revoke
//! the tokens, rotate the key, take the server down and count the calls. Since ADR-0016 an
//! RSA key can be created too, and `sign` answers with an RSA-PSS signature over SHA-256
//! the way `OpenBao` does (`vault:vN:<base64>`), refusing any other parameters.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::hkdf::{HKDF_SHA256, Salt};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::signature::{RSA_PSS_SHA256, RsaKeyPair};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

/// What a fake transit key holds: one 32-byte secret per version, and whether it derives;
/// or, for an RSA key, the key pair (one version).
struct Key {
    derived: bool,
    versions: Vec<[u8; 32]>,
    min_decryption_version: usize,
    rsa: Option<Arc<RsaKeyPair>>,
}

struct TransitState {
    role: String,
    jwt: String,
    mount: String,
    lease_secs: u64,
    tokens: HashMap<String, Instant>,
    keys: HashMap<String, Key>,
    down: bool,
    logins: usize,
    encrypts: usize,
    decrypts: usize,
    signs: usize,
}

/// The fake `OpenBao`, bound to an ephemeral local port.
pub struct FakeTransit {
    /// `http://127.0.0.1:<port>`, for `TransitConfig::url`.
    pub url: String,
    state: Arc<Mutex<TransitState>>,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for FakeTransit {
    fn drop(&mut self) {
        self.server.abort();
    }
}

type Shared = Arc<Mutex<TransitState>>;

fn errors(status: StatusCode, msg: &str) -> Response {
    (status, axum::Json(serde_json::json!({ "errors": [msg] }))).into_response()
}

fn random(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    SystemRandom::new().fill(&mut b).expect("randomness");
    b
}

fn secret() -> [u8; 32] {
    let mut b = [0u8; 32];
    SystemRandom::new().fill(&mut b).expect("randomness");
    b
}

/// The per-context key of a derived transit key: HKDF over the version's secret.
fn subkey(secret: &[u8; 32], context: &[u8]) -> LessSafeKey {
    let prk = Salt::new(HKDF_SHA256, context).extract(secret);
    let okm = prk
        .expand(&[b"transit"], &AES_256_GCM)
        .expect("hkdf expand");
    LessSafeKey::new(UnboundKey::from(okm))
}

/// `POST /v1/auth/kubernetes/login`.
async fn login(
    State(st): State<Shared>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> Response {
    let mut s = st.lock().expect("transit state");
    if s.down {
        return errors(StatusCode::SERVICE_UNAVAILABLE, "down");
    }
    s.logins += 1;
    let (Some(role), Some(jwt)) = (
        body.get("role").and_then(|v| v.as_str()),
        body.get("jwt").and_then(|v| v.as_str()),
    ) else {
        return errors(StatusCode::BAD_REQUEST, "missing role or jwt");
    };
    if role != s.role || jwt != s.jwt {
        return errors(StatusCode::FORBIDDEN, "permission denied");
    }
    let token = format!(
        "hvs.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random(16))
    );
    let lease = s.lease_secs;
    s.tokens
        .insert(token.clone(), Instant::now() + Duration::from_secs(lease));
    axum::Json(serde_json::json!({
        "auth": { "client_token": token, "lease_duration": lease, "renewable": true }
    }))
    .into_response()
}

/// The token check every transit call runs.
fn authorized(s: &TransitState, headers: &HeaderMap) -> bool {
    headers
        .get("x-vault-token")
        .and_then(|v| v.to_str().ok())
        .and_then(|t| s.tokens.get(t))
        .is_some_and(|expiry| *expiry > Instant::now())
}

/// `POST /v1/<mount>/encrypt/<key>`.
async fn encrypt(
    State(st): State<Shared>,
    Path((mount, key)): Path<(String, String)>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> Response {
    let mut s = st.lock().expect("transit state");
    if s.down {
        return errors(StatusCode::SERVICE_UNAVAILABLE, "down");
    }
    if mount != s.mount {
        return errors(StatusCode::NOT_FOUND, "no handler for route");
    }
    if !authorized(&s, &headers) {
        return errors(StatusCode::FORBIDDEN, "permission denied");
    }
    s.encrypts += 1;
    let Some(k) = s.keys.get(&key) else {
        return errors(StatusCode::BAD_REQUEST, "encryption key not found");
    };
    if k.rsa.is_some() {
        return errors(
            StatusCode::BAD_REQUEST,
            "key type does not support encryption",
        );
    }
    let Some(Ok(plaintext)) = body
        .get("plaintext")
        .and_then(|v| v.as_str())
        .map(|p| STANDARD.decode(p))
    else {
        return errors(StatusCode::BAD_REQUEST, "missing plaintext");
    };
    let context = match body.get("context").and_then(|v| v.as_str()) {
        Some(c) => match STANDARD.decode(c) {
            Ok(c) => Some(c),
            Err(_) => return errors(StatusCode::BAD_REQUEST, "context is not base64"),
        },
        None => None,
    };
    let secret = match (k.derived, &context) {
        (true, Some(c)) => subkey(k.versions.last().expect("a version"), c),
        (true, None) => {
            return errors(
                StatusCode::BAD_REQUEST,
                "missing 'context' for key derivation",
            );
        }
        (false, Some(_)) => {
            return errors(
                StatusCode::BAD_REQUEST,
                "key was not created with derivation; context is not allowed",
            );
        }
        (false, None) => subkey(k.versions.last().expect("a version"), b""),
    };
    let nonce = random(12);
    let mut buf = plaintext;
    let nonce_arr: [u8; 12] = nonce.as_slice().try_into().expect("12 bytes");
    secret
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce_arr),
            Aad::empty(),
            &mut buf,
        )
        .expect("seal");
    let mut blob = nonce;
    blob.extend(buf);
    let version = k.versions.len();
    axum::Json(serde_json::json!({
        "data": { "ciphertext": format!("vault:v{version}:{}", STANDARD.encode(blob)), "key_version": version }
    }))
    .into_response()
}

/// `POST /v1/<mount>/decrypt/<key>`.
async fn decrypt(
    State(st): State<Shared>,
    Path((mount, key)): Path<(String, String)>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> Response {
    let mut s = st.lock().expect("transit state");
    if s.down {
        return errors(StatusCode::SERVICE_UNAVAILABLE, "down");
    }
    if mount != s.mount {
        return errors(StatusCode::NOT_FOUND, "no handler for route");
    }
    if !authorized(&s, &headers) {
        return errors(StatusCode::FORBIDDEN, "permission denied");
    }
    s.decrypts += 1;
    let Some(k) = s.keys.get(&key) else {
        return errors(StatusCode::BAD_REQUEST, "encryption key not found");
    };
    if k.rsa.is_some() {
        return errors(
            StatusCode::BAD_REQUEST,
            "key type does not support decryption",
        );
    }
    let Some(ciphertext) = body.get("ciphertext").and_then(|v| v.as_str()) else {
        return errors(StatusCode::BAD_REQUEST, "missing ciphertext");
    };
    let context = match body.get("context").and_then(|v| v.as_str()) {
        Some(c) => match STANDARD.decode(c) {
            Ok(c) => Some(c),
            Err(_) => return errors(StatusCode::BAD_REQUEST, "context is not base64"),
        },
        None => None,
    };
    let Some(rest) = ciphertext.strip_prefix("vault:v") else {
        return errors(StatusCode::BAD_REQUEST, "invalid ciphertext: no prefix");
    };
    let Some((version, b64)) = rest.split_once(':') else {
        return errors(StatusCode::BAD_REQUEST, "invalid ciphertext: no version");
    };
    let Ok(version) = version.parse::<usize>() else {
        return errors(StatusCode::BAD_REQUEST, "invalid ciphertext: bad version");
    };
    if version == 0 || version > k.versions.len() {
        return errors(
            StatusCode::BAD_REQUEST,
            "invalid ciphertext: unknown version",
        );
    }
    if version < k.min_decryption_version {
        return errors(
            StatusCode::BAD_REQUEST,
            "ciphertext version is below min_decryption_version",
        );
    }
    let Ok(blob) = STANDARD.decode(b64) else {
        return errors(StatusCode::BAD_REQUEST, "invalid ciphertext: not base64");
    };
    if blob.len() < 12 {
        return errors(StatusCode::BAD_REQUEST, "invalid ciphertext: too short");
    }
    let secret = match (k.derived, &context) {
        (true, Some(c)) => subkey(&k.versions[version - 1], c),
        (true, None) => {
            return errors(
                StatusCode::BAD_REQUEST,
                "missing 'context' for key derivation",
            );
        }
        (false, Some(_)) => {
            return errors(
                StatusCode::BAD_REQUEST,
                "key was not created with derivation; context is not allowed",
            );
        }
        (false, None) => subkey(&k.versions[version - 1], b""),
    };
    let nonce: [u8; 12] = blob[..12].try_into().expect("12 bytes");
    let mut buf = blob[12..].to_vec();
    let Ok(opened) =
        secret.open_in_place(Nonce::assume_unique_for_key(nonce), Aad::empty(), &mut buf)
    else {
        return errors(
            StatusCode::BAD_REQUEST,
            "cipher: message authentication failed",
        );
    };
    axum::Json(serde_json::json!({ "data": { "plaintext": STANDARD.encode(opened) } }))
        .into_response()
}

/// `POST /v1/<mount>/sign/<key>`: RSA-PSS over SHA-256 with the salt the hash's length,
/// which is what a PS256 client assertion needs; every other parameter is refused, as
/// `OpenBao` refuses what a key type cannot do.
async fn sign(
    State(st): State<Shared>,
    Path((mount, key)): Path<(String, String)>,
    headers: HeaderMap,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> Response {
    let mut s = st.lock().expect("transit state");
    if s.down {
        return errors(StatusCode::SERVICE_UNAVAILABLE, "down");
    }
    if mount != s.mount {
        return errors(StatusCode::NOT_FOUND, "no handler for route");
    }
    if !authorized(&s, &headers) {
        return errors(StatusCode::FORBIDDEN, "permission denied");
    }
    s.signs += 1;
    let Some(k) = s.keys.get(&key) else {
        return errors(StatusCode::BAD_REQUEST, "signing key not found");
    };
    let Some(rsa) = k.rsa.clone() else {
        return errors(StatusCode::BAD_REQUEST, "key type does not support signing");
    };
    let param = |name: &str, default: &str| -> String {
        body.get(name)
            .and_then(|v| v.as_str())
            .unwrap_or(default)
            .to_owned()
    };
    if param("hash_algorithm", "sha2-256") != "sha2-256" {
        return errors(StatusCode::BAD_REQUEST, "unsupported hash_algorithm");
    }
    if param("signature_algorithm", "pss") != "pss" {
        return errors(StatusCode::BAD_REQUEST, "only pss is served here");
    }
    if !matches!(param("salt_length", "auto").as_str(), "hash" | "auto") {
        return errors(StatusCode::BAD_REQUEST, "unsupported salt_length");
    }
    if body.get("prehashed").and_then(serde_json::Value::as_bool) == Some(true) {
        return errors(StatusCode::BAD_REQUEST, "prehashed is not served here");
    }
    let Some(Ok(input)) = body
        .get("input")
        .and_then(|v| v.as_str())
        .map(|p| STANDARD.decode(p))
    else {
        return errors(StatusCode::BAD_REQUEST, "missing input");
    };
    let mut signature = vec![0u8; rsa.public_modulus_len()];
    rsa.sign(
        &RSA_PSS_SHA256,
        &SystemRandom::new(),
        &input,
        &mut signature,
    )
    .expect("rsa-pss sign");
    axum::Json(serde_json::json!({
        "data": { "signature": format!("vault:v1:{}", STANDARD.encode(signature)), "key_version": 1 }
    }))
    .into_response()
}

impl FakeTransit {
    /// A fake `OpenBao` that accepts the Kubernetes login for `role` with exactly `jwt`, with
    /// one derived key `key` under mount `transit`. Tokens live an hour.
    ///
    /// # Panics
    ///
    /// If no local port can be bound.
    pub async fn spawn(role: &str, jwt: &str, key: &str) -> Self {
        let state = Arc::new(Mutex::new(TransitState {
            role: role.to_owned(),
            jwt: jwt.to_owned(),
            mount: "transit".to_owned(),
            lease_secs: 3600,
            tokens: HashMap::new(),
            keys: HashMap::new(),
            down: false,
            logins: 0,
            encrypts: 0,
            decrypts: 0,
            signs: 0,
        }));
        let fake = Self::serve(state).await;
        fake.create_key(key, true);
        fake
    }

    async fn serve(state: Shared) -> Self {
        let app = axum::Router::new()
            .route("/v1/auth/kubernetes/login", axum::routing::post(login))
            .route("/v1/{mount}/encrypt/{key}", axum::routing::post(encrypt))
            .route("/v1/{mount}/decrypt/{key}", axum::routing::post(decrypt))
            .route("/v1/{mount}/sign/{key}", axum::routing::post(sign))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a local port");
        let url = format!("http://{}", listener.local_addr().expect("local addr"));
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self { url, state, server }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, TransitState> {
        self.state.lock().expect("transit state")
    }

    /// Create (or replace) a key, `derived` or not, at version 1.
    pub fn create_key(&self, name: &str, derived: bool) {
        self.lock().keys.insert(
            name.to_owned(),
            Key {
                derived,
                versions: vec![secret()],
                min_decryption_version: 1,
                rsa: None,
            },
        );
    }

    /// Create (or replace) `name` as an RSA signing key holding the process's client
    /// test key (`crate::entra::client_credential`), so the certificate on that key
    /// verifies what this fake signs.
    ///
    /// # Panics
    /// If the generated test key does not parse; this is test scaffolding.
    pub fn create_rsa_key(&self, name: &str) {
        let pair = RsaKeyPair::from_pkcs8(&crate::entra::client_credential().key_der)
            .expect("the RSA test key");
        self.lock().keys.insert(
            name.to_owned(),
            Key {
                derived: false,
                versions: vec![secret()],
                min_decryption_version: 1,
                rsa: Some(Arc::new(pair)),
            },
        );
    }

    /// Rotate `name`: new ciphertexts carry the next version, old ones still decrypt.
    pub fn rotate(&self, name: &str) {
        if let Some(k) = self.lock().keys.get_mut(name) {
            k.versions.push(secret());
        }
    }

    /// Refuse to decrypt anything older than `version`, as the administrator would.
    pub fn set_min_decryption_version(&self, name: &str, version: usize) {
        if let Some(k) = self.lock().keys.get_mut(name) {
            k.min_decryption_version = version;
        }
    }

    /// Every token issued so far is dead: the next transit call is 403.
    pub fn revoke_tokens(&self) {
        self.lock().tokens.clear();
    }

    /// How long a token issued from now lives.
    pub fn set_lease_secs(&self, secs: u64) {
        self.lock().lease_secs = secs;
    }

    /// Answer every request with 503 while `down`.
    pub fn set_down(&self, down: bool) {
        self.lock().down = down;
    }

    /// Logins attempted so far.
    #[must_use]
    pub fn logins(&self) -> usize {
        self.lock().logins
    }

    /// Authorized encrypt calls so far.
    #[must_use]
    pub fn encrypts(&self) -> usize {
        self.lock().encrypts
    }

    /// Authorized decrypt calls so far.
    #[must_use]
    pub fn decrypts(&self) -> usize {
        self.lock().decrypts
    }

    /// Authorized sign calls so far.
    #[must_use]
    pub fn signs(&self) -> usize {
        self.lock().signs
    }
}
