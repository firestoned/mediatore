// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Test-only helpers. Never a dependency of a shipped binary.
//!
//! [`FakeIdp`] plays the part of Dex or Entra in tests: it serves OIDC discovery and a JWKS
//! over a real HTTP listener, and mints ES256 tokens with whatever claims a test asks for.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use p256::elliptic_curve::sec1::ToSec1Point;
use p256::pkcs8::DecodePrivateKey;

/// Default lifetime of a minted test token.
const TEST_TOKEN_TTL_MINUTES: i64 = 5;

/// Key id the fixed test key is published under.
const TEST_KID: &str = "test-1";

/// Fixed throwaway P-256 key for the fake issuer. Test material only; never reuse.
const IDP_TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgrhNnnYdeXEjxagP5
BxtNbemcWCB16Xj/4jAOKGjlneChRANCAATwTU0Is+XLXuVw1S7cYHSjxzVYamsp
A+cAOHS5TsO7u6ChTcvHBecD+F7/j/ckAn5UHCjH9AYZ0qdljaXLdUMe
-----END PRIVATE KEY-----
";

/// A minimal OIDC issuer bound to an ephemeral local port.
pub struct FakeIdp {
    /// Issuer URL (`http://127.0.0.1:<port>`), to be used verbatim in `IssuerConfig.url`.
    pub issuer: String,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for FakeIdp {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl FakeIdp {
    /// Like [`FakeIdp::start`], on an ephemeral port.
    ///
    /// # Panics
    /// On any setup failure; this is test scaffolding.
    pub async fn start() -> Self {
        Self::start_on("127.0.0.1:0").await
    }

    /// Bind `addr` and serve `/.well-known/openid-configuration` and `/jwks`, signing with
    /// the fixed test key.
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
        });
        let jwks = serde_json::json!({ "keys": [jwk] });
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
            );
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        Self { issuer, server }
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
