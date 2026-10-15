// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Upstream identity providers.
//!
//! Three responsibilities:
//! 1. Validate the bearer token a caller presents to `POST /v1/claims` (issuer, audience,
//!    signature via JWKS, expiry, and the per-issuer authorisation gate).
//! 2. For an issuer with a `session`, refresh the delegated upstream session before every
//!    issue and validate the ID token it returns the same way (ADR-0013).
//! 3. For the `entra-obo` backend, exchange that token for downstream access tokens (the
//!    request shape exists; the path is the next slice of roadmap 04).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk, JwkSet};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use mediatore_proto::Subject;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// How long a fetched JWKS may be served from cache before it is re-fetched.
const JWKS_CACHE_TTL_SECS: u64 = 300;

/// Which exchange mechanism serves an issuer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Backend {
    /// Entra ID On-Behalf-Of: mediatore is a confidential client with a certificate credential.
    EntraObo,
    /// mediatore signs its own tokens (see `mediatore-sts`); upstream is only for login.
    Sts,
}

/// The delegated upstream session an issuer requires (ADR-0013): the caller hands over
/// the refresh token it got as `client_id` (a public client, no secret), and mediatore
/// refreshes it before every issue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionConfig {
    /// The OAuth client the refresh token was issued to; `mediatore login` uses
    /// mediatore's own public client, so this is normally the issuer's `client_id`.
    pub client_id: String,
}

/// One trusted issuer, from config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerConfig {
    /// `iss` value, byte-for-byte.
    pub url: String,
    /// Exchange mechanism.
    pub backend: Backend,
    /// Our client id at this issuer; also the required `aud`.
    pub client_id: String,
    /// Claim carrying the subject id: `oid` for Entra, `preferred_username` for Dex.
    #[serde(default = "default_subject_claim")]
    pub subject_claim: String,
    /// A group the token must carry (Dex `groups`, Entra `groups`/`roles`); none = no gate.
    #[serde(default)]
    pub required_group: Option<String>,
    /// Set when claims from this issuer must delegate a refresh token (ADR-0013).
    #[serde(default)]
    pub session: Option<SessionConfig>,
    /// A PEM file with the CA certificates that sign this issuer's TLS certificate, for an
    /// issuer on a private PKI. When set, discovery, JWKS and token requests to this issuer
    /// trust exactly those certificates and not the public roots. Read at startup
    /// (`Validator::with_issuer_ca`); a missing or empty file stops the process.
    #[serde(default)]
    pub ca_file: Option<std::path::PathBuf>,
}

fn default_subject_claim() -> String {
    "oid".to_owned()
}

/// Errors from validation or exchange.
#[derive(Debug, thiserror::Error)]
pub enum IdpError {
    /// The token's `iss` is not configured.
    #[error("unknown issuer")]
    UnknownIssuer,
    /// Audience, signature, expiry or claim shape failed.
    #[error("invalid token: {0}")]
    Invalid(String),
    /// The subject is authenticated but not allowed (group gate).
    #[error("forbidden: {0}")]
    Forbidden(String),
    /// Upstream HTTP failure.
    #[error("upstream: {0}")]
    Upstream(String),
    /// The issuer refused to refresh the session (`invalid_grant`): revoked upstream, or
    /// the user is gone. A revocation, not an outage.
    #[error("session revoked upstream: {0}")]
    SessionRevoked(String),
    /// Feature not wired yet.
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
}

/// What a successful validation yields.
#[derive(Debug, Clone)]
pub struct Validated {
    /// Subject as it will be written to the claim.
    pub subject: Subject,
    /// Issuer config the token matched.
    pub issuer: IssuerConfig,
    /// Groups carried in the token, if any.
    pub groups: Vec<String>,
    /// Token expiry, informational.
    pub expires_at: DateTime<Utc>,
}

/// Unverified `iss` peek, used to pick the issuer config before verifying the signature.
fn peek_issuer(token: &str) -> Result<String, IdpError> {
    let mut parts = token.split('.');
    let (_h, payload) = (
        parts.next(),
        parts
            .next()
            .ok_or_else(|| IdpError::Invalid("not a JWT".into()))?,
    );
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|e| IdpError::Invalid(e.to_string()))?;
    let v: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| IdpError::Invalid(e.to_string()))?;
    v.get("iss")
        .and_then(|s| s.as_str())
        .map(ToOwned::to_owned)
        .ok_or_else(|| IdpError::Invalid("missing iss".into()))
}

/// What the discovery document told us, with the JWKS, and when.
struct CachedIssuer {
    set: JwkSet,
    token_endpoint: Option<String>,
    fetched_at: Instant,
}

/// What a refresh yields (ADR-0013 decision 4).
#[derive(Debug, Clone)]
pub struct Refreshed {
    /// The fresh ID token, validated exactly like a login token.
    pub validated: Validated,
    /// The refresh token to keep: the rotated one, or the one just used when the issuer
    /// does not rotate.
    pub refresh_token: String,
}

/// Validates upstream tokens against a configured set of issuers.
#[derive(Clone)]
pub struct Validator {
    issuers: Vec<IssuerConfig>,
    http: reqwest::Client,
    /// Per-issuer clients over a private CA (`IssuerConfig::ca_file`), keyed by issuer URL.
    pinned: HashMap<String, reqwest::Client>,
    jwks: Arc<RwLock<HashMap<String, CachedIssuer>>>,
}

impl std::fmt::Debug for Validator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Validator")
            .field("issuers", &self.issuers)
            .finish_non_exhaustive()
    }
}

/// Signing algorithm implied by a JWK's parameters.
fn algorithm_of(jwk: &Jwk) -> Result<Algorithm, IdpError> {
    match &jwk.algorithm {
        AlgorithmParameters::EllipticCurve(p) => match p.curve {
            EllipticCurve::P256 => Ok(Algorithm::ES256),
            EllipticCurve::P384 => Ok(Algorithm::ES384),
            ref other => Err(IdpError::Invalid(format!("unsupported curve {other:?}"))),
        },
        AlgorithmParameters::RSA(_) => Ok(Algorithm::RS256),
        other => Err(IdpError::Invalid(format!("unsupported key type {other:?}"))),
    }
}

/// String values of a JSON array claim, e.g. `groups` or `roles`.
fn string_array(claims: &serde_json::Value, key: &str) -> Vec<String> {
    claims
        .get(key)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

impl Validator {
    /// Build from config.
    ///
    /// # Panics
    /// If `reqwest` cannot build a client over the workspace TLS config, which would be a
    /// broken build rather than a runtime condition.
    #[must_use]
    pub fn new(issuers: Vec<IssuerConfig>) -> Self {
        Self {
            issuers,
            http: reqwest::Client::builder()
                .use_preconfigured_tls(mediatore_proto::tls::https_client_config())
                .build()
                .expect("reqwest client over the workspace TLS config"),
            pinned: HashMap::new(),
            jwks: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Trust exactly the CA certificates in `pem` for the issuer at `url` (its
    /// `ca_file`), instead of the public roots. Fails closed on a PEM with no certificate.
    pub fn with_issuer_ca(mut self, url: &str, pem: &[u8]) -> Result<Self, IdpError> {
        let cfg = mediatore_proto::tls::https_client_config_with_ca(pem)
            .map_err(|e| IdpError::Upstream(format!("{url}: {e}")))?;
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(cfg)
            .build()
            .map_err(|e| IdpError::Upstream(e.to_string()))?;
        self.pinned.insert(url.to_owned(), client);
        Ok(self)
    }

    /// The HTTP client for an issuer: the pinned one when it has a `ca_file`.
    fn http_for(&self, issuer_url: &str) -> &reqwest::Client {
        self.pinned.get(issuer_url).unwrap_or(&self.http)
    }

    /// Find the issuer config for a token without trusting anything in it yet.
    pub fn issuer_for(&self, token: &str) -> Result<&IssuerConfig, IdpError> {
        let iss = peek_issuer(token)?;
        self.issuers
            .iter()
            .find(|i| i.url == iss)
            .ok_or(IdpError::UnknownIssuer)
    }

    /// The issuer's JWKS, from cache unless stale or `force` is set.
    async fn jwks_for(&self, issuer_url: &str, force: bool) -> Result<JwkSet, IdpError> {
        Ok(self.discover(issuer_url, force).await?.0)
    }

    /// The issuer's token endpoint, from the same discovery document as the JWKS.
    async fn token_endpoint_for(&self, issuer_url: &str) -> Result<String, IdpError> {
        self.discover(issuer_url, false)
            .await?
            .1
            .ok_or_else(|| IdpError::Upstream("discovery document has no token_endpoint".into()))
    }

    /// The JWKS and the token endpoint, from cache unless stale or `force` is set.
    async fn discover(
        &self,
        issuer_url: &str,
        force: bool,
    ) -> Result<(JwkSet, Option<String>), IdpError> {
        if !force
            && let Some(cached) = self.jwks.read().await.get(issuer_url)
            && cached.fetched_at.elapsed().as_secs() < JWKS_CACHE_TTL_SECS
        {
            return Ok((cached.set.clone(), cached.token_endpoint.clone()));
        }

        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            issuer_url.trim_end_matches('/')
        );
        let discovery: serde_json::Value = self
            .http_for(issuer_url)
            .get(&discovery_url)
            .send()
            .await
            .map_err(|e| IdpError::Upstream(format!("discovery: {e}")))?
            .error_for_status()
            .map_err(|e| IdpError::Upstream(format!("discovery: {e}")))?
            .json()
            .await
            .map_err(|e| IdpError::Upstream(format!("discovery: {e}")))?;
        let jwks_uri = discovery
            .get("jwks_uri")
            .and_then(|v| v.as_str())
            .ok_or_else(|| IdpError::Upstream("discovery document has no jwks_uri".into()))?;
        let token_endpoint = discovery
            .get("token_endpoint")
            .and_then(|v| v.as_str())
            .map(ToOwned::to_owned);

        let set: JwkSet = self
            .http_for(issuer_url)
            .get(jwks_uri)
            .send()
            .await
            .map_err(|e| IdpError::Upstream(format!("jwks: {e}")))?
            .error_for_status()
            .map_err(|e| IdpError::Upstream(format!("jwks: {e}")))?
            .json()
            .await
            .map_err(|e| IdpError::Upstream(format!("jwks: {e}")))?;

        self.jwks.write().await.insert(
            issuer_url.to_owned(),
            CachedIssuer {
                set: set.clone(),
                token_endpoint: token_endpoint.clone(),
                fetched_at: Instant::now(),
            },
        );
        tracing::debug!(issuer = issuer_url, keys = set.keys.len(), "jwks fetched");
        Ok((set, token_endpoint))
    }

    /// The key that signed `kid`, re-fetching the JWKS once on a miss (key rotation).
    async fn key_for(&self, issuer_url: &str, kid: Option<&str>) -> Result<Jwk, IdpError> {
        let pick = |set: &JwkSet| match kid {
            Some(k) => set.find(k).cloned(),
            None => set.keys.first().cloned(),
        };
        if let Some(jwk) = pick(&self.jwks_for(issuer_url, false).await?) {
            return Ok(jwk);
        }
        pick(&self.jwks_for(issuer_url, true).await?)
            .ok_or_else(|| IdpError::Invalid(format!("no key for kid {kid:?}")))
    }

    /// Full validation: signature via the issuer's JWKS, `aud` == `client_id`, `exp`/`nbf`,
    /// subject claim present, group gate satisfied.
    pub async fn validate(&self, token: &str) -> Result<Validated, IdpError> {
        let issuer = self.issuer_for(token)?.clone();
        self.validate_as(&issuer, token).await
    }

    /// The configured issuer named `url`, for a record that remembers which one it is.
    pub fn issuer_named(&self, url: &str) -> Option<&IssuerConfig> {
        self.issuers.iter().find(|i| i.url == url)
    }

    /// Refresh a delegated session (ADR-0013 decision 4): the `refresh_token` grant at the
    /// issuer's token endpoint as the session's client, then the returned ID token
    /// validated exactly like a login token. `invalid_grant` is [`IdpError::SessionRevoked`];
    /// any other failure is [`IdpError::Upstream`] and revokes nothing.
    pub async fn refresh(
        &self,
        issuer: &IssuerConfig,
        refresh_token: &str,
    ) -> Result<Refreshed, IdpError> {
        let session = issuer
            .session
            .as_ref()
            .ok_or(IdpError::NotImplemented("issuer takes no session"))?;
        let endpoint = self.token_endpoint_for(&issuer.url).await?;
        let form = [
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", session.client_id.as_str()),
        ];
        let resp = self
            .http_for(&issuer.url)
            .post(&endpoint)
            .form(&form)
            .send()
            .await
            .map_err(|e| IdpError::Upstream(format!("refresh: {e}")))?;
        let status = resp.status();
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| IdpError::Upstream(format!("refresh: {e}")))?;
        if !status.is_success() {
            let code = body
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned();
            if status.is_client_error() && code == "invalid_grant" {
                return Err(IdpError::SessionRevoked(code));
            }
            return Err(IdpError::Upstream(format!("refresh: {status} {code}")));
        }
        let id_token = body
            .get("id_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| IdpError::Upstream("refresh: no id_token in the response".into()))?;
        let validated = self.validate_as(issuer, id_token).await?;
        let refresh_token = body
            .get("refresh_token")
            .and_then(|v| v.as_str())
            .unwrap_or(refresh_token)
            .to_owned();
        Ok(Refreshed {
            validated,
            refresh_token,
        })
    }

    /// [`Self::validate`] against one known issuer.
    async fn validate_as(&self, issuer: &IssuerConfig, token: &str) -> Result<Validated, IdpError> {
        tracing::debug!(issuer = %issuer.url, backend = ?issuer.backend, "validating upstream token");

        let header =
            jsonwebtoken::decode_header(token).map_err(|e| IdpError::Invalid(e.to_string()))?;
        let jwk = self.key_for(&issuer.url, header.kid.as_deref()).await?;
        let key = DecodingKey::from_jwk(&jwk).map_err(|e| IdpError::Invalid(e.to_string()))?;

        let mut validation = Validation::new(algorithm_of(&jwk)?);
        validation.set_audience(&[&issuer.client_id]);
        validation.set_issuer(&[&issuer.url]);
        let data = jsonwebtoken::decode::<serde_json::Value>(token, &key, &validation)
            .map_err(|e| IdpError::Invalid(e.to_string()))?;
        let claims = data.claims;

        let id = claims
            .get(&issuer.subject_claim)
            .and_then(|v| v.as_str())
            .ok_or_else(|| IdpError::Invalid(format!("missing claim {}", issuer.subject_claim)))?
            .to_owned();

        let mut groups = string_array(&claims, "groups");
        groups.extend(string_array(&claims, "roles"));
        if let Some(required) = &issuer.required_group
            && !groups.iter().any(|g| g == required)
        {
            return Err(IdpError::Forbidden(format!(
                "not in required group {required}"
            )));
        }

        let display = ["upn", "email", "name"]
            .iter()
            .find_map(|k| claims.get(*k).and_then(|v| v.as_str()))
            .map(ToOwned::to_owned);
        let expires_at = claims
            .get("exp")
            .and_then(serde_json::Value::as_i64)
            .and_then(|ts| DateTime::from_timestamp(ts, 0))
            .ok_or_else(|| IdpError::Invalid("missing exp".into()))?;

        Ok(Validated {
            subject: Subject {
                issuer: issuer.url.clone(),
                id,
                display,
            },
            issuer: issuer.clone(),
            groups,
            expires_at,
        })
    }
}

/// Entra On-Behalf-Of exchange.
#[derive(Debug, Clone)]
pub struct Obo {
    tenant_id: String,
    client_id: String,
    http: reqwest::Client,
}

/// Result of an OBO or refresh call.
#[derive(Debug, Clone, Deserialize)]
pub struct Exchanged {
    /// Access token for the requested scope.
    pub access_token: String,
    /// Seconds until expiry.
    pub expires_in: i64,
    /// Refresh token, present when `offline_access` was granted. Store encrypted, never return.
    #[serde(default)]
    pub refresh_token: Option<String>,
}

impl Obo {
    /// Construct for a tenant and our app id. The client assertion signer is injected per call.
    ///
    /// # Panics
    /// If `reqwest` cannot build a client over the workspace TLS config, which would be a
    /// broken build rather than a runtime condition.
    #[must_use]
    pub fn new(tenant_id: impl Into<String>, client_id: impl Into<String>) -> Self {
        Self {
            tenant_id: tenant_id.into(),
            client_id: client_id.into(),
            http: reqwest::Client::builder()
                .use_preconfigured_tls(mediatore_proto::tls::https_client_config())
                .build()
                .expect("reqwest client over the workspace TLS config"),
        }
    }

    /// Token endpoint for this tenant.
    #[must_use]
    pub fn token_endpoint(&self) -> String {
        format!(
            "https://login.microsoftonline.com/{}/oauth2/v2.0/token",
            self.tenant_id
        )
    }

    /// `grant_type=jwt-bearer` with `requested_token_use=on_behalf_of`.
    pub async fn exchange(
        &self,
        user_assertion: &str,
        client_assertion: &str,
        scope: &str,
    ) -> Result<Exchanged, IdpError> {
        let form = [
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("client_id", self.client_id.as_str()),
            (
                "client_assertion_type",
                "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            ),
            ("client_assertion", client_assertion),
            ("assertion", user_assertion),
            ("scope", scope),
            ("requested_token_use", "on_behalf_of"),
        ];
        let resp = self
            .http
            .post(self.token_endpoint())
            .form(&form)
            .send()
            .await
            .map_err(|e| IdpError::Upstream(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(IdpError::Upstream(format!("obo: {}", resp.status())));
        }
        resp.json::<Exchanged>()
            .await
            .map_err(|e| IdpError::Upstream(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_pinned_issuer_ca_is_read_at_construction_and_an_empty_one_is_refused() {
        let v = Validator::new(vec![]);
        let err = v
            .with_issuer_ca("https://dex.home.example", b"")
            .unwrap_err();
        assert!(err.to_string().contains("no certificate"), "{err}");
        let v = Validator::new(vec![])
            .with_issuer_ca(
                "https://dex.home.example",
                mediatore_testkit::fixture_ca_pem().as_bytes(),
            )
            .unwrap();
        assert!(v.pinned.contains_key("https://dex.home.example"));
        assert!(std::ptr::eq(
            v.http_for("https://other.example"),
            std::ptr::from_ref(&v.http)
        ));
    }

    use mediatore_testkit::FakeIdp;

    use super::*;

    fn issuer_config(idp: &FakeIdp) -> IssuerConfig {
        IssuerConfig {
            url: idp.issuer.clone(),
            backend: Backend::Sts,
            client_id: "mediatore".into(),
            subject_claim: "preferred_username".into(),
            required_group: Some("firestoned:sandbox-users".into()),
            session: Some(SessionConfig {
                client_id: "mediatore".into(),
            }),
            ca_file: None,
        }
    }

    #[tokio::test]
    async fn a_refresh_validates_the_fresh_id_token_rotates_and_sees_revocation() {
        let idp = FakeIdp::start().await;
        idp.set_groups("octocat", &["firestoned:sandbox-users"]);
        let v = Validator::new(vec![issuer_config(&idp)]);
        let (_, refresh_token) = idp.session("octocat", "mediatore");

        let first = v
            .refresh(&issuer_config(&idp), &refresh_token)
            .await
            .unwrap();
        assert_eq!(first.validated.subject.id, "octocat");
        assert_ne!(first.refresh_token, refresh_token, "rotated");
        assert!(
            matches!(
                v.refresh(&issuer_config(&idp), &refresh_token).await,
                Err(IdpError::SessionRevoked(_))
            ),
            "the old token is dead after rotation"
        );

        // The group gate runs on the fresh token: removal from the group is a refusal.
        // The issuer rotated before we looked, so that session is spent either way.
        idp.set_groups("octocat", &["firestoned:other"]);
        assert!(matches!(
            v.refresh(&issuer_config(&idp), &first.refresh_token).await,
            Err(IdpError::Forbidden(_))
        ));
        idp.set_groups("octocat", &["firestoned:sandbox-users"]);
        let (_, again) = idp.session("octocat", "mediatore");
        let second = v.refresh(&issuer_config(&idp), &again).await.unwrap();

        idp.revoke("octocat");
        assert!(matches!(
            v.refresh(&issuer_config(&idp), &second.refresh_token).await,
            Err(IdpError::SessionRevoked(_))
        ));
        assert_eq!(idp.refreshes(), 3);
    }

    #[tokio::test]
    async fn an_issuer_outage_is_not_a_revocation() {
        let idp = FakeIdp::start().await;
        let v = Validator::new(vec![issuer_config(&idp)]);
        let (_, refresh_token) = idp.session("octocat", "mediatore");
        idp.set_down(true);
        assert!(matches!(
            v.refresh(&issuer_config(&idp), &refresh_token).await,
            Err(IdpError::Upstream(_))
        ));
        idp.set_down(false);
        v.refresh(&issuer_config(&idp), &refresh_token)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn an_issuer_without_a_session_cannot_refresh() {
        let idp = FakeIdp::start().await;
        let mut cfg = issuer_config(&idp);
        cfg.session = None;
        let v = Validator::new(vec![cfg.clone()]);
        assert!(matches!(
            v.refresh(&cfg, "whatever").await,
            Err(IdpError::NotImplemented(_))
        ));
    }

    #[tokio::test]
    async fn valid_token_yields_subject_and_groups() {
        let idp = FakeIdp::start().await;
        let v = Validator::new(vec![issuer_config(&idp)]);
        let token = idp.token(serde_json::json!({
            "aud": "mediatore",
            "preferred_username": "octocat",
            "email": "octocat@example.com",
            "groups": ["firestoned:sandbox-users", "firestoned:dev"],
        }));
        let out = v.validate(&token).await.unwrap();
        assert_eq!(out.subject.id, "octocat");
        assert_eq!(out.subject.issuer, idp.issuer);
        assert_eq!(out.subject.display.as_deref(), Some("octocat@example.com"));
        assert!(out.groups.contains(&"firestoned:dev".to_owned()));
    }

    #[tokio::test]
    async fn wrong_audience_is_invalid() {
        let idp = FakeIdp::start().await;
        let v = Validator::new(vec![issuer_config(&idp)]);
        let token = idp.token(serde_json::json!({
            "aud": "kubernetes",
            "preferred_username": "octocat",
            "groups": ["firestoned:sandbox-users"],
        }));
        assert!(matches!(
            v.validate(&token).await,
            Err(IdpError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn missing_required_group_is_forbidden() {
        let idp = FakeIdp::start().await;
        let v = Validator::new(vec![issuer_config(&idp)]);
        let token = idp.token(serde_json::json!({
            "aud": "mediatore",
            "preferred_username": "octocat",
            "groups": ["firestoned:other"],
        }));
        assert!(matches!(
            v.validate(&token).await,
            Err(IdpError::Forbidden(_))
        ));
    }

    #[tokio::test]
    async fn unknown_issuer_is_rejected_before_any_fetch() {
        let idp = FakeIdp::start().await;
        let v = Validator::new(vec![]);
        let token = idp.token(serde_json::json!({ "aud": "mediatore" }));
        assert!(matches!(
            v.validate(&token).await,
            Err(IdpError::UnknownIssuer)
        ));
    }

    #[tokio::test]
    async fn expired_token_is_invalid() {
        let idp = FakeIdp::start().await;
        let v = Validator::new(vec![issuer_config(&idp)]);
        let token = idp.token(serde_json::json!({
            "aud": "mediatore",
            "preferred_username": "octocat",
            "groups": ["firestoned:sandbox-users"],
            "exp": chrono::Utc::now().timestamp() - 3600,
        }));
        assert!(matches!(
            v.validate(&token).await,
            Err(IdpError::Invalid(_))
        ));
    }

    #[tokio::test]
    async fn garbage_is_invalid() {
        let v = Validator::new(vec![]);
        assert!(v.validate("not-a-jwt").await.is_err());
    }
}
