//! Upstream identity providers.
//!
//! Two responsibilities:
//! 1. Validate the bearer token a caller presents to `POST /v1/claims` (issuer, audience,
//!    signature via JWKS, expiry, and the per-issuer authorisation gate).
//! 2. For the `entra-obo` backend, exchange that token for downstream access tokens.
//!
//! The JWKS fetch and the OBO call are stubs wired to `reqwest`; the shapes are final, the
//! bodies are the next commit.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use mediatore_proto::Subject;
use serde::{Deserialize, Serialize};

/// Which exchange mechanism serves an issuer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Backend {
    /// Entra ID On-Behalf-Of: mediatore is a confidential client with a certificate credential.
    EntraObo,
    /// mediatore signs its own tokens (see `mediatore-sts`); upstream is only for login.
    Sts,
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
    let (_h, payload) = (parts.next(), parts.next().ok_or_else(|| IdpError::Invalid("not a JWT".into()))?);
    let bytes = URL_SAFE_NO_PAD.decode(payload).map_err(|e| IdpError::Invalid(e.to_string()))?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| IdpError::Invalid(e.to_string()))?;
    v.get("iss")
        .and_then(|s| s.as_str())
        .map(ToOwned::to_owned)
        .ok_or_else(|| IdpError::Invalid("missing iss".into()))
}

/// Validates upstream tokens against a configured set of issuers.
#[derive(Debug, Clone)]
pub struct Validator {
    issuers: Vec<IssuerConfig>,
    http: reqwest::Client,
}

impl Validator {
    /// Build from config.
    #[must_use]
    pub fn new(issuers: Vec<IssuerConfig>) -> Self {
        Self { issuers, http: reqwest::Client::new() }
    }

    /// Find the issuer config for a token without trusting anything in it yet.
    pub fn issuer_for(&self, token: &str) -> Result<&IssuerConfig, IdpError> {
        let iss = peek_issuer(token)?;
        self.issuers.iter().find(|i| i.url == iss).ok_or(IdpError::UnknownIssuer)
    }

    /// Full validation: signature via the issuer's JWKS, `aud` == `client_id`, `exp`/`nbf`,
    /// subject claim present, group gate satisfied.
    ///
    /// JWKS discovery and caching are the next step; until then this returns
    /// `NotImplemented` after the issuer lookup so callers fail closed.
    pub async fn validate(&self, token: &str) -> Result<Validated, IdpError> {
        let issuer = self.issuer_for(token)?;
        tracing::debug!(issuer = %issuer.url, backend = ?issuer.backend, "validating upstream token");
        let _ = &self.http; // JWKS fetch lands here
        Err(IdpError::NotImplemented("JWKS signature validation"))
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
    #[must_use]
    pub fn new(tenant_id: impl Into<String>, client_id: impl Into<String>) -> Self {
        Self { tenant_id: tenant_id.into(), client_id: client_id.into(), http: reqwest::Client::new() }
    }

    /// Token endpoint for this tenant.
    #[must_use]
    pub fn token_endpoint(&self) -> String {
        format!("https://login.microsoftonline.com/{}/oauth2/v2.0/token", self.tenant_id)
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
            ("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"),
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
        resp.json::<Exchanged>().await.map_err(|e| IdpError::Upstream(e.to_string()))
    }
}
