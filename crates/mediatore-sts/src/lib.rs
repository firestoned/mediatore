//! mediatore as a Security Token Service.
//!
//! Used when the upstream IdP cannot delegate (Dex + GitHub in a homelab), and optionally at
//! work for internal services that validate JWTs against a JWKS. Tokens carry an RFC 8693
//! `act` claim naming the sandbox (its claim SVID) as the actor and the person as `sub`.

use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use mediatore_proto::Subject;
use serde::Serialize;
use uuid::Uuid;

/// Errors from minting.
#[derive(Debug, thiserror::Error)]
pub enum StsError {
    /// The signing key could not be parsed.
    #[error("signing key: {0}")]
    Key(jsonwebtoken::errors::Error),
    /// Encoding failed.
    #[error("encode: {0}")]
    Encode(jsonwebtoken::errors::Error),
    /// Requested TTL exceeds the configured maximum.
    #[error("ttl {requested}s exceeds max {max}s")]
    TtlTooLong {
        /// What was asked for.
        requested: i64,
        /// What is allowed.
        max: i64,
    },
}

/// RFC 8693 actor claim.
#[derive(Debug, Serialize)]
struct Actor<'a> {
    sub: &'a str,
}

#[derive(Debug, Serialize)]
struct Claims<'a> {
    iss: &'a str,
    sub: &'a str,
    aud: &'a str,
    exp: i64,
    iat: i64,
    nbf: i64,
    jti: String,
    act: Actor<'a>,
    claim_uid: Uuid,
    upstream_iss: &'a str,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    groups: Vec<String>,
}

/// What to mint.
#[derive(Debug)]
pub struct MintRequest<'a> {
    /// The person.
    pub subject: &'a Subject,
    /// The sandbox acting for them: its claim SPIFFE ID.
    pub actor_spiffe_id: &'a str,
    /// Kubernetes UID of the claim.
    pub claim_uid: Uuid,
    /// Exactly one downstream audience.
    pub audience: &'a str,
    /// Group memberships carried through from the upstream token.
    pub groups: Vec<String>,
    /// Requested lifetime; capped by [`Sts::max_ttl`].
    pub ttl: Duration,
}

/// A minted token.
#[derive(Debug)]
pub struct Minted {
    /// Compact JWS.
    pub token: String,
    /// Absolute expiry.
    pub expires_at: DateTime<Utc>,
}

/// ES256 token issuer.
pub struct Sts {
    issuer: String,
    kid: String,
    key: EncodingKey,
    max_ttl: Duration,
    jwks: serde_json::Value,
}

impl std::fmt::Debug for Sts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sts").field("issuer", &self.issuer).field("kid", &self.kid).finish()
    }
}

impl Sts {
    /// Build an issuer from a PKCS#8/SEC1 EC P-256 private key in PEM form and the matching
    /// public JWKS document (served at `/.well-known/jwks.json`).
    ///
    /// Deriving the JWK from the private key is a follow-up; for now both are supplied so
    /// the public half can also live outside the process (e.g. OpenBao transit).
    pub fn new(
        issuer: impl Into<String>,
        kid: impl Into<String>,
        private_key_pem: &[u8],
        jwks: serde_json::Value,
        max_ttl: Duration,
    ) -> Result<Self, StsError> {
        let key = EncodingKey::from_ec_pem(private_key_pem).map_err(StsError::Key)?;
        Ok(Self { issuer: issuer.into(), kid: kid.into(), key, max_ttl, jwks })
    }

    /// Issuer URL as written into `iss`.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Maximum lifetime this issuer will grant.
    #[must_use]
    pub fn max_ttl(&self) -> Duration {
        self.max_ttl
    }

    /// The public JWKS document.
    #[must_use]
    pub fn jwks(&self) -> &serde_json::Value {
        &self.jwks
    }

    /// Mint a token. `now` is injectable for tests.
    pub fn mint_at(&self, req: &MintRequest<'_>, now: DateTime<Utc>) -> Result<Minted, StsError> {
        if req.ttl > self.max_ttl {
            return Err(StsError::TtlTooLong {
                requested: req.ttl.num_seconds(),
                max: self.max_ttl.num_seconds(),
            });
        }
        let expires_at = now + req.ttl;
        let claims = Claims {
            iss: &self.issuer,
            sub: &req.subject.id,
            aud: req.audience,
            exp: expires_at.timestamp(),
            iat: now.timestamp(),
            nbf: now.timestamp() - 30,
            jti: Uuid::new_v4().to_string(),
            act: Actor { sub: req.actor_spiffe_id },
            claim_uid: req.claim_uid,
            upstream_iss: &req.subject.issuer,
            groups: req.groups.clone(),
        };
        let header = Header { alg: Algorithm::ES256, kid: Some(self.kid.clone()), ..Default::default() };
        let token = jsonwebtoken::encode(&header, &claims, &self.key).map_err(StsError::Encode)?;
        Ok(Minted { token, expires_at })
    }

    /// Mint a token as of now.
    pub fn mint(&self, req: &MintRequest<'_>) -> Result<Minted, StsError> {
        self.mint_at(req, Utc::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Throwaway P-256 key for tests only.
    const TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgFApsEtOoq/zU2AMl
NjczQzdEb8+EC12wyP1hNepqJkuhRANCAATOWnqq6rNaA6njNwPcprZBfF0+PImq
MUX5AKaxsGDNBXbbUOvRmJfjaSyiqtitNnd5Zd7UoxcUu0EiVY9OuHW2
-----END PRIVATE KEY-----
";

    #[test]
    fn rejects_ttl_over_max() {
        let sts = Sts::new(
            "https://mediatore.test",
            "k1",
            TEST_KEY.as_bytes(),
            serde_json::json!({"keys": []}),
            Duration::minutes(15),
        )
        .unwrap();
        let subject = Subject { issuer: "https://dex.test".into(), id: "octocat".into(), display: None };
        let req = MintRequest {
            subject: &subject,
            actor_spiffe_id: "spiffe://td/banlieue/claim/x",
            claim_uid: Uuid::new_v4(),
            audience: "grafana",
            groups: vec![],
            ttl: Duration::hours(2),
        };
        assert!(matches!(sts.mint(&req), Err(StsError::TtlTooLong { .. })));
    }

    #[test]
    fn mints_three_part_jws() {
        let sts = Sts::new(
            "https://mediatore.test",
            "k1",
            TEST_KEY.as_bytes(),
            serde_json::json!({"keys": []}),
            Duration::minutes(15),
        )
        .unwrap();
        let subject = Subject { issuer: "https://dex.test".into(), id: "octocat".into(), display: None };
        let req = MintRequest {
            subject: &subject,
            actor_spiffe_id: "spiffe://td/banlieue/claim/x",
            claim_uid: Uuid::new_v4(),
            audience: "grafana",
            groups: vec!["firestoned:sandbox-users".into()],
            ttl: Duration::minutes(5),
        };
        let m = sts.mint(&req).unwrap();
        assert_eq!(m.token.split('.').count(), 3);
    }
}
