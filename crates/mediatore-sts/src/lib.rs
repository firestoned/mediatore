//! mediatore as a Security Token Service.
//!
//! Used when the upstream `IdP` cannot delegate (Dex + GitHub in a homelab), and optionally at
//! work for internal services that validate JWTs against a JWKS. Tokens carry an RFC 8693
//! `act` claim naming the sandbox (its claim SVID) as the actor and the person as `sub`.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use mediatore_proto::Subject;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::pkcs8::DecodePrivateKey;
use serde::Serialize;
use uuid::Uuid;

/// Errors from minting.
#[derive(Debug, thiserror::Error)]
pub enum StsError {
    /// The signing key could not be parsed.
    #[error("signing key: {0}")]
    Key(jsonwebtoken::errors::Error),
    /// The public JWK could not be derived from the signing key.
    #[error("jwk derivation: {0}")]
    Jwk(String),
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
        f.debug_struct("Sts")
            .field("issuer", &self.issuer)
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

/// Derive the public JWK for a P-256 private key in PKCS#8 or SEC1 PEM form.
fn public_jwk(private_key_pem: &[u8], kid: &str) -> Result<serde_json::Value, StsError> {
    let pem = std::str::from_utf8(private_key_pem).map_err(|e| StsError::Jwk(e.to_string()))?;
    let secret = p256::SecretKey::from_pkcs8_pem(pem)
        .or_else(|_| p256::SecretKey::from_sec1_pem(pem))
        .map_err(|e| StsError::Jwk(e.to_string()))?;
    let public = secret.public_key();
    let point = public.to_encoded_point(false);
    let x = point
        .x()
        .ok_or_else(|| StsError::Jwk("point has no x coordinate".into()))?;
    let y = point
        .y()
        .ok_or_else(|| StsError::Jwk("point has no y coordinate".into()))?;
    Ok(serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "use": "sig",
        "alg": "ES256",
        "kid": kid,
        "x": URL_SAFE_NO_PAD.encode(x),
        "y": URL_SAFE_NO_PAD.encode(y),
    }))
}

impl Sts {
    /// Build an issuer from an EC P-256 private key in PKCS#8 or SEC1 PEM form.
    ///
    /// The public JWKS served at `/.well-known/jwks.json` is derived from the key, so the
    /// two can never drift. A signer whose key lives outside the process (`OpenBao` transit)
    /// will be a separate constructor.
    pub fn new(
        issuer: impl Into<String>,
        kid: impl Into<String>,
        private_key_pem: &[u8],
        max_ttl: Duration,
    ) -> Result<Self, StsError> {
        let key = EncodingKey::from_ec_pem(private_key_pem).map_err(StsError::Key)?;
        let kid: String = kid.into();
        let jwks = serde_json::json!({ "keys": [public_jwk(private_key_pem, &kid)?] });
        Ok(Self {
            issuer: issuer.into(),
            kid,
            key,
            max_ttl,
            jwks,
        })
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
            act: Actor {
                sub: req.actor_spiffe_id,
            },
            claim_uid: req.claim_uid,
            upstream_iss: &req.subject.issuer,
            groups: req.groups.clone(),
        };
        let header = Header {
            alg: Algorithm::ES256,
            kid: Some(self.kid.clone()),
            ..Default::default()
        };
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

    fn test_sts() -> Sts {
        Sts::new(
            "https://mediatore.test",
            "k1",
            TEST_KEY.as_bytes(),
            Duration::minutes(15),
        )
        .unwrap()
    }

    #[test]
    fn rejects_ttl_over_max() {
        let sts = test_sts();
        let subject = Subject {
            issuer: "https://dex.test".into(),
            id: "octocat".into(),
            display: None,
        };
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
        let sts = test_sts();
        let subject = Subject {
            issuer: "https://dex.test".into(),
            id: "octocat".into(),
            display: None,
        };
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

    #[test]
    fn jwks_is_derived_from_the_signing_key() {
        let sts = test_sts();
        let keys = sts.jwks()["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        let jwk = &keys[0];
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        assert_eq!(jwk["alg"], "ES256");
        assert_eq!(jwk["kid"], "k1");
        assert!(jwk["x"].as_str().is_some_and(|x| !x.is_empty()));
        assert!(jwk["y"].as_str().is_some_and(|y| !y.is_empty()));
    }

    #[test]
    fn minted_token_verifies_against_the_derived_jwk() {
        let sts = test_sts();
        let subject = Subject {
            issuer: "https://dex.test".into(),
            id: "octocat".into(),
            display: Some("octocat@example.com".into()),
        };
        let claim_uid = Uuid::new_v4();
        let req = MintRequest {
            subject: &subject,
            actor_spiffe_id: "spiffe://td/banlieue/claim/x",
            claim_uid,
            audience: "grafana",
            groups: vec![],
            ttl: Duration::minutes(5),
        };
        let m = sts.mint(&req).unwrap();

        let jwk = &sts.jwks()["keys"][0];
        let key = jsonwebtoken::DecodingKey::from_ec_components(
            jwk["x"].as_str().unwrap(),
            jwk["y"].as_str().unwrap(),
        )
        .unwrap();
        let mut validation = jsonwebtoken::Validation::new(Algorithm::ES256);
        validation.set_audience(&["grafana"]);
        validation.set_issuer(&["https://mediatore.test"]);
        let data = jsonwebtoken::decode::<serde_json::Value>(&m.token, &key, &validation).unwrap();
        assert_eq!(data.claims["sub"], "octocat");
        assert_eq!(data.claims["act"]["sub"], "spiffe://td/banlieue/claim/x");
        assert_eq!(data.claims["claim_uid"], claim_uid.to_string());
        assert_eq!(data.claims["upstream_iss"], "https://dex.test");
    }
}
