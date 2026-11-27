// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! mediatore as a Security Token Service.
//!
//! Used when the upstream `IdP` cannot delegate (Dex + GitHub in a homelab), and optionally at
//! work for internal services that validate JWTs against a JWKS. Tokens carry an RFC 8693
//! `act` claim naming the sandbox (its claim SVID) as the actor and the person as `sub`.
//!
//! The broker can trust several upstream issuers, and a subject id is unique only inside the
//! issuer that gave it. [`SubjectPrefixes`] is what keeps two people with the same id at two
//! issuers from getting the same `sub` (ADR-0071): each issuer's short prefix goes in front
//! of the id, and a set of issuers that could yield one `sub` for two people is refused
//! before anything is minted.

use std::borrow::Cow;
use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jiff::{SignedDuration, Timestamp};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use mediatore_proto::Subject;
use p256::elliptic_curve::sec1::ToSec1Point;
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
    /// The subject's issuer has no `subject_prefix` while others do (ADR-0071 decision 4):
    /// its bare id could be another issuer's qualified one, so nothing is minted.
    #[error("issuer {issuer} has no subject_prefix and this STS qualifies `sub` (ADR-0071)")]
    NoSubjectPrefix {
        /// The issuer the subject logged in at.
        issuer: String,
    },
}

/// The longest `issuers[].subject_prefix`, delimiter included.
pub const SUBJECT_PREFIX_MAX_LEN: usize = 32;

/// What every `issuers[].subject_prefix` ends with, and never holds before its end: the
/// prefix of a `sub` is everything up to and including the first one.
pub const SUBJECT_PREFIX_DELIMITER: char = ':';

/// Why a set of issuers cannot be given unambiguous `sub` values (ADR-0071 decisions 1 and
/// 3). Each message names the configuration key and the issuer by its `url`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SubjectPrefixError {
    /// Not the form decision 1 allows.
    #[error(
        "issuers[{issuer}].subject_prefix {prefix:?} must be 1 to 31 of a-z, 0-9, '.', '_' and '-', the first a letter or a digit, followed by one ':' (ADR-0071 decision 1)"
    )]
    Form {
        /// The issuer's `url`.
        issuer: String,
        /// The value as written.
        prefix: String,
    },
    /// Several issuers and this one has no prefix.
    #[error(
        "issuers[{issuer}].subject_prefix is not set: with {count} issuers every one needs a subject_prefix, or two people with the same subject id at two issuers would be minted the same `sub` (ADR-0071 decision 3)"
    )]
    Missing {
        /// The issuer's `url`.
        issuer: String,
        /// How many issuers are configured.
        count: usize,
    },
    /// Two issuers whose prefixes are equal, or one the start of the other.
    #[error(
        "issuers[{issuer}].subject_prefix {prefix:?} and issuers[{other}].subject_prefix {other_prefix:?} overlap: the two issuers could be minted the same `sub` (ADR-0071 decision 3)"
    )]
    Overlap {
        /// The later issuer's `url`.
        issuer: String,
        /// Its prefix.
        prefix: String,
        /// The earlier issuer's `url`.
        other: String,
        /// Its prefix.
        other_prefix: String,
    },
}

/// Whether `prefix` has the form of ADR-0071 decision 1: a letter or digit, then letters,
/// digits, `.`, `_` or `-` (lower case only, so a verifier that folds case cannot merge
/// two), then exactly one [`SUBJECT_PREFIX_DELIMITER`], at most
/// [`SUBJECT_PREFIX_MAX_LEN`] bytes in all.
#[must_use]
pub fn subject_prefix_is_well_formed(prefix: &str) -> bool {
    let Some(body) = prefix.strip_suffix(SUBJECT_PREFIX_DELIMITER) else {
        return false;
    };
    prefix.len() <= SUBJECT_PREFIX_MAX_LEN
        && body
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && body.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        })
}

/// The `sub` prefix of each trusted issuer, checked as a set (ADR-0071).
///
/// Built only by [`SubjectPrefixes::new`], so a value of this type is always one under which
/// two different issuers cannot be minted the same `sub`: either there is one issuer at
/// most and no prefix (the bare id, as before ADR-0071), or every issuer that is known here
/// has a prefix and no prefix is the start of another.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SubjectPrefixes {
    by_issuer: BTreeMap<String, String>,
}

impl SubjectPrefixes {
    /// Check the issuers as `(url, subject_prefix)` pairs, in configuration order.
    ///
    /// # Errors
    /// [`SubjectPrefixError::Form`] for a prefix outside decision 1's form, whatever the
    /// number of issuers; [`SubjectPrefixError::Missing`] when there are two or more
    /// issuers and one has none; [`SubjectPrefixError::Overlap`] when two are equal or one
    /// starts with the other.
    pub fn new<'a>(
        issuers: impl IntoIterator<Item = (&'a str, Option<&'a str>)>,
    ) -> Result<Self, SubjectPrefixError> {
        let issuers: Vec<_> = issuers.into_iter().collect();
        let count = issuers.len();
        let mut seen: Vec<(&str, &str)> = Vec::with_capacity(count);
        for (issuer, prefix) in issuers {
            let Some(prefix) = prefix else {
                if count > 1 {
                    return Err(SubjectPrefixError::Missing {
                        issuer: issuer.to_owned(),
                        count,
                    });
                }
                continue;
            };
            if !subject_prefix_is_well_formed(prefix) {
                return Err(SubjectPrefixError::Form {
                    issuer: issuer.to_owned(),
                    prefix: prefix.to_owned(),
                });
            }
            // The form already makes "starts with" mean "equals" (the delimiter is last and
            // nowhere else); the wider test is kept so the property does not rest on it.
            if let Some((other, other_prefix)) = seen
                .iter()
                .find(|(_, p)| p.starts_with(prefix) || prefix.starts_with(p))
            {
                return Err(SubjectPrefixError::Overlap {
                    issuer: issuer.to_owned(),
                    prefix: prefix.to_owned(),
                    other: (*other).to_owned(),
                    other_prefix: (*other_prefix).to_owned(),
                });
            }
            seen.push((issuer, prefix));
        }
        Ok(Self {
            by_issuer: seen
                .into_iter()
                .map(|(issuer, prefix)| (issuer.to_owned(), prefix.to_owned()))
                .collect(),
        })
    }

    /// True when no issuer has a prefix: `sub` is the bare subject id.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_issuer.is_empty()
    }

    /// The prefix of the issuer with this `url`, when it has one.
    #[must_use]
    pub fn get(&self, issuer: &str) -> Option<&str> {
        self.by_issuer.get(issuer).map(String::as_str)
    }

    /// The `sub` for `subject`: its issuer's prefix and then its id, or the bare id when no
    /// issuer has a prefix.
    ///
    /// # Errors
    /// [`StsError::NoSubjectPrefix`] when some issuer has a prefix and this subject's does
    /// not (an issuer this set was not built with): fail closed, its bare id is not minted
    /// beside qualified ones.
    pub fn sub<'a>(&self, subject: &'a Subject) -> Result<Cow<'a, str>, StsError> {
        match self.by_issuer.get(&subject.issuer) {
            Some(prefix) => Ok(Cow::Owned(format!("{prefix}{}", subject.id))),
            None if self.by_issuer.is_empty() => Ok(Cow::Borrowed(&subject.id)),
            None => Err(StsError::NoSubjectPrefix {
                issuer: subject.issuer.clone(),
            }),
        }
    }
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
    /// Requested lifetime; capped by [`Sts::max_ttl_for`] the audience.
    pub ttl: SignedDuration,
}

/// A minted token.
#[derive(Debug)]
pub struct Minted {
    /// Compact JWS.
    pub token: String,
    /// Absolute expiry.
    pub expires_at: Timestamp,
}

/// ES256 token issuer.
pub struct Sts {
    issuer: String,
    kid: String,
    key: EncodingKey,
    max_ttl: SignedDuration,
    /// Per audience, a maximum of its own below `max_ttl` ([`Sts::with_audience_max_ttl`]).
    audience_max_ttl: BTreeMap<String, SignedDuration>,
    /// Per upstream issuer, what goes in front of the subject id in `sub`
    /// ([`Sts::with_subject_prefixes`]); empty is the bare id.
    subject_prefixes: SubjectPrefixes,
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
    let point = public.to_sec1_point(false);
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
        max_ttl: SignedDuration,
    ) -> Result<Self, StsError> {
        let key = EncodingKey::from_ec_pem(private_key_pem).map_err(StsError::Key)?;
        let kid: String = kid.into();
        let jwks = serde_json::json!({ "keys": [public_jwk(private_key_pem, &kid)?] });
        Ok(Self {
            issuer: issuer.into(),
            kid,
            key,
            max_ttl,
            audience_max_ttl: BTreeMap::new(),
            subject_prefixes: SubjectPrefixes::default(),
            jwks,
        })
    }

    /// Bound tokens for `audience` to `max_ttl` (the audience's own `max_ttl` from the
    /// configuration), whatever the other audiences allow. A value above the issuer's
    /// maximum changes nothing: the lower of the two applies.
    #[must_use]
    pub fn with_audience_max_ttl(
        mut self,
        audience: impl Into<String>,
        max_ttl: SignedDuration,
    ) -> Self {
        self.audience_max_ttl.insert(audience.into(), max_ttl);
        self
    }

    /// Qualify `sub` by upstream issuer (ADR-0071): a subject of an issuer with a prefix is
    /// minted `<prefix><id>`. The set was checked when it was built, so two issuers cannot
    /// be minted the same `sub`. Without this call, or with an empty set, `sub` is the bare
    /// id: right for one issuer, and what every token was before ADR-0071.
    #[must_use]
    pub fn with_subject_prefixes(mut self, prefixes: SubjectPrefixes) -> Self {
        self.subject_prefixes = prefixes;
        self
    }

    /// Maximum lifetime of a token for `audience`: its own maximum when it has one, never
    /// above [`Self::max_ttl`].
    #[must_use]
    pub fn max_ttl_for(&self, audience: &str) -> SignedDuration {
        self.audience_max_ttl
            .get(audience)
            .map_or(self.max_ttl, |own| (*own).min(self.max_ttl))
    }

    /// Issuer URL as written into `iss`.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Maximum lifetime this issuer will grant.
    #[must_use]
    pub fn max_ttl(&self) -> SignedDuration {
        self.max_ttl
    }

    /// The public JWKS document.
    #[must_use]
    pub fn jwks(&self) -> &serde_json::Value {
        &self.jwks
    }

    /// Mint a token that expires `req.ttl` after `now`. `now` is the caller's when it has
    /// already measured the lifetime against a deadline of its own (a claim's), and
    /// injectable for tests.
    ///
    /// # Errors
    /// [`StsError::TtlTooLong`] when `req.ttl` is above [`Self::max_ttl_for`] the audience;
    /// [`StsError::NoSubjectPrefix`] when `sub` is qualified and the subject's issuer has no
    /// prefix; [`StsError::Encode`] when signing fails.
    pub fn mint_at(&self, req: &MintRequest<'_>, now: Timestamp) -> Result<Minted, StsError> {
        let max = self.max_ttl_for(req.audience);
        if req.ttl > max {
            return Err(StsError::TtlTooLong {
                requested: req.ttl.as_secs(),
                max: max.as_secs(),
            });
        }
        let expires_at = now + req.ttl;
        let sub = self.subject_prefixes.sub(req.subject)?;
        let claims = Claims {
            iss: &self.issuer,
            sub: &sub,
            aud: req.audience,
            exp: expires_at.as_second(),
            iat: now.as_second(),
            nbf: now.as_second() - 30,
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
        self.mint_at(req, Timestamp::now())
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
            SignedDuration::from_mins(15),
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
            ttl: SignedDuration::from_hours(2),
        };
        assert!(matches!(sts.mint(&req), Err(StsError::TtlTooLong { .. })));
    }

    #[test]
    fn an_audience_with_a_maximum_of_its_own_is_held_to_it_and_the_others_are_not() {
        let sts = test_sts()
            .with_audience_max_ttl("short", SignedDuration::from_mins(2))
            .with_audience_max_ttl("generous", SignedDuration::from_hours(2));
        assert_eq!(sts.max_ttl_for("short"), SignedDuration::from_mins(2));
        assert_eq!(sts.max_ttl_for("grafana"), SignedDuration::from_mins(15));
        assert_eq!(
            sts.max_ttl_for("generous"),
            SignedDuration::from_mins(15),
            "never above the issuer's maximum"
        );
        let subject = Subject {
            issuer: "https://dex.test".into(),
            id: "octocat".into(),
            display: None,
        };
        let request = |audience: &'static str, ttl: SignedDuration| MintRequest {
            subject: &subject,
            actor_spiffe_id: "spiffe://td/banlieue/claim/x",
            claim_uid: Uuid::new_v4(),
            audience,
            groups: vec![],
            ttl,
        };
        let five = SignedDuration::from_mins(5);
        assert!(matches!(
            sts.mint(&request("short", five)),
            Err(StsError::TtlTooLong { max: 120, .. })
        ));
        assert!(sts.mint(&request("grafana", five)).is_ok());
        assert!(
            sts.mint(&request("short", SignedDuration::from_mins(2)))
                .is_ok()
        );
    }

    #[test]
    fn a_token_expires_ttl_after_the_instant_it_is_minted_at() {
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
            ttl: SignedDuration::from_secs(60),
        };
        let now = Timestamp::now();
        let m = sts.mint_at(&req, now).unwrap();
        assert_eq!(m.expires_at, now + SignedDuration::from_secs(60));

        let jwk = &sts.jwks()["keys"][0];
        let key = jsonwebtoken::DecodingKey::from_ec_components(
            jwk["x"].as_str().unwrap(),
            jwk["y"].as_str().unwrap(),
        )
        .unwrap();
        let mut validation = jsonwebtoken::Validation::new(Algorithm::ES256);
        validation.set_audience(&["grafana"]);
        let data = jsonwebtoken::decode::<serde_json::Value>(&m.token, &key, &validation).unwrap();
        assert_eq!(data.claims["exp"], m.expires_at.as_second());
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
            ttl: SignedDuration::from_mins(5),
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
            ttl: SignedDuration::from_mins(5),
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

    // ----- ADR-0071: `sub` qualified by upstream issuer ---------------------------------------------

    const DEX: &str = "https://dex.test";
    const OTHER: &str = "https://login.example.com";

    fn subject_at(issuer: &str) -> Subject {
        Subject {
            issuer: issuer.into(),
            id: "octocat".into(),
            display: None,
        }
    }

    /// The `sub` and `upstream_iss` of a token minted for `subject`, read after verification.
    fn minted_sub(sts: &Sts, subject: &Subject) -> Result<(String, String), StsError> {
        let m = sts.mint(&MintRequest {
            subject,
            actor_spiffe_id: "spiffe://td/banlieue/claim/x",
            claim_uid: Uuid::new_v4(),
            audience: "grafana",
            groups: vec![],
            ttl: SignedDuration::from_mins(5),
        })?;
        let jwk = &sts.jwks()["keys"][0];
        let key = jsonwebtoken::DecodingKey::from_ec_components(
            jwk["x"].as_str().unwrap(),
            jwk["y"].as_str().unwrap(),
        )
        .unwrap();
        let mut validation = jsonwebtoken::Validation::new(Algorithm::ES256);
        validation.set_audience(&["grafana"]);
        let claims = jsonwebtoken::decode::<serde_json::Value>(&m.token, &key, &validation)
            .unwrap()
            .claims;
        Ok((
            claims["sub"].as_str().unwrap().to_owned(),
            claims["upstream_iss"].as_str().unwrap().to_owned(),
        ))
    }

    #[test]
    fn one_issuer_without_a_prefix_keeps_the_bare_sub() {
        let prefixes = SubjectPrefixes::new([(DEX, None)]).unwrap();
        assert!(prefixes.is_empty());
        let sts = test_sts().with_subject_prefixes(prefixes);
        assert_eq!(
            minted_sub(&sts, &subject_at(DEX)).unwrap(),
            ("octocat".to_owned(), DEX.to_owned())
        );
        // No issuer at all (a broker that only places secrets) is the same empty set.
        assert!(SubjectPrefixes::new([]).unwrap().is_empty());
    }

    #[test]
    fn a_prefixed_issuers_sub_is_the_prefix_then_the_subject_id() {
        let prefixes = SubjectPrefixes::new([(DEX, Some("dex:"))]).unwrap();
        assert_eq!(prefixes.get(DEX), Some("dex:"));
        let sts = test_sts().with_subject_prefixes(prefixes);
        assert_eq!(
            minted_sub(&sts, &subject_at(DEX)).unwrap(),
            ("dex:octocat".to_owned(), DEX.to_owned()),
            "the prefix, then the id; upstream_iss stays"
        );
    }

    #[test]
    fn the_same_subject_id_at_two_issuers_mints_two_different_subs() {
        let sts = test_sts().with_subject_prefixes(
            SubjectPrefixes::new([(DEX, Some("dex:")), (OTHER, Some("corp:"))]).unwrap(),
        );
        let (dex, _) = minted_sub(&sts, &subject_at(DEX)).unwrap();
        let (other, _) = minted_sub(&sts, &subject_at(OTHER)).unwrap();
        assert_eq!(dex, "dex:octocat");
        assert_eq!(other, "corp:octocat");
        assert_ne!(dex, other);
    }

    #[test]
    fn two_issuers_without_prefixes_are_refused_naming_the_key() {
        let err = SubjectPrefixes::new([(DEX, None), (OTHER, None)]).unwrap_err();
        assert_eq!(
            err,
            SubjectPrefixError::Missing {
                issuer: DEX.into(),
                count: 2
            }
        );
        let text = err.to_string();
        assert!(
            text.contains(&format!("issuers[{DEX}].subject_prefix")),
            "{text}"
        );
    }

    #[test]
    fn two_issuers_with_one_prefix_missing_are_refused() {
        for issuers in [
            [(DEX, Some("dex:")), (OTHER, None)],
            [(OTHER, None), (DEX, Some("dex:"))],
        ] {
            assert_eq!(
                SubjectPrefixes::new(issuers).unwrap_err(),
                SubjectPrefixError::Missing {
                    issuer: OTHER.into(),
                    count: 2
                }
            );
        }
    }

    #[test]
    fn two_issuers_with_the_same_prefix_are_refused() {
        let err = SubjectPrefixes::new([(DEX, Some("idp:")), (OTHER, Some("idp:"))]).unwrap_err();
        assert!(
            matches!(&err, SubjectPrefixError::Overlap { issuer, other, .. } if issuer == OTHER && other == DEX),
            "{err}"
        );
        let text = err.to_string();
        assert!(text.contains("subject_prefix"), "{text}");
    }

    #[test]
    fn a_prefix_outside_the_charset_or_without_the_delimiter_is_refused() {
        for good in ["dex:", "a:", "corp-2.eu_west:", "0:"] {
            assert!(subject_prefix_is_well_formed(good), "{good}");
        }
        let long = format!("{}:", "a".repeat(SUBJECT_PREFIX_MAX_LEN));
        for bad in [
            "",
            ":",
            "dex",
            "dex/",
            "Dex:",
            "dex :",
            "-dex:",
            ".dex:",
            "dex::",
            "a:b:",
            "d\u{e9}x:",
            "dex:|",
            " dex:",
            &long,
        ] {
            assert!(!subject_prefix_is_well_formed(bad), "{bad:?}");
            // One issuer or several, a malformed prefix is refused, with the key named.
            let err = SubjectPrefixes::new([(DEX, Some(bad))]).unwrap_err();
            assert_eq!(
                err,
                SubjectPrefixError::Form {
                    issuer: DEX.into(),
                    prefix: bad.into()
                }
            );
        }
        let longest = format!("{}:", "a".repeat(SUBJECT_PREFIX_MAX_LEN - 1));
        assert!(subject_prefix_is_well_formed(&longest));
    }

    #[test]
    fn no_prefix_can_be_the_start_of_another() {
        // `a:` inside `a:b:` would let (`a:`, id `b:x`) and (`a:b:`, id `x`) be one `sub`.
        // The form refuses the second, and the set check would refuse the pair by itself.
        assert_eq!(
            SubjectPrefixes::new([(DEX, Some("a:")), (OTHER, Some("a:b:"))]).unwrap_err(),
            SubjectPrefixError::Form {
                issuer: OTHER.into(),
                prefix: "a:b:".into()
            }
        );
        // A subject id may itself hold the delimiter: the prefix is up to the first one.
        let sts = test_sts().with_subject_prefixes(
            SubjectPrefixes::new([(DEX, Some("a:")), (OTHER, Some("ab:"))]).unwrap(),
        );
        let odd = Subject {
            issuer: DEX.into(),
            id: "b:octocat".into(),
            display: None,
        };
        assert_eq!(minted_sub(&sts, &odd).unwrap().0, "a:b:octocat");
        assert_eq!(
            minted_sub(&sts, &subject_at(OTHER)).unwrap().0,
            "ab:octocat"
        );
    }

    #[test]
    fn an_issuer_without_an_entry_is_refused_at_mint_once_any_prefix_is_configured() {
        let sts =
            test_sts().with_subject_prefixes(SubjectPrefixes::new([(DEX, Some("dex:"))]).unwrap());
        let err = minted_sub(&sts, &subject_at(OTHER)).unwrap_err();
        assert!(
            matches!(&err, StsError::NoSubjectPrefix { issuer } if issuer == OTHER),
            "{err}"
        );
    }
}
