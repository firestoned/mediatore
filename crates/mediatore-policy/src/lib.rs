// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! notaio's policy bundles as the broker reads them (ADR-0026).
//!
//! The verifier and the version floor's rule are notaio's (`sandboxpolicy-bundle`), linked at
//! a release tag and never re-implemented here (decision 1). This crate adds what is the
//! broker's: the trusted keys come from its configuration (decision 2), and the floor lives in
//! the store, moved by a compare and set so replicas cannot race it down (decisions 4 and 5).
//! [`admit`] is the one way in: verify, decide the floor, persist it, and only then hand back
//! the payload.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use chrono::{DateTime, Utc};
use mediatore_store::{ClaimStore, PolicyFloor, StoreError};
use sandboxpolicy_bundle::conformance::error_name;
use sandboxpolicy_bundle::floor::{FloorEntry, next_floor};
use sandboxpolicy_bundle::{BundleError, VerifyOptions, verify_bundle};
use serde::Deserialize;

pub use sandboxpolicy_bundle::{BundlePayload, Envelope, TrustedKeys};
/// The parts of a bundle's content (an audience grant, an egress rule, a lease), notaio's.
pub use sandboxpolicy_types as types;

/// How many times [`admit`] reads and decides again after losing a race for the floor.
const ATTEMPTS: usize = 3;

/// One key notaio signs bundles with, as configured under `policy.trusted_keys`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct TrustedKey {
    /// notaio's key id, `<transit key>:v<version>`, as the envelope's signature names it.
    pub id: String,
    /// The Ed25519 public key, standard base64 of its 32 bytes.
    pub public_key: String,
}

/// A configured key the broker refuses to start with (ADR-0026 decision 2).
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyError {
    /// The key id is empty.
    #[error("a trusted key has an empty id")]
    EmptyId,
    /// The same id twice: one of them would silently win.
    #[error("trusted key {0} is listed twice")]
    Duplicate(String),
    /// Not 32 bytes of standard base64, or not a valid Ed25519 point.
    #[error("trusted key {id}: {reason}")]
    Invalid {
        /// The key's id.
        id: String,
        /// Why it was refused.
        reason: String,
    },
}

/// The configured keys, ready for verification. Every key is checked; any bad one refuses.
///
/// # Errors
/// A [`KeyError`] naming the first key that is empty, listed twice, or not an Ed25519 key.
pub fn trusted_keys(configured: &[TrustedKey]) -> Result<TrustedKeys, KeyError> {
    let mut keys = TrustedKeys::new();
    let mut seen = std::collections::BTreeSet::new();
    for k in configured {
        if k.id.is_empty() {
            return Err(KeyError::EmptyId);
        }
        if !seen.insert(k.id.as_str()) {
            return Err(KeyError::Duplicate(k.id.clone()));
        }
        let invalid = |reason: String| KeyError::Invalid {
            id: k.id.clone(),
            reason,
        };
        let raw = STANDARD
            .decode(k.public_key.trim())
            .map_err(|e| invalid(format!("not standard base64: {e}")))?;
        let public: [u8; 32] = raw
            .try_into()
            .map_err(|raw: Vec<u8>| invalid(format!("{} bytes, not 32", raw.len())))?;
        keys.insert(&k.id, public)
            .map_err(|e| invalid(e.to_string()))?;
    }
    Ok(keys)
}

/// Why a bundle was not admitted. Nothing about it was used, and the floor did not move.
#[derive(Debug, thiserror::Error)]
pub enum Refusal {
    /// notaio's verifier or floor rule refused it.
    #[error(transparent)]
    Bundle(BundleError),
    /// The bundle names a policy in another namespace than the one it was read from: a copy,
    /// never the policy's own.
    #[error("a bundle for {bundle} found in namespace {found}")]
    Misplaced {
        /// The namespace the payload names.
        bundle: String,
        /// The namespace it was read from.
        found: String,
    },
    /// The floor could not be read or written.
    #[error("store: {0}")]
    Store(StoreError),
    /// Other replicas kept moving the floor; the next delivery of the bundle tries again.
    #[error("the floor of {0} kept moving")]
    Contended(String),
}

impl Refusal {
    /// A stable name for logs: notaio's error name (as its conformance vectors spell it) for
    /// a bundle it refused, otherwise this crate's.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Bundle(e) => error_name(e),
            Self::Misplaced { .. } => "Misplaced",
            Self::Store(_) => "Store",
            Self::Contended(_) => "Contended",
        }
    }
}

fn entry(f: &PolicyFloor) -> FloorEntry {
    FloorEntry {
        uid: f.uid.clone(),
        version: f.version,
        issued_at: f.issued_at,
    }
}

/// Verify `envelope`, read from a `ConfigMap` in `namespace`, decide its policy's version floor
/// with notaio's rule, persist the new floor, and only then return the payload (ADR-0026
/// decision 4). A bundle that comes back is one the broker may act on and will never forget
/// having seen; anything else is a [`Refusal`] and left the floor where it was.
///
/// # Errors
/// A [`Refusal`]: forged, expired, a downgrade or a stale incarnation (`Bundle`); a copy in the
/// wrong namespace (`Misplaced`); a store failure (`Store`); a floor that kept moving under
/// other replicas (`Contended`).
pub async fn admit(
    store: &dyn ClaimStore,
    envelope: &Envelope,
    namespace: &str,
    keys: &TrustedKeys,
    now: DateTime<Utc>,
) -> Result<BundlePayload, Refusal> {
    let payload =
        verify_bundle(envelope, keys, &VerifyOptions::at(now)).map_err(Refusal::Bundle)?;
    let policy = &payload.content.policy;
    if policy.namespace != namespace {
        return Err(Refusal::Misplaced {
            bundle: format!("{}/{}", policy.namespace, policy.name),
            found: namespace.to_string(),
        });
    }
    for _ in 0..ATTEMPTS {
        let held = store
            .get_policy_floor(&policy.namespace, &policy.name)
            .await
            .map_err(Refusal::Store)?;
        let decided =
            next_floor(held.as_ref().map(entry).as_ref(), &payload).map_err(Refusal::Bundle)?;
        let next = PolicyFloor {
            namespace: policy.namespace.clone(),
            name: policy.name.clone(),
            uid: decided.uid,
            version: decided.version,
            issued_at: decided.issued_at,
        };
        if held.as_ref() == Some(&next) {
            // A re-delivery that leaves the floor as it is: nothing to write.
            return Ok(payload);
        }
        match store.advance_policy_floor(held.as_ref(), next).await {
            Ok(()) => return Ok(payload),
            Err(StoreError::Conflict(_)) => {}
            Err(e) => return Err(Refusal::Store(e)),
        }
    }
    Err(Refusal::Contended(format!(
        "{}/{}",
        policy.namespace, policy.name
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use mediatore_store::MemoryStore;
    use sandboxpolicy_bundle::conformance::{self, Expect, Suite, Vector};

    fn suite() -> Suite {
        conformance::suite().expect("notaio's vectors parse")
    }

    fn configured(suite: &Suite) -> Vec<TrustedKey> {
        suite
            .trusted_keys
            .iter()
            .map(|k| TrustedKey {
                id: k.key_id.clone(),
                public_key: k.public_key.clone(),
            })
            .collect()
    }

    fn floor_of(suite: &Suite, e: &FloorEntry) -> PolicyFloor {
        PolicyFloor {
            namespace: suite.policy.namespace.clone(),
            name: suite.policy.name.clone(),
            uid: e.uid.clone(),
            version: e.version,
            issued_at: e.issued_at,
        }
    }

    /// One vector through exactly the calls the broker makes: the configured keys, a store
    /// seeded with the vector's floor, [`admit`].
    async fn check(suite: &Suite, keys: &TrustedKeys, v: &Vector) -> Result<(), String> {
        let store = MemoryStore::default();
        let held = v.floor.as_ref().map(|e| floor_of(suite, e));
        if let Some(h) = &held {
            store
                .advance_policy_floor(None, h.clone())
                .await
                .map_err(|e| e.to_string())?;
        }
        let (ns, name) = (&suite.policy.namespace, &suite.policy.name);
        let outcome = admit(&store, &v.envelope, ns, keys, v.now).await;
        let after = store
            .get_policy_floor(ns, name)
            .await
            .map_err(|e| e.to_string())?;
        match (&v.expect, outcome) {
            (
                Expect::Accepted {
                    version,
                    floor_after,
                },
                Ok(p),
            ) => {
                if p.meta.version != *version {
                    return Err(format!(
                        "accepted version {}, not {version}",
                        p.meta.version
                    ));
                }
                if after != Some(floor_of(suite, floor_after)) {
                    return Err(format!("floor after is {after:?}, not {floor_after:?}"));
                }
                Ok(())
            }
            (Expect::Refused { error }, Err(r)) if r.code() == error => {
                if after != held {
                    return Err("a refused bundle moved the floor".into());
                }
                Ok(())
            }
            (expect, got) => Err(format!(
                "expected {expect:?}, got {:?}",
                got.map(|p| p.meta.version).map_err(|r| r.code())
            )),
        }
    }

    #[tokio::test]
    async fn the_broker_reaches_notaios_verdict_on_every_conformance_vector() {
        let suite = suite();
        let keys = trusted_keys(&configured(&suite)).expect("the suite's keys");
        // v0.3.3 ships 14; a tag bump that ships fewer is worth a look before it passes.
        assert!(suite.vectors.len() >= 14, "{} vectors", suite.vectors.len());
        let mut failed = Vec::new();
        for v in &suite.vectors {
            if let Err(why) = check(&suite, &keys, v).await {
                failed.push(format!("{}: {why}", v.name));
            }
        }
        assert!(failed.is_empty(), "{failed:#?}");
    }

    #[tokio::test]
    async fn a_bundle_read_from_another_namespace_is_refused_and_moves_nothing() {
        let suite = suite();
        let keys = trusted_keys(&configured(&suite)).unwrap();
        let v = suite
            .vectors
            .iter()
            .find(|v| v.floor.is_none() && matches!(v.expect, Expect::Accepted { .. }))
            .expect("a first-sight vector");
        let store = MemoryStore::default();
        let r = admit(&store, &v.envelope, "elsewhere", &keys, v.now)
            .await
            .unwrap_err();
        assert_eq!(r.code(), "Misplaced", "{r}");
        let (ns, name) = (&suite.policy.namespace, &suite.policy.name);
        assert_eq!(store.get_policy_floor(ns, name).await.unwrap(), None);
    }

    #[tokio::test]
    async fn the_same_bundle_twice_is_admitted_twice_and_leaves_one_floor() {
        let suite = suite();
        let keys = trusted_keys(&configured(&suite)).unwrap();
        let v = suite
            .vectors
            .iter()
            .find(|v| v.floor.is_none() && matches!(v.expect, Expect::Accepted { .. }))
            .unwrap();
        let store = MemoryStore::default();
        let ns = &suite.policy.namespace;
        let first = admit(&store, &v.envelope, ns, &keys, v.now).await.unwrap();
        let again = admit(&store, &v.envelope, ns, &keys, v.now).await.unwrap();
        assert_eq!(first.meta.version, again.meta.version);
    }

    fn key(id: &str, public_key: &str) -> TrustedKey {
        TrustedKey {
            id: id.into(),
            public_key: public_key.into(),
        }
    }

    #[test]
    fn a_bad_configured_key_refuses_the_start() {
        let good = configured(&suite()).remove(0);
        assert!(trusted_keys(std::slice::from_ref(&good)).is_ok());
        // Two versions of the key side by side, as during a rotation.
        let mut rotated = good.clone();
        rotated.id = "notaio:v2".into();
        assert!(trusted_keys(&[good.clone(), rotated]).is_ok());

        assert_eq!(
            trusted_keys(&[good.clone(), good.clone()]).err(),
            Some(KeyError::Duplicate(good.id.clone()))
        );
        assert_eq!(
            trusted_keys(&[key("", &good.public_key)]).err(),
            Some(KeyError::EmptyId)
        );
        for bad in ["not base64!", "AAAA", ""] {
            assert!(
                matches!(
                    trusted_keys(&[key("notaio:v1", bad)]),
                    Err(KeyError::Invalid { .. })
                ),
                "{bad:?} was accepted"
            );
        }
    }
}
