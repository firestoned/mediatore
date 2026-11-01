// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! A notaio bundle signed here and now (ADR-0026). notaio's conformance vectors are fixed at
//! 2026-01-01 and expired against any real clock, so a test that drives the reflector at
//! `Utc::now()` signs its own bundle: the conformance content under a key of this module's,
//! valid for an hour either side of `now`. The key is a fixed seed, test-only; it signs
//! nothing a real broker trusts.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use k8s_openapi::api::core::v1::ConfigMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use sandboxpolicy_bundle::conformance;
use sandboxpolicy_bundle::{
    BundleMeta, BundlePayload, Ed25519Signer, Envelope, TrustedKeys, VerifyOptions, sign_bundle,
    verify_bundle,
};

/// The key id the fresh bundle is signed under.
pub const KEY_ID: &str = "testkit:v1";

/// A bundle signed by [`fresh_bundle`], with the keys that verify it and the payload inside.
pub struct FreshBundle {
    /// Trusts [`KEY_ID`] and nothing else.
    pub keys: TrustedKeys,
    /// The signed envelope, as notaio would write it into a `ConfigMap`.
    pub envelope: Envelope,
    /// What the envelope carries: the conformance policy (`conformance/agent`) at `version`.
    pub payload: BundlePayload,
}

/// The conformance content at `version`, issued an hour before `now` and valid an hour
/// after it, signed under [`KEY_ID`].
///
/// # Panics
/// If notaio's checked-in vectors do not parse or verify, which its own release gate rules
/// out.
#[must_use]
pub fn fresh_bundle(now: DateTime<Utc>, version: u64) -> FreshBundle {
    let suite = conformance::suite().expect("notaio's vectors parse");
    let base = suite
        .vectors
        .iter()
        .find(|v| v.name == "accepted-first-sight")
        .expect("the first-sight vector");
    let content = verify_bundle(
        &base.envelope,
        &suite.keys().expect("the suite's keys"),
        &VerifyOptions::at(base.now),
    )
    .expect("the vector verifies at its own clock")
    .content;
    let payload = BundlePayload::new(
        BundleMeta {
            version,
            issued_at: now - Duration::hours(1),
            not_after: now + Duration::hours(1),
        },
        content,
    )
    .expect("the conformance content is canonical");
    let signer = Ed25519Signer::from_seed(KEY_ID, [0x42; 32]);
    let mut keys = TrustedKeys::new();
    keys.insert(KEY_ID, signer.verifying_key_bytes())
        .expect("a 32-byte key");
    let envelope = sign_bundle(&payload, &signer).expect("signs");
    FreshBundle {
        keys,
        envelope,
        payload,
    }
}

/// The `ConfigMap` notaio writes for a bundle: labelled `managed-by=notaio`, the envelope
/// under `bundle.dsse.json`, in the policy's namespace.
///
/// # Panics
/// If the envelope does not serialize, which one from [`fresh_bundle`] always does.
#[must_use]
pub fn bundle_configmap(namespace: &str, name: &str, envelope: &Envelope) -> ConfigMap {
    ConfigMap {
        metadata: ObjectMeta {
            name: Some(name.into()),
            namespace: Some(namespace.into()),
            labels: Some(BTreeMap::from([(
                "app.kubernetes.io/managed-by".to_string(),
                "notaio".to_string(),
            )])),
            ..ObjectMeta::default()
        },
        data: Some(BTreeMap::from([(
            "bundle.dsse.json".to_string(),
            serde_json::to_string(envelope).expect("an envelope serializes"),
        )])),
        ..ConfigMap::default()
    }
}
