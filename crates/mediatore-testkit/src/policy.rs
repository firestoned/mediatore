// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! A notaio bundle signed here and now (ADR-0026). notaio's conformance vectors are fixed at
//! 2026-01-01 and expired against any real clock, so a test that drives the reflector at
//! `Timestamp::now()` signs its own bundle: the conformance content under a key of this module's,
//! valid for an hour either side of `now`. The key is a fixed seed, test-only; it signs
//! nothing a real broker trusts.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use jiff::{SignedDuration, Timestamp};
use k8s_openapi::api::core::v1::ConfigMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use sandboxpolicy_bundle::conformance;
use sandboxpolicy_bundle::{
    AudienceBundleContent, AudienceBundlePayload, AudienceRef, BundleContent, BundleMeta,
    BundlePayload, Ed25519Signer, Envelope, Signature, Signer as _, Subjects, TrustedKeys,
    VerifyOptions, sign_audience_bundle, sign_bundle, verify_bundle,
};
use sandboxpolicy_types::AudienceDefinition;

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
pub fn fresh_bundle(now: Timestamp, version: u64) -> FreshBundle {
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
    signed_bundle(now, version, content)
}

/// `content` at `version`, issued an hour before `now` and valid an hour after it, signed
/// under [`KEY_ID`]: a bundle that differs from the conformance one where a test needs it
/// to (a shorter lease, another audience). The same key as [`fresh_bundle`], so one
/// reflector admits both.
///
/// # Panics
/// If `content` has no canonical form (a float in it), which the conformance content and
/// any edit of its integers never has.
#[must_use]
pub fn signed_bundle(now: Timestamp, version: u64, content: BundleContent) -> FreshBundle {
    let payload = BundlePayload::new(window(now, version), content)
        .expect("the conformance content is canonical");
    signed(payload)
}

/// `content` as a schema v4 bundle (notaio ADR-0026) at `version`, stating `groups` as its
/// subjects, in the same window and under the same key as [`signed_bundle`]: the v4 twin of
/// the v3 bundle that function signs for the same content.
///
/// # Panics
/// As [`signed_bundle`], and if `content` already carries v4 members that make it
/// non-canonical, which the conformance content never does.
#[must_use]
pub fn signed_bundle_v4(
    now: Timestamp,
    version: u64,
    mut content: BundleContent,
    groups: &[&str],
) -> FreshBundle {
    content.subjects = Some(Subjects {
        groups: groups.iter().map(|g| (*g).to_owned()).collect(),
    });
    let payload = BundlePayload::new_v4(window(now, version), content)
        .expect("v4 content with subjects is canonical");
    signed(payload)
}

/// An envelope of `payload_type` carrying `payload` exactly as given, signed under [`KEY_ID`]
/// over its DSSE pre-authentication encoding: a bundle of a schema or payload type notaio
/// does not write, with a signature a reflector trusting [`fresh_bundle`]'s keys accepts, so
/// whatever refuses it is the schema check and not the signature.
///
/// # Panics
/// Never: the signer is in process.
#[must_use]
pub fn signed_raw(payload_type: &str, payload: &[u8]) -> Envelope {
    let mut message = format!(
        "DSSEv1 {} {payload_type} {} ",
        payload_type.len(),
        payload.len()
    )
    .into_bytes();
    message.extend_from_slice(payload);
    let sig = signer().sign(&message).expect("signs");
    Envelope {
        payload_type: payload_type.to_owned(),
        payload: STANDARD.encode(payload),
        signatures: vec![Signature {
            keyid: KEY_ID.to_owned(),
            sig: STANDARD.encode(sig),
        }],
    }
}

fn window(now: Timestamp, version: u64) -> BundleMeta {
    BundleMeta {
        version,
        issued_at: now - SignedDuration::from_hours(1),
        not_after: now + SignedDuration::from_hours(1),
    }
}

fn signer() -> Ed25519Signer {
    Ed25519Signer::from_seed(KEY_ID, [0x42; 32])
}

fn signed(payload: BundlePayload) -> FreshBundle {
    let signer = signer();
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

/// An audience bundle signed by [`signed_audience`] (ADR-0055), with the keys that verify it.
pub struct FreshAudience {
    /// Trusts [`KEY_ID`] and nothing else: the same keys as [`fresh_bundle`]'s.
    pub keys: TrustedKeys,
    /// The signed envelope, as notaio writes it into `<audience>-audience`.
    pub envelope: Envelope,
    /// What the envelope carries.
    pub payload: AudienceBundlePayload,
}

/// `definition` as the audience `namespace`/`name` at `version`, issued an hour before `now`
/// and valid an hour after it, signed under [`KEY_ID`]. The incarnation is
/// `uid-<namespace>-<name>`, so a test that wants a new incarnation names it differently.
///
/// # Panics
/// If the definition has no canonical form, which a definition of strings and integers never
/// lacks.
#[must_use]
pub fn signed_audience(
    now: Timestamp,
    version: u64,
    namespace: &str,
    name: &str,
    definition: AudienceDefinition,
) -> FreshAudience {
    let payload = AudienceBundlePayload::new(
        BundleMeta {
            version,
            issued_at: now - SignedDuration::from_hours(1),
            not_after: now + SignedDuration::from_hours(1),
        },
        AudienceBundleContent {
            audience: AudienceRef {
                namespace: namespace.into(),
                name: name.into(),
                uid: format!("uid-{namespace}-{name}"),
            },
            definition,
        },
    )
    .expect("the definition is canonical");
    let signer = Ed25519Signer::from_seed(KEY_ID, [0x42; 32]);
    let mut keys = TrustedKeys::new();
    keys.insert(KEY_ID, signer.verifying_key_bytes())
        .expect("a 32-byte key");
    let envelope = sign_audience_bundle(&payload, &signer).expect("signs");
    FreshAudience {
        keys,
        envelope,
        payload,
    }
}

/// The `ConfigMap` notaio writes for an audience bundle: `<audience>-audience`, labelled
/// `managed-by=notaio`, the envelope under `audience.dsse.json`.
///
/// # Panics
/// If the envelope does not serialize, which a signed one always does.
#[must_use]
pub fn audience_configmap(namespace: &str, audience: &str, envelope: &Envelope) -> ConfigMap {
    let mut cm = bundle_configmap(namespace, &format!("{audience}-audience"), envelope);
    let text = serde_json::to_string(envelope).expect("an envelope serializes");
    cm.data = Some(BTreeMap::from([("audience.dsse.json".to_string(), text)]));
    cm
}
