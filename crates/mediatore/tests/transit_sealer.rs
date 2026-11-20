// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The transit sealer (ADR-0015) against the fake `OpenBao`: the binding as derivation
//! context, the key id, the startup probe, token renewal after a revocation, an outage as
//! `Unavailable` rather than a refusal, and a rotation that keeps old envelopes readable.

use mediatore_store::seal::{
    FORMAT_BARE_UID, FORMAT_SLOT, SealError, SealPurpose, Sealer, Slot, TransitConfig,
    TransitSealer,
};
use mediatore_testkit::FakeTransit;
use uuid::Uuid;

const ROLE: &str = "mediatore";
const KEY: &str = "mediatore";

/// A projected token file, as the kubelet would write it.
fn token_file(dir: &std::path::Path, jwt: &str) -> std::path::PathBuf {
    let path = dir.join("token");
    std::fs::write(&path, jwt).unwrap();
    path
}

fn config(fake: &FakeTransit, token_file: std::path::PathBuf) -> TransitConfig {
    TransitConfig {
        url: fake.url.clone(),
        ca_file: None,
        mount: "transit".into(),
        key: KEY.into(),
        role: ROLE.into(),
        token_file,
        auth_mount: "kubernetes".into(),
    }
}

async fn sealer(fake: &FakeTransit, dir: &std::path::Path) -> TransitSealer {
    TransitSealer::connect(&config(fake, token_file(dir, "sa-jwt")))
        .await
        .expect("the probe round-trips")
}

#[tokio::test]
async fn an_envelope_opens_only_for_its_binding_and_names_the_transit_key() {
    let dir = tempdir();
    let fake = FakeTransit::spawn(ROLE, "sa-jwt", KEY).await;
    let s = sealer(&fake, &dir).await;
    assert_eq!(s.key_id(), "transit:transit/mediatore");
    let uid = Uuid::new_v4();
    let env = s.seal_session(Slot::Issuer, uid, b"refresh").await.unwrap();
    assert_eq!(env.key_id, s.key_id());
    assert_eq!(env.nonce.len(), 0, "OpenBao owns the nonce");
    assert_eq!(env.format, FORMAT_SLOT, "everything sealed now is format 2");
    assert!(
        env.ciphertext.starts_with(b"vault:v1:"),
        "{:?}",
        String::from_utf8_lossy(&env.ciphertext)
    );
    assert_eq!(
        s.unseal_session(Slot::Issuer, uid, &env).await.unwrap(),
        b"refresh"
    );
    // The context is the binding: another UID derives another key.
    assert!(matches!(
        s.unseal_session(Slot::Issuer, Uuid::new_v4(), &env).await,
        Err(SealError::Rejected)
    ));
    let mut other = env.clone();
    other.key_id = "transit:transit/other".into();
    assert!(matches!(
        s.unseal_session(Slot::Issuer, uid, &other).await,
        Err(SealError::UnknownKey(_))
    ));
    let mut tampered = env.clone();
    let n = tampered.ciphertext.len();
    tampered.ciphertext[n - 1] ^= 1;
    assert!(matches!(
        s.unseal_session(Slot::Issuer, uid, &tampered).await,
        Err(SealError::Rejected)
    ));
}

#[tokio::test]
async fn the_probe_at_startup_refuses_a_bad_role_a_missing_key_and_an_underived_key() {
    let dir = tempdir();
    let fake = FakeTransit::spawn(ROLE, "sa-jwt", KEY).await;
    // The wrong projected token: the login is refused, not retried into a loop.
    let err = TransitSealer::connect(&config(&fake, token_file(&dir, "someone-else")))
        .await
        .unwrap_err();
    assert!(
        matches!(err, SealError::Key(ref m) if m.contains("login refused")),
        "{err}"
    );
    // A key OpenBao does not have.
    let mut cfg = config(&fake, token_file(&dir, "sa-jwt"));
    cfg.key = "nope".into();
    assert!(matches!(
        TransitSealer::connect(&cfg).await.unwrap_err(),
        SealError::Rejected
    ));
    // A key created without derivation would ignore the binding: refused at the probe.
    fake.create_key("flat", false);
    cfg.key = "flat".into();
    let err = TransitSealer::connect(&cfg).await.unwrap_err();
    assert!(
        matches!(err, SealError::Rejected | SealError::Key(_)),
        "{err}"
    );
    // The right one.
    assert!(fake.logins() >= 2);
    assert!(
        TransitSealer::connect(&config(&fake, token_file(&dir, "sa-jwt")))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn a_revoked_token_is_exchanged_again_and_an_outage_is_unavailable() {
    let dir = tempdir();
    let fake = FakeTransit::spawn(ROLE, "sa-jwt", KEY).await;
    let s = sealer(&fake, &dir).await;
    let logins = fake.logins();
    let uid = Uuid::new_v4();
    let env = s.seal_session(Slot::Issuer, uid, b"refresh").await.unwrap();
    assert_eq!(fake.logins(), logins, "one token serves many calls");

    fake.revoke_tokens();
    assert_eq!(
        s.unseal_session(Slot::Issuer, uid, &env).await.unwrap(),
        b"refresh"
    );
    assert_eq!(
        fake.logins(),
        logins + 1,
        "a 403 is retried once after a fresh login"
    );

    fake.set_down(true);
    assert!(matches!(
        s.unseal_session(Slot::Issuer, uid, &env).await,
        Err(SealError::Unavailable(_))
    ));
    assert!(matches!(
        s.seal_session(Slot::Issuer, uid, b"x").await,
        Err(SealError::Unavailable(_))
    ));
    fake.set_down(false);
    assert_eq!(
        s.unseal_session(Slot::Issuer, uid, &env).await.unwrap(),
        b"refresh"
    );
}

#[tokio::test]
async fn a_short_lease_is_renewed_before_it_ends() {
    let dir = tempdir();
    let fake = FakeTransit::spawn(ROLE, "sa-jwt", KEY).await;
    // Tokens that are already inside the renewal margin: every call logs in again,
    // and every call still succeeds.
    fake.set_lease_secs(10);
    let s = sealer(&fake, &dir).await;
    let logins = fake.logins();
    let uid = Uuid::new_v4();
    let env = s.seal_session(Slot::Issuer, uid, b"refresh").await.unwrap();
    assert_eq!(
        s.unseal_session(Slot::Issuer, uid, &env).await.unwrap(),
        b"refresh"
    );
    assert!(
        fake.logins() > logins,
        "a token inside the margin is exchanged"
    );
}

#[tokio::test]
async fn a_rotation_at_openbao_keeps_old_envelopes_readable_until_retired() {
    let dir = tempdir();
    let fake = FakeTransit::spawn(ROLE, "sa-jwt", KEY).await;
    let s = sealer(&fake, &dir).await;
    let uid = Uuid::new_v4();
    let old = s.seal_session(Slot::Issuer, uid, b"before").await.unwrap();
    fake.rotate(KEY);
    let new = s.seal_session(Slot::Issuer, uid, b"after").await.unwrap();
    assert!(new.ciphertext.starts_with(b"vault:v2:"));
    assert_eq!(
        s.unseal_session(Slot::Issuer, uid, &old).await.unwrap(),
        b"before"
    );
    assert_eq!(
        s.unseal_session(Slot::Issuer, uid, &new).await.unwrap(),
        b"after"
    );
    assert_eq!(
        old.key_id, new.key_id,
        "the key id names the key, not its version"
    );
    fake.set_min_decryption_version(KEY, 2);
    assert!(matches!(
        s.unseal_session(Slot::Issuer, uid, &old).await,
        Err(SealError::Rejected)
    ));
    assert_eq!(
        s.unseal_session(Slot::Issuer, uid, &new).await.unwrap(),
        b"after"
    );
}

fn tempdir() -> std::path::PathBuf {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(Uuid::new_v4().to_string());
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[tokio::test]
async fn the_login_goes_to_the_configured_kubernetes_auth_mount() {
    // A platform that mounts the Kubernetes auth method per cluster (a dotted name, not `kubernetes`) is reachable
    // by naming the mount; the default stays `kubernetes`.
    let dir = tempdir();
    let fake = FakeTransit::spawn(ROLE, "sa-jwt", KEY).await;
    fake.set_auth_mount("computefabric-cluster.k8s.example");
    let mut cfg = config(&fake, token_file(&dir, "sa-jwt"));
    cfg.auth_mount = "computefabric-cluster.k8s.example".into();
    TransitSealer::connect(&cfg)
        .await
        .expect("logs in at the named mount");
    let wrong = config(&fake, token_file(&dir, "sa-jwt"));
    assert!(
        TransitSealer::connect(&wrong).await.is_err(),
        "the default mount is not where this fake's auth method is"
    );
}

/// What the fake `OpenBao` encrypts under exactly `context`, as an envelope of `format`: how
/// a test holds an envelope the sealer itself no longer makes.
fn encrypted_under(
    fake: &FakeTransit,
    context: &[u8],
    plaintext: &[u8],
    format: u8,
) -> mediatore_store::Sealed {
    mediatore_store::Sealed {
        key_id: format!("transit:transit/{KEY}"),
        nonce: Vec::new(),
        ciphertext: fake.encrypt_under(KEY, context, plaintext).into_bytes(),
        format,
    }
}

#[tokio::test]
async fn a_delegation_opens_only_for_its_audience_and_never_as_the_issuers_session() {
    let dir = tempdir();
    let fake = FakeTransit::spawn(ROLE, "sa-jwt", KEY).await;
    let s = sealer(&fake, &dir).await;
    let uid = Uuid::new_v4();
    let github = s
        .seal_session(Slot::Delegation("github"), uid, b"gh")
        .await
        .unwrap();
    assert_eq!(
        s.unseal_session(Slot::Delegation("github"), uid, &github)
            .await
            .unwrap(),
        b"gh"
    );
    for slot in [Slot::Delegation("anthropic"), Slot::Issuer] {
        assert!(matches!(
            s.unseal_session(slot, uid, &github).await,
            Err(SealError::Rejected)
        ));
    }
    let session = s.seal_session(Slot::Issuer, uid, b"refresh").await.unwrap();
    assert!(matches!(
        s.unseal_session(Slot::Delegation("github"), uid, &session)
            .await,
        Err(SealError::Rejected)
    ));
    // The output's context stays apart from every slot (ADR-0052).
    let blob = s
        .seal_with(SealPurpose::Logs, uid, b"output")
        .await
        .unwrap();
    assert!(matches!(
        s.unseal_session(Slot::Issuer, uid, &blob).await,
        Err(SealError::Rejected)
    ));
}

#[tokio::test]
async fn the_fake_derives_by_the_exact_format_2_context_bytes() {
    // TB-10: the fake OpenBao must hold the context the way the real one does. An envelope the
    // fake encrypted under the pinned bytes opens through the sealer for that slot, and one
    // encrypted under bytes that differ in the last one does not.
    let dir = tempdir();
    let fake = FakeTransit::spawn(ROLE, "sa-jwt", KEY).await;
    let s = sealer(&fake, &dir).await;
    let uid = Uuid::new_v4();
    let mut context = b"mediatore-session\0".to_vec();
    context.extend_from_slice(uid.as_bytes());
    context.push(0x01);
    context.extend_from_slice(b"github");
    assert_eq!(
        SealPurpose::Session(Slot::Delegation("github")).context(uid),
        context
    );
    let exact = encrypted_under(&fake, &context, b"gh", FORMAT_SLOT);
    assert_eq!(
        s.unseal_session(Slot::Delegation("github"), uid, &exact)
            .await
            .unwrap(),
        b"gh"
    );
    let mut off_by_one = context.clone();
    off_by_one.push(b'x');
    let other = encrypted_under(&fake, &off_by_one, b"gh", FORMAT_SLOT);
    assert!(matches!(
        s.unseal_session(Slot::Delegation("github"), uid, &other)
            .await,
        Err(SealError::Rejected)
    ));
}

#[tokio::test]
async fn a_format_1_envelope_still_opens_under_the_bare_uid_and_a_relabelled_one_does_not() {
    let dir = tempdir();
    let fake = FakeTransit::spawn(ROLE, "sa-jwt", KEY).await;
    let s = sealer(&fake, &dir).await;
    let uid = Uuid::new_v4();
    // What a broker before ADR-0057 stored: the bare UID as the context, no marker.
    let old = encrypted_under(&fake, uid.as_bytes(), b"refresh", FORMAT_BARE_UID);
    assert_eq!(
        s.unseal_session(Slot::Issuer, uid, &old).await.unwrap(),
        b"refresh"
    );
    let mut relabelled = old.clone();
    relabelled.format = FORMAT_SLOT;
    assert!(matches!(
        s.unseal_session(Slot::Issuer, uid, &relabelled).await,
        Err(SealError::Rejected)
    ));
    let new = s.seal_session(Slot::Issuer, uid, b"refresh").await.unwrap();
    let mut downgraded = new.clone();
    downgraded.format = FORMAT_BARE_UID;
    assert!(matches!(
        s.unseal_session(Slot::Issuer, uid, &downgraded).await,
        Err(SealError::Rejected)
    ));
    // Nothing seals format 1 again, and no call is spent finding that out.
    let encrypts = fake.encrypts();
    assert!(matches!(
        s.seal_with(SealPurpose::SessionFormat1, uid, b"x").await,
        Err(SealError::RetiredFormat)
    ));
    assert_eq!(fake.encrypts(), encrypts);
}

#[tokio::test]
async fn the_probe_at_startup_refuses_a_key_that_does_not_bind_the_slot() {
    let dir = tempdir();
    let fake = FakeTransit::spawn(ROLE, "sa-jwt", KEY).await;
    // A key that derives from the label and the UID and ignores what follows: the binding to
    // the sandbox holds, the binding to the slot does not.
    fake.create_truncating_key("blunt", 18 + 16);
    let mut cfg = config(&fake, token_file(&dir, "sa-jwt"));
    cfg.key = "blunt".into();
    let err = TransitSealer::connect(&cfg).await.unwrap_err();
    assert!(
        matches!(err, SealError::Key(ref m) if m.contains("does not bind the slot")),
        "{err}"
    );
    // The same key over the whole context starts.
    fake.create_key("whole", true);
    cfg.key = "whole".into();
    assert!(TransitSealer::connect(&cfg).await.is_ok());
}
