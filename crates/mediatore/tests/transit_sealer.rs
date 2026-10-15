// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The transit sealer (ADR-0015) against the fake `OpenBao`: the binding as derivation
//! context, the key id, the startup probe, token renewal after a revocation, an outage as
//! `Unavailable` rather than a refusal, and a rotation that keeps old envelopes readable.

use mediatore_store::seal::{SealError, Sealer, TransitConfig, TransitSealer};
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
    let env = s.seal(uid, b"refresh").await.unwrap();
    assert_eq!(env.key_id, s.key_id());
    assert_eq!(env.nonce.len(), 0, "OpenBao owns the nonce");
    assert!(
        env.ciphertext.starts_with(b"vault:v1:"),
        "{:?}",
        String::from_utf8_lossy(&env.ciphertext)
    );
    assert_eq!(s.unseal(uid, &env).await.unwrap(), b"refresh");
    // The context is the binding: another UID derives another key.
    assert!(matches!(
        s.unseal(Uuid::new_v4(), &env).await,
        Err(SealError::Rejected)
    ));
    let mut other = env.clone();
    other.key_id = "transit:transit/other".into();
    assert!(matches!(
        s.unseal(uid, &other).await,
        Err(SealError::UnknownKey(_))
    ));
    let mut tampered = env.clone();
    let n = tampered.ciphertext.len();
    tampered.ciphertext[n - 1] ^= 1;
    assert!(matches!(
        s.unseal(uid, &tampered).await,
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
    let env = s.seal(uid, b"refresh").await.unwrap();
    assert_eq!(fake.logins(), logins, "one token serves many calls");

    fake.revoke_tokens();
    assert_eq!(s.unseal(uid, &env).await.unwrap(), b"refresh");
    assert_eq!(
        fake.logins(),
        logins + 1,
        "a 403 is retried once after a fresh login"
    );

    fake.set_down(true);
    assert!(matches!(
        s.unseal(uid, &env).await,
        Err(SealError::Unavailable(_))
    ));
    assert!(matches!(
        s.seal(uid, b"x").await,
        Err(SealError::Unavailable(_))
    ));
    fake.set_down(false);
    assert_eq!(s.unseal(uid, &env).await.unwrap(), b"refresh");
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
    let env = s.seal(uid, b"refresh").await.unwrap();
    assert_eq!(s.unseal(uid, &env).await.unwrap(), b"refresh");
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
    let old = s.seal(uid, b"before").await.unwrap();
    fake.rotate(KEY);
    let new = s.seal(uid, b"after").await.unwrap();
    assert!(new.ciphertext.starts_with(b"vault:v2:"));
    assert_eq!(s.unseal(uid, &old).await.unwrap(), b"before");
    assert_eq!(s.unseal(uid, &new).await.unwrap(), b"after");
    assert_eq!(
        old.key_id, new.key_id,
        "the key id names the key, not its version"
    );
    fake.set_min_decryption_version(KEY, 2);
    assert!(matches!(
        s.unseal(uid, &old).await,
        Err(SealError::Rejected)
    ));
    assert_eq!(s.unseal(uid, &new).await.unwrap(), b"after");
}

fn tempdir() -> std::path::PathBuf {
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR")).join(Uuid::new_v4().to_string());
    std::fs::create_dir_all(&dir).unwrap();
    dir
}
