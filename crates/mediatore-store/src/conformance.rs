// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The storage contract as tests, run over every implementation (ADR-0012 decision 5):
//! `MemoryStore`, `SqlStore` on SQLite in memory, and `SqlStore` on a live PostgreSQL. A
//! behaviour one backend has and another lacks is a bug in the one that lacks it.

use chrono::{DateTime, Duration, TimeZone, Utc};
use mediatore_proto::{Provider, Subject, Workload};
use uuid::Uuid;

use crate::seal::{LocalKeySealer, Sealer};
use crate::{ClaimRecord, ClaimStore, NodeRecord, SessionRecord, StoreError};

/// One `#[tokio::test]` per listed case, each over a fresh store from `$make`.
macro_rules! cases {
    ($make:expr; $($name:ident),* $(,)?) => {
        $(
            #[tokio::test]
            async fn $name() {
                let store = $make;
                crate::conformance::$name(&store).await;
            }
        )*
    };
}

/// Every test in the suite, in a module named `$backend`.
macro_rules! suite {
    ($backend:ident, $make:expr) => {
        mod $backend {
            use super::*;

            crate::conformance::cases!($make;
                a_claim_round_trips_every_field,
                a_second_put_of_the_same_uid_is_a_conflict,
                update_replaces_and_needs_an_existing_row,
                revoke_is_idempotent_and_drops_the_refresh_envelope,
                revoke_of_an_unknown_claim_is_not_found,
                claim_by_node_finds_only_the_newest_live_claim,
                a_node_round_trips_and_registers_once,
                duplicate_ek_with_another_dmi_is_a_conflict,
                ban_marks_the_node_and_needs_an_existing_row,
                a_sweep_moves_ended_claims_into_the_audit_table,
                a_session_is_taken_once_deleted_on_demand_and_swept_when_stale,
                ping_answers,
            );
        }
    };
}
pub(crate) use {cases, suite};

fn subject() -> Subject {
    Subject {
        issuer: "https://issuer.example.com".into(),
        id: "octocat".into(),
        display: Some("The Octocat".into()),
    }
}

/// A fixed, microsecond-precise instant: both engines store microseconds.
fn at(secs: i64) -> DateTime<Utc> {
    Utc.timestamp_opt(1_700_000_000 + secs, 123_456_000)
        .unwrap()
}

pub(crate) fn claim(uid: Uuid) -> ClaimRecord {
    ClaimRecord {
        uid,
        name: format!("sandbox-{}", &uid.to_string()[..8]),
        subject: subject(),
        entry_id: None,
        node_id: None,
        audiences: vec!["api://trading-data".into(), "e2e".into()],
        workload: Workload {
            image: "registry.internal:5000/sandbox/claude:latest".into(),
            args: vec!["/usr/bin/claude".into(), "-p".into(), "hello".into()],
        },
        ttl_seconds: 3600,
        refresh: None,
        created_at: at(0),
        expires_at: None,
        revoked_at: None,
        sandbox_uid: None,
    }
}

pub(crate) fn node(ek: &str, dmi: Uuid) -> NodeRecord {
    NodeRecord {
        ek_hash: ek.into(),
        node_id: format!("spiffe://sandbox.test/spire/agent/tpm/{ek}"),
        dmi_uuid: dmi,
        hostname: "member-01".into(),
        provider: Some(Provider::Libvirt),
        banned: false,
        registered_at: at(0),
    }
}

fn sealer() -> LocalKeySealer {
    LocalKeySealer::new([7u8; 32])
}

pub(crate) async fn a_claim_round_trips_every_field(s: &dyn ClaimStore) {
    let uid = Uuid::new_v4();
    let mut rec = claim(uid);
    rec.entry_id = Some("mediatore-claim-x".into());
    rec.node_id = Some("spiffe://sandbox.test/spire/agent/tpm/ek1".into());
    let sandbox_uid = Uuid::new_v4();
    rec.sandbox_uid = Some(sandbox_uid);
    rec.refresh = Some(sealer().seal(sandbox_uid, b"refresh-token").await.unwrap());
    rec.expires_at = Some(at(3600));
    s.put_claim(rec.clone()).await.unwrap();

    for got in [
        s.get_claim(uid).await.unwrap(),
        s.get_claim_by_name(&rec.name).await.unwrap(),
    ] {
        assert_eq!(got.uid, uid);
        assert_eq!(got.name, rec.name);
        assert_eq!(got.subject, rec.subject);
        assert_eq!(got.entry_id, rec.entry_id);
        assert_eq!(got.node_id, rec.node_id);
        assert_eq!(got.audiences, rec.audiences);
        assert_eq!(got.workload.image, rec.workload.image);
        assert_eq!(got.workload.args, rec.workload.args);
        assert_eq!(got.ttl_seconds, 3600);
        assert_eq!(got.created_at, rec.created_at);
        assert_eq!(got.expires_at, rec.expires_at);
        assert_eq!(got.revoked_at, None);
        assert_eq!(got.sandbox_uid, Some(sandbox_uid));
        assert_eq!(got.seal_binding(), sandbox_uid);
        let env = got.refresh.as_ref().expect("envelope survives");
        assert_eq!(env, rec.refresh.as_ref().unwrap());
        assert_eq!(
            sealer()
                .unseal(got.seal_binding(), env)
                .await
                .unwrap()
                .as_slice(),
            b"refresh-token"
        );
    }
    assert_eq!(s.list_claims().await.unwrap().len(), 1);
    assert!(matches!(
        s.get_claim(Uuid::new_v4()).await,
        Err(StoreError::NotFound(_))
    ));
    assert!(matches!(
        s.get_claim_by_name("nope").await,
        Err(StoreError::NotFound(_))
    ));
}

pub(crate) async fn a_second_put_of_the_same_uid_is_a_conflict(s: &dyn ClaimStore) {
    let uid = Uuid::new_v4();
    s.put_claim(claim(uid)).await.unwrap();
    let err = s.put_claim(claim(uid)).await.unwrap_err();
    assert!(matches!(err, StoreError::Conflict(_)), "{err}");
    assert_eq!(s.list_claims().await.unwrap().len(), 1);
}

pub(crate) async fn update_replaces_and_needs_an_existing_row(s: &dyn ClaimStore) {
    let uid = Uuid::new_v4();
    s.put_claim(claim(uid)).await.unwrap();
    let mut rec = s.get_claim(uid).await.unwrap();
    rec.entry_id = Some("entry".into());
    rec.node_id = Some("node".into());
    rec.expires_at = Some(at(10));
    rec.audiences = vec!["only".into()];
    s.update_claim(rec).await.unwrap();
    let got = s.get_claim(uid).await.unwrap();
    assert_eq!(got.entry_id.as_deref(), Some("entry"));
    assert_eq!(got.node_id.as_deref(), Some("node"));
    assert_eq!(got.expires_at, Some(at(10)));
    assert_eq!(got.audiences, vec!["only".to_owned()]);

    let err = s.update_claim(claim(Uuid::new_v4())).await.unwrap_err();
    assert!(matches!(err, StoreError::NotFound(_)), "{err}");
}

pub(crate) async fn revoke_is_idempotent_and_drops_the_refresh_envelope(s: &dyn ClaimStore) {
    let uid = Uuid::new_v4();
    let mut rec = claim(uid);
    rec.refresh = Some(sealer().seal(uid, b"secret").await.unwrap());
    rec.expires_at = Some(at(3600));
    s.put_claim(rec).await.unwrap();

    s.revoke_claim(uid, at(5)).await.unwrap();
    s.revoke_claim(uid, at(9)).await.unwrap();
    let got = s.get_claim(uid).await.unwrap();
    assert_eq!(got.revoked_at, Some(at(5)), "the first revocation wins");
    assert!(got.refresh.is_none(), "revocation drops refresh material");
    assert!(!got.is_live(at(0)));
}

pub(crate) async fn revoke_of_an_unknown_claim_is_not_found(s: &dyn ClaimStore) {
    let err = s.revoke_claim(Uuid::new_v4(), at(0)).await.unwrap_err();
    assert!(matches!(err, StoreError::NotFound(_)), "{err}");
}

pub(crate) async fn claim_by_node_finds_only_the_newest_live_claim(s: &dyn ClaimStore) {
    let node = "spiffe://sandbox.test/spire/agent/tpm/ek1";
    let far = Utc::now() + Duration::hours(1);
    let old = Uuid::new_v4();
    let mut rec = claim(old);
    rec.node_id = Some(node.into());
    rec.expires_at = Some(far);
    rec.created_at = at(0);
    s.put_claim(rec).await.unwrap();
    assert_eq!(s.get_claim_by_node(node).await.unwrap().uid, old);

    // A newer live claim on the same node (a rebind after the old one lapsed) wins.
    let new = Uuid::new_v4();
    let mut rec = claim(new);
    rec.node_id = Some(node.into());
    rec.expires_at = Some(far);
    rec.created_at = at(1);
    s.put_claim(rec).await.unwrap();
    assert_eq!(s.get_claim_by_node(node).await.unwrap().uid, new);

    s.revoke_claim(new, Utc::now()).await.unwrap();
    assert_eq!(s.get_claim_by_node(node).await.unwrap().uid, old);

    // An expired deadline is as dead as a revocation.
    let mut rec = s.get_claim(old).await.unwrap();
    rec.expires_at = Some(Utc::now() - Duration::seconds(1));
    s.update_claim(rec).await.unwrap();
    assert!(matches!(
        s.get_claim_by_node(node).await,
        Err(StoreError::NotFound(_))
    ));
    assert!(matches!(
        s.get_claim_by_node("spiffe://sandbox.test/spire/agent/tpm/other")
            .await,
        Err(StoreError::NotFound(_))
    ));
}

pub(crate) async fn a_node_round_trips_and_registers_once(s: &dyn ClaimStore) {
    let dmi = Uuid::new_v4();
    s.put_node(node("ek1", dmi)).await.unwrap();
    // The same VM registering again (a reboot) is a no-op that keeps the first record.
    let mut again = node("ek1", dmi);
    again.hostname = "renamed".into();
    again.registered_at = at(99);
    s.put_node(again).await.unwrap();

    for got in [
        s.get_node("ek1").await.unwrap(),
        s.get_node_by_dmi(dmi).await.unwrap(),
    ] {
        assert_eq!(got.ek_hash, "ek1");
        assert_eq!(got.node_id, "spiffe://sandbox.test/spire/agent/tpm/ek1");
        assert_eq!(got.dmi_uuid, dmi);
        assert_eq!(got.hostname, "member-01");
        assert_eq!(got.provider, Some(Provider::Libvirt));
        assert!(!got.banned);
        assert_eq!(got.registered_at, at(0));
    }
    let mut bare = node("ek2", Uuid::new_v4());
    bare.provider = None;
    s.put_node(bare).await.unwrap();
    assert_eq!(s.get_node("ek2").await.unwrap().provider, None);
    assert_eq!(s.list_nodes().await.unwrap().len(), 2);
    assert!(matches!(
        s.get_node("ek3").await,
        Err(StoreError::NotFound(_))
    ));
    assert!(matches!(
        s.get_node_by_dmi(Uuid::new_v4()).await,
        Err(StoreError::NotFound(_))
    ));
}

pub(crate) async fn duplicate_ek_with_another_dmi_is_a_conflict(s: &dyn ClaimStore) {
    s.put_node(node("ek1", Uuid::new_v4())).await.unwrap();
    let err = s.put_node(node("ek1", Uuid::new_v4())).await.unwrap_err();
    assert!(matches!(err, StoreError::Conflict(_)), "{err}");
    assert_eq!(s.list_nodes().await.unwrap().len(), 1);
}

pub(crate) async fn ban_marks_the_node_and_needs_an_existing_row(s: &dyn ClaimStore) {
    s.put_node(node("ek1", Uuid::new_v4())).await.unwrap();
    s.ban_node("ek1").await.unwrap();
    assert!(s.get_node("ek1").await.unwrap().banned);
    let err = s.ban_node("ek9").await.unwrap_err();
    assert!(matches!(err, StoreError::NotFound(_)), "{err}");
}

pub(crate) async fn a_sweep_moves_ended_claims_into_the_audit_table(s: &dyn ClaimStore) {
    let revoked = Uuid::new_v4();
    let mut rec = claim(revoked);
    rec.node_id = Some("node-a".into());
    rec.expires_at = Some(at(3600));
    s.put_claim(rec).await.unwrap();
    s.revoke_claim(revoked, at(100)).await.unwrap();

    let expired = Uuid::new_v4();
    let mut rec = claim(expired);
    rec.expires_at = Some(at(200));
    s.put_claim(rec).await.unwrap();

    let live = Uuid::new_v4();
    let mut rec = claim(live);
    rec.expires_at = Some(at(10_000));
    s.put_claim(rec).await.unwrap();

    let pending = Uuid::new_v4();
    s.put_claim(claim(pending)).await.unwrap();

    // Nothing ended before this instant.
    assert_eq!(s.sweep(at(50)).await.unwrap(), 0);
    assert_eq!(s.list_claims().await.unwrap().len(), 4);
    assert_eq!(s.list_audit().await.unwrap().len(), 0);

    assert_eq!(s.sweep(at(1000)).await.unwrap(), 2);
    let left: Vec<Uuid> = s
        .list_claims()
        .await
        .unwrap()
        .iter()
        .map(|c| c.uid)
        .collect();
    assert_eq!(left.len(), 2);
    assert!(left.contains(&live) && left.contains(&pending));

    let audit = s.list_audit().await.unwrap();
    assert_eq!(audit.len(), 2);
    let a = audit.iter().find(|a| a.uid == revoked).expect("audit row");
    assert_eq!(a.name, claim(revoked).name);
    assert_eq!(a.subject, subject());
    assert_eq!(a.node_id.as_deref(), Some("node-a"));
    assert_eq!(a.created_at, at(0));
    assert_eq!(a.expires_at, Some(at(3600)));
    assert_eq!(a.revoked_at, Some(at(100)));
    assert!(a.swept_at > at(0));
    let e = audit.iter().find(|a| a.uid == expired).expect("audit row");
    assert_eq!(e.revoked_at, None);
    assert_eq!(e.expires_at, Some(at(200)));

    // A second sweep finds nothing and the audit rows stay.
    assert_eq!(s.sweep(at(1000)).await.unwrap(), 0);
    assert_eq!(s.list_audit().await.unwrap().len(), 2);
}

pub(crate) async fn a_session_is_taken_once_deleted_on_demand_and_swept_when_stale(
    s: &dyn ClaimStore,
) {
    let sandbox_uid = Uuid::new_v4();
    let session = SessionRecord {
        sandbox_uid,
        subject: subject(),
        issuer: "https://issuer.example.com".into(),
        refresh: sealer().seal(sandbox_uid, b"dex-refresh").await.unwrap(),
        created_at: at(0),
    };
    s.put_session(session.clone()).await.unwrap();
    let err = s.put_session(session.clone()).await.unwrap_err();
    assert!(matches!(err, StoreError::Conflict(_)), "{err}");

    let taken = s.take_session(sandbox_uid).await.unwrap().expect("parked");
    assert_eq!(taken, session);
    assert_eq!(
        sealer().unseal(sandbox_uid, &taken.refresh).await.unwrap(),
        b"dex-refresh"
    );
    assert!(
        s.take_session(sandbox_uid).await.unwrap().is_none(),
        "taken once"
    );

    s.put_session(session.clone()).await.unwrap();
    s.delete_session(sandbox_uid).await.unwrap();
    s.delete_session(sandbox_uid).await.unwrap();
    assert!(s.take_session(sandbox_uid).await.unwrap().is_none());

    let mut old = session.clone();
    old.sandbox_uid = Uuid::new_v4();
    old.created_at = at(0);
    let mut fresh = session;
    fresh.sandbox_uid = Uuid::new_v4();
    fresh.created_at = at(100);
    s.put_session(old.clone()).await.unwrap();
    s.put_session(fresh.clone()).await.unwrap();
    assert_eq!(s.sweep_sessions(at(50)).await.unwrap(), 1);
    assert!(s.take_session(old.sandbox_uid).await.unwrap().is_none());
    assert!(s.take_session(fresh.sandbox_uid).await.unwrap().is_some());
}

pub(crate) async fn ping_answers(s: &dyn ClaimStore) {
    s.ping().await.unwrap();
}
