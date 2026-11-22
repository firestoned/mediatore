// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The storage contract as tests, run over every implementation (ADR-0012 decision 5):
//! `MemoryStore`; the Kubernetes store (ADR-0034) is proven by the kind tiers on a real API
//! server, since a record there needs an `AgentSandbox` to live on. A
//! behaviour one backend has and another lacks is a bug in the one that lacks it.
//!
//! The cases of ADR-0057 (the version, the compare-and-set, the release that cannot lose,
//! `modify_claim`) are not here: they are in [`crate::shared_cases`], which `mediatore-claims`
//! runs over the Kubernetes store on its fake API server too.

use std::collections::BTreeMap;

use jiff::{SignedDuration, Timestamp};
use mediatore_proto::{
    LogBatch, LogEntry, LogGap, LogRecord, LogStream, Provider, Subject, Workload,
};
use uuid::Uuid;

use crate::seal::{LocalKeySealer, Sealed, Sealer, Slot};
use crate::{
    ClaimRecord, ClaimStore, DelegatedSession, LogLimits, NodeRecord, PolicyFloor, SessionRecord,
    StoreError,
};

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
                a_name_in_one_namespace_is_not_found_in_another,
                an_old_claim_record_reads_as_the_fallback_namespace,
                update_replaces_and_needs_an_existing_row,
                an_update_over_a_released_claim_writes_nothing,
                revoke_is_idempotent_and_drops_the_refresh_envelope,
                revoke_of_an_unknown_claim_is_not_found,
                claim_by_node_finds_only_the_newest_live_claim,
                a_node_round_trips_and_registers_once,
                duplicate_ek_with_another_dmi_is_a_conflict,
                ban_marks_the_node_and_needs_an_existing_row,
                delete_node_removes_the_row_and_is_idempotent,
                a_sweep_removes_claims_that_ended_before_the_retention,
                a_session_is_taken_once_deleted_on_demand_and_swept_when_stale,
                an_envelope_is_swept_when_it_expires_and_not_only_when_it_is_old,
                a_bound_claims_delegation_is_removed_when_it_expires,
                a_parked_issuer_session_is_swept_when_it_expires,
                a_live_claims_session_outlasts_the_sweep_and_an_ended_claims_does_not,
                delegations_are_parked_per_audience_and_revocation_empties_them,
                a_policy_floor_round_trips_to_the_nanosecond,
                a_policy_floor_moves_only_from_what_is_held,
                a_floor_written_under_another_policy_is_refused,
                an_audience_floor_is_its_own_beside_a_policy_of_the_same_name,
                ping_answers,
                appended_output_reads_back_in_sequence,
                a_partial_record_keeps_its_mark_through_a_write_and_a_read,
                a_retried_batch_stores_nothing_and_is_counted_ignored,
                an_overlapping_batch_stores_only_its_new_records,
                a_gap_is_stored_before_a_batch_with_dropped_counts_and_not_for_a_replay,
                the_ring_drops_the_oldest_and_counts_the_bytes_it_dropped,
                a_read_since_a_cursor_returns_later_records_and_the_gap_right_before_them,
                a_log_sweep_removes_gone_and_ended_claims_output_and_keeps_a_live_claims,
                deleting_output_that_was_never_stored_is_fine,
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
fn at(secs: i64) -> Timestamp {
    Timestamp::new(1_700_000_000 + secs, 123_456_000).unwrap()
}

pub(crate) fn claim(uid: Uuid) -> ClaimRecord {
    ClaimRecord {
        rendered: None,
        follow: None,
        uid,
        name: format!("sandbox-{}", &uid.to_string()[..8]),
        namespace: "team-a".into(),
        subject: subject(),
        entry_id: None,
        node_id: None,
        audiences: vec!["api://trading-data".into(), "e2e".into()],
        workload: Workload {
            image: "registry.internal:5000/sandbox/claude:latest".into(),
            args: vec!["/usr/bin/claude".into(), "-p".into(), "hello".into()],
            restart: mediatore_proto::RestartPolicy::OnFailure,
            logs: false,
        },
        ttl_seconds: 3600,
        refresh: None,
        created_at: at(0),
        expires_at: None,
        revoked_at: None,
        sandbox_uid: None,
        policy_uid: None,
        bundle_version: None,
        report: None,
        exit: None,
        delegations: BTreeMap::new(),
        version: None,
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

/// An envelope for `binding`, sealed under the issuer's slot: the store keeps envelopes and
/// opens none, so one slot serves every case here.
async fn seal(binding: Uuid, plain: &[u8]) -> Sealed {
    sealer()
        .seal_session(Slot::Issuer, binding, plain)
        .await
        .unwrap()
}

/// What [`seal`] sealed.
async fn unseal(binding: Uuid, envelope: &Sealed) -> Vec<u8> {
    sealer()
        .unseal_session(Slot::Issuer, binding, envelope)
        .await
        .unwrap()
}

pub(crate) async fn a_claim_round_trips_every_field(s: &dyn ClaimStore) {
    let uid = Uuid::new_v4();
    let mut rec = claim(uid);
    rec.entry_id = Some("mediatore-claim-x".into());
    rec.node_id = Some("spiffe://sandbox.test/spire/agent/tpm/ek1".into());
    let sandbox_uid = Uuid::new_v4();
    rec.sandbox_uid = Some(sandbox_uid);
    rec.refresh = Some(seal(sandbox_uid, b"refresh-token").await);
    rec.expires_at = Some(at(3600));
    rec.policy_uid = Some("3f1b8d2a-0c4e-4b7a-9d6f-2e5c1a7b9f03".into());
    rec.bundle_version = Some(u64::from(u32::MAX) + 1);
    rec.report = Some(mediatore_proto::ClaimReport {
        reported_at: at(60),
        report: mediatore_proto::GuestReport {
            image_digest: format!("sha256:{}", "ab".repeat(32)),
            sandbox_ruleset_sha256: "cd".repeat(32),
            host_table: mediatore_proto::HostTable::Loaded {
                sha256: "ef".repeat(32),
            },
        },
    });
    rec.exit = Some(mediatore_proto::WorkloadExit {
        exited_at: at(90),
        exit: mediatore_proto::GuestExit {
            code: Some(0),
            signal: None,
            restarts: 2,
        },
    });
    s.put_claim(rec.clone()).await.unwrap();

    for got in [
        s.get_claim(uid).await.unwrap(),
        s.get_claim_by_name(&rec.namespace, &rec.name)
            .await
            .unwrap(),
    ] {
        assert_eq!(got.uid, uid);
        assert_eq!(got.name, rec.name);
        assert_eq!(got.subject, rec.subject);
        assert_eq!(got.entry_id, rec.entry_id);
        assert_eq!(got.node_id, rec.node_id);
        assert_eq!(got.audiences, rec.audiences);
        assert_eq!(got.workload.image, rec.workload.image);
        assert_eq!(got.workload.args, rec.workload.args);
        assert_eq!(
            got.workload.restart,
            mediatore_proto::RestartPolicy::OnFailure,
            "the restart policy rides in the workload JSON (ADR-0033)"
        );
        assert_eq!(got.ttl_seconds, 3600);
        assert_eq!(got.created_at, rec.created_at);
        assert_eq!(got.expires_at, rec.expires_at);
        assert_eq!(got.revoked_at, None);
        assert_eq!(got.sandbox_uid, Some(sandbox_uid));
        assert_eq!(got.seal_binding(), sandbox_uid);
        assert_eq!(got.policy_uid, rec.policy_uid);
        assert_eq!(got.bundle_version, rec.bundle_version);
        assert_eq!(
            got.report, rec.report,
            "the guest's report round-trips (ADR-0029)"
        );
        assert_eq!(
            got.exit, rec.exit,
            "the workload's exit round-trips (ADR-0033)"
        );
        let env = got.refresh.as_ref().expect("envelope survives");
        assert_eq!(env, rec.refresh.as_ref().unwrap());
        assert_eq!(
            unseal(got.seal_binding(), env).await.as_slice(),
            b"refresh-token"
        );
    }
    assert_eq!(s.list_claims().await.unwrap().len(), 1);
    assert!(matches!(
        s.get_claim(Uuid::new_v4()).await,
        Err(StoreError::NotFound(_))
    ));
    assert!(matches!(
        s.get_claim_by_name("team-a", "nope").await,
        Err(StoreError::NotFound(_))
    ));
}

pub(crate) async fn a_name_in_one_namespace_is_not_found_in_another(s: &dyn ClaimStore) {
    let a = claim(Uuid::new_v4());
    let mut b = claim(Uuid::new_v4());
    b.name.clone_from(&a.name);
    b.namespace = "infra".into();
    s.put_claim(a.clone()).await.unwrap();
    assert!(matches!(
        s.get_claim_by_name("infra", &a.name).await,
        Err(StoreError::NotFound(_))
    ));
    s.put_claim(b.clone()).await.unwrap();
    assert_eq!(
        s.get_claim_by_name("team-a", &a.name).await.unwrap().uid,
        a.uid
    );
    assert_eq!(
        s.get_claim_by_name("infra", &a.name).await.unwrap().uid,
        b.uid
    );
}

pub(crate) async fn an_old_claim_record_reads_as_the_fallback_namespace(s: &dyn ClaimStore) {
    let mut v = serde_json::to_value(claim(Uuid::new_v4())).unwrap();
    v.as_object_mut().unwrap().remove("namespace");
    let old: ClaimRecord = serde_json::from_value(v).unwrap();
    assert_eq!(old.namespace, crate::FALLBACK_NAMESPACE);
    s.put_claim(old.clone()).await.unwrap();
    let got = s
        .get_claim_by_name(crate::FALLBACK_NAMESPACE, &old.name)
        .await
        .unwrap();
    assert_eq!(got.uid, old.uid);
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
    rec.policy_uid = Some("policy-uid".into());
    rec.bundle_version = Some(7);
    s.update_claim(rec).await.unwrap();
    let got = s.get_claim(uid).await.unwrap();
    assert_eq!(got.entry_id.as_deref(), Some("entry"));
    assert_eq!(got.node_id.as_deref(), Some("node"));
    assert_eq!(got.expires_at, Some(at(10)));
    assert_eq!(got.audiences, vec!["only".to_owned()]);
    assert_eq!(got.policy_uid.as_deref(), Some("policy-uid"));
    assert_eq!(got.bundle_version, Some(7));

    let err = s.update_claim(claim(Uuid::new_v4())).await.unwrap_err();
    assert!(matches!(err, StoreError::NotFound(_)), "{err}");
}

/// A released record is final. A writer that read its copy before the release (a guest's report, a refresh, a bind)
/// and writes it afterwards must not bring the claim back: `revoked_at` stays, and neither the refresh envelope
/// nor a delegation is stored again.
pub(crate) async fn an_update_over_a_released_claim_writes_nothing(s: &dyn ClaimStore) {
    let (uid, sandbox_uid) = (Uuid::new_v4(), Uuid::new_v4());
    let mut rec = claim(uid);
    rec.sandbox_uid = Some(sandbox_uid);
    rec.expires_at = Some(at(3600));
    rec.refresh = Some(seal(sandbox_uid, b"dex-refresh").await);
    rec.delegations.insert(
        "github".into(),
        DelegatedSession {
            envelope: seal(sandbox_uid, b"{\"token\":\"gh\"}").await,
            expires_at: None,
        },
    );
    s.put_claim(rec).await.unwrap();

    // The copy a slow writer holds: read while the claim was live, refresh material and all.
    let mut stale = s.get_claim(uid).await.unwrap();
    let carried = stale.refresh.is_some() && stale.delegations.len() == 1;
    assert!(carried, "the copy read before the release carries both");
    s.revoke_claim(uid, at(5)).await.unwrap();

    stale.entry_id = Some("entry".into());
    let refused = matches!(s.update_claim(stale).await, Err(StoreError::Conflict(_)));
    assert!(refused, "an update over a released claim is a conflict");

    let got = s.get_claim(uid).await.unwrap();
    assert_eq!(
        got.revoked_at,
        Some(at(5)),
        "still released, at the same instant"
    );
    assert!(!got.is_live(at(0)));
    assert!(got.refresh.is_none(), "no refresh material came back");
    assert!(got.delegations.is_empty(), "no delegation came back");
    assert!(got.entry_id.is_none(), "no field of the stale copy landed");
    // Nor as a session for the sandbox to be taken again.
    assert!(s.take_session(sandbox_uid).await.unwrap().is_none());
    assert!(
        s.take_delegations(sandbox_uid).await.unwrap().is_empty(),
        "no delegation is left to take"
    );
}

pub(crate) async fn revoke_is_idempotent_and_drops_the_refresh_envelope(s: &dyn ClaimStore) {
    let uid = Uuid::new_v4();
    let mut rec = claim(uid);
    rec.refresh = Some(seal(uid, b"secret").await);
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
    let far = Timestamp::now() + SignedDuration::from_hours(1);
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

    s.revoke_claim(new, Timestamp::now()).await.unwrap();
    assert_eq!(s.get_claim_by_node(node).await.unwrap().uid, old);

    // An expired deadline is as dead as a revocation.
    let mut rec = s.get_claim(old).await.unwrap();
    rec.expires_at = Some(Timestamp::now() - SignedDuration::from_secs(1));
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

/// ADR-0039: a node leaves the register when its VM is gone. Deleting is idempotent (a row
/// already gone is success), touches no other row, and frees the DMI UUID and the EK hash
/// for a machine that registers again.
pub(crate) async fn delete_node_removes_the_row_and_is_idempotent(s: &dyn ClaimStore) {
    let dmi1 = Uuid::new_v4();
    s.put_node(node("ek1", dmi1)).await.unwrap();
    s.put_node(node("ek2", Uuid::new_v4())).await.unwrap();
    s.delete_node("ek1").await.unwrap();
    assert!(matches!(
        s.get_node("ek1").await,
        Err(StoreError::NotFound(_))
    ));
    assert!(matches!(
        s.get_node_by_dmi(dmi1).await,
        Err(StoreError::NotFound(_))
    ));
    assert_eq!(s.list_nodes().await.unwrap().len(), 1);
    assert!(s.get_node("ek2").await.is_ok(), "no other row is touched");
    // Already gone, never there: success both times.
    s.delete_node("ek1").await.unwrap();
    s.delete_node("never-registered").await.unwrap();
    // The hash is free again, with another DMI UUID (no `Conflict`).
    s.put_node(node("ek1", Uuid::new_v4())).await.unwrap();
    assert_eq!(s.list_nodes().await.unwrap().len(), 2);
}

pub(crate) async fn a_sweep_removes_claims_that_ended_before_the_retention(s: &dyn ClaimStore) {
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
}

pub(crate) async fn a_session_is_taken_once_deleted_on_demand_and_swept_when_stale(
    s: &dyn ClaimStore,
) {
    let sandbox_uid = Uuid::new_v4();
    let session = SessionRecord {
        sandbox_uid,
        subject: subject(),
        issuer: "https://issuer.example.com".into(),
        refresh: seal(sandbox_uid, b"dex-refresh").await,
        created_at: at(0),
        audience: None,
        expires_at: None,
    };
    s.put_session(session.clone()).await.unwrap();
    let err = s.put_session(session.clone()).await.unwrap_err();
    assert!(matches!(err, StoreError::Conflict(_)), "{err}");

    let taken = s.take_session(sandbox_uid).await.unwrap().expect("parked");
    assert_eq!(taken, session);
    assert_eq!(unseal(sandbox_uid, &taken.refresh).await, b"dex-refresh");
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

/// ADR-0035: a delegated credential is a session for one audience, parked beside the
/// issuer's, taken once per audience, kept on the record as an envelope, and emptied with
/// the record's refresh material on revocation.
pub(crate) async fn delegations_are_parked_per_audience_and_revocation_empties_them(
    s: &dyn ClaimStore,
) {
    let sandbox_uid = Uuid::new_v4();
    let issuer = parked(sandbox_uid, None, b"dex-refresh", None).await;
    let github = parked(sandbox_uid, Some("github"), b"{\"token\":\"gh\"}", None).await;
    let anthropic = parked(
        sandbox_uid,
        Some("anthropic"),
        b"{\"token\":\"sess\"}",
        Some(at(900)),
    )
    .await;
    s.put_session(issuer.clone()).await.unwrap();
    s.put_session(github.clone()).await.unwrap();
    s.put_session(anthropic.clone()).await.unwrap();
    let err = s.put_session(anthropic.clone()).await.unwrap_err();
    assert!(matches!(err, StoreError::Conflict(_)), "{err}");

    let taken = s.take_delegations(sandbox_uid).await.unwrap();
    assert_eq!(
        taken,
        vec![anthropic.clone(), github.clone()],
        "audience order"
    );
    assert_eq!(
        s.take_delegations(sandbox_uid).await.unwrap(),
        Vec::new(),
        "taken once"
    );
    assert_eq!(
        s.take_session(sandbox_uid).await.unwrap().as_ref(),
        Some(&issuer),
        "the issuer's session is untouched by the delegations"
    );

    let uid = Uuid::new_v4();
    let mut rec = claim(uid);
    rec.sandbox_uid = Some(sandbox_uid);
    rec.refresh = Some(issuer.refresh.clone());
    for d in &taken {
        rec.delegations.insert(
            d.audience.clone().unwrap(),
            DelegatedSession {
                envelope: d.refresh.clone(),
                expires_at: d.expires_at,
            },
        );
    }
    s.put_claim(rec.clone()).await.unwrap();
    let got = s.get_claim(uid).await.unwrap();
    assert_eq!(got.delegations, rec.delegations);
    assert_eq!(
        unseal(sandbox_uid, &got.delegations["anthropic"].envelope).await,
        b"{\"token\":\"sess\"}"
    );
    s.revoke_claim(uid, at(5)).await.unwrap();
    let got = s.get_claim(uid).await.unwrap();
    assert!(
        got.delegations.is_empty(),
        "revocation empties every envelope"
    );
    assert!(got.refresh.is_none());

    s.put_session(github.clone()).await.unwrap();
    s.put_session(issuer.clone()).await.unwrap();
    s.delete_session(sandbox_uid).await.unwrap();
    assert!(s.take_session(sandbox_uid).await.unwrap().is_none());
    assert_eq!(s.take_delegations(sandbox_uid).await.unwrap(), Vec::new());
}

/// ADR-0043 decision 4: a credential parked for a claim that never binds must not outlive that claim. The
/// age rule alone (`created_at` before the cutoff) keeps it for the whole grace period, long after the claim's
/// TTL; the envelope's own `expires_at` is when it stops being useful, so a sweep removes it then.
pub(crate) async fn an_envelope_is_swept_when_it_expires_and_not_only_when_it_is_old(
    s: &dyn ClaimStore,
) {
    let (expired_uid, open_ended_uid, later_uid) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    // All three were created after the cutoff below, so the age rule removes none of them.
    let mut expired = parked(expired_uid, Some("registry"), b"user:secret", Some(at(160))).await;
    expired.created_at = at(100);
    let mut open_ended = parked(open_ended_uid, Some("registry"), b"user:secret", None).await;
    open_ended.created_at = at(100);
    let mut later = parked(
        later_uid,
        Some("registry"),
        b"user:secret",
        Some(Timestamp::now() + SignedDuration::from_hours(1)),
    )
    .await;
    later.created_at = at(100);
    for r in [&expired, &open_ended, &later] {
        s.put_session(r.clone()).await.unwrap();
    }

    assert_eq!(
        s.sweep_sessions(at(50)).await.unwrap(),
        1,
        "the envelope that has expired goes; one with no expiry or an expiry ahead stays"
    );
    assert_eq!(s.take_delegations(expired_uid).await.unwrap(), Vec::new());
    assert_eq!(s.take_delegations(open_ended_uid).await.unwrap().len(), 1);
    assert_eq!(s.take_delegations(later_uid).await.unwrap().len(), 1);
}

/// The operator's rule, 2026-11-15 (ADR-0043 decision 4): a delegated secret is stored no longer than the claim's TTL.
/// Once the claim is bound the envelope lives on its record, and the sweep removes it there when it expires, not at
/// the claim's end, which can be later than the envelope's expiry by the time the claim waited to bind.
pub(crate) async fn a_bound_claims_delegation_is_removed_when_it_expires(s: &dyn ClaimStore) {
    let uid = Uuid::new_v4();
    let envelope = |plain: &'static [u8]| async move { seal(uid, plain).await };
    let mut rec = claim(uid);
    rec.delegations.insert(
        "expired".into(),
        DelegatedSession {
            envelope: envelope(b"{\"token\":\"a\"}").await,
            expires_at: Some(at(160)),
        },
    );
    rec.delegations.insert(
        "later".into(),
        DelegatedSession {
            envelope: envelope(b"{\"token\":\"b\"}").await,
            expires_at: Some(Timestamp::now() + SignedDuration::from_hours(1)),
        },
    );
    rec.delegations.insert(
        "open".into(),
        DelegatedSession {
            envelope: envelope(b"{\"token\":\"c\"}").await,
            expires_at: None,
        },
    );
    s.put_claim(rec).await.unwrap();

    assert_eq!(
        s.sweep_sessions(at(50)).await.unwrap(),
        1,
        "the expired envelope on the record goes"
    );
    let kept: Vec<String> = s
        .get_claim(uid)
        .await
        .unwrap()
        .delegations
        .keys()
        .cloned()
        .collect();
    assert_eq!(kept, vec!["later".to_string(), "open".to_string()]);
}

/// The issuer's session is an envelope like any other: parked with an expiry (the claim's creation plus its TTL), it
/// goes when that passes, whatever its age, so one whose sandbox never got a record is not kept for the grace period.
pub(crate) async fn a_parked_issuer_session_is_swept_when_it_expires(s: &dyn ClaimStore) {
    let (expired_uid, later_uid) = (Uuid::new_v4(), Uuid::new_v4());
    // Both created after the cutoff below, so the age rule removes neither.
    let mut expired = parked(expired_uid, None, b"dex-refresh", Some(at(160))).await;
    expired.created_at = at(100);
    let mut later = parked(
        later_uid,
        None,
        b"dex-refresh",
        Some(Timestamp::now() + SignedDuration::from_hours(1)),
    )
    .await;
    later.created_at = at(100);
    s.put_session(expired).await.unwrap();
    s.put_session(later.clone()).await.unwrap();

    assert_eq!(
        s.sweep_sessions(at(50)).await.unwrap(),
        1,
        "the issuer's session past its expiry goes; the one with time left stays"
    );
    assert!(s.take_session(expired_uid).await.unwrap().is_none());
    let kept = s.take_session(later_uid).await.unwrap() == Some(later);
    assert!(
        kept,
        "the session with time left is still there, expiry and all"
    );
}

/// The other half of the rule: a claim's own session is kept for as long as the claim may issue, however long ago
/// it was delegated, so a bound claim refreshes to its deadline and an unbound one waits with its session; once the
/// claim has ended, nothing of it is stored any more.
pub(crate) async fn a_live_claims_session_outlasts_the_sweep_and_an_ended_claims_does_not(
    s: &dyn ClaimStore,
) {
    let (bound, waiting, ended) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let now = Timestamp::now();
    for (uid, expires_at) in [
        (bound, Some(now + SignedDuration::from_hours(1))),
        (waiting, None),
        (ended, Some(now - SignedDuration::from_secs(1))),
    ] {
        let mut rec = claim(uid);
        rec.name = format!("sandbox-{uid}");
        // Created long before any cutoff a sweep is given.
        rec.created_at = at(0);
        rec.expires_at = expires_at;
        rec.refresh = Some(seal(uid, b"dex-refresh").await);
        rec.delegations.insert(
            "open".into(),
            DelegatedSession {
                envelope: seal(uid, b"{\"token\":\"c\"}").await,
                expires_at: None,
            },
        );
        s.put_claim(rec).await.unwrap();
    }

    assert_eq!(
        s.sweep_sessions(now).await.unwrap(),
        2,
        "the ended claim's session and its delegation, nothing of a live claim"
    );
    for uid in [bound, waiting] {
        let got = s.get_claim(uid).await.unwrap();
        let kept = got.refresh.is_some() && got.delegations.len() == 1;
        assert!(kept, "a claim that may still issue keeps its envelopes");
    }
    let got = s.get_claim(ended).await.unwrap();
    let emptied = got.refresh.is_none() && got.delegations.is_empty();
    assert!(emptied, "a claim past its deadline keeps none");
    assert_eq!(s.sweep_sessions(now).await.unwrap(), 0, "and only once");
}

/// A session parked for `sandbox_uid`: the issuer's (`audience` `None`) or a delegation's.
async fn parked(
    sandbox_uid: Uuid,
    audience: Option<&str>,
    plain: &[u8],
    expires_at: Option<Timestamp>,
) -> SessionRecord {
    SessionRecord {
        sandbox_uid,
        subject: subject(),
        issuer: String::new(),
        refresh: seal(sandbox_uid, plain).await,
        created_at: at(0),
        audience: audience.map(str::to_owned),
        expires_at,
    }
}

fn floor(name: &str, uid: &str, version: u64, issued_at: Timestamp) -> PolicyFloor {
    PolicyFloor {
        namespace: "sandboxes".into(),
        name: name.into(),
        uid: uid.into(),
        version,
        issued_at,
    }
}

pub(crate) async fn a_policy_floor_round_trips_to_the_nanosecond(s: &dyn ClaimStore) {
    assert_eq!(
        s.get_policy_floor("sandboxes", "agent").await.unwrap(),
        None
    );
    // notaio's issuedAt carries nanoseconds; the floor orders incarnations by it.
    let issued = at(0) + SignedDuration::from_nanos(927_958_397);
    let f = floor("agent", "uid-1", 3, issued);
    s.advance_policy_floor(None, f.clone()).await.unwrap();
    assert_eq!(
        s.get_policy_floor("sandboxes", "agent").await.unwrap(),
        Some(f)
    );
    assert_eq!(
        s.get_policy_floor("sandboxes", "other").await.unwrap(),
        None
    );
    assert_eq!(
        s.get_policy_floor("elsewhere", "agent").await.unwrap(),
        None
    );
}

pub(crate) async fn a_policy_floor_moves_only_from_what_is_held(s: &dyn ClaimStore) {
    let v3 = floor("agent", "uid-1", 3, at(0));
    s.advance_policy_floor(None, v3.clone()).await.unwrap();

    // A second replica that also read "no floor" loses the race.
    let err = s
        .advance_policy_floor(None, floor("agent", "uid-1", 2, at(0)))
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::Conflict(_)), "{err}");

    let v4 = floor("agent", "uid-1", 4, at(10));
    s.advance_policy_floor(Some(&v3), v4.clone()).await.unwrap();

    // Decided from v3, which is no longer held: refused, and v4 stays.
    let err = s
        .advance_policy_floor(Some(&v3), floor("agent", "uid-1", 3, at(5)))
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::Conflict(_)), "{err}");
    // Held matching on uid and version but not issuedAt is not held either.
    let mut almost = v4.clone();
    almost.issued_at = at(10) + SignedDuration::from_nanos(1);
    let err = s
        .advance_policy_floor(Some(&almost), floor("agent", "uid-1", 5, at(20)))
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::Conflict(_)), "{err}");
    assert_eq!(
        s.get_policy_floor("sandboxes", "agent").await.unwrap(),
        Some(v4.clone())
    );

    // A new incarnation replaces the row; another policy's floor is its own.
    let recreated = floor("agent", "uid-2", 1, at(30));
    s.advance_policy_floor(Some(&v4), recreated.clone())
        .await
        .unwrap();
    s.advance_policy_floor(None, floor("other", "uid-9", 1, at(0)))
        .await
        .unwrap();
    assert_eq!(
        s.get_policy_floor("sandboxes", "agent").await.unwrap(),
        Some(recreated)
    );
}

pub(crate) async fn a_floor_written_under_another_policy_is_refused(s: &dyn ClaimStore) {
    let held = floor("agent", "uid-1", 1, at(0));
    s.advance_policy_floor(None, held.clone()).await.unwrap();
    let err = s
        .advance_policy_floor(Some(&held), floor("other", "uid-1", 2, at(1)))
        .await
        .unwrap_err();
    assert!(matches!(err, StoreError::Conflict(_)), "{err}");
    assert_eq!(
        s.get_policy_floor("sandboxes", "other").await.unwrap(),
        None
    );
    assert_eq!(
        s.get_policy_floor("sandboxes", "agent").await.unwrap(),
        Some(held)
    );
}

/// ADR-0055 decision 1: an audience's floor is kept under notaio's `audience/<name>`, a name no
/// policy can have, beside the policy floors and never in their place.
pub(crate) async fn an_audience_floor_is_its_own_beside_a_policy_of_the_same_name(
    s: &dyn ClaimStore,
) {
    let policy = floor("artifactory", "policy-uid", 7, at(0));
    let audience = floor("audience/artifactory", "audience-uid", 2, at(5));
    s.advance_policy_floor(None, policy.clone()).await.unwrap();
    s.advance_policy_floor(None, audience.clone())
        .await
        .unwrap();
    assert_eq!(
        s.get_policy_floor("sandboxes", "artifactory")
            .await
            .unwrap(),
        Some(policy)
    );
    assert_eq!(
        s.get_policy_floor("sandboxes", "audience/artifactory")
            .await
            .unwrap(),
        Some(audience.clone())
    );
    let next = floor("audience/artifactory", "audience-uid", 3, at(10));
    s.advance_policy_floor(Some(&audience), next.clone())
        .await
        .unwrap();
    assert_eq!(
        s.get_policy_floor("sandboxes", "audience/artifactory")
            .await
            .unwrap(),
        Some(next)
    );
}

pub(crate) async fn ping_answers(s: &dyn ClaimStore) {
    s.ping().await.unwrap();
}

// ---------- the output ring (ADR-0045 decisions 4, 6, 7 and 8) ----------

fn log_record(seq: u64, stream: LogStream, text: &str) -> LogRecord {
    LogRecord {
        seq,
        stream,
        ts: at(i64::try_from(seq).unwrap()),
        text: text.into(),
        partial: false,
    }
}

/// A batch of stdout lines `from..=to`, each `text` repeated, no drops.
fn batch(from: u64, to: u64, text: &str) -> LogBatch {
    LogBatch {
        records: (from..=to)
            .map(|seq| log_record(seq, LogStream::Stdout, text))
            .collect(),
        ..LogBatch::default()
    }
}

fn records_of(entries: &[LogEntry]) -> Vec<u64> {
    entries.iter().filter_map(LogEntry::seq).collect()
}

/// Room for plenty: the default of the broker, far above what these cases store.
const ROOMY: LogLimits = LogLimits {
    max_bytes: mediatore_proto::DEFAULT_LOG_MAX_BYTES,
};

pub(crate) async fn appended_output_reads_back_in_sequence(s: &dyn ClaimStore) {
    let uid = Uuid::new_v4();
    let rec = claim(uid);
    s.put_claim(rec.clone()).await.unwrap();
    assert_eq!(
        s.read_logs(uid, None).await.unwrap(),
        crate::LogChunk::default(),
        "nothing stored is an empty chunk, not an error"
    );
    let mut first = batch(1, 2, "hello");
    first.records[1] = log_record(2, LogStream::Stderr, "oops");
    let done = s.append_logs(&rec, &first, &ROOMY).await.unwrap();
    assert_eq!(
        done,
        crate::LogAppend {
            stored: 2,
            ignored: 0,
            dropped: 0
        }
    );
    let done = s
        .append_logs(&rec, &batch(3, 3, "bye"), &ROOMY)
        .await
        .unwrap();
    assert_eq!(done.stored, 1);
    let chunk = s.read_logs(uid, None).await.unwrap();
    assert_eq!(chunk.truncated_before, 0);
    assert_eq!(chunk.last_seq, Some(3));
    assert_eq!(
        chunk.entries,
        vec![
            LogEntry::Record(first.records[0].clone()),
            LogEntry::Record(first.records[1].clone()),
            LogEntry::Record(log_record(3, LogStream::Stdout, "bye")),
        ],
        "every field of a record, the stream included, in sequence"
    );
    // Another claim's output is another ring.
    let other = Uuid::new_v4();
    assert_eq!(s.read_logs(other, None).await.unwrap().entries, Vec::new());
}

/// The `partial` mark of every record among `entries`, in order.
fn partial_marks(entries: &[LogEntry]) -> Vec<bool> {
    entries
        .iter()
        .filter_map(|e| match e {
            LogEntry::Record(r) => Some(r.partial),
            LogEntry::Gap(_) => None,
        })
        .collect()
}

/// ADR-0045 decision 9, amended 2026-11-20: a record that says its line goes on says so
/// when it is read back, whole, from a cursor and as a tail; one that does not, does not.
pub(crate) async fn a_partial_record_keeps_its_mark_through_a_write_and_a_read(s: &dyn ClaimStore) {
    let uid = Uuid::new_v4();
    let rec = claim(uid);
    s.put_claim(rec.clone()).await.unwrap();
    let mut pieces = batch(1, 3, "piece");
    pieces.records[0].partial = true;
    pieces.records[1].partial = true;
    s.append_logs(&rec, &pieces, &ROOMY).await.unwrap();
    let chunk = s.read_logs(uid, None).await.unwrap();
    assert_eq!(records_of(&chunk.entries), vec![1, 2, 3]);
    assert_eq!(
        partial_marks(&chunk.entries),
        vec![true, true, false],
        "the mark is stored with its record"
    );
    let chunk = s.read_logs(uid, Some(1)).await.unwrap();
    assert_eq!(partial_marks(&chunk.entries), vec![true, false]);
    let chunk = s.read_logs_tail(uid, None, 1).await.unwrap();
    assert_eq!(partial_marks(&chunk.entries), vec![false]);
}

pub(crate) async fn a_retried_batch_stores_nothing_and_is_counted_ignored(s: &dyn ClaimStore) {
    let uid = Uuid::new_v4();
    let rec = claim(uid);
    s.put_claim(rec.clone()).await.unwrap();
    let b = batch(1, 3, "line");
    s.append_logs(&rec, &b, &ROOMY).await.unwrap();
    let again = s.append_logs(&rec, &b, &ROOMY).await.unwrap();
    assert_eq!(
        again,
        crate::LogAppend {
            stored: 0,
            ignored: 3,
            dropped: 0
        }
    );
    let chunk = s.read_logs(uid, None).await.unwrap();
    assert_eq!(records_of(&chunk.entries), vec![1, 2, 3]);
    assert_eq!(chunk.last_seq, Some(3));
}

pub(crate) async fn an_overlapping_batch_stores_only_its_new_records(s: &dyn ClaimStore) {
    let uid = Uuid::new_v4();
    let rec = claim(uid);
    s.put_claim(rec.clone()).await.unwrap();
    s.append_logs(&rec, &batch(1, 3, "a"), &ROOMY)
        .await
        .unwrap();
    let done = s
        .append_logs(&rec, &batch(2, 5, "b"), &ROOMY)
        .await
        .unwrap();
    assert_eq!(
        done,
        crate::LogAppend {
            stored: 2,
            ignored: 2,
            dropped: 0
        }
    );
    let chunk = s.read_logs(uid, None).await.unwrap();
    assert_eq!(records_of(&chunk.entries), vec![1, 2, 3, 4, 5]);
    let texts: Vec<&str> = chunk
        .entries
        .iter()
        .filter_map(|e| match e {
            LogEntry::Record(r) => Some(r.text.as_str()),
            LogEntry::Gap(_) => None,
        })
        .collect();
    assert_eq!(
        texts,
        vec!["a", "a", "a", "b", "b"],
        "the stored copy wins over a replay"
    );
}

pub(crate) async fn a_gap_is_stored_before_a_batch_with_dropped_counts_and_not_for_a_replay(
    s: &dyn ClaimStore,
) {
    let uid = Uuid::new_v4();
    let rec = claim(uid);
    s.put_claim(rec.clone()).await.unwrap();
    s.append_logs(&rec, &batch(1, 1, "start"), &ROOMY)
        .await
        .unwrap();
    let mut lossy = batch(2, 3, "after");
    lossy.dropped_stdout = 4096;
    lossy.dropped_stderr = 12;
    s.append_logs(&rec, &lossy, &ROOMY).await.unwrap();
    // The same batch again: no second gap.
    let again = s.append_logs(&rec, &lossy, &ROOMY).await.unwrap();
    assert_eq!(again.stored, 0);
    let chunk = s.read_logs(uid, None).await.unwrap();
    assert_eq!(
        chunk.entries,
        vec![
            LogEntry::Record(log_record(1, LogStream::Stdout, "start")),
            LogEntry::Gap(LogGap {
                lost_stdout: 4096,
                lost_stderr: 12,
                unreadable: 0,
            }),
            LogEntry::Record(log_record(2, LogStream::Stdout, "after")),
            LogEntry::Record(log_record(3, LogStream::Stdout, "after")),
        ]
    );
    assert_eq!(
        chunk.truncated_before, 0,
        "the guest's loss is a gap, not the ring's"
    );
}

pub(crate) async fn the_ring_drops_the_oldest_and_counts_the_bytes_it_dropped(s: &dyn ClaimStore) {
    let uid = Uuid::new_v4();
    let rec = claim(uid);
    s.put_claim(rec.clone()).await.unwrap();
    // One segment's worth of output per batch, exactly: 64 records of 1 KiB.
    let kib = "x".repeat(1024);
    let segment = mediatore_proto::LOG_SEGMENT_BYTES;
    let per_batch = u64::try_from(segment / 1024).unwrap();
    let limits = LogLimits {
        max_bytes: 2 * segment,
    };
    for i in 0..3u64 {
        let from = i * per_batch + 1;
        let b = batch(from, from + per_batch - 1, &kib);
        assert_eq!(b.text_bytes(), segment);
        s.append_logs(&rec, &b, &limits).await.unwrap();
    }
    let chunk = s.read_logs(uid, None).await.unwrap();
    let kept: usize = chunk.entries.iter().map(LogEntry::text_bytes).sum();
    assert!(
        kept <= limits.max_bytes,
        "{kept} bytes kept over a cap of {}",
        limits.max_bytes
    );
    assert_eq!(
        chunk.truncated_before,
        u64::try_from(3 * segment - kept).unwrap(),
        "what was dropped is counted exactly"
    );
    assert_eq!(
        chunk.truncated_before,
        u64::try_from(segment).unwrap(),
        "the oldest segment's worth went"
    );
    assert_eq!(
        records_of(&chunk.entries).first().copied(),
        Some(per_batch + 1),
        "the oldest records went first"
    );
    assert_eq!(chunk.last_seq, Some(3 * per_batch), "the newest stayed");
}

pub(crate) async fn a_read_since_a_cursor_returns_later_records_and_the_gap_right_before_them(
    s: &dyn ClaimStore,
) {
    let uid = Uuid::new_v4();
    let rec = claim(uid);
    s.put_claim(rec.clone()).await.unwrap();
    s.append_logs(&rec, &batch(1, 2, "a"), &ROOMY)
        .await
        .unwrap();
    let mut lossy = batch(3, 4, "b");
    lossy.dropped_stderr = 7;
    s.append_logs(&rec, &lossy, &ROOMY).await.unwrap();
    let chunk = s.read_logs(uid, Some(2)).await.unwrap();
    assert_eq!(
        chunk.entries,
        vec![
            LogEntry::Gap(LogGap {
                lost_stdout: 0,
                lost_stderr: 7,
                unreadable: 0,
            }),
            LogEntry::Record(log_record(3, LogStream::Stdout, "b")),
            LogEntry::Record(log_record(4, LogStream::Stdout, "b")),
        ],
        "the gap that precedes the first new record comes with it"
    );
    let chunk = s.read_logs(uid, Some(3)).await.unwrap();
    assert_eq!(records_of(&chunk.entries), vec![4]);
    assert!(
        !chunk.entries.iter().any(|e| matches!(e, LogEntry::Gap(_))),
        "a gap before an already-read record is not repeated"
    );
    let chunk = s.read_logs(uid, Some(4)).await.unwrap();
    assert!(chunk.entries.is_empty(), "nothing after the newest");
    assert_eq!(
        chunk.last_seq,
        Some(4),
        "the cursor does not hide the ring's state"
    );
}

pub(crate) async fn a_log_sweep_removes_gone_and_ended_claims_output_and_keeps_a_live_claims(
    s: &dyn ClaimStore,
) {
    // A claim whose record is gone: output appended, no record ever written.
    let orphan = Uuid::new_v4();
    s.append_logs(&claim(orphan), &batch(1, 1, "lost"), &ROOMY)
        .await
        .unwrap();
    // One that ended before the retention.
    let ended = Uuid::new_v4();
    let mut rec = claim(ended);
    rec.expires_at = Some(at(200));
    s.put_claim(rec.clone()).await.unwrap();
    s.append_logs(&rec, &batch(1, 1, "done"), &ROOMY)
        .await
        .unwrap();
    // One still running.
    let live = Uuid::new_v4();
    let mut rec = claim(live);
    rec.expires_at = Some(at(10_000));
    s.put_claim(rec.clone()).await.unwrap();
    s.append_logs(&rec, &batch(1, 1, "running"), &ROOMY)
        .await
        .unwrap();

    assert_eq!(s.sweep_logs(at(1000)).await.unwrap(), 2);
    assert_eq!(s.read_logs(orphan, None).await.unwrap().entries, Vec::new());
    assert_eq!(s.read_logs(ended, None).await.unwrap().entries, Vec::new());
    assert_eq!(
        records_of(&s.read_logs(live, None).await.unwrap().entries),
        vec![1]
    );
    // Already swept: nothing more.
    assert_eq!(s.sweep_logs(at(1000)).await.unwrap(), 0);
}

pub(crate) async fn deleting_output_that_was_never_stored_is_fine(s: &dyn ClaimStore) {
    let uid = Uuid::new_v4();
    s.delete_logs(uid).await.unwrap();
    let rec = claim(uid);
    s.put_claim(rec.clone()).await.unwrap();
    s.append_logs(&rec, &batch(1, 2, "x"), &ROOMY)
        .await
        .unwrap();
    s.delete_logs(uid).await.unwrap();
    assert_eq!(s.read_logs(uid, None).await.unwrap().entries, Vec::new());
    s.delete_logs(uid).await.unwrap();
}
