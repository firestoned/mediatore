// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The storage contract's cases that every store is held to by the same code (ADR-0057
//! decision 6): the version a record is read at, the compare-and-set of an update, the
//! release that carries no precondition and cannot lose, and [`modify_claim`]. Run over
//! `MemoryStore` here and, through the `test-support` feature, by `mediatore-claims` over the
//! Kubernetes store on its fake API server. A store that accepts what another refuses fails a
//! case here.
//!
//! A case builds its own records; [`Fixture::prepare`] is where a store that keeps a record
//! on something else (an `AgentSandbox`) makes that thing exist first.

#![allow(
    clippy::missing_panics_doc,
    reason = "every case panics when the contract is broken: these are test bodies, not an API"
)]

use std::collections::BTreeMap;

use jiff::{SignedDuration, Timestamp};
use mediatore_proto::{Subject, Workload};
use uuid::Uuid;

use crate::seal::{FORMAT_SLOT, Sealed};
use crate::{
    ClaimRecord, ClaimStore, DelegatedSession, MODIFY_ATTEMPTS, MemoryStore, Modified,
    SessionRecord, StoreError, modify_claim,
};

/// A store under test, and what a record needs before it can be put there.
pub trait Fixture: Send + Sync {
    /// The store.
    fn store(&self) -> &dyn ClaimStore;
    /// Make whatever `rec` lives on exist, and return the record to hand to
    /// [`ClaimStore::put_claim`]. A store that keeps records by themselves returns it as it is.
    fn prepare(&self, rec: ClaimRecord) -> ClaimRecord;
}

impl Fixture for MemoryStore {
    fn store(&self) -> &dyn ClaimStore {
        self
    }

    fn prepare(&self, rec: ClaimRecord) -> ClaimRecord {
        rec
    }
}

/// One `#[tokio::test]` per shared case, each over a fresh fixture from `$make`.
#[macro_export]
macro_rules! shared_suite {
    (@each $make:expr; $($name:ident),* $(,)?) => {
        $(
            #[tokio::test]
            async fn $name() {
                let fixture = $make;
                $crate::shared_cases::$name(&fixture).await;
            }
        )*
    };
    ($make:expr) => {
        $crate::shared_suite!(@each $make;
            a_record_read_twice_carries_a_version_and_a_write_moves_it,
            an_update_from_a_stale_version_is_a_conflict_and_writes_nothing,
            two_updates_from_one_read_land_once,
            an_update_without_a_version_is_a_conflict,
            a_release_between_a_read_and_its_update_is_never_overwritten,
            a_release_lands_whatever_version_anyone_holds,
            a_second_release_keeps_the_first_timestamp_and_still_drops_what_is_left,
            an_update_never_puts_back_an_envelope_the_release_dropped,
            modify_claim_decides_again_on_the_fresh_record_and_stops_at_a_released_one,
            modify_claim_gives_up_after_its_attempts_with_a_conflict,
            what_the_guest_rendered_and_the_follow_verdict_survive_a_write,
            a_claim_is_found_by_the_x509pop_agent_id_of_its_node,
        );
    };
}

/// A whole second: a Kubernetes `Time` keeps no more.
fn at(secs: i64) -> Timestamp {
    Timestamp::from_second(1_700_000_000 + secs).unwrap()
}

fn subject() -> Subject {
    Subject {
        issuer: "https://issuer.example.com".into(),
        id: "octocat".into(),
        display: None,
    }
}

/// A record for claim `uid`, on a sandbox of its own, nothing bound.
fn record(uid: Uuid) -> ClaimRecord {
    ClaimRecord {
        rendered: None,
        follow: None,
        uid,
        name: format!("sandbox-{}", &uid.to_string()[..8]),
        namespace: "team-a".into(),
        subject: subject(),
        entry_id: None,
        node_id: None,
        audiences: vec!["e2e".into()],
        workload: Workload {
            image: "registry.internal:5000/sandbox/x:1".into(),
            args: vec!["/bin/x".into()],
            restart: mediatore_proto::RestartPolicy::OnFailure,
            logs: false,
        },
        ttl_seconds: 3600,
        refresh: None,
        created_at: at(0),
        expires_at: None,
        revoked_at: None,
        sandbox_uid: Some(Uuid::new_v4()),
        policy_uid: None,
        bundle_version: None,
        report: None,
        exit: None,
        delegations: BTreeMap::new(),
        version: None,
    }
}

/// An envelope as a store sees one: bytes it keeps and never opens. `tag` tells two apart.
fn envelope(tag: u8) -> Sealed {
    Sealed {
        key_id: "k1".into(),
        nonce: vec![tag],
        ciphertext: vec![tag, tag],
        format: FORMAT_SLOT,
    }
}

/// A record for claim `uid` carrying the issuer's session and one delegation.
fn record_with_envelopes(uid: Uuid) -> ClaimRecord {
    let mut rec = record(uid);
    rec.refresh = Some(envelope(1));
    rec.delegations.insert(
        "github".into(),
        DelegatedSession {
            envelope: envelope(2),
            expires_at: None,
        },
    );
    rec
}

/// Put a fresh record and return the UID of its claim and of its sandbox.
async fn stored(f: &dyn Fixture, rec: ClaimRecord) -> (Uuid, Uuid) {
    let rec = f.prepare(rec);
    let (uid, sandbox_uid) = (rec.uid, rec.sandbox_uid.expect("a sandbox uid"));
    f.store().put_claim(rec).await.unwrap();
    (uid, sandbox_uid)
}

/// ADR-0061 decision 2: what the guest was handed and the follow rule's verdict are kept on
/// the record by every store, field for field.
pub async fn what_the_guest_rendered_and_the_follow_verdict_survive_a_write(f: &dyn Fixture) {
    let s = f.store();
    let (uid, _) = stored(f, record(Uuid::new_v4())).await;
    let mut rec = s.get_claim(uid).await.unwrap();
    assert!(
        rec.rendered.is_none() && rec.follow.is_none(),
        "neither is set on a new record"
    );
    let rendered = mediatore_proto::Rendered {
        bundle_version: 3,
        bundle_digest: "sha256:0123".into(),
        routes: vec![mediatore_proto::RenderedRoute {
            audience: Some("e2e".into()),
            endpoint: "git.example.com:443".parse().unwrap(),
            rules: vec![mediatore_proto::EndpointRule {
                method: "GET".into(),
                path: "/repos/**".into(),
            }],
        }],
        egress: vec!["git.example.com:443".parse().unwrap()],
    };
    let follow = mediatore_proto::FollowRefusal {
        reason: mediatore_proto::FollowReason::LeaseExceeded,
        rendered_version: Some(3),
        current_version: 4,
        enforced: false,
        at: at(60),
    };
    rec.rendered = Some(rendered.clone());
    rec.follow = Some(follow.clone());
    s.update_claim(rec).await.unwrap();
    let read = s.get_claim(uid).await.unwrap();
    assert!(
        read.rendered == Some(rendered),
        "the rendered routes and egress are kept"
    );
    assert!(read.follow == Some(follow), "the follow verdict is kept");
}

/// Decision 1: every read sets the version, two reads with no write between them agree, and
/// every write of the record moves it, a release included.
pub async fn a_record_read_twice_carries_a_version_and_a_write_moves_it(f: &dyn Fixture) {
    let s = f.store();
    let (uid, _) = stored(f, record(Uuid::new_v4())).await;
    let first = s.get_claim(uid).await.unwrap();
    let second = s.get_claim(uid).await.unwrap();
    assert!(first.version.is_some(), "a record read carries a version");
    assert!(
        first.version == second.version,
        "two reads with no write between them carry the same version"
    );
    let by_name = s
        .get_claim_by_name(&first.namespace, &first.name)
        .await
        .unwrap();
    assert!(
        by_name.version == first.version,
        "the read by name carries it"
    );
    let listed = s.list_claims().await.unwrap();
    let in_list = listed
        .iter()
        .any(|c| c.uid == uid && c.version == first.version);
    assert!(in_list, "the listing carries it");

    let node = "spiffe://sandbox.test/spire/agent/tpm/ek1";
    let mut bound = second;
    bound.node_id = Some(node.into());
    bound.expires_at = Some(Timestamp::now() + SignedDuration::from_hours(1));
    s.update_claim(bound).await.unwrap();
    let third = s.get_claim(uid).await.unwrap();
    assert!(
        third.version.is_some() && third.version != first.version,
        "an update moves the version"
    );
    let by_node = s.get_claim_by_node(node).await.unwrap();
    assert!(
        by_node.version == third.version,
        "the read by node carries it"
    );

    s.revoke_claim(uid, at(5)).await.unwrap();
    let fourth = s.get_claim(uid).await.unwrap();
    assert!(
        fourth.version.is_some() && fourth.version != third.version,
        "a release moves the version"
    );
}

/// ADR-0049 decision 8: a claim bound to an x509pop node carries that node's agent ID, and the
/// lookup by node finds it by exactly that ID: not by another guest of the same host, not by
/// another host's guest of the same name, not by a longer or shorter ID. The names are at the
/// length limit, so a store that keys the lookup on something bounded (a label) is held to it.
pub async fn a_claim_is_found_by_the_x509pop_agent_id_of_its_node(f: &dyn Fixture) {
    let s = f.store();
    let issuer = "h".repeat(64);
    let subject = "v".repeat(64);
    let agent = format!("spiffe://sandbox.test/spire/agent/x509pop/{issuer}/{subject}");
    let (uid, _) = stored(f, record(Uuid::new_v4())).await;
    let mut bound = s.get_claim(uid).await.unwrap();
    bound.node_id = Some(agent.clone());
    bound.expires_at = Some(Timestamp::now() + SignedDuration::from_hours(1));
    s.update_claim(bound).await.unwrap();
    let found = s.get_claim_by_node(&agent).await.unwrap();
    assert!(found.uid == uid, "found by its node's x509pop agent ID");
    assert!(
        found.node_id.as_deref() == Some(agent.as_str()),
        "and the ID is stored whole"
    );
    for other in [
        format!("spiffe://sandbox.test/spire/agent/x509pop/{issuer}/other"),
        format!("spiffe://sandbox.test/spire/agent/x509pop/other/{subject}"),
        format!("spiffe://sandbox.test/spire/agent/x509pop/{issuer}"),
        format!("{agent}/extra"),
        format!("spiffe://other.test/spire/agent/x509pop/{issuer}/{subject}"),
    ] {
        let missed = matches!(
            s.get_claim_by_node(&other).await,
            Err(StoreError::NotFound(_))
        );
        assert!(missed, "another agent's ID finds nothing");
    }
}

/// Decision 2: a copy read before another write landed is refused, and nothing of it lands.
pub async fn an_update_from_a_stale_version_is_a_conflict_and_writes_nothing(f: &dyn Fixture) {
    let s = f.store();
    let (uid, _) = stored(f, record(Uuid::new_v4())).await;
    let stale = s.get_claim(uid).await.unwrap();
    let mut winner = s.get_claim(uid).await.unwrap();
    winner.node_id = Some("node-a".into());
    s.update_claim(winner).await.unwrap();

    let mut late = stale;
    late.entry_id = Some("late-entry".into());
    let refused = matches!(s.update_claim(late).await, Err(StoreError::Conflict(_)));
    assert!(refused, "an update from a stale version is a conflict");
    let got = s.get_claim(uid).await.unwrap();
    assert_eq!(got.node_id.as_deref(), Some("node-a"), "the winner stays");
    assert!(got.entry_id.is_none(), "no field of the late copy landed");
}

/// Decision 2: of two writers that decided from the same read, one lands and the other is
/// told, instead of silently undoing the first.
pub async fn two_updates_from_one_read_land_once(f: &dyn Fixture) {
    let s = f.store();
    let (uid, _) = stored(f, record(Uuid::new_v4())).await;
    let read = s.get_claim(uid).await.unwrap();
    let mut first = read.clone();
    first.entry_id = Some("entry-first".into());
    let mut second = read;
    second.node_id = Some("node-second".into());
    s.update_claim(first).await.unwrap();
    let refused = matches!(s.update_claim(second).await, Err(StoreError::Conflict(_)));
    assert!(refused, "the second write from the same read is a conflict");
    let got = s.get_claim(uid).await.unwrap();
    assert_eq!(got.entry_id.as_deref(), Some("entry-first"));
    assert!(got.node_id.is_none(), "the loser wrote nothing");
}

/// Decision 2: a record that was not read from the store has no version, and an update of
/// one is a caller's bug that writes nothing.
pub async fn an_update_without_a_version_is_a_conflict(f: &dyn Fixture) {
    let s = f.store();
    let (uid, _) = stored(f, record(Uuid::new_v4())).await;
    let mut built = s.get_claim(uid).await.unwrap();
    built.version = None;
    built.entry_id = Some("entry".into());
    let refused = matches!(s.update_claim(built).await, Err(StoreError::Conflict(_)));
    assert!(refused, "an update without a version is a conflict");
    assert!(
        s.get_claim(uid).await.unwrap().entry_id.is_none(),
        "and writes nothing"
    );
}

/// Decisions 2 and 3: a release that lands between a writer's read and its update is never
/// written over. The record stays released at the same instant, with no envelope.
pub async fn a_release_between_a_read_and_its_update_is_never_overwritten(f: &dyn Fixture) {
    let s = f.store();
    let (uid, sandbox_uid) = stored(f, record_with_envelopes(Uuid::new_v4())).await;
    let mut held = s.get_claim(uid).await.unwrap();
    let carried = held.refresh.is_some() && held.delegations.len() == 1;
    assert!(carried, "the copy read before the release carries both");

    s.revoke_claim(uid, at(5)).await.unwrap();

    held.entry_id = Some("entry".into());
    held.node_id = Some("node".into());
    let refused = matches!(s.update_claim(held).await, Err(StoreError::Conflict(_)));
    assert!(refused, "the update decided before the release is refused");
    let got = s.get_claim(uid).await.unwrap();
    assert_eq!(got.revoked_at, Some(at(5)), "still released, same instant");
    assert!(got.refresh.is_none(), "no refresh material came back");
    assert!(got.delegations.is_empty(), "no delegation came back");
    assert!(
        got.entry_id.is_none() && got.node_id.is_none(),
        "no field of the stale copy landed"
    );
    assert!(s.take_session(sandbox_uid).await.unwrap().is_none());
    assert!(
        s.take_delegations(sandbox_uid).await.unwrap().is_empty(),
        "no delegation is left to take"
    );
}

/// Decision 3: a release names no version. It lands on a record nobody read, and on one that
/// moved any number of times since anyone read it.
pub async fn a_release_lands_whatever_version_anyone_holds(f: &dyn Fixture) {
    let s = f.store();
    // Never read at all.
    let (unread, _) = stored(f, record(Uuid::new_v4())).await;
    s.revoke_claim(unread, at(1)).await.unwrap();
    assert_eq!(
        s.get_claim(unread).await.unwrap().revoked_at,
        Some(at(1)),
        "a release needs no read"
    );

    // Moved twice since the holder's read.
    let (uid, _) = stored(f, record_with_envelopes(Uuid::new_v4())).await;
    let held = s.get_claim(uid).await.unwrap();
    for entry in ["entry-1", "entry-2"] {
        let mut next = s.get_claim(uid).await.unwrap();
        next.entry_id = Some(entry.into());
        s.update_claim(next).await.unwrap();
    }
    s.revoke_claim(uid, at(7)).await.unwrap();
    let got = s.get_claim(uid).await.unwrap();
    assert_eq!(got.revoked_at, Some(at(7)), "the release landed");
    assert!(got.refresh.is_none() && got.delegations.is_empty());
    assert_eq!(
        got.entry_id.as_deref(),
        Some("entry-2"),
        "a release names only what it sets: the entry a retraction needs stays"
    );
    // And the copy held from before all of it writes nothing.
    let refused = matches!(s.update_claim(held).await, Err(StoreError::Conflict(_)));
    assert!(refused, "a copy from before the release is refused");
}

/// Decisions 3 and 4: a release of a record read as released keeps the first timestamp, and
/// still removes what a failed first attempt (or a late writer) left for the sandbox.
pub async fn a_second_release_keeps_the_first_timestamp_and_still_drops_what_is_left(
    f: &dyn Fixture,
) {
    let s = f.store();
    let (uid, sandbox_uid) = stored(f, record_with_envelopes(Uuid::new_v4())).await;
    s.revoke_claim(uid, at(5)).await.unwrap();

    // What is left: a session of the sandbox, in storage beside a released record.
    s.put_session(SessionRecord {
        sandbox_uid,
        subject: subject(),
        issuer: "https://issuer.example.com".into(),
        refresh: envelope(3),
        created_at: at(6),
        audience: None,
        expires_at: None,
    })
    .await
    .unwrap();
    s.put_session(SessionRecord {
        sandbox_uid,
        subject: subject(),
        issuer: String::new(),
        refresh: envelope(4),
        created_at: at(6),
        audience: Some("github".into()),
        expires_at: None,
    })
    .await
    .unwrap();

    s.revoke_claim(uid, at(9)).await.unwrap();
    let got = s.get_claim(uid).await.unwrap();
    assert_eq!(got.revoked_at, Some(at(5)), "the first timestamp stays");
    assert!(got.refresh.is_none() && got.delegations.is_empty());
    assert!(
        s.take_session(sandbox_uid).await.unwrap().is_none(),
        "the second release removed the session that was left"
    );
    assert!(
        s.take_delegations(sandbox_uid).await.unwrap().is_empty(),
        "and the delegation"
    );
}

/// Decision 4: an update that changes only an envelope (a rotated refresh token) and was
/// decided before a release stores nothing: the envelope the release dropped stays dropped.
pub async fn an_update_never_puts_back_an_envelope_the_release_dropped(f: &dyn Fixture) {
    let s = f.store();
    let (uid, sandbox_uid) = stored(f, record_with_envelopes(Uuid::new_v4())).await;
    let mut held = s.get_claim(uid).await.unwrap();
    s.revoke_claim(uid, at(5)).await.unwrap();

    held.refresh = Some(envelope(9));
    let refused = matches!(s.update_claim(held).await, Err(StoreError::Conflict(_)));
    assert!(refused, "the rotated envelope is refused after the release");
    let got = s.get_claim(uid).await.unwrap();
    assert!(got.refresh.is_none(), "no envelope on the record");
    assert!(got.delegations.is_empty(), "no delegation on the record");
    assert!(
        s.take_session(sandbox_uid).await.unwrap().is_none(),
        "and none in storage for the sandbox"
    );
    assert!(
        s.take_delegations(sandbox_uid).await.unwrap().is_empty(),
        "nor a delegation"
    );
}

/// Decision 5: `modify_claim` hands the closure the fresh record on every attempt, writes
/// what the closure decided from it, and never hands it a released record.
pub async fn modify_claim_decides_again_on_the_fresh_record_and_stops_at_a_released_one(
    f: &dyn Fixture,
) {
    let s = f.store();
    let (uid, _) = stored(f, record(Uuid::new_v4())).await;
    // A decision made from a copy that has since moved: the first attempt writes it and loses.
    let stale = s.get_claim(uid).await.unwrap();
    let mut other = s.get_claim(uid).await.unwrap();
    other.node_id = Some("node-other".into());
    s.update_claim(other).await.unwrap();

    let mut calls = 0;
    let mut saw_the_other_write = false;
    let outcome = modify_claim(s, uid, |fresh| {
        calls += 1;
        let mut next = if calls == 1 { stale.clone() } else { fresh };
        if calls > 1 {
            saw_the_other_write = next.node_id.as_deref() == Some("node-other");
        }
        next.entry_id = Some("entry".into());
        Some(next)
    })
    .await
    .unwrap();
    assert_eq!(outcome, Modified::Written);
    assert_eq!(calls, 2, "one conflict, one second decision");
    assert!(
        saw_the_other_write,
        "the second decision saw the fresh record"
    );
    let got = s.get_claim(uid).await.unwrap();
    assert_eq!(got.entry_id.as_deref(), Some("entry"));
    assert_eq!(
        got.node_id.as_deref(),
        Some("node-other"),
        "nothing of the other writer was undone"
    );

    // Nothing to write for the record as it is: no write, the version stays.
    let before = s.get_claim(uid).await.unwrap().version;
    let outcome = modify_claim(s, uid, |_| None).await.unwrap();
    assert_eq!(outcome, Modified::Unchanged);
    assert!(
        s.get_claim(uid).await.unwrap().version == before,
        "an unchanged record is not written"
    );

    // Released: the closure is not asked, nothing is written.
    s.revoke_claim(uid, at(5)).await.unwrap();
    let mut asked = false;
    let outcome = modify_claim(s, uid, |fresh| {
        asked = true;
        Some(fresh)
    })
    .await
    .unwrap();
    assert_eq!(outcome, Modified::Released);
    assert!(!asked, "a released record is not handed to the closure");
    assert_eq!(s.get_claim(uid).await.unwrap().revoked_at, Some(at(5)));

    // Gone: not found.
    let missing = modify_claim(s, Uuid::new_v4(), Some).await;
    assert!(matches!(missing, Err(StoreError::NotFound(_))));
}

/// Decision 5: a caller that loses every attempt is told with a `Conflict` after
/// [`MODIFY_ATTEMPTS`] decisions, and nothing of its record is written.
pub async fn modify_claim_gives_up_after_its_attempts_with_a_conflict(f: &dyn Fixture) {
    let s = f.store();
    let (uid, _) = stored(f, record(Uuid::new_v4())).await;
    // A writer whose every decision is from a copy that has moved: it loses each time.
    let mut stale = s.get_claim(uid).await.unwrap();
    stale.entry_id = Some("never".into());
    let mut other = s.get_claim(uid).await.unwrap();
    other.node_id = Some("node-other".into());
    s.update_claim(other).await.unwrap();

    let mut calls = 0;
    let outcome = modify_claim(s, uid, |_fresh| {
        calls += 1;
        Some(stale.clone())
    })
    .await;
    let gave_up = matches!(outcome, Err(StoreError::Conflict(_)));
    assert!(gave_up, "attempts that all lost are a conflict");
    assert_eq!(
        calls, MODIFY_ATTEMPTS,
        "it decides that many times, no more"
    );
    let got = s.get_claim(uid).await.unwrap();
    assert!(got.entry_id.is_none(), "nothing of the loser was written");
    assert_eq!(got.node_id.as_deref(), Some("node-other"));
}
