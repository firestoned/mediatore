// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! What the broker holds for tripwires (ADR-0069, ADR-0070): the mode, what each class does,
//! the limiter of `POST /v1/me/trip`, and two bounded in-memory tables, the event ids already
//! recorded and the fold of classified refusals. Per replica, like every limiter here.
//!
//! No table grows with what a peer chooses to send: each has a fixed cap and counts what it
//! could not hold.

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use jiff::Timestamp;
use mediatore_proto::trip::{
    ClassAction, DeniedSwitches, TrapCatalogue, TrapsBody, TrapsMode, TrapsPolicy, TripClass,
};
use uuid::Uuid;

use crate::Limiter;

/// Batches a second per claim on `POST /v1/me/trip`, the burst the same: the rate of
/// `POST /v1/me/logs` (ADR-0069 decision 8).
pub const TRIP_BATCHES_PER_SECOND: u32 = 2;
/// Batches a second, the burst the same, that `POST /v1/gateway/decisions` takes from one
/// gateway identity (the review's F1). Every gateway shares the authorizer's identity, so the
/// bucket is the whole fleet's: an honest gateway sends one batch every two seconds (sooner
/// only at 256 decisions waiting), so this is forty gateways at their cadence, or a second of
/// twenty full batches. Past it, `429 too_many_batches` with `Retry-After`, and the batch is
/// neither logged nor judged.
pub const GATEWAY_BATCHES_PER_SECOND: u32 = 20;
/// The most batches of decisions whose denies are being judged against their claims at once
/// (`deny_outside_rendered`, each up to [`crate::classify::MAX_DENY_CLAIMS`] record reads).
/// A batch that finds them all taken is answered as always and its denies are not judged;
/// how many were skipped is said at the next flush of the fold.
pub const MAX_JUDGING_BATCHES: usize = 4;
/// How long after a trip is recorded (`tripped.recorded_at`) the node the claim was bound to
/// may still ship its output on `POST /v1/me/logs` (ADR-0069 decision 7 step 4, amended
/// 2026-11-27): the final line naming the trap and what the workload wrote last reach the
/// owner, though the claim is released by then. Past it, a batch is dropped as for any claim
/// that has ended.
pub const LOGS_AFTER_A_TRIP: Duration = Duration::from_secs(60);
/// How long an event id is remembered, so that a retried report is recorded once.
pub const SEEN_FOR: Duration = Duration::from_secs(600);
/// The most event ids remembered; past it the oldest is forgotten.
pub const SEEN_MAX: usize = 65_536;
/// The most peers the fold of classified refusals holds between two flushes (ADR-0070
/// decision 8); past it a refusal is counted and its peer is not kept.
pub const FOLD_MAX_PEERS: usize = 1024;
/// How often the fold is flushed into audit lines (ADR-0070 decision 8: a count per minute).
pub const FOLD_FLUSH_EVERY: Duration = Duration::from_mins(1);
/// The most bytes of a peer's SPIFFE ID the fold keeps. An ID the handlers recognise is far
/// shorter; one of another shape, refused at the handshake, is cut here.
pub const FOLD_MAX_PEER_BYTES: usize = 255;

/// Everything of ADR-0069 and ADR-0070 a handler needs: [`AppState`](crate::AppState)'s one
/// field for both. The default is the broker with no tripwire configured: `off`, every class
/// at `report`.
pub struct Tripwires {
    /// `policy.traps`. Under `off`, `POST /v1/me/trip` answers `501` and `GET /v1/me` carries
    /// no traps.
    pub mode: TrapsMode,
    /// `policy.traps_denied`: what each `denied` class does, served to the guest.
    pub denied: DeniedSwitches,
    /// The `tripwires` section: what each `protocol` and `segment` class does.
    pub classes: ClassActions,
    /// The deployment's catalogue, served in `GET /v1/me`. `None`: no bundle carries one yet.
    pub catalogue: Option<TrapCatalogue>,
    /// `audiences[].traps_body: skip` (ADR-0069 decision 6, amended): the audiences whose
    /// routes tell the proxy to match bait in the headers, the path and the query only, because
    /// their bodies carry the agent's own conversation. By audience name, for the audiences of
    /// the broker's own file; empty by default, so every route's body is matched.
    pub body_skip: BTreeSet<String>,
    /// [`TRIP_BATCHES_PER_SECOND`] per claim, or per node for a node with no claim.
    pub limiter: Limiter,
    /// [`GATEWAY_BATCHES_PER_SECOND`] per gateway identity, on `POST /v1/gateway/decisions`.
    pub decisions: Limiter,
    /// [`MAX_JUDGING_BATCHES`] permits: one held by each batch whose denies are being judged.
    pub judging: Arc<tokio::sync::Semaphore>,
    /// Batches whose denies were not judged because every permit was held, since the last
    /// flush of the fold.
    pub unjudged: AtomicU64,
    /// The event ids this replica has recorded.
    pub seen: SeenIds,
    /// Classified refusals, folded per class and peer until the next flush. Shared, so the
    /// sandbox listener's handshake authorizer can note on it too (`identity_shape`).
    pub fold: Arc<ClassFold>,
    /// Whether `no_record` is judged at all (ADR-0070 decision 3, amended). `false` when
    /// `store.retention_secs` is not above the claim SVID's lifetime: an honest claim released
    /// a moment ago then has no record while its SVID is still valid, and would read as one.
    pub no_record_judged: bool,
}

impl Default for Tripwires {
    fn default() -> Self {
        Self {
            mode: TrapsMode::Off,
            denied: DeniedSwitches::default(),
            classes: ClassActions::default(),
            catalogue: None,
            body_skip: BTreeSet::new(),
            limiter: Limiter::per_second(TRIP_BATCHES_PER_SECOND),
            decisions: Limiter::per_second(GATEWAY_BATCHES_PER_SECOND),
            judging: Arc::new(tokio::sync::Semaphore::new(MAX_JUDGING_BATCHES)),
            unjudged: AtomicU64::new(0),
            seen: SeenIds::default(),
            fold: Arc::new(ClassFold::default()),
            no_record_judged: true,
        }
    }
}

impl Tripwires {
    /// What `GET /v1/me` says about traps (ADR-0069 decision 5): the mode, the `denied`
    /// switches and the catalogue. `None` under `off`, so a guest of an `off` broker reads
    /// exactly what it read before tripwires existed and arms nothing.
    #[must_use]
    pub fn policy(&self) -> Option<TrapsPolicy> {
        (self.mode != TrapsMode::Off).then(|| TrapsPolicy {
            mode: self.mode,
            denied: self.denied,
            catalogue: self.catalogue.clone(),
        })
    }

    /// Whether the proxy matches bait in the request bodies of `audience`'s routes.
    #[must_use]
    pub fn traps_body(&self, audience: &str) -> TrapsBody {
        if self.body_skip.contains(audience) {
            TrapsBody::Skip
        } else {
            TrapsBody::Match
        }
    }
}

/// What each class does: `report` unless set to `trip`, and never `trip` for a class that may
/// not (ADR-0070 decisions 5 and 6).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClassActions(BTreeMap<TripClass, ClassAction>);

impl ClassActions {
    /// What `class` does; `report` when nothing was set.
    #[must_use]
    pub fn action(&self, class: TripClass) -> ClassAction {
        self.0.get(&class).copied().unwrap_or_default()
    }

    /// Set what `class` does.
    ///
    /// # Errors
    /// `trip` on a class with no scope a trip could act on, on a class of the authorizer's,
    /// and on a `segment` class: the configuration check refuses the same at start, and this
    /// is the second place it cannot get past.
    pub fn set(&mut self, class: TripClass, action: ClassAction) -> Result<(), &'static str> {
        if action == ClassAction::Trip && !class.may_trip() {
            return Err("this class records only: it cannot be set to trip");
        }
        self.0.insert(class, action);
        Ok(())
    }

    /// The classes set to `trip`, for the start log.
    pub fn tripping(&self) -> impl Iterator<Item = TripClass> + '_ {
        self.0
            .iter()
            .filter(|(_, a)| **a == ClassAction::Trip)
            .map(|(c, _)| *c)
    }
}

/// The event ids a replica has recorded, for [`SEEN_FOR`] and at most [`SEEN_MAX`]: the
/// dedupe that makes a retried report idempotent (ADR-0069 decision 8). Per replica: a retry
/// that lands on another replica is recorded there too (decision 9, amended).
#[derive(Debug, Default)]
pub struct SeenIds {
    inner: Mutex<Seen>,
}

#[derive(Debug, Default)]
struct Seen {
    at: HashMap<Uuid, Instant>,
    order: VecDeque<(Instant, Uuid)>,
}

impl SeenIds {
    /// Whether `id` is new, remembering it if so.
    pub fn first_sight(&self, id: Uuid) -> bool {
        self.first_sight_at(id, Instant::now())
    }

    /// [`Self::first_sight`] at `now`.
    fn first_sight_at(&self, id: Uuid, now: Instant) -> bool {
        let mut seen = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        while let Some((when, old)) = seen.order.front().copied() {
            if now.saturating_duration_since(when) < SEEN_FOR && seen.order.len() < SEEN_MAX {
                break;
            }
            seen.order.pop_front();
            // Only the sight this queue entry stands for: the id may have been seen again.
            if seen.at.get(&old) == Some(&when) {
                seen.at.remove(&old);
            }
        }
        if seen.at.contains_key(&id) {
            return false;
        }
        seen.at.insert(id, now);
        seen.order.push_back((now, id));
        true
    }

    /// How many ids are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .at
            .len()
    }

    /// Whether none is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// What the route's own grammar admitted of a classified request (ADR-0070 decision 8): the
/// one value an audit line may carry beside the broker's own facts. Never a path, a query, a
/// header, a body or a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Named {
    /// An audience, checked as a name.
    Audience(String),
    /// A `host[:port]`, checked as an authority.
    Authority(String),
}

/// The broker's own facts of one classified refusal, kept for the audit line of its class and
/// peer: those of the first refusal between two flushes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Detail {
    /// The route's template (`POST /v1/token`), or a constant for no route: never the path.
    pub route: &'static str,
    /// The claim the refusal is about, where it is not the peer itself: the claim a gateway's
    /// reported deny names.
    pub claim_uid: Option<Uuid>,
    /// The audience or authority, within its grammar.
    pub named: Option<Named>,
}

/// What [`ClassFold::note`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sight {
    /// The first refusal of this class and peer since the last flush.
    First,
    /// One more of a class and peer already held.
    Repeat,
    /// The table is full: counted, the peer not kept.
    Overflow,
}

/// One line of a flush: how many times `peer` was refused as `class` since the last one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Folded {
    /// The class.
    pub class: TripClass,
    /// The peer's SPIFFE ID, verified at the handshake.
    pub peer: String,
    /// How many refusals.
    pub count: u64,
    /// The first refusal's facts.
    pub detail: Detail,
    /// When the first was seen, by the broker's clock.
    pub first_at: Timestamp,
    /// When the last was.
    pub last_at: Timestamp,
}

/// What a flush hands back: one line per class and peer, and what did not fit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Flushed {
    /// The lines, by peer and then class.
    pub lines: Vec<Folded>,
    /// Refusals of peers the table had no room for.
    pub overflow: u64,
}

/// Classified refusals between two flushes (ADR-0070 decision 8): one count per class and
/// peer, at most [`FOLD_MAX_PEERS`] peers, the rest counted without their peer. A
/// `std::sync::Mutex`, never held across an await, so the handshake's synchronous authorizer
/// can note on it too.
#[derive(Debug, Default)]
pub struct ClassFold {
    inner: Mutex<Fold>,
}

/// Who a count is kept for: the peer, and the claim a report of the peer's names.
type FoldKey = (String, Option<Uuid>);

#[derive(Debug, Default)]
struct Fold {
    peers: BTreeMap<FoldKey, BTreeMap<TripClass, Tally>>,
    overflow: u64,
}

#[derive(Debug)]
struct Tally {
    count: u64,
    detail: Detail,
    first_at: Timestamp,
    last_at: Timestamp,
}

/// `peer`, cut to [`FOLD_MAX_PEER_BYTES`] on a character boundary.
fn bounded(peer: &str) -> &str {
    let mut end = peer.len().min(FOLD_MAX_PEER_BYTES);
    while !peer.is_char_boundary(end) {
        end -= 1;
    }
    &peer[..end]
}

impl ClassFold {
    /// Count one refusal of `peer` as `class`, keeping `detail` if it is the first.
    pub fn note(&self, class: TripClass, peer: &str, detail: Detail) -> Sight {
        self.note_at(class, peer, detail, Timestamp::now())
    }

    /// [`Self::note`] at `now`.
    fn note_at(&self, class: TripClass, peer: &str, detail: Detail, now: Timestamp) -> Sight {
        let key = (bounded(peer).to_owned(), detail.claim_uid);
        let mut fold = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        if !fold.peers.contains_key(&key) && fold.peers.len() >= FOLD_MAX_PEERS {
            fold.overflow = fold.overflow.saturating_add(1);
            return Sight::Overflow;
        }
        match fold.peers.entry(key).or_default().entry(class) {
            std::collections::btree_map::Entry::Occupied(mut held) => {
                let tally = held.get_mut();
                tally.count = tally.count.saturating_add(1);
                tally.last_at = now;
                Sight::Repeat
            }
            std::collections::btree_map::Entry::Vacant(free) => {
                free.insert(Tally {
                    count: 1,
                    detail,
                    first_at: now,
                    last_at: now,
                });
                Sight::First
            }
        }
    }

    /// Take everything counted since the last flush, leaving the table empty.
    pub fn flush(&self) -> Flushed {
        let taken = std::mem::take(&mut *self.inner.lock().unwrap_or_else(PoisonError::into_inner));
        Flushed {
            lines: taken
                .peers
                .into_iter()
                .flat_map(|((peer, _), classes)| {
                    classes.into_iter().map(move |(class, tally)| Folded {
                        class,
                        peer: peer.clone(),
                        count: tally.count,
                        detail: tally.detail,
                        first_at: tally.first_at,
                        last_at: tally.last_at,
                    })
                })
                .collect(),
            overflow: taken.overflow,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_off_with_every_class_at_report() {
        let t = Tripwires::default();
        assert_eq!(t.mode, TrapsMode::Off);
        assert_eq!(t.denied, DeniedSwitches::default());
        assert_eq!(t.catalogue, None);
        for class in TripClass::DENIED
            .into_iter()
            .chain(TripClass::PROTOCOL)
            .chain(TripClass::SEGMENT)
        {
            assert_eq!(t.classes.action(class), ClassAction::Report, "{class:?}");
        }
        assert!(t.seen.is_empty());
        assert_eq!(t.fold.flush(), Flushed::default());
    }

    #[test]
    fn a_class_that_may_not_trip_cannot_be_set_to_trip() {
        let mut actions = ClassActions::default();
        for class in TripClass::PROTOCOL.into_iter().chain(TripClass::SEGMENT) {
            assert_eq!(
                actions.set(class, ClassAction::Trip).is_ok(),
                class.may_trip(),
                "{class:?}"
            );
            assert_eq!(actions.set(class, ClassAction::Report), Ok(()));
        }
        actions
            .set(TripClass::ForeignRoute, ClassAction::Trip)
            .unwrap();
        assert_eq!(actions.action(TripClass::ForeignRoute), ClassAction::Trip);
        assert_eq!(actions.action(TripClass::NoRecord), ClassAction::Report);
        assert_eq!(
            actions.tripping().collect::<Vec<_>>(),
            [TripClass::ForeignRoute]
        );
    }

    #[test]
    fn an_id_is_new_once_then_again_after_its_window_and_the_table_is_bounded() {
        let seen = SeenIds::default();
        let t0 = Instant::now();
        let id = Uuid::from_u128(1);
        assert!(seen.first_sight_at(id, t0));
        assert!(!seen.first_sight_at(id, t0 + Duration::from_secs(1)));
        assert!(!seen.first_sight_at(id, t0 + Duration::from_secs(SEEN_FOR.as_secs() - 1)));
        assert!(seen.first_sight_at(id, t0 + SEEN_FOR));
        assert_eq!(seen.len(), 1);
        // Past the cap the oldest goes, and the table never holds more than the cap.
        let seen = SeenIds::default();
        for n in 0..=(SEEN_MAX as u128) {
            assert!(seen.first_sight_at(Uuid::from_u128(n), t0));
        }
        assert_eq!(seen.len(), SEEN_MAX);
        assert!(
            seen.first_sight_at(Uuid::from_u128(0), t0),
            "the oldest was forgotten"
        );
        assert!(!seen.first_sight_at(Uuid::from_u128(SEEN_MAX as u128), t0));
    }

    #[test]
    fn repeats_fold_into_one_count_and_peers_past_the_bound_are_counted_without_a_name() {
        let fold = ClassFold::default();
        let a = "spiffe://sandbox.test/banlieue/claim/a";
        let t0: Timestamp = "2026-11-27T10:00:00Z".parse().unwrap();
        let t1: Timestamp = "2026-11-27T10:00:20Z".parse().unwrap();
        let first = Detail {
            route: "GET /v1/me",
            claim_uid: None,
            named: Some(Named::Audience("first".into())),
        };
        let later = Detail {
            route: "POST /v1/me/exit",
            claim_uid: None,
            named: Some(Named::Audience("later".into())),
        };
        assert_eq!(
            fold.note_at(TripClass::ForeignRoute, a, first.clone(), t0),
            Sight::First
        );
        assert_eq!(
            fold.note_at(TripClass::ForeignRoute, a, later.clone(), t1),
            Sight::Repeat
        );
        assert_eq!(
            fold.note_at(TripClass::UnknownRoute, a, later.clone(), t1),
            Sight::First,
            "another class of the same peer is its own line"
        );
        let flushed = fold.flush();
        assert_eq!(
            flushed.lines,
            vec![
                Folded {
                    class: TripClass::ForeignRoute,
                    peer: a.into(),
                    count: 2,
                    detail: first,
                    first_at: t0,
                    last_at: t1,
                },
                Folded {
                    class: TripClass::UnknownRoute,
                    peer: a.into(),
                    count: 1,
                    detail: later,
                    first_at: t1,
                    last_at: t1,
                },
            ],
            "the first refusal's facts are the line's, whatever came after"
        );
        assert_eq!(flushed.overflow, 0);
        assert_eq!(
            fold.flush(),
            Flushed::default(),
            "a flush empties the table"
        );
        for n in 0..FOLD_MAX_PEERS + 3 {
            let sight = fold.note(
                TripClass::NoRecord,
                &format!("spiffe://sandbox.test/x/{n}"),
                Detail::default(),
            );
            assert_eq!(sight == Sight::Overflow, n >= FOLD_MAX_PEERS);
        }
        // A peer already held is still counted once the table is full.
        assert_eq!(
            fold.note(
                TripClass::NoRecord,
                "spiffe://sandbox.test/x/0",
                Detail::default()
            ),
            Sight::Repeat
        );
        let flushed = fold.flush();
        assert_eq!(flushed.lines.len(), FOLD_MAX_PEERS);
        assert_eq!(flushed.overflow, 3);
        assert_eq!(
            flushed.lines.iter().map(|l| l.count).sum::<u64>(),
            FOLD_MAX_PEERS as u64 + 1
        );
    }

    #[test]
    fn a_claim_a_report_names_is_its_own_line_and_a_long_peer_is_cut() {
        // The authorizer reports for many claims under one identity: one line a claim, and
        // each claim takes a place in the same bounded table.
        let fold = ClassFold::default();
        let authorizer = "spiffe://sandbox.test/gateway/authorizer";
        let (a, b) = (Uuid::from_u128(1), Uuid::from_u128(2));
        for uid in [a, b, a] {
            fold.note(
                TripClass::DenyOutsideRendered,
                authorizer,
                Detail {
                    route: "POST /v1/gateway/decisions",
                    claim_uid: Some(uid),
                    named: None,
                },
            );
        }
        let flushed = fold.flush();
        let counts: Vec<(Option<Uuid>, u64)> = flushed
            .lines
            .iter()
            .map(|l| (l.detail.claim_uid, l.count))
            .collect();
        assert_eq!(counts, [(Some(a), 2), (Some(b), 1)]);
        // An identity of no admitted shape can be as long as a certificate lets it be.
        let long = format!("spiffe://sandbox.test/{}", "é".repeat(400));
        fold.note(TripClass::IdentityShape, &long, Detail::default());
        fold.note(TripClass::IdentityShape, &long, Detail::default());
        let flushed = fold.flush();
        assert_eq!(flushed.lines.len(), 1);
        assert_eq!(flushed.lines[0].count, 2);
        assert!(flushed.lines[0].peer.len() <= FOLD_MAX_PEER_BYTES);
        assert!(long.starts_with(&flushed.lines[0].peer));
    }
}
