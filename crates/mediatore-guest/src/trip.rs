// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! What a trip does on the VM (ADR-0069 decision 7): the network cut, the signal that kills
//! the jail, the report to the broker, and the local socket the egress proxy tells the guest
//! on.
//!
//! Every decider (a decoy listener, the reader of what the chain dropped, the proxy through
//! the socket) notes a [`Cause`] on the claim's [`Trips`]. One task decides each in turn:
//!
//! - Under `enforce`, the first cause that trips is **contained before anything else**: the
//!   sandbox uid's table is replaced by a drop of everything in one `nft -f` transaction
//!   ([`drop_all_ruleset`]), the time from the verdict to the end of that is measured, and
//!   only then is [`Tripwire::tripped`] set, which the supervision kills the jail on. If
//!   `nft` fails or does not answer within its bound the kill still happens, and the report
//!   carries no `containment_ms`: a figure is never invented.
//! - Under `shadow` nothing is cut and nothing is killed. A `denied` class at `report` cuts
//!   nothing under `enforce` either (decision 10).
//!
//! A second task reports, and containment never waits on it. Repeats of one kind, trap,
//! class and target fold into a count; at most [`MAX_TRIP_EVENTS`] distinct events leave in
//! one window of a minute and the rest ride the next; the event that ended the run goes at
//! once, outside that budget. A batch keeps its event ids across its retries, so the broker
//! records it once. It is retried with a capped backoff until the broker answers `204` or
//! refuses it for good.
//!
//! Nothing here logs or reports a bait value, a path, a query, a header or a body: an event
//! carries a kind, a trap's or a class's name and a target in the grammar of
//! `mediatore_proto::trip`, and the guest's own log lines carry the kind and the name alone
//! (decision 12).

use std::os::unix::fs::{
    DirBuilderExt as _, FileTypeExt as _, MetadataExt as _, PermissionsExt as _,
};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use jiff::Timestamp;
use mediatore_proto::trip::{
    ClassAction, DeniedSwitches, GuestToProxy, MAX_CONTAINMENT_MS, MAX_TRIP_COUNT, MAX_TRIP_EVENTS,
    ProxyToGuest, ProxyTraps, ProxyTrip, TRAP_FRAME_MAX, TRAP_SOCKET_NAME, TripClass, TripEffect,
    TripEvent, TripKind, TripMode, TripReport, TripSource, TripTarget,
};
use tokio::io::{AsyncBufRead, AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use tokio::time::Instant;
use uuid::Uuid;

use crate::client::SandboxClient;
use crate::net::{Denied, NftRunner, SystemNft, TABLE};

/// The mode of the trap socket's directory: root's, and searchable by the proxy, which is
/// the sandbox uid outside the jail.
pub const SOCKET_DIR_MODE: u32 = 0o711;
/// The mode of the socket itself: the peer is admitted by its credential, not by the mode.
pub const SOCKET_MODE: u32 = 0o666;
/// How long the final line naming the trap may take to reach the broker with the workload's
/// output (ADR-0069 decision 7 step 4).
pub const FINAL_FLUSH: Duration = Duration::from_secs(2);
/// How often the guest reads what the sandbox uid's chain dropped (decision 10).
pub const DENIED_EVERY: Duration = Duration::from_millis(250);
/// How long, once the jail is gone, a use on its way may take to be noted before the guest
/// decides the run was not tripped: two reads of the chain's drops and a margin. Only under
/// `enforce`.
pub const SETTLE: Duration = Duration::from_millis(600);
/// How long the guest waits for the broker to acknowledge the report of a trip before it
/// tears down: the cut, the kill and the kept user and table do not wait on it, and past this
/// the guest ends with the report unacknowledged (logged).
pub const REPORT_WAIT: Duration = Duration::from_secs(120);
/// The most distinct events held for a later report. A use beyond it is counted and logged,
/// never held: the workload chooses a `denied` target and must not grow the guest.
pub const MAX_PENDING: usize = 256;
/// How many noted causes may wait for the decider.
const NOTE_QUEUE: usize = 1024;
/// What stands in a report for a host or a trap name outside the grammar the broker admits
/// (RFC 2606's reserved name): the event is still reported, and nothing the peer chose is.
const OUTSIDE_THE_GRAMMAR: &str = "invalid";

/// The `nft -f` script that cuts the sandbox uid off: the claim's table replaced, in one
/// transaction, by a drop of everything that uid sends. No `ct state established` accept: an
/// open flow is cut with the rest. The guest's own path to the broker is root's and is not
/// touched.
#[must_use]
pub fn drop_all_ruleset(uid: u32) -> String {
    format!(
        "# mediatore guest (ADR-0069 decision 7): uid {uid} tripped; nothing it sends leaves\n\
         table inet {TABLE}\n\
         delete table inet {TABLE}\n\
         table inet {TABLE} {{\n\
         \x20 chain output {{\n\
         \x20   type filter hook output priority filter; policy accept;\n\
         \x20   meta skuid {uid} counter drop\n\
         \x20 }}\n\
         }}\n"
    )
}

/// One use of a trap, as the listener, the chain's reader or the proxy saw it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cause {
    /// The verdict's time: containment is measured from it.
    pub at: Timestamp,
    /// What kind of trap.
    pub kind: TripKind,
    /// The trap's name, on `port`, `route` and `credential`.
    pub trap: Option<String>,
    /// The class, on `denied`.
    pub class: Option<TripClass>,
    /// What was reached for.
    pub target: Option<TripTarget>,
    /// Whose value the target is.
    pub source: TripSource,
}

/// What repeats of one use fold on (ADR-0069 decision 8, amended).
type Key = (
    TripKind,
    Option<String>,
    Option<TripClass>,
    Option<TripTarget>,
    TripSource,
);

impl Cause {
    /// The last line of the workload's output, for its owner (ADR-0069 decision 7 step 4):
    /// the kind and the trap's or the class's name. Never the target, which the workload may
    /// have chosen, and never a value.
    #[must_use]
    pub fn final_line(&self) -> String {
        let kind = self.kind.as_str();
        match (&self.trap, self.class) {
            (Some(trap), _) => {
                format!(
                    "mediatore: this sandbox was ended by a tripwire (kind {kind}, trap {trap})"
                )
            }
            (None, Some(class)) => format!(
                "mediatore: this sandbox was ended by a tripwire (kind {kind}, class {})",
                class.as_str()
            ),
            (None, None) => {
                format!("mediatore: this sandbox was ended by a tripwire (kind {kind})")
            }
        }
    }

    /// Whether this is the proxy's refusal of a request body its matcher could not finish
    /// scanning: a compressed body past the expansion bound, or one that does not decode as
    /// its encoding ([`crate::trapmatch::TRAP_EXPANSION`],
    /// [`crate::trapmatch::TRAP_UNDECODABLE`]). The proxy forwarded nothing more of it. It is
    /// no use of a trap: an honest large upload or a buggy client does the same, so it ends
    /// nothing under any mode.
    fn is_refused_body(&self) -> bool {
        self.kind == TripKind::Credential
            && matches!(
                self.trap.as_deref(),
                Some(crate::trapmatch::TRAP_EXPANSION | crate::trapmatch::TRAP_UNDECODABLE)
            )
    }

    fn key(&self) -> Key {
        (
            self.kind,
            self.trap.clone(),
            self.class,
            self.target.clone(),
            self.source,
        )
    }

    fn event(&self, id: Uuid, count: u64, containment_ms: Option<u32>) -> TripEvent {
        TripEvent {
            id,
            at: self.at,
            kind: self.kind,
            trap: self.trap.clone(),
            class: self.class,
            target: self.target.clone(),
            source: self.source,
            containment_ms,
            count,
            source_address: None,
        }
    }

    /// Whether the broker would take an event of this cause, and the fault if not: a
    /// `&'static str` with nothing of the cause in it.
    fn reportable(&self, mode: TripMode) -> Result<(), &'static str> {
        TripReport {
            mode,
            events: vec![self.event(Uuid::nil(), 1, None)],
        }
        .validate()
    }
}

/// The bounds of one tripwire's cut and reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    /// How long `nft` may take to cut. Past it the kill goes ahead with no figure.
    pub cut: Duration,
    /// How long a new event waits for its repeats before it is sent.
    pub fold: Duration,
    /// The window [`MAX_TRIP_EVENTS`] distinct events may leave in.
    pub window: Duration,
    /// How long one post may take.
    pub post: Duration,
    /// The first wait between two attempts; it doubles.
    pub backoff_min: Duration,
    /// The longest wait between two attempts, a broker's `Retry-After` included.
    pub backoff_max: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            cut: Duration::from_secs(5),
            fold: Duration::from_secs(1),
            window: Duration::from_secs(60),
            post: Duration::from_secs(15),
            backoff_min: Duration::from_millis(250),
            backoff_max: Duration::from_secs(30),
        }
    }
}

/// One folded event waiting for a report.
#[derive(Debug)]
struct Pending {
    cause: Cause,
    seen: Instant,
    count: u64,
    containment_ms: Option<u32>,
    /// The event that ended the run: sent at once, never merged with a repeat.
    ended: bool,
}

#[derive(Debug, Default)]
struct Fold {
    entries: Vec<Pending>,
    /// Everything pending goes now, with no delay and outside the budget: the event that
    /// ended the run is waiting, or [`Trips::flush`] asked.
    now: bool,
    /// A batch is at the broker, or on its way.
    in_flight: bool,
    /// The deciders are gone: the reporter sends what is left and ends.
    closed: bool,
    /// Uses not held because [`MAX_PENDING`] distinct events were.
    overflow: u64,
}

impl Fold {
    fn push(&mut self, cause: Cause, count: u64, containment_ms: Option<u32>, ended: bool) {
        if ended {
            self.now = true;
            self.entries.insert(
                0,
                Pending {
                    cause,
                    seen: Instant::now(),
                    count,
                    containment_ms,
                    ended,
                },
            );
            return;
        }
        let key = cause.key();
        if let Some(held) = self
            .entries
            .iter_mut()
            .find(|p| !p.ended && p.cause.key() == key)
        {
            held.count = held.count.saturating_add(count).min(MAX_TRIP_COUNT);
            return;
        }
        if self.entries.len() >= MAX_PENDING {
            self.overflow = self.overflow.saturating_add(count);
            return;
        }
        self.entries.push(Pending {
            cause,
            seen: Instant::now(),
            count: count.clamp(1, MAX_TRIP_COUNT),
            containment_ms,
            ended,
        });
    }
}

/// What the reporter does next.
enum Step {
    /// Nothing to send: until woken, or for this long.
    Wait(Option<Duration>),
    /// This batch, and whether it holds the event that ended the run.
    Send(Vec<TripEvent>, bool),
    /// The deciders are gone and nothing is left.
    End,
}

struct Shared {
    mode: TripMode,
    denied: DeniedSwitches,
    /// True from the instant a use that ends the run was noted (before the cut, before the
    /// signal): the one cause that takes this goes to the decider on a slot of its own, and
    /// the proxy is told at once to forward nothing more.
    ending: tokio::sync::watch::Sender<bool>,
    /// How long the cut may take ([`Timing::cut`]): what a settling waits for the signal.
    cut: Duration,
    tripped: tokio::sync::watch::Sender<Option<Cause>>,
    /// True once the report of the event that ended the run was acknowledged or refused.
    reported: tokio::sync::watch::Sender<bool>,
    fold: Mutex<Fold>,
    wake: tokio::sync::Notify,
    /// Causes that found the decider's queue full.
    dropped: AtomicU64,
    /// Causes the queue took, and causes the decider is done with: equal when none waits.
    noted: AtomicU64,
    decided: AtomicU64,
    /// Request bodies the proxy refused unscanned ([`Cause::is_refused_body`]).
    refused_bodies: AtomicU64,
}

impl Shared {
    fn fold(&self) -> std::sync::MutexGuard<'_, Fold> {
        // A panic while the lock was held leaves the fold as it was: still the truth.
        self.fold
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// What a use does under this tripwire's mode and switches.
    fn effect_of(&self, cause: &Cause) -> TripEffect {
        let enforcing = self.mode == TripMode::Enforce;
        match cause.kind {
            // Never a trip, under any mode: the proxy refused the request and nothing of the
            // body it could not scan left.
            TripKind::Credential if cause.is_refused_body() => TripEffect::Reported,
            TripKind::Port | TripKind::Route | TripKind::Credential if enforcing => {
                TripEffect::Tripped
            }
            TripKind::Port | TripKind::Route | TripKind::Credential => TripEffect::WouldTrip,
            TripKind::Denied => {
                let action = cause
                    .class
                    .map_or(ClassAction::Report, |c| self.denied.action(c));
                match (action, enforcing) {
                    (ClassAction::Report, _) => TripEffect::Reported,
                    (ClassAction::Trip, true) => TripEffect::Tripped,
                    (ClassAction::Trip, false) => TripEffect::WouldTrip,
                }
            }
            // The broker's and the host table's: never decided on a claim's tripwire.
            TripKind::Protocol | TripKind::Segment => TripEffect::Reported,
        }
    }

    fn signal(&self, cause: &Cause) {
        self.tripped.send_if_modified(|held| {
            if held.is_some() {
                return false;
            }
            *held = Some(cause.clone());
            true
        });
    }

    fn is_tripped(&self) -> bool {
        self.tripped.borrow().is_some()
    }

    /// Take the end of the run for one cause: true for the first caller only.
    fn take_the_end(&self) -> bool {
        self.ending.send_if_modified(|ending| {
            if *ending {
                return false;
            }
            *ending = true;
            true
        })
    }

    fn is_ending(&self) -> bool {
        *self.ending.borrow()
    }

    fn new(mode: TripMode, denied: DeniedSwitches, cut: Duration) -> Self {
        Self {
            mode,
            denied,
            ending: tokio::sync::watch::channel(false).0,
            cut,
            tripped: tokio::sync::watch::channel(None).0,
            reported: tokio::sync::watch::channel(false).0,
            fold: Mutex::new(Fold::default()),
            wake: tokio::sync::Notify::new(),
            dropped: AtomicU64::new(0),
            noted: AtomicU64::new(0),
            decided: AtomicU64::new(0),
            refused_bodies: AtomicU64::new(0),
        }
    }

    /// The reporter's next step at `now`, given the window it is in.
    fn next(&self, window: &mut (Instant, usize), timing: &Timing, now: Instant) -> Step {
        let mut fold = self.fold();
        if now.duration_since(window.0) >= timing.window {
            *window = (now, 0);
        }
        if fold.entries.is_empty() {
            fold.now = false;
            return if fold.closed {
                Step::End
            } else {
                Step::Wait(None)
            };
        }
        let take = if fold.now || fold.closed {
            fold.entries.len().min(MAX_TRIP_EVENTS)
        } else {
            let budget = MAX_TRIP_EVENTS.saturating_sub(window.1);
            if budget == 0 {
                return Step::Wait(Some(
                    timing.window.saturating_sub(now.duration_since(window.0)),
                ));
            }
            let age = fold
                .entries
                .iter()
                .map(|p| now.duration_since(p.seen))
                .max()
                .unwrap_or_default();
            if age < timing.fold {
                return Step::Wait(Some(timing.fold.saturating_sub(age)));
            }
            fold.entries.len().min(budget)
        };
        fold.in_flight = true;
        window.1 += take;
        let batch: Vec<Pending> = fold.entries.drain(..take).collect();
        if fold.entries.is_empty() {
            fold.now = false;
        }
        let ended = batch.iter().any(|p| p.ended);
        let events = batch
            .iter()
            .map(|p| p.cause.event(Uuid::new_v4(), p.count, p.containment_ms))
            .collect();
        Step::Send(events, ended)
    }
}

/// The handle every decider notes a use on.
#[derive(Clone)]
pub struct Trips {
    tx: tokio::sync::mpsc::Sender<(Cause, u64)>,
    /// The slot of the one cause that ends the run: never shared with the queue, so no
    /// number of `denied` notes can crowd it out.
    first: tokio::sync::mpsc::Sender<(Cause, u64)>,
    shared: Arc<Shared>,
}

impl std::fmt::Debug for Trips {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Trips")
            .field("mode", &self.shared.mode)
            .finish_non_exhaustive()
    }
}

impl Trips {
    /// Note one use. It decides `would_trip`, `reported` or a trip, and under `enforce` cuts
    /// the network first and signals the supervision after. It never blocks and never
    /// fails: the cut, the signal and the report happen on the tripwire's own tasks.
    pub fn note(&self, cause: Cause) {
        self.note_many(cause, 1);
    }

    /// Note `count` uses of one trap at once (what a read of the chain's set folds).
    pub fn note_many(&self, cause: Cause, count: u64) {
        let trips = self.shared.effect_of(&cause) == TripEffect::Tripped;
        // Counted before it is queued, so the decider's count never runs ahead.
        self.shared.noted.fetch_add(1, Ordering::SeqCst);
        // The first use that ends the run takes the slot of its own: the queue may be full of
        // `denied` notes, and the trip must still be cut and reported as the ending event.
        if trips && self.shared.take_the_end() {
            if self.first.try_send((cause.clone(), count.max(1))).is_err() {
                // The decider is gone: fail closed, the jail is killed without the cut.
                self.shared.decided.fetch_add(1, Ordering::SeqCst);
                tracing::error!(
                    kind = cause.kind.as_str(),
                    "a trap was used and the tripwire's decider is gone: the supervision is signalled without the cut"
                );
                self.shared.signal(&cause);
            }
            return;
        }
        if let Err(refused) = self.tx.try_send((cause, count.max(1))) {
            self.shared.decided.fetch_add(1, Ordering::SeqCst);
            let (gone, (cause, _)) = match refused {
                tokio::sync::mpsc::error::TrySendError::Full(c) => (false, c),
                tokio::sync::mpsc::error::TrySendError::Closed(c) => (true, c),
            };
            let dropped = self.shared.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            if trips && gone {
                // Fail closed: no decider, so no cut; the supervision is signalled.
                self.shared.signal(&cause);
            }
            if trips && dropped.is_power_of_two() {
                // A use after the one that ended the run, which had its own slot: a count
                // lost, never the end lost.
                tracing::warn!(
                    kind = cause.kind.as_str(),
                    dropped,
                    "a trap was used again after the trip and the tripwire's queue did not take it: the use is not reported"
                );
            } else if dropped.is_power_of_two() {
                tracing::warn!(
                    kind = cause.kind.as_str(),
                    dropped,
                    "the tripwire's queue is full: uses are not recorded"
                );
            }
        }
    }

    /// The mode this tripwire runs under.
    #[must_use]
    pub fn mode(&self) -> TripMode {
        self.shared.mode
    }

    /// Whether a trip has ended the run.
    #[must_use]
    pub fn is_tripped(&self) -> bool {
        self.shared.is_tripped()
    }

    /// Wait until the report of the event that ended the run was acknowledged by the broker
    /// (or refused for good, or could not be reported at all). It waits as long as the
    /// broker is unreachable: decision 7 retries until `204` or the VM is gone. It never
    /// returns on a run no trip ended.
    pub async fn reported(&self) {
        let mut done = self.shared.reported.subscribe();
        if done.wait_for(|reported| *reported).await.is_err() {
            std::future::pending::<()>().await;
        }
    }

    /// [`Self::reported`], bounded: whether the report was acknowledged within `within`.
    pub async fn reported_within(&self, within: Duration) -> bool {
        tokio::time::timeout(within, self.reported()).await.is_ok()
    }

    /// After the run's jail is gone, for whatever reason: the cause of a trip that ended it,
    /// or `None`. A use the deciders noted up to `window` after the call (a decoy's accept, the
    /// proxy's message, the next read of the chain's drops) is waited for, and so is a cut
    /// still in `nft` (bounded by the cut's own bound and a second): the run a trip raced is
    /// the tripped run (the maintainer's decision 12 of 2026-11-27). Under `shadow` nothing
    /// ends a run and this returns at once.
    pub async fn settle(&self, window: Duration) -> Option<Cause> {
        if self.shared.mode != TripMode::Enforce {
            return None;
        }
        let until = Instant::now() + window;
        // Uses still in the queue are waited for past the window, never past this.
        let at_most = until + self.shared.cut;
        loop {
            if self.shared.is_ending() {
                let mut signal = self.shared.tripped.subscribe();
                let within = self.shared.cut + Duration::from_secs(1);
                let _ = tokio::time::timeout(within, signal.wait_for(Option::is_some)).await;
                return self.shared.tripped.borrow().clone();
            }
            let waiting = self.shared.decided.load(Ordering::SeqCst)
                < self.shared.noted.load(Ordering::SeqCst);
            let now = Instant::now();
            if (now >= until && !waiting) || now >= at_most {
                return self.shared.tripped.borrow().clone();
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    /// Send everything pending now, ahead of the fold's delay and the window's budget, and
    /// wait at most `within` for the broker to have it: what a claim that ends under
    /// `shadow` calls before it tears down. Whether nothing was left unsent.
    pub async fn flush(&self, within: Duration) -> bool {
        let settled = async {
            loop {
                {
                    // What was noted before this call is decided first: a use still in the
                    // queue is not yet in the fold.
                    let waiting = self.shared.decided.load(Ordering::SeqCst)
                        < self.shared.noted.load(Ordering::SeqCst);
                    let mut fold = self.shared.fold();
                    if !waiting && fold.entries.is_empty() && !fold.in_flight {
                        return;
                    }
                    fold.now = true;
                }
                self.shared.wake.notify_one();
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        };
        tokio::time::timeout(within, settled).await.is_ok()
    }

    /// A handle that decides nothing: what was noted comes out of the receiver.
    #[cfg(test)]
    pub(crate) fn recording(mode: TripMode) -> (Self, tokio::sync::mpsc::Receiver<(Cause, u64)>) {
        let (tx, rx) = tokio::sync::mpsc::channel(NOTE_QUEUE);
        let shared = Arc::new(Shared::new(
            mode,
            DeniedSwitches::default(),
            Timing::default().cut,
        ));
        // One receiver for both: the cause that ends the run comes out of it too.
        (
            Self {
                first: tx.clone(),
                tx,
                shared,
            },
            rx,
        )
    }
}

/// A claim's armed tripwire: the handle the deciders note on, and what the supervision
/// watches for the first cause that ends the run.
#[derive(Debug)]
pub struct Tripwire {
    /// The handle, cloned to every decider.
    pub trips: Trips,
    /// `Some` from the first trip on: the signal to kill the jail.
    pub tripped: tokio::sync::watch::Receiver<Option<Cause>>,
}

/// Arm the tripwire for the sandbox `uid` under `mode`, with the `denied` switches the broker
/// served, reporting through `sink`. The cut runs the VM's `nft`. Must be called on the
/// runtime: it starts the tripwire's two tasks, which end when every [`Trips`] is dropped.
#[must_use]
pub fn start(
    mode: TripMode,
    denied: DeniedSwitches,
    uid: u32,
    sink: Arc<dyn TripSink>,
) -> Tripwire {
    start_with(
        mode,
        denied,
        uid,
        sink,
        Arc::new(SystemNft),
        Timing::default(),
    )
}

/// [`start`] with the `nft` to cut through and the bounds to keep.
#[must_use]
pub fn start_with(
    mode: TripMode,
    denied: DeniedSwitches,
    uid: u32,
    sink: Arc<dyn TripSink>,
    nft: Arc<dyn NftRunner>,
    timing: Timing,
) -> Tripwire {
    let (tx, rx) = tokio::sync::mpsc::channel(NOTE_QUEUE);
    let (first, first_rx) = tokio::sync::mpsc::channel(1);
    let shared = Arc::new(Shared::new(mode, denied, timing.cut));
    let tripped = shared.tripped.subscribe();
    tokio::spawn(decide(shared.clone(), nft, uid, timing, first_rx, rx));
    tokio::spawn(report(shared.clone(), sink, timing));
    Tripwire {
        trips: Trips { tx, first, shared },
        tripped,
    }
}

/// Cut the sandbox uid off; the milliseconds from the verdict to the end of the cut, or
/// `None` when `nft` failed or did not answer in time (the kill goes ahead either way).
async fn cut(nft: &dyn NftRunner, script: &str, cause: &Cause, within: Duration) -> Option<u32> {
    match tokio::time::timeout(within, nft.run(&["-f", "-"], Some(script))).await {
        Ok(Ok(out)) if out.success => {
            let elapsed = Timestamp::now().duration_since(cause.at).as_millis();
            let ms = u32::try_from(elapsed.max(0)).unwrap_or(MAX_CONTAINMENT_MS);
            Some(ms.min(MAX_CONTAINMENT_MS))
        }
        Ok(Ok(out)) => {
            tracing::error!(error = %out.stderr, "nft refused the cut: the sandbox uid's network is NOT cut; the jail is killed all the same");
            None
        }
        Ok(Err(e)) => {
            tracing::error!(error = %e, "nft could not be run for the cut: the sandbox uid's network is NOT cut; the jail is killed all the same");
            None
        }
        Err(_) => {
            tracing::error!(
                within_ms = u64::try_from(within.as_millis()).unwrap_or(u64::MAX),
                "nft did not answer for the cut: the sandbox uid's network may not be cut; the jail is killed all the same"
            );
            None
        }
    }
}

/// The deciding task: each noted cause in turn. Containment happens here and waits on
/// nothing but `nft`.
async fn decide(
    shared: Arc<Shared>,
    nft: Arc<dyn NftRunner>,
    uid: u32,
    timing: Timing,
    mut first: tokio::sync::mpsc::Receiver<(Cause, u64)>,
    mut rx: tokio::sync::mpsc::Receiver<(Cause, u64)>,
) {
    let script = drop_all_ruleset(uid);
    loop {
        // The cause that ends the run first, whatever waits in the queue.
        let (cause, count, ends) = tokio::select! {
            biased;
            Some((cause, count)) = first.recv() => (cause, count, true),
            Some((cause, count)) = rx.recv() => (cause, count, false),
            else => break,
        };
        if cause.is_refused_body() {
            // Kept on the VM: a report has no shape for "refused, ends nothing" on a
            // `credential` event (the broker would record `would_trip` under `shadow` and end
            // the claim under `enforce`), so the guest's log line is the record of it.
            let refused = shared.refused_bodies.fetch_add(count, Ordering::Relaxed) + count;
            if refused == count || refused.is_power_of_two() {
                tracing::warn!(
                    trap = cause.trap.as_deref(),
                    mode = shared.mode.as_str(),
                    refused,
                    "the proxy could not finish scanning a request body: under enforce it refused the request, nothing unscanned left; nothing is ended and nothing is reported to the broker"
                );
            }
            shared.decided.fetch_add(1, Ordering::SeqCst);
            continue;
        }
        let effect = shared.effect_of(&cause);
        let containment_ms = if ends {
            let ms = cut(nft.as_ref(), &script, &cause, timing.cut).await;
            shared.signal(&cause);
            tracing::error!(
                kind = cause.kind.as_str(),
                trap = cause.trap.as_deref(),
                class = cause.class.map(TripClass::as_str),
                containment_ms = ms,
                cut = ms.is_some(),
                "a trap was used: the sandbox uid's network is cut and the jail is killed (ADR-0069 decision 7)"
            );
            ms
        } else {
            None
        };
        if let Err(fault) = cause.reportable(shared.mode) {
            tracing::error!(
                kind = cause.kind.as_str(),
                fault,
                "a use the broker would not take is not reported"
            );
            if ends {
                shared.reported.send_replace(true);
            }
            shared.decided.fetch_add(1, Ordering::SeqCst);
            continue;
        }
        let new = {
            let mut fold = shared.fold();
            let before = fold.entries.len();
            fold.push(cause.clone(), count, containment_ms, ends);
            fold.entries.len() > before
        };
        if new && !ends {
            tracing::warn!(
                kind = cause.kind.as_str(),
                trap = cause.trap.as_deref(),
                class = cause.class.map(TripClass::as_str),
                mode = shared.mode.as_str(),
                effect = effect.as_str(),
                "a trap was used; nothing is ended"
            );
        }
        shared.decided.fetch_add(1, Ordering::SeqCst);
        shared.wake.notify_one();
    }
    shared.fold().closed = true;
    shared.wake.notify_one();
}

/// The reporting task: batches of the fold, each sent until the broker has it.
async fn report(shared: Arc<Shared>, sink: Arc<dyn TripSink>, timing: Timing) {
    let mut window = (Instant::now(), 0_usize);
    loop {
        match shared.next(&mut window, &timing, Instant::now()) {
            Step::End => return,
            Step::Wait(None) => shared.wake.notified().await,
            Step::Wait(Some(wait)) => {
                tokio::select! {
                    () = shared.wake.notified() => {}
                    () = tokio::time::sleep(wait) => {}
                }
            }
            Step::Send(events, ended) => {
                let report = TripReport {
                    mode: shared.mode,
                    events,
                };
                report_with(sink.as_ref(), &report, &timing, None).await;
                let overflow = {
                    let mut fold = shared.fold();
                    fold.in_flight = false;
                    std::mem::take(&mut fold.overflow)
                };
                if overflow > 0 {
                    tracing::warn!(
                        uses = overflow,
                        held = MAX_PENDING,
                        "uses of traps were not reported: too many distinct events were pending"
                    );
                }
                if ended {
                    shared.reported.send_replace(true);
                }
            }
        }
    }
}

/// What the broker made of one report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostOutcome {
    /// `204`: recorded.
    Acknowledged,
    /// `429` or a `5xx`: send it again, after this long when the broker said.
    Retry {
        /// The broker's `Retry-After`.
        after: Option<Duration>,
    },
    /// Any other answer (`400`, `403`, `501`): sending it again changes nothing.
    Refused,
}

/// Where trip reports go: the broker in the guest, a recorder in a test.
#[async_trait]
pub trait TripSink: Send + Sync {
    /// Send one report, once.
    ///
    /// # Errors
    /// The broker unreachable, which the caller retries.
    async fn post(&self, report: &TripReport) -> anyhow::Result<PostOutcome>;
}

/// `POST /v1/me/trip` over the node SVID.
pub struct BrokerTripSink {
    client: Arc<SandboxClient>,
}

impl BrokerTripSink {
    /// A sink that reports with the guest's own client.
    #[must_use]
    pub fn new(client: Arc<SandboxClient>) -> Self {
        Self { client }
    }
}

#[async_trait]
impl TripSink for BrokerTripSink {
    async fn post(&self, report: &TripReport) -> anyhow::Result<PostOutcome> {
        crate::report::send_trip(&self.client, report).await
    }
}

/// Send `report` until the broker acknowledges it or refuses it for good, or, with
/// `attempts`, until that many were made. Whether it was acknowledged.
pub(crate) async fn report_with(
    sink: &dyn TripSink,
    report: &TripReport,
    timing: &Timing,
    attempts: Option<u32>,
) -> bool {
    let mut backoff = timing.backoff_min;
    let mut made: u32 = 0;
    loop {
        made = made.saturating_add(1);
        let wait = match tokio::time::timeout(timing.post, sink.post(report)).await {
            Ok(Ok(PostOutcome::Acknowledged)) => return true,
            Ok(Ok(PostOutcome::Refused)) => {
                tracing::error!(
                    events = report.events.len(),
                    mode = report.mode.as_str(),
                    "the broker refused the trip report: it is not sent again"
                );
                return false;
            }
            Ok(Ok(PostOutcome::Retry { after })) => {
                after.map_or(backoff, |a| a.min(timing.backoff_max))
            }
            Ok(Err(e)) => {
                tracing::warn!(error = %e, attempt = made, events = report.events.len(), "the trip report did not reach the broker");
                backoff
            }
            Err(_) => {
                tracing::warn!(
                    attempt = made,
                    events = report.events.len(),
                    "the broker did not answer the trip report in time"
                );
                backoff
            }
        };
        if attempts.is_some_and(|most| made >= most) {
            tracing::warn!(
                attempts = made,
                events = report.events.len(),
                "the trip report is given up"
            );
            return false;
        }
        tokio::time::sleep(wait).await;
        backoff = backoff.saturating_mul(2).min(timing.backoff_max);
    }
}

/// Send `report` until the broker acknowledges or refuses it, with a capped backoff: for as
/// long as the broker is unreachable (ADR-0069 decision 7 step 5: until `204` or the VM is
/// gone). Containment never waits on this, and it never fails: what it could not send it
/// logs.
pub async fn report_until_acknowledged(sink: &dyn TripSink, report: TripReport) {
    report_with(sink, &report, &Timing::default(), None).await;
}

/// The guest's end of the trap socket: dropping it stops the listener and removes the path.
#[derive(Debug)]
pub struct SocketGuard {
    path: PathBuf,
    task: tokio::task::JoinHandle<()>,
    armed: tokio::sync::watch::Receiver<Option<u32>>,
}

impl SocketGuard {
    /// The socket's path: what the proxy is started with (`--trap-socket`).
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Wait for the proxy to say its matcher is built; the number of patterns it holds.
    ///
    /// # Errors
    /// The proxy did not say so within `within`: under `enforce` no jail starts.
    pub async fn armed(&mut self, within: Duration) -> anyhow::Result<u32> {
        let waited = tokio::time::timeout(within, self.armed.wait_for(Option::is_some)).await;
        match waited {
            Ok(Ok(patterns)) => Ok(patterns.unwrap_or_default()),
            Ok(Err(_)) => anyhow::bail!("the trap socket's listener is gone"),
            Err(_) => anyhow::bail!(
                "the egress proxy did not arm its traps within {}s (ADR-0069 decision 5)",
                within.as_secs()
            ),
        }
    }
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        self.task.abort();
        let _ = std::fs::remove_file(&self.path);
    }
}

/// What is wrong with the trap socket's directory, if anything: it must be the guest's own
/// (`own`, the owner of the socket the guest just bound: root in a guest) and mode `0711`,
/// so nobody but the guest can replace the socket in it.
fn dir_fault(owner: u32, mode: u32, own: u32) -> Option<&'static str> {
    if owner != own {
        Some("the trap socket's directory is not the guest's own")
    } else if mode & 0o7777 != SOCKET_DIR_MODE {
        Some("the trap socket's directory is not mode 0711")
    } else {
        None
    }
}

/// Listen on the trap socket in `dir` (root's, mode `0711`), admit the one peer whose
/// credential is `uid`, send it `drawn`, and note every trip it reports on `trips`.
///
/// The socket is a path, [`TRAP_SOCKET_NAME`] in `dir`, never an abstract name. A peer is
/// admitted by `SO_PEERCRED` alone: any other uid is refused and logged. The draw is handed
/// over once, to the first admitted connection; a later connection is refused, so a process
/// of the sandbox uid that connects after the proxy learns nothing.
///
/// # Errors
/// The directory cannot be made the guest's own at mode `0711`, the socket cannot be bound,
/// or the draw does not fit one message: the proxy cannot be armed, so under `enforce` no
/// jail starts.
pub async fn serve_socket(
    dir: &Path,
    uid: u32,
    drawn: ProxyTraps,
    trips: Trips,
) -> anyhow::Result<SocketGuard> {
    let mut arm = serde_json::to_vec(&GuestToProxy::Arm(drawn))?;
    arm.push(b'\n');
    anyhow::ensure!(
        arm.len() <= TRAP_FRAME_MAX,
        "the draw does not fit one message of the trap socket ({TRAP_FRAME_MAX} bytes)"
    );
    let made = dir.to_owned();
    tokio::task::spawn_blocking(move || {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(SOCKET_DIR_MODE)
            .create(&made)
    })
    .await??;
    tokio::fs::set_permissions(dir, std::fs::Permissions::from_mode(SOCKET_DIR_MODE)).await?;
    let path = dir.join(TRAP_SOCKET_NAME);
    match tokio::fs::remove_file(&path).await {
        Ok(()) => tracing::warn!("a trap socket of an earlier claim was removed"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let listener = tokio::net::UnixListener::bind(&path)?;
    let (armed_tx, armed) = tokio::sync::watch::channel(None);
    let guard = SocketGuard {
        path: path.clone(),
        task: tokio::spawn(accept(listener, uid, arm, trips, armed_tx)),
        armed,
    };
    // From here an error drops the guard, which removes the socket.
    tokio::fs::set_permissions(&path, std::fs::Permissions::from_mode(SOCKET_MODE)).await?;
    let socket = tokio::fs::symlink_metadata(&path).await?;
    anyhow::ensure!(
        socket.file_type().is_socket(),
        "the trap socket's path is not a socket"
    );
    let held = tokio::fs::metadata(dir).await?;
    if let Some(fault) = dir_fault(held.uid(), held.mode(), socket.uid()) {
        anyhow::bail!("{fault}: {} (ADR-0069 decision 7)", dir.display());
    }
    Ok(guard)
}

/// Whether the `refusals`-th refused connection on the trap socket is logged: the first, then
/// one each time the count doubles. A peer that connects in a loop must not write the guest's
/// log at its own pace.
fn refusal_logged(refusals: u64) -> bool {
    refusals.is_power_of_two()
}

/// Admit the sandbox uid, once; refuse and log everyone else.
async fn accept(
    listener: tokio::net::UnixListener,
    uid: u32,
    arm: Vec<u8>,
    trips: Trips,
    armed: tokio::sync::watch::Sender<Option<u32>>,
) {
    let mut arm = Some(arm);
    let armed = Arc::new(armed);
    let mut refusals: u64 = 0;
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(e) => {
                tracing::warn!(error = %e, "the trap socket could not accept");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        match stream.peer_cred().map(|cred| cred.uid()) {
            Ok(peer) if peer == uid => {}
            Ok(peer) => {
                refusals = refusals.saturating_add(1);
                if refusal_logged(refusals) {
                    tracing::warn!(
                        peer_uid = peer,
                        refusals,
                        "a peer that is not the sandbox uid on the trap socket: refused"
                    );
                }
                continue;
            }
            Err(e) => {
                refusals = refusals.saturating_add(1);
                if refusal_logged(refusals) {
                    tracing::warn!(error = %e, refusals, "a peer without a credential on the trap socket: refused");
                }
                continue;
            }
        }
        let Some(arm) = arm.take() else {
            refusals = refusals.saturating_add(1);
            if refusal_logged(refusals) {
                tracing::warn!(
                    refusals,
                    "a second connection on the trap socket: refused, the draw is handed over once"
                );
            }
            continue;
        };
        tokio::spawn(converse(stream, arm, trips.clone(), armed.clone()));
    }
}

/// Why a frame was not read.
#[derive(Debug)]
pub(crate) enum FrameFault {
    /// More than [`TRAP_FRAME_MAX`] bytes without a newline.
    TooLong,
    /// The peer closed in the middle of a message.
    Cut,
    /// The read failed.
    Io,
}

/// One newline-delimited message of at most [`TRAP_FRAME_MAX`] bytes; `None` at a clean
/// end. Never more than the bound is held.
pub(crate) async fn read_frame<R: AsyncBufRead + Unpin>(
    reader: &mut R,
) -> Result<Option<Vec<u8>>, FrameFault> {
    let mut frame = Vec::new();
    loop {
        let available = reader.fill_buf().await.map_err(|_| FrameFault::Io)?;
        if available.is_empty() {
            return if frame.is_empty() {
                Ok(None)
            } else {
                Err(FrameFault::Cut)
            };
        }
        let newline = available.iter().position(|b| *b == b'\n');
        let take = newline.unwrap_or(available.len());
        if frame.len() + take > TRAP_FRAME_MAX {
            return Err(FrameFault::TooLong);
        }
        frame.extend_from_slice(&available[..take]);
        reader.consume(take + usize::from(newline.is_some()));
        if newline.is_some() {
            return Ok(Some(frame));
        }
    }
}

/// The cause a verdict of the proxy is. `None` for a kind the proxy does not decide. A host
/// or a trap name outside the grammar the broker admits is replaced by `invalid`: the use
/// is still reported, and nothing the peer chose outside the grammar is.
fn cause_of(trip: ProxyTrip, mode: TripMode) -> Option<Cause> {
    let source = match (trip.kind, trip.trap.is_some(), trip.class) {
        (TripKind::Route, true, None) => TripSource::Drawn,
        (TripKind::Credential, true, None)
        | (TripKind::Denied, false, Some(TripClass::UnknownHost)) => TripSource::Workload,
        _ => return None,
    };
    let mut cause = Cause {
        at: trip.at,
        kind: trip.kind,
        trap: trip.trap,
        class: trip.class,
        target: Some(TripTarget::Host(trip.host)),
        source,
    };
    if cause.reportable(mode).is_err() {
        tracing::warn!(
            kind = cause.kind.as_str(),
            "the proxy named a host or a trap outside the report's grammar: reported as `invalid`"
        );
        cause.target = Some(TripTarget::Host(OUTSIDE_THE_GRAMMAR.to_owned()));
        cause.trap = cause.trap.map(|_| OUTSIDE_THE_GRAMMAR.to_owned());
    }
    Some(cause)
}

/// A task that ends with its holder.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// One admitted connection: the draw out, then the proxy's messages until one is off.
async fn converse(
    stream: tokio::net::UnixStream,
    arm: Vec<u8>,
    trips: Trips,
    armed: Arc<tokio::sync::watch::Sender<Option<u32>>>,
) {
    let (read, mut write) = stream.into_split();
    if let Err(e) = write.write_all(&arm).await {
        tracing::error!(error = %e, "the draw could not be handed to the proxy");
        return;
    }
    drop(arm);
    // Under enforce, the instant a use is decided to end the run the proxy is told to forward
    // nothing more: ahead of the cut, which takes `nft` its time (decision 7 step 1).
    let mut ending = trips.shared.ending.subscribe();
    let telling = tokio::spawn(async move {
        if ending.wait_for(|ending| *ending).await.is_err() {
            return;
        }
        let mut line = serde_json::to_vec(&GuestToProxy::Tripped).unwrap_or_default();
        line.push(b'\n');
        if let Err(e) = write.write_all(&line).await {
            tracing::warn!(error = %e, "the proxy could not be told of the trip: the cut and the kill stop it");
        }
        // Held until the reader ends: closing it would read as the guest gone.
        std::future::pending::<()>().await;
    });
    let _telling = AbortOnDrop(telling);
    let mut reader = BufReader::new(read);
    // Never a byte of a frame in a log line: only why it was refused.
    let why = loop {
        let frame = match read_frame(&mut reader).await {
            Ok(Some(frame)) => frame,
            Ok(None) => break "the proxy closed it",
            Err(FrameFault::TooLong) => break "a message over the bound",
            Err(FrameFault::Cut) => break "a message cut short",
            Err(FrameFault::Io) => break "a read failed",
        };
        match serde_json::from_slice::<ProxyToGuest>(&frame) {
            Ok(ProxyToGuest::Armed { patterns }) => {
                tracing::info!(patterns, "the egress proxy armed its traps");
                armed.send_replace(Some(patterns));
            }
            Ok(ProxyToGuest::Trip(trip)) => match cause_of(trip, trips.mode()) {
                Some(cause) => trips.note(cause),
                None => break "a trip of a kind the proxy does not decide",
            },
            Err(_) => break "an unknown message",
        }
    };
    tracing::error!(
        why,
        "the trap socket's connection is closed: the proxy can report no more trips and ends the claim (ADR-0069 decision 7)"
    );
}

/// The `denied` use a dropped connection is, by its destination (ADR-0069 decision 10):
/// loopback is `loopback_port`, the private and link-local ranges are `private_range`.
/// `None` for any other destination: refused and logged by the chain, and no class.
///
/// The source is always `workload`, though the egress proxy's own sockets carry the same uid
/// (ADR-0040 decision 7) and the chain, which keys on that uid alone, cannot tell its drops
/// from the jail's. In the direct shape a proxy that re-resolves an audience's name to a
/// private address the ruleset did not resolve is dropped and read here as the workload's
/// `private_range`. Both share one uid by design; telling them apart would need a mark the
/// proxy sets on its sockets, which the jail could not, and is not done here.
#[must_use]
pub fn denied_cause(denied: &Denied, at: Timestamp) -> Option<Cause> {
    let private = match denied.address {
        std::net::IpAddr::V4(a) => a.is_private() || a.is_link_local(),
        std::net::IpAddr::V6(a) => {
            let first = a.segments()[0];
            first & 0xfe00 == 0xfc00 || first & 0xffc0 == 0xfe80
        }
    };
    let (class, target) = if denied.address.is_loopback() {
        (TripClass::LoopbackPort, TripTarget::Port(denied.port))
    } else if private {
        let address = std::net::SocketAddr::new(denied.address, denied.port);
        (
            TripClass::PrivateRange,
            TripTarget::Address(address.to_string()),
        )
    } else {
        return None;
    };
    Some(Cause {
        at,
        kind: TripKind::Denied,
        trap: None,
        class: Some(class),
        target: Some(target),
        source: TripSource::Workload,
    })
}

/// The running reader of what the chain dropped: dropping it stops it. Drop it before the
/// claim's table is unloaded.
#[derive(Debug)]
pub struct DeniedReader {
    task: tokio::task::JoinHandle<()>,
}

impl Drop for DeniedReader {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Read the `denied` sets of the claim's table every `every` with the VM's `nft` and note
/// each destination that is a class on `trips`. The table must be loaded, with its draw.
#[must_use]
pub fn watch_denied(trips: Trips, every: Duration) -> DeniedReader {
    watch_denied_with(Arc::new(SystemNft), trips, every)
}

/// [`watch_denied`] through `nft`. A read that fails is logged (the first, then one in 256)
/// and tried again: the classes it feeds are observations, and the chain drops with or
/// without a reader. It ends at a trip, when the table is the cut's.
#[must_use]
pub fn watch_denied_with(nft: Arc<dyn NftRunner>, trips: Trips, every: Duration) -> DeniedReader {
    let task = tokio::spawn(async move {
        let mut failures: u64 = 0;
        loop {
            tokio::time::sleep(every).await;
            if trips.is_tripped() {
                return;
            }
            let read = tokio::time::timeout(
                Duration::from_secs(2),
                crate::net::read_denied(nft.as_ref()),
            )
            .await
            .unwrap_or_else(|_| Err(anyhow::anyhow!("nft did not answer in time")));
            match read {
                Ok(denied) => {
                    failures = 0;
                    let at = Timestamp::now();
                    for d in &denied {
                        if let Some(cause) = denied_cause(d, at) {
                            trips.note_many(cause, d.packets);
                        }
                    }
                }
                Err(e) => {
                    if failures.is_multiple_of(256) && !trips.is_tripped() {
                        tracing::warn!(error = %e, failures, "what the sandbox uid's chain dropped could not be read: the loopback_port and private_range classes see nothing");
                    }
                    failures = failures.saturating_add(1);
                }
            }
        }
    });
    DeniedReader { task }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::NftOutput;
    use crate::net::testing::FakeNft;
    use std::collections::VecDeque;
    use std::sync::OnceLock;

    /// What a recorder answers a post with.
    #[derive(Debug, Clone, Copy)]
    enum Answer {
        Outcome(PostOutcome),
        Unreachable,
    }

    /// A broker that records every post, answers from a queue and then `204`.
    #[derive(Default)]
    struct Recorder {
        posts: Mutex<Vec<TripReport>>,
        answers: Mutex<VecDeque<Answer>>,
        at: Mutex<Vec<Instant>>,
    }

    impl Recorder {
        fn answering(answers: impl IntoIterator<Item = Answer>) -> Arc<Self> {
            let recorder = Self::default();
            recorder.answers.lock().unwrap().extend(answers);
            Arc::new(recorder)
        }

        fn posts(&self) -> Vec<TripReport> {
            self.posts.lock().unwrap().clone()
        }

        /// Wait until `n` posts were made.
        async fn after(&self, n: usize) -> Vec<TripReport> {
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    let posts = self.posts();
                    if posts.len() >= n {
                        return posts;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("the reports were not sent in time")
        }
    }

    #[async_trait]
    impl TripSink for Recorder {
        async fn post(&self, report: &TripReport) -> anyhow::Result<PostOutcome> {
            self.posts.lock().unwrap().push(report.clone());
            self.at.lock().unwrap().push(Instant::now());
            let answer = self.answers.lock().unwrap().pop_front();
            match answer {
                None => Ok(PostOutcome::Acknowledged),
                Some(Answer::Outcome(outcome)) => Ok(outcome),
                Some(Answer::Unreachable) => anyhow::bail!("unreachable"),
            }
        }
    }

    /// A broker that never answers.
    struct Silent;

    #[async_trait]
    impl TripSink for Silent {
        async fn post(&self, _: &TripReport) -> anyhow::Result<PostOutcome> {
            std::future::pending().await
        }
    }

    /// Bounds short enough for a test and long enough to tell an order.
    fn quick() -> Timing {
        Timing {
            cut: Duration::from_millis(300),
            fold: Duration::from_millis(40),
            window: Duration::from_millis(600),
            post: Duration::from_millis(300),
            backoff_min: Duration::from_millis(10),
            backoff_max: Duration::from_millis(40),
        }
    }

    fn cause() -> Cause {
        Cause {
            at: Timestamp::now(),
            kind: TripKind::Port,
            trap: Some("redis".into()),
            class: None,
            target: Some(TripTarget::Port(6379)),
            source: TripSource::Drawn,
        }
    }

    fn unknown_host(host: &str) -> Cause {
        Cause {
            at: Timestamp::now(),
            kind: TripKind::Denied,
            trap: None,
            class: Some(TripClass::UnknownHost),
            target: Some(TripTarget::Host(host.to_owned())),
            source: TripSource::Workload,
        }
    }

    fn armed(
        mode: TripMode,
        denied: DeniedSwitches,
        sink: Arc<dyn TripSink>,
        nft: Arc<dyn NftRunner>,
    ) -> Tripwire {
        start_with(mode, denied, 1234, sink, nft, quick())
    }

    async fn tripped(wire: &mut Tripwire) -> Cause {
        tokio::time::timeout(
            Duration::from_secs(10),
            wire.tripped.wait_for(Option::is_some),
        )
        .await
        .expect("the supervision was not signalled in time")
        .expect("the tripwire is alive")
        .clone()
        .expect("a cause")
    }

    #[test]
    fn the_drop_all_ruleset_is_this_text() {
        assert_eq!(
            drop_all_ruleset(1234),
            "# mediatore guest (ADR-0069 decision 7): uid 1234 tripped; nothing it sends leaves\n\
table inet mediatore_sandbox\n\
delete table inet mediatore_sandbox\n\
table inet mediatore_sandbox {\n  chain output {\n    type filter hook output priority filter; policy accept;\n    meta skuid 1234 counter drop\n  }\n}\n"
        );
        assert!(!drop_all_ruleset(1234).contains("established"));
        assert!(!drop_all_ruleset(1234).contains("accept;\n    meta skuid 1234 jump"));
    }

    /// An `nft` and a broker that write down the order they were called in, and whether the
    /// supervision had been signalled by then.
    #[derive(Default)]
    struct Order {
        seen: Mutex<Vec<&'static str>>,
        scripts: Mutex<Vec<(Vec<String>, Option<String>)>>,
        signal: OnceLock<tokio::sync::watch::Receiver<Option<Cause>>>,
    }

    impl Order {
        fn signalled(&self) -> bool {
            self.signal.get().is_some_and(|rx| rx.borrow().is_some())
        }
    }

    #[async_trait]
    impl NftRunner for Order {
        async fn run(&self, args: &[&str], stdin: Option<&str>) -> std::io::Result<NftOutput> {
            self.scripts.lock().unwrap().push((
                args.iter().map(|a| (*a).to_owned()).collect(),
                stdin.map(str::to_owned),
            ));
            self.seen.lock().unwrap().push(if self.signalled() {
                "the cut, after the kill's signal"
            } else {
                "the cut"
            });
            // Long enough that a signal or a report racing ahead of it would be seen.
            tokio::time::sleep(Duration::from_millis(30)).await;
            Ok(NftOutput {
                success: true,
                stdout: Vec::new(),
                stderr: String::new(),
            })
        }
    }

    #[async_trait]
    impl TripSink for Order {
        async fn post(&self, _: &TripReport) -> anyhow::Result<PostOutcome> {
            self.seen.lock().unwrap().push(if self.signalled() {
                "the report"
            } else {
                "the report, before the kill's signal"
            });
            Ok(PostOutcome::Acknowledged)
        }
    }

    #[tokio::test]
    async fn under_enforce_the_cut_comes_before_the_kill_and_both_before_the_report() {
        let order = Arc::new(Order::default());
        let mut wire = armed(
            TripMode::Enforce,
            DeniedSwitches::default(),
            order.clone(),
            order.clone(),
        );
        assert!(order.signal.set(wire.tripped.clone()).is_ok());
        assert_eq!(*wire.tripped.borrow(), None);
        let first = cause();
        wire.trips.note(first.clone());
        assert_eq!(tripped(&mut wire).await, first);
        assert!(wire.trips.is_tripped());
        tokio::time::timeout(Duration::from_secs(10), wire.trips.reported())
            .await
            .expect("the report was acknowledged");
        assert_eq!(*order.seen.lock().unwrap(), ["the cut", "the report"]);
        // One `nft -f` transaction, and its script is the drop of everything the uid sends.
        assert_eq!(
            *order.scripts.lock().unwrap(),
            [(
                vec!["-f".to_owned(), "-".to_owned()],
                Some(drop_all_ruleset(1234))
            )]
        );
    }

    #[tokio::test]
    async fn the_report_of_a_trip_carries_the_containment_figure_and_validates() {
        let sink = Recorder::answering([]);
        let nft = Arc::new(FakeNft::default());
        let mut wire = armed(
            TripMode::Enforce,
            DeniedSwitches::default(),
            sink.clone(),
            nft,
        );
        wire.trips.note(cause());
        tripped(&mut wire).await;
        let posts = sink.after(1).await;
        assert_eq!(posts[0].mode, TripMode::Enforce);
        assert_eq!(posts[0].validate(), Ok(()));
        let event = &posts[0].events[0];
        assert_eq!(
            (event.kind, event.trap.as_deref(), event.count),
            (TripKind::Port, Some("redis"), 1)
        );
        assert_eq!(event.target, Some(TripTarget::Port(6379)));
        assert!(
            event.containment_ms.is_some_and(|ms| ms < 5000),
            "measured from the verdict to the end of the cut"
        );
        assert!(!event.id.is_nil());
    }

    #[tokio::test]
    async fn only_the_first_cause_contains_and_later_ones_are_folded_into_the_report() {
        let sink = Recorder::answering([]);
        let nft = Arc::new(FakeNft::default());
        let mut wire = armed(
            TripMode::Enforce,
            DeniedSwitches::default(),
            sink.clone(),
            nft.clone(),
        );
        let first = cause();
        wire.trips.note(first.clone());
        let mut second = cause();
        second.trap = Some("ssh".into());
        second.target = Some(TripTarget::Port(22));
        wire.trips.clone().note(second.clone());
        wire.trips.note(second);
        assert_eq!(tripped(&mut wire).await, first, "the first cause is kept");
        assert!(wire.trips.flush(Duration::from_secs(5)).await);
        let posts = sink.posts();
        assert_eq!(nft.calls().len(), 1, "one cut, whatever comes after");
        let all: Vec<&TripEvent> = posts.iter().flat_map(|p| p.events.iter()).collect();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].trap.as_deref(), Some("redis"), "the trip leads");
        assert!(all[0].containment_ms.is_some());
        assert_eq!(all[0].count, 1);
        assert_eq!(all[1].trap.as_deref(), Some("ssh"));
        assert_eq!(all[1].containment_ms, None, "one figure, the first cause's");
        assert_eq!(all[1].count, 2);
        assert!(posts.iter().all(|p| p.validate().is_ok()));
        // A later use of the very trap that tripped is its own entry: the trip keeps its
        // time and its figure.
        wire.trips.note(first);
        assert!(wire.trips.flush(Duration::from_secs(5)).await);
        let later = sink.posts();
        let last = later.last().unwrap().events.last().unwrap();
        assert_eq!(last.trap.as_deref(), Some("redis"));
        assert_eq!(last.containment_ms, None);
    }

    #[tokio::test]
    async fn containment_does_not_wait_on_a_broker_that_never_answers() {
        let nft = Arc::new(FakeNft::default());
        let mut wire = armed(
            TripMode::Enforce,
            DeniedSwitches::default(),
            Arc::new(Silent),
            nft.clone(),
        );
        wire.trips.note(cause());
        tripped(&mut wire).await;
        assert_eq!(nft.calls().len(), 1, "cut");
        // And the report is still owed: nothing says it was made.
        let reported = tokio::time::timeout(Duration::from_millis(200), wire.trips.reported());
        assert!(reported.await.is_err());
    }

    #[tokio::test]
    async fn nft_failing_at_the_cut_still_kills_and_the_report_carries_no_containment() {
        for nft in [
            FakeNft::refusing("Error: Could not process rule"),
            FakeNft::absent(),
            FakeNft::hanging(),
        ] {
            let sink = Recorder::answering([]);
            let mut wire = armed(
                TripMode::Enforce,
                DeniedSwitches::default(),
                sink.clone(),
                Arc::new(nft),
            );
            wire.trips.note(cause());
            tripped(&mut wire).await;
            let posts = sink.after(1).await;
            assert_eq!(posts[0].events.len(), 1);
            assert_eq!(
                posts[0].events[0].containment_ms, None,
                "a figure is never invented for a cut that was not made"
            );
            assert_eq!(posts[0].validate(), Ok(()));
        }
    }

    #[tokio::test]
    async fn the_report_is_retried_with_capped_backoff_until_204() {
        let sink = Recorder::answering([
            Answer::Unreachable,
            Answer::Outcome(PostOutcome::Retry { after: None }),
            Answer::Unreachable,
            Answer::Unreachable,
            Answer::Outcome(PostOutcome::Retry {
                after: Some(Duration::from_secs(3600)),
            }),
            Answer::Unreachable,
        ]);
        let report = TripReport {
            mode: TripMode::Enforce,
            events: vec![cause().event(Uuid::new_v4(), 1, Some(12))],
        };
        let timing = quick();
        let started = Instant::now();
        assert!(report_with(sink.as_ref(), &report, &timing, None).await);
        let took = started.elapsed();
        let posts = sink.posts();
        assert_eq!(posts.len(), 7, "six failures, then the 204");
        assert!(
            posts.iter().all(|p| *p == report),
            "every attempt is the same report, ids included: the broker records it once"
        );
        // 10, 20, 40, 40, a Retry-After of an hour capped at 40, 40: the waits double to the
        // cap and stay there.
        assert!(took >= Duration::from_millis(190), "it backed off");
        assert!(took < Duration::from_secs(5), "and the cap held");
        let at = sink.at.lock().unwrap().clone();
        let waits: Vec<Duration> = at.windows(2).map(|w| w[1].duration_since(w[0])).collect();
        assert!(waits[0] >= Duration::from_millis(10));
        assert!(waits[1] >= Duration::from_millis(20));
        assert!(waits[2..].iter().all(|w| *w >= Duration::from_millis(40)));
    }

    #[tokio::test]
    async fn a_refused_report_is_not_sent_again_and_a_bounded_one_gives_up() {
        let sink = Recorder::answering([Answer::Outcome(PostOutcome::Refused)]);
        let report = TripReport {
            mode: TripMode::Shadow,
            events: vec![cause().event(Uuid::new_v4(), 1, None)],
        };
        assert!(!report_with(sink.as_ref(), &report, &quick(), None).await);
        assert_eq!(sink.posts().len(), 1);
        let down = Recorder::answering(std::iter::repeat_n(Answer::Unreachable, 10));
        assert!(!report_with(down.as_ref(), &report, &quick(), Some(3)).await);
        assert_eq!(down.posts().len(), 3);
        // A broker that never answers is a failed attempt, not a hang.
        assert!(!report_with(&Silent, &report, &quick(), Some(2)).await);
    }

    #[tokio::test]
    async fn under_shadow_nothing_is_cut_and_repeats_fold_into_a_count() {
        let sink = Recorder::answering([]);
        let nft = Arc::new(FakeNft::default());
        let wire = armed(
            TripMode::Shadow,
            DeniedSwitches::default(),
            sink.clone(),
            nft.clone(),
        );
        let first = cause();
        for _ in 0..5 {
            let mut again = cause();
            again.at = first.at;
            wire.trips.note(again);
        }
        wire.trips.note(unknown_host("mirror.example"));
        wire.trips.note_many(unknown_host("mirror.example"), 3);
        let posts = sink.after(1).await;
        assert_eq!(posts.len(), 1);
        assert_eq!(posts[0].mode, TripMode::Shadow);
        assert_eq!(posts[0].validate(), Ok(()));
        let counts: Vec<(TripKind, u64, Option<u32>)> = posts[0]
            .events
            .iter()
            .map(|e| (e.kind, e.count, e.containment_ms))
            .collect();
        assert_eq!(
            counts,
            [(TripKind::Port, 5, None), (TripKind::Denied, 4, None)]
        );
        assert_eq!(posts[0].events[0].at, first.at, "the first use's time");
        assert!(nft.calls().is_empty(), "nothing is cut");
        assert_eq!(*wire.tripped.borrow(), None, "nothing is killed");
        assert!(!wire.trips.is_tripped());
    }

    #[tokio::test]
    async fn no_more_than_32_distinct_events_a_minute_and_the_rest_ride_the_next_batch() {
        let sink = Recorder::answering([]);
        let wire = armed(
            TripMode::Shadow,
            DeniedSwitches::default(),
            sink.clone(),
            Arc::new(FakeNft::default()),
        );
        for n in 0..40 {
            wire.trips.note(unknown_host(&format!("host-{n}.example")));
        }
        let posts = sink.after(1).await;
        assert_eq!(posts[0].events.len(), 32, "the window's budget");
        // What is used while the budget is spent is counted, and waits.
        wire.trips.note(unknown_host("host-39.example"));
        wire.trips.note(unknown_host("host-39.example"));
        tokio::time::sleep(quick().fold * 3).await;
        assert_eq!(sink.posts().len(), 1, "nothing more leaves in this window");
        let posts = sink.after(2).await;
        assert_eq!(posts[1].events.len(), 8, "the rest ride the next batch");
        let last = posts[1].events.last().unwrap();
        assert_eq!(
            last.target,
            Some(TripTarget::Host("host-39.example".into()))
        );
        assert_eq!(last.count, 3, "with every use counted");
        assert!(posts.iter().all(|p| p.validate().is_ok()));
        let ids: std::collections::BTreeSet<Uuid> = posts
            .iter()
            .flat_map(|p| p.events.iter().map(|e| e.id))
            .collect();
        assert_eq!(ids.len(), 40, "an id an event");
    }

    #[tokio::test]
    async fn the_event_that_ended_the_run_does_not_wait_for_the_budget() {
        let sink = Recorder::answering([]);
        let mut slow = quick();
        slow.window = Duration::from_secs(3600);
        slow.fold = Duration::from_millis(10);
        let mut wire = start_with(
            TripMode::Enforce,
            DeniedSwitches::default(),
            1234,
            sink.clone(),
            Arc::new(FakeNft::default()),
            slow,
        );
        for n in 0..32 {
            wire.trips.note(unknown_host(&format!("host-{n}.example")));
        }
        assert_eq!(sink.after(1).await[0].events.len(), 32);
        assert_eq!(*wire.tripped.borrow(), None, "unknown_host is at report");
        wire.trips.note(cause());
        tripped(&mut wire).await;
        let posts = sink.after(2).await;
        assert_eq!(posts[1].events[0].kind, TripKind::Port);
        assert!(posts[1].events[0].containment_ms.is_some());
    }

    #[tokio::test]
    async fn a_denied_class_at_report_never_cuts_under_enforce() {
        let sink = Recorder::answering([]);
        let nft = Arc::new(FakeNft::default());
        let mut wire = armed(
            TripMode::Enforce,
            DeniedSwitches::default(),
            sink.clone(),
            nft.clone(),
        );
        wire.trips.note(unknown_host("mirror.example"));
        let posts = sink.after(1).await;
        assert_eq!(posts[0].mode, TripMode::Enforce);
        assert_eq!(posts[0].events[0].class, Some(TripClass::UnknownHost));
        assert_eq!(posts[0].events[0].containment_ms, None);
        assert!(nft.calls().is_empty(), "no cut");
        assert_eq!(*wire.tripped.borrow(), None, "no kill");
        drop(wire);

        // The same class switched to `trip` ends the run, and under shadow it never does.
        let switched = DeniedSwitches {
            unknown_host: ClassAction::Trip,
            ..DeniedSwitches::default()
        };
        let nft = Arc::new(FakeNft::default());
        wire = armed(TripMode::Enforce, switched, sink.clone(), nft.clone());
        wire.trips.note(unknown_host("mirror.example"));
        assert_eq!(tripped(&mut wire).await.class, Some(TripClass::UnknownHost));
        assert_eq!(nft.calls().len(), 1);
        let shadow = armed(
            TripMode::Shadow,
            switched,
            sink.clone(),
            Arc::new(FakeNft::default()),
        );
        shadow.trips.note(unknown_host("mirror.example"));
        assert!(shadow.trips.flush(Duration::from_secs(5)).await);
        assert_eq!(*shadow.tripped.borrow(), None);
    }

    #[tokio::test]
    async fn a_flush_sends_what_is_pending_at_once_and_is_bounded() {
        let sink = Recorder::answering([]);
        let mut slow = quick();
        slow.fold = Duration::from_secs(3600);
        let wire = start_with(
            TripMode::Shadow,
            DeniedSwitches::default(),
            1234,
            sink.clone(),
            Arc::new(FakeNft::default()),
            slow,
        );
        wire.trips.note(cause());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(sink.posts().is_empty(), "still waiting for repeats");
        assert!(wire.trips.flush(Duration::from_secs(5)).await);
        assert_eq!(sink.posts().len(), 1);
        // With a broker that never answers the flush gives up at its bound.
        let silent = start_with(
            TripMode::Shadow,
            DeniedSwitches::default(),
            1234,
            Arc::new(Silent),
            Arc::new(FakeNft::default()),
            slow,
        );
        silent.trips.note(cause());
        assert!(!silent.trips.flush(Duration::from_millis(100)).await);
    }

    #[tokio::test]
    async fn a_use_the_decider_cannot_take_under_enforce_still_signals_the_supervision() {
        // No decider at all: the queue's other end is gone.
        let (trips, rx) = Trips::recording(TripMode::Enforce);
        drop(rx);
        assert!(!trips.is_tripped());
        trips.note(unknown_host("mirror.example"));
        assert!(!trips.is_tripped(), "a class at report ends nothing");
        trips.note(cause());
        assert!(trips.is_tripped(), "fail closed: the jail is killed");
        let (shadow, rx) = Trips::recording(TripMode::Shadow);
        drop(rx);
        shadow.note(cause());
        assert!(!shadow.is_tripped());
    }

    /// A cause the decider must not be able to lose: a tripping use that arrives while the
    /// queue is full of `denied` notes (S1 of the review). Under a current-thread runtime the
    /// decider cannot run until this test yields, so the queue is full when the trap is used.
    #[tokio::test]
    async fn a_trip_that_finds_the_queue_full_is_still_cut_reported_and_ends_the_run() {
        let sink = Recorder::answering([]);
        let nft = Arc::new(FakeNft::default());
        let mut wire = armed(
            TripMode::Enforce,
            DeniedSwitches::default(),
            sink.clone(),
            nft.clone(),
        );
        for n in 0..NOTE_QUEUE + 16 {
            wire.trips
                .note(unknown_host(&format!("host-{}.example", n % 300)));
        }
        let first = cause();
        wire.trips.note(first.clone());
        assert_eq!(tripped(&mut wire).await, first);
        tokio::time::timeout(Duration::from_secs(10), wire.trips.reported())
            .await
            .expect("the report of the trip was acknowledged");
        assert_eq!(nft.calls().len(), 1, "the trip was cut");
        let posts = sink.posts();
        let ended: Vec<&TripEvent> = posts
            .iter()
            .flat_map(|p| p.events.iter())
            .filter(|e| e.kind == TripKind::Port)
            .collect();
        assert_eq!(ended.len(), 1, "the trip was reported once");
        assert!(
            ended[0].containment_ms.is_some(),
            "as the event that ended the run, with its figure"
        );
        assert!(posts.iter().all(|p| p.validate().is_ok()));
    }

    #[tokio::test]
    async fn the_wait_for_the_report_of_a_trip_is_bounded() {
        let mut wire = armed(
            TripMode::Enforce,
            DeniedSwitches::default(),
            Arc::new(Silent),
            Arc::new(FakeNft::default()),
        );
        wire.trips.note(cause());
        tripped(&mut wire).await;
        let started = Instant::now();
        assert!(
            !wire.trips.reported_within(Duration::from_millis(100)).await,
            "no broker acknowledged it"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "and it returned"
        );
    }

    /// An `nft` whose cut takes a while: what a workload that uses a trap and exits at once
    /// races against.
    struct SlowCut(Duration);

    #[async_trait]
    impl NftRunner for SlowCut {
        async fn run(&self, _: &[&str], _: Option<&str>) -> std::io::Result<NftOutput> {
            tokio::time::sleep(self.0).await;
            Ok(NftOutput {
                success: true,
                stdout: Vec::new(),
                stderr: String::new(),
            })
        }
    }

    #[tokio::test]
    async fn a_run_that_ends_while_its_trip_is_being_cut_is_still_the_tripped_run() {
        // Decision 12 of 2026-11-27: the jail exited, and the trip is decided but not yet
        // signalled (the cut is in `nft`): what the guest settles on is the trip.
        let wire = armed(
            TripMode::Enforce,
            DeniedSwitches::default(),
            Recorder::answering([]),
            Arc::new(SlowCut(Duration::from_millis(200))),
        );
        wire.trips.note(cause());
        tokio::task::yield_now().await;
        assert!(!wire.trips.is_tripped(), "the cut is still running");
        let settled = wire.trips.settle(Duration::from_millis(50)).await;
        assert_eq!(settled.map(|c| c.kind), Some(TripKind::Port));
        assert!(wire.trips.is_tripped());

        // A use noted a moment after the jail's exit is seen too, within the settling window.
        let late = armed(
            TripMode::Enforce,
            DeniedSwitches::default(),
            Recorder::answering([]),
            Arc::new(FakeNft::default()),
        );
        let trips = late.trips.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            trips.note(cause());
        });
        assert!(
            late.trips
                .settle(Duration::from_millis(300))
                .await
                .is_some()
        );

        // No trip: nothing after the window. Under shadow nothing can end the run, and the
        // settling returns at once.
        let quiet = armed(
            TripMode::Enforce,
            DeniedSwitches::default(),
            Recorder::answering([]),
            Arc::new(FakeNft::default()),
        );
        quiet.trips.note(unknown_host("mirror.example"));
        assert!(
            quiet
                .trips
                .settle(Duration::from_millis(50))
                .await
                .is_none()
        );
        let shadow = armed(
            TripMode::Shadow,
            DeniedSwitches::default(),
            Recorder::answering([]),
            Arc::new(FakeNft::default()),
        );
        shadow.trips.note(cause());
        let started = Instant::now();
        assert!(shadow.trips.settle(Duration::from_secs(5)).await.is_none());
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn the_proxy_is_told_a_trip_was_decided_before_the_cut_lands() {
        // NIT of the review: under enforce the proxy refuses at once from the guest's decision,
        // not from the cut. Here the cut takes long enough that the message must come first.
        let dir = tempfile::tempdir().unwrap();
        let me = own_uid(dir.path());
        let wire = armed(
            TripMode::Enforce,
            DeniedSwitches::default(),
            Recorder::answering([]),
            Arc::new(SlowCut(Duration::from_secs(2))),
        );
        let mut guard = serve_socket(&dir.path().join("t"), me, drawn(), wire.trips.clone())
            .await
            .unwrap();
        let stream = tokio::net::UnixStream::connect(guard.path()).await.unwrap();
        let (read, mut write) = stream.into_split();
        let mut reader = BufReader::new(read);
        assert!(line(&mut reader).await.is_some(), "the draw");
        write
            .write_all(b"{\"type\":\"armed\",\"patterns\":1}\n")
            .await
            .unwrap();
        guard.armed(Duration::from_secs(5)).await.unwrap();
        wire.trips.note(cause());
        let told = tokio::time::timeout(Duration::from_millis(500), read_frame(&mut reader))
            .await
            .expect("told before the cut ended")
            .unwrap()
            .expect("a message");
        assert_eq!(
            serde_json::from_slice::<GuestToProxy>(&told).unwrap(),
            GuestToProxy::Tripped
        );
        assert!(!wire.trips.is_tripped(), "and the cut had not landed yet");
    }

    #[test]
    fn refused_peers_on_the_trap_socket_are_logged_a_bounded_number_of_times() {
        // A NIT of the review: one `warn` per refused connection lets a peer write the guest's
        // log at its own pace. The first refusal is logged, then one each time the count
        // doubles.
        let logged = (1..=100_000_u64).filter(|n| refusal_logged(*n)).count();
        assert!(refusal_logged(1), "the first is always logged");
        assert!(
            logged <= 17,
            "{logged} lines for a hundred thousand refusals"
        );
    }

    #[test]
    fn the_final_line_names_the_kind_and_the_trap_and_never_the_target() {
        let line = cause().final_line();
        assert_eq!(
            line,
            "mediatore: this sandbox was ended by a tripwire (kind port, trap redis)"
        );
        assert!(!line.contains("6379"));
        let denied = unknown_host("exfil.attacker.example").final_line();
        assert_eq!(
            denied,
            "mediatore: this sandbox was ended by a tripwire (kind denied, class unknown_host)"
        );
        assert!(
            !denied.contains("attacker"),
            "a workload-chosen host is never in it"
        );
    }

    #[test]
    fn a_verdict_of_the_proxy_becomes_a_cause_and_nothing_outside_the_grammar_is_reported() {
        let at: Timestamp = "2026-11-26T15:02:11Z".parse().unwrap();
        let trip = |kind, trap: Option<&str>, class, host: &str| ProxyTrip {
            at,
            kind,
            trap: trap.map(str::to_owned),
            class,
            host: host.to_owned(),
        };
        let mode = TripMode::Enforce;
        let route = cause_of(
            trip(
                TripKind::Route,
                Some("vault"),
                None,
                "secrets.prod.internal",
            ),
            mode,
        )
        .unwrap();
        assert_eq!(
            (route.kind, route.source, route.at),
            (TripKind::Route, TripSource::Drawn, at)
        );
        assert_eq!(
            route.target,
            Some(TripTarget::Host("secrets.prod.internal".into()))
        );
        let credential = cause_of(
            trip(TripKind::Credential, Some("aws"), None, "git.example"),
            mode,
        )
        .unwrap();
        assert_eq!(credential.source, TripSource::Workload);
        assert_eq!(credential.trap.as_deref(), Some("aws"));
        let unknown = cause_of(
            trip(
                TripKind::Denied,
                None,
                Some(TripClass::UnknownHost),
                "mirror.example",
            ),
            mode,
        )
        .unwrap();
        assert_eq!(unknown.class, Some(TripClass::UnknownHost));
        for c in [&route, &credential, &unknown] {
            assert_eq!(c.reportable(mode), Ok(()));
        }
        // The matcher's own names (G2) are trap names like any other.
        for reserved in ["body-expansion", "body-undecodable", "matcher-not-built"] {
            let c = cause_of(
                trip(TripKind::Credential, Some(reserved), None, "git.example"),
                mode,
            )
            .unwrap();
            assert_eq!(c.trap.as_deref(), Some(reserved));
        }
        // A host or a name that is not in the grammar: reported, as `invalid`, and still a use.
        let odd = cause_of(
            trip(
                TripKind::Credential,
                Some("AWS key"),
                None,
                "Git.Example/path?token=bait",
            ),
            mode,
        )
        .unwrap();
        assert_eq!(odd.target, Some(TripTarget::Host("invalid".into())));
        assert_eq!(odd.trap.as_deref(), Some("invalid"));
        assert_eq!(odd.reportable(mode), Ok(()));
        // What the proxy does not decide is no cause at all.
        for (kind, trap, class) in [
            (TripKind::Port, Some("redis"), None),
            (TripKind::Segment, None, Some(TripClass::PoolInbound)),
            (TripKind::Protocol, None, Some(TripClass::ForeignRoute)),
            (TripKind::Denied, None, Some(TripClass::LoopbackPort)),
            (TripKind::Denied, None, None),
            (TripKind::Route, None, None),
            (
                TripKind::Credential,
                Some("aws"),
                Some(TripClass::UnknownHost),
            ),
        ] {
            assert!(cause_of(trip(kind, trap, class, "git.example"), mode).is_none());
        }
    }

    /// The test's own uid, from a file it made: the admitted peer in these tests.
    fn own_uid(dir: &Path) -> u32 {
        let probe = dir.join("probe");
        std::fs::write(&probe, b"").unwrap();
        let uid = std::fs::metadata(&probe).unwrap().uid();
        std::fs::remove_file(&probe).unwrap();
        uid
    }

    fn drawn() -> ProxyTraps {
        ProxyTraps {
            mode: TripMode::Enforce,
            unknown_host: ClassAction::Report,
            routes: vec![mediatore_proto::trip::ProxyDecoyRoute {
                name: "vault".into(),
                host: "secrets.prod.internal".into(),
            }],
            bait: vec![],
        }
    }

    /// One line from the socket, parsed.
    async fn line(reader: &mut BufReader<tokio::net::unix::OwnedReadHalf>) -> Option<Vec<u8>> {
        tokio::time::timeout(Duration::from_secs(5), read_frame(reader))
            .await
            .expect("the guest answered in time")
            .ok()
            .flatten()
    }

    #[tokio::test]
    async fn the_socket_admits_the_sandbox_uid_and_refuses_any_other_peer() {
        let dir = tempfile::tempdir().unwrap();
        let me = own_uid(dir.path());
        // Another uid is the sandbox's: this test's own connection is refused, with nothing.
        let (trips, mut noted) = Trips::recording(TripMode::Enforce);
        let other = dir.path().join("other");
        let guard = serve_socket(&other, me.wrapping_add(1), drawn(), trips)
            .await
            .unwrap();
        let stream = tokio::net::UnixStream::connect(guard.path()).await.unwrap();
        let (read, mut write) = stream.into_split();
        let mut reader = BufReader::new(read);
        assert_eq!(line(&mut reader).await, None, "closed without the draw");
        let trip = br#"{"type":"trip","at":"2026-11-26T15:02:11Z","kind":"route","trap":"vault","host":"secrets.prod.internal"}"#;
        let _ = write.write_all(trip).await;
        let _ = write.write_all(b"\n").await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(noted.try_recv().is_err(), "and nothing it says is noted");
        drop(guard);

        // The sandbox uid is this test's: admitted, armed, heard.
        let (trips, mut noted) = Trips::recording(TripMode::Enforce);
        let mine = dir.path().join("mine");
        let mut guard = serve_socket(&mine, me, drawn(), trips).await.unwrap();
        let stream = tokio::net::UnixStream::connect(guard.path()).await.unwrap();
        let (read, mut write) = stream.into_split();
        let mut reader = BufReader::new(read);
        let arm = line(&mut reader).await.expect("the draw");
        assert_eq!(
            serde_json::from_slice::<GuestToProxy>(&arm).unwrap(),
            GuestToProxy::Arm(drawn())
        );
        write
            .write_all(b"{\"type\":\"armed\",\"patterns\":5}\n")
            .await
            .unwrap();
        assert_eq!(guard.armed(Duration::from_secs(5)).await.unwrap(), 5);
        write.write_all(trip).await.unwrap();
        write.write_all(b"\n").await.unwrap();
        let (cause, count) = tokio::time::timeout(Duration::from_secs(5), noted.recv())
            .await
            .unwrap()
            .expect("a noted cause");
        assert_eq!(count, 1);
        assert_eq!(
            (cause.kind, cause.trap.as_deref(), cause.source),
            (TripKind::Route, Some("vault"), TripSource::Drawn)
        );
        // The draw is handed over once: a second connection of the same uid gets nothing.
        let second = tokio::net::UnixStream::connect(guard.path()).await.unwrap();
        let mut second = BufReader::new(second.into_split().0);
        assert_eq!(line(&mut second).await, None);
    }

    #[tokio::test]
    async fn a_proxy_that_never_says_armed_is_an_arming_failure() {
        let dir = tempfile::tempdir().unwrap();
        let me = own_uid(dir.path());
        let (trips, _noted) = Trips::recording(TripMode::Enforce);
        let mut guard = serve_socket(&dir.path().join("t"), me, drawn(), trips)
            .await
            .unwrap();
        let err = guard.armed(Duration::from_millis(50)).await.unwrap_err();
        assert!(err.to_string().contains("did not arm"));
    }

    #[tokio::test]
    async fn the_socket_is_a_path_in_a_root_owned_directory_and_never_abstract() {
        let dir = tempfile::tempdir().unwrap();
        let me = own_uid(dir.path());
        let (trips, _noted) = Trips::recording(TripMode::Enforce);
        // A directory left group- and world-writable by an earlier run is made 0711 again,
        // and a stale socket in it is replaced.
        let held = dir.path().join("run").join("trap");
        std::fs::create_dir_all(&held).unwrap();
        std::fs::set_permissions(&held, std::fs::Permissions::from_mode(0o777)).unwrap();
        std::fs::write(held.join(TRAP_SOCKET_NAME), b"stale").unwrap();
        let guard = serve_socket(&held, me, drawn(), trips).await.unwrap();
        assert_eq!(guard.path(), held.join(TRAP_SOCKET_NAME));
        let socket = std::fs::symlink_metadata(guard.path()).unwrap();
        assert!(socket.file_type().is_socket(), "a name in the filesystem");
        assert_eq!(socket.mode() & 0o7777, SOCKET_MODE);
        let at = std::fs::metadata(&held).unwrap();
        assert_eq!(at.mode() & 0o7777, SOCKET_DIR_MODE);
        assert_eq!(
            at.uid(),
            socket.uid(),
            "the directory is the guest's own: root's in a guest"
        );
        let path = guard.path().to_owned();
        drop(guard);
        assert!(!path.exists(), "the path goes with the guard");

        // The rule itself: the guest's own, mode 0711, nothing else.
        assert_eq!(dir_fault(0, 0o040_711, 0), None);
        assert!(
            dir_fault(1234, 0o040_711, 0).is_some(),
            "the sandbox user's"
        );
        assert!(dir_fault(0, 0o040_777, 0).is_some(), "writable by others");
        assert!(
            dir_fault(0, 0o040_731, 0).is_some(),
            "writable by the group"
        );
        assert!(dir_fault(0, 0o041_711, 0).is_some());
        assert_eq!(
            mediatore_proto::trip::TRAP_SOCKET_DIR,
            "/run/mediatore-guest/trap"
        );
        assert!(!TRAP_SOCKET_NAME.starts_with('\0') && !TRAP_SOCKET_NAME.starts_with('@'));

        // A draw that does not fit one message cannot arm the proxy.
        let (trips, _noted) = Trips::recording(TripMode::Enforce);
        let mut huge = drawn();
        huge.routes[0].host = "h".repeat(TRAP_FRAME_MAX);
        assert!(serve_socket(&held, me, huge, trips).await.is_err());
    }

    #[tokio::test]
    async fn a_frame_over_the_bound_or_an_unknown_message_closes_the_connection() {
        let dir = tempfile::tempdir().unwrap();
        let me = own_uid(dir.path());
        let over = "x".repeat(TRAP_FRAME_MAX + 1);
        let cases: [&[u8]; 5] = [
            over.as_bytes(),
            b"{\"type\":\"disarm\"}\n",
            b"not json\n",
            // A field the message does not have.
            b"{\"type\":\"armed\",\"patterns\":5,\"extra\":1}\n",
            // A kind the proxy does not decide.
            b"{\"type\":\"trip\",\"at\":\"2026-11-26T15:02:11Z\",\"kind\":\"port\",\"trap\":\"redis\",\"host\":\"git.example\"}\n",
        ];
        for (n, case) in cases.into_iter().enumerate() {
            let (trips, mut noted) = Trips::recording(TripMode::Enforce);
            let at = dir.path().join(format!("case-{n}"));
            let guard = serve_socket(&at, me, drawn(), trips).await.unwrap();
            let stream = tokio::net::UnixStream::connect(guard.path()).await.unwrap();
            let (read, mut write) = stream.into_split();
            let mut reader = BufReader::new(read);
            assert!(line(&mut reader).await.is_some(), "the draw comes first");
            // The guest may close while the rest is still being written.
            let _ = write.write_all(case).await;
            assert_eq!(line(&mut reader).await, None, "the guest closed it");
            // And what follows on that connection is never read.
            let _ = write
                .write_all(b"{\"type\":\"trip\",\"at\":\"2026-11-26T15:02:11Z\",\"kind\":\"route\",\"trap\":\"vault\",\"host\":\"a.example\"}\n")
                .await;
            tokio::time::sleep(Duration::from_millis(30)).await;
            assert!(noted.try_recv().is_err());
        }
        // The bound itself: a message of exactly the bound is read, one byte more is not.
        let exact = format!("{}\n", "y".repeat(TRAP_FRAME_MAX));
        let mut reader = BufReader::new(exact.as_bytes());
        assert_eq!(
            read_frame(&mut reader).await.unwrap().map(|f| f.len()),
            Some(TRAP_FRAME_MAX)
        );
        let mut reader = BufReader::new(over.as_bytes());
        assert!(matches!(
            read_frame(&mut reader).await,
            Err(FrameFault::TooLong)
        ));
        let mut reader = BufReader::new(&b"half a message"[..]);
        assert!(matches!(
            read_frame(&mut reader).await,
            Err(FrameFault::Cut)
        ));
    }

    #[test]
    fn what_the_chain_dropped_is_a_class_by_its_destination_or_no_class_at_all() {
        let at = Timestamp::now();
        let to = |address: &str, port| Denied {
            address: address.parse().unwrap(),
            port,
            packets: 1,
        };
        let loopback = denied_cause(&to("127.0.0.1", 8080), at).unwrap();
        assert_eq!(loopback.class, Some(TripClass::LoopbackPort));
        assert_eq!(loopback.target, Some(TripTarget::Port(8080)));
        assert_eq!(
            denied_cause(&to("::1", 8080), at).unwrap().class,
            Some(TripClass::LoopbackPort)
        );
        for (address, shown) in [
            ("10.0.0.5", "10.0.0.5:80"),
            ("172.16.3.4", "172.16.3.4:80"),
            ("192.168.200.7", "192.168.200.7:80"),
            ("169.254.169.254", "169.254.169.254:80"),
            ("fd00::5", "[fd00::5]:80"),
            ("fe80::1", "[fe80::1]:80"),
        ] {
            let c = denied_cause(&to(address, 80), at).unwrap();
            assert_eq!(c.class, Some(TripClass::PrivateRange));
            assert_eq!(c.target, Some(TripTarget::Address(shown.to_owned())));
        }
        for c in [
            denied_cause(&to("127.0.0.1", 8080), at).unwrap(),
            denied_cause(&to("fd00::5", 80), at).unwrap(),
            denied_cause(&to("10.0.0.5", 80), at).unwrap(),
        ] {
            assert_eq!(c.reportable(TripMode::Enforce), Ok(()));
            assert_eq!((c.kind, c.source), (TripKind::Denied, TripSource::Workload));
        }
        // A public address the chain refused is a drop and a log line, and no class.
        assert_eq!(denied_cause(&to("203.0.113.9", 80), at), None);
        assert_eq!(denied_cause(&to("2001:db8::9", 80), at), None);
    }

    #[tokio::test]
    async fn the_reader_of_the_chain_notes_each_classed_destination_with_its_count() {
        let listing = |name: &str, elem: &str| {
            format!(
                r#"{{"nftables": [{{"metainfo": {{"json_schema_version": 1}}}}, {{"set": {{"family": "inet", "name": "{name}", "table": "mediatore_sandbox", "size": 1024{elem}}}}}]}}"#
            )
        };
        let four = listing(
            "denied4",
            r#", "elem": [{"elem": {"val": {"concat": ["10.0.0.5", 80]}, "counter": {"packets": 3, "bytes": 180}}}, {"elem": {"val": {"concat": ["203.0.113.9", 80]}, "counter": {"packets": 7, "bytes": 420}}}]"#,
        );
        let six = listing("denied6", "");
        let nft = Arc::new(FakeNft::answering([four.as_str(), six.as_str()]));
        let (trips, mut noted) = Trips::recording(TripMode::Shadow);
        let reader = watch_denied_with(nft.clone(), trips, Duration::from_millis(10));
        let (cause, count) = tokio::time::timeout(Duration::from_secs(5), noted.recv())
            .await
            .unwrap()
            .expect("a noted cause");
        assert_eq!(cause.class, Some(TripClass::PrivateRange));
        assert_eq!(
            cause.target,
            Some(TripTarget::Address("10.0.0.5:80".into()))
        );
        assert_eq!(count, 3);
        // The reads that follow fail (the recorder has no more listings): nothing is noted,
        // and the reader goes on.
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(noted.try_recv().is_err(), "the public address is no class");
        assert!(nft.calls().len() > 2, "it reads again after a failed read");
        drop(reader);
    }

    #[tokio::test]
    async fn a_body_the_matcher_could_not_finish_ends_nothing_and_is_not_reported_under_any_mode() {
        // The maintainer's decision 4 of 2026-11-27: `body-expansion` and `body-undecodable`
        // are the proxy refusing a request, never a use of a trap.
        for mode in [TripMode::Enforce, TripMode::Shadow] {
            let sink = Recorder::answering([]);
            let nft = Arc::new(FakeNft::default());
            let wire = armed(mode, DeniedSwitches::default(), sink.clone(), nft.clone());
            for trap in [
                crate::trapmatch::TRAP_EXPANSION,
                crate::trapmatch::TRAP_UNDECODABLE,
            ] {
                let refused = cause_of(
                    ProxyTrip {
                        at: Timestamp::now(),
                        kind: TripKind::Credential,
                        trap: Some(trap.to_owned()),
                        class: None,
                        host: "git.example".into(),
                    },
                    mode,
                )
                .expect("the socket takes the message");
                assert_eq!(wire.trips.shared.effect_of(&refused), TripEffect::Reported);
                wire.trips.note(refused);
            }
            assert!(wire.trips.flush(Duration::from_secs(5)).await);
            assert!(!wire.trips.is_tripped(), "nothing is ended");
            assert!(nft.calls().is_empty(), "nothing is cut");
            assert!(sink.posts().is_empty(), "nothing is reported to the broker");
            // A real bait match beside it still is what it was.
            let mut bait = cause();
            bait.kind = TripKind::Credential;
            bait.trap = Some("aws".into());
            bait.target = Some(TripTarget::Host("git.example".into()));
            bait.source = TripSource::Workload;
            let expected = if mode == TripMode::Enforce {
                TripEffect::Tripped
            } else {
                TripEffect::WouldTrip
            };
            assert_eq!(wire.trips.shared.effect_of(&bait), expected);
        }
    }

    #[test]
    fn with_no_tripwire_the_proxy_argv_is_byte_identical_to_before() {
        // ADR-0069 decision 5: under `off` there is no trap socket and the proxy is started
        // exactly as it was before the ADR. This is that argument list, whole.
        let files = crate::egress::EgressFiles {
            routes: "/mnt/sandbox/egress/routes.json".into(),
            gateways: "/mnt/sandbox/egress/gateways.json".into(),
            phantom: "/mnt/sandbox/egress/phantom".into(),
        };
        let args = crate::egress::command_args(
            "127.0.0.1:3128".parse().unwrap(),
            "https://198.51.100.1:3130",
            "/run/spire/sockets/agent.sock",
            &files,
            &crate::egress::UpstreamArgs {
                ca: None,
                min_tls: mediatore_proto::tls::UpstreamTls::Tls13,
            },
        );
        assert_eq!(
            args,
            [
                "egress-proxy",
                "--listen",
                "127.0.0.1:3128",
                "--mediatore-url",
                "https://198.51.100.1:3130",
                "--workload-api-socket",
                "/run/spire/sockets/agent.sock",
                "--routes",
                "/mnt/sandbox/egress/routes.json",
                "--gateways",
                "/mnt/sandbox/egress/gateways.json",
                "--phantom-file",
                "/mnt/sandbox/egress/phantom",
            ]
        );
        assert!(
            !args.iter().any(|a| a.contains("trap")),
            "no trap socket is named to a proxy that has none"
        );
    }

    #[test]
    fn a_use_is_judged_by_the_mode_and_the_switches() {
        let (enforce, _rx) = Trips::recording(TripMode::Enforce);
        let (shadow, _rx2) = Trips::recording(TripMode::Shadow);
        assert_eq!(enforce.shared.effect_of(&cause()), TripEffect::Tripped);
        assert_eq!(shadow.shared.effect_of(&cause()), TripEffect::WouldTrip);
        let denied = unknown_host("mirror.example");
        assert_eq!(enforce.shared.effect_of(&denied), TripEffect::Reported);
        assert_eq!(shadow.shared.effect_of(&denied), TripEffect::Reported);
        let mut segment = cause();
        segment.kind = TripKind::Segment;
        assert_eq!(
            enforce.shared.effect_of(&segment),
            TripEffect::Reported,
            "a segment event never ends anything"
        );
        assert_eq!(enforce.mode(), TripMode::Enforce);
    }
}
