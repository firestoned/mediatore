// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! A trip at the broker (ADR-0069 decisions 8 and 9, ADR-0070 decisions 6 and 8):
//! `POST /v1/me/trip`, where a guest reports the use of a trap over its node SVID, and
//! [`end_claim`], the one way a claim is ended for a trip, whichever ADR's event ended it.
//!
//! What is recorded of an event: one audit line, an entry folded into the claim's trip summary
//! (`status.tripwires`), and, for the event that ends the claim, `tripped` on its record. Never
//! a path, a query, a header, a body or a bait value: the wire type has no field that could
//! carry one, and a body with any other field is refused whole (decision 12).

use axum::Extension;
use axum::Json;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use jiff::Timestamp;
use mediatore_proto::trip::{
    ClassAction, TRIP_RETRY_AFTER_SECS, TripClass, TripEffect, TripEntry, TripEvent, TripKind,
    TripMode, TripReport, Tripped,
};
use mediatore_proto::{ClaimResponse, ErrorBody, error_code};
use mediatore_store::{ClaimRecord, Modified, NodeRecord, StoreError, modify_claim};
use mediatore_tls::PeerSpiffeId;
use uuid::Uuid;

use crate::{ApiError, AppState, Shared, node_of_peer, reconciler, store_error};

/// What [`end_claim`] found and did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ended {
    /// `tripped` was written by this call, and the claim released.
    Tripped,
    /// The record already carried a `tripped` (the first one wins, by compare and set): it is
    /// left as it is, and the claim is released, again if it already was.
    AlreadyTripped,
    /// The claim had ended already (released, or its record swept): nothing was written.
    NotLive,
    /// `tripped` could not be written (the store failed, or every attempt lost to another
    /// write) and the claim was released all the same: the audit line is the record.
    Unrecorded,
}

/// End claim `claim_uid` for a trip: the single way either ADR ends one (ADR-0069 decision 9,
/// ADR-0070 decision 6). It takes the facts of the event, not a request, so the trip route and
/// the classifier of `protocol` events call the same code.
///
/// In order: `tripped` is put on the record by compare and set, if the record carries none
/// (the first event to end a claim is the one kept); then the claim is released, the entry
/// retracted and the record revoked, as a release always is. A record that could not take
/// `tripped` is released all the same, and that is logged: a claim is never left running
/// because its record was busy. The `AgentSandbox` is not deleted: the sandbox's reconciler
/// sees `tripped` on the record, deletes the `VirtualMachineClaim` and marks the sandbox
/// `Failed` with `Tripped=True`, and the object stays for its owner to read until the
/// retention sweep deletes it (`store.retention_secs` after the release); an exit racing the
/// trip deletes nothing either.
///
/// Idempotent: a second call for a claim already tripped releases it again (which finishes a
/// release that failed half way) and one for a claim already ended does nothing.
///
/// # Errors
/// The release failed (the entry could not be retracted or the record revoked). `tripped` may
/// be on the record by then, and a record with it set issues nothing; the caller reports the
/// failure so that whoever sent the event sends it again.
pub(crate) async fn end_claim(
    st: &AppState,
    claim_uid: Uuid,
    tripped: Tripped,
) -> Result<Ended, ApiError> {
    let written = modify_claim(st.store.as_ref(), claim_uid, |mut fresh| {
        if fresh.tripped.is_some() {
            return None;
        }
        fresh.tripped = Some(tripped.clone());
        Some(fresh)
    })
    .await;
    let ended = match written {
        Ok(Modified::Written) => Ended::Tripped,
        Ok(Modified::Unchanged) => Ended::AlreadyTripped,
        Ok(Modified::Released) | Err(StoreError::NotFound(_)) => {
            tracing::debug!(%claim_uid, "a trip for a claim that has ended already; nothing to end");
            return Ok(Ended::NotLive);
        }
        Err(e) => {
            tracing::warn!(%claim_uid, error = %e, "tripped could not be put on the record; the claim is released all the same");
            Ended::Unrecorded
        }
    };
    if let Err(e) = reconciler(st).release(claim_uid).await {
        tracing::error!(%claim_uid, error = %e, "release after a trip failed; the claim is not released");
        return Err(ApiError::internal("the claim could not be released"));
    }
    tracing::warn!(
        %claim_uid,
        id = %tripped.id,
        kind = tripped.kind.as_str(),
        trap = tripped.trap.as_deref().unwrap_or_default(),
        class = tripped.class.map_or("", TripClass::as_str),
        target = %target_of(tripped.target.as_ref()),
        source = tripped.source.as_str(),
        recorded = ended != Ended::Unrecorded,
        "claim ended by a trip: entry retracted, record revoked (ADR-0069 decision 9)"
    );
    Ok(ended)
}

/// Fold `entries` into the trip summary of claim `claim_uid`. A fold that fails is logged and
/// nothing more: the audit line of each event has been written by then and stands as the
/// record (ADR-0069 decision 9), and no answer waits on the summary.
pub(crate) async fn fold(st: &AppState, claim_uid: Uuid, entries: &[TripEntry]) {
    if entries.is_empty() {
        return;
    }
    if let Err(e) = st
        .store
        .fold_trips(claim_uid, entries, Timestamp::now())
        .await
    {
        tracing::warn!(%claim_uid, entries = entries.len(), error = %e, "the trip summary could not be written; the audit lines stand");
    }
}

/// What the owner of a claim is shown of its trips on `GET /v1/claims/{name}`: `tripped` from
/// the record and the folded events from the store. A claim a trap ended is never `ready`,
/// whatever the sandbox's status still mirrors before the reconciler's next pass. A summary
/// that cannot be read is left out, said at `warn`; the rest of the answer does not wait on it.
pub(crate) async fn shown(st: &AppState, rec: &ClaimRecord, resp: &mut ClaimResponse) {
    resp.tripped.clone_from(&rec.tripped);
    if rec.tripped.is_some() {
        resp.ready = false;
    }
    resp.tripwires = match st.store.trips(rec.uid).await {
        Ok(summary) => summary,
        Err(e) => {
            tracing::warn!(claim_uid = %rec.uid, error = %e, "the trip summary could not be read; left out of the answer");
            None
        }
    };
}

/// A target for a log line: its host, port or address, whose grammar was checked; nothing
/// for none.
fn target_of(target: Option<&mediatore_proto::trip::TripTarget>) -> String {
    target.map(ToString::to_string).unwrap_or_default()
}

/// `400 invalid_trip`, with a detail that names the fault and nothing of the body.
fn invalid(fault: &'static str) -> ApiError {
    ApiError::bad_request(error_code::INVALID_TRIP, fault)
}

/// The body as a report that passes [`TripReport::validate`], or `400 invalid_trip`. Parsed
/// here, never by the JSON extractor, whose own refusals are `415` and `422` in its own words.
fn parse(body: &[u8]) -> Result<TripReport, ApiError> {
    // The parser's own message can quote what it could not read: a fixed one goes back.
    let report: TripReport =
        serde_json::from_slice(body).map_err(|_| invalid("the body is not a trip report"))?;
    report.validate().map_err(invalid)?;
    Ok(report)
}

/// The claim a node's report is about: its live one, else the newest it ever had.
struct NodeClaim {
    rec: ClaimRecord,
    /// Whether the claim may still be ended: it is the node's live claim.
    live: bool,
}

/// The claim of `node`: the live one, else the last one whose record is still kept (a report
/// can arrive after its claim ended), else none.
async fn claim_of(st: &AppState, node: &NodeRecord) -> Result<Option<NodeClaim>, ApiError> {
    match st.store.get_claim_by_node(&node.node_id).await {
        Ok(rec) => return Ok(Some(NodeClaim { rec, live: true })),
        Err(StoreError::NotFound(_)) => {}
        Err(e) => return Err(store_error(e)),
    }
    match st.store.last_claim_by_node(&node.node_id).await {
        Ok(rec) => Ok(Some(NodeClaim { rec, live: false })),
        Err(StoreError::NotFound(_)) => Ok(None),
        Err(e) => Err(store_error(e)),
    }
}

/// The limiter's key for a node with no claim: the first 128 bits of its EK hash. The
/// register holds only hashes of 64 hexadecimal characters; anything else shares one bucket.
fn node_key(ek_hash: &str) -> Uuid {
    ek_hash
        .get(..32)
        .and_then(|head| u128::from_str_radix(head, 16).ok())
        .map_or(Uuid::nil(), Uuid::from_u128)
}

/// `429 too_many_trips`, with `Retry-After`.
fn too_many() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, TRIP_RETRY_AFTER_SECS.to_string())],
        Json(ErrorBody {
            error: error_code::TOO_MANY_TRIPS.into(),
            detail: Some("two trip reports per second per claim".into()),
        }),
    )
        .into_response()
}

/// What an accepted event did. `segment` never ends anything (ADR-0070 decision 5); a
/// `denied` event follows its class's switch, and at `report` it is recorded without ending
/// anything, under `enforce` too (ADR-0069 decision 10); anything else ended the claim when
/// `enforcing`, and would have under `shadow`.
fn effect_of(st: &AppState, enforcing: bool, event: &TripEvent) -> TripEffect {
    let reported = match event.kind {
        TripKind::Segment | TripKind::Protocol => true,
        TripKind::Denied => {
            event
                .class
                .map_or(ClassAction::Report, |c| st.tripwires.denied.action(c))
                == ClassAction::Report
        }
        TripKind::Port | TripKind::Route | TripKind::Credential => false,
    };
    if reported {
        TripEffect::Reported
    } else if enforcing {
        TripEffect::Tripped
    } else {
        TripEffect::WouldTrip
    }
}

/// The audit line of one accepted event (ADR-0069 decision 9, ADR-0070 decision 8): the
/// record of it. At `warn` when `loud`, else at `info`. Every field is the broker's own or
/// was checked against its grammar: no path, query, header, body or bait value has a field.
fn audit(
    node: &NodeRecord,
    claim: Option<&ClaimRecord>,
    mode: TripMode,
    effect: TripEffect,
    event: &TripEvent,
    loud: bool,
) {
    let claim_uid = claim.map(|c| c.uid.to_string()).unwrap_or_default();
    let subject = claim.map_or("", |c| c.subject.id.as_str());
    let target = target_of(event.target.as_ref());
    let containment_ms = event
        .containment_ms
        .map(|ms| ms.to_string())
        .unwrap_or_default();
    macro_rules! line {
        ($level:ident) => {
            tracing::$level!(
                claim_uid = %claim_uid,
                subject = %subject,
                node = %node.node_id,
                id = %event.id,
                mode = mode.as_str(),
                effect = effect.as_str(),
                kind = event.kind.as_str(),
                trap = event.trap.as_deref().unwrap_or_default(),
                class = event.class.map_or("", TripClass::as_str),
                target = %target,
                source = event.source.as_str(),
                source_address = event.source_address.as_deref().unwrap_or_default(),
                count = event.count,
                containment_ms = %containment_ms,
                at = %event.at,
                "trip reported"
            )
        };
    }
    if loud {
        line!(warn);
    } else {
        line!(info);
    }
}

/// `POST /v1/me/trip` (ADR-0069 decision 8): a guest, over its node SVID, reports the use of
/// a trap. In order: `501` under `policy.traps: off`, for any body but a report of `segment`
/// events alone (ADR-0070 decision 8, amended 2026-11-27: the pool's host table exists with
/// gateways whatever `policy.traps` says, so its drops are recorded under `off` too, as audit
/// lines on no claim and nothing more); the peer must be a registered node, as on
/// `POST /v1/me/exit`; a body that is off in any part is `400 invalid_trip` and nothing of it is
/// recorded; two reports a second per claim, `429 too_many_trips` with `Retry-After` beyond,
/// under every mode. Then, for each event not seen before by its `id`: one audit line, and an entry in
/// the claim's trip summary, but for a `segment` event, which is the audit line alone and
/// names no claim. Under `enforce` the first event that ends the claim puts `tripped` on its
/// record and the claim is released ([`end_claim`]), before the summary is written.
///
/// The claim is the node's live one, else the last it had: a report for a claim that has
/// ended is `204` and only the summary changes. A node with no claim at all may report
/// `segment` events alone (ADR-0070 decision 8), which are audit lines and nothing more; any
/// other report from it is dropped, `204`, as a late exit is.
///
/// A report whose mode is not the broker's (`policy.traps` changed during the claim) is
/// followed where either says `enforce`: the VM has cut and killed already when the report
/// says so, and the operator wants claims ended when the broker does.
pub(crate) async fn trip(
    State(st): State<Shared>,
    headers: HeaderMap,
    peer: Option<Extension<PeerSpiffeId>>,
    body: Bytes,
) -> Result<Response, ApiError> {
    let configured = st.tripwires.mode.trip_mode();
    // Under off the body decides the answer before the peer is looked at: a report of segment
    // events alone goes on as under shadow, and anything else (an ADR-0069 event, a body that
    // is no report) is the `501` it always was, so the off broker's answer to every other body
    // is unchanged.
    let segments_under_off = match configured {
        Some(_) => None,
        None => match parse(&body) {
            Ok(report) if report.is_segment_only() => Some(report),
            _ => {
                return Err(ApiError::not_implemented(
                    "tripwires are off on this broker (policy.traps)",
                ));
            }
        },
    };
    let peer = peer.as_ref().map(|e| &e.0);
    let node = node_of_peer(&st, &headers, peer, crate::route::ME_TRIP).await?;
    let report = match segments_under_off.map_or_else(|| parse(&body), Ok) {
        Ok(report) => report,
        Err(refused) => {
            tracing::debug!(node = %node.node_id, fault = refused.body.detail.as_deref().unwrap_or_default(), "trip report refused: nothing of it is recorded");
            return Err(refused);
        }
    };
    let claim = claim_of(&st, &node).await?;
    let key = claim
        .as_ref()
        .map_or_else(|| node_key(&node.ek_hash), |c| c.rec.uid);
    if !st.tripwires.limiter.allow(key) {
        tracing::info!(node = %node.node_id, events = report.events.len(), "trip report rate-limited (ADR-0069 decision 8)");
        return Ok(too_many());
    }
    match (configured, claim) {
        (Some(configured), Some(claim)) => {
            record(&st, configured, &node, &claim, &report).await?;
        }
        // Under off the report is segment events alone (checked above): unattributed audit
        // lines, whether or not the node has a claim, exactly as `record` writes them.
        (None, _) | (Some(_), None) => record_without_a_claim(&st, &node, &report),
    }
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// A report from a node that never had a claim, or whose every record was swept, and any
/// report under `policy.traps: off` (which is `segment` events alone by then): `segment`
/// events are one audit line each at `warn` (ADR-0070 decision 8) and nothing else is kept;
/// a report with any other kind in it is dropped whole.
fn record_without_a_claim(st: &AppState, node: &NodeRecord, report: &TripReport) {
    if !report.is_segment_only() {
        tracing::debug!(node = %node.node_id, events = report.events.len(), "a node reported a trip with no claim bound, now or before; dropped");
        return;
    }
    for event in &report.events {
        if st.tripwires.seen.first_sight(event.id) {
            audit(node, None, report.mode, TripEffect::Reported, event, true);
        }
    }
}

/// A report about `claim`: the audit lines, the fold, and under `enforce` the end of the
/// claim. Deduplicated on each event's `id`, per replica: an event seen before is neither
/// logged nor folded again, and still ends a claim it should have ended and has not (a retry
/// after a release that failed).
///
/// A `segment` event is recorded unattributed (ADR-0070 decision 8): its audit line names no
/// claim and it is folded onto none, whatever the reporting VM runs, so that a neighbour
/// forging sources at a pool VM can neither speak for its claim nor evict that claim's own
/// entries. The release comes before the fold and never waits on it.
async fn record(
    st: &AppState,
    configured: TripMode,
    node: &NodeRecord,
    claim: &NodeClaim,
    report: &TripReport,
) -> Result<(), ApiError> {
    let rec = &claim.rec;
    let enforcing = configured == TripMode::Enforce || report.mode == TripMode::Enforce;
    // A segment report always says shadow: it ends nothing, by design, so under enforce it is
    // no sign that policy.traps changed during the claim.
    if report.mode != configured && !report.is_segment_only() {
        tracing::warn!(
            claim_uid = %rec.uid,
            node = %node.node_id,
            reported = report.mode.as_str(),
            configured = configured.as_str(),
            "a trip report was made under another mode than the broker's (policy.traps changed during the claim); enforce is followed where either says it"
        );
    }
    let mut entries = Vec::new();
    let mut ending: Option<&TripEvent> = None;
    for event in &report.events {
        if event.kind == TripKind::Segment {
            if st.tripwires.seen.first_sight(event.id) {
                audit(node, None, report.mode, TripEffect::Reported, event, true);
            }
            continue;
        }
        let mut effect = effect_of(st, enforcing, event);
        // A claim that ended for another reason was not ended by this event.
        if effect == TripEffect::Tripped && !claim.live && rec.tripped.is_none() {
            effect = TripEffect::Reported;
        }
        if effect == TripEffect::Tripped && ending.is_none() {
            ending = Some(event);
        }
        if !st.tripwires.seen.first_sight(event.id) {
            continue;
        }
        audit(node, Some(rec), report.mode, effect, event, enforcing);
        entries.push(TripEntry::of(event, effect));
    }
    // The end first, then the summary (ADR-0069 decision 9's order is `tripped`, then the
    // release): a release never waits on a status write. A failed release still lets the
    // summary be written, and is then the answer.
    let ended = match ending {
        Some(event) if claim.live => end_claim(st, rec.uid, Tripped::of(event, Timestamp::now()))
            .await
            .map(|_| ()),
        _ => Ok(()),
    };
    fold(st, rec.uid, &entries).await;
    ended
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    use axum::body::Body;
    use axum::http::Request;
    use jiff::SignedDuration;
    use mediatore_claims::sandbox::SandboxFrontDoor;
    use mediatore_proto::trip::{DeniedSwitches, TrapsBody, TrapsMode, TripSource, TripTarget};
    use mediatore_proto::{LogBatch, Me};
    use mediatore_store::{
        ClaimStore, LogAppend, LogChunk, LogLimits, LogStore, MemoryStore, PolicyFloor,
        SessionRecord,
    };
    use tower::ServiceExt as _;

    use super::*;
    use crate::sandbox_router;
    use crate::tests::{base_state, call, capture_logs, captured, claim, code, gateway_peer};
    use crate::tripwires::LOGS_AFTER_A_TRIP;

    const EK: &str = "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf00";
    const OTHER_EK: &str = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf00";
    const AT: &str = "2026-11-26T15:02:11.204Z";

    /// A store that forwards to a memory store, records the writes a trip makes in the order
    /// they arrive, and can be told to fail one of them.
    pub(crate) struct Ordered {
        pub(crate) inner: Arc<MemoryStore>,
        calls: Mutex<Vec<&'static str>>,
        /// Refuse every write of a record that carries `tripped`.
        refuse_tripped: AtomicBool,
        /// Fail this many releases before letting one through.
        fail_releases: Mutex<usize>,
        /// Refuse every fold.
        refuse_folds: AtomicBool,
        /// Once: put this `tripped` on the record right after a read of a node's claim, as a
        /// trip landing between a handler's read and its write does.
        trip_after_node_read: Mutex<Option<Tripped>>,
        /// Once: put this `tripped` on the record right after a write that carries an exit.
        trip_after_exit_write: Mutex<Option<Tripped>>,
    }

    impl Ordered {
        pub(crate) fn new() -> Arc<Self> {
            Arc::new(Self {
                inner: MemoryStore::shared(),
                calls: Mutex::new(Vec::new()),
                refuse_tripped: AtomicBool::new(false),
                fail_releases: Mutex::new(0),
                refuse_folds: AtomicBool::new(false),
                trip_after_node_read: Mutex::new(None),
                trip_after_exit_write: Mutex::new(None),
            })
        }

        /// Put `tripped` on claim `uid`'s record, by compare and set, without a release.
        async fn racing_trip(&self, uid: Uuid, tripped: Tripped) {
            let mut fresh = self.inner.get_claim(uid).await.unwrap();
            fresh.tripped = Some(tripped);
            self.inner.update_claim(fresh).await.unwrap();
            self.note("tripped (racing)");
        }

        fn note(&self, call: &'static str) {
            self.calls.lock().unwrap().push(call);
        }

        pub(crate) fn calls(&self) -> Vec<&'static str> {
            self.calls.lock().unwrap().clone()
        }
    }

    #[async_trait::async_trait]
    impl LogStore for Ordered {
        async fn append_logs(
            &self,
            rec: &ClaimRecord,
            batch: &LogBatch,
            limits: &LogLimits,
        ) -> Result<LogAppend, StoreError> {
            self.inner.append_logs(rec, batch, limits).await
        }
        async fn read_logs(
            &self,
            claim_uid: Uuid,
            since: Option<u64>,
        ) -> Result<LogChunk, StoreError> {
            self.inner.read_logs(claim_uid, since).await
        }
        async fn delete_logs(&self, claim_uid: Uuid) -> Result<(), StoreError> {
            self.inner.delete_logs(claim_uid).await
        }
        async fn sweep_logs(&self, before: Timestamp) -> Result<usize, StoreError> {
            self.inner.sweep_logs(before).await
        }
    }

    #[async_trait::async_trait]
    impl ClaimStore for Ordered {
        async fn put_claim(&self, rec: ClaimRecord) -> Result<(), StoreError> {
            self.inner.put_claim(rec).await
        }
        async fn get_claim(&self, uid: Uuid) -> Result<ClaimRecord, StoreError> {
            self.inner.get_claim(uid).await
        }
        async fn get_claim_by_name(
            &self,
            namespace: &str,
            name: &str,
        ) -> Result<ClaimRecord, StoreError> {
            self.inner.get_claim_by_name(namespace, name).await
        }
        async fn update_claim(&self, rec: ClaimRecord) -> Result<(), StoreError> {
            if rec.exit.is_some() && rec.tripped.is_none() {
                let (uid, racing) = (rec.uid, self.trip_after_exit_write.lock().unwrap().take());
                self.note("exit");
                self.inner.update_claim(rec).await?;
                if let Some(tripped) = racing {
                    self.racing_trip(uid, tripped).await;
                }
                return Ok(());
            }
            if rec.tripped.is_some() {
                if self.refuse_tripped.load(Ordering::SeqCst) {
                    self.note("tripped refused");
                    return Err(StoreError::Backend("the write failed".into()));
                }
                self.note("tripped");
            }
            self.inner.update_claim(rec).await
        }
        async fn revoke_claim(&self, uid: Uuid, at: Timestamp) -> Result<(), StoreError> {
            let failing = {
                let mut left = self.fail_releases.lock().unwrap();
                let failing = *left > 0;
                *left = left.saturating_sub(1);
                failing
            };
            if failing {
                self.note("release failed");
                return Err(StoreError::Backend("the release failed".into()));
            }
            self.note("release");
            self.inner.revoke_claim(uid, at).await
        }
        async fn get_claim_by_node(&self, node_id: &str) -> Result<ClaimRecord, StoreError> {
            let rec = self.inner.get_claim_by_node(node_id).await?;
            let racing = self.trip_after_node_read.lock().unwrap().take();
            if let Some(tripped) = racing {
                self.racing_trip(rec.uid, tripped).await;
            }
            Ok(rec)
        }
        async fn last_claim_by_node(&self, node_id: &str) -> Result<ClaimRecord, StoreError> {
            self.inner.last_claim_by_node(node_id).await
        }
        async fn fold_trips(
            &self,
            claim_uid: Uuid,
            delta: &[TripEntry],
            now: Timestamp,
        ) -> Result<(), StoreError> {
            if self.refuse_folds.load(Ordering::SeqCst) {
                self.note("fold refused");
                return Err(StoreError::Backend("the fold failed".into()));
            }
            self.note("fold");
            self.inner.fold_trips(claim_uid, delta, now).await
        }
        async fn trips(
            &self,
            claim_uid: Uuid,
        ) -> Result<Option<mediatore_proto::trip::TripSummary>, StoreError> {
            self.inner.trips(claim_uid).await
        }
        async fn list_claims(&self) -> Result<Vec<ClaimRecord>, StoreError> {
            self.inner.list_claims().await
        }
        async fn put_node(&self, rec: NodeRecord) -> Result<(), StoreError> {
            self.inner.put_node(rec).await
        }
        async fn get_node(&self, ek_hash: &str) -> Result<NodeRecord, StoreError> {
            self.inner.get_node(ek_hash).await
        }
        async fn get_node_by_dmi(&self, dmi_uuid: Uuid) -> Result<NodeRecord, StoreError> {
            self.inner.get_node_by_dmi(dmi_uuid).await
        }
        async fn ban_node(&self, ek_hash: &str) -> Result<(), StoreError> {
            self.inner.ban_node(ek_hash).await
        }
        async fn list_nodes(&self) -> Result<Vec<NodeRecord>, StoreError> {
            self.inner.list_nodes().await
        }
        async fn delete_node(&self, ek_hash: &str) -> Result<(), StoreError> {
            self.inner.delete_node(ek_hash).await
        }
        async fn sweep(&self, before: Timestamp) -> Result<usize, StoreError> {
            self.inner.sweep(before).await
        }
        async fn put_session(&self, rec: SessionRecord) -> Result<(), StoreError> {
            self.inner.put_session(rec).await
        }
        async fn take_session(
            &self,
            sandbox_uid: Uuid,
        ) -> Result<Option<SessionRecord>, StoreError> {
            self.inner.take_session(sandbox_uid).await
        }
        async fn take_delegations(
            &self,
            sandbox_uid: Uuid,
        ) -> Result<Vec<SessionRecord>, StoreError> {
            self.inner.take_delegations(sandbox_uid).await
        }
        async fn delete_session(&self, sandbox_uid: Uuid) -> Result<(), StoreError> {
            self.inner.delete_session(sandbox_uid).await
        }
        async fn sweep_sessions(&self, before: Timestamp) -> Result<usize, StoreError> {
            self.inner.sweep_sessions(before).await
        }
        async fn get_policy_floor(
            &self,
            namespace: &str,
            name: &str,
        ) -> Result<Option<PolicyFloor>, StoreError> {
            self.inner.get_policy_floor(namespace, name).await
        }
        async fn advance_policy_floor(
            &self,
            held: Option<&PolicyFloor>,
            next: PolicyFloor,
        ) -> Result<(), StoreError> {
            self.inner.advance_policy_floor(held, next).await
        }
        async fn ping(&self) -> Result<(), StoreError> {
            self.inner.ping().await
        }
    }

    /// A broker under `mode`, over a store that records what a trip writes, with one
    /// registered node and its bound, live claim: the state, the store, the node's SPIFFE ID
    /// and the claim's record.
    struct Rig {
        st: Shared,
        store: Arc<Ordered>,
        node: String,
        rec: ClaimRecord,
    }

    pub(crate) async fn register(st: &AppState, ek: &str) -> String {
        st.store
            .put_node(NodeRecord {
                ek_hash: ek.into(),
                node_id: st.naming.agent_id(ek),
                dmi_uuid: Uuid::new_v4(),
                hostname: "member-01".into(),
                provider: None,
                banned: false,
                registered_at: Timestamp::now(),
            })
            .await
            .unwrap();
        st.naming.node_id(ek)
    }

    async fn rig_with(mode: TrapsMode, set: impl FnOnce(&mut AppState)) -> Rig {
        let store = Ordered::new();
        let mut st = base_state();
        st.store = store.clone();
        st.tripwires.mode = mode;
        set(&mut st);
        let st: Shared = Arc::new(st);
        let node = register(&st, EK).await;
        let mut rec = claim(&[], Some(st.naming.agent_id(EK)));
        rec.expires_at = Some(Timestamp::now() + SignedDuration::from_hours(1));
        st.store.put_claim(rec.clone()).await.unwrap();
        Rig {
            st,
            store,
            node,
            rec,
        }
    }

    async fn rig(mode: TrapsMode) -> Rig {
        rig_with(mode, |_| {}).await
    }

    impl Rig {
        async fn post(&self, body: serde_json::Value) -> (StatusCode, serde_json::Value, String) {
            call(&self.st, "POST", "/v1/me/trip", Some(&self.node), body).await
        }

        async fn held(&self) -> ClaimRecord {
            self.store.inner.get_claim(self.rec.uid).await.unwrap()
        }

        async fn summary(&self) -> Option<mediatore_proto::trip::TripSummary> {
            self.store.inner.trips(self.rec.uid).await.unwrap()
        }

        /// Nothing of a trip is on the claim: no `tripped`, no summary, not released.
        async fn untouched(&self) -> bool {
            let held = self.held().await;
            held.tripped.is_none() && held.revoked_at.is_none() && self.summary().await.is_none()
        }
    }

    /// One event: `fields` over an id and a time.
    fn event(id: Uuid, fields: &serde_json::Value) -> serde_json::Value {
        let mut event = serde_json::json!({ "id": id, "at": AT });
        for (k, v) in fields.as_object().unwrap() {
            event[k] = v.clone();
        }
        event
    }

    fn port_event(id: Uuid) -> serde_json::Value {
        event(
            id,
            &serde_json::json!({ "kind": "port", "trap": "redis", "target": { "port": 6379 }, "source": "drawn" }),
        )
    }

    fn credential_event(id: Uuid) -> serde_json::Value {
        event(
            id,
            &serde_json::json!({ "kind": "credential", "trap": "aws", "target": { "host": "git.example" }, "source": "workload" }),
        )
    }

    fn unknown_host_event(id: Uuid) -> serde_json::Value {
        event(
            id,
            &serde_json::json!({ "kind": "denied", "class": "unknown_host", "target": { "host": "mirror.example" }, "source": "workload" }),
        )
    }

    fn segment_event(id: Uuid) -> serde_json::Value {
        event(
            id,
            &serde_json::json!({ "kind": "segment", "class": "pool_inbound", "target": { "port": 22 }, "source": "peer", "source_address": "192.0.2.7", "count": 3 }),
        )
    }

    fn report(mode: &str, events: &[serde_json::Value]) -> serde_json::Value {
        serde_json::json!({ "mode": mode, "events": events })
    }

    /// `POST /v1/me/trip` with the body and the headers as given, for what `call` does not
    /// send: a body that is no JSON, no content type, a header of the peer's own.
    async fn raw(st: &Shared, peer: &str, body: &str, extra: &[(&str, &str)]) -> Response {
        let mut req = Request::builder()
            .method("POST")
            .uri("/v1/me/trip")
            .header("x-mediatore-peer-spiffe-id", peer);
        for (k, v) in extra {
            req = req.header(*k, *v);
        }
        sandbox_router(st.clone())
            .oneshot(req.body(Body::from(body.to_owned())).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn the_trip_route_is_501_under_off() {
        let r = rig(TrapsMode::Off).await;
        let body = report("enforce", &[port_event(Uuid::new_v4())]);
        let gateway = gateway_peer();
        for peer in [Some(r.node.as_str()), Some(gateway.as_str()), None] {
            let (status, answer, _) = call(&r.st, "POST", "/v1/me/trip", peer, body.clone()).await;
            assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
            assert_eq!(code(&answer), "not_implemented");
        }
        // A body that is no report at all: still this answer, never a 400.
        let resp = raw(&r.st, &r.node, "not json", &[]).await;
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
        assert!(r.untouched().await, "nothing is recorded under off");
        assert!(r.store.calls().is_empty(), "and nothing is written");
        // Another method on the path is axum's 405, as on every route here.
        let (status, ..) = call(&r.st, "GET", "/v1/me/trip", Some(&r.node), body).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn a_segment_only_report_under_off_is_accepted_as_an_audit_line_and_nothing_more() {
        // ADR-0070 decision 8, amended 2026-11-27 (the pool's segment classes under off): the
        // host table exists with gateways whatever `policy.traps` says, so its drops are
        // recorded under off as under shadow, one audit line each, on no claim.
        capture_logs();
        let r = rig(TrapsMode::Off).await;
        let (status, ..) = r
            .post(report("shadow", &[segment_event(Uuid::new_v4())]))
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let logged = captured();
        let line = logged
            .lines()
            .find(|l| l.contains("trip reported"))
            .expect("an audit line");
        assert!(line.contains("WARN"), "said at warn, as under shadow");
        for field in [
            "kind=\"segment\"",
            "class=\"pool_inbound\"",
            "effect=\"reported\"",
            "claim_uid= ",
            "subject= ",
        ] {
            assert!(line.contains(field), "the line lacks {field}");
        }
        assert!(r.untouched().await, "nothing is put on the claim");
        assert!(r.store.calls().is_empty(), "and nothing is written");

        // From a node with no claim: the same.
        let other = register(&r.st, OTHER_EK).await;
        let resp = raw(
            &r.st,
            &other,
            &report("shadow", &[segment_event(Uuid::new_v4())]).to_string(),
            &[],
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // Any peer but a registered node is refused, as under shadow: never recorded.
        let unregistered =
            r.st.naming
                .node_id("e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff00");
        for peer in [
            gateway_peer(),
            r.st.naming.claim_id(r.rec.uid),
            unregistered,
        ] {
            let resp = raw(
                &r.st,
                &peer,
                &report("shadow", &[segment_event(Uuid::new_v4())]).to_string(),
                &[],
            )
            .await;
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        }
    }

    #[tokio::test]
    async fn a_report_with_any_adr_0069_event_under_off_is_still_501_and_nothing_is_recorded() {
        capture_logs();
        let r = rig(TrapsMode::Off).await;
        for events in [
            vec![segment_event(Uuid::new_v4()), port_event(Uuid::new_v4())],
            vec![credential_event(Uuid::new_v4())],
            vec![unknown_host_event(Uuid::new_v4())],
            vec![],
        ] {
            let (status, answer, _) = r.post(report("shadow", &events)).await;
            assert_eq!(status, StatusCode::NOT_IMPLEMENTED);
            assert_eq!(code(&answer), "not_implemented");
        }
        assert!(!captured().contains("trip reported"), "nothing is audited");
        assert!(r.untouched().await);
        assert_eq!(r.store.calls(), Vec::<&str>::new(), "nothing is written");
    }

    #[tokio::test]
    async fn segment_reports_under_off_keep_the_per_node_rate_limit() {
        let r = rig(TrapsMode::Off).await;
        let segment = || report("shadow", &[segment_event(Uuid::new_v4())]).to_string();
        for _ in 0..2 {
            let resp = raw(&r.st, &r.node, &segment(), &[]).await;
            assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        }
        let resp = raw(&r.st, &r.node, &segment(), &[]).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        // A node with no claim, keyed by its EK hash: its own bucket, limited the same way.
        let other = register(&r.st, OTHER_EK).await;
        for _ in 0..2 {
            let resp = raw(&r.st, &other, &segment(), &[]).await;
            assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        }
        let resp = raw(&r.st, &other, &segment(), &[]).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn a_body_that_is_off_in_any_part_is_400_and_nothing_is_recorded() {
        let r = rig(TrapsMode::Enforce).await;
        let good = port_event(Uuid::new_v4());
        let mut unknown_field = good.clone();
        unknown_field["path"] = "/secret-canary".into();
        let mut bad_target = credential_event(Uuid::new_v4());
        bad_target["target"] = serde_json::json!({ "host": "git.example/secret-canary" });
        let mut two_targets = good.clone();
        two_targets["target"] = serde_json::json!({ "port": 6379, "host": "git.example" });
        let protocol = event(
            Uuid::new_v4(),
            &serde_json::json!({ "kind": "protocol", "class": "foreign_route", "target": { "host": "git.example" }, "source": "peer" }),
        );
        let too_many: Vec<serde_json::Value> =
            (0..33).map(|_| port_event(Uuid::new_v4())).collect();
        let bodies = [
            report("enforce", &[unknown_field]),
            report("enforce", &[bad_target]),
            report("enforce", &[two_targets]),
            report("enforce", &[protocol]),
            report("enforce", &too_many),
            report("enforce", &[]),
            report("off", std::slice::from_ref(&good)),
            serde_json::json!({ "mode": "enforce", "events": [good.clone()], "extra": true }),
            // One good event beside a bad one: the report is refused whole.
            report(
                "enforce",
                &[good.clone(), serde_json::json!({ "id": "not-a-uuid" })],
            ),
        ];
        // More bodies than the rate limit would take: a refused body spends nothing of it.
        for body in bodies {
            let (status, answer, text) = r.post(body).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_eq!(code(&answer), "invalid_trip");
            assert!(
                !text.contains("secret-canary"),
                "the answer quotes nothing of the body"
            );
        }
        // No JSON at all, and JSON with no content type that says so: the handler's own 400,
        // never the extractor's 415 or 422.
        for (body, headers) in [
            ("not json", vec![("content-type", "application/json")]),
            ("", vec![]),
            (
                "{\"mode\":\"enforce\"}",
                vec![("content-type", "text/plain")],
            ),
        ] {
            let resp = raw(&r.st, &r.node, body, &headers).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        }
        assert!(
            r.untouched().await,
            "nothing of a refused report is recorded"
        );
        assert_eq!(r.store.calls().len(), 0, "and nothing is written");
        // And a good report with no content type at all is read: the body is what counts.
        let body = report("enforce", &[good]).to_string();
        let resp = raw(&r.st, &r.node, &body, &[]).await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn a_trip_from_a_claim_identity_or_the_authorizer_is_403() {
        let r = rig(TrapsMode::Enforce).await;
        let body = report("enforce", &[port_event(Uuid::new_v4())]);
        let claim_id = r.st.naming.claim_id(r.rec.uid);
        let unregistered = r.st.naming.node_id(OTHER_EK);
        let plain_gateway = r.st.naming.gateway_id();
        for peer in [
            claim_id.as_str(),
            gateway_peer().as_str(),
            plain_gateway.as_str(),
            unregistered.as_str(),
            "spiffe://elsewhere.test/banlieue/node/abc",
        ] {
            let (status, answer, _) =
                call(&r.st, "POST", "/v1/me/trip", Some(peer), body.clone()).await;
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_eq!(code(&answer), "forbidden");
        }
        let (status, ..) = call(&r.st, "POST", "/v1/me/trip", None, body.clone()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "no peer identity at all");
        // Another node, registered, with no claim of its own: its report ends nothing of this
        // node's claim and records nothing on it.
        let other = register(&r.st, OTHER_EK).await;
        let (status, ..) = call(&r.st, "POST", "/v1/me/trip", Some(&other), body).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(
            r.untouched().await,
            "another node's report ends nothing here"
        );
        assert_eq!(r.store.calls().len(), 0, "and nothing is written");
    }

    #[tokio::test]
    async fn a_trip_under_enforce_writes_tripped_then_releases_in_that_order() {
        let r = rig(TrapsMode::Enforce).await;
        let id = Uuid::new_v4();
        let mut used = credential_event(id);
        used["containment_ms"] = 41.into();
        let before = Timestamp::now();
        let (status, _, text) = r.post(report("enforce", &[used])).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(text, "", "no body");
        assert_eq!(
            r.store.calls(),
            vec!["tripped", "release", "fold"],
            "tripped by compare and set, the release, then the summary: the release never waits on the summary"
        );
        let held = r.held().await;
        let tripped = held.tripped.expect("tripped is on the record");
        assert_eq!(tripped.id, id);
        assert_eq!(tripped.kind, TripKind::Credential);
        assert_eq!(tripped.trap.as_deref(), Some("aws"));
        assert_eq!(tripped.class, None);
        assert_eq!(tripped.target, Some(TripTarget::Host("git.example".into())));
        assert_eq!(tripped.source, TripSource::Workload);
        assert_eq!(tripped.at, AT.parse::<Timestamp>().unwrap());
        assert!(tripped.recorded_at >= before && tripped.recorded_at <= Timestamp::now());
        assert!(held.revoked_at.is_some(), "the claim is released");
        let summary = r.summary().await.expect("a summary");
        assert_eq!(summary.entries.len(), 1);
        assert_eq!(summary.entries[0].effect, TripEffect::Tripped);
        assert_eq!(summary.entries[0].containment_ms, Some(41));
        assert_eq!(summary.entries[0].count, 1);
    }

    #[tokio::test]
    async fn a_trip_under_shadow_records_would_trip_and_ends_nothing() {
        let r = rig(TrapsMode::Shadow).await;
        let mut twice = port_event(Uuid::new_v4());
        twice["count"] = 2.into();
        let events = vec![
            twice,
            credential_event(Uuid::new_v4()),
            unknown_host_event(Uuid::new_v4()),
        ];
        let (status, ..) = r.post(report("shadow", &events)).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(r.store.calls(), vec!["fold"], "one write, of the summary");
        let held = r.held().await;
        assert!(held.tripped.is_none() && held.revoked_at.is_none());
        let summary = r.summary().await.expect("a summary");
        assert_eq!(summary.entries.len(), 3);
        let effect_of = |kind: TripKind| {
            summary
                .entries
                .iter()
                .find(|e| e.kind == kind)
                .map(|e| (e.effect, e.count))
        };
        assert_eq!(effect_of(TripKind::Port), Some((TripEffect::WouldTrip, 2)));
        assert_eq!(
            effect_of(TripKind::Credential),
            Some((TripEffect::WouldTrip, 1))
        );
        // A class at `report` would end nothing under enforce either: it says `reported`.
        assert_eq!(effect_of(TripKind::Denied), Some((TripEffect::Reported, 1)));
        // A containment figure is refused on a shadow report: nothing was contained.
        let mut contained = port_event(Uuid::new_v4());
        contained["containment_ms"] = 41.into();
        let (status, ..) = r.post(report("shadow", &[contained])).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn a_denied_event_at_report_ends_nothing_under_enforce_and_one_at_trip_ends_the_claim() {
        // Every class at `report`, the default.
        let r = rig(TrapsMode::Enforce).await;
        let (status, ..) = r
            .post(report("enforce", &[unknown_host_event(Uuid::new_v4())]))
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let held = r.held().await;
        assert!(held.tripped.is_none() && held.revoked_at.is_none());
        assert_eq!(
            r.summary().await.expect("a summary").entries[0].effect,
            TripEffect::Reported
        );
        assert_eq!(r.store.calls(), vec!["fold"]);

        // `unknown_host` moved to `trip`; the other two classes stay at `report`.
        let r = rig_with(TrapsMode::Enforce, |st| {
            st.tripwires.denied = DeniedSwitches {
                unknown_host: ClassAction::Trip,
                ..DeniedSwitches::default()
            };
        })
        .await;
        let loopback = event(
            Uuid::new_v4(),
            &serde_json::json!({ "kind": "denied", "class": "loopback_port", "target": { "port": 8080 }, "source": "workload" }),
        );
        let (status, ..) = r.post(report("enforce", &[loopback])).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(r.held().await.revoked_at.is_none(), "a class at report");
        let id = Uuid::new_v4();
        let (status, ..) = r.post(report("enforce", &[unknown_host_event(id)])).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let held = r.held().await;
        let tripped = held.tripped.expect("a class at trip ends the claim");
        assert_eq!(tripped.id, id);
        assert_eq!(tripped.kind, TripKind::Denied);
        assert_eq!(tripped.class, Some(TripClass::UnknownHost));
        assert_eq!(tripped.trap, None);
        assert!(held.revoked_at.is_some());
    }

    #[tokio::test]
    async fn a_repeated_id_is_recorded_once() {
        capture_logs();
        let r = rig(TrapsMode::Shadow).await;
        let body = report("shadow", &[port_event(Uuid::new_v4())]);
        for _ in 0..2 {
            let (status, ..) = r.post(body.clone()).await;
            assert_eq!(
                status,
                StatusCode::NO_CONTENT,
                "a retry is answered as the first"
            );
        }
        let summary = r.summary().await.expect("a summary");
        assert_eq!(summary.entries.len(), 1);
        assert_eq!(
            summary.entries[0].count, 1,
            "the retry is not counted again"
        );
        assert_eq!(r.store.calls(), vec!["fold"], "and writes nothing");
        assert_eq!(
            captured().matches("trip reported").count(),
            1,
            "one audit line for one event"
        );
        assert_eq!(r.st.tripwires.seen.len(), 1);
    }

    #[tokio::test]
    async fn a_second_trip_for_a_tripped_claim_is_204_and_only_the_status_changes() {
        let r = rig(TrapsMode::Enforce).await;
        let first = Uuid::new_v4();
        let (status, ..) = r.post(report("enforce", &[port_event(first)])).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let ended = r.held().await;
        assert!(ended.revoked_at.is_some());

        let (status, ..) = r
            .post(report("enforce", &[credential_event(Uuid::new_v4())]))
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let after = r.held().await;
        assert_eq!(
            after.tripped.as_ref().map(|t| t.id),
            Some(first),
            "the first event to end the claim is the one kept"
        );
        assert_eq!(after.revoked_at, ended.revoked_at);
        assert_eq!(
            r.store.calls(),
            vec!["tripped", "release", "fold", "fold"],
            "the second report writes the summary and nothing else"
        );
        let summary = r.summary().await.expect("a summary");
        assert_eq!(summary.entries.len(), 2);
        assert!(
            summary
                .entries
                .iter()
                .all(|e| e.effect == TripEffect::Tripped)
        );
    }

    #[tokio::test]
    async fn a_trip_for_a_claim_that_ended_for_another_reason_is_reported_and_ends_nothing() {
        let r = rig(TrapsMode::Enforce).await;
        r.store
            .inner
            .revoke_claim(r.rec.uid, Timestamp::now())
            .await
            .unwrap();
        let (status, ..) = r
            .post(report("enforce", &[port_event(Uuid::new_v4())]))
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(r.store.calls(), vec!["fold"]);
        assert!(
            r.held().await.tripped.is_none(),
            "it was not ended by a trap"
        );
        assert_eq!(
            r.summary().await.expect("a summary").entries[0].effect,
            TripEffect::Reported
        );
    }

    #[tokio::test]
    async fn the_third_batch_in_a_second_is_429_with_retry_after() {
        let r = rig(TrapsMode::Shadow).await;
        let one = || report("shadow", &[port_event(Uuid::new_v4())]).to_string();
        for _ in 0..2 {
            let resp = raw(&r.st, &r.node, &one(), &[]).await;
            assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        }
        let resp = raw(&r.st, &r.node, &one(), &[]).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            resp.headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok()),
            Some("1")
        );
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap();
        let answer: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(code(&answer), "too_many_trips");
        assert_eq!(
            r.summary().await.expect("a summary").entries[0].count,
            2,
            "the refused batch is not recorded"
        );
        // A node with no claim has a bucket of its own, keyed by its EK hash.
        let other = register(&r.st, OTHER_EK).await;
        let segment = || report("shadow", &[segment_event(Uuid::new_v4())]).to_string();
        for _ in 0..2 {
            let resp = raw(&r.st, &other, &segment(), &[]).await;
            assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        }
        let resp = raw(&r.st, &other, &segment(), &[]).await;
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_ne!(node_key(EK), node_key(OTHER_EK));
        assert_eq!(node_key("not a hash"), Uuid::nil());
    }

    #[tokio::test]
    async fn a_segment_event_from_a_node_with_no_claim_is_accepted_and_any_other_kind_is_dropped() {
        capture_logs();
        let r = rig(TrapsMode::Shadow).await;
        let other = register(&r.st, OTHER_EK).await;
        let post = |body: serde_json::Value| {
            let st = r.st.clone();
            let other = other.clone();
            async move { call(&st, "POST", "/v1/me/trip", Some(&other), body).await }
        };
        // A segment event alone: one audit line, at warn, with no claim to name.
        let (status, ..) = post(report("shadow", &[segment_event(Uuid::new_v4())])).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let logged = captured();
        let line = logged
            .lines()
            .find(|l| l.contains("trip reported"))
            .expect("an audit line");
        assert!(line.contains("WARN"), "a segment event is said at warn");
        for field in [
            "kind=\"segment\"",
            "class=\"pool_inbound\"",
            "effect=\"reported\"",
            "target=22",
            "source=\"peer\"",
            "source_address=\"192.0.2.7\"",
            "count=3",
        ] {
            assert!(line.contains(field), "the line lacks a field");
        }
        // Any other kind from a node with no claim, alone or beside a segment event: dropped.
        capture_logs();
        let (status, ..) = post(report("shadow", &[port_event(Uuid::new_v4())])).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(!captured().contains("trip reported"), "nothing is recorded");
        assert!(r.untouched().await);
        assert!(r.store.calls().is_empty(), "no claim, nothing written");
    }

    #[tokio::test]
    async fn segment_events_from_a_node_with_a_live_claim_are_never_put_on_its_summary() {
        // ADR-0070 decision 8 (S6 of the review): a segment event is recorded unattributed,
        // an audit line and nothing else, whichever claim the reporting VM runs. A neighbour
        // that forges sources at a pool VM must not evict the claim's own evidence.
        let r = rig(TrapsMode::Shadow).await;
        let (status, ..) = r
            .post(report("shadow", &[port_event(Uuid::new_v4())]))
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let before = r.summary().await.expect("the claim's own entry");
        assert_eq!(before.entries.len(), 1);
        let calls = r.store.calls().len();
        capture_logs();
        // More forged sources than the summary holds entries, in one report.
        let forged: Vec<serde_json::Value> = (0..mediatore_proto::trip::MAX_TRIP_EVENTS)
            .map(|n| {
                let mut e = segment_event(Uuid::new_v4());
                e["source_address"] = format!("198.51.100.{n}").into();
                e
            })
            .collect();
        let (status, ..) = r.post(report("shadow", &forged)).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(
            r.summary().await,
            Some(before),
            "the claim's summary is unchanged and its own entry not evicted"
        );
        assert_eq!(r.store.calls().len(), calls, "nothing is written");
        let held = r.held().await;
        assert!(held.tripped.is_none() && held.revoked_at.is_none());
        let logged = captured();
        let lines: Vec<&str> = logged
            .lines()
            .filter(|l| l.contains("trip reported"))
            .collect();
        assert_eq!(lines.len(), forged.len(), "one audit line an event");
        for line in lines {
            assert!(line.contains("WARN") && line.contains("kind=\"segment\""));
            assert!(
                line.contains("claim_uid= ") && line.contains("subject= "),
                "unattributed: no claim is named"
            );
        }

        // The same under enforce: still nothing on the summary, and nothing ended.
        let r = rig(TrapsMode::Enforce).await;
        let (status, ..) = r
            .post(report("shadow", &[segment_event(Uuid::new_v4())]))
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(r.untouched().await);
        assert_eq!(r.store.calls(), Vec::<&str>::new(), "nothing is written");
    }

    #[tokio::test]
    async fn a_segment_report_under_an_enforce_broker_is_no_mode_mismatch() {
        // A segment report always says shadow (it ends nothing, by design): under enforce
        // that is no sign that policy.traps changed during the claim.
        capture_logs();
        let r = rig(TrapsMode::Enforce).await;
        let (status, ..) = r
            .post(report("shadow", &[segment_event(Uuid::new_v4())]))
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let logged = captured();
        assert!(logged.contains("trip reported"), "the capture is live");
        assert!(!logged.contains("another mode than the broker's"));
        // Any other kind under the other mode still says so.
        capture_logs();
        let (status, ..) = r
            .post(report("shadow", &[port_event(Uuid::new_v4())]))
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(captured().contains("another mode than the broker's"));
    }

    #[tokio::test]
    async fn a_tripped_record_gets_no_token_before_its_release_lands() {
        // `tripped` is written and the release has not landed: the window between the two.
        let r = rig(TrapsMode::Enforce).await;
        let mut held = r.held().await;
        held.tripped = Some(Tripped {
            id: Uuid::new_v4(),
            at: Timestamp::now(),
            recorded_at: Timestamp::now(),
            kind: TripKind::Port,
            trap: Some("redis".into()),
            class: None,
            target: Some(TripTarget::Port(6379)),
            source: TripSource::Drawn,
        });
        r.store.inner.update_claim(held).await.unwrap();
        assert!(r.held().await.revoked_at.is_none(), "not released yet");
        let claim_id = r.st.naming.claim_id(r.rec.uid);
        let token = serde_json::json!({ "audience": "grafana" });
        let gateway = gateway_peer();
        let uid = r.rec.uid;
        let asks = [
            (
                "POST",
                "/v1/token".to_owned(),
                claim_id.clone(),
                token.clone(),
            ),
            (
                "GET",
                "/v1/me".to_owned(),
                r.node.clone(),
                serde_json::Value::Null,
            ),
            (
                "GET",
                format!("/v1/gateway/claims/{uid}"),
                gateway.clone(),
                serde_json::Value::Null,
            ),
            (
                "POST",
                format!("/v1/gateway/claims/{uid}/credential"),
                gateway.clone(),
                token.clone(),
            ),
        ];
        let mut tripped_answers = Vec::new();
        for (method, uri, peer, body) in &asks {
            let (status, answer, _) = call(&r.st, method, uri, Some(peer), body.clone()).await;
            tripped_answers.push((status, answer));
        }
        assert_eq!(tripped_answers[0].0, StatusCode::FORBIDDEN, "no token");
        assert_eq!(
            tripped_answers[1].0,
            StatusCode::NOT_FOUND,
            "no claim to run"
        );
        assert_eq!(code(&tripped_answers[1].1), "no_claim");
        assert_eq!(
            tripped_answers[2].0,
            StatusCode::NOT_FOUND,
            "the gateway denies"
        );
        assert_eq!(tripped_answers[3].0, StatusCode::NOT_FOUND, "no credential");
        // An exit for a tripped claim has nothing to end, and is no error for the guest: the
        // release is the trip's own.
        let exit = serde_json::json!({ "code": 0, "restarts": 0 });
        let (status, ..) = call(&r.st, "POST", "/v1/me/exit", Some(&r.node), exit).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(r.held().await.exit.is_none());
        // Each is, to the byte, what a released claim is told.
        r.store
            .inner
            .revoke_claim(uid, Timestamp::now())
            .await
            .unwrap();
        for ((method, uri, peer, body), tripped) in asks.iter().zip(&tripped_answers) {
            let (status, answer, _) = call(&r.st, method, uri, Some(peer), body.clone()).await;
            assert!(
                (status, &answer) == (tripped.0, &tripped.1),
                "a tripped claim is answered as a released one"
            );
        }
    }

    #[tokio::test]
    async fn me_carries_the_mode_and_the_denied_switches_and_nothing_under_off() {
        let r = rig_with(TrapsMode::Shadow, |st| {
            st.tripwires.denied.unknown_host = ClassAction::Trip;
        })
        .await;
        let (status, answer, _) = call(
            &r.st,
            "GET",
            "/v1/me",
            Some(&r.node),
            serde_json::Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            answer["traps"],
            serde_json::json!({
                "mode": "shadow",
                "denied": { "loopback_port": "report", "private_range": "report", "unknown_host": "trip" },
            }),
            "the mode and the switches, and no catalogue: no bundle carries one"
        );
        let me: Me = serde_json::from_value(answer).unwrap();
        assert_eq!(me.traps.map(|t| t.mode), Some(TrapsMode::Shadow));

        let r = rig(TrapsMode::Enforce).await;
        let (_, answer, _) = call(
            &r.st,
            "GET",
            "/v1/me",
            Some(&r.node),
            serde_json::Value::Null,
        )
        .await;
        assert_eq!(answer["traps"]["mode"], "enforce");

        // Off: the answer is byte for byte what it was before tripwires existed.
        let r = rig(TrapsMode::Off).await;
        let (status, answer, text) = call(
            &r.st,
            "GET",
            "/v1/me",
            Some(&r.node),
            serde_json::Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(answer.get("traps").is_none());
        assert!(!text.contains("traps"));
    }

    #[tokio::test]
    async fn a_route_of_an_audience_marked_skip_says_so_and_no_other_does() {
        let r = rig_with(TrapsMode::Enforce, |st| {
            st.audiences = vec!["model".into(), "git".into()];
            st.egress
                .insert("model".into(), vec!["model.example:443".parse().unwrap()]);
            st.egress
                .insert("git".into(), vec!["git.example:443".parse().unwrap()]);
            st.tripwires.body_skip.insert("model".into());
        })
        .await;
        let mut rec = r.held().await;
        rec.audiences = vec!["model".into(), "git".into()];
        r.store.inner.update_claim(rec).await.unwrap();
        let (status, answer, _) = call(
            &r.st,
            "GET",
            "/v1/me",
            Some(&r.node),
            serde_json::Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let me: Me = serde_json::from_value(answer.clone()).unwrap();
        let body_of = |audience: &str| {
            me.routes
                .iter()
                .find(|route| route.audience.as_deref() == Some(audience))
                .map(|route| route.traps_body)
        };
        assert_eq!(body_of("model"), Some(TrapsBody::Skip));
        assert_eq!(body_of("git"), Some(TrapsBody::Match));
        let routes = answer["routes"].as_array().unwrap();
        assert_eq!(
            routes
                .iter()
                .filter(|r| r.get("traps_body").is_some())
                .count(),
            1,
            "match stays off the wire"
        );
    }

    #[tokio::test]
    async fn the_audit_line_names_the_event_and_never_a_path_a_header_or_a_value() {
        capture_logs();
        let r = rig(TrapsMode::Enforce).await;
        let id = Uuid::new_v4();
        let mut used = credential_event(id);
        used["containment_ms"] = 41.into();
        let body = report("enforce", &[used]).to_string();
        // A header of the peer's own rides along: it is no part of the report.
        let resp = raw(
            &r.st,
            &r.node,
            &body,
            &[
                ("x-canary", "header-canary-0b1c"),
                ("authorization", "Bearer token-canary-7f3e"),
            ],
        )
        .await;
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        let logged = captured();
        let line = logged
            .lines()
            .find(|l| l.contains("trip reported"))
            .expect("an audit line");
        assert!(line.contains("WARN"), "at warn under enforce");
        let uid = r.rec.uid.to_string();
        for field in [
            format!("claim_uid={uid}"),
            "subject=octocat".to_owned(),
            format!("id={id}"),
            "mode=\"enforce\"".to_owned(),
            "effect=\"tripped\"".to_owned(),
            "kind=\"credential\"".to_owned(),
            "trap=\"aws\"".to_owned(),
            "target=git.example".to_owned(),
            "source=\"workload\"".to_owned(),
            "count=1".to_owned(),
            "containment_ms=41".to_owned(),
        ] {
            assert!(line.contains(&field), "the audit line lacks a field");
        }
        assert!(
            logged.contains("claim ended by a trip"),
            "and the end of the claim is one line more"
        );
        // Refused reports: a path in a target, a value in a field the wire does not have, a
        // body that is no JSON. None of it reaches a line, at any level.
        let mut with_path = credential_event(Uuid::new_v4());
        with_path["target"] =
            serde_json::json!({ "host": "git.example/path-canary-55aa?q=query-canary-91c2" });
        let mut with_value = credential_event(Uuid::new_v4());
        with_value["value"] = "AKIACANARYVALUE0000".into();
        for body in [
            report("enforce", &[with_path]).to_string(),
            report("enforce", &[with_value]).to_string(),
            "body-canary-3d4e".to_owned(),
        ] {
            let resp = raw(&r.st, &r.node, &body, &[]).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        }
        let logged = captured();
        for canary in [
            "header-canary-0b1c",
            "token-canary-7f3e",
            "path-canary-55aa",
            "query-canary-91c2",
            "AKIACANARYVALUE0000",
            "body-canary-3d4e",
        ] {
            assert!(
                !logged.contains(canary),
                "something the peer sent is in a log line"
            );
        }

        // Under shadow the line is at info.
        capture_logs();
        let r = rig(TrapsMode::Shadow).await;
        let (status, ..) = r
            .post(report("shadow", &[port_event(Uuid::new_v4())]))
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let logged = captured();
        let line = logged
            .lines()
            .find(|l| l.contains("trip reported"))
            .expect("an audit line");
        assert!(line.contains("INFO") && line.contains("effect=\"would_trip\""));
        assert!(line.contains("target=6379") && line.contains("trap=\"redis\""));
    }

    #[tokio::test]
    async fn a_tripped_that_cannot_be_written_still_releases_the_claim() {
        capture_logs();
        let r = rig(TrapsMode::Enforce).await;
        r.store.refuse_tripped.store(true, Ordering::SeqCst);
        let (status, ..) = r
            .post(report("enforce", &[port_event(Uuid::new_v4())]))
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(r.store.calls(), vec!["tripped refused", "release", "fold"]);
        let held = r.held().await;
        assert!(
            held.revoked_at.is_some(),
            "released though tripped never landed"
        );
        assert!(held.tripped.is_none());
        let logged = captured();
        assert!(logged.contains("tripped could not be put on the record"));
        assert!(
            logged.contains("trip reported"),
            "the audit line is the record"
        );

        // A summary that cannot be written stops nothing either.
        let r = rig(TrapsMode::Enforce).await;
        r.store.refuse_folds.store(true, Ordering::SeqCst);
        let (status, ..) = r
            .post(report("enforce", &[port_event(Uuid::new_v4())]))
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(r.store.calls(), vec!["tripped", "release", "fold refused"]);
        let held = r.held().await;
        assert!(held.tripped.is_some() && held.revoked_at.is_some());
    }

    #[tokio::test]
    async fn a_retried_report_ends_a_claim_whose_release_failed_the_first_time() {
        let r = rig(TrapsMode::Enforce).await;
        *r.store.fail_releases.lock().unwrap() = 1;
        let id = Uuid::new_v4();
        let body = report("enforce", &[port_event(id)]);
        let (status, answer, text) = r.post(body.clone()).await;
        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "the guest sends it again"
        );
        assert_eq!(code(&answer), "internal");
        assert!(
            !text.contains("the release failed"),
            "the store's words stay in the log"
        );
        let held = r.held().await;
        assert!(held.tripped.is_some() && held.revoked_at.is_none());
        // The same report again: deduplicated for the line and the count, and it still ends
        // the claim it had not ended.
        let (status, ..) = r.post(body).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(
            r.store.calls(),
            vec!["tripped", "release failed", "fold", "release"]
        );
        let held = r.held().await;
        assert_eq!(held.tripped.map(|t| t.id), Some(id));
        assert!(held.revoked_at.is_some());
        assert_eq!(r.summary().await.expect("a summary").entries[0].count, 1);
    }

    #[tokio::test]
    async fn a_report_under_another_mode_than_the_brokers_follows_enforce_wherever_it_is_said() {
        // The broker moved to shadow during the claim; the VM has cut and killed already.
        capture_logs();
        let r = rig(TrapsMode::Shadow).await;
        let (status, ..) = r
            .post(report("enforce", &[port_event(Uuid::new_v4())]))
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let held = r.held().await;
        assert!(held.tripped.is_some() && held.revoked_at.is_some());
        assert!(captured().contains("another mode than the broker's"));
        // The broker moved to enforce during the claim; the guest was armed under shadow.
        let r = rig(TrapsMode::Enforce).await;
        let (status, ..) = r
            .post(report("shadow", &[port_event(Uuid::new_v4())]))
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let held = r.held().await;
        assert!(held.tripped.is_some() && held.revoked_at.is_some());
        assert_eq!(
            r.summary().await.expect("a summary").entries[0].effect,
            TripEffect::Tripped
        );
    }

    /// The `AgentSandbox` of the rig's claim, in `front`.
    async fn put_sandbox(r: &Rig, front: &mediatore_testkit::sandboxes::MemorySandboxes) {
        let sandbox = mediatore_claims::sandbox::AgentSandbox::new(
            &r.rec.name,
            mediatore_claims::sandbox::AgentSandboxSpec {
                subject: mediatore_claims::sandbox::SandboxSubject {
                    issuer: r.rec.subject.issuer.clone(),
                    id: r.rec.subject.id.clone(),
                    display: None,
                },
                pool_ref: Some(banlieue_api::common::LocalObjectReference {
                    name: "pool-a".into(),
                }),
                pool_selector: None,
                selection: None,
                ttl_seconds: 900,
                audiences: vec![],
                workload: mediatore_claims::sandbox::SandboxWorkload {
                    image: "registry.internal:5000/x:1".into(),
                    args: vec![],
                    restart: None,
                    logs: false,
                },
                policy_ref: None,
            },
        );
        let mut sandbox = sandbox;
        sandbox.metadata.namespace = Some(r.rec.namespace.clone());
        front.create(sandbox).await.unwrap();
    }

    /// Whether the rig's claim's `AgentSandbox` is still in `front`.
    async fn sandbox_kept(r: &Rig, front: &mediatore_testkit::sandboxes::MemorySandboxes) -> bool {
        front
            .get(&r.rec.namespace, &r.rec.name)
            .await
            .unwrap()
            .is_some()
    }

    fn a_trip() -> Tripped {
        Tripped {
            id: Uuid::new_v4(),
            at: Timestamp::now(),
            recorded_at: Timestamp::now(),
            kind: TripKind::Port,
            trap: Some("redis".into()),
            class: None,
            target: None,
            source: TripSource::Drawn,
        }
    }

    /// A rig outside `dev_mode`, where an exit releases by deleting the `AgentSandbox`, with
    /// the claim's sandbox in the returned front door.
    async fn kube_rig() -> (Rig, Arc<mediatore_testkit::sandboxes::MemorySandboxes>) {
        let front = Arc::new(mediatore_testkit::sandboxes::MemorySandboxes::default());
        let held = front.clone();
        let r = rig_with(TrapsMode::Enforce, move |st| {
            st.dev_mode = false;
            st.sandboxes = Some(held);
        })
        .await;
        put_sandbox(&r, &front).await;
        (r, front)
    }

    /// `POST /v1/me/exit` from the rig's node, over its SVID (no header outside `dev_mode`).
    async fn post_exit(r: &Rig) -> StatusCode {
        let mut req = Request::builder()
            .method("POST")
            .uri("/v1/me/exit")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({ "code": 0, "restarts": 0 }).to_string(),
            ))
            .unwrap();
        req.extensions_mut().insert(PeerSpiffeId(r.node.clone()));
        sandbox_router(r.st.clone())
            .oneshot(req)
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn an_honest_exit_still_deletes_the_sandbox() {
        let (r, front) = kube_rig().await;
        assert_eq!(post_exit(&r).await, StatusCode::NO_CONTENT);
        assert!(
            !sandbox_kept(&r, &front).await,
            "released through the AgentSandbox"
        );
        assert!(r.held().await.exit.is_some());
    }

    #[tokio::test]
    async fn a_pull_failure_exit_is_recorded_with_its_reason_and_releases_the_claim() {
        // ADR-0076 decision 4: the guest that could not pull the image ends the claim on the
        // exit route, with a reason from a closed set; the claim is released as for any exit.
        capture_logs();
        let (r, front) = kube_rig().await;
        let mut req = Request::builder()
            .method("POST")
            .uri("/v1/me/exit")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "restarts": 0,
                    "reason": { "kind": "pull_failed", "attempts": 3, "error": "unreachable" },
                })
                .to_string(),
            ))
            .unwrap();
        req.extensions_mut().insert(PeerSpiffeId(r.node.clone()));
        let status = sandbox_router(r.st.clone())
            .oneshot(req)
            .await
            .unwrap()
            .status();
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(!sandbox_kept(&r, &front).await, "released");
        let exit = r.held().await.exit.expect("the exit is on the record").exit;
        assert_eq!(
            exit.reason,
            Some(mediatore_proto::ExitReason::PullFailed {
                attempts: 3,
                error: mediatore_proto::PullError::Unreachable,
            })
        );
        assert_eq!((exit.code, exit.signal), (None, None));
        let logged = captured();
        let line = logged
            .lines()
            .find(|l| l.contains("could not be pulled"))
            .expect("the broker's line");
        assert!(line.contains("WARN") && line.contains("error=\"unreachable\""));
        assert!(line.contains("attempts=3"));

        // A reason outside the closed set is no exit: refused, nothing ends.
        let (r, front) = kube_rig().await;
        let mut req = Request::builder()
            .method("POST")
            .uri("/v1/me/exit")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({ "restarts": 0, "reason": { "kind": "pull_failed", "attempts": 1, "error": "see https://registry.example/v2/?token=x" } })
                    .to_string(),
            ))
            .unwrap();
        req.extensions_mut().insert(PeerSpiffeId(r.node.clone()));
        let status = sandbox_router(r.st.clone())
            .oneshot(req)
            .await
            .unwrap()
            .status();
        assert!(status.is_client_error(), "refused: {status}");
        assert!(sandbox_kept(&r, &front).await);
        assert!(r.held().await.exit.is_none());
    }

    #[tokio::test]
    async fn an_exit_racing_a_trip_writes_nothing_and_deletes_nothing() {
        // ADR-0069 decision 9 (decision 12 of the review round): the AgentSandbox of a
        // tripped record is never deleted but by the retention sweep.
        // The exit read the claim before the trip; `tripped` lands before the exit's write,
        // and the release has not landed yet.
        let (r, front) = kube_rig().await;
        let tripped = a_trip();
        *r.store.trip_after_node_read.lock().unwrap() = Some(tripped.clone());
        assert_eq!(post_exit(&r).await, StatusCode::NO_CONTENT);
        assert!(
            sandbox_kept(&r, &front).await,
            "the tripped sandbox is kept"
        );
        let held = r.held().await;
        assert_eq!(held.tripped, Some(tripped));
        assert!(
            held.exit.is_none(),
            "the exit is not written on a tripped record"
        );
        assert!(held.revoked_at.is_none(), "the exit released nothing");
        assert_eq!(r.store.calls(), ["tripped (racing)"]);

        // The reverse: the exit's write lands, then `tripped`, before the exit's delete.
        let (r, front) = kube_rig().await;
        *r.store.trip_after_exit_write.lock().unwrap() = Some(a_trip());
        assert_eq!(post_exit(&r).await, StatusCode::NO_CONTENT);
        assert!(
            sandbox_kept(&r, &front).await,
            "the tripped sandbox is kept"
        );
        let held = r.held().await;
        assert!(held.tripped.is_some() && held.exit.is_some());
        assert_eq!(r.store.calls(), ["exit", "tripped (racing)"]);

        // And an exit after `tripped` is written and before the release lands, read as such.
        let (r, front) = kube_rig().await;
        r.store.racing_trip(r.rec.uid, a_trip()).await;
        assert_eq!(post_exit(&r).await, StatusCode::NO_CONTENT);
        assert!(sandbox_kept(&r, &front).await);
        assert!(r.held().await.exit.is_none());
    }

    fn one_line(seq: u64) -> serde_json::Value {
        serde_json::to_value(LogBatch {
            records: vec![mediatore_proto::LogRecord {
                seq,
                stream: mediatore_proto::LogStream::Stdout,
                ts: Timestamp::now(),
                text: "the-last-line".into(),
                partial: false,
            }],
            ..LogBatch::default()
        })
        .unwrap()
    }

    async fn stored_lines(r: &Rig, uid: Uuid) -> usize {
        r.store
            .inner
            .read_logs(uid, None)
            .await
            .unwrap()
            .entries
            .len()
    }

    async fn logs_rig() -> Rig {
        let r = rig_with(TrapsMode::Enforce, |st| {
            st.logs = Some(LogLimits {
                max_bytes: mediatore_proto::DEFAULT_LOG_MAX_BYTES,
            });
        })
        .await;
        let mut rec = r.store.inner.get_claim(r.rec.uid).await.unwrap();
        rec.workload.logs = true;
        r.store.inner.update_claim(rec).await.unwrap();
        r
    }

    #[tokio::test]
    async fn a_tripped_claims_last_output_reaches_its_owner_when_the_trip_lands_first() {
        // ADR-0069 decision 7 step 4: the final line naming the trap and the output buffered
        // before the trip are flushed after the report, which ends the claim at once.
        let r = logs_rig().await;
        let (status, ..) = r
            .post(report("enforce", &[port_event(Uuid::new_v4())]))
            .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        let held = r.held().await;
        assert!(held.tripped.is_some() && held.revoked_at.is_some());
        let (status, _, text) =
            call(&r.st, "POST", "/v1/me/logs", Some(&r.node), one_line(1)).await;
        assert_eq!(status, StatusCode::NO_CONTENT, "{text}");
        assert_eq!(stored_lines(&r, r.rec.uid).await, 1, "stored for the owner");
        // From any other node: dropped, as for any node with no live claim.
        let other = register(&r.st, OTHER_EK).await;
        let (status, ..) = call(&r.st, "POST", "/v1/me/logs", Some(&other), one_line(2)).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(stored_lines(&r, r.rec.uid).await, 1);
        // The node is still handed no claim.
        let (status, ..) = call(
            &r.st,
            "GET",
            "/v1/me",
            Some(&r.node),
            serde_json::Value::Null,
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a_tripped_claims_output_is_dropped_after_the_grace_and_a_released_ones_always() {
        let r = logs_rig().await;
        let other = register(&r.st, OTHER_EK).await;
        let ended = |tripped_ago: Option<i64>| {
            let mut rec = claim(&[], Some(r.st.naming.agent_id(OTHER_EK)));
            rec.workload.logs = true;
            let now = Timestamp::now();
            rec.revoked_at = Some(now);
            rec.tripped = tripped_ago.map(|ago| {
                let mut t = a_trip();
                t.recorded_at = now - SignedDuration::from_secs(ago);
                t.at = t.recorded_at;
                t
            });
            rec
        };
        let grace = i64::try_from(LOGS_AFTER_A_TRIP.as_secs()).unwrap();
        for (tripped_ago, kept) in [(Some(grace - 5), 1), (Some(grace + 1), 0), (None, 0)] {
            let rec = ended(tripped_ago);
            r.store.inner.put_claim(rec.clone()).await.unwrap();
            let (status, ..) = call(&r.st, "POST", "/v1/me/logs", Some(&other), one_line(1)).await;
            assert_eq!(status, StatusCode::NO_CONTENT);
            assert_eq!(stored_lines(&r, rec.uid).await, kept, "{tripped_ago:?}");
            r.store.inner.delete_logs(rec.uid).await.unwrap();
            // The next record must be the node's last: an older one is never the target.
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        // A claim past its deadline and not yet released is no live claim either.
        let mut expired = ended(None);
        expired.revoked_at = None;
        expired.expires_at = Some(Timestamp::now() - SignedDuration::from_secs(1));
        r.store.inner.put_claim(expired.clone()).await.unwrap();
        let (status, ..) = call(&r.st, "POST", "/v1/me/logs", Some(&other), one_line(1)).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(stored_lines(&r, expired.uid).await, 0, "past its deadline");
    }

    #[tokio::test]
    async fn ending_a_claim_for_a_trip_never_deletes_its_sandbox() {
        use mediatore_testkit::sandboxes::MemorySandboxes;
        let front = Arc::new(MemorySandboxes::default());
        let r = rig_with(TrapsMode::Enforce, |st| {
            // Outside dev_mode an exit releases by deleting the AgentSandbox. A trip does not.
            st.dev_mode = false;
            st.sandboxes = Some(front.clone());
        })
        .await;
        put_sandbox(&r, &front).await;
        let tripped = Tripped {
            id: Uuid::new_v4(),
            at: Timestamp::now(),
            recorded_at: Timestamp::now(),
            kind: TripKind::Protocol,
            trap: None,
            class: Some(TripClass::AudienceOutsideRendered),
            target: None,
            source: TripSource::Peer,
        };
        let ended = end_claim(&r.st, r.rec.uid, tripped.clone()).await.unwrap();
        assert_eq!(ended, Ended::Tripped);
        assert!(
            front
                .get(&r.rec.namespace, &r.rec.name)
                .await
                .unwrap()
                .is_some(),
            "the AgentSandbox is still there, for its owner to read"
        );
        let held = r.held().await;
        assert!(held.tripped == Some(tripped.clone()) && held.revoked_at.is_some());
        // Again: the claim has ended, and nothing is written over the first trip.
        let mut second = tripped;
        second.id = Uuid::new_v4();
        assert_eq!(
            end_claim(&r.st, r.rec.uid, second).await.unwrap(),
            Ended::NotLive
        );
        assert_eq!(
            end_claim(&r.st, Uuid::new_v4(), held.tripped.clone().unwrap())
                .await
                .unwrap(),
            Ended::NotLive,
            "a claim the store never held"
        );
        assert_eq!(r.store.calls(), vec!["tripped", "release"]);
    }
}
