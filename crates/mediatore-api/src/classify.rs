// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Tripwires past the jail (ADR-0070): the broker classifies refusals it already makes on the
//! sandbox listener. A request no honest guest, proxy or authorizer sends is one of eight
//! `protocol` classes; the refusal it gets is the one the route gives today, in the same
//! bytes, and what is recorded is decided here.
//!
//! Three rules hold everywhere in this module.
//!
//! - **A trip changes no answer** (decision 2). Every entry point is called where a handler
//!   has already decided to refuse, takes no part in the answer, and returns nothing. It
//!   counts in a bounded table under a `std::sync::Mutex` and, for a class at `trip`, spawns
//!   the end of the claim: no store call is awaited on the path of the response.
//! - **Nothing the peer sent is kept** (decision 9) but what the route's own grammar admits:
//!   an audience name, a `host[:port]`. The route is its template, the peer its SPIFFE ID in
//!   the broker's own spelling.
//! - **Only a claim can be ended** (decision 6), through [`trip::end_claim`], and only by a
//!   class whose [`TripClass::may_trip`] says so, whatever the configuration holds.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use axum::Extension;
use axum::extract::{MatchedPath, State};
use axum::http::{HeaderMap, Method, Request, StatusCode};
use jiff::Timestamp;
use mediatore_proto::ek::is_ek_hash;
use mediatore_proto::trip::{
    ClassAction, ClassScope, TripClass, TripEffect, TripEntry, TripKind, TripSource, TripTarget,
    Tripped,
};
use mediatore_proto::{DecisionVerdict, GatewayDecisions, Rendered};
use mediatore_spire::Naming;
use mediatore_store::{ClaimRecord, StoreError};
use mediatore_tls::PeerSpiffeId;
use uuid::Uuid;

use crate::tripwires::{
    ClassFold, Detail, FOLD_MAX_PEERS, Folded, MAX_JUDGING_BATCHES, Named, Sight,
};
use crate::{AppState, Shared, trip};

/// The route of a refusal made before any route: the sandbox listener's handshake.
pub(crate) const HANDSHAKE: &str = "(handshake)";
/// The route of a request for a path the router does not serve. A constant: nothing of the
/// path is kept (decision 8).
pub(crate) const UNKNOWN_ROUTE: &str = "(unknown)";
/// What stands for a method no route of this broker takes, in the request span.
const OTHER_METHOD: &str = "(other)";
/// The gateway's refusal code for a claim the broker no longer answers for: an honest deny,
/// whatever its authority (a release racing a request).
const CLAIM_GONE: &str = "claim_gone";
/// The most distinct claims one batch of decisions has looked up for `deny_outside_rendered`;
/// the denies of any further claim in the batch are not judged.
pub(crate) const MAX_DENY_CLAIMS: usize = 16;
/// The most bytes of an audience an audit line carries.
const MAX_AUDIENCE_BYTES: usize = 253;

/// Who a route of the sandbox listener is for: the honest request set of ADR-0070 is, per
/// role, the routes that name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Role {
    /// Answered to any admitted identity, and classified for none (`/healthz`).
    Any,
    /// A pool VM's guest, over its node SVID.
    Node,
    /// The egress proxy, over the claim SVID.
    Claim,
    /// A gateway's authorizer.
    Authorizer,
}

/// A peer of the sandbox listener, as the broker spells it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Peer {
    role: Role,
    /// The SPIFFE ID, rebuilt from what was parsed out of it: never the text as it came.
    id: String,
    /// The claim a claim identity names.
    claim: Option<Uuid>,
    /// The EK hash a node identity names.
    ek: Option<String>,
}

/// The peer `raw` is, or `None` for an identity of no admitted shape. Under mutual TLS such
/// an identity never gets past the handshake; a `dev_mode` header can carry anything, and
/// anything else is classified nowhere and recorded nowhere.
pub(crate) fn identify(naming: &Naming, raw: &str) -> Option<Peer> {
    if let Some(uid) = naming.claim_uid_from(raw) {
        return Some(Peer {
            role: Role::Claim,
            id: naming.claim_id(uid),
            claim: Some(uid),
            ek: None,
        });
    }
    if let Some(ek) = naming.node_ek_from(raw) {
        let ek = is_ek_hash(&ek).then_some(ek);
        return Some(Peer {
            role: Role::Node,
            id: naming.node_id(ek.as_deref().unwrap_or("(not-an-ek-hash)")),
            claim: None,
            ek,
        });
    }
    let authorizer = naming.is_gateway_authorizer(raw);
    (authorizer || naming.is_gateway(raw)).then(|| Peer {
        role: Role::Authorizer,
        id: if authorizer {
            naming.gateway_authorizer_id()
        } else {
            naming.gateway_id()
        },
        claim: None,
        ek: None,
    })
}

/// Whether a class at `action` ends a claim: `trip`, and a class that may. The second half is
/// what the configuration check and [`crate::tripwires::ClassActions::set`] already refuse;
/// it is asked again here so that neither is what the property rests on.
const fn acts(action: ClassAction, class: TripClass) -> bool {
    matches!(action, ClassAction::Trip) && class.may_trip()
}

/// Whose claim an event of `class` is about.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Whom {
    /// This claim.
    Claim(Uuid),
    /// The live claim of the node with this SPIRE agent ID, if it has one.
    Node(String),
}

/// The claim an event of `class` by `peer` is scoped to (decision 6): the claim named, the
/// claim the peer is, or the claim bound to the node the peer is. `None` for the authorizer
/// and for a class with no scope: nothing of theirs is ever ended or put on a status.
fn whom(naming: &Naming, class: TripClass, peer: &Peer, named: Option<Uuid>) -> Option<Whom> {
    match class.scope() {
        ClassScope::Claim => named.or(peer.claim).map(Whom::Claim),
        ClassScope::ClaimNodeOrAuthorizer => match peer.role {
            Role::Claim => peer.claim.map(Whom::Claim),
            Role::Node => peer.ek.as_deref().map(|ek| Whom::Node(naming.agent_id(ek))),
            Role::Authorizer | Role::Any => None,
        },
        ClassScope::Authorizer | ClassScope::None => None,
    }
}

/// The scope word of an audit line.
fn scope_word(class: TripClass, peer: Option<&Peer>) -> &'static str {
    match class.scope() {
        ClassScope::Claim => "claim",
        ClassScope::Authorizer => "authorizer",
        ClassScope::None => "none",
        ClassScope::ClaimNodeOrAuthorizer => match peer.map(|p| p.role) {
            Some(Role::Claim) => "claim",
            Some(Role::Node) => "node",
            Some(Role::Authorizer) => "authorizer",
            Some(Role::Any) | None => "none",
        },
    }
}

/// Count one refusal of `peer` as `class` and, for a class at `trip` scoped to a claim, start
/// the end of that claim. Synchronous: the count is taken under the fold's mutex and the end
/// runs in a task of its own, so the caller's answer waits on neither (decision 2).
fn note(st: &Shared, class: TripClass, peer: &Peer, detail: Detail) {
    if class == TripClass::NoRecord && !st.tripwires.no_record_judged {
        return;
    }
    let named = detail.claim_uid;
    let target = detail.named.as_ref().and_then(target_of);
    let sight = st.tripwires.fold.note(class, &peer.id, detail);
    if sight == Sight::Repeat || !acts(st.tripwires.classes.action(class), class) {
        return;
    }
    let Some(whom) = whom(&st.naming, class, peer, named) else {
        return;
    };
    let st = st.clone();
    tokio::spawn(async move { end(&st, class, whom, target, sight == Sight::First).await });
}

/// The claim of `whom`, or `None` when a node has none bound.
async fn claim_of(st: &AppState, whom: Whom) -> Option<Uuid> {
    match whom {
        Whom::Claim(uid) => Some(uid),
        Whom::Node(agent) => match st.store.get_claim_by_node(&agent).await {
            Ok(rec) => Some(rec.uid),
            Err(StoreError::NotFound(_)) => None,
            Err(e) => {
                tracing::warn!(node = %agent, error = %e, "the claim of a node could not be read for a classified refusal; nothing is recorded on it");
                None
            }
        },
    }
}

/// A `protocol` entry of a claim's trip summary.
fn entry(
    class: TripClass,
    effect: TripEffect,
    target: Option<TripTarget>,
    count: u64,
    first_at: Timestamp,
    last_at: Timestamp,
) -> TripEntry {
    TripEntry {
        effect,
        kind: TripKind::Protocol,
        trap: None,
        class: Some(class),
        target,
        source: TripSource::Peer,
        source_address: None,
        containment_ms: None,
        count,
        first_at,
        last_at,
    }
}

/// End the claim of `whom` for an event of `class` (decision 6): [`trip::end_claim`], the one
/// way a claim is ended for a trip, and one entry in the claim's summary, `tripped` when this
/// ended it and `reported` when it had ended already. `counted` is whether the fold holds
/// this event as the first of its line: the flush then leaves it out of what it records, and
/// an event the fold had no room for is put on the summary only if it ended the claim.
async fn end(
    st: &AppState,
    class: TripClass,
    whom: Whom,
    target: Option<TripTarget>,
    counted: bool,
) {
    let Some(uid) = claim_of(st, whom).await else {
        return;
    };
    let now = Timestamp::now();
    let tripped = Tripped {
        id: Uuid::new_v4(),
        at: now,
        recorded_at: now,
        kind: TripKind::Protocol,
        trap: None,
        class: Some(class),
        target: target.clone(),
        source: TripSource::Peer,
    };
    // A failed release is logged by `end_claim`; the reconciler finishes a record that
    // carries `tripped`, and the next line of this class and peer tries again.
    let outcome = trip::end_claim(st, uid, tripped).await;
    let effect = match outcome {
        Ok(trip::Ended::NotLive) => TripEffect::Reported,
        Ok(_) | Err(_) => TripEffect::Tripped,
    };
    if counted || matches!(outcome, Ok(trip::Ended::Tripped)) {
        fold_onto(st, uid, &entry(class, effect, target, 1, now, now)).await;
    }
}

/// Fold one entry into a claim's summary. A claim with no record is nothing to write on; any
/// other failure is said once, and the audit line stands.
async fn fold_onto(st: &AppState, claim_uid: Uuid, entry: &TripEntry) {
    match st
        .store
        .fold_trips(claim_uid, std::slice::from_ref(entry), Timestamp::now())
        .await
    {
        Ok(()) => {}
        Err(StoreError::NotFound(_)) => {
            tracing::debug!(%claim_uid, "a classified refusal for a claim with no record; nothing to put it on");
        }
        Err(e) => {
            tracing::warn!(%claim_uid, error = %e, "the trip summary could not be written; the audit lines stand");
        }
    }
}

/// An audience as an audit line may carry it: a name, or nothing.
fn audience_named(audience: &str) -> Option<Named> {
    let ok = (1..=MAX_AUDIENCE_BYTES).contains(&audience.len())
        && audience
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
    ok.then(|| Named::Audience(audience.to_owned()))
}

/// The host and port of an authority, the port 443 when it names none (as
/// `InjectRoute::matches_authority` reads it), the host without brackets.
fn host_port(authority: &str) -> Option<(&str, u16)> {
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        match after.strip_prefix(':') {
            Some(port) => (host, Some(port)),
            None if after.is_empty() => (host, None),
            None => return None,
        }
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    let port = match port {
        Some(p) => p.parse::<u16>().ok().filter(|p| *p != 0)?,
        None => 443,
    };
    (!host.is_empty()).then_some((host, port))
}

/// Whether `authority` is one the claim was handed: an endpoint of a route of its `rendered`
/// or one of its destinations. The host without regard to case, the port equal.
fn inside(rendered: &Rendered, authority: &str) -> bool {
    let Some((host, port)) = host_port(authority) else {
        return false;
    };
    rendered
        .routes
        .iter()
        .map(|r| &r.endpoint)
        .chain(&rendered.egress)
        .any(|e| e.port == port && e.host.eq_ignore_ascii_case(host))
}

/// What a summary entry says was reached for: an address and a port, or a host, within the
/// grammar of [`TripTarget`]; nothing for an audience, and nothing for an authority outside it.
fn target_of(named: &Named) -> Option<TripTarget> {
    let Named::Authority(authority) = named else {
        return None;
    };
    let (host, port) = host_port(authority)?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(TripTarget::Address(SocketAddr::new(ip, port).to_string()));
    }
    let name = host.len() <= mediatore_proto::trip::MAX_TARGET_HOST_BYTES
        && host
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'));
    name.then(|| TripTarget::Host(host.to_owned()))
}

// ---------- the hook points: each called where a handler has already refused ----------

/// `foreign_route` (decision 3): an admitted identity on a route of another kind. `raw` is the
/// peer as the handler read it and `route` the route that refused it, whose role is read from
/// the list the router is built from ([`crate::honest_role`]). An identity of no admitted
/// shape is not this class, and neither is the route's own kind of peer refused for something
/// else (a node registering another node's EK).
pub(crate) fn foreign_route(st: &Shared, raw: &str, route: &'static str) {
    if let Some(peer) = identify(&st.naming, raw)
        && crate::honest_role(route).is_some_and(|honest| honest != peer.role)
    {
        let detail = Detail {
            route,
            ..Detail::default()
        };
        note(st, TripClass::ForeignRoute, &peer, detail);
    }
}

/// `no_record`: a claim identity whose uid has no record at all, or a node identity whose EK
/// hash is not registered. Not judged where the store keeps an ended claim no longer than its
/// SVID lives (`Tripwires::no_record_judged`).
pub(crate) fn no_record(st: &Shared, raw: &str, route: &'static str) {
    if let Some(peer) = identify(&st.naming, raw) {
        let detail = Detail {
            route,
            ..Detail::default()
        };
        note(st, TripClass::NoRecord, &peer, detail);
    }
}

/// `audience_outside_rendered`: `POST /v1/token` named an audience the claim does not have,
/// and no route the claim's guest was handed carries it. A claim with nothing rendered is not
/// judged, and an audience that was rendered and is granted no more is an honest proxy's.
pub(crate) fn audience_refused(st: &Shared, raw: &str, rec: &ClaimRecord, audience: &str) {
    let Some(rendered) = rec.rendered.as_ref() else {
        return;
    };
    if rendered
        .routes
        .iter()
        .any(|r| r.audience.as_deref() == Some(audience))
    {
        return;
    }
    if let Some(peer) = identify(&st.naming, raw) {
        let detail = Detail {
            route: crate::route::TOKEN,
            claim_uid: None,
            named: audience_named(audience),
        };
        note(st, TripClass::AudienceOutsideRendered, &peer, detail);
    }
}

/// `claim_never_issued`: the authorizer asked about a uid the store holds no record of.
pub(crate) fn claim_never_issued(st: &Shared, raw: &str, route: &'static str) {
    if let Some(peer) = identify(&st.naming, raw) {
        let detail = Detail {
            route,
            ..Detail::default()
        };
        note(st, TripClass::ClaimNeverIssued, &peer, detail);
    }
}

/// `credential_outside_inject`: the authorizer asked for a credential of an audience that is
/// not gateway-placed for the claim.
pub(crate) fn credential_outside_inject(st: &Shared, raw: &str) {
    if let Some(peer) = identify(&st.naming, raw) {
        let detail = Detail {
            route: crate::route::GATEWAY_CREDENTIAL,
            ..Detail::default()
        };
        note(st, TripClass::CredentialOutsideInject, &peer, detail);
    }
}

/// `deny_outside_rendered`: a gateway reported a deny for an authority the claim was never
/// handed. Called once the batch's `204` is decided; the claims are read in a task of its
/// own, at most [`MAX_DENY_CLAIMS`] of them a batch. A deny whose reason is `claim_gone`, one
/// for a claim that has ended or has no record, and one for a claim with nothing rendered are
/// not judged.
pub(crate) fn reported_denies(st: &Shared, raw: &str, batch: &GatewayDecisions) {
    let denies: Vec<(Uuid, String)> = batch
        .decisions
        .iter()
        .filter(|d| d.verdict == DecisionVerdict::Deny && d.reason.as_deref() != Some(CLAIM_GONE))
        .map(|d| (d.claim_uid, d.authority.to_ascii_lowercase()))
        .collect();
    if denies.is_empty() {
        return;
    }
    let Some(peer) = identify(&st.naming, raw) else {
        return;
    };
    // A bounded number of batches judged at once (the review's F1): one that finds every
    // permit held is not judged, and is counted for the next flush.
    let Ok(permit) = st.tripwires.judging.clone().try_acquire_owned() else {
        st.tripwires.unjudged.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let st = st.clone();
    tokio::spawn(async move {
        judge_denies(&st, &peer, denies).await;
        drop(permit);
    });
}

/// What each reported deny is judged against: the `rendered` of its claim, read once a claim.
async fn judge_denies(st: &Shared, peer: &Peer, denies: Vec<(Uuid, String)>) {
    let mut rendered: BTreeMap<Uuid, Option<Rendered>> = BTreeMap::new();
    let mut not_judged = 0_u64;
    for (uid, authority) in denies {
        if !rendered.contains_key(&uid) {
            if rendered.len() >= MAX_DENY_CLAIMS {
                not_judged += 1;
                continue;
            }
            let now = Timestamp::now();
            let held = match st.store.get_claim(uid).await {
                Ok(rec) if rec.tripped.is_none() && rec.is_live(now) => rec.rendered,
                _ => None,
            };
            rendered.insert(uid, held);
        }
        let Some(Some(handed)) = rendered.get(&uid) else {
            continue;
        };
        if inside(handed, &authority) {
            continue;
        }
        let detail = Detail {
            route: crate::route::GATEWAY_DECISIONS,
            claim_uid: Some(uid),
            // The batch's own check held the authority to a `host[:port]` before this.
            named: Some(Named::Authority(authority)),
        };
        note(st, TripClass::DenyOutsideRendered, peer, detail);
    }
    if not_judged > 0 {
        tracing::debug!(
            not_judged,
            max_claims = MAX_DENY_CLAIMS,
            "a batch of decisions denied for more claims than one batch is judged for; the rest were not compared with what their claims were handed"
        );
    }
}

/// `unknown_route`: the router's fallback, a request for a path it does not serve. The answer
/// is the empty `404` the router gave before it had a fallback; the route recorded is a
/// constant and nothing of the request is read but who sent it.
pub(crate) async fn unknown_route(
    State(st): State<Shared>,
    headers: HeaderMap,
    peer: Option<Extension<PeerSpiffeId>>,
) -> StatusCode {
    if let Ok(raw) = crate::peer_spiffe_id(&st, peer.as_ref().map(|e| &e.0), &headers)
        && let Some(peer) = identify(&st.naming, &raw)
    {
        let detail = Detail {
            route: UNKNOWN_ROUTE,
            ..Detail::default()
        };
        note(&st, TripClass::UnknownRoute, &peer, detail);
    }
    StatusCode::NOT_FOUND
}

/// Who may complete a handshake with the sandbox listener ([`crate::sandbox_authorizer`]),
/// with every refusal counted as `identity_shape` (decision 3): a valid SVID of the trust
/// domain that is none of the admitted shapes, the listeners' `spiffe://<td>/gateway` included
/// while `accept_plain_gateway_identity` is off. The verifier calls this after the chain and
/// the trust domain are verified, synchronously, so the count is taken under the fold's
/// `std::sync::Mutex` and nothing is awaited. The class records only: it has no scope.
pub fn sandbox_authorizer_classified(
    naming: Naming,
    accept_plain_gateway_identity: bool,
    fold: Arc<ClassFold>,
) -> mediatore_tls::Authorizer {
    let admits = crate::sandbox_authorizer(naming, accept_plain_gateway_identity);
    Arc::new(move |id: &mediatore_tls::SpiffeId| {
        let admitted = admits(id);
        if !admitted {
            let detail = Detail {
                route: HANDSHAKE,
                ..Detail::default()
            };
            fold.note(TripClass::IdentityShape, &id.to_string(), detail);
        }
        admitted
    })
}

// ---------- the flush: the audit lines, and the status of a claim-scoped class ----------

/// Write what the fold counted since the last flush (decision 8): one `warn` line per class
/// and peer with its count, one more for what the table had no room for, and for a class
/// scoped to a claim an entry in that claim's trip summary.
pub async fn flush(st: &AppState) {
    let flushed = st.tripwires.fold.flush();
    for line in &flushed.lines {
        let peer = identify(&st.naming, &line.peer);
        let action = st.tripwires.classes.action(line.class);
        let claim_uid = line
            .detail
            .claim_uid
            .or(peer.as_ref().and_then(|p| p.claim))
            .map(|u| u.to_string())
            .unwrap_or_default();
        let (audience, authority) = match &line.detail.named {
            Some(Named::Audience(a)) => (a.as_str(), ""),
            Some(Named::Authority(a)) => ("", a.as_str()),
            None => ("", ""),
        };
        tracing::warn!(
            class = line.class.as_str(),
            scope = scope_word(line.class, peer.as_ref()),
            action = action.as_str(),
            peer = %line.peer,
            route = line.detail.route,
            claim_uid = %claim_uid,
            audience,
            authority,
            count = line.count,
            first_at = %line.first_at,
            last_at = %line.last_at,
            "a refusal no honest build earns (ADR-0070 decision 8)"
        );
        if let Some(peer) = peer {
            record(st, line, &peer, action).await;
        }
    }
    if flushed.overflow > 0 {
        tracing::warn!(
            overflow = flushed.overflow,
            max_peers = FOLD_MAX_PEERS,
            "classified refusals of more peers than the table holds: counted, their peers not kept (ADR-0070 decision 8)"
        );
    }
    let unjudged = st.tripwires.unjudged.swap(0, Ordering::Relaxed);
    if unjudged > 0 {
        tracing::warn!(
            batches = unjudged,
            max_judging = MAX_JUDGING_BATCHES,
            "batches of decisions not judged for deny_outside_rendered: as many were being judged as the broker allows at once; each was answered as always"
        );
    }
}

/// Put a flushed line on the summary of the claim it is scoped to, as `reported`. Where the
/// class is at `trip` the line's first event was recorded when it ended the claim ([`end`]),
/// and what is left is what came after.
async fn record(st: &AppState, line: &Folded, peer: &Peer, action: ClassAction) {
    let Some(whom) = whom(&st.naming, line.class, peer, line.detail.claim_uid) else {
        return;
    };
    let count = line
        .count
        .saturating_sub(u64::from(acts(action, line.class)));
    if count == 0 {
        return;
    }
    let Some(uid) = claim_of(st, whom).await else {
        return;
    };
    let target = line.detail.named.as_ref().and_then(target_of);
    let reported = entry(
        line.class,
        TripEffect::Reported,
        target,
        count,
        line.first_at,
        line.last_at,
    );
    fold_onto(st, uid, &reported).await;
}

/// Flush the fold every `every` for as long as the broker runs (decision 8: a count per
/// minute, [`crate::tripwires::FOLD_FLUSH_EVERY`]). What was counted since the last flush
/// when the process stops is not written.
pub fn spawn_flush(st: Shared, every: Duration) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(every);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick of an interval is immediate, and there is nothing to flush yet.
        tick.tick().await;
        loop {
            tick.tick().await;
            flush(&st).await;
        }
    })
}

// ---------- the request span ----------

/// The span of one request on either listener: its method and the template of the route that
/// matched, never the URI (ADR-0069 decision 12, ADR-0070 decision 9). A path the router does
/// not serve is [`UNKNOWN_ROUTE`], and a method no route here takes is one word for all.
pub(crate) fn request_span<B>(req: &Request<B>) -> tracing::Span {
    let method = match *req.method() {
        Method::GET => "GET",
        Method::POST => "POST",
        Method::DELETE => "DELETE",
        Method::PUT => "PUT",
        Method::PATCH => "PATCH",
        Method::HEAD => "HEAD",
        Method::OPTIONS => "OPTIONS",
        _ => OTHER_METHOD,
    };
    let route = req
        .extensions()
        .get::<MatchedPath>()
        .map_or(UNKNOWN_ROUTE, MatchedPath::as_str);
    tracing::debug_span!("request", method, route)
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use jiff::SignedDuration;
    use mediatore_proto::trip::TripSummary;
    use mediatore_proto::{Endpoint, RenderedRoute};
    use mediatore_store::ClaimStore as _;
    use tower::ServiceExt as _;

    use super::*;
    use crate::tests::{capture_logs, captured, claim, placed_state};
    use crate::trip::tests::{Ordered, register};
    use crate::{sandbox_router, sandbox_routes, user_router};

    const EK: &str = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
    const OTHER_EK: &str = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2";
    const AUDIT: &str = "a refusal no honest build earns";

    /// What the tests plant where a peer could put something, and look for in every line.
    const CANARY_PATH: &str = "canary-path-7f3a";
    const CANARY_QUERY: &str = "canary-query-91bc";
    const CANARY_HEADER: &str = "canary-header-52de";
    const CANARY_TOKEN: &str = "canary-token-c08e";
    const CANARIES: [&str; 4] = [CANARY_PATH, CANARY_QUERY, CANARY_HEADER, CANARY_TOKEN];

    fn endpoint(host: &str, port: u16) -> Endpoint {
        Endpoint {
            host: host.into(),
            port,
        }
    }

    /// What a guest was handed: a route for `grafana`, one for an audience granted no more,
    /// and a direct destination.
    fn handed() -> Rendered {
        let route = |audience: &str, host: &str| RenderedRoute {
            audience: Some(audience.into()),
            endpoint: endpoint(host, 443),
            rules: vec![],
        };
        Rendered {
            bundle_version: 3,
            bundle_digest: "sha256:0".into(),
            routes: vec![
                route("grafana", "grafana.example"),
                route("narrowed", "narrowed.example"),
            ],
            egress: vec![
                endpoint("grafana.example", 443),
                endpoint("direct.example", 8443),
            ],
        }
    }

    /// A broker with one registered node and its bound, live claim, whose guest was handed
    /// [`handed`]: the state, the store that records what is written, and the three peers.
    struct Scene {
        st: Shared,
        store: Arc<Ordered>,
        rec: ClaimRecord,
        node: String,
        claim: String,
        authorizer: String,
    }

    async fn scene_with(tripping: &[TripClass], set: impl FnOnce(&mut AppState)) -> Scene {
        let store = Ordered::new();
        let mut st = placed_state();
        st.store = store.clone();
        for class in tripping {
            st.tripwires
                .classes
                .set(*class, ClassAction::Trip)
                .expect("a class that may trip");
        }
        set(&mut st);
        let st: Shared = Arc::new(st);
        let node = register(&st, EK).await;
        let mut rec = claim(&["anthropic", "grafana"], Some(st.naming.agent_id(EK)));
        rec.expires_at = Some(Timestamp::now() + SignedDuration::from_hours(1));
        rec.rendered = Some(handed());
        st.store.put_claim(rec.clone()).await.unwrap();
        Scene {
            claim: st.naming.claim_id(rec.uid),
            authorizer: st.naming.gateway_authorizer_id(),
            st,
            store,
            rec,
            node,
        }
    }

    async fn scene(tripping: &[TripClass]) -> Scene {
        scene_with(tripping, |_| {}).await
    }

    /// Every class that may be set to `trip`, set to it.
    fn all_tripping() -> Vec<TripClass> {
        TripClass::PROTOCOL
            .into_iter()
            .filter(|c| c.may_trip())
            .collect()
    }

    /// The whole of an answer: what "a trip changes no answer" compares.
    #[derive(Debug, PartialEq, Eq)]
    struct Answer {
        status: StatusCode,
        headers: Vec<(String, Vec<u8>)>,
        body: Vec<u8>,
    }

    async fn answer_of(resp: axum::response::Response) -> Answer {
        let status = resp.status();
        let mut headers: Vec<(String, Vec<u8>)> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_owned(), v.as_bytes().to_vec()))
            .collect();
        headers.sort();
        let body = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .unwrap()
            .to_vec();
        Answer {
            status,
            headers,
            body,
        }
    }

    fn request(
        method: &str,
        uri: &str,
        peer: Option<&str>,
        extra: &[(&str, &str)],
        body: &str,
    ) -> Request<Body> {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .header("content-type", "application/json");
        if let Some(peer) = peer {
            req = req.header("x-mediatore-peer-spiffe-id", peer);
        }
        for (k, v) in extra {
            req = req.header(*k, *v);
        }
        req.body(Body::from(body.to_owned())).unwrap()
    }

    async fn send(st: &Shared, method: &str, uri: &str, peer: &str, body: &str) -> Answer {
        let resp = sandbox_router(st.clone())
            .oneshot(request(method, uri, Some(peer), &[], body))
            .await
            .unwrap();
        answer_of(resp).await
    }

    /// Let every task the handlers spawned run to its end. The stores of these tests answer
    /// without waiting, so a task is done after a few turns of the runtime.
    async fn settle() {
        for _ in 0..200 {
            tokio::task::yield_now().await;
        }
    }

    /// What the fold holds, taken: class, peer, count and route of each line.
    fn noted(st: &AppState) -> Vec<(TripClass, String, u64, &'static str)> {
        st.tripwires
            .fold
            .flush()
            .lines
            .into_iter()
            .map(|l| (l.class, l.peer, l.count, l.detail.route))
            .collect()
    }

    impl Scene {
        async fn held(&self) -> ClaimRecord {
            self.store.inner.get_claim(self.rec.uid).await.unwrap()
        }

        async fn summary(&self) -> Option<TripSummary> {
            self.store.inner.trips(self.rec.uid).await.unwrap()
        }

        /// Nothing of a trip is on the claim, and nothing was written for one.
        async fn untouched(&self) -> bool {
            let held = self.held().await;
            held.tripped.is_none()
                && held.revoked_at.is_none()
                && self.summary().await.is_none()
                && self.store.calls().is_empty()
        }

        /// The entries of the claim's summary: effect, class, target, count.
        async fn entries(&self) -> Vec<(TripEffect, Option<TripClass>, Option<TripTarget>, u64)> {
            self.summary()
                .await
                .map(|s| {
                    s.entries
                        .into_iter()
                        .map(|e| {
                            assert_eq!(e.kind, TripKind::Protocol);
                            assert_eq!(e.source, TripSource::Peer);
                            assert_eq!(e.trap, None);
                            (e.effect, e.class, e.target, e.count)
                        })
                        .collect()
                })
                .unwrap_or_default()
        }

        fn deny(&self, authority: &str) -> String {
            decisions(&[(self.rec.uid, authority, "deny", Some("not_allowed"))])
        }
    }

    /// A batch of tunnel decisions: claim, authority, verdict, reason.
    fn decisions(of: &[(Uuid, &str, &str, Option<&str>)]) -> String {
        let decisions: Vec<serde_json::Value> = of
            .iter()
            .map(|(uid, authority, verdict, reason)| {
                let mut d = serde_json::json!({
                    "at": "2026-11-27T10:00:00Z", "claim_uid": uid, "kind": "tunnel",
                    "authority": authority, "verdict": verdict,
                });
                if let Some(reason) = reason {
                    d["reason"] = (*reason).into();
                }
                d
            })
            .collect();
        serde_json::json!({ "gateway": "gateway-02", "decisions": decisions }).to_string()
    }

    /// A guest's report, as `POST /v1/me/report` reads one.
    fn report_body() -> String {
        serde_json::to_string(&mediatore_proto::GuestReport {
            image_digest: format!("sha256:{}", "0".repeat(64)),
            sandbox_ruleset_sha256: "0".repeat(64),
            host_table: mediatore_proto::HostTable::NotLoaded,
        })
        .unwrap()
    }

    fn token_for(audience: &str) -> String {
        serde_json::json!({ "audience": audience }).to_string()
    }

    // ---------- each class fires on its case ----------

    #[tokio::test]
    async fn a_claim_identity_on_a_node_route_is_foreign_route() {
        let s = scene(&[]).await;
        let a = send(&s.st, "GET", "/v1/me", &s.claim, "").await;
        assert_eq!(a.status, StatusCode::FORBIDDEN);
        // A gateway route under the claim's identity is the same class, and the same line.
        let uri = format!("/v1/gateway/claims/{}", s.rec.uid);
        let a = send(&s.st, "GET", &uri, &s.claim, "").await;
        assert_eq!(a.status, StatusCode::FORBIDDEN);
        settle().await;
        assert!(
            s.untouched().await,
            "at report nothing is written before the flush"
        );
        assert_eq!(
            noted(&s.st),
            [(TripClass::ForeignRoute, s.claim.clone(), 2, "GET /v1/me")]
        );
        // The flush puts what it counted on the claim's summary, and ends nothing.
        send(&s.st, "POST", "/v1/me/exit", &s.claim, "{}").await;
        flush(&s.st).await;
        assert_eq!(
            s.entries().await,
            [(TripEffect::Reported, Some(TripClass::ForeignRoute), None, 1)]
        );
        let held = s.held().await;
        assert!(held.tripped.is_none() && held.revoked_at.is_none());
        assert_eq!(s.store.calls(), ["fold"]);
    }

    #[tokio::test]
    async fn a_node_on_the_token_route_is_foreign_route() {
        // At report: counted, and at the flush put on the claim bound to the node.
        let s = scene(&[]).await;
        let a = send(&s.st, "POST", "/v1/token", &s.node, &token_for("grafana")).await;
        assert_eq!(a.status, StatusCode::FORBIDDEN);
        let uri = format!("/v1/gateway/claims/{}/credential", s.rec.uid);
        let a = send(&s.st, "POST", &uri, &s.node, &token_for("anthropic")).await;
        assert_eq!(a.status, StatusCode::FORBIDDEN);
        settle().await;
        assert!(s.untouched().await);
        flush(&s.st).await;
        assert_eq!(
            s.entries().await,
            [(TripEffect::Reported, Some(TripClass::ForeignRoute), None, 2)]
        );
        assert!(s.held().await.tripped.is_none());

        // At trip: the claim bound to the node is ended (decision 6).
        let s = scene(&[TripClass::ForeignRoute]).await;
        send(&s.st, "POST", "/v1/token", &s.node, &token_for("grafana")).await;
        settle().await;
        let held = s.held().await;
        let tripped = held.tripped.expect("the node's claim is tripped");
        assert_eq!(tripped.class, Some(TripClass::ForeignRoute));
        assert!(held.revoked_at.is_some());
        // A node with no claim bound: recorded, and there is nothing to end.
        let other = register(&s.st, OTHER_EK).await;
        send(&s.st, "POST", "/v1/token", &other, &token_for("grafana")).await;
        settle().await;
        assert_eq!(
            noted(&s.st),
            [
                (TripClass::ForeignRoute, s.node.clone(), 1, "POST /v1/token"),
                (TripClass::ForeignRoute, other, 1, "POST /v1/token"),
            ]
        );
    }

    #[tokio::test]
    async fn the_authorizer_on_me_is_foreign_route() {
        let s = scene(&all_tripping()).await;
        for (method, uri, body) in [
            ("GET", "/v1/me", String::new()),
            ("POST", "/v1/token", token_for("grafana")),
            ("POST", "/v1/me/exit", "{}".to_owned()),
        ] {
            let a = send(&s.st, method, uri, &s.authorizer, &body).await;
            assert_eq!(a.status, StatusCode::FORBIDDEN, "{method} {uri}");
        }
        settle().await;
        assert!(
            s.untouched().await,
            "nothing is ended for the authorizer, at trip either"
        );
        capture_logs();
        flush(&s.st).await;
        let logs = captured();
        let line = logs.lines().find(|l| l.contains(AUDIT)).expect("a line");
        for want in [
            "class=\"foreign_route\"",
            "scope=\"authorizer\"",
            "route=\"GET /v1/me\"",
            "count=3",
        ] {
            assert!(line.contains(want), "{want} in {line}");
        }
        assert!(s.untouched().await, "and the flush writes on no claim");
    }

    #[tokio::test]
    async fn an_unserved_path_is_unknown_route_and_nothing_of_the_path_is_kept() {
        capture_logs();
        let s = scene(&[]).await;
        let uri = format!("/v1/{CANARY_PATH}?q={CANARY_QUERY}");
        for peer in [&s.claim, &s.node, &s.authorizer] {
            let a = send(&s.st, "GET", &uri, peer, "").await;
            assert_eq!(a.status, StatusCode::NOT_FOUND);
            assert_eq!(a.body.len(), 0, "no body");
        }
        settle().await;
        assert!(s.untouched().await);
        flush(&s.st).await;
        let logs = captured();
        let lines: Vec<&str> = logs.lines().filter(|l| l.contains(AUDIT)).collect();
        assert_eq!(lines.len(), 3, "one line a peer");
        for line in &lines {
            assert!(line.contains("class=\"unknown_route\""), "{line}");
            assert!(line.contains("route=\"(unknown)\""), "{line}");
        }
        for canary in CANARIES {
            assert!(
                !logs.contains(canary),
                "nothing the peer chose is in a line"
            );
        }
        // The claim's own and its node's are on the claim's summary; the authorizer's is not.
        assert_eq!(
            s.entries().await,
            [(TripEffect::Reported, Some(TripClass::UnknownRoute), None, 2)]
        );
    }

    #[tokio::test]
    async fn a_claim_uid_with_no_record_is_no_record() {
        let s = scene(&all_tripping()).await;
        let ghost = s.st.naming.claim_id(Uuid::new_v4());
        let a = send(&s.st, "POST", "/v1/token", &ghost, &token_for("grafana")).await;
        assert_eq!(a.status, StatusCode::FORBIDDEN);
        settle().await;
        assert_eq!(
            noted(&s.st),
            [(TripClass::NoRecord, ghost, 1, "POST /v1/token")]
        );
        assert!(s.untouched().await);
    }

    #[tokio::test]
    async fn an_unregistered_node_on_me_is_no_record_and_on_nodes_is_not() {
        let s = scene(&[]).await;
        let stranger = s.st.naming.node_id(OTHER_EK);
        for (method, uri, body) in [
            ("GET", "/v1/me", ""),
            ("POST", "/v1/me/exit", "{}"),
            ("POST", "/v1/me/report", report_body().as_str()),
        ] {
            let a = send(&s.st, method, uri, &stranger, body).await;
            assert_eq!(a.status, StatusCode::FORBIDDEN, "{method} {uri}");
        }
        assert_eq!(
            noted(&s.st),
            [(TripClass::NoRecord, stranger.clone(), 3, "GET /v1/me")]
        );
        // The same node registering itself is what an honest guest does first.
        let registration = serde_json::json!({
            "ek_hash": OTHER_EK, "dmi_uuid": Uuid::new_v4(), "hostname": "member-02",
        })
        .to_string();
        let a = send(&s.st, "POST", "/v1/nodes", &stranger, &registration).await;
        assert_eq!(a.status, StatusCode::OK);
        // And a node registering another node's EK is refused and is not a class.
        let a = send(&s.st, "POST", "/v1/nodes", &s.node, &registration).await;
        assert_eq!(a.status, StatusCode::FORBIDDEN);
        assert_eq!(noted(&s.st), []);
    }

    #[tokio::test]
    async fn no_record_is_not_judged_where_the_store_keeps_no_ended_claim() {
        // Decision 3, amended: at a retention not above the claim SVID's lifetime an honest
        // claim released a moment ago has no record and a valid SVID.
        let s = scene_with(&[], |st| st.tripwires.no_record_judged = false).await;
        let ghost = s.st.naming.claim_id(Uuid::new_v4());
        let a = send(&s.st, "POST", "/v1/token", &ghost, &token_for("grafana")).await;
        assert_eq!(a.status, StatusCode::FORBIDDEN);
        let stranger = s.st.naming.node_id(OTHER_EK);
        let a = send(&s.st, "GET", "/v1/me", &stranger, "").await;
        assert_eq!(a.status, StatusCode::FORBIDDEN);
        assert_eq!(noted(&s.st), []);
        // Every other class is judged as before.
        send(&s.st, "GET", "/v1/me", &s.claim, "").await;
        assert_eq!(noted(&s.st).len(), 1);
    }

    #[tokio::test]
    async fn an_audience_in_no_rendered_route_is_audience_outside_rendered() {
        let s = scene(&[]).await;
        let a = send(
            &s.st,
            "POST",
            "/v1/token",
            &s.claim,
            &token_for("elsewhere"),
        )
        .await;
        assert_eq!(a.status, StatusCode::BAD_REQUEST);
        // An audience that is no name is counted and never kept.
        let odd = format!("else where/{CANARY_TOKEN}?x");
        let a = send(&s.st, "POST", "/v1/token", &s.claim, &token_for(&odd)).await;
        assert_eq!(a.status, StatusCode::BAD_REQUEST);
        settle().await;
        assert!(s.untouched().await);
        let flushed = s.st.tripwires.fold.flush();
        assert_eq!(flushed.lines.len(), 1);
        let line = &flushed.lines[0];
        assert_eq!(
            (line.class, line.count, line.detail.route),
            (TripClass::AudienceOutsideRendered, 2, "POST /v1/token")
        );
        assert_eq!(
            line.detail.named,
            Some(Named::Audience("elsewhere".into())),
            "the first one, within the grammar of a name"
        );
        assert_eq!(audience_named(&odd), None);
        assert_eq!(audience_named(&"a".repeat(MAX_AUDIENCE_BYTES + 1)), None);
    }

    #[tokio::test]
    async fn the_authorizer_asking_about_a_uid_never_issued_is_claim_never_issued() {
        let s = scene(&all_tripping()).await;
        let ghost = Uuid::new_v4();
        let a = send(
            &s.st,
            "GET",
            &format!("/v1/gateway/claims/{ghost}"),
            &s.authorizer,
            "",
        )
        .await;
        assert_eq!(a.status, StatusCode::NOT_FOUND);
        let uri = format!("/v1/gateway/claims/{ghost}/credential");
        let a = send(&s.st, "POST", &uri, &s.authorizer, &token_for("anthropic")).await;
        assert_eq!(a.status, StatusCode::NOT_FOUND);
        settle().await;
        assert_eq!(
            noted(&s.st),
            [(
                TripClass::ClaimNeverIssued,
                s.authorizer.clone(),
                2,
                "GET /v1/gateway/claims/{uid}"
            )]
        );
        assert!(s.untouched().await);
    }

    #[tokio::test]
    async fn a_credential_asked_for_an_audience_placed_in_the_proxy_is_credential_outside_inject() {
        let s = scene(&all_tripping()).await;
        let uri = format!("/v1/gateway/claims/{}/credential", s.rec.uid);
        // `grafana` is the claim's, placed in the proxy; `elsewhere` is not the claim's at all.
        let a = send(&s.st, "POST", &uri, &s.authorizer, &token_for("grafana")).await;
        assert_eq!(a.status, StatusCode::FORBIDDEN);
        let a = send(&s.st, "POST", &uri, &s.authorizer, &token_for("elsewhere")).await;
        assert_eq!(a.status, StatusCode::BAD_REQUEST);
        settle().await;
        assert_eq!(
            noted(&s.st),
            [(
                TripClass::CredentialOutsideInject,
                s.authorizer.clone(),
                2,
                "POST /v1/gateway/claims/{uid}/credential"
            )]
        );
        assert!(s.untouched().await);
        // The audience that is placed at the gateway is the honest ask.
        let a = send(&s.st, "POST", &uri, &s.authorizer, &token_for("anthropic")).await;
        assert_eq!(a.status, StatusCode::OK);
        assert_eq!(noted(&s.st), []);
    }

    #[tokio::test]
    async fn a_reported_deny_for_an_authority_never_rendered_is_deny_outside_rendered() {
        let s = scene(&[]).await;
        let batch = decisions(&[
            (s.rec.uid, "Evil.example:443", "deny", Some("not_allowed")),
            (s.rec.uid, "evil.example:443", "deny", Some("not_allowed")),
            // An allow is no deny, whatever its authority.
            (s.rec.uid, "other.example:443", "allow", None),
        ]);
        let a = send(
            &s.st,
            "POST",
            "/v1/gateway/decisions",
            &s.authorizer,
            &batch,
        )
        .await;
        assert_eq!(a.status, StatusCode::NO_CONTENT);
        assert!(
            s.st.tripwires.fold.flush().lines.is_empty(),
            "the answer is built before any claim is read"
        );
        settle().await;
        assert!(s.untouched().await, "at report nothing is written yet");
        let flushed = s.st.tripwires.fold.flush();
        assert_eq!(flushed.lines.len(), 1);
        let line = &flushed.lines[0];
        assert_eq!(
            (line.class, line.peer.as_str(), line.count),
            (TripClass::DenyOutsideRendered, s.authorizer.as_str(), 2)
        );
        assert_eq!(line.detail.route, "POST /v1/gateway/decisions");
        assert_eq!(line.detail.claim_uid, Some(s.rec.uid));
        assert_eq!(
            line.detail.named,
            Some(Named::Authority("evil.example:443".into()))
        );
        // At the flush it is on the summary of the claim the deny names, with its host.
        send(
            &s.st,
            "POST",
            "/v1/gateway/decisions",
            &s.authorizer,
            &batch,
        )
        .await;
        settle().await;
        flush(&s.st).await;
        assert_eq!(
            s.entries().await,
            [(
                TripEffect::Reported,
                Some(TripClass::DenyOutsideRendered),
                Some(TripTarget::Host("evil.example".into())),
                2
            )]
        );
        assert!(s.held().await.tripped.is_none());
    }

    #[tokio::test]
    async fn a_reported_deny_outside_rendered_only_records_whatever_the_configuration_says() {
        // ADR-0070 decision 6 (amended 2026-11-27): the claim a deny names is the word of
        // whoever holds the authorizer's shared identity, so the class records and never ends
        // a claim. Refused by the table; and a `trip` that got past it would not act.
        let mut actions = crate::tripwires::ClassActions::default();
        assert!(
            actions
                .set(TripClass::DenyOutsideRendered, ClassAction::Trip)
                .is_err()
        );
        assert!(!acts(ClassAction::Trip, TripClass::DenyOutsideRendered));
        assert!(!all_tripping().contains(&TripClass::DenyOutsideRendered));
        // Every class that may trip at trip: a deny for each of many claims ends none of them.
        let s = scene(&all_tripping()).await;
        let mut others = Vec::new();
        for _ in 0..3 {
            let mut rec = claim(&["grafana"], None);
            rec.expires_at = Some(Timestamp::now() + SignedDuration::from_hours(1));
            rec.rendered = Some(handed());
            s.st.store.put_claim(rec.clone()).await.unwrap();
            others.push(rec.uid);
        }
        let mut denies = vec![(s.rec.uid, "evil.example:443", "deny", Some("not_allowed"))];
        denies.extend(
            others
                .iter()
                .map(|uid| (*uid, "evil.example:443", "deny", Some("not_allowed"))),
        );
        let a = send(
            &s.st,
            "POST",
            "/v1/gateway/decisions",
            &s.authorizer,
            &decisions(&denies),
        )
        .await;
        assert_eq!(a.status, StatusCode::NO_CONTENT);
        settle().await;
        assert!(
            !s.store
                .calls()
                .iter()
                .any(|c| *c == "tripped" || *c == "release"),
            "nothing is ended from a gateway's batch"
        );
        for uid in std::iter::once(s.rec.uid).chain(others.iter().copied()) {
            let held = s.st.store.get_claim(uid).await.unwrap();
            assert!(held.tripped.is_none() && held.revoked_at.is_none());
        }
        // Recorded: at the flush, on the summary of the claim named, as `reported`.
        flush(&s.st).await;
        assert_eq!(
            s.entries().await,
            [(
                TripEffect::Reported,
                Some(TripClass::DenyOutsideRendered),
                Some(TripTarget::Host("evil.example".into())),
                1
            )]
        );
    }

    #[tokio::test]
    async fn the_decisions_route_takes_so_many_batches_a_second_per_gateway_identity() {
        use crate::tripwires::GATEWAY_BATCHES_PER_SECOND;
        let s = scene_with(&[], |st| st.accept_plain_gateway_identity = true).await;
        let batch = decisions(&[(s.rec.uid, "grafana.example:443", "allow", None)]);
        // A batch the route's check refuses spends nothing.
        let off = decisions(&[(s.rec.uid, "not an authority", "allow", None)]);
        let a = send(&s.st, "POST", "/v1/gateway/decisions", &s.authorizer, &off).await;
        assert_eq!(a.status, StatusCode::BAD_REQUEST);
        for _ in 0..GATEWAY_BATCHES_PER_SECOND {
            let a = send(
                &s.st,
                "POST",
                "/v1/gateway/decisions",
                &s.authorizer,
                &batch,
            )
            .await;
            assert_eq!(a.status, StatusCode::NO_CONTENT);
        }
        capture_logs();
        let a = send(
            &s.st,
            "POST",
            "/v1/gateway/decisions",
            &s.authorizer,
            &batch,
        )
        .await;
        assert_eq!(a.status, StatusCode::TOO_MANY_REQUESTS);
        assert!(
            a.headers
                .iter()
                .any(|(k, v)| k == "retry-after" && v.as_slice() == b"1")
        );
        let refusal: serde_json::Value = serde_json::from_slice(&a.body).unwrap();
        assert_eq!(refusal["error"], "too_many_batches");
        let logs = captured();
        assert!(logs.contains("gateway decisions rate-limited"));
        assert!(
            !logs.contains("gateway decision claim_uid"),
            "a refused batch is not logged decision by decision"
        );
        // The listeners' identity, where it is accepted, has a bucket of its own.
        let plain = s.st.naming.gateway_id();
        let a = send(&s.st, "POST", "/v1/gateway/decisions", &plain, &batch).await;
        assert_eq!(a.status, StatusCode::NO_CONTENT);
    }

    #[test]
    fn an_honest_fleet_at_its_cadence_never_meets_the_decisions_limit() {
        // Forty gateways, each a batch every two seconds, for ten minutes: twenty a second.
        let limiter = crate::Limiter::per_second(crate::tripwires::GATEWAY_BATCHES_PER_SECOND);
        let key = Uuid::from_u128(1);
        let start = std::time::Instant::now();
        for tick in 0..1200_u64 {
            let at = start + Duration::from_millis(tick * 500);
            for _ in 0..10 {
                assert!(limiter.allow_at(key, at), "an honest batch was refused");
            }
        }
    }

    #[tokio::test]
    async fn a_batch_that_finds_every_judging_permit_held_is_answered_and_not_judged() {
        use crate::tripwires::MAX_JUDGING_BATCHES;
        let s = scene(&[]).await;
        let held =
            s.st.tripwires
                .judging
                .clone()
                .acquire_many_owned(u32::try_from(MAX_JUDGING_BATCHES).unwrap())
                .await
                .unwrap();
        let a = send(
            &s.st,
            "POST",
            "/v1/gateway/decisions",
            &s.authorizer,
            &s.deny("evil.example:443"),
        )
        .await;
        assert_eq!(a.status, StatusCode::NO_CONTENT, "the answer is unchanged");
        settle().await;
        assert_eq!(noted(&s.st), [], "the denies were not judged");
        capture_logs();
        flush(&s.st).await;
        let logs = captured();
        let line = logs
            .lines()
            .find(|l| l.contains("batches of decisions not judged"))
            .expect("the skip is said at the flush");
        assert!(line.contains("batches=1") && line.contains("WARN"));
        // Said once: the count starts again.
        capture_logs();
        flush(&s.st).await;
        assert!(!captured().contains("batches of decisions not judged"));
        // With a permit free, the next batch is judged as before.
        drop(held);
        send(
            &s.st,
            "POST",
            "/v1/gateway/decisions",
            &s.authorizer,
            &s.deny("evil.example:443"),
        )
        .await;
        settle().await;
        assert_eq!(noted(&s.st).len(), 1);
        assert_eq!(
            s.st.tripwires.judging.available_permits(),
            MAX_JUDGING_BATCHES,
            "the permit goes back when the judging ends"
        );
    }

    #[tokio::test]
    async fn one_batch_is_judged_for_sixteen_claims_and_no_more() {
        // The lookups a batch can cause are bounded: the denies of a seventeenth claim are
        // not compared with anything, and are no class.
        let s = scene(&[]).await;
        let mut denied = Vec::new();
        for _ in 0..=MAX_DENY_CLAIMS {
            let mut rec = claim(&["grafana"], None);
            rec.expires_at = Some(Timestamp::now() + SignedDuration::from_hours(1));
            rec.rendered = Some(handed());
            s.st.store.put_claim(rec.clone()).await.unwrap();
            denied.push(rec.uid);
        }
        let of: Vec<(Uuid, &str, &str, Option<&str>)> = denied
            .iter()
            .flat_map(|uid| {
                // Two denies a claim: a claim is read once, however often it is named.
                [(*uid, "evil.example:443", "deny", Some("not_allowed")); 2]
            })
            .collect();
        let a = send(
            &s.st,
            "POST",
            "/v1/gateway/decisions",
            &s.authorizer,
            &decisions(&of),
        )
        .await;
        assert_eq!(a.status, StatusCode::NO_CONTENT);
        settle().await;
        let flushed = s.st.tripwires.fold.flush();
        assert_eq!(
            flushed.lines.len(),
            MAX_DENY_CLAIMS,
            "one line a claim judged"
        );
        assert!(flushed.lines.iter().all(|l| l.count == 2));
        let judged: Vec<Uuid> = flushed
            .lines
            .iter()
            .filter_map(|l| l.detail.claim_uid)
            .collect();
        assert!(
            !judged.contains(&denied[MAX_DENY_CLAIMS]),
            "the last is not"
        );
    }

    #[test]
    fn a_wrong_shaped_svid_at_the_handshake_is_identity_shape_and_the_plain_gateway_id_is_too_while_the_switch_is_off()
     {
        let naming = Naming {
            trust_domain: "sandbox.test".into(),
        };
        let id = |s: &str| mediatore_tls::SpiffeId::new(s).expect("a SPIFFE ID");
        let admitted = [
            naming.node_id(EK),
            naming.claim_id(Uuid::new_v4()),
            naming.gateway_authorizer_id(),
        ];
        let strangers = [
            naming.broker_id(),
            "spiffe://sandbox.test/gateway/authorizer/extra".to_owned(),
            "spiffe://sandbox.test/spire/agent/tpm/abc".to_owned(),
        ];
        let plain = naming.gateway_id();
        for accept_plain in [false, true] {
            let fold = Arc::new(ClassFold::default());
            let classified =
                sandbox_authorizer_classified(naming.clone(), accept_plain, fold.clone());
            let bare = crate::sandbox_authorizer(naming.clone(), accept_plain);
            for peer in admitted.iter().chain(&strangers).chain([&plain]) {
                assert_eq!(
                    classified(&id(peer)),
                    bare(&id(peer)),
                    "classifying changes no handshake"
                );
                // Twice: a repeat is a count, not a line.
                classified(&id(peer));
            }
            let mut want: Vec<String> = strangers.to_vec();
            if !accept_plain {
                want.push(plain.clone());
            }
            want.sort();
            let flushed = fold.flush();
            let got: Vec<String> = flushed.lines.iter().map(|l| l.peer.clone()).collect();
            assert_eq!(got, want);
            for line in &flushed.lines {
                assert_eq!(
                    (line.class, line.count, line.detail.route),
                    (TripClass::IdentityShape, 2, HANDSHAKE)
                );
            }
        }
    }

    // ---------- what is deliberately not a class: each records nothing ----------

    #[tokio::test]
    async fn a_request_for_a_claim_released_a_moment_ago_records_nothing() {
        let s = scene(&all_tripping()).await;
        s.store
            .inner
            .revoke_claim(s.rec.uid, Timestamp::now())
            .await
            .unwrap();
        let uri = format!("/v1/gateway/claims/{}", s.rec.uid);
        let credential = format!("{uri}/credential");
        for (method, uri, peer, body, status) in [
            ("POST", "/v1/token", &s.claim, token_for("grafana"), 403),
            ("POST", "/v1/token", &s.claim, token_for("elsewhere"), 403),
            ("GET", "/v1/me", &s.node, String::new(), 404),
            ("POST", "/v1/me/exit", &s.node, "{}".to_owned(), 204),
            ("GET", uri.as_str(), &s.authorizer, String::new(), 404),
            (
                "POST",
                credential.as_str(),
                &s.authorizer,
                token_for("grafana"),
                404,
            ),
            (
                "POST",
                "/v1/gateway/decisions",
                &s.authorizer,
                s.deny("evil.example:443"),
                204,
            ),
        ] {
            let a = send(&s.st, method, uri, peer, &body).await;
            assert_eq!(a.status.as_u16(), status, "{method} {uri}");
        }
        settle().await;
        assert_eq!(noted(&s.st), []);
        assert!(s.store.calls().is_empty() && s.summary().await.is_none());
    }

    #[tokio::test]
    async fn an_audience_rendered_and_since_narrowed_records_nothing() {
        // `narrowed` is in a route the guest was handed and is the claim's no more: the
        // refusal an honest proxy gets after a newer bundle (ADR-0061).
        let s = scene(&all_tripping()).await;
        let a = send(&s.st, "POST", "/v1/token", &s.claim, &token_for("narrowed")).await;
        assert_eq!(a.status, StatusCode::BAD_REQUEST);
        settle().await;
        assert_eq!(noted(&s.st), []);
        assert!(s.untouched().await);
    }

    #[tokio::test]
    async fn a_deny_for_a_route_rendered_and_since_narrowed_records_nothing() {
        let s = scene(&all_tripping()).await;
        let ghost = Uuid::new_v4();
        let batch = decisions(&[
            // A route the guest was handed, a destination it was handed, and the same
            // authority as an inject request carries it: no port, another case.
            (
                s.rec.uid,
                "narrowed.example:443",
                "deny",
                Some("not_allowed"),
            ),
            (
                s.rec.uid,
                "direct.example:8443",
                "deny",
                Some("not_allowed"),
            ),
            (s.rec.uid, "GRAFANA.example", "deny", Some("not_allowed")),
            // A release racing a request, and a claim the store does not hold.
            (s.rec.uid, "evil.example:443", "deny", Some("claim_gone")),
            (ghost, "evil.example:443", "deny", Some("not_allowed")),
        ]);
        let a = send(
            &s.st,
            "POST",
            "/v1/gateway/decisions",
            &s.authorizer,
            &batch,
        )
        .await;
        assert_eq!(a.status, StatusCode::NO_CONTENT);
        settle().await;
        assert_eq!(noted(&s.st), []);
        assert!(s.untouched().await);
        // The port is part of what was handed: the same host on another port is outside.
        assert!(!inside(&handed(), "grafana.example:8443"));
        assert!(!inside(&handed(), "direct.example"));
        assert!(!inside(&handed(), "grafana.example:0"));
        assert!(!inside(&handed(), "grafana.example:x"));
        assert!(inside(&handed(), "grafana.example:443"));
    }

    #[tokio::test]
    async fn no_claim_for_a_node_not_bound_yet_records_nothing() {
        let s = scene(&all_tripping()).await;
        let waiting = register(&s.st, OTHER_EK).await;
        let a = send(&s.st, "GET", "/v1/me", &waiting, "").await;
        assert_eq!(a.status, StatusCode::NOT_FOUND);
        let a = send(&s.st, "POST", "/v1/me/exit", &waiting, "{}").await;
        assert_eq!(a.status, StatusCode::NO_CONTENT);
        settle().await;
        assert_eq!(noted(&s.st), []);
        assert!(s.untouched().await);
    }

    #[tokio::test]
    async fn a_malformed_body_records_nothing() {
        let s = scene(&all_tripping()).await;
        let credential = format!("/v1/gateway/claims/{}/credential", s.rec.uid);
        for (uri, peer) in [
            ("/v1/token", &s.claim),
            ("/v1/nodes", &s.node),
            ("/v1/me/exit", &s.node),
            ("/v1/me/report", &s.node),
            ("/v1/gateway/decisions", &s.authorizer),
            (credential.as_str(), &s.authorizer),
            // The extractor answers before the handler looks at who is asking: a body that
            // does not read is refused the same for a peer of another kind, and is no class.
            ("/v1/me/exit", &s.claim),
            ("/v1/token", &s.node),
        ] {
            let a = send(&s.st, "POST", uri, peer, "{ not json").await;
            assert!(a.status.is_client_error(), "{uri}");
        }
        // A batch whose shape is off is refused whole and none of its denies is judged.
        let mut batch: serde_json::Value =
            serde_json::from_str(&s.deny("evil.example:443")).unwrap();
        batch["gateway"] = "Not A Name".into();
        let a = send(
            &s.st,
            "POST",
            "/v1/gateway/decisions",
            &s.authorizer,
            &batch.to_string(),
        )
        .await;
        assert_eq!(a.status, StatusCode::BAD_REQUEST);
        // A claim uid that is no uuid is the route's own 400.
        let a = send(
            &s.st,
            "GET",
            "/v1/gateway/claims/not-a-uuid",
            &s.authorizer,
            "",
        )
        .await;
        assert_eq!(a.status, StatusCode::BAD_REQUEST);
        settle().await;
        assert_eq!(noted(&s.st), []);
        assert!(s.untouched().await);
    }

    #[tokio::test]
    async fn a_wrong_method_on_a_known_path_records_nothing() {
        let s = scene(&all_tripping()).await;
        for (method, uri) in [
            ("DELETE", "/v1/me"),
            ("GET", "/v1/token"),
            ("PUT", "/v1/gateway/decisions"),
        ] {
            for peer in [&s.claim, &s.node, &s.authorizer] {
                let a = send(&s.st, method, uri, peer, "").await;
                assert_eq!(a.status, StatusCode::METHOD_NOT_ALLOWED, "{method} {uri}");
            }
        }
        settle().await;
        assert_eq!(noted(&s.st), []);
        assert!(s.untouched().await);
    }

    #[tokio::test]
    async fn a_claim_with_nothing_rendered_is_never_judged_against_rendered() {
        let s = scene(&all_tripping()).await;
        // A claim under no policy: nothing was recorded of what its guest was handed.
        let mut bare = claim(&["grafana"], None);
        bare.expires_at = Some(Timestamp::now() + SignedDuration::from_hours(1));
        s.st.store.put_claim(bare.clone()).await.unwrap();
        let peer = s.st.naming.claim_id(bare.uid);
        let a = send(&s.st, "POST", "/v1/token", &peer, &token_for("elsewhere")).await;
        assert_eq!(a.status, StatusCode::BAD_REQUEST);
        let batch = decisions(&[(bare.uid, "evil.example:443", "deny", Some("not_allowed"))]);
        let a = send(
            &s.st,
            "POST",
            "/v1/gateway/decisions",
            &s.authorizer,
            &batch,
        )
        .await;
        assert_eq!(a.status, StatusCode::NO_CONTENT);
        settle().await;
        assert_eq!(noted(&s.st), []);
        let held = s.store.inner.get_claim(bare.uid).await.unwrap();
        assert!(held.tripped.is_none() && held.revoked_at.is_none());
        assert!(s.untouched().await);
    }

    #[tokio::test]
    async fn an_identity_of_no_admitted_shape_is_classified_nowhere() {
        // Only a `dev_mode` header can carry one past the handshake; whatever it says, it
        // is counted under no class and kept in no table.
        let s = scene(&all_tripping()).await;
        let odd = format!("spiffe://elsewhere.test/{CANARY_HEADER}");
        for (method, uri) in [("GET", "/v1/me"), ("POST", "/v1/token"), ("GET", "/v1/zzz")] {
            send(&s.st, method, uri, &odd, &token_for("grafana")).await;
        }
        let resp = sandbox_router(s.st.clone())
            .oneshot(request("GET", "/v1/zzz", None, &[], ""))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        settle().await;
        assert_eq!(noted(&s.st), []);
        // A node identity whose last segment is no EK hash is spelled without it.
        let peer = identify(&s.st.naming, "spiffe://sandbox.test/banlieue/node/whatever").unwrap();
        assert_eq!(
            peer.id,
            "spiffe://sandbox.test/banlieue/node/(not-an-ek-hash)"
        );
        assert_eq!(peer.ek, None);
    }

    // ---------- under trip, and that only a claim is ever ended ----------

    #[tokio::test]
    async fn a_claim_scoped_class_at_trip_ends_the_claim_after_the_answer_and_once() {
        let cases: [(TripClass, &str, &str, bool, Option<TripTarget>); 3] = [
            (TripClass::ForeignRoute, "GET", "/v1/me", true, None),
            (TripClass::UnknownRoute, "GET", "/v1/zzz", true, None),
            (
                TripClass::AudienceOutsideRendered,
                "POST",
                "/v1/token",
                true,
                None,
            ),
        ];
        for (class, method, uri, as_claim, target) in cases {
            let s = scene(&[class]).await;
            let (peer, body) = if as_claim {
                (&s.claim, token_for("elsewhere"))
            } else {
                (&s.authorizer, s.deny("evil.example:443"))
            };
            let before = Timestamp::now();
            let first = send(&s.st, method, uri, peer, &body).await;
            assert!(
                s.store.calls().is_empty(),
                "{class:?}: the answer is built before anything is written"
            );
            settle().await;
            assert_eq!(
                s.store.calls(),
                ["tripped", "release", "fold"],
                "{class:?}: tripped by compare and set, the release, then the summary"
            );
            let held = s.held().await;
            let tripped = held.tripped.clone().expect("tripped");
            assert_eq!(tripped.kind, TripKind::Protocol, "{class:?}");
            assert_eq!(tripped.class, Some(class));
            assert_eq!(tripped.source, TripSource::Peer);
            assert_eq!(tripped.trap, None);
            assert_eq!(tripped.target, target, "{class:?}");
            assert!(tripped.at >= before && tripped.recorded_at == tripped.at);
            assert!(held.revoked_at.is_some(), "{class:?}: released");
            assert_eq!(
                s.entries().await,
                [(TripEffect::Tripped, Some(class), target.clone(), 1)]
            );
            // The same again: the same answer for a class whose refusal does not depend on
            // the claim being live, one count more, and nothing more is ended or written.
            let again = send(&s.st, method, uri, peer, &body).await;
            if class != TripClass::AudienceOutsideRendered {
                assert_eq!(again, first, "{class:?}");
            }
            settle().await;
            assert_eq!(s.store.calls().len(), 3, "{class:?}: one end a line");
            // The flush records what came after the event that ended the claim.
            capture_logs();
            flush(&s.st).await;
            let logs = captured();
            let line = logs.lines().find(|l| l.contains(AUDIT)).expect("a line");
            assert!(line.contains("action=\"trip\""), "{line}");
            assert!(line.contains("scope=\"claim\""), "{line}");
            assert!(line.contains(&format!("claim_uid={}", s.rec.uid)), "{line}");
            let reported = s
                .entries()
                .await
                .into_iter()
                .filter(|e| e.0 == TripEffect::Reported)
                .count();
            // A token asked for by a tripped claim is refused before its audience is read:
            // it has no second event.
            let repeats = class != TripClass::AudienceOutsideRendered;
            assert_eq!(reported, usize::from(repeats), "{class:?}");
        }
    }

    #[tokio::test]
    async fn a_claim_that_had_ended_already_is_not_tripped_after_the_fact() {
        let s = scene(&all_tripping()).await;
        s.store
            .inner
            .revoke_claim(s.rec.uid, Timestamp::now())
            .await
            .unwrap();
        send(&s.st, "GET", "/v1/me", &s.claim, "").await;
        settle().await;
        let held = s.held().await;
        assert!(
            held.tripped.is_none(),
            "tripped is never set after the fact"
        );
        assert_eq!(
            s.entries().await,
            [(TripEffect::Reported, Some(TripClass::ForeignRoute), None, 1)]
        );
    }

    #[test]
    fn the_authorizers_classes_never_end_anything_whatever_the_configuration_says() {
        let naming = Naming {
            trust_domain: "sandbox.test".into(),
        };
        let uid = Uuid::new_v4();
        let peers = [
            identify(&naming, &naming.claim_id(uid)).unwrap(),
            identify(&naming, &naming.node_id(EK)).unwrap(),
            identify(&naming, &naming.gateway_authorizer_id()).unwrap(),
            identify(&naming, &naming.gateway_id()).unwrap(),
        ];
        let mut actions = crate::tripwires::ClassActions::default();
        for class in TripClass::PROTOCOL
            .into_iter()
            .chain(TripClass::SEGMENT)
            .chain(TripClass::DENIED)
        {
            let held_to_report = matches!(
                class,
                TripClass::IdentityShape
                    | TripClass::NoRecord
                    | TripClass::ClaimNeverIssued
                    | TripClass::CredentialOutsideInject
                    | TripClass::DenyOutsideRendered
                    | TripClass::GatewayPort
                    | TripClass::GatewayOutput
                    | TripClass::PoolInbound
                    | TripClass::PoolOutput
            );
            assert_eq!(class.may_trip(), !held_to_report, "{class:?}");
            // Three places, each enough: the table refuses the setting, a `trip` that got
            // past it would not act, and the class is scoped to no claim to act on.
            assert_eq!(
                actions.set(class, ClassAction::Trip).is_err(),
                held_to_report
            );
            assert_eq!(acts(ClassAction::Trip, class), !held_to_report);
            assert!(!acts(ClassAction::Report, class));
            // A reported deny is scoped to the claim it names, for that claim's summary
            // (below), and ends nothing: the other two places hold it.
            if held_to_report && class != TripClass::DenyOutsideRendered {
                for peer in &peers {
                    assert_eq!(whom(&naming, class, peer, Some(uid)), None, "{class:?}");
                }
            }
        }
        // And on a class that may trip, the authorizer's own request is scoped to no claim.
        for class in [TripClass::ForeignRoute, TripClass::UnknownRoute] {
            assert_eq!(whom(&naming, class, &peers[2], None), None);
            assert_eq!(whom(&naming, class, &peers[3], None), None);
            assert_eq!(
                whom(&naming, class, &peers[0], None),
                Some(Whom::Claim(uid))
            );
            assert_eq!(
                whom(&naming, class, &peers[1], None),
                Some(Whom::Node(naming.agent_id(EK)))
            );
        }
        // A reported deny is scoped to the claim it names, never to who reported it.
        assert_eq!(
            whom(
                &naming,
                TripClass::DenyOutsideRendered,
                &peers[2],
                Some(uid)
            ),
            Some(Whom::Claim(uid))
        );
        assert_eq!(
            whom(&naming, TripClass::DenyOutsideRendered, &peers[2], None),
            None
        );
    }

    // ---------- a trip changes no answer ----------

    /// One refusal of each class that has an answer: the class, the request, and the answer
    /// the route gave before any of it was classified.
    fn refusals(s: &Scene) -> Vec<(TripClass, &'static str, String, String, String, u16, String)> {
        let ghost = Uuid::new_v4();
        let forbidden =
            |detail: &str| format!("{{\"error\":\"forbidden\",\"detail\":\"{detail}\"}}");
        vec![
            (
                TripClass::ForeignRoute,
                "GET",
                "/v1/me".into(),
                s.claim.clone(),
                String::new(),
                403,
                forbidden("peer is not a node identity"),
            ),
            (
                TripClass::ForeignRoute,
                "POST",
                "/v1/token".into(),
                s.node.clone(),
                token_for("grafana"),
                403,
                forbidden("peer is not a claim identity"),
            ),
            (
                TripClass::ForeignRoute,
                "GET",
                format!("/v1/gateway/claims/{}", s.rec.uid),
                s.claim.clone(),
                String::new(),
                403,
                forbidden("peer is not the gateway authorizer's identity"),
            ),
            (
                TripClass::UnknownRoute,
                "GET",
                "/v1/zzz".into(),
                s.claim.clone(),
                String::new(),
                404,
                String::new(),
            ),
            (
                TripClass::NoRecord,
                "POST",
                "/v1/token".into(),
                s.st.naming.claim_id(ghost),
                token_for("grafana"),
                403,
                forbidden("unknown claim"),
            ),
            (
                TripClass::NoRecord,
                "GET",
                "/v1/me".into(),
                s.st.naming.node_id(OTHER_EK),
                String::new(),
                403,
                forbidden("node not registered"),
            ),
            (
                TripClass::AudienceOutsideRendered,
                "POST",
                "/v1/token".into(),
                s.claim.clone(),
                token_for("elsewhere"),
                400,
                "{\"error\":\"unknown_audience\",\"detail\":\"elsewhere\"}".into(),
            ),
            (
                TripClass::ClaimNeverIssued,
                "GET",
                format!("/v1/gateway/claims/{ghost}"),
                s.authorizer.clone(),
                String::new(),
                404,
                "{\"error\":\"not_found\",\"detail\":\"no live claim with this uid\"}".into(),
            ),
            (
                TripClass::CredentialOutsideInject,
                "POST",
                format!("/v1/gateway/claims/{}/credential", s.rec.uid),
                s.authorizer.clone(),
                token_for("grafana"),
                403,
                "{\"error\":\"not_placed_at_gateway\",\"detail\":\"the audience's credential is placed in the proxy, not at the gateway\"}".into(),
            ),
            (
                TripClass::DenyOutsideRendered,
                "POST",
                "/v1/gateway/decisions".into(),
                s.authorizer.clone(),
                s.deny("evil.example:443"),
                204,
                String::new(),
            ),
        ]
    }

    #[tokio::test]
    async fn the_response_is_byte_identical_with_the_class_at_report_and_at_trip() {
        let count = refusals(&scene(&[]).await).len();
        let mut classes = std::collections::BTreeSet::new();
        for n in 0..count {
            // A scene of its own for each answer: a trip ends the claim, and the answer
            // compared is the one to the request that tripped.
            let report = scene(&[]).await;
            let trip = scene(&all_tripping()).await;
            let unjudged = scene_with(&[], |st| st.tripwires.no_record_judged = false).await;
            let mut answers = Vec::new();
            for s in [&report, &trip, &unjudged] {
                let (class, method, uri, peer, body, status, text) = refusals(s).remove(n);
                classes.insert(class);
                // The scenes differ in the uids their requests name and in nothing else of
                // the answer: status, every header, every byte of the body.
                let a = send(&s.st, method, &uri, &peer, &body).await;
                assert_eq!(a.status.as_u16(), status, "{class:?} {method} {uri}");
                assert_eq!(
                    String::from_utf8_lossy(&a.body),
                    text,
                    "{class:?}: the body the route gave before it was classified"
                );
                answers.push(a);
                settle().await;
            }
            assert_eq!(answers[0], answers[1], "report and trip");
            assert_eq!(answers[0], answers[2], "judged and not judged");
            let (class, ..) = refusals(&trip).remove(n);
            // The comparison is of a request that was classified, and at trip acted on.
            let ended = trip.held().await.tripped.is_some();
            assert_eq!(
                ended,
                class.may_trip(),
                "{class:?}: ended at trip exactly when the class may trip"
            );
            assert!(report.held().await.tripped.is_none());
        }
        let with_an_answer: std::collections::BTreeSet<TripClass> = TripClass::PROTOCOL
            .into_iter()
            .filter(|c| *c != TripClass::IdentityShape)
            .collect();
        assert_eq!(
            classes, with_an_answer,
            "every class but the handshake's has an answer compared here"
        );
    }

    #[tokio::test]
    async fn the_fallback_answers_as_the_router_did_without_one() {
        // What axum answers for a path no route serves, from a router with no fallback.
        // Built as the sandbox router was before it had one: a route, the trace layer, a state.
        let bare: axum::Router = axum::Router::new()
            .route("/v1/me", axum::routing::get(|| async {}))
            .layer(crate::request_trace())
            .with_state(());
        for (method, uri) in [("GET", "/v1/zzz"), ("POST", "/"), ("DELETE", "/v1/me/x/y")] {
            let want = answer_of(
                bare.clone()
                    .oneshot(request(method, uri, None, &[], ""))
                    .await
                    .unwrap(),
            )
            .await;
            assert_eq!(want.status, StatusCode::NOT_FOUND);
            for tripping in [vec![], all_tripping()] {
                let s = scene(&tripping).await;
                let got = send(&s.st, method, uri, &s.claim, "").await;
                assert_eq!(got, want, "{method} {uri}");
            }
        }
        // And a known path under another method is the router's own 405, with its `allow`.
        let want = answer_of(
            bare.oneshot(request("POST", "/v1/me", None, &[], ""))
                .await
                .unwrap(),
        )
        .await;
        let s = scene(&all_tripping()).await;
        let got = send(&s.st, "POST", "/v1/me", &s.claim, "").await;
        assert_eq!(got, want);
    }

    // ---------- the fold bounds the lines ----------

    #[tokio::test]
    async fn repeats_of_one_class_and_peer_are_one_line_a_minute_with_a_count() {
        capture_logs();
        let s = scene(&[]).await;
        for _ in 0..5 {
            send(&s.st, "GET", "/v1/me", &s.claim, "").await;
        }
        send(
            &s.st,
            "POST",
            "/v1/token",
            &s.claim,
            &token_for("elsewhere"),
        )
        .await;
        assert!(
            !captured().contains(AUDIT),
            "no line a request: the flush writes them"
        );
        flush(&s.st).await;
        let logs = captured();
        let lines: Vec<&str> = logs.lines().filter(|l| l.contains(AUDIT)).collect();
        assert_eq!(lines.len(), 2, "one line a class and peer");
        assert!(lines.iter().all(|l| l.contains("WARN")));
        for want in [
            "class=\"foreign_route\"",
            "route=\"GET /v1/me\"",
            "audience=\"\"",
            "count=5",
        ] {
            assert!(lines[0].contains(want), "{want} in {}", lines[0]);
        }
        for want in [
            "class=\"audience_outside_rendered\"".to_owned(),
            "scope=\"claim\"".to_owned(),
            "action=\"report\"".to_owned(),
            format!("peer={}", s.claim),
            "route=\"POST /v1/token\"".to_owned(),
            format!("claim_uid={}", s.rec.uid),
            "audience=\"elsewhere\"".to_owned(),
            "authority=\"\"".to_owned(),
            "count=1".to_owned(),
        ] {
            assert!(lines[1].contains(&want), "{want} in {}", lines[1]);
        }
        // A flush with nothing counted writes nothing.
        capture_logs();
        flush(&s.st).await;
        assert!(!captured().contains(AUDIT));
        assert_eq!(crate::tripwires::FOLD_FLUSH_EVERY, Duration::from_secs(60));
    }

    #[tokio::test]
    async fn the_flush_task_writes_the_lines_on_its_interval() {
        capture_logs();
        let s = scene(&[]).await;
        let task = spawn_flush(s.st.clone(), Duration::from_millis(20));
        send(&s.st, "GET", "/v1/me", &s.claim, "").await;
        assert!(!captured().contains(AUDIT), "not with the request");
        for _ in 0..200 {
            if !s.entries().await.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(captured().contains(AUDIT), "at the interval");
        assert_eq!(
            s.entries().await.len(),
            1,
            "and the claim's summary with it"
        );
        task.abort();
    }

    #[tokio::test]
    async fn the_table_holds_1024_peers_and_counts_the_rest() {
        capture_logs();
        let s = scene(&[TripClass::ForeignRoute]).await;
        // More claim identities than the table holds, each on a node route once.
        for _ in 0..FOLD_MAX_PEERS + 3 {
            let peer = s.st.naming.claim_id(Uuid::new_v4());
            let a = send(&s.st, "GET", "/v1/me", &peer, "").await;
            assert_eq!(a.status, StatusCode::FORBIDDEN);
        }
        // A full table hides no trip: the claim that comes after it is ended all the same.
        send(&s.st, "GET", "/v1/me", &s.claim, "").await;
        settle().await;
        let held = s.held().await;
        assert!(held.tripped.is_some() && held.revoked_at.is_some());
        assert_eq!(
            s.entries().await,
            [(TripEffect::Tripped, Some(TripClass::ForeignRoute), None, 1)]
        );
        capture_logs();
        flush(&s.st).await;
        let logs = captured();
        assert_eq!(
            logs.lines().filter(|l| l.contains(AUDIT)).count(),
            FOLD_MAX_PEERS
        );
        let over = logs
            .lines()
            .find(|l| l.contains("more peers than the table holds"))
            .expect("the overflow line");
        assert!(over.contains("overflow=4"), "{over}");
        assert!(over.contains("max_peers=1024"), "{over}");
        assert!(
            !logs.contains(&s.claim),
            "a peer the table had no room for is in no line"
        );
    }

    // ---------- the honest request set ----------

    /// A body the route's extractor reads, so the handler is what answers.
    fn body_for(route: &str) -> String {
        match route {
            "POST /v1/nodes" => serde_json::json!({
                "ek_hash": EK, "dmi_uuid": Uuid::new_v4(), "hostname": "member-01",
            })
            .to_string(),
            "POST /v1/me/report" => report_body(),
            "POST /v1/me/exit" | "POST /v1/me/trip" => "{}".into(),
            "POST /v1/me/logs" => "{\"records\":[]}".into(),
            "POST /v1/token" | "POST /v1/gateway/claims/{uid}/credential" => token_for("anthropic"),
            "POST /v1/gateway/decisions" => decisions(&[]),
            _ => String::new(),
        }
    }

    #[tokio::test]
    async fn every_route_of_the_sandbox_router_is_in_the_honest_set_of_exactly_one_role() {
        // The list the router is built from. A route added to it fails here until it is
        // given a role in this table too: that is the class decision of ADR-0070.
        let served: Vec<(Role, &str)> =
            sandbox_routes().iter().map(|r| (r.role, r.route)).collect();
        let mut want = vec![
            (Role::Any, "GET /healthz"),
            (Role::Node, "POST /v1/nodes"),
            (Role::Node, "GET /v1/me"),
            (Role::Node, "POST /v1/me/report"),
            (Role::Node, "POST /v1/me/exit"),
            (Role::Node, "POST /v1/me/trip"),
            (Role::Node, "POST /v1/me/logs"),
            (Role::Claim, "POST /v1/token"),
            (Role::Authorizer, "GET /v1/gateway/claims/{uid}"),
            (Role::Authorizer, "POST /v1/gateway/decisions"),
            (Role::Authorizer, "POST /v1/gateway/claims/{uid}/credential"),
        ];
        assert_eq!(served, want, "the honest request set, role by role");
        want.sort_by_key(|(_, route)| *route);
        want.dedup_by_key(|(_, route)| *route);
        assert_eq!(
            want.len(),
            served.len(),
            "each route once, so one role each"
        );
        for (role, route) in &served {
            assert_eq!(crate::honest_role(route), Some(*role));
        }
        assert_eq!(crate::honest_role("GET /v1/zzz"), None);

        // And the router agrees with the list, route by route and role by role: with a body
        // its extractor reads, a route answers its own kind of peer without a class, and any
        // other admitted identity is `foreign_route` on it and on nothing else.
        for (role, route) in served {
            let (method, path) = route.split_once(' ').unwrap();
            for asking in [Role::Node, Role::Claim, Role::Authorizer] {
                // The trip route and the output route answer `501` before they look at the
                // peer unless their feature is on.
                let s = scene_with(&[], |st| {
                    st.tripwires.mode = mediatore_proto::trip::TrapsMode::Shadow;
                    st.logs = Some(mediatore_store::LogLimits {
                        max_bytes: mediatore_proto::DEFAULT_LOG_MAX_BYTES,
                    });
                })
                .await;
                let peer = match asking {
                    Role::Node => &s.node,
                    Role::Claim => &s.claim,
                    _ => &s.authorizer,
                };
                let uri = path.replace("{uid}", &s.rec.uid.to_string());
                let a = send(&s.st, method, &uri, peer, &body_for(route)).await;
                assert_ne!(a.status, StatusCode::METHOD_NOT_ALLOWED, "{route}");
                settle().await;
                let classes: Vec<TripClass> = noted(&s.st).into_iter().map(|l| l.0).collect();
                if role == Role::Any || role == asking {
                    assert_eq!(classes, [], "{route} as {asking:?}: {}", a.status);
                } else {
                    assert_eq!(a.status, StatusCode::FORBIDDEN, "{route} as {asking:?}");
                    assert_eq!(classes, [TripClass::ForeignRoute], "{route} as {asking:?}");
                }
            }
        }
    }

    // ---------- nothing the peer sent is in a line ----------

    #[tokio::test]
    async fn a_token_a_path_and_a_header_planted_on_every_classified_route_appear_in_no_line() {
        capture_logs();
        let mut sent = 0;
        let mut kept = String::new();
        // Once with every class at report, so each class is reached, and once with every
        // class that may trip at trip, so the lines of a trip are in the capture too.
        for tripping in [vec![], all_tripping()] {
            let s = scene_with(&tripping, |st| {
                st.tripwires.mode = mediatore_proto::trip::TrapsMode::Shadow;
                st.accept_plain_gateway_identity = true;
                st.logs = Some(mediatore_store::LogLimits {
                    max_bytes: mediatore_proto::DEFAULT_LOG_MAX_BYTES,
                });
            })
            .await;
            sent += plant(&s).await;
            settle().await;
            flush(&s.st).await;
            // Nor on the status or the record: no entry and no target is a canary.
            kept.push_str(&serde_json::to_string(&s.summary().await).unwrap());
            kept.push_str(&serde_json::to_string(&s.held().await.tripped).unwrap());
        }
        let logs = captured();
        // The capture is live, at the level of the request span, and the classes fired.
        assert!(sent > 400);
        assert!(logs.contains("DEBUG request{method=\"POST\" route=\"/v1/token\"}"));
        assert!(logs.contains("route=\"(unknown)\""));
        for class in [
            "foreign_route",
            "unknown_route",
            "no_record",
            "audience_outside_rendered",
            "claim_never_issued",
            "credential_outside_inject",
            "deny_outside_rendered",
        ] {
            let fired = logs
                .lines()
                .any(|l| l.contains(AUDIT) && l.contains(&format!("class=\"{class}\"")));
            assert!(fired, "{class} fired in this run");
        }
        assert!(
            logs.contains("claim ended by a trip"),
            "and a trip acted in it"
        );
        for canary in CANARIES {
            assert!(
                !logs.contains(canary),
                "a value the peer planted is in a log line"
            );
        }
        assert!(kept.contains("deny_outside_rendered") && kept.contains("tripped"));
        for canary in CANARIES {
            assert!(
                !kept.contains(canary),
                "a value the peer planted is on a status or a record"
            );
        }
    }

    /// Every route of the router and three paths it does not serve, under every identity,
    /// each with a planted path, query, token and headers, and with bodies that carry an
    /// audience and a key no grammar admits. How many requests were sent.
    async fn plant(s: &Scene) -> usize {
        let ghost = s.st.naming.claim_id(Uuid::new_v4());
        let plain = s.st.naming.gateway_id();
        let extra = [
            ("authorization", format!("Bearer {CANARY_TOKEN}")),
            ("x-api-key", CANARY_TOKEN.to_owned()),
            ("cookie", format!("session={CANARY_HEADER}")),
            ("x-forwarded-for", CANARY_HEADER.to_owned()),
            ("user-agent", CANARY_HEADER.to_owned()),
        ];
        let extra: Vec<(&str, &str)> = extra.iter().map(|(k, v)| (*k, v.as_str())).collect();
        let query = format!("?token={CANARY_TOKEN}&q={CANARY_QUERY}");
        let audience = format!("aud/{CANARY_TOKEN}?");
        let peers = [&s.authorizer, &plain, &ghost, &s.claim, &s.node];
        let mut sent = 0;
        for route in sandbox_routes().iter().map(|r| r.route) {
            let (method, path) = route.split_once(' ').unwrap();
            let bodies = [
                body_for(route),
                token_for(&audience),
                s.deny("evil.example:443"),
                format!("{{\"audience\":\"grafana\",\"{CANARY_TOKEN}\":\"{CANARY_TOKEN}\"}}"),
                // Bodies no route reads: a value where an enum, a uuid and a number go, a
                // key a closed type refuses, and no JSON at all.
                format!(
                    "{{\"gateway\":\"gateway-02\",\"decisions\":[{{\"at\":\"{CANARY_TOKEN}\",\"claim_uid\":\"{CANARY_TOKEN}\",\"kind\":\"{CANARY_TOKEN}\"}}]}}"
                ),
                format!("{{\"mode\":\"{CANARY_TOKEN}\",\"events\":[],\"{CANARY_TOKEN}\":1}}"),
                format!(
                    "{{\"ek_hash\":7,\"dmi_uuid\":\"{CANARY_TOKEN}\",\"audience\":[\"{CANARY_TOKEN}\"]}}"
                ),
                format!("{CANARY_TOKEN} is not json"),
            ];
            for peer in peers {
                // The node's own exit would end the claim before the routes after it are
                // reached: the one honest request that is left out.
                if route == crate::route::ME_EXIT && peer == &s.node {
                    continue;
                }
                let uids = [
                    s.rec.uid.to_string(),
                    Uuid::new_v4().to_string(),
                    CANARY_PATH.to_owned(),
                ];
                for uid in uids {
                    for body in &bodies {
                        let uri = format!("{}{query}", path.replace("{uid}", &uid));
                        let req = request(method, &uri, Some(peer), &extra, body);
                        sandbox_router(s.st.clone()).oneshot(req).await.unwrap();
                        sent += 1;
                    }
                }
            }
        }
        for peer in peers {
            for path in [
                format!("/v1/{CANARY_PATH}"),
                format!("/v1/me/{CANARY_PATH}"),
                format!("/{CANARY_PATH}/v1/token"),
            ] {
                let uri = format!("{path}{query}");
                let req = request("POST", &uri, Some(peer), &extra, &token_for(&audience));
                sandbox_router(s.st.clone()).oneshot(req).await.unwrap();
                sent += 1;
            }
        }
        sent
    }

    #[tokio::test]
    async fn the_request_span_names_the_method_and_the_route_template_and_never_the_uri() {
        capture_logs();
        let s = scene(&[]).await;
        let uri = format!("/v1/gateway/claims/{CANARY_PATH}?q={CANARY_QUERY}");
        send(&s.st, "GET", &uri, &s.authorizer, "").await;
        let req = request("CANARY-METHOD-91bc", "/v1/me", Some(&s.node), &[], "");
        sandbox_router(s.st.clone()).oneshot(req).await.unwrap();
        // The user listener's router has the same span.
        let uri = format!("/v1/claims/{CANARY_PATH}?namespace={CANARY_QUERY}");
        let req = request("GET", &uri, None, &[("authorization", "Bearer x")], "");
        user_router(s.st.clone()).oneshot(req).await.unwrap();
        let logs = captured();
        assert!(
            logs.contains("request{method=\"GET\" route=\"/v1/gateway/claims/{uid}\"}"),
            "{logs}"
        );
        assert!(logs.contains("request{method=\"(other)\" route=\"/v1/me\"}"));
        assert!(logs.contains("request{method=\"GET\" route=\"/v1/claims/{name}\"}"));
        for planted in [CANARY_PATH, CANARY_QUERY, "CANARY-METHOD"] {
            assert!(!logs.contains(planted), "{planted} is in a line");
        }
    }

    // ---------- the gateway's probes ----------

    #[tokio::test]
    async fn each_probe_of_a_batch_is_one_line_and_ends_and_folds_nothing() {
        capture_logs();
        let s = scene(&all_tripping()).await;
        let batch = serde_json::json!({
            "gateway": "gateway-02",
            "decisions": [],
            "probes": [
                { "at": "2026-11-27T10:00:00Z", "class": "gateway_port", "count": 7,
                  "port": 22, "source_address": "198.51.100.9" },
                // The remainder of a full set: no port and no source.
                { "at": "2026-11-27T10:00:01Z", "class": "gateway_port", "count": 2 },
                { "at": "2026-11-27T10:00:02Z", "class": "gateway_output", "count": 1,
                  "port": 443, "user": "envoy-inject" },
                { "at": "2026-11-27T10:00:03Z", "class": "gateway_output", "count": 3 },
            ],
        });
        let a = send(
            &s.st,
            "POST",
            "/v1/gateway/decisions",
            &s.authorizer,
            &batch.to_string(),
        )
        .await;
        assert_eq!(a.status, StatusCode::NO_CONTENT);
        assert_eq!(a.body.len(), 0, "no body");
        settle().await;
        let logs = captured();
        let lines: Vec<&str> = logs
            .lines()
            .filter(|l| l.contains("gateway probe"))
            .collect();
        assert_eq!(lines.len(), 4, "one line a probe");
        assert!(lines.iter().all(|l| l.contains("WARN")));
        for want in [
            "kind=\"segment\"",
            "class=\"gateway_port\"",
            "gateway=gateway-02",
            "count=7",
            "port=22",
            "source_address=\"198.51.100.9\"",
            "user=\"\"",
            "at=2026-11-27T10:00:00Z",
        ] {
            assert!(lines[0].contains(want), "{want} in {}", lines[0]);
        }
        for want in ["count=2", "port= ", "source_address=\"\"", "user=\"\""] {
            assert!(lines[1].contains(want), "{want} in {}", lines[1]);
        }
        for want in [
            "class=\"gateway_output\"",
            "port=443",
            "user=\"envoy-inject\"",
        ] {
            assert!(lines[2].contains(want), "{want} in {}", lines[2]);
        }
        // Unattributed, on no claim and in no table, whatever the configuration says.
        assert_eq!(noted(&s.st), []);
        assert!(s.untouched().await);
        let mut actions = crate::tripwires::ClassActions::default();
        for class in TripClass::SEGMENT {
            assert!(actions.set(class, ClassAction::Trip).is_err());
        }

        // From anything but the authorizer, and of a shape that is off: no line at all.
        capture_logs();
        for peer in [&s.claim, &s.node] {
            let a = send(
                &s.st,
                "POST",
                "/v1/gateway/decisions",
                peer,
                &batch.to_string(),
            )
            .await;
            assert_eq!(a.status, StatusCode::FORBIDDEN);
        }
        let probe = batch["probes"][0].clone();
        let mut too_many = batch.clone();
        too_many["probes"] =
            vec![probe.clone(); mediatore_proto::trip::MAX_GATEWAY_PROBES + 1].into();
        let mut wrong_class = batch.clone();
        wrong_class["probes"][0]["class"] = "pool_inbound".into();
        let mut planted = batch.clone();
        planted["probes"][2]["user"] = format!("a/{CANARY_PATH}").into();
        let mut unknown_field = batch.clone();
        unknown_field["probes"][0]["path"] = CANARY_PATH.into();
        for body in [too_many, wrong_class, planted, unknown_field] {
            let a = send(
                &s.st,
                "POST",
                "/v1/gateway/decisions",
                &s.authorizer,
                &body.to_string(),
            )
            .await;
            assert!(a.status.is_client_error());
        }
        let logs = captured();
        assert!(
            !logs.contains("gateway probe"),
            "a refused batch is refused whole"
        );
        assert!(!logs.contains(CANARY_PATH));
    }

    #[tokio::test]
    async fn a_probes_source_is_named_from_the_cache_and_the_answer_is_unchanged() {
        // ADR-0078: the holder of a probe's source address is named on its line where exactly
        // one live member or declared host holds it. The answer is byte for byte the one
        // without a cache, and nothing is folded, written or ended.
        let batch = serde_json::json!({
            "gateway": "gateway-02",
            "decisions": [],
            "probes": [
                { "at": "2026-11-28T10:00:00Z", "class": "gateway_port", "count": 7,
                  "port": 22, "source_address": "198.51.100.9" },
                { "at": "2026-11-28T10:00:01Z", "class": "gateway_port", "count": 1,
                  "port": 23, "source_address": "198.51.100.10" },
                { "at": "2026-11-28T10:00:02Z", "class": "gateway_port", "count": 1,
                  "port": 24, "source_address": "198.51.100.11" },
                { "at": "2026-11-28T10:00:03Z", "class": "gateway_output", "count": 1,
                  "port": 443, "user": "envoy-inject" },
            ],
        })
        .to_string();
        let mut answers = Vec::new();
        for filled in [false, true] {
            capture_logs();
            let s = scene(&all_tripping()).await;
            if filled {
                crate::trip::tests::list(
                    &s.st,
                    &[
                        crate::trip::tests::member_vm("member-1", &["198.51.100.9"]),
                        crate::trip::tests::member_vm("member-2", &["198.51.100.10"]),
                        crate::trip::tests::member_vm("member-3", &["198.51.100.10"]),
                    ],
                    &[crate::trip::tests::bound_claim("member-1", s.rec.uid)],
                );
            }
            answers.push(
                send(
                    &s.st,
                    "POST",
                    "/v1/gateway/decisions",
                    &s.authorizer,
                    &batch,
                )
                .await,
            );
            settle().await;
            let logs = captured();
            let lines: Vec<&str> = logs
                .lines()
                .filter(|l| l.contains("gateway probe"))
                .collect();
            assert_eq!(lines.len(), 4, "one line a probe");
            if filled {
                for want in [
                    "attribution=\"member\"".to_owned(),
                    "source_vm=member-1".to_owned(),
                    "source_namespace=sandboxes".to_owned(),
                    format!(
                        "source_node={}",
                        s.st.naming.agent_id(mediatore_testkit::ek::RSA_EK_HASH)
                    ),
                    format!("source_claim_uid={}", s.rec.uid),
                ] {
                    assert!(lines[0].contains(&want), "{want} in {}", lines[0]);
                }
                assert!(
                    lines[1].contains("attribution=\"ambiguous\""),
                    "{}",
                    lines[1]
                );
                assert!(lines[1].contains("source_vm= "), "{}", lines[1]);
            } else {
                assert!(
                    lines[0].contains("attribution=\"unattributed\""),
                    "{}",
                    lines[0]
                );
                assert!(
                    lines[1].contains("attribution=\"unattributed\""),
                    "{}",
                    lines[1]
                );
            }
            assert!(
                lines[2].contains("attribution=\"unattributed\""),
                "{}",
                lines[2]
            );
            assert!(
                lines[3].contains("attribution=\"unattributed\""),
                "{}",
                lines[3]
            );
            // On no claim, in no table, nothing ended.
            assert_eq!(noted(&s.st), []);
            assert!(s.untouched().await);
        }
        assert_eq!(answers[0], answers[1], "attribution changes no answer");
    }

    // ---------- the grammar of what a line may carry ----------

    #[test]
    fn an_authority_is_a_host_and_a_port_and_a_target_only_within_the_targets_grammar() {
        assert_eq!(host_port("git.example:8443"), Some(("git.example", 8443)));
        assert_eq!(host_port("git.example"), Some(("git.example", 443)));
        assert_eq!(host_port("[2001:db8::1]:8443"), Some(("2001:db8::1", 8443)));
        assert_eq!(host_port("[2001:db8::1]"), Some(("2001:db8::1", 443)));
        for off in [
            "",
            ":443",
            "git.example:",
            "git.example:0",
            "git.example:70000",
            "[::1]x",
        ] {
            assert_eq!(host_port(off), None, "{off}");
        }
        let target = |a: &str| target_of(&Named::Authority(a.into()));
        assert_eq!(
            target("git.example:8443"),
            Some(TripTarget::Host("git.example".into()))
        );
        assert_eq!(
            target("192.0.2.7:22"),
            Some(TripTarget::Address("192.0.2.7:22".into()))
        );
        assert_eq!(
            target("[2001:db8::1]"),
            Some(TripTarget::Address("[2001:db8::1]:443".into()))
        );
        assert_eq!(target("under_score.example:443"), None);
        assert_eq!(target("a:b:c"), None);
        assert_eq!(target(&format!("{}.example", "a".repeat(260))), None);
        assert_eq!(target_of(&Named::Audience("grafana".into())), None);
    }
}
