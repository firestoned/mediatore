// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Tripwires on the wire (ADR-0069, ADR-0070): the body of `POST /v1/me/trip`, what
//! `GET /v1/me` says about traps, what a claim's record and status keep of a trip, the probes a
//! gateway adds to ADR-0062's batch, and the messages on the local socket between the guest and
//! its egress proxy.
//!
//! Nothing here carries a bait value, a path, a query, a header or a body (ADR-0069 decision
//! 12). The one place a bait value travels is [`ProxyBait`], on the VM's own socket, and there
//! it is a [`Secret`], which never prints.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::Secret;

/// The most events one `POST /v1/me/trip` may carry (ADR-0069 decision 8).
pub const MAX_TRIP_EVENTS: usize = 32;
/// The most bytes of a trap's name: `a-z`, `0-9`, `.` and `-`.
pub const MAX_TRAP_NAME_BYTES: usize = 63;
/// The most bytes of a `host` target.
pub const MAX_TARGET_HOST_BYTES: usize = 253;
/// The most bytes of an `address` target: a bracketed IPv6 address, a colon and a port.
pub const MAX_TARGET_ADDRESS_BYTES: usize = 53;
/// The most bytes of a `source_address`: an IPv6 address with an embedded IPv4 one.
pub const MAX_SOURCE_ADDRESS_BYTES: usize = 45;
/// The largest containment figure a report may carry, in milliseconds.
pub const MAX_CONTAINMENT_MS: u32 = 600_000;
/// The largest count an event or an entry carries: what a JSON number holds exactly.
pub const MAX_TRIP_COUNT: u64 = (1 << 53) - 1;
/// The most entries of a claim's trip summary (ADR-0069 decision 9).
pub const MAX_TRIP_STATUS_ENTRIES: usize = 16;
/// What `Retry-After` says on `429 too_many_trips`, in seconds.
pub const TRIP_RETRY_AFTER_SECS: u64 = 1;
/// The most probes one gateway batch may carry (ADR-0070 decision 8).
pub const MAX_GATEWAY_PROBES: usize = 64;
/// The metadata service's address, the one `address` a `port` event may name (ADR-0069
/// decision 13): a platform constant, nobody's own.
pub const METADATA_ADDRESS: &str = "169.254.169.254:80";

/// `policy.traps` (ADR-0069 decision 5). Anything else refuses the broker at start.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrapsMode {
    /// Nothing is armed and `POST /v1/me/trip` answers `501`.
    #[default]
    Off,
    /// Every trap is armed, every use is reported as `would_trip`, nothing is ended.
    Shadow,
    /// A use ends the sandbox.
    Enforce,
}

impl TrapsMode {
    /// The word on the wire and in a log line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Shadow => "shadow",
            Self::Enforce => "enforce",
        }
    }

    /// The mode a report made under this one carries; `None` under `off`, where none is made.
    #[must_use]
    pub const fn trip_mode(self) -> Option<TripMode> {
        match self {
            Self::Off => None,
            Self::Shadow => Some(TripMode::Shadow),
            Self::Enforce => Some(TripMode::Enforce),
        }
    }
}

/// The mode a report is made under: never `off`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TripMode {
    /// The reporter cut nothing.
    Shadow,
    /// The reporter cut the network and killed the jail before it reported.
    Enforce,
}

impl TripMode {
    /// The word on the wire and in a log line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Shadow => "shadow",
            Self::Enforce => "enforce",
        }
    }
}

/// What kind of trap an event is about (ADR-0069 decision 2, ADR-0070 decisions 3 and 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TripKind {
    /// A drawn loopback listener, or the metadata address.
    Port,
    /// A drawn host the proxy carries as a route that is no audience.
    Route,
    /// A drawn credential seen in a request the proxy was asked to forward.
    Credential,
    /// The space no honest run reaches, by class.
    Denied,
    /// A request no honest build makes, classified by the broker.
    Protocol,
    /// A connection a host table dropped.
    Segment,
}

impl TripKind {
    /// The word on the wire and in a log line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Port => "port",
            Self::Route => "route",
            Self::Credential => "credential",
            Self::Denied => "denied",
            Self::Protocol => "protocol",
            Self::Segment => "segment",
        }
    }
}

/// Whose value an event's target is (ADR-0069 decision 8, ADR-0070).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TripSource {
    /// The guest's own: a decoy's port or host.
    Drawn,
    /// The workload chose it.
    Workload,
    /// A peer past the jail chose it.
    Peer,
}

impl TripSource {
    /// The word on the wire and in a log line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Drawn => "drawn",
            Self::Workload => "workload",
            Self::Peer => "peer",
        }
    }
}

/// Every class of both ADRs, one closed enum (so a label set built from it is fixed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TripClass {
    /// `denied`: a loopback port that is neither the proxy's nor drawn.
    LoopbackPort,
    /// `denied`: the link-local and private ranges.
    PrivateRange,
    /// `denied`: a host at the proxy that is no route.
    UnknownHost,
    /// `protocol`: a valid SVID of the trust domain in none of the admitted shapes.
    IdentityShape,
    /// `protocol`: an admitted identity on a route of another kind.
    ForeignRoute,
    /// `protocol`: a path the sandbox router does not serve.
    UnknownRoute,
    /// `protocol`: a claim identity with no record, or a node identity never registered.
    NoRecord,
    /// `protocol`: a token asked for an audience in no route the claim rendered.
    AudienceOutsideRendered,
    /// `protocol`: the authorizer asking about a claim uid the store never held.
    ClaimNeverIssued,
    /// `protocol`: the authorizer asking for a credential that is not gateway-placed.
    CredentialOutsideInject,
    /// `protocol`: a gateway's reported deny for an authority the claim never rendered.
    /// Records only ([`Self::may_trip`]).
    DenyOutsideRendered,
    /// `segment`: a new connection to a port the gateway does not serve.
    GatewayPort,
    /// `segment`: a gateway user's new connection outside its allowlist.
    GatewayOutput,
    /// `segment`: a new inbound connection to a pool VM.
    PoolInbound,
    /// `segment`: a connection from a pool VM's root or daemons that its host table drops.
    PoolOutput,
}

/// What a class can be scoped to (ADR-0070 decision 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassScope {
    /// One claim, always.
    Claim,
    /// Whichever of a claim, a node or the authorizer made the request.
    ClaimNodeOrAuthorizer,
    /// The authorizer's identity, which every gateway shares.
    Authorizer,
    /// Nothing that could be acted on.
    None,
}

impl TripClass {
    /// The classes of `kind: denied` (ADR-0069 decision 10).
    pub const DENIED: [Self; 3] = [Self::LoopbackPort, Self::PrivateRange, Self::UnknownHost];
    /// The classes of `kind: protocol` (ADR-0070 decision 3).
    pub const PROTOCOL: [Self; 8] = [
        Self::IdentityShape,
        Self::ForeignRoute,
        Self::UnknownRoute,
        Self::NoRecord,
        Self::AudienceOutsideRendered,
        Self::ClaimNeverIssued,
        Self::CredentialOutsideInject,
        Self::DenyOutsideRendered,
    ];
    /// The classes of `kind: segment` (ADR-0070 decision 4).
    pub const SEGMENT: [Self; 4] = [
        Self::GatewayPort,
        Self::GatewayOutput,
        Self::PoolInbound,
        Self::PoolOutput,
    ];

    /// The kind an event of this class has.
    #[must_use]
    pub const fn kind(self) -> TripKind {
        match self {
            Self::LoopbackPort | Self::PrivateRange | Self::UnknownHost => TripKind::Denied,
            Self::IdentityShape
            | Self::ForeignRoute
            | Self::UnknownRoute
            | Self::NoRecord
            | Self::AudienceOutsideRendered
            | Self::ClaimNeverIssued
            | Self::CredentialOutsideInject
            | Self::DenyOutsideRendered => TripKind::Protocol,
            Self::GatewayPort | Self::GatewayOutput | Self::PoolInbound | Self::PoolOutput => {
                TripKind::Segment
            }
        }
    }

    /// The word on the wire, in the configuration and in a log line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LoopbackPort => "loopback_port",
            Self::PrivateRange => "private_range",
            Self::UnknownHost => "unknown_host",
            Self::IdentityShape => "identity_shape",
            Self::ForeignRoute => "foreign_route",
            Self::UnknownRoute => "unknown_route",
            Self::NoRecord => "no_record",
            Self::AudienceOutsideRendered => "audience_outside_rendered",
            Self::ClaimNeverIssued => "claim_never_issued",
            Self::CredentialOutsideInject => "credential_outside_inject",
            Self::DenyOutsideRendered => "deny_outside_rendered",
            Self::GatewayPort => "gateway_port",
            Self::GatewayOutput => "gateway_output",
            Self::PoolInbound => "pool_inbound",
            Self::PoolOutput => "pool_output",
        }
    }

    /// What an event of this class can be scoped to.
    #[must_use]
    pub const fn scope(self) -> ClassScope {
        match self {
            Self::LoopbackPort
            | Self::PrivateRange
            | Self::UnknownHost
            | Self::AudienceOutsideRendered
            | Self::DenyOutsideRendered => ClassScope::Claim,
            Self::ForeignRoute | Self::UnknownRoute => ClassScope::ClaimNodeOrAuthorizer,
            Self::ClaimNeverIssued | Self::CredentialOutsideInject => ClassScope::Authorizer,
            Self::IdentityShape
            | Self::NoRecord
            | Self::GatewayPort
            | Self::GatewayOutput
            | Self::PoolInbound
            | Self::PoolOutput => ClassScope::None,
        }
    }

    /// Whether configuration may set this class to `trip`. Never for a class with no scope, a
    /// class of the authorizer's, or a `segment` class (ADR-0070 decisions 5 and 6): the
    /// broker refuses to start on one. Nor for `deny_outside_rendered`, scoped to a claim but
    /// on the authorizer's word: the claim uid comes from a gateway's batch, and every gateway
    /// shares the authorizer's identity, so `trip` would let any holder of it end any live
    /// claim (ADR-0070 decision 6, amended 2026-11-27).
    #[must_use]
    pub const fn may_trip(self) -> bool {
        matches!(
            self.scope(),
            ClassScope::Claim | ClassScope::ClaimNodeOrAuthorizer
        ) && !matches!(self, Self::DenyOutsideRendered)
    }
}

/// What a class does: `report` records, `trip` ends the claim. `report` everywhere by default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClassAction {
    /// Record the event and end nothing.
    #[default]
    Report,
    /// End the claim the event is scoped to.
    Trip,
}

impl ClassAction {
    /// The word in the configuration and in a log line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Report => "report",
            Self::Trip => "trip",
        }
    }
}

/// What the workload or peer reached for: exactly one of the three. On the wire
/// `{"host":"git.example"}`, `{"port":6379}` or `{"address":"192.0.2.7:22"}`. Never a path, a
/// query, a header, a body or a bait value.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TripTarget {
    /// An RFC 1123 name or a literal address without brackets, lower case, at most
    /// [`MAX_TARGET_HOST_BYTES`].
    Host(String),
    /// A TCP port, never zero.
    Port(u16),
    /// An IP address and a port, as `std::net::SocketAddr` prints one, lower case.
    Address(String),
}

impl TripTarget {
    /// The grammar of the variant; the first fault, named, with nothing of the value in it.
    fn check(&self) -> Result<(), &'static str> {
        match self {
            Self::Host(h) if !host_ok(h) => {
                Err("target host is not a lower-case name or address of 1 to 253 bytes")
            }
            Self::Port(0) => Err("target port is zero"),
            Self::Address(a) if !address_ok(a) => Err("target address is not an ip and a port"),
            _ => Ok(()),
        }
    }
}

/// For an audit line: the host, the port or the address, whose grammar
/// [`TripReport::validate`] has checked.
impl std::fmt::Display for TripTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Host(h) => f.write_str(h),
            Self::Port(p) => write!(f, "{p}"),
            Self::Address(a) => f.write_str(a),
        }
    }
}

/// 1 to 63 of `a-z`, `0-9`, `.` and `-`.
fn trap_ok(s: &str) -> bool {
    (1..=MAX_TRAP_NAME_BYTES).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'))
}

/// A lower-case DNS name, an IPv4 address, or an IPv6 address without brackets.
fn host_ok(s: &str) -> bool {
    if !(1..=MAX_TARGET_HOST_BYTES).contains(&s.len()) {
        return false;
    }
    let name = s
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'));
    name || (address_bytes(s, false) && s.parse::<Ipv6Addr>().is_ok())
}

/// Only what a lower-case IP address is written in, with brackets when `brackets`.
fn address_bytes(s: &str, brackets: bool) -> bool {
    s.bytes().all(|b| {
        b.is_ascii_digit()
            || matches!(b, b'a'..=b'f' | b'.' | b':')
            || (brackets && matches!(b, b'[' | b']'))
    })
}

/// An IP address and a port, lower case.
fn address_ok(s: &str) -> bool {
    s.len() <= MAX_TARGET_ADDRESS_BYTES && address_bytes(s, true) && s.parse::<SocketAddr>().is_ok()
}

/// An IP address alone, lower case.
fn ip_ok(s: &str) -> bool {
    s.len() <= MAX_SOURCE_ADDRESS_BYTES && address_bytes(s, false) && s.parse::<IpAddr>().is_ok()
}

fn one() -> u64 {
    1
}

/// One event of `POST /v1/me/trip` (ADR-0069 decision 8, extended by ADR-0070 decision 8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TripEvent {
    /// Random per event, from the reporter: what the broker deduplicates on.
    pub id: Uuid,
    /// The reporter's clock at its verdict.
    pub at: Timestamp,
    /// What kind of trap.
    pub kind: TripKind,
    /// The catalogue entry's or the drawn decoy's name: on `port`, `route` and `credential`
    /// only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trap: Option<String>,
    /// The class: on `denied`, `protocol` and `segment` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<TripClass>,
    /// What was reached for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<TripTarget>,
    /// Whose value the target is.
    pub source: TripSource,
    /// Milliseconds from the verdict to the network cut, on an `enforce` event only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub containment_ms: Option<u32>,
    /// How many uses this event folds; one when absent.
    #[serde(default = "one")]
    pub count: u64,
    /// The peer's address, without a port: on `segment`, the inbound classes only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_address: Option<String>,
}

impl TripEvent {
    /// The event against the matrix of [`TripReport::validate`].
    fn check(&self, mode: TripMode) -> Result<(), &'static str> {
        if !(1..=MAX_TRIP_COUNT).contains(&self.count) {
            return Err("count is not 1 to 2^53 - 1");
        }
        if let Some(ms) = self.containment_ms {
            if mode != TripMode::Enforce {
                return Err("containment_ms on a report that is not enforce");
            }
            if ms > MAX_CONTAINMENT_MS {
                return Err("containment_ms is over 600000");
            }
        }
        if !self.trap.as_deref().is_none_or(trap_ok) {
            return Err("trap is not 1 to 63 of a-z, 0-9, '.' and '-'");
        }
        if !self.source_address.as_deref().is_none_or(ip_ok) {
            return Err("source_address is not an ip address");
        }
        let Some(target) = &self.target else {
            return Err("an event without a target");
        };
        target.check()?;
        match self.kind {
            TripKind::Port => {
                self.check_decoy(TripSource::Drawn)?;
                let metadata = matches!(target, TripTarget::Address(a) if a == METADATA_ADDRESS);
                if metadata || matches!(target, TripTarget::Port(_)) {
                    Ok(())
                } else {
                    Err("a port event's target is not a port or the metadata address")
                }
            }
            TripKind::Route => {
                self.check_decoy(TripSource::Drawn)?;
                host_target(target, "a route event's target is not a host")
            }
            TripKind::Credential => {
                self.check_decoy(TripSource::Workload)?;
                host_target(target, "a credential event's target is not a host")
            }
            TripKind::Denied => self.check_denied(target),
            TripKind::Segment => self.check_segment(target),
            TripKind::Protocol => Err("a protocol event is the broker's own and is never reported"),
        }
    }

    /// `port`, `route` and `credential`: a named trap, no class, no source address.
    fn check_decoy(&self, source: TripSource) -> Result<(), &'static str> {
        if self.trap.is_none() {
            return Err("a port, route or credential event without a trap");
        }
        if self.class.is_some() {
            return Err("a port, route or credential event with a class");
        }
        if self.source_address.is_some() {
            return Err("a source_address on an event that is not segment");
        }
        if self.source != source {
            return Err("source is not the one this kind has");
        }
        Ok(())
    }

    /// `denied`: no trap, one of the three classes, the target that class has.
    fn check_denied(&self, target: &TripTarget) -> Result<(), &'static str> {
        if self.trap.is_some() {
            return Err("a denied event with a trap");
        }
        if self.source_address.is_some() {
            return Err("a source_address on an event that is not segment");
        }
        if self.source != TripSource::Workload {
            return Err("source is not the one this kind has");
        }
        match (self.class, target) {
            (Some(TripClass::LoopbackPort), TripTarget::Port(_))
            | (Some(TripClass::PrivateRange), TripTarget::Address(_))
            | (Some(TripClass::UnknownHost), TripTarget::Host(_)) => Ok(()),
            (
                Some(TripClass::LoopbackPort | TripClass::PrivateRange | TripClass::UnknownHost),
                _,
            ) => Err("a denied event's target is not the one its class has"),
            _ => Err("a denied event without one of the denied classes"),
        }
    }

    /// `segment`, from a pool VM: one of its two classes, a port, a peer, never a containment.
    fn check_segment(&self, target: &TripTarget) -> Result<(), &'static str> {
        if self.trap.is_some() {
            return Err("a segment event with a trap");
        }
        if self.source != TripSource::Peer {
            return Err("source is not the one this kind has");
        }
        if self.containment_ms.is_some() {
            return Err("containment_ms on a segment event");
        }
        if !matches!(target, TripTarget::Port(_)) {
            return Err("a segment event's target is not a port");
        }
        match (self.class, self.source_address.is_some()) {
            (Some(TripClass::PoolInbound), true) | (Some(TripClass::PoolOutput), false) => Ok(()),
            (Some(TripClass::PoolInbound), false) => Err("pool_inbound without a source_address"),
            (Some(TripClass::PoolOutput), true) => Err("pool_output with a source_address"),
            _ => Err("a segment event on this route is pool_inbound or pool_output"),
        }
    }
}

fn host_target(target: &TripTarget, fault: &'static str) -> Result<(), &'static str> {
    if matches!(target, TripTarget::Host(_)) {
        Ok(())
    } else {
        Err(fault)
    }
}

/// `POST /v1/me/trip` body (ADR-0069 decision 8): sent by the guest over the node SVID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TripReport {
    /// The mode the reporter acted under.
    pub mode: TripMode,
    /// 1 to [`MAX_TRIP_EVENTS`].
    pub events: Vec<TripEvent>,
}

impl TripReport {
    /// What a report must be before the broker records any of it: the first fault, named, with
    /// nothing of the offending value in it (the shape of
    /// [`GatewayDecisions::check`](crate::GatewayDecisions::check)).
    ///
    /// | kind | trap | class | target | source | `containment_ms` | `source_address` |
    /// | --- | --- | --- | --- | --- | --- | --- |
    /// | `port` | required | none | `port`, or `address` equal to [`METADATA_ADDRESS`] | `drawn` | under `enforce` | none |
    /// | `route` | required | none | `host` | `drawn` | under `enforce` | none |
    /// | `credential` | required | none | `host` | `workload` | under `enforce` | none |
    /// | `denied` | none | a `DENIED` class | `port`, `address` or `host` by class | `workload` | under `enforce` | none |
    /// | `segment` | none | `pool_inbound`, `pool_output` | `port` | `peer` | none | required inbound, none outbound |
    /// | `protocol` | refused | | | | | |
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.events.is_empty() {
            return Err("no events");
        }
        if self.events.len() > MAX_TRIP_EVENTS {
            return Err("more than 32 events");
        }
        self.events.iter().try_for_each(|e| e.check(self.mode))
    }

    /// Every event is `kind: segment`: the one report a node with no claim may send (ADR-0070
    /// decision 8). False for a report with no event.
    #[must_use]
    pub fn is_segment_only(&self) -> bool {
        !self.events.is_empty() && self.events.iter().all(|e| e.kind == TripKind::Segment)
    }
}

/// `tripped` on the claim's record (ADR-0069 decision 9): the first event that ended the claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tripped {
    /// The event's id: a second report naming it changes nothing.
    pub id: Uuid,
    /// The reporter's clock.
    pub at: Timestamp,
    /// The broker's clock when it recorded the trip.
    pub recorded_at: Timestamp,
    /// What kind of trap.
    pub kind: TripKind,
    /// The trap's name, on `port`, `route` and `credential`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trap: Option<String>,
    /// The class, on `denied` and `protocol`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<TripClass>,
    /// What was reached for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<TripTarget>,
    /// Whose value the target is.
    pub source: TripSource,
}

impl Tripped {
    /// What the record keeps of `event`, recorded at `recorded_at`.
    #[must_use]
    pub fn of(event: &TripEvent, recorded_at: Timestamp) -> Self {
        Self {
            id: event.id,
            at: event.at,
            recorded_at,
            kind: event.kind,
            trap: event.trap.clone(),
            class: event.class,
            target: event.target.clone(),
            source: event.source,
        }
    }
}

/// What an entry of the summary did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TripEffect {
    /// Under `shadow`: it would have ended the claim.
    WouldTrip,
    /// A class at `report`: recorded, nothing ended.
    Reported,
    /// It ended the claim.
    Tripped,
}

impl TripEffect {
    /// The word on the wire and in a log line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WouldTrip => "would_trip",
            Self::Reported => "reported",
            Self::Tripped => "tripped",
        }
    }
}

/// One folded entry of a claim's trip summary. Never carries an event's `id`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TripEntry {
    /// What the events folded here did.
    pub effect: TripEffect,
    /// What kind of trap.
    pub kind: TripKind,
    /// The trap's name, on `port`, `route` and `credential`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trap: Option<String>,
    /// The class, on `denied`, `protocol` and `segment`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<TripClass>,
    /// What was reached for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<TripTarget>,
    /// Whose value the target is.
    pub source: TripSource,
    /// The peer's address, on a `segment` entry of an inbound class.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_address: Option<String>,
    /// The first containment figure reported for this entry, in milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub containment_ms: Option<u32>,
    /// How many uses, saturating at [`MAX_TRIP_COUNT`].
    pub count: u64,
    /// The earliest event folded here, by the reporter's clock.
    pub first_at: Timestamp,
    /// The latest.
    pub last_at: Timestamp,
}

/// What two entries must share to be one: everything but the counts and the times.
type EntryKey<'a> = (
    TripEffect,
    TripKind,
    Option<&'a str>,
    Option<TripClass>,
    Option<&'a TripTarget>,
    Option<&'a str>,
);

impl TripEntry {
    /// The entry one accepted `event` becomes, having done `effect`.
    #[must_use]
    pub fn of(event: &TripEvent, effect: TripEffect) -> Self {
        Self {
            effect,
            kind: event.kind,
            trap: event.trap.clone(),
            class: event.class,
            target: event.target.clone(),
            source: event.source,
            source_address: event.source_address.clone(),
            containment_ms: event.containment_ms,
            count: event.count.min(MAX_TRIP_COUNT),
            first_at: event.at,
            last_at: event.at,
        }
    }

    fn key(&self) -> EntryKey<'_> {
        (
            self.effect,
            self.kind,
            self.trap.as_deref(),
            self.class,
            self.target.as_ref(),
            self.source_address.as_deref(),
        )
    }

    /// Fold `more`, an entry of the same key, into this one.
    fn absorb(&mut self, more: &Self) {
        self.count = self.count.saturating_add(more.count).min(MAX_TRIP_COUNT);
        self.first_at = self.first_at.min(more.first_at);
        self.last_at = self.last_at.max(more.last_at);
        self.containment_ms = self.containment_ms.or(more.containment_ms);
    }
}

/// A claim's trip summary: `status.tripwires` on the cluster, a map entry in the memory store.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TripSummary {
    /// The broker's clock at the last fold.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<Timestamp>,
    /// At most [`MAX_TRIP_STATUS_ENTRIES`], the latest first.
    #[serde(default)]
    pub entries: Vec<TripEntry>,
    /// The uses of the entries that did not fit.
    #[serde(default, skip_serializing_if = "crate::is_zero")]
    pub overflow: u64,
}

impl TripSummary {
    /// The one merge every store uses (ADR-0069 decision 9). Entries are one when they share
    /// effect, kind, trap, class, target and source address: counts add (saturating),
    /// `first_at` is the minimum and `last_at` the maximum. A new entry with
    /// [`MAX_TRIP_STATUS_ENTRIES`] held evicts the entry with the oldest `last_at` that did not
    /// end the claim, whose count goes to `overflow`; an entry that ended the claim is never
    /// evicted, and when every entry held is one, the new entry's count goes to `overflow`.
    /// The result is ordered by `last_at`, the latest first, then by key. An empty `delta`
    /// changes nothing.
    pub fn fold(&mut self, delta: &[TripEntry], now: Timestamp) {
        if delta.is_empty() {
            return;
        }
        for d in delta {
            if let Some(held) = self.entries.iter_mut().find(|e| e.key() == d.key()) {
                held.absorb(d);
                continue;
            }
            let mut new = d.clone();
            new.count = new.count.min(MAX_TRIP_COUNT);
            if self.entries.len() < MAX_TRIP_STATUS_ENTRIES {
                self.entries.push(new);
                continue;
            }
            let oldest = self
                .entries
                .iter()
                .enumerate()
                .filter(|(_, e)| e.effect != TripEffect::Tripped)
                .min_by_key(|(_, e)| e.last_at)
                .map(|(i, _)| i);
            let lost = match oldest {
                Some(i) => std::mem::replace(&mut self.entries[i], new).count,
                None => new.count,
            };
            self.overflow = self.overflow.saturating_add(lost).min(MAX_TRIP_COUNT);
        }
        self.entries.sort_by(|a, b| {
            b.last_at
                .cmp(&a.last_at)
                .then_with(|| a.key().cmp(&b.key()))
        });
        self.updated_at = Some(now);
    }
}

/// What `GET /v1/me` says about traps (ADR-0069 decisions 4, 5 and 10). Absent from a broker
/// under `off`, and from an older broker: the guest then arms nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrapsPolicy {
    /// `shadow` or `enforce`; `off` reads as absent.
    pub mode: TrapsMode,
    /// What each `denied` class does.
    #[serde(default)]
    pub denied: DeniedSwitches,
    /// The deployment's catalogue (ADR-0069 decision 4). No broker serves one yet: the
    /// bundle's `traps` section waits on notaio.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub catalogue: Option<TrapCatalogue>,
}

/// `policy.traps_denied` (ADR-0069 decision 10): each `denied` class `report` or `trip`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeniedSwitches {
    /// A loopback port that is neither the proxy's nor drawn.
    #[serde(default)]
    pub loopback_port: ClassAction,
    /// The link-local and private ranges.
    #[serde(default)]
    pub private_range: ClassAction,
    /// A host at the proxy that is no route.
    #[serde(default)]
    pub unknown_host: ClassAction,
}

impl DeniedSwitches {
    /// What `class` does; `report` for a class that is not a `denied` one.
    #[must_use]
    pub const fn action(&self, class: TripClass) -> ClassAction {
        match class {
            TripClass::LoopbackPort => self.loopback_port,
            TripClass::PrivateRange => self.private_range,
            TripClass::UnknownHost => self.unknown_host,
            _ => ClassAction::Report,
        }
    }
}

/// The most ports, host stems and variables a catalogue adds.
pub const MAX_CATALOGUE_ENTRIES: usize = 64;
/// The most host suffixes a catalogue adds.
pub const MAX_CATALOGUE_SUFFIXES: usize = 32;
/// The most bytes of a host suffix.
pub const MAX_CATALOGUE_SUFFIX_BYTES: usize = 128;
/// The most bytes of a variable's name.
pub const MAX_TRAP_VARIABLE_BYTES: usize = 64;

/// A deployment's additions to the draw (ADR-0069 decision 4). It adds and never narrows, and
/// carries no literal value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrapCatalogue {
    /// Seed ports, at most [`MAX_CATALOGUE_ENTRIES`], never zero.
    #[serde(default)]
    pub ports: Vec<u16>,
    /// Host stems, each an RFC 1123 label, at most [`MAX_CATALOGUE_ENTRIES`].
    #[serde(default)]
    pub host_stems: Vec<String>,
    /// Host suffixes, each a dot and one or more labels (`.prod.internal`), at most
    /// [`MAX_CATALOGUE_SUFFIXES`] of at most [`MAX_CATALOGUE_SUFFIX_BYTES`].
    #[serde(default)]
    pub host_suffixes: Vec<String>,
    /// Variable names, each with a generator, at most [`MAX_CATALOGUE_ENTRIES`].
    #[serde(default)]
    pub variables: Vec<TrapVariable>,
    /// How many of each kind, within the built-in bounds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<TrapCounts>,
}

/// One variable a catalogue adds: its name and the generator of its value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrapVariable {
    /// An upper-case letter, then at most 63 of `A-Z`, `0-9` and `_`.
    pub name: String,
    /// What draws the value.
    pub generator: TrapGenerator,
}

/// The fixed set of generators: a catalogue names one and never a literal value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrapGenerator {
    /// An AWS access key id.
    AwsAccessKeyId,
    /// An AWS secret access key.
    AwsSecretAccessKey,
    /// A GitHub classic personal access token.
    GithubPat,
    /// A GitHub fine-grained personal access token.
    GithubFineGrainedPat,
    /// A GitLab personal access token.
    GitlabPat,
    /// An npm access token.
    NpmToken,
    /// A Python package index API token.
    PypiToken,
    /// A container registry `auth` value.
    DockerAuth,
    /// A Kubernetes bearer token.
    KubeBearer,
    /// A Hugging Face token.
    HfToken,
    /// A model provider's API key, in the `sk-` shape.
    OpenaiKey,
    /// A Stripe secret key.
    StripeSecretKey,
    /// A Slack bot token.
    SlackBotToken,
    /// A Google API key.
    GoogleApiKey,
    /// An Azure storage connection string.
    AzureStorageConnection,
    /// A PostgreSQL URL with a password.
    PostgresUrl,
    /// A hex secret of the length a JWT signing key has.
    JwtSecretHex,
    /// A `.netrc` password.
    NetrcPassword,
}

/// A count's bounds, both inclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CountRange {
    /// The fewest.
    pub min: u8,
    /// The most.
    pub max: u8,
}

impl CountRange {
    /// Whether this range is one, and lies inside `bounds`.
    #[must_use]
    pub const fn within(self, bounds: Self) -> bool {
        self.min <= self.max && self.min >= bounds.min && self.max <= bounds.max
    }
}

/// How many traps of each kind a draw has, where a catalogue says so.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrapCounts {
    /// Within [`PORT_COUNT`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ports: Option<CountRange>,
    /// Within [`ROUTE_COUNT`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routes: Option<CountRange>,
    /// Within [`CREDENTIAL_COUNT`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<CountRange>,
}

/// How many `port` traps a draw has (ADR-0069 decision 3).
pub const PORT_COUNT: CountRange = CountRange { min: 2, max: 5 };
/// How many `route` traps a draw has.
pub const ROUTE_COUNT: CountRange = CountRange { min: 1, max: 3 };
/// How many `credential` traps a draw has.
pub const CREDENTIAL_COUNT: CountRange = CountRange { min: 3, max: 6 };

impl TrapCatalogue {
    /// The bounds above; the first fault, naming the field and never the value.
    pub fn validate(&self) -> Result<(), String> {
        if self.ports.len() > MAX_CATALOGUE_ENTRIES {
            return Err("traps.ports: more than 64".into());
        }
        if self.ports.contains(&0) {
            return Err("traps.ports: a port is zero".into());
        }
        if self.host_stems.len() > MAX_CATALOGUE_ENTRIES {
            return Err("traps.host_stems: more than 64".into());
        }
        if !self.host_stems.iter().all(|s| crate::is_dns_label(s)) {
            return Err("traps.host_stems: a stem is not an RFC 1123 label".into());
        }
        if self.host_suffixes.len() > MAX_CATALOGUE_SUFFIXES {
            return Err("traps.host_suffixes: more than 32".into());
        }
        if !self.host_suffixes.iter().all(|s| suffix_ok(s)) {
            return Err(
                "traps.host_suffixes: a suffix is not a dot and labels of at most 128 bytes".into(),
            );
        }
        if self.variables.len() > MAX_CATALOGUE_ENTRIES {
            return Err("traps.variables: more than 64".into());
        }
        if !self.variables.iter().all(|v| variable_ok(&v.name)) {
            return Err(
                "traps.variables: a name is not an upper-case letter and at most 63 of A-Z, 0-9 and '_'"
                    .into(),
            );
        }
        if let Some(c) = &self.counts {
            for (range, bounds, field) in [
                (c.ports, PORT_COUNT, "ports"),
                (c.routes, ROUTE_COUNT, "routes"),
                (c.credentials, CREDENTIAL_COUNT, "credentials"),
            ] {
                if !range.is_none_or(|r| r.within(bounds)) {
                    return Err(format!(
                        "traps.counts.{field}: not a range within {} to {}",
                        bounds.min, bounds.max
                    ));
                }
            }
        }
        Ok(())
    }
}

/// `.label(.label)*`, at most [`MAX_CATALOGUE_SUFFIX_BYTES`].
fn suffix_ok(s: &str) -> bool {
    s.len() <= MAX_CATALOGUE_SUFFIX_BYTES
        && s.strip_prefix('.')
            .is_some_and(|rest| rest.split('.').all(crate::is_dns_label))
}

/// `[A-Z][A-Z0-9_]{0,63}`.
fn variable_ok(s: &str) -> bool {
    s.len() <= MAX_TRAP_VARIABLE_BYTES
        && s.bytes().next().is_some_and(|b| b.is_ascii_uppercase())
        && s.bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

/// Whether the proxy matches bait in a route's request body (ADR-0069 decision 6). `skip` on
/// an audience that carries the agent's own conversation: the proxy then matches the headers,
/// the path and the query only.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrapsBody {
    /// The body is matched.
    #[default]
    Match,
    /// The body is not.
    Skip,
}

impl TrapsBody {
    /// For serde: `match` stays off the wire.
    #[allow(clippy::trivially_copy_pass_by_ref)] // serde's `skip_serializing_if` passes a reference
    #[must_use]
    pub fn is_match(&self) -> bool {
        *self == Self::Match
    }
}

/// One host-table drop count read on a gateway (ADR-0070 decisions 4 and 8), in the `probes`
/// of [`GatewayDecisions`](crate::GatewayDecisions).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayProbe {
    /// The gateway's clock when it read the counter.
    pub at: Timestamp,
    /// `gateway_port` or `gateway_output`, no other.
    pub class: TripClass,
    /// How many drops since the last read, 1 to [`MAX_TRIP_COUNT`].
    pub count: u64,
    /// The destination port, where the table kept one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    /// The source address, without a port: `gateway_port` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_address: Option<String>,
    /// The gateway's local user whose chain dropped: `gateway_output` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
}

impl GatewayProbe {
    /// What a probe must be before the broker logs it; the first fault, named.
    pub(crate) fn check(&self) -> Result<(), &'static str> {
        if !(1..=MAX_TRIP_COUNT).contains(&self.count) {
            return Err("probe count is not 1 to 2^53 - 1");
        }
        if self.port == Some(0) {
            return Err("probe port is zero");
        }
        if !self.source_address.as_deref().is_none_or(ip_ok) {
            return Err("probe source_address is not an ip address");
        }
        if !self.user.as_deref().is_none_or(|u| crate::word_ok(u, 32)) {
            return Err("probe user is not a name");
        }
        match self.class {
            TripClass::GatewayPort if self.user.is_some() => Err("gateway_port with a user"),
            TripClass::GatewayOutput if self.source_address.is_some() => {
                Err("gateway_output with a source_address")
            }
            TripClass::GatewayPort | TripClass::GatewayOutput => Ok(()),
            _ => Err("probe class is not gateway_port or gateway_output"),
        }
    }
}

/// The directory of the guest's trap socket: root's, mode `0711`, outside what the jail
/// mounts (ADR-0069 decision 7).
pub const TRAP_SOCKET_DIR: &str = "/run/mediatore-guest/trap";
/// The socket's name in [`TRAP_SOCKET_DIR`]: a path, never an abstract name, since the jail
/// shares the VM's network namespace and abstract names are per network namespace.
pub const TRAP_SOCKET_NAME: &str = "trap.sock";
/// The most bytes of one newline-delimited JSON message on the trap socket.
pub const TRAP_FRAME_MAX: usize = 64 * 1024;

/// What the guest sends the proxy on the trap socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum GuestToProxy {
    /// The drawn result, once, first.
    Arm(ProxyTraps),
    /// Under `enforce` the guest decided a trip: the proxy forwards nothing more from the
    /// moment it reads this, ahead of the cut (ADR-0069 decision 7 step 1). It stays up; the
    /// kill ends it. An older proxy ignores it, as it ignores anything after `arm`.
    Tripped,
}

/// The drawn result the proxy is handed: never the catalogue, never the ports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyTraps {
    /// `shadow` or `enforce`.
    pub mode: TripMode,
    /// What a host that is no route does.
    pub unknown_host: ClassAction,
    /// The decoy routes.
    pub routes: Vec<ProxyDecoyRoute>,
    /// The bait credentials.
    pub bait: Vec<ProxyBait>,
}

/// One decoy route: a host the proxy treats as a trap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyDecoyRoute {
    /// The decoy's name, what a report's `trap` says.
    pub name: String,
    /// The host a request names, in [`TripTarget::Host`]'s grammar.
    pub host: String,
}

/// One bait credential: its catalogue name and every value planted for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyBait {
    /// The catalogue entry's name, what a report's `trap` says.
    pub name: String,
    /// The values, which never print.
    pub values: Vec<Secret>,
}

/// What the proxy sends the guest on the trap socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProxyToGuest {
    /// Once, after `arm`: the matcher is built. The guest reads the proxy's ready line only
    /// after this.
    Armed {
        /// How many patterns the matcher holds.
        patterns: u32,
    },
    /// A trap was used.
    Trip(ProxyTrip),
}

/// One verdict of the proxy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyTrip {
    /// The proxy's clock at its verdict: the guest measures containment from it.
    pub at: Timestamp,
    /// `route`, `credential` or `denied`.
    pub kind: TripKind,
    /// The decoy's or the catalogue entry's name, on `route` and `credential`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trap: Option<String>,
    /// `unknown_host`, on `denied`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class: Option<TripClass>,
    /// The host the request named, in [`TripTarget::Host`]'s grammar.
    pub host: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GatewayDecisions, Me, Route};

    fn ts(s: &str) -> Timestamp {
        s.parse().unwrap()
    }

    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    /// A valid event of each kind a guest may report.
    fn event(kind: TripKind) -> TripEvent {
        let base = TripEvent {
            id: id(1),
            at: ts("2026-11-26T15:02:11.204Z"),
            kind,
            trap: None,
            class: None,
            target: None,
            source: TripSource::Workload,
            containment_ms: None,
            count: 1,
            source_address: None,
        };
        match kind {
            TripKind::Port => TripEvent {
                trap: Some("redis".into()),
                target: Some(TripTarget::Port(6379)),
                source: TripSource::Drawn,
                ..base
            },
            TripKind::Route => TripEvent {
                trap: Some("vault".into()),
                target: Some(TripTarget::Host("secrets.prod.internal".into())),
                source: TripSource::Drawn,
                ..base
            },
            TripKind::Credential => TripEvent {
                trap: Some("aws".into()),
                target: Some(TripTarget::Host("git.example".into())),
                ..base
            },
            TripKind::Denied => TripEvent {
                class: Some(TripClass::UnknownHost),
                target: Some(TripTarget::Host("typo.example".into())),
                ..base
            },
            TripKind::Segment => TripEvent {
                class: Some(TripClass::PoolInbound),
                target: Some(TripTarget::Port(22)),
                source: TripSource::Peer,
                source_address: Some("192.0.2.9".into()),
                ..base
            },
            TripKind::Protocol => TripEvent {
                class: Some(TripClass::ForeignRoute),
                target: Some(TripTarget::Host("git.example".into())),
                source: TripSource::Peer,
                ..base
            },
        }
    }

    fn report(mode: TripMode, e: TripEvent) -> Result<(), &'static str> {
        TripReport {
            mode,
            events: vec![e],
        }
        .validate()
    }

    /// `kind`'s valid event with one change, under `enforce`.
    fn with(kind: TripKind, f: impl FnOnce(&mut TripEvent)) -> Result<(), &'static str> {
        let mut e = event(kind);
        f(&mut e);
        report(TripMode::Enforce, e)
    }

    #[test]
    fn a_trip_report_is_on_the_wire_as_adr_0069_writes_it() {
        let wire = serde_json::json!({
            "mode": "enforce",
            "events": [{
                "id": "6f1c0e2a-5b7d-4c3e-9a41-0d2f8b6c7e15",
                "at": "2026-11-26T15:02:11.204Z",
                "kind": "credential",
                "trap": "aws",
                "target": { "host": "git.example" },
                "source": "workload",
                "containment_ms": 41,
                "count": 1
            }]
        });
        let parsed: TripReport = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(
            parsed,
            TripReport {
                mode: TripMode::Enforce,
                events: vec![TripEvent {
                    id: "6f1c0e2a-5b7d-4c3e-9a41-0d2f8b6c7e15".parse().unwrap(),
                    containment_ms: Some(41),
                    ..event(TripKind::Credential)
                }],
            }
        );
        assert_eq!(parsed.validate(), Ok(()));
        assert_eq!(serde_json::to_value(&parsed).unwrap(), wire);
        // The other two targets, and a count left off the wire reads as one.
        let e: TripEvent = serde_json::from_value(serde_json::json!({
            "id": "6f1c0e2a-5b7d-4c3e-9a41-0d2f8b6c7e15", "at": "2026-11-26T15:02:11.204Z",
            "kind": "port", "trap": "redis", "target": { "port": 6379 }, "source": "drawn"
        }))
        .unwrap();
        assert_eq!((e.count, e.target), (1, Some(TripTarget::Port(6379))));
        assert_eq!(
            serde_json::to_value(TripTarget::Address("192.0.2.7:22".into())).unwrap(),
            serde_json::json!({ "address": "192.0.2.7:22" })
        );
    }

    #[test]
    fn every_kind_takes_exactly_its_own_fields() {
        use TripKind::{Credential, Denied, Port, Route, Segment};
        for kind in [Port, Route, Credential, Denied, Segment] {
            assert_eq!(with(kind, |_| {}), Ok(()), "{kind:?} as built");
            assert!(
                with(kind, |e| e.target = None).is_err(),
                "{kind:?} no target"
            );
        }
        // trap: required on the three decoy kinds, refused on the other two.
        for kind in [Port, Route, Credential] {
            assert!(with(kind, |e| e.trap = None).is_err(), "{kind:?} no trap");
            assert!(with(kind, |e| e.class = Some(TripClass::UnknownHost)).is_err());
            assert!(with(kind, |e| e.source_address = Some("192.0.2.9".into())).is_err());
            assert_eq!(with(kind, |e| e.containment_ms = Some(41)), Ok(()));
        }
        for kind in [Denied, Segment] {
            assert!(
                with(kind, |e| e.trap = Some("aws".into())).is_err(),
                "{kind:?} trap"
            );
            assert!(with(kind, |e| e.class = None).is_err(), "{kind:?} no class");
        }
        // target.
        assert_eq!(
            with(Port, |e| e.target =
                Some(TripTarget::Address(METADATA_ADDRESS.into()))),
            Ok(())
        );
        assert!(
            with(Port, |e| e.target =
                Some(TripTarget::Address("192.0.2.7:80".into())))
            .is_err()
        );
        assert!(
            with(Port, |e| e.target =
                Some(TripTarget::Host("git.example".into())))
            .is_err()
        );
        assert!(with(Port, |e| e.target = Some(TripTarget::Port(0))).is_err());
        assert!(with(Route, |e| e.target = Some(TripTarget::Port(443))).is_err());
        assert!(with(Credential, |e| e.target = Some(TripTarget::Port(443))).is_err());
        assert!(
            with(Segment, |e| e.target =
                Some(TripTarget::Host("a.example".into())))
            .is_err()
        );
        // source.
        assert!(with(Port, |e| e.source = TripSource::Workload).is_err());
        assert!(with(Route, |e| e.source = TripSource::Workload).is_err());
        assert!(with(Credential, |e| e.source = TripSource::Drawn).is_err());
        assert!(with(Denied, |e| e.source = TripSource::Drawn).is_err());
        assert!(with(Segment, |e| e.source = TripSource::Workload).is_err());
        // denied: each class has its own target, and only the three classes are denied ones.
        let denied = |class, target| {
            with(Denied, |e| {
                e.class = Some(class);
                e.target = Some(target);
            })
        };
        assert_eq!(
            denied(TripClass::LoopbackPort, TripTarget::Port(8080)),
            Ok(())
        );
        assert_eq!(
            denied(
                TripClass::PrivateRange,
                TripTarget::Address("198.51.100.7:22".into())
            ),
            Ok(())
        );
        assert!(
            denied(
                TripClass::LoopbackPort,
                TripTarget::Host("a.example".into())
            )
            .is_err()
        );
        assert!(denied(TripClass::PrivateRange, TripTarget::Port(22)).is_err());
        assert!(denied(TripClass::UnknownHost, TripTarget::Port(22)).is_err());
        assert!(denied(TripClass::PoolInbound, TripTarget::Port(22)).is_err());
        assert!(with(Denied, |e| e.source_address = Some("192.0.2.9".into())).is_err());
        assert_eq!(with(Denied, |e| e.containment_ms = Some(41)), Ok(()));
        // segment: a source address on the inbound class and on no other; never a containment.
        assert!(with(Segment, |e| e.source_address = None).is_err());
        assert!(with(Segment, |e| e.source_address = Some("192.0.2.9:22".into())).is_err());
        assert!(with(Segment, |e| e.containment_ms = Some(41)).is_err());
        assert_eq!(
            with(Segment, |e| {
                e.class = Some(TripClass::PoolOutput);
                e.source_address = None;
            }),
            Ok(())
        );
        assert!(with(Segment, |e| e.class = Some(TripClass::PoolOutput)).is_err());
    }

    #[test]
    fn a_trap_name_a_count_and_a_batch_have_their_bounds() {
        use TripKind::Port;
        assert!(with(Port, |e| e.trap = Some("Redis".into())).is_err());
        assert!(with(Port, |e| e.trap = Some("r".repeat(64))).is_err());
        assert!(with(Port, |e| e.trap = Some(String::new())).is_err());
        assert!(with(Port, |e| e.count = 0).is_err());
        assert!(with(Port, |e| e.count = MAX_TRIP_COUNT + 1).is_err());
        assert_eq!(with(Port, |e| e.count = MAX_TRIP_COUNT), Ok(()));
        let many = |n| TripReport {
            mode: TripMode::Shadow,
            events: vec![event(Port); n],
        };
        assert!(many(0).validate().is_err());
        assert_eq!(many(MAX_TRIP_EVENTS).validate(), Ok(()));
        assert!(many(MAX_TRIP_EVENTS + 1).validate().is_err());
    }

    #[test]
    fn a_protocol_event_and_a_gateway_class_are_refused_on_the_trip_route() {
        assert!(with(TripKind::Protocol, |_| {}).is_err());
        for class in TripClass::PROTOCOL {
            assert!(with(TripKind::Protocol, |e| e.class = Some(class)).is_err());
            assert!(with(TripKind::Denied, |e| e.class = Some(class)).is_err());
        }
        for class in [TripClass::GatewayPort, TripClass::GatewayOutput] {
            assert!(with(TripKind::Segment, |e| e.class = Some(class)).is_err());
            assert!(
                with(TripKind::Segment, |e| {
                    e.class = Some(class);
                    e.source_address = None;
                })
                .is_err()
            );
        }
        // Only a report of segment events alone is the one a node with no claim may send.
        let both = TripReport {
            mode: TripMode::Shadow,
            events: vec![event(TripKind::Segment), event(TripKind::Port)],
        };
        assert!(!both.is_segment_only());
        let segment = TripReport {
            mode: TripMode::Shadow,
            events: vec![event(TripKind::Segment)],
        };
        assert!(segment.is_segment_only());
        let none = TripReport {
            mode: TripMode::Shadow,
            events: vec![],
        };
        assert!(!none.is_segment_only());
    }

    #[test]
    fn a_target_is_exactly_one_of_host_port_and_address_and_never_a_path() {
        let host = |h: &str| {
            with(TripKind::Route, |e| {
                e.target = Some(TripTarget::Host(h.into()));
            })
        };
        assert_eq!(host("git.example"), Ok(()));
        assert_eq!(host("192.0.2.7"), Ok(()));
        assert_eq!(host("2001:db8::7"), Ok(()));
        assert_eq!(host(&"a".repeat(253)), Ok(()));
        assert!(host("git.example/x").is_err());
        assert!(host("Git.example").is_err());
        assert!(host(&"a".repeat(254)).is_err());
        assert!(host("").is_err());
        assert!(host("git.example:443").is_err());
        assert!(host("[2001:db8::7]").is_err());
        assert!(host("2001:DB8::7").is_err());
        assert!(host("git.example?token=x").is_err());
        assert!(host("git.example\nforged").is_err());
        let address = |a: &str| {
            with(TripKind::Denied, |e| {
                e.class = Some(TripClass::PrivateRange);
                e.target = Some(TripTarget::Address(a.into()));
            })
        };
        assert_eq!(address("198.51.100.7:22"), Ok(()));
        assert_eq!(address("[2001:db8::7]:22"), Ok(()));
        assert!(address("198.51.100.7").is_err());
        assert!(address("git.example:22").is_err());
        assert!(address("198.51.100.7:22/x").is_err());
        assert!(address("[2001:DB8::7]:22").is_err());
        // Two members, or one this type does not have, is no target.
        for wire in [
            serde_json::json!({ "host": "git.example", "port": 22 }),
            serde_json::json!({ "path": "/x" }),
            serde_json::json!({}),
            serde_json::json!("git.example"),
        ] {
            assert!(serde_json::from_value::<TripTarget>(wire).is_err());
        }
    }

    #[test]
    fn containment_is_refused_under_shadow_and_over_the_bound() {
        let contained = |mode, ms| {
            let mut e = event(TripKind::Credential);
            e.containment_ms = Some(ms);
            report(mode, e)
        };
        assert_eq!(contained(TripMode::Enforce, 41), Ok(()));
        assert_eq!(contained(TripMode::Enforce, MAX_CONTAINMENT_MS), Ok(()));
        assert!(contained(TripMode::Enforce, MAX_CONTAINMENT_MS + 1).is_err());
        assert!(contained(TripMode::Shadow, 41).is_err());
        assert_eq!(
            report(TripMode::Shadow, event(TripKind::Credential)),
            Ok(())
        );
    }

    #[test]
    fn an_unknown_field_anywhere_in_the_body_is_refused() {
        let good = serde_json::to_value(TripReport {
            mode: TripMode::Shadow,
            events: vec![event(TripKind::Port)],
        })
        .unwrap();
        assert!(serde_json::from_value::<TripReport>(good.clone()).is_ok());
        let mut top = good.clone();
        top["path"] = "/x".into();
        assert!(serde_json::from_value::<TripReport>(top).is_err());
        let mut inner = good.clone();
        inner["events"][0]["header"] = "authorization".into();
        assert!(serde_json::from_value::<TripReport>(inner).is_err());
        let mut mode = good.clone();
        mode["mode"] = "off".into();
        assert!(serde_json::from_value::<TripReport>(mode).is_err());
        let mut kind = good;
        kind["events"][0]["kind"] = "file".into();
        assert!(serde_json::from_value::<TripReport>(kind).is_err());
    }

    fn entry(effect: TripEffect, port: u16, at: &str, count: u64) -> TripEntry {
        let mut e = event(TripKind::Port);
        e.target = Some(TripTarget::Port(port));
        e.at = ts(at);
        e.count = count;
        TripEntry::of(&e, effect)
    }

    #[test]
    fn the_fold_adds_counts_keeps_the_first_and_last_time_and_orders_by_last() {
        let now = ts("2026-11-26T16:00:00Z");
        let mut s = TripSummary::default();
        s.fold(&[], now);
        assert_eq!(s, TripSummary::default(), "an empty delta changes nothing");
        s.fold(
            &[
                entry(TripEffect::WouldTrip, 6379, "2026-11-26T15:00:02Z", 2),
                entry(TripEffect::WouldTrip, 22, "2026-11-26T15:00:05Z", 1),
            ],
            now,
        );
        s.fold(
            &[
                entry(TripEffect::WouldTrip, 6379, "2026-11-26T15:00:09Z", 3),
                entry(TripEffect::WouldTrip, 6379, "2026-11-26T15:00:01Z", 1),
            ],
            now,
        );
        assert_eq!(s.updated_at, Some(now));
        assert_eq!(s.overflow, 0);
        assert_eq!(s.entries.len(), 2);
        let first = &s.entries[0];
        assert_eq!(first.target, Some(TripTarget::Port(6379)));
        assert_eq!(first.count, 6);
        assert_eq!(first.first_at, ts("2026-11-26T15:00:01Z"));
        assert_eq!(first.last_at, ts("2026-11-26T15:00:09Z"));
        assert_eq!(s.entries[1].target, Some(TripTarget::Port(22)));
        // The effect is part of the key, and a count saturates.
        s.fold(
            &[
                entry(TripEffect::Tripped, 6379, "2026-11-26T15:00:09Z", 1),
                entry(
                    TripEffect::WouldTrip,
                    22,
                    "2026-11-26T15:00:05Z",
                    MAX_TRIP_COUNT,
                ),
            ],
            now,
        );
        assert_eq!(s.entries.len(), 3);
        // Two entries at one time: the key orders them, `would_trip` before `tripped`.
        assert_eq!(
            s.entries.iter().map(|e| e.effect).collect::<Vec<_>>(),
            [
                TripEffect::WouldTrip,
                TripEffect::Tripped,
                TripEffect::WouldTrip
            ]
        );
        assert_eq!(s.entries[2].count, MAX_TRIP_COUNT);
        // An entry never carries an event's id.
        assert!(
            !serde_json::to_value(&s)
                .unwrap()
                .to_string()
                .contains("\"id\"")
        );
    }

    #[test]
    fn the_seventeenth_key_evicts_the_oldest_entry_that_did_not_trip_and_never_one_that_did() {
        let now = ts("2026-11-26T16:00:00Z");
        let mut s = TripSummary::default();
        // The oldest entry of all is one that ended the claim; the next oldest did not.
        s.fold(
            &[entry(TripEffect::Tripped, 1000, "2026-11-26T15:00:00Z", 1)],
            now,
        );
        s.fold(
            &[entry(
                TripEffect::WouldTrip,
                1001,
                "2026-11-26T15:00:01Z",
                7,
            )],
            now,
        );
        for i in 2..16_u16 {
            let at = format!("2026-11-26T15:00:{i:02}Z");
            s.fold(&[entry(TripEffect::Reported, 1000 + i, &at, 1)], now);
        }
        assert_eq!((s.entries.len(), s.overflow), (MAX_TRIP_STATUS_ENTRIES, 0));
        s.fold(
            &[entry(
                TripEffect::WouldTrip,
                2000,
                "2026-11-26T15:01:00Z",
                1,
            )],
            now,
        );
        assert_eq!((s.entries.len(), s.overflow), (MAX_TRIP_STATUS_ENTRIES, 7));
        let ports: Vec<_> = s.entries.iter().filter_map(|e| e.target.clone()).collect();
        assert!(
            ports.contains(&TripTarget::Port(1000)),
            "the tripped entry stays"
        );
        assert!(
            !ports.contains(&TripTarget::Port(1001)),
            "the oldest other goes"
        );
        assert_eq!(s.entries[0].target, Some(TripTarget::Port(2000)));
        // A key already held folds in and evicts nothing.
        s.fold(
            &[entry(
                TripEffect::WouldTrip,
                2000,
                "2026-11-26T15:02:00Z",
                1,
            )],
            now,
        );
        assert_eq!((s.entries.len(), s.overflow), (MAX_TRIP_STATUS_ENTRIES, 7));
    }

    #[test]
    fn sixteen_tripped_entries_send_the_next_to_overflow() {
        let now = ts("2026-11-26T16:00:00Z");
        let mut s = TripSummary::default();
        for i in 0..16_u16 {
            let at = format!("2026-11-26T15:00:{i:02}Z");
            s.fold(&[entry(TripEffect::Tripped, 1000 + i, &at, 1)], now);
        }
        let held = s.entries.clone();
        s.fold(
            &[entry(
                TripEffect::WouldTrip,
                2000,
                "2026-11-26T15:01:00Z",
                5,
            )],
            now,
        );
        s.fold(
            &[entry(TripEffect::Tripped, 2001, "2026-11-26T15:01:01Z", 2)],
            now,
        );
        assert_eq!(s.entries, held);
        assert_eq!(s.overflow, 7);
    }

    #[test]
    fn a_catalogue_outside_its_bounds_or_with_a_count_outside_the_built_in_range_is_refused() {
        let good = TrapCatalogue {
            ports: vec![9200, 27017],
            host_stems: vec!["billing".into()],
            host_suffixes: vec![".prod.internal".into()],
            variables: vec![TrapVariable {
                name: "BILLING_STRIPE_TOKEN".into(),
                generator: TrapGenerator::StripeSecretKey,
            }],
            counts: Some(TrapCounts {
                ports: Some(CountRange { min: 3, max: 5 }),
                routes: None,
                credentials: Some(CREDENTIAL_COUNT),
            }),
        };
        assert_eq!(good.validate(), Ok(()));
        assert_eq!(TrapCatalogue::default().validate(), Ok(()));
        let bad = |f: &dyn Fn(&mut TrapCatalogue)| {
            let mut c = good.clone();
            f(&mut c);
            c.validate().is_err()
        };
        assert!(bad(&|c| c.ports = vec![9200; 65]));
        assert!(bad(&|c| c.ports.push(0)));
        assert!(bad(&|c| c.host_stems = vec!["billing".into(); 65]));
        assert!(bad(&|c| c.host_stems.push("Billing".into())));
        assert!(bad(&|c| c.host_stems.push("a.b".into())));
        assert!(bad(&|c| c.host_suffixes = vec![".internal".into(); 33]));
        assert!(bad(&|c| c.host_suffixes.push("prod.internal".into())));
        assert!(bad(&|c| c.host_suffixes.push(".".into())));
        assert!(bad(&|c| c.host_suffixes.push(".prod..internal".into())));
        assert!(bad(&|c| c
            .host_suffixes
            .push(format!(".{0}.{0}.x", "a".repeat(63)))));
        assert!(!bad(&|c| c
            .host_suffixes
            .push(format!(".{0}.{0}", "a".repeat(63)))));
        assert!(bad(&|c| c.variables[0].name = "billing".into()));
        assert!(bad(&|c| c.variables[0].name = "1TOKEN".into()));
        assert!(bad(&|c| c.variables[0].name = String::new()));
        assert!(bad(&|c| c.variables[0].name = "A".repeat(65)));
        assert!(bad(&|c| c.variables = vec![c.variables[0].clone(); 65]));
        let count = |f: &dyn Fn(&mut TrapCounts)| {
            let mut c = good.clone();
            f(c.counts.as_mut().unwrap());
            c.validate().is_err()
        };
        assert!(count(&|c| c.ports = Some(CountRange { min: 1, max: 5 })));
        assert!(count(&|c| c.ports = Some(CountRange { min: 2, max: 6 })));
        assert!(count(&|c| c.ports = Some(CountRange { min: 4, max: 3 })));
        assert!(count(&|c| c.routes = Some(CountRange { min: 0, max: 3 })));
        assert!(count(
            &|c| c.credentials = Some(CountRange { min: 3, max: 7 })
        ));
        assert!(!count(&|c| c.routes = Some(ROUTE_COUNT)));
        // A literal value has nowhere to go: a variable names a generator of the fixed set.
        assert!(
            serde_json::from_value::<TrapVariable>(serde_json::json!({
                "name": "AWS_SECRET_ACCESS_KEY", "generator": "aws_secret_access_key", "value": "x"
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<TrapVariable>(serde_json::json!({
                "name": "AWS_SECRET_ACCESS_KEY", "generator": "literal"
            }))
            .is_err()
        );
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "one row per class: the table is the test"
    )]
    fn every_class_names_its_kind_its_scope_and_whether_it_may_trip() {
        use ClassScope::{Authorizer, Claim, ClaimNodeOrAuthorizer};
        use TripClass as C;
        let table = [
            (
                C::LoopbackPort,
                "loopback_port",
                TripKind::Denied,
                Claim,
                true,
            ),
            (
                C::PrivateRange,
                "private_range",
                TripKind::Denied,
                Claim,
                true,
            ),
            (
                C::UnknownHost,
                "unknown_host",
                TripKind::Denied,
                Claim,
                true,
            ),
            (
                C::IdentityShape,
                "identity_shape",
                TripKind::Protocol,
                ClassScope::None,
                false,
            ),
            (
                C::ForeignRoute,
                "foreign_route",
                TripKind::Protocol,
                ClaimNodeOrAuthorizer,
                true,
            ),
            (
                C::UnknownRoute,
                "unknown_route",
                TripKind::Protocol,
                ClaimNodeOrAuthorizer,
                true,
            ),
            (
                C::NoRecord,
                "no_record",
                TripKind::Protocol,
                ClassScope::None,
                false,
            ),
            (
                C::AudienceOutsideRendered,
                "audience_outside_rendered",
                TripKind::Protocol,
                Claim,
                true,
            ),
            (
                C::ClaimNeverIssued,
                "claim_never_issued",
                TripKind::Protocol,
                Authorizer,
                false,
            ),
            (
                C::CredentialOutsideInject,
                "credential_outside_inject",
                TripKind::Protocol,
                Authorizer,
                false,
            ),
            // Scoped to the claim a gateway's batch names, so it is put on that claim's
            // summary, and never `trip`: the uid is the word of whoever holds the authorizer's
            // shared identity (ADR-0070 decision 6, amended 2026-11-27).
            (
                C::DenyOutsideRendered,
                "deny_outside_rendered",
                TripKind::Protocol,
                Claim,
                false,
            ),
            (
                C::GatewayPort,
                "gateway_port",
                TripKind::Segment,
                ClassScope::None,
                false,
            ),
            (
                C::GatewayOutput,
                "gateway_output",
                TripKind::Segment,
                ClassScope::None,
                false,
            ),
            (
                C::PoolInbound,
                "pool_inbound",
                TripKind::Segment,
                ClassScope::None,
                false,
            ),
            (
                C::PoolOutput,
                "pool_output",
                TripKind::Segment,
                ClassScope::None,
                false,
            ),
        ];
        for (class, name, kind, scope, may_trip) in table {
            assert_eq!(class.as_str(), name);
            assert_eq!(
                serde_json::to_value(class).unwrap(),
                serde_json::json!(name)
            );
            assert_eq!(class.kind(), kind, "{name}");
            assert_eq!(class.scope(), scope, "{name}");
            assert_eq!(class.may_trip(), may_trip, "{name}");
        }
        // The three lists are the table, each class once.
        let listed: Vec<C> = C::DENIED
            .into_iter()
            .chain(C::PROTOCOL)
            .chain(C::SEGMENT)
            .collect();
        assert_eq!(listed, table.map(|row| row.0));
        assert!(C::DENIED.iter().all(|c| c.kind() == TripKind::Denied));
        assert!(C::PROTOCOL.iter().all(|c| c.kind() == TripKind::Protocol));
        assert!(C::SEGMENT.iter().all(|c| c.kind() == TripKind::Segment));
    }

    fn probe(class: TripClass) -> GatewayProbe {
        GatewayProbe {
            at: ts("2026-11-22T14:41:58Z"),
            class,
            count: 3,
            port: Some(2375),
            source_address: None,
            user: None,
        }
    }

    #[test]
    fn a_batch_with_probes_is_checked_and_one_without_reads_as_before() {
        // A batch from a gateway that knows nothing of probes.
        let old: GatewayDecisions =
            serde_json::from_value(serde_json::json!({ "gateway": "gateway-02", "decisions": [] }))
                .unwrap();
        assert_eq!(old.probes, vec![]);
        assert_eq!(old.check(), Ok(()));
        assert_eq!(
            serde_json::to_value(&old).unwrap(),
            serde_json::json!({ "gateway": "gateway-02", "decisions": [] }),
            "no probes, nothing new on the wire"
        );
        let with = |f: &dyn Fn(&mut GatewayDecisions)| {
            let mut b = GatewayDecisions {
                gateway: "gateway-02".into(),
                decisions: vec![],
                probes: vec![
                    GatewayProbe {
                        source_address: Some("192.0.2.9".into()),
                        ..probe(TripClass::GatewayPort)
                    },
                    GatewayProbe {
                        user: Some("envoy".into()),
                        ..probe(TripClass::GatewayOutput)
                    },
                ],
            };
            f(&mut b);
            b.check()
        };
        assert_eq!(with(&|_| {}), Ok(()));
        assert_eq!(
            with(&|b| b.probes = vec![probe(TripClass::GatewayPort); MAX_GATEWAY_PROBES]),
            Ok(())
        );
        assert!(
            with(&|b| b.probes = vec![probe(TripClass::GatewayPort); MAX_GATEWAY_PROBES + 1])
                .is_err()
        );
        for class in TripClass::DENIED
            .into_iter()
            .chain(TripClass::PROTOCOL)
            .chain([TripClass::PoolInbound, TripClass::PoolOutput])
        {
            assert!(with(&|b| b.probes[0].class = class).is_err(), "{class:?}");
        }
        assert!(with(&|b| b.probes[0].count = 0).is_err());
        assert!(with(&|b| b.probes[0].port = Some(0)).is_err());
        assert!(with(&|b| b.probes[0].source_address = Some("192.0.2.9:22".into())).is_err());
        assert!(with(&|b| b.probes[0].source_address = Some("a.example\nforged".into())).is_err());
        assert!(with(&|b| b.probes[0].user = Some("envoy".into())).is_err());
        assert!(with(&|b| b.probes[1].source_address = Some("192.0.2.9".into())).is_err());
        assert!(with(&|b| b.probes[1].user = Some("en voy".into())).is_err());
        assert!(with(&|b| b.probes[1].user = Some("u".repeat(33))).is_err());
    }

    #[test]
    fn a_probe_is_on_the_wire_with_its_own_members_and_no_other() {
        let wire = serde_json::json!({
            "at": "2026-11-22T14:41:58Z", "class": "gateway_output", "count": 3, "port": 2375,
            "user": "envoy"
        });
        let parsed: GatewayProbe = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(serde_json::to_value(&parsed).unwrap(), wire);
        let mut extra = wire;
        extra["path"] = "/x".into();
        assert!(serde_json::from_value::<GatewayProbe>(extra).is_err());
    }

    #[test]
    fn me_without_traps_reads_as_off() {
        let old = serde_json::json!({
            "claim_uid": "00000000-0000-0000-0000-000000000001",
            "subject": { "issuer": "https://issuer.example.com", "id": "octocat" },
            "expires_at": "2026-11-26T16:00:00Z",
            "workload": { "image": "registry.internal:5000/sandbox/claude:latest" }
        });
        let me: Me = serde_json::from_value(old.clone()).unwrap();
        assert_eq!(me.traps, None);
        assert!(serde_json::to_value(&me).unwrap().get("traps").is_none());
        let mut armed = old;
        armed["traps"] = serde_json::json!({ "mode": "shadow" });
        let me: Me = serde_json::from_value(armed).unwrap();
        assert_eq!(
            me.traps,
            Some(TrapsPolicy {
                mode: TrapsMode::Shadow,
                denied: DeniedSwitches::default(),
                catalogue: None,
            })
        );
        // The defaults: off, and every denied class at report.
        assert_eq!(TrapsMode::default(), TrapsMode::Off);
        assert_eq!(TrapsMode::Off.trip_mode(), None);
        assert_eq!(TrapsMode::Enforce.trip_mode(), Some(TripMode::Enforce));
        let denied = DeniedSwitches::default();
        assert!(
            TripClass::DENIED
                .iter()
                .all(|c| denied.action(*c) == ClassAction::Report)
        );
        assert!(
            serde_json::from_value::<TrapsPolicy>(serde_json::json!({ "mode": "on" })).is_err()
        );
        assert!(
            serde_json::from_value::<DeniedSwitches>(serde_json::json!({ "open_port": "trip" }))
                .is_err()
        );
    }

    #[test]
    fn a_route_without_traps_body_reads_as_match() {
        let old = serde_json::json!({
            "audience": "internal-git",
            "endpoint": { "host": "git.home.example", "port": 443 }
        });
        let route: Route = serde_json::from_value(old).unwrap();
        assert_eq!(route.traps_body, TrapsBody::Match);
        let wire = serde_json::to_value(&route).unwrap();
        assert!(wire.get("traps_body").is_none(), "match stays off the wire");
        let mut skip = wire;
        skip["traps_body"] = "skip".into();
        let route: Route = serde_json::from_value(skip).unwrap();
        assert_eq!(route.traps_body, TrapsBody::Skip);
        assert_eq!(serde_json::to_value(&route).unwrap()["traps_body"], "skip");
    }

    #[test]
    fn the_socket_messages_are_tagged_lines_and_a_bait_value_never_prints() {
        let arm = GuestToProxy::Arm(ProxyTraps {
            mode: TripMode::Enforce,
            unknown_host: ClassAction::Report,
            routes: vec![ProxyDecoyRoute {
                name: "vault".into(),
                host: "secrets.prod.internal".into(),
            }],
            bait: vec![ProxyBait {
                name: "aws".into(),
                values: vec![Secret("AKIAEXAMPLEEXAMPLE00".into())],
            }],
        });
        let line = serde_json::to_string(&arm).unwrap();
        assert!(
            line.starts_with(r#"{"type":"arm","mode":"enforce""#),
            "{line}"
        );
        assert!(!line.contains('\n'));
        assert_eq!(serde_json::from_str::<GuestToProxy>(&line).unwrap(), arm);
        assert!(!format!("{arm:?}").contains("AKIA"));
        // The guest's word that a trip was decided: a tag and nothing else.
        assert_eq!(
            serde_json::to_string(&GuestToProxy::Tripped).unwrap(),
            r#"{"type":"tripped"}"#
        );
        assert_eq!(
            serde_json::from_str::<GuestToProxy>(r#"{"type":"tripped"}"#).unwrap(),
            GuestToProxy::Tripped
        );
        let armed = ProxyToGuest::Armed { patterns: 5 };
        assert_eq!(
            serde_json::to_string(&armed).unwrap(),
            r#"{"type":"armed","patterns":5}"#
        );
        let trip = ProxyToGuest::Trip(ProxyTrip {
            at: ts("2026-11-26T15:02:11.204Z"),
            kind: TripKind::Credential,
            trap: Some("aws".into()),
            class: None,
            host: "git.example".into(),
        });
        let line = serde_json::to_string(&trip).unwrap();
        assert_eq!(serde_json::from_str::<ProxyToGuest>(&line).unwrap(), trip);
        for bad in [
            r#"{"type":"disarm"}"#,
            r#"{"type":"armed","patterns":5,"extra":1}"#,
            r#"{"type":"trip","at":"2026-11-26T15:02:11.204Z","kind":"route","host":"a.example","path":"/x"}"#,
        ] {
            assert!(serde_json::from_str::<ProxyToGuest>(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_record_and_an_entry_keep_an_events_fields_and_never_more() {
        let mut e = event(TripKind::Credential);
        e.containment_ms = Some(41);
        let recorded_at = ts("2026-11-26T15:02:12Z");
        let tripped = Tripped::of(&e, recorded_at);
        assert_eq!(
            serde_json::to_value(&tripped).unwrap(),
            serde_json::json!({
                "id": "00000000-0000-0000-0000-000000000001",
                "at": "2026-11-26T15:02:11.204Z",
                "recorded_at": "2026-11-26T15:02:12Z",
                "kind": "credential",
                "trap": "aws",
                "target": { "host": "git.example" },
                "source": "workload"
            })
        );
        assert_eq!(
            serde_json::to_value(TripEntry::of(&e, TripEffect::Tripped)).unwrap(),
            serde_json::json!({
                "effect": "tripped",
                "kind": "credential",
                "trap": "aws",
                "target": { "host": "git.example" },
                "source": "workload",
                "containment_ms": 41,
                "count": 1,
                "first_at": "2026-11-26T15:02:11.204Z",
                "last_at": "2026-11-26T15:02:11.204Z"
            })
        );
        assert_eq!(TripTarget::Port(6379).to_string(), "6379");
        assert_eq!(
            TripTarget::Host("git.example".into()).to_string(),
            "git.example"
        );
    }
}
