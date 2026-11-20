// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Wire contract between the broker (`mediatore serve`), the in-guest agent (`mediatore guest`)
//! and the workload-side client (`mediatore token`).
//!
//! Every type here is versioned together with [`API_VERSION`]. Breaking changes to any of
//! them are a new API version, never a silent edit.

pub mod cert;
pub mod ek;
pub mod image;
pub mod tls;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

/// Path prefix all endpoints live under.
pub const API_VERSION: &str = "v1";

/// Where the one mediatore binary lives on a pool member (ADR-0014). The node entry's
/// `unix:path` selector pins it, and the guest role bind-mounts this exact path, never the
/// path it happens to run from, into the jail at the same place.
pub const AGENT_BINARY_PATH: &str = "/usr/bin/mediatore";

/// Length of the hex suffix in a derived sandbox username (`sb-` + this many hex chars).
pub const USERNAME_HASH_LEN: usize = 12;

/// Which hypervisor a node runs on. Recorded for audit; identity does not depend on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Provider {
    /// `VMware vSphere` (vTPM, EK certificate issued by the VMCA).
    Vsphere,
    /// Cloud Hypervisor with `swtpm` on a socket.
    CloudHypervisor,
    /// libvirt/KVM with `swtpm` emulator backend.
    Libvirt,
}

/// `POST /v1/nodes`, sent by the in-guest agent at boot over the node SVID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRegistration {
    /// SHA-256 of the TPM endorsement public key, as the SPIRE TPM attestor computes it.
    pub ek_hash: String,
    /// `/sys/class/dmi/id/product_uuid` inside the guest.
    pub dmi_uuid: Uuid,
    /// Guest hostname, informational.
    pub hostname: String,
    /// Hypervisor, if the guest can tell.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<Provider>,
}

/// Response to a node registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRegistered {
    /// The node's SPIFFE ID as SPIRE reports it.
    pub node_id: String,
}

/// The subject a claim was handed to. Mirrors `spec.subject` on the banlieue claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Subject {
    /// OIDC issuer URL, byte-for-byte as it appears in `iss`.
    pub issuer: String,
    /// Raw subject identifier: Entra `oid`, or the GitHub login via Dex.
    pub id: String,
    /// Human-readable name (UPN, e-mail, or login), informational only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
}

impl Subject {
    /// Derive the deterministic, valid Linux username for this subject:
    /// `sb-` followed by the first [`USERNAME_HASH_LEN`] hex characters of
    /// `sha256(issuer || "|" || id)`.
    #[must_use]
    pub fn sandbox_username(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.issuer.as_bytes());
        h.update(b"|");
        h.update(self.id.as_bytes());
        let digest = hex::encode(h.finalize());
        format!("sb-{}", &digest[..USERNAME_HASH_LEN])
    }
}

/// What the guest found loaded for the pool VM's host table (ADR-0029 decision 3) when it
/// reported: the hash of the table as `nft` lists it, or that it was missing where the
/// environment has gateways, or that none is loaded in an environment without them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum HostTable {
    /// `inet mediatore_host` is loaded; the SHA-256 of `nft -s list table` output, hex.
    Loaded {
        /// The hash.
        sha256: String,
    },
    /// The environment has gateways and the table is not loaded: flushed, or never loaded.
    Missing,
    /// No gateways, no host table (ADR-0029 decision 4).
    NotLoaded,
}

/// `POST /v1/me/report`: what the guest pulled and loaded before it started the workload
/// (ADR-0029 decision 5), sent over the node SVID once per claim, so the record says which
/// bytes and which rules ran and a later `nft list table` can be compared.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestReport {
    /// The manifest digest the pull resolved to, `sha256:<64 hex>`.
    pub image_digest: String,
    /// SHA-256 of the sandbox uid's ruleset as loaded (`net::Ruleset::sha256`), hex.
    pub sandbox_ruleset_sha256: String,
    /// The host table.
    pub host_table: HostTable,
}

impl GuestReport {
    /// The two hashes and the digest in their one shape.
    ///
    /// # Errors
    /// A digest not `sha256:` plus 64 hex characters, a hash not 64 hex characters.
    pub fn validate(&self) -> Result<(), String> {
        let hex64 = |s: &str| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        };
        match self.image_digest.strip_prefix("sha256:") {
            Some(h) if hex64(h) => {}
            _ => {
                return Err(format!(
                    "image_digest {:?} is not sha256:<64 hex>",
                    self.image_digest
                ));
            }
        }
        if !hex64(&self.sandbox_ruleset_sha256) {
            return Err("sandbox_ruleset_sha256 is not 64 hex characters".into());
        }
        if let HostTable::Loaded { sha256 } = &self.host_table
            && !hex64(sha256)
        {
            return Err("host_table.sha256 is not 64 hex characters".into());
        }
        Ok(())
    }
}

/// The guest's report as the broker keeps it on the claim and shows it on
/// `GET /v1/claims/{name}` (ADR-0029 decision 5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimReport {
    /// When the broker received it.
    pub reported_at: Timestamp,
    /// What the guest said.
    #[serde(flatten)]
    pub report: GuestReport,
}

/// What the sandbox should run once identity is established.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Workload {
    /// OCI reference of the rootfs to unpack into `/mnt/sandbox`.
    pub image: String,
    /// Command and arguments to exec inside the jail.
    #[serde(default)]
    pub args: Vec<String>,
    /// What the guest does when the workload exits before the deadline (ADR-0033
    /// decision 1); `always` when absent, which is what every guest did before.
    #[serde(default, skip_serializing_if = "RestartPolicy::is_always")]
    pub restart: RestartPolicy,
    /// The requester's opt-in to output capture (ADR-0045 decision 1, amended): `true` and
    /// the guest tees the workload's stdout and stderr, redacts them and ships them to the
    /// broker, where the claim's owner reads them back. `false` (the default, left off the
    /// wire) and the output lands on the VM console only, as every guest did before. A
    /// claim that opts in on a broker whose `logs` section is off is refused at creation.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub logs: bool,
}

/// What the guest does when the workload exits before the claim's deadline (ADR-0033
/// decision 1), the systemd shape. The confinement refusal and the egress proxy's exit end
/// the claim whatever the policy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestartPolicy {
    /// Restart whatever the status, until the deadline: the agent that runs until told.
    #[default]
    Always,
    /// Restart a non-zero exit; an exit `0` ends the claim: the agent that runs once.
    OnFailure,
    /// Any exit ends the claim.
    Never,
}

impl RestartPolicy {
    /// As the configuration spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::OnFailure => "on-failure",
            Self::Never => "never",
        }
    }

    /// The default, left off the wire.
    #[must_use]
    pub const fn is_always(&self) -> bool {
        matches!(self, Self::Always)
    }
}

impl std::fmt::Display for RestartPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How the workload ended when its restart policy ended the claim (ADR-0033 decision 2):
/// the guest's `POST /v1/me/exit`, kept on the record until it is swept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestExit {
    /// The exit code, when the workload exited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<i32>,
    /// The signal, when it was killed by one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<i32>,
    /// How many times the supervisor had restarted it before this exit.
    #[serde(default)]
    pub restarts: u32,
}

/// [`GuestExit`] as the broker recorded it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadExit {
    /// When the broker received it.
    pub exited_at: Timestamp,
    /// What the guest said.
    #[serde(flatten)]
    pub exit: GuestExit,
}

/// Which of the workload's two output streams a [`LogRecord`] came from (ADR-0045 decision 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogStream {
    /// The workload's standard output.
    Stdout,
    /// The workload's standard error.
    Stderr,
}

/// One line of the workload's output, already redacted in the VM (ADR-0045 decisions 1 and 2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogRecord {
    /// Per-claim sequence number, strictly increasing in the order the guest's readers produced
    /// the records. It is what makes a retried batch idempotent at the broker.
    pub seq: u64,
    /// The stream the line was read from.
    pub stream: LogStream,
    /// When the guest read the line.
    pub ts: Timestamp,
    /// The line, lossy UTF-8, without its terminator.
    pub text: String,
}

/// The guest's `POST /v1/me/logs` body (ADR-0045 decision 9): output the claim's node ships to
/// the broker. The broker re-validates sizes and does not redact again, because it cannot know
/// which secrets the jail was given; redaction is the guest's, before this leaves the VM.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogBatch {
    /// The records, `seq` strictly increasing.
    pub records: Vec<LogRecord>,
    /// Bytes of stdout the guest dropped from its queue since the last accepted batch.
    #[serde(default)]
    pub dropped_stdout: u64,
    /// Bytes of stderr the guest dropped from its queue since the last accepted batch.
    #[serde(default)]
    pub dropped_stderr: u64,
}

/// First line of the user route's NDJSON answer (ADR-0045 decision 9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogHeader {
    /// Bytes of older output the broker's ring dropped (ADR-0045 decision 4); `0` when none.
    pub truncated_before: u64,
    /// The claim's phase when the read started.
    pub claim_phase: String,
}

/// Why a log stream ended: the `reason` of its last line (ADR-0045 decision 9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LogEnd {
    /// The claim ended and everything stored was sent.
    ClaimEnded,
    /// The output's retention expired.
    Ttl,
    /// The reader went away.
    Client,
}

/// Output the guest's queue dropped before the records that follow (ADR-0045 decision 8):
/// stored and served in sequence as a line of its own, so a reader sees the gap where it is,
/// never silence. Also written by the broker when its ring dropped stored records between two
/// reads of a follower.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogGap {
    /// Bytes of stdout lost before this point.
    pub lost_stdout: u64,
    /// Bytes of stderr lost before this point.
    pub lost_stderr: u64,
    /// Bytes of output stored here that the broker could not serve: a sealed batch that did
    /// not open for this claim, or a segment not in the sealed format (ADR-0052 decision 4).
    /// Zero, and absent on the wire, for a gap of the guest's own.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub unreadable: u64,
}

#[allow(clippy::trivially_copy_pass_by_ref)] // serde's `skip_serializing_if` passes a reference
fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// One stored unit of a claim's output: a record, or a gap before the next one. Serialised
/// untagged: a record has `seq`, a gap has `lost_stdout`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum LogEntry {
    /// A line the guest shipped.
    Record(LogRecord),
    /// Output that was lost.
    Gap(LogGap),
}

impl LogEntry {
    /// Record text bytes, what the size limits count; a gap weighs nothing.
    #[must_use]
    pub fn text_bytes(&self) -> usize {
        match self {
            Self::Record(r) => r.text.len(),
            Self::Gap(_) => 0,
        }
    }

    /// The record's `seq`; a gap has none.
    #[must_use]
    pub fn seq(&self) -> Option<u64> {
        match self {
            Self::Record(r) => Some(r.seq),
            Self::Gap(_) => None,
        }
    }
}

/// Last line of the user route's NDJSON answer (ADR-0045 decision 9): `{"end": true,
/// "reason": ...}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogEndLine {
    /// Always `true`; what marks the line.
    pub end: bool,
    /// Why the stream ended.
    pub reason: LogEnd,
}

impl LogEndLine {
    /// The end line for `reason`.
    #[must_use]
    pub const fn new(reason: LogEnd) -> Self {
        Self { end: true, reason }
    }
}

/// Every line `GET /v1/claims/{name}/logs` may send (ADR-0045 decision 9), as the CLI parses
/// them: the header first, then records and gaps in sequence, the end line last. Between them
/// a follower may receive an empty line every [`LOG_KEEPALIVE_SECS`] seconds, which is not a
/// `LogLine` and is skipped by the reader. Untagged: each variant has a field no other has.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum LogLine {
    /// First line.
    Header(LogHeader),
    /// A line of output.
    Record(LogRecord),
    /// Output that was lost.
    Gap(LogGap),
    /// Last line.
    End(LogEndLine),
}

/// Largest single record text the broker accepts (ADR-0045 decision 9): the guest splits longer
/// lines.
pub const MAX_LOG_RECORD_BYTES: usize = 64 * 1024;

/// Largest batch the broker accepts, as the sum of record texts (ADR-0045 decision 4).
pub const MAX_LOG_BATCH_BYTES: usize = 256 * 1024;

/// Default of `logs.max_bytes`: the newest output the broker keeps per claim (ADR-0045
/// decision 4).
pub const DEFAULT_LOG_MAX_BYTES: usize = 1024 * 1024;

/// Hard ceiling of `logs.max_bytes`; a configuration above it is refused at start (ADR-0045
/// decision 4).
pub const LOG_MAX_BYTES_CEILING: usize = 4 * 1024 * 1024;

/// One segment of the broker's ring (ADR-0045 decision 6): the most record text one stored
/// object holds. Also the floor of `logs.max_bytes`, so the ring has at least one segment.
pub const LOG_SEGMENT_BYTES: usize = 64 * 1024;

/// Seconds between the empty keepalive lines of a `follow` read (ADR-0045 decision 9).
pub const LOG_KEEPALIVE_SECS: u64 = 15;

// The limits nest: a record fits a segment, a segment fits the default cap, the default fits
// the ceiling, and a batch fits the default cap. Checked at compile time.
const _: () = assert!(MAX_LOG_RECORD_BYTES <= LOG_SEGMENT_BYTES);
const _: () = assert!(LOG_SEGMENT_BYTES <= DEFAULT_LOG_MAX_BYTES);
const _: () = assert!(DEFAULT_LOG_MAX_BYTES <= LOG_MAX_BYTES_CEILING);
const _: () = assert!(MAX_LOG_BATCH_BYTES <= DEFAULT_LOG_MAX_BYTES);

/// Seconds a node waits before its next batch when the broker answered `429` (ADR-0045
/// decision 4): one batch per second per claim, the `Retry-After` the broker sends.
pub const LOG_RETRY_AFTER_SECS: u64 = 1;

impl LogBatch {
    /// Total bytes of record text, what the size limits count.
    #[must_use]
    pub fn text_bytes(&self) -> usize {
        self.records.iter().map(|r| r.text.len()).sum()
    }

    /// Check the shape the broker requires (ADR-0045 decision 9): `seq` strictly increasing, no
    /// record over [`MAX_LOG_RECORD_BYTES`].
    ///
    /// # Errors
    /// A description of the first violation, for a `400`.
    pub fn validate(&self) -> Result<(), String> {
        let mut last: Option<u64> = None;
        for r in &self.records {
            if last.is_some_and(|l| r.seq <= l) {
                return Err(format!("seq {} is not strictly increasing", r.seq));
            }
            if r.text.len() > MAX_LOG_RECORD_BYTES {
                return Err(format!(
                    "record {} is {} bytes, over the {MAX_LOG_RECORD_BYTES} limit",
                    r.seq,
                    r.text.len()
                ));
            }
            last = Some(r.seq);
        }
        Ok(())
    }
}

/// A destination the jailed workload may reach: a host (a name or an address) and a TCP
/// port. Declared per audience in the broker's config, returned by `GET /v1/me` for the
/// claim's audiences, admitted by the guest's ruleset for the sandbox uid (ADR-0020).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Endpoint {
    /// Host name or IP address, without brackets.
    pub host: String,
    /// TCP port.
    pub port: u16,
}

impl std::str::FromStr for Endpoint {
    type Err = String;

    /// `host:port`, with an IPv6 address in brackets (`[2001:db8::1]:443`).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (host, port) = s
            .rsplit_once(':')
            .ok_or_else(|| format!("{s:?}: expected host:port"))?;
        let host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        if host.is_empty() || (host.contains(':') && !s.starts_with('[')) {
            return Err(format!(
                "{s:?}: expected host:port, an IPv6 address in brackets"
            ));
        }
        let port: u16 = port
            .parse()
            .ok()
            .filter(|p| *p != 0)
            .ok_or_else(|| format!("{s:?}: the port must be 1 to 65535"))?;
        Ok(Self {
            host: host.to_owned(),
            port,
        })
    }
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.host.contains(':') {
            write!(f, "[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
        }
    }
}

/// One rule of what a workload may ask of an audience through the egress proxy (ADR-0025
/// decision 4), in nono's `endpoint_rules` shape: an HTTP method or `*`, and a path glob
/// where `*` matches one segment and `**` zero or more.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EndpointRule {
    /// `GET`, `POST`, ... or `*` for any method. Compared case-insensitively.
    pub method: String,
    /// The path glob, matched against the request path without the query.
    pub path: String,
}

/// The most segments a request path may have and still be matched against a rule: a longer
/// path matches nothing, so the work one request costs the matcher is bounded by a constant
/// and not by what the workload chose to send. Far above any path an API names.
pub const MAX_PATH_SEGMENTS: usize = 64;

impl EndpointRule {
    /// Whether `method` and `path` (no query) are admitted by this rule. A path of more than
    /// [`MAX_PATH_SEGMENTS`] segments is admitted by no rule.
    #[must_use]
    pub fn matches(&self, method: &str, path: &str) -> bool {
        if self.method != "*" && !self.method.eq_ignore_ascii_case(method) {
            return false;
        }
        let path = segments(path);
        path.len() <= MAX_PATH_SEGMENTS && glob_matches(&segments(&self.path), &path)
    }

    /// Check the rule's path glob as configuration: at most one `**` segment (two or more
    /// say nothing one does not, and cost the matcher more on a path the workload chooses),
    /// and at most [`MAX_PATH_SEGMENTS`] segments, since a longer pattern without a `**`
    /// could match nothing. The broker's config check calls this for every rule.
    ///
    /// # Errors
    /// A description of what the path glob breaks.
    pub fn validate(&self) -> Result<(), String> {
        let pattern = segments(&self.path);
        let wildcards = pattern.iter().filter(|s| **s == "**").count();
        if wildcards > 1 {
            return Err(format!(
                "path glob {:?} has {wildcards} `**` segments; at most one is allowed",
                self.path
            ));
        }
        if pattern.len() > MAX_PATH_SEGMENTS {
            return Err(format!(
                "path glob {:?} has {} segments; at most {MAX_PATH_SEGMENTS} are allowed",
                self.path,
                pattern.len()
            ));
        }
        Ok(())
    }
}

/// A path split into its non-empty segments: `/a//b/` is `["a", "b"]`.
fn segments(path: &str) -> Vec<&str> {
    path.split('/').filter(|s| !s.is_empty()).collect()
}

/// Segment-wise glob: `*` matches exactly one segment, `**` zero or more, anything else
/// matches itself. One pass per pattern segment over the path, so the cost is the product of
/// the two lengths whatever the pattern holds: nothing backtracks.
fn glob_matches(pattern: &[&str], path: &[&str]) -> bool {
    // `reach[j]`: the pattern segments taken so far match exactly the first `j` of the path.
    let mut reach = vec![false; path.len() + 1];
    reach[0] = true;
    for seg in pattern {
        let mut next = vec![false; path.len() + 1];
        if *seg == "**" {
            let mut any = false;
            for (slot, reached) in next.iter_mut().zip(&reach) {
                any |= *reached;
                *slot = any;
            }
        } else {
            for (j, head) in path.iter().enumerate() {
                next[j + 1] = reach[j] && (*seg == "*" || seg == head);
            }
        }
        reach = next;
    }
    reach[path.len()]
}

/// Whether a request path (no query) is in the one spelling the rules can be trusted on.
/// The rules are globs over the path as sent, and the path is forwarded as sent, so a path
/// the upstream would resolve to another one walks around a rule with the credential
/// attached. Both enforcement points, the guest's egress proxy and the gateway's inject
/// authorizer, refuse a path this refuses before any rule is consulted.
///
/// Refused: a path that does not start with `/`; a `.` or `..` segment; an empty segment
/// other than the one a trailing slash leaves (`//`); a backslash; a control character;
/// a `%` not followed by two hex digits; and an escape that decodes to a dot, a slash, a
/// backslash or a control character (`%2e`, `%2f`, `%5c`, `%00`, in either case). Every
/// other escape (`%20`, `%2B`) and any other character, ASCII or not, is left to the rules.
#[must_use]
pub fn path_is_canonical(path: &str) -> bool {
    let Some(rest) = path.strip_prefix('/') else {
        return false;
    };
    if path.chars().any(|c| c == '\\' || c.is_control()) || !escapes_are_plain(path.as_bytes()) {
        return false;
    }
    let mut segs = rest.split('/').peekable();
    while let Some(seg) = segs.next() {
        let last = segs.peek().is_none();
        if seg == "." || seg == ".." || (seg.is_empty() && !last) {
            return false;
        }
    }
    true
}

/// Whether every `%` starts a well-formed escape that decodes to none of the bytes
/// [`path_is_canonical`] refuses in their encoded form.
fn escapes_are_plain(path: &[u8]) -> bool {
    let hex = |b: u8| char::from(b).to_digit(16);
    let mut i = 0;
    while i < path.len() {
        if path[i] != b'%' {
            i += 1;
            continue;
        }
        let (Some(hi), Some(lo)) = (
            path.get(i + 1).copied().and_then(hex),
            path.get(i + 2).copied().and_then(hex),
        ) else {
            return false;
        };
        let decoded = hi * 16 + lo;
        if matches!(decoded, 0x2e | 0x2f | 0x5c | 0x7f) || decoded < 0x20 {
            return false;
        }
        i += 3;
    }
    true
}

/// What the egress proxy puts in place of the phantom on a route (ADR-0025 decision 8).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Credential {
    /// The route's audience's bearer, fetched over the claim SVID: the default, so a route
    /// written before the field existed keeps its meaning.
    #[default]
    Token,
    /// Nothing: the phantom is dropped and the request leaves bare. A policy bundle's
    /// direct egress (ADR-0030), or an audience declared `via: none`.
    None,
    /// The gateway places the audience's credential (ADR-0040): the proxy never asks for a
    /// token. It still refuses a non-phantom credential and checks the rules, strips the phantom
    /// and sends the request in origin form to the route's `inject_port` on a gateway instead
    /// of tunnelling. An audience declared `inject: gateway`.
    Gateway,
}

/// One route of the egress proxy (ADR-0025): one `host:port` the proxy forwards to, the
/// rules a request must meet there, and what goes in place of the phantom. `GET /v1/me`
/// carries one per audience and `egress` endpoint of the claim and, in `policy.egress:
/// enforce`, one per direct egress entry its bundle holds that the gateway serves
/// (decision 8); the proxy chooses the route, and so the credential, by the endpoint a
/// request names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    /// The audience this route belongs to: whose token goes in when `credential` is
    /// `token`, whose rules and CA apply either way. Absent on a route rendered from a
    /// bundle's direct egress, which has no audience and so carries `credential: none`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// The upstream, reached over HTTPS.
    pub endpoint: Endpoint,
    /// The audience's rules; empty admits every method and path.
    #[serde(default)]
    pub rules: Vec<EndpointRule>,
    /// The CA certificates, PEM, the proxy trusts for this route instead of the Mozilla
    /// roots (`audiences[].ca_file`, ADR-0025 amended): an upstream on a private PKI.
    /// Public material. Absent, the Mozilla roots.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_pem: Option<String>,
    /// What replaces the phantom on this route (ADR-0025 decision 8); `token` when absent.
    #[serde(default)]
    pub credential: Credential,
    /// The request header the credential goes in, when it is not `Authorization`
    /// (ADR-0032 decision 2, an audience `via: secret` with `secret_header`): the proxy
    /// recognises the phantom there too and owns that header on every route (decision 3).
    /// Absent, `Authorization: Bearer`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_header: Option<String>,
    /// The gateway's inject port (`gateway_inject_port`, ADR-0040 decision 7) that a
    /// `credential: gateway` route's request is sent to, on the gateway addresses of
    /// `Me.gateways`. Absent on every other route, and on a route from an older broker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inject_port: Option<u16>,
}

impl Route {
    /// Whether a request for `method` and `path` is admitted: always when the route carries
    /// no rules, else by at least one of them (ADR-0025 decision 4).
    #[must_use]
    pub fn admits(&self, method: &str, path: &str) -> bool {
        self.rules.is_empty() || self.rules.iter().any(|r| r.matches(method, path))
    }

    /// Whether the proxy swaps the phantom for the audience's token here.
    #[must_use]
    pub fn injects(&self) -> bool {
        self.credential == Credential::Token
    }

    /// Whether the gateway, not the proxy, places the credential here (ADR-0040): the proxy
    /// sends the request to the gateway's inject port and never fetches a token.
    #[must_use]
    pub fn placed_at_gateway(&self) -> bool {
        self.credential == Credential::Gateway
    }

    /// The audience for a log line: the name, or `-` on a route without one.
    #[must_use]
    pub fn audience_label(&self) -> &str {
        self.audience.as_deref().unwrap_or("-")
    }
}

/// A credential in a request body: serialises as the plain string, never prints.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(pub String);

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}

/// A label selector over `VirtualMachinePool`s, the shape of Kubernetes' `LabelSelector`
/// (ADR-0044 decision 4): the proto crate's own copy, since it depends on nothing of kube's.
/// Empty (`{}`) matches every pool in the sandbox's namespace, and is the explicit spelling
/// of "any pool" (banlieue ADR-0132 decision 2).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolSelector {
    /// Labels the pool must carry, each with this exact value.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub match_labels: BTreeMap<String, String>,
    /// Requirements on the pool's labels, all of which must hold.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub match_expressions: Vec<PoolSelectorRequirement>,
}

/// One requirement of a [`PoolSelector`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolSelectorRequirement {
    /// The label key.
    pub key: String,
    /// How `values` applies to the key.
    pub operator: PoolSelectorOperator,
    /// The values, for `In` and `NotIn`; empty for `Exists` and `DoesNotExist`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub values: Vec<String>,
}

/// The operators of a [`PoolSelectorRequirement`], as Kubernetes spells them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PoolSelectorOperator {
    /// The label's value is one of `values`.
    In,
    /// The label is absent or its value is none of `values`.
    NotIn,
    /// The label is present, whatever its value.
    Exists,
    /// The label is absent.
    DoesNotExist,
}

/// Which pool a request asks for, once it has been checked to ask for exactly one thing
/// (ADR-0044 decision 2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PoolChoice<'a> {
    /// One pool, by name.
    Named(&'a str),
    /// Every pool in the namespace whose labels match; `{}` for all of them.
    Selected(&'a PoolSelector),
}

impl std::fmt::Display for PoolChoice<'_> {
    /// The name, or the selector as `kubectl -l` would take it (`any pool` for `{}`): for
    /// log lines, which name pools and never anything secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Named(name) => f.write_str(name),
            Self::Selected(sel) => {
                let mut terms: Vec<String> = sel
                    .match_labels
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect();
                for r in &sel.match_expressions {
                    terms.push(match r.operator {
                        PoolSelectorOperator::In => {
                            format!("{} in ({})", r.key, r.values.join(","))
                        }
                        PoolSelectorOperator::NotIn => {
                            format!("{} notin ({})", r.key, r.values.join(","))
                        }
                        PoolSelectorOperator::Exists => r.key.clone(),
                        PoolSelectorOperator::DoesNotExist => format!("!{}", r.key),
                    });
                }
                if terms.is_empty() {
                    f.write_str("any pool")
                } else {
                    f.write_str(&terms.join(","))
                }
            }
        }
    }
}

/// A request that asks for no pool, or for a pool two ways at once.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PoolChoiceError {
    /// Neither `pool_ref` nor `pool_selector`: never read as "any pool".
    #[error(
        "a claim takes exactly one of pool_ref or pool_selector; use pool_selector: {{}} for any pool in the namespace"
    )]
    Neither,
    /// Both at once.
    #[error("a claim takes exactly one of pool_ref or pool_selector, not both")]
    Both,
    /// `pool_ref` present but empty: names nothing.
    #[error("pool_ref must not be empty")]
    EmptyName,
}

/// How banlieue ranks the Ready members of the matched pools when it picks one for the claim
/// (ADR-0047 decision 3; banlieue ADR-0135): the proto crate's own copy of banlieue's
/// `SelectionStrategy`, spelled as banlieue spells it so a body, a sandbox and a claim read
/// the same. A strategy only reorders, never filters: no strategy leaves a claim `Pending`
/// while a Ready member exists.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum SelectionStrategy {
    /// No placement preference: the member Ready longest, the order every claim had before
    /// the field existed.
    #[default]
    LongestReady,
    /// Take from the failure domain with the most Ready members, so warm capacity drains
    /// evenly and no single domain runs dry first.
    MostAvailable,
    /// Take from the failure domain where this claim's subject holds the fewest members,
    /// then as `MostAvailable`, so one subject's sandboxes do not share a host. Soft: a
    /// claim never waits for a free domain.
    Spread,
}

impl std::fmt::Display for SelectionStrategy {
    /// The value as it is spelled on the wire and on the claim, for log lines.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::LongestReady => "LongestReady",
            Self::MostAvailable => "MostAvailable",
            Self::Spread => "Spread",
        })
    }
}

/// How a claim chooses among the Ready members it may take (ADR-0047 decision 3): the shape
/// of banlieue's `ClaimSelection`, a struct so later knobs have somewhere to go. `{}` is the
/// default strategy written down.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Selection {
    /// The ranking to apply; `LongestReady` when absent.
    #[serde(default)]
    pub strategy: SelectionStrategy,
}

/// `POST /v1/claims` body, sent by a user or agent with an `IdP` bearer token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimRequest {
    /// The namespace the claim is made in (ADR-0046 decision 4). Absent means the one
    /// namespace of a broker without a namespace map, and `400 namespace_required` with one;
    /// never serialised when `None`, so an existing client's body is unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// `spec.poolRef` on the banlieue claim: one pool, by name. Exactly one of this or
    /// `pool_selector` (ADR-0044 decision 2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_ref: Option<String>,
    /// `spec.poolSelector` on the banlieue claim: any pool in the sandbox's namespace whose
    /// labels match, `{}` for all of them (ADR-0044 decision 4). Exactly one of this or
    /// `pool_ref`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool_selector: Option<PoolSelector>,
    /// `spec.selection` on the banlieue claim: how the member is picked among the Ready ones
    /// (ADR-0047 decisions 2 and 3). Absent stays absent, which banlieue reads as
    /// `LongestReady`; the broker writes no default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selection: Option<Selection>,
    /// `spec.ttlSeconds` on the banlieue claim; a deadline counted from bind.
    pub ttl_seconds: u32,
    /// Downstream audiences the sandbox may request tokens for. Must be a subset of
    /// what mediatore is configured to serve.
    #[serde(default)]
    pub audiences: Vec<String>,
    /// What to run.
    pub workload: Workload,
    /// The caller's upstream refresh token, delegated to mediatore so it can refresh the
    /// session before every issue (ADR-0013). Required for an issuer configured with a
    /// `session`, refused for any other. Sealed before it is stored; never returned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<Secret>,
    /// The notaio `SandboxPolicy` the sandbox is under, by name in the sandbox namespace
    /// (ADR-0026 decision 6): `spec.policyRef` on the `AgentSandbox`. Optional while the
    /// bundle is read in shadow; naming one grants and refuses nothing yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_ref: Option<String>,
    /// The caller's own credentials for `via: delegated` audiences (ADR-0035): one per such
    /// audience the claim names, sealed before they are stored, never returned. A
    /// `delegated` audience without one refuses the claim; one for any other audience too.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub delegations: Vec<Delegation>,
}

impl ClaimRequest {
    /// Which pool the request asks for: exactly one of `pool_ref` and `pool_selector`, or
    /// the reason it asks for nothing usable (ADR-0044 decision 2; fail closed, neither is
    /// never "any").
    ///
    /// # Errors
    /// Neither field, both fields, or an empty `pool_ref`.
    pub fn pool(&self) -> Result<PoolChoice<'_>, PoolChoiceError> {
        match (self.pool_ref.as_deref(), self.pool_selector.as_ref()) {
            (Some(_), Some(_)) => Err(PoolChoiceError::Both),
            (None, None) => Err(PoolChoiceError::Neither),
            (Some(""), None) => Err(PoolChoiceError::EmptyName),
            (Some(name), None) => Ok(PoolChoice::Named(name)),
            (None, Some(sel)) => Ok(PoolChoice::Selected(sel)),
        }
    }
}

/// A credential the caller delegates for one audience (ADR-0035 decision 2): the bearer the
/// proxy will place, what renews it, when it dies. `pending` promises it for a later
/// `PUT /v1/claims/{name}/delegations/{audience}` (the transit shape), carrying nothing now.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delegation {
    /// The audience it is for; must be one the broker serves `via: delegated`.
    pub audience: String,
    /// The bearer itself. Absent only with `pending`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<Secret>,
    /// What renews it, when the audience declares a `refresh` endpoint (decision 5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<Secret>,
    /// When the bearer dies, if the caller knows: a claim that would outlast it is refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
    /// The envelope follows, sealed on the caller's machine (decision 3, transit shape).
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub pending: bool,
}

/// What a sealed delegation holds once opened (ADR-0035 decision 3): the envelope's
/// plaintext is this, serialised, so the shape can grow without re-sealing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationPlain {
    /// The bearer.
    pub token: Secret,
    /// What renews it, if anything.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<Secret>,
    /// When the stored credential stops being used (ADR-0057 decision 11): sealed with the
    /// bearer, so the issue path believes this and no expiry kept in clear beside the
    /// envelope. `None` only in an envelope sealed before the ADR (format 1).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
}

/// Claim lifecycle as mirrored from banlieue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClaimPhase {
    /// Waiting for a Ready pool member.
    Pending,
    /// Bound to a member; identity entry created.
    Bound,
    /// TTL reached or deleted; member being destroyed.
    Releasing,
    /// Terminal; never rebound.
    Failed,
}

/// `POST /v1/claims` and `GET /v1/claims/{name}` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimResponse {
    /// Kubernetes object name.
    pub name: String,
    /// The namespace the claim lives in (ADR-0046 decisions 4 and 16). A current broker
    /// always sets it; `None` is an old broker that predates the field, which the client
    /// tells from a broker that answered a different namespace than the one it asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    /// The claim's UID, once the claim exists: the key of the claim's SPIFFE identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<Uuid>,
    /// The `AgentSandbox` UID: what a delegation sealed on the caller's machine binds to
    /// (ADR-0035 decision 2). Absent in `dev_mode`, where there is no resource.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_uid: Option<Uuid>,
    /// Current phase.
    pub phase: ClaimPhase,
    /// `Bound` and the claim's registration entry is set: the sandbox can fetch its SVID
    /// (ADR-0008 decision 11).
    #[serde(default)]
    pub ready: bool,
    /// The pool the bound member came from (ADR-0044 decision 5), once the claim is bound:
    /// the answer, whether the request named a pool or selected among them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pool: Option<String>,
    /// Deadline, once bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
    /// Guest addresses, once known.
    #[serde(default)]
    pub addresses: Vec<String>,
    /// What the guest pulled and loaded before the workload started, once it reported
    /// (ADR-0029 decision 5); absent until then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<ClaimReport>,
    /// How the workload ended, when its restart policy ended the claim (ADR-0033).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit: Option<WorkloadExit>,
}

/// `GET /v1/me`, answered to the in-guest agent over the node SVID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Me {
    /// Kubernetes UID of the claim bound to this node.
    pub claim_uid: Uuid,
    /// Who the sandbox is for.
    pub subject: Subject,
    /// Deadline after which the guest tears the jail down regardless.
    pub expires_at: Timestamp,
    /// What to run.
    pub workload: Workload,
    /// Where the workload may connect, beyond the broker: the `egress` of every audience
    /// on the claim, sorted and deduplicated (ADR-0020). Empty with an old broker or an
    /// audience that declares none; the jail then reaches the broker only.
    #[serde(default)]
    pub egress: Vec<Endpoint>,
    /// The egress proxy's routes (ADR-0025): one per audience and `egress` endpoint of the
    /// claim, with the audience's rules, and in `policy.egress: enforce` one without a
    /// credential per direct egress entry of the claim's bundle that the gateway serves
    /// (ADR-0025 decision 8, ADR-0030); sorted by endpoint. The same destinations as
    /// `egress`, which stays for the ruleset. Empty with an old broker: the proxy then
    /// routes nothing and the jail reaches nowhere.
    #[serde(default)]
    pub routes: Vec<Route>,
    /// The operator's credential for the registry `workload.image` names, when one is
    /// configured (ADR-0022); absent, the pull is anonymous. Used by the guest for one
    /// pull, kept nowhere.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_credential: Option<RegistryCredential>,
    /// The egress gateways of this environment, in the broker's order (ADR-0028 decision 6):
    /// each gateway's `sandbox` address and data-plane port. The authoritative list for the
    /// forwarder, which starts at a random position and fails over along it (decision 7),
    /// and for the ruleset, which admits the sandbox uid to them (ADR-0027 decision 4 lets
    /// the pool's bootstrap list disagree; this one wins). Empty with an old broker, or an
    /// environment with no gateway yet: the jail then reaches what `egress` names directly.
    #[serde(default)]
    pub gateways: Vec<Endpoint>,
}

/// `GET /v1/gateway/claims/{uid}` response (ADR-0028 decision 4): what a gateway may let
/// one claim reach. Answered to the gateway identity only, and only for a claim that is
/// bound and live; a released, expired, pending or unknown claim is `404`, which the
/// gateway's authorizer takes as "drop the cached answer, deny".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimEgress {
    /// The claim, as its SVID names it.
    pub claim_uid: Uuid,
    /// The claim's deadline; no cached answer outlives it.
    pub expires_at: Timestamp,
    /// The `host:port` pairs the claim may reach: the union of its audiences' `egress`,
    /// sorted and deduplicated, exactly what `GET /v1/me` hands the guest.
    #[serde(default)]
    pub egress: Vec<Endpoint>,
    /// The claim's gateway-placed routes (ADR-0040 decision 2): one per audience declared
    /// `inject: gateway` and exact endpoint of it, with the rules the gateway enforces, the
    /// header the credential goes in and the public extra headers. Empty (and absent on the
    /// wire) for a claim with no such audience, and from an older broker.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inject: Vec<InjectRoute>,
}

/// What the gateway places for one claim at one upstream (ADR-0040 decisions 2 and 4): the
/// authority the request must name, what it may ask there, and the headers the authorizer
/// writes. Carries no credential: the credential comes from
/// `POST /v1/gateway/claims/{uid}/credential`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InjectRoute {
    /// The audience the credential is for.
    pub audience: String,
    /// The one exact upstream authority; the credential is added for this authority and no
    /// other (a credential is bound to the authority that needs it).
    pub endpoint: Endpoint,
    /// What a request may ask of the upstream. Never empty on a valid route: a placed
    /// credential does not get the proxy's empty-rules-admit-all default.
    pub rules: Vec<EndpointRule>,
    /// The request header the credential goes in, lowercase (`authorization`, `x-api-key`).
    pub header: String,
    /// Public headers the authorizer adds beside the credential (`anthropic-version`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_headers: Vec<HeaderPair>,
}

impl InjectRoute {
    /// Whether a request for `method` and `path` (no query) is admitted: by a rule, and by
    /// nothing else. No rules admit nothing.
    #[must_use]
    pub fn admits(&self, method: &str, path: &str) -> bool {
        self.rules.iter().any(|r| r.matches(method, path))
    }

    /// Whether the request's authority is this route's, exactly: the host compared without
    /// regard to case, the port equal, and an absent port taken as 443 (the guest proxy sends
    /// `Host` without a port, ADR-0040 decision 4).
    #[must_use]
    pub fn matches_authority(&self, host: &str, port: Option<u16>) -> bool {
        self.endpoint.host.eq_ignore_ascii_case(host) && self.endpoint.port == port.unwrap_or(443)
    }

    /// The request headers a client could use to carry a credential of its own, which the
    /// authorizer removes (ADR-0040 decision 4): `authorization`, `x-api-key` and this
    /// route's header, lowercase, sorted, once each. Not the public extra headers.
    #[must_use]
    pub fn client_headers_to_strip(&self) -> Vec<String> {
        let mut names: std::collections::BTreeSet<String> =
            ["authorization".to_owned(), "x-api-key".to_owned()].into();
        names.insert(self.header.to_ascii_lowercase());
        names.into_iter().collect()
    }
}

/// The hard cap, in seconds, on a gateway-placed credential's life (ADR-0040 decision 1): a
/// constant, not a setting. `inject: gateway` refuses a larger `max_ttl` at start, and the
/// broker never answers a credential that expires later than this from now.
pub const GATEWAY_CREDENTIAL_MAX_TTL_SECS: i64 = 300;

/// Stable error codes of ADR-0040, in the `error` field of [`ErrorBody`].
pub mod error_code {
    /// `POST /v1/token` for an audience declared `inject: gateway` (`403`): the credential is
    /// the gateway's to place, so the claim SVID on the pool VM cannot obtain it.
    pub const PLACED_AT_GATEWAY: &str = "placed_at_gateway";
    /// `POST /v1/gateway/claims/{uid}/credential` for an audience that is not declared
    /// `inject: gateway` (`403`): the route answers nothing for an audience placed in the proxy.
    pub const NOT_PLACED_AT_GATEWAY: &str = "not_placed_at_gateway";
    /// A claim or `GET`/`DELETE` that names no namespace on a broker with a namespace map
    /// (`400`, ADR-0046 decision 4): there is no default to fall back to.
    pub const NAMESPACE_REQUIRED: &str = "namespace_required";
    /// A namespace that is not an RFC 1123 label (`400`, ADR-0046 decision 4).
    pub const INVALID_NAMESPACE: &str = "invalid_namespace";
}

/// An RFC 1123 label, which is what a namespace name must be (ADR-0046 decision 4). The
/// broker's config check and the API share this one function.
#[must_use]
pub fn is_dns_label(s: &str) -> bool {
    (1..=63).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !s.starts_with('-')
        && !s.ends_with('-')
}

/// `POST /v1/gateway/claims/{uid}/credential` body (ADR-0040 decision 2), sent by the gateway
/// identity only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayCredentialRequest {
    /// Exactly one audience, declared `inject: gateway`.
    pub audience: String,
}

/// `POST /v1/gateway/claims/{uid}/credential` response (ADR-0040 decision 2): the header the
/// authorizer writes, whole, and when it stops being good. The value prints as `[redacted]`
/// and is never logged; it travels only to the authorizer, over SPIFFE mutual TLS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayCredential {
    /// Echo of the audience.
    pub audience: String,
    /// Who the credential acts for (the audit line's subject).
    pub subject: Subject,
    /// The request header the credential goes in, lowercase.
    pub header: String,
    /// The complete header value: `Bearer <token>` for `authorization`, the bare value for
    /// another header (as the proxy would have placed it).
    pub value: Secret,
    /// Public headers added beside it (`anthropic-version`); empty for the minted backends.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_headers: Vec<HeaderPair>,
    /// Absolute expiry, at most [`GATEWAY_CREDENTIAL_MAX_TTL_SECS`] after the broker's clock
    /// when it answered. The gateway holds nothing past it.
    pub expires_at: Timestamp,
}

impl GatewayCredential {
    /// The gateway's answer from the token the same per-backend code produced for
    /// `POST /v1/token`: the header and the whole value as the proxy would have placed them,
    /// and an expiry never later than `now` plus the cap (and never extended: an earlier one
    /// is kept).
    #[must_use]
    pub fn from_token_response(resp: TokenResponse, now: Timestamp) -> Self {
        let cap = now + jiff::SignedDuration::from_secs(GATEWAY_CREDENTIAL_MAX_TTL_SECS);
        let (header, value) = match resp.header {
            Some(h) => (h, resp.access_token),
            None => (
                "authorization".to_owned(),
                format!("Bearer {}", resp.access_token),
            ),
        };
        Self {
            audience: resp.audience,
            subject: resp.subject,
            header,
            value: Secret(value),
            extra_headers: resp.extra_headers,
            expires_at: resp.expires_at.min(cap),
        }
    }
}

/// The operator's pull credential for one registry, handed to the guest for the registry
/// its claim's image names (ADR-0022). The password prints as `[redacted]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryCredential {
    /// The registry host as the API reaches it (`registry-1.docker.io` for Docker Hub).
    pub host: String,
    /// The login at that registry.
    pub username: String,
    /// The password or token.
    pub password: Secret,
}

/// `POST /v1/token` body, sent by the jailed workload over its claim SVID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRequest {
    /// Exactly one downstream audience.
    pub audience: String,
}

/// `POST /v1/token` response. Never contains a refresh token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    /// The credential for `audience`: a bearer token, or with `header` set the bare value
    /// for that header (ADR-0032).
    pub access_token: String,
    /// `Bearer`, or `Header` when `header` names one (ADR-0032 decision 2).
    pub token_type: String,
    /// Absolute expiry; the workload must not cache past this.
    pub expires_at: Timestamp,
    /// Echo of the requested audience.
    pub audience: String,
    /// Who the token acts for.
    pub subject: Subject,
    /// The request header the proxy sets to `access_token` (ADR-0032 decision 2). Absent:
    /// `Authorization: Bearer <access_token>`, the shape every backend had before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<String>,
    /// Headers the proxy adds beside the credential on every credentialed request
    /// (`audiences[].secret_extra_headers`); public material, empty for the minted backends.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_headers: Vec<HeaderPair>,
}

/// One request header by name and value, as the configuration spells it (ADR-0032).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeaderPair {
    /// The header name, lowercase.
    pub name: String,
    /// The value, as sent.
    pub value: String,
}

/// Error body for every non-2xx response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    /// Stable machine-readable code (`unauthorized`, `unknown_audience`, ...).
    pub error: String,
    /// Human-readable detail, safe to show to a caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_workloads_logs_opt_in_is_off_by_default_and_left_off_the_wire() {
        let w: Workload = serde_json::from_value(serde_json::json!({
            "image": "registry.internal:5000/sandbox:latest"
        }))
        .unwrap();
        assert!(!w.logs, "ADR-0045: capture is opt-in");
        let v = serde_json::to_value(&w).unwrap();
        assert!(
            v.get("logs").is_none(),
            "an existing client's body is byte-identical: {v}"
        );
        let on: Workload = serde_json::from_value(serde_json::json!({
            "image": "registry.internal:5000/sandbox:latest",
            "logs": true
        }))
        .unwrap();
        assert!(on.logs);
        assert_eq!(
            serde_json::to_value(&on).unwrap()["logs"],
            serde_json::Value::Bool(true)
        );
    }

    #[test]
    fn every_log_line_round_trips_and_is_told_apart_untagged() {
        let lines = vec![
            LogLine::Header(LogHeader {
                truncated_before: 12,
                claim_phase: "Bound".into(),
            }),
            LogLine::Record(log_record(1, "hello")),
            LogLine::Gap(LogGap {
                lost_stdout: 4096,
                lost_stderr: 0,
                unreadable: 0,
            }),
            LogLine::Record(log_record(2, "world")),
            LogLine::End(LogEndLine::new(LogEnd::ClaimEnded)),
        ];
        for line in &lines {
            let text = serde_json::to_string(line).unwrap();
            let back: LogLine = serde_json::from_str(&text).unwrap();
            assert_eq!(&back, line, "{text}");
        }
        assert_eq!(
            serde_json::to_value(LogEndLine::new(LogEnd::Ttl)).unwrap(),
            serde_json::json!({"end": true, "reason": "ttl"})
        );
        let entry: LogEntry = serde_json::from_str(r#"{"lost_stdout":1,"lost_stderr":2}"#).unwrap();
        assert_eq!(
            entry,
            LogEntry::Gap(LogGap {
                lost_stdout: 1,
                lost_stderr: 2,
                unreadable: 0,
            })
        );
        assert_eq!(entry.text_bytes(), 0);
        assert_eq!(entry.seq(), None);
        let rec = LogEntry::Record(log_record(7, "abc"));
        assert_eq!(rec.text_bytes(), 3);
        assert_eq!(rec.seq(), Some(7));
    }

    fn log_record(seq: u64, text: &str) -> LogRecord {
        LogRecord {
            seq,
            stream: LogStream::Stdout,
            ts: Timestamp::UNIX_EPOCH,
            text: text.to_owned(),
        }
    }

    #[test]
    fn a_log_batch_must_have_strictly_increasing_seq() {
        let ok = LogBatch {
            records: vec![log_record(1, "a"), log_record(2, "b"), log_record(9, "c")],
            ..LogBatch::default()
        };
        assert!(ok.validate().is_ok());
        assert_eq!(ok.text_bytes(), 3);
        for seqs in [[1, 1], [2, 1]] {
            let bad = LogBatch {
                records: seqs.iter().map(|s| log_record(*s, "x")).collect(),
                ..LogBatch::default()
            };
            assert!(bad.validate().is_err(), "{seqs:?}");
        }
        assert!(
            LogBatch::default().validate().is_ok(),
            "an empty batch is valid"
        );
    }

    #[test]
    fn a_log_record_over_the_limit_is_refused() {
        let big = "x".repeat(MAX_LOG_RECORD_BYTES + 1);
        let bad = LogBatch {
            records: vec![log_record(1, &big)],
            ..LogBatch::default()
        };
        assert!(bad.validate().unwrap_err().contains("over the"));
        let edge = "x".repeat(MAX_LOG_RECORD_BYTES);
        let ok = LogBatch {
            records: vec![log_record(1, &edge)],
            ..LogBatch::default()
        };
        assert!(ok.validate().is_ok(), "exactly the limit is allowed");
    }

    #[test]
    fn the_log_wire_shape_is_lowercase_streams_and_snake_case_reasons() {
        let b: LogBatch = serde_json::from_value(serde_json::json!({
            "records": [{ "seq": 1, "stream": "stderr", "ts": "2026-11-17T00:00:00Z", "text": "boom" }]
        }))
        .unwrap();
        assert_eq!(b.records[0].stream, LogStream::Stderr);
        assert_eq!(
            (b.dropped_stdout, b.dropped_stderr),
            (0, 0),
            "dropped counts default to 0"
        );
        assert_eq!(
            serde_json::to_value(LogEnd::ClaimEnded).unwrap(),
            serde_json::json!("claim_ended")
        );
        assert_eq!(
            serde_json::to_value(LogEnd::Ttl).unwrap(),
            serde_json::json!("ttl")
        );
    }

    #[test]
    fn an_endpoint_is_host_and_port_with_ipv6_in_brackets() {
        let e: Endpoint = "grafana.home.example:443".parse().unwrap();
        assert_eq!((e.host.as_str(), e.port), ("grafana.home.example", 443));
        assert_eq!(e.to_string(), "grafana.home.example:443");
        let e: Endpoint = "[2001:db8::1]:8443".parse().unwrap();
        assert_eq!((e.host.as_str(), e.port), ("2001:db8::1", 8443));
        assert_eq!(e.to_string(), "[2001:db8::1]:8443");
        let e: Endpoint = "192.0.2.10:80".parse().unwrap();
        assert_eq!((e.host.as_str(), e.port), ("192.0.2.10", 80));
    }

    #[test]
    fn a_malformed_endpoint_is_refused() {
        for bad in [
            "grafana.home.example",
            ":443",
            "grafana.home.example:0",
            "grafana.home.example:65536",
            "grafana.home.example:https",
            "2001:db8::1:443",
            "[2001:db8::1]:",
        ] {
            assert!(bad.parse::<Endpoint>().is_err(), "{bad} parsed");
        }
    }

    #[test]
    fn me_without_egress_deserialises_as_an_empty_list() {
        let me: Me = serde_json::from_value(serde_json::json!({
            "claim_uid": "00000000-0000-0000-0000-000000000001",
            "subject": { "issuer": "https://dex.home.example", "id": "octocat" },
            "expires_at": "2026-01-01T00:00:00Z",
            "workload": { "image": "registry.internal:5000/sandbox:latest" }
        }))
        .unwrap();
        assert_eq!(me.egress, Vec::<Endpoint>::new());
        assert_eq!(me.routes, Vec::<Route>::new(), "an old broker: no routes");
        assert_eq!(
            me.gateways,
            Vec::<Endpoint>::new(),
            "an old broker: no gateway"
        );
    }

    #[test]
    fn a_claims_egress_round_trips_and_an_old_broker_names_none() {
        let full = ClaimEgress {
            claim_uid: Uuid::nil(),
            expires_at: "2026-01-01T00:00:00Z".parse().unwrap(),
            egress: vec!["api.home.example:443".parse().unwrap()],
            inject: Vec::new(),
        };
        let json = serde_json::to_value(&full).unwrap();
        assert_eq!(json["egress"][0]["host"], "api.home.example");
        assert_eq!(serde_json::from_value::<ClaimEgress>(json).unwrap(), full);
        let bare: ClaimEgress = serde_json::from_value(serde_json::json!({
            "claim_uid": "00000000-0000-0000-0000-000000000001",
            "expires_at": "2026-01-01T00:00:00Z"
        }))
        .unwrap();
        assert_eq!(bare.egress, Vec::<Endpoint>::new());
    }

    #[test]
    fn a_rule_matches_its_method_and_a_segment_glob() {
        let rule = |m: &str, p: &str| EndpointRule {
            method: m.into(),
            path: p.into(),
        };
        // Exact path, exact method, case-insensitive on the method.
        assert!(rule("GET", "/v1/chat/completions").matches("get", "/v1/chat/completions"));
        assert!(!rule("GET", "/v1/chat/completions").matches("POST", "/v1/chat/completions"));
        assert!(!rule("GET", "/v1/chat/completions").matches("GET", "/v1/chat"));
        assert!(!rule("GET", "/v1/chat/completions").matches("GET", "/v1/chat/completions/x"));
        // `*` is one segment.
        assert!(rule("*", "/repos/*/issues").matches("DELETE", "/repos/octo/issues"));
        assert!(!rule("*", "/repos/*/issues").matches("GET", "/repos/issues"));
        assert!(!rule("*", "/repos/*/issues").matches("GET", "/repos/a/b/issues"));
        // `**` is zero or more.
        assert!(rule("GET", "/api/**").matches("GET", "/api"));
        assert!(rule("GET", "/api/**").matches("GET", "/api/v4/projects/7"));
        assert!(!rule("GET", "/api/**").matches("GET", "/apix"));
        assert!(
            rule("POST", "/api/v4/projects/*/merge_requests/*/notes")
                .matches("POST", "/api/v4/projects/7/merge_requests/12/notes")
        );
        assert!(rule("GET", "/**/notes").matches("GET", "/a/b/c/notes"));
        // Empty segments and trailing slashes do not count.
        assert!(rule("GET", "/a/b").matches("GET", "/a//b/"));
    }

    #[test]
    fn a_route_without_rules_admits_everything_and_one_with_rules_only_what_they_say() {
        let open = Route {
            audience: Some("internal-git".into()),
            endpoint: "git.home.example:443".parse().unwrap(),
            rules: vec![],
            ca_pem: None,
            credential: Credential::Token,
            credential_header: None,
            inject_port: None,
        };
        assert!(open.admits("DELETE", "/anything/at/all"));
        let narrow = Route {
            rules: vec![
                EndpointRule {
                    method: "GET".into(),
                    path: "/platform/**".into(),
                },
                EndpointRule {
                    method: "POST".into(),
                    path: "/platform/*/git-receive-pack".into(),
                },
            ],
            ..open
        };
        assert!(narrow.admits("GET", "/platform/services.git/info/refs"));
        assert!(narrow.admits("POST", "/platform/services.git/git-receive-pack"));
        assert!(!narrow.admits("POST", "/platform/services.git/info/refs"));
        assert!(!narrow.admits("GET", "/other/services.git/info/refs"));
    }

    #[test]
    fn routes_roundtrip_with_rules_defaulting_to_none() {
        let r: Route = serde_json::from_value(serde_json::json!({
            "audience": "internal-git",
            "endpoint": { "host": "git.home.example", "port": 443 }
        }))
        .unwrap();
        assert_eq!(r.rules, Vec::<EndpointRule>::new());
        assert_eq!(r.ca_pem, None, "no ca_pem: the Mozilla roots");
        assert_eq!(
            r.credential,
            Credential::Token,
            "a route written before the field: the audience's token"
        );
        assert!(r.injects());
        assert_eq!(r.audience_label(), "internal-git");
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["rules"], serde_json::json!([]));
        assert!(json.get("ca_pem").is_none(), "absent, not null: {json}");
        assert_eq!(json["credential"], "token");
        let with_ca = Route {
            ca_pem: Some("-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n".into()),
            ..r
        };
        let json = serde_json::to_value(&with_ca).unwrap();
        assert!(
            json["ca_pem"]
                .as_str()
                .unwrap()
                .starts_with("-----BEGIN CERTIFICATE-----")
        );
    }

    #[test]
    fn a_route_without_a_credential_needs_no_audience_and_says_so_on_the_wire() {
        // A bundle's direct egress (ADR-0025 decision 8): no audience, nothing injected.
        let r: Route = serde_json::from_value(serde_json::json!({
            "endpoint": { "host": "repo.home.example", "port": 443 },
            "credential": "none"
        }))
        .unwrap();
        assert_eq!(r.audience, None);
        assert!(!r.injects());
        assert_eq!(r.audience_label(), "-");
        let json = serde_json::to_value(&r).unwrap();
        assert!(json.get("audience").is_none(), "absent, not null: {json}");
        assert_eq!(json["credential"], "none");
        // An audience reached without a token keeps its name (its rules and CA apply).
        let named: Route = serde_json::from_value(serde_json::json!({
            "audience": "api.example.com",
            "endpoint": { "host": "api.example.com", "port": 443 },
            "credential": "none"
        }))
        .unwrap();
        assert_eq!(named.audience.as_deref(), Some("api.example.com"));
        assert!(!named.injects());
        assert_eq!(
            named.credential_header, None,
            "no header named: Authorization, as every route before ADR-0032"
        );
    }

    #[test]
    fn a_token_response_without_a_header_is_a_bearer_and_one_with_names_where_it_goes() {
        let bearer: TokenResponse = serde_json::from_value(serde_json::json!({
            "access_token": "t", "token_type": "Bearer", "expires_at": "2026-01-01T00:00:00Z",
            "audience": "a", "subject": { "issuer": "https://idp.example", "id": "octocat" }
        }))
        .unwrap();
        assert_eq!(bearer.header, None);
        assert_eq!(bearer.extra_headers.len(), 0);
        let json = serde_json::to_value(&bearer).unwrap();
        assert!(
            json.get("header").is_none() && json.get("extra_headers").is_none(),
            "{json}"
        );
        let keyed = TokenResponse {
            header: Some("x-api-key".into()),
            token_type: "Header".into(),
            extra_headers: vec![HeaderPair {
                name: "anthropic-beta".into(),
                value: "oauth-2025-04-20".into(),
            }],
            ..bearer
        };
        let json = serde_json::to_value(&keyed).unwrap();
        assert_eq!(json["header"], "x-api-key");
        assert_eq!(json["extra_headers"][0]["name"], "anthropic-beta");
    }

    #[test]
    fn username_is_deterministic_and_valid() {
        let s = Subject {
            issuer: "https://dex.home.example".into(),
            id: "octocat".into(),
            display: None,
        };
        let a = s.sandbox_username();
        let b = s.sandbox_username();
        assert_eq!(a, b);
        assert_eq!(a.len(), 3 + USERNAME_HASH_LEN);
        assert!(a.starts_with("sb-"));
        assert!(a[3..].chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn username_changes_with_issuer() {
        let mk = |iss: &str| Subject {
            issuer: iss.into(),
            id: "octocat".into(),
            display: None,
        };
        assert_ne!(
            mk("https://a").sandbox_username(),
            mk("https://b").sandbox_username()
        );
    }

    #[test]
    fn claim_request_roundtrips() {
        let req = ClaimRequest {
            pool_ref: Some("pool-a".into()),
            pool_selector: None,
            selection: None,
            ttl_seconds: 3600,
            audiences: vec!["grafana.home.example".into()],
            workload: Workload {
                image: "registry/sandbox:latest".into(),
                args: vec![],
                restart: RestartPolicy::Always,
                logs: false,
            },
            refresh_token: None,
            policy_ref: None,
            delegations: vec![],
            namespace: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: ClaimRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.pool_ref.as_deref(), Some("pool-a"));
        assert_eq!(back.pool(), Ok(PoolChoice::Named("pool-a")));
    }

    // ----- ADR-0044: a sandbox selects its pool by label, or names it ----------------------------------------------

    fn request_with(pool_ref: Option<&str>, pool_selector: Option<PoolSelector>) -> ClaimRequest {
        ClaimRequest {
            pool_ref: pool_ref.map(str::to_owned),
            pool_selector,
            selection: None,
            ttl_seconds: 3600,
            audiences: vec![],
            workload: Workload {
                image: "registry/sandbox:latest".into(),
                args: vec![],
                restart: RestartPolicy::Always,
                logs: false,
            },
            refresh_token: None,
            policy_ref: None,
            delegations: vec![],
            namespace: None,
        }
    }

    /// The body every client has sent so far, `{"pool_ref": "pool-a", ...}`, still parses
    /// and still names that pool (ADR-0044: wire compatible).
    #[test]
    fn a_request_naming_a_pool_as_before_still_parses() {
        let req: ClaimRequest = serde_json::from_str(
            r#"{"pool_ref":"pool-a","ttl_seconds":60,"workload":{"image":"r/i:1","args":[]}}"#,
        )
        .unwrap();
        assert_eq!(req.pool(), Ok(PoolChoice::Named("pool-a")));
    }

    /// `pool_selector: {}` is "any pool in the namespace" and survives a round trip as an
    /// empty selector, never as an absent one: the two mean opposite things (banlieue
    /// ADR-0132 decision 2).
    #[test]
    fn an_empty_selector_is_any_pool_and_is_kept_on_the_wire() {
        let req = request_with(None, Some(PoolSelector::default()));
        let json = serde_json::to_value(&req).unwrap();
        assert_eq!(json["pool_selector"], serde_json::json!({}), "got {json}");
        assert!(json.get("pool_ref").is_none(), "got {json}");
        let back: ClaimRequest = serde_json::from_value(json).unwrap();
        assert_eq!(
            back.pool(),
            Ok(PoolChoice::Selected(&PoolSelector::default()))
        );
    }

    #[test]
    fn a_selector_with_labels_and_expressions_round_trips_in_kubernetes_spelling() {
        let sel = PoolSelector {
            match_labels: BTreeMap::from([(
                "sandbox.example.com/image".to_owned(),
                "agent".to_owned(),
            )]),
            match_expressions: vec![PoolSelectorRequirement {
                key: "topology.kubernetes.io/zone".into(),
                operator: PoolSelectorOperator::In,
                values: vec!["a".into(), "b".into()],
            }],
        };
        let json = serde_json::to_value(&sel).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "match_labels": { "sandbox.example.com/image": "agent" },
                "match_expressions": [
                    { "key": "topology.kubernetes.io/zone", "operator": "In", "values": ["a", "b"] }
                ]
            })
        );
        let back: PoolSelector = serde_json::from_value(json).unwrap();
        assert_eq!(back, sel);
    }

    /// Neither is refused, never read as "any pool"; both is refused; an empty name names
    /// nothing (ADR-0044 decision 2, fail closed).
    #[test]
    fn a_request_takes_exactly_one_of_pool_ref_or_pool_selector() {
        assert_eq!(
            request_with(None, None).pool(),
            Err(PoolChoiceError::Neither)
        );
        assert_eq!(
            request_with(Some("pool-a"), Some(PoolSelector::default())).pool(),
            Err(PoolChoiceError::Both)
        );
        assert_eq!(
            request_with(Some(""), None).pool(),
            Err(PoolChoiceError::EmptyName)
        );
        let req: ClaimRequest =
            serde_json::from_str(r#"{"ttl_seconds":60,"workload":{"image":"r/i:1","args":[]}}"#)
                .unwrap();
        assert_eq!(req.pool(), Err(PoolChoiceError::Neither));
    }

    // ----- ADR-0047: a sandbox chooses its member by strategy ---------------------------------------------------

    /// The field is spelled as banlieue spells it, so a body, a sandbox and a claim read the
    /// same (ADR-0047 decision 3), and it round-trips.
    #[test]
    fn a_strategy_round_trips_in_banlieues_spelling() {
        for (s, name) in [
            (SelectionStrategy::LongestReady, "LongestReady"),
            (SelectionStrategy::MostAvailable, "MostAvailable"),
            (SelectionStrategy::Spread, "Spread"),
        ] {
            let mut req = request_with(Some("pool-a"), None);
            req.selection = Some(Selection { strategy: s });
            let json = serde_json::to_value(&req).unwrap();
            assert_eq!(
                json["selection"],
                serde_json::json!({ "strategy": name }),
                "got {json}"
            );
            let back: ClaimRequest = serde_json::from_value(json).unwrap();
            assert_eq!(back.selection, Some(Selection { strategy: s }));
            assert_eq!(s.to_string(), name);
        }
    }

    /// Absent stays absent (ADR-0047 decision 2): never serialised, never defaulted here;
    /// `selection: {}` is the default strategy written down, as on the claim.
    #[test]
    fn an_absent_selection_is_not_sent_and_parses_back_absent() {
        let req = request_with(Some("pool-a"), None);
        assert_eq!(req.selection, None);
        let json = serde_json::to_value(&req).unwrap();
        assert!(json.get("selection").is_none(), "got {json}");
        let back: ClaimRequest = serde_json::from_str(
            r#"{"pool_ref":"pool-a","ttl_seconds":60,"workload":{"image":"r/i:1","args":[]}}"#,
        )
        .unwrap();
        assert_eq!(back.selection, None);
        let empty: ClaimRequest = serde_json::from_str(
            r#"{"pool_ref":"pool-a","ttl_seconds":60,"workload":{"image":"r/i:1","args":[]},"selection":{}}"#,
        )
        .unwrap();
        assert_eq!(empty.selection, Some(Selection::default()));
        assert_eq!(
            Selection::default().strategy,
            SelectionStrategy::LongestReady
        );
    }

    /// A strategy the broker does not know is a parse error, never a default (ADR-0047
    /// decision 3).
    #[test]
    fn an_unknown_strategy_does_not_parse() {
        let err = serde_json::from_str::<ClaimRequest>(
            r#"{"pool_ref":"pool-a","ttl_seconds":60,"workload":{"image":"r/i:1","args":[]},"selection":{"strategy":"Pack"}}"#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("Pack"), "{err}");
    }

    // ----- ADR-0040: the gateway places an audience's credential -----------------------------------------------------

    fn rule(method: &str, path: &str) -> EndpointRule {
        EndpointRule {
            method: method.into(),
            path: path.into(),
        }
    }

    fn inject_route(rules: Vec<EndpointRule>) -> InjectRoute {
        InjectRoute {
            audience: "anthropic".into(),
            endpoint: "api.anthropic.example:443".parse().unwrap(),
            rules,
            header: "x-api-key".into(),
            extra_headers: vec![HeaderPair {
                name: "anthropic-version".into(),
                value: "2023-06-01".into(),
            }],
        }
    }

    fn token_response(header: Option<&str>, expires_at: &str) -> TokenResponse {
        TokenResponse {
            access_token: "sk-ant-not-a-real-credential".into(),
            token_type: if header.is_some() { "Header" } else { "Bearer" }.into(),
            expires_at: expires_at.parse().unwrap(),
            audience: "anthropic".into(),
            subject: Subject {
                issuer: "https://idp.example".into(),
                id: "octocat".into(),
                display: None,
            },
            header: header.map(ToOwned::to_owned),
            extra_headers: vec![HeaderPair {
                name: "anthropic-version".into(),
                value: "2023-06-01".into(),
            }],
        }
    }

    #[test]
    fn a_gateway_route_says_gateway_on_the_wire_carries_the_inject_port_and_the_proxy_never_swaps_there()
     {
        let route = Route {
            audience: Some("anthropic".into()),
            endpoint: "api.anthropic.example:443".parse().unwrap(),
            rules: vec![rule("POST", "/v1/messages")],
            ca_pem: None,
            credential: Credential::Gateway,
            credential_header: Some("x-api-key".into()),
            inject_port: Some(3133),
        };
        let json = serde_json::to_value(&route).unwrap();
        assert_eq!(json["credential"], "gateway");
        assert_eq!(json["inject_port"], 3133);
        assert_eq!(serde_json::from_value::<Route>(json).unwrap(), route);
        assert!(route.placed_at_gateway());
        assert!(
            !route.injects(),
            "the proxy never swaps the phantom for a token on a gateway route"
        );
    }

    #[test]
    fn a_route_written_before_the_inject_port_still_parses_and_a_route_without_one_does_not_print_it()
     {
        let old: Route = serde_json::from_value(serde_json::json!({
            "endpoint": { "host": "api.example.com", "port": 443 },
            "credential": "token"
        }))
        .unwrap();
        assert_eq!(old.inject_port, None);
        assert!(!old.placed_at_gateway());
        let json = serde_json::to_value(&old).unwrap();
        assert!(
            json.get("inject_port").is_none(),
            "an old guest reads exactly the JSON it always did: {json}"
        );
    }

    #[test]
    fn a_claims_egress_carries_its_inject_routes_and_an_answer_without_them_still_parses() {
        let with = ClaimEgress {
            claim_uid: Uuid::nil(),
            expires_at: "2026-01-01T00:00:00Z".parse().unwrap(),
            egress: vec!["api.anthropic.example:443".parse().unwrap()],
            inject: vec![inject_route(vec![rule("POST", "/v1/messages")])],
        };
        let json = serde_json::to_value(&with).unwrap();
        assert_eq!(json["inject"][0]["audience"], "anthropic");
        assert_eq!(json["inject"][0]["header"], "x-api-key");
        assert_eq!(serde_json::from_value::<ClaimEgress>(json).unwrap(), with);
        let none = ClaimEgress {
            inject: Vec::new(),
            ..with
        };
        assert!(
            serde_json::to_value(&none).unwrap().get("inject").is_none(),
            "a claim with no gateway-placed audience answers byte for byte as before"
        );
        let old: ClaimEgress = serde_json::from_value(serde_json::json!({
            "claim_uid": "00000000-0000-0000-0000-000000000001",
            "expires_at": "2026-01-01T00:00:00Z",
            "egress": []
        }))
        .unwrap();
        assert_eq!(old.inject, Vec::<InjectRoute>::new());
    }

    #[test]
    fn an_inject_route_admits_only_what_a_rule_names_and_never_by_default() {
        let none = inject_route(Vec::new());
        assert!(
            !none.admits("GET", "/"),
            "a placed credential does not get the proxy's empty-rules-admit-all default (ADR-0040 decision 1)"
        );
        let r = inject_route(vec![
            rule("POST", "/v1/messages"),
            rule("GET", "/v1/models/*"),
        ]);
        assert!(r.admits("post", "/v1/messages"));
        assert!(r.admits("GET", "/v1/models/claude"));
        assert!(!r.admits("GET", "/v1/messages"));
        assert!(!r.admits("POST", "/v1/messages/batches"));
    }

    #[test]
    fn an_inject_route_matches_its_authority_exactly_and_a_missing_port_is_443() {
        let r = inject_route(Vec::new());
        assert!(r.matches_authority("api.anthropic.example", None));
        assert!(r.matches_authority("api.anthropic.example", Some(443)));
        assert!(
            r.matches_authority("API.Anthropic.Example", None),
            "host names compare case-insensitively"
        );
        assert!(!r.matches_authority("api.anthropic.example", Some(8443)));
        assert!(!r.matches_authority("api.anthropic.example.evil.example", None));
        assert!(!r.matches_authority("xapi.anthropic.example", None));
        assert!(!r.matches_authority("other.example", None));
    }

    #[test]
    fn the_headers_a_client_may_not_send_on_a_gateway_route_are_the_standard_pair_and_the_routes_own()
     {
        let mut r = inject_route(Vec::new());
        assert_eq!(
            r.client_headers_to_strip(),
            vec!["authorization", "x-api-key"]
        );
        r.header = "authorization".into();
        assert_eq!(
            r.client_headers_to_strip(),
            vec!["authorization", "x-api-key"]
        );
        r.header = "x-custom-key".into();
        assert_eq!(
            r.client_headers_to_strip(),
            vec!["authorization", "x-api-key", "x-custom-key"]
        );
        assert!(
            !r.client_headers_to_strip()
                .contains(&"anthropic-version".to_owned()),
            "the public extra headers are the authorizer's to add, not to strip"
        );
    }

    #[test]
    fn a_gateway_credential_never_prints_its_value_and_round_trips() {
        let c = GatewayCredential::from_token_response(
            token_response(Some("x-api-key"), "2026-01-01T00:04:00Z"),
            "2026-01-01T00:00:00Z".parse().unwrap(),
        );
        let debug = format!("{c:?}");
        assert!(
            !debug.contains("sk-ant"),
            "Debug leaked the credential: {debug}"
        );
        assert!(debug.contains("[redacted]"), "{debug}");
        let json = serde_json::to_value(&c).unwrap();
        assert_eq!(
            json["value"], "sk-ant-not-a-real-credential",
            "on the wire it is the plain string"
        );
        assert_eq!(json["header"], "x-api-key");
        assert_eq!(
            serde_json::from_value::<GatewayCredential>(json).unwrap(),
            c
        );
    }

    #[test]
    fn a_gateway_credential_is_a_bearer_unless_the_token_names_a_header() {
        let now: Timestamp = "2026-01-01T00:00:00Z".parse().unwrap();
        let bearer = GatewayCredential::from_token_response(
            token_response(None, "2026-01-01T00:04:00Z"),
            now,
        );
        assert_eq!(bearer.header, "authorization");
        assert_eq!(
            bearer.value,
            Secret("Bearer sk-ant-not-a-real-credential".into())
        );
        let bare = GatewayCredential::from_token_response(
            token_response(Some("x-api-key"), "2026-01-01T00:04:00Z"),
            now,
        );
        assert_eq!(bare.header, "x-api-key");
        assert_eq!(bare.value, Secret("sk-ant-not-a-real-credential".into()));
        assert_eq!(bare.extra_headers.len(), 1);
        assert_eq!(bare.audience, "anthropic");
        assert_eq!(bare.subject.id, "octocat");
    }

    #[test]
    fn a_gateway_credential_never_outlives_the_cap_and_is_never_extended() {
        assert_eq!(GATEWAY_CREDENTIAL_MAX_TTL_SECS, 300);
        let now: Timestamp = "2026-01-01T00:00:00Z".parse().unwrap();
        let long = GatewayCredential::from_token_response(
            token_response(None, "2026-01-01T00:15:00Z"),
            now,
        );
        assert_eq!(
            long.expires_at,
            "2026-01-01T00:05:00Z".parse::<Timestamp>().unwrap()
        );
        let short = GatewayCredential::from_token_response(
            token_response(None, "2026-01-01T00:01:40Z"),
            now,
        );
        assert_eq!(
            short.expires_at,
            "2026-01-01T00:01:40Z".parse::<Timestamp>().unwrap()
        );
        let past = GatewayCredential::from_token_response(
            token_response(None, "2025-12-31T23:59:50Z"),
            now,
        );
        assert_eq!(
            past.expires_at,
            "2025-12-31T23:59:50Z".parse::<Timestamp>().unwrap()
        );
    }

    #[test]
    fn the_gateway_placement_error_codes_are_stable_strings() {
        assert_eq!(error_code::PLACED_AT_GATEWAY, "placed_at_gateway");
        assert_eq!(error_code::NOT_PLACED_AT_GATEWAY, "not_placed_at_gateway");
        let req: GatewayCredentialRequest =
            serde_json::from_value(serde_json::json!({ "audience": "anthropic" })).unwrap();
        assert_eq!(req.audience, "anthropic");
    }

    // ----- ADR-0046: a claim names the namespace it is made in --------------------------------------------------

    #[test]
    fn a_claim_request_without_namespace_serialises_as_before() {
        let v = serde_json::to_value(request_with(Some("pool-a"), None)).unwrap();
        assert!(
            v.get("namespace").is_none(),
            "an existing client's body is unchanged: {v}"
        );
    }

    #[test]
    fn a_claim_request_with_namespace_round_trips() {
        let mut req = request_with(Some("pool-a"), None);
        req.namespace = Some("team-a".into());
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains(r#""namespace":"team-a""#));
        let back: ClaimRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(back.namespace.as_deref(), Some("team-a"));
        let old: ClaimRequest = serde_json::from_str(
            r#"{"pool_ref":"pool-a","ttl_seconds":60,"workload":{"image":"r/i:1","args":[]}}"#,
        )
        .unwrap();
        assert_eq!(old.namespace, None);
    }

    fn response_json(extra: &str) -> String {
        format!(r#"{{"name":"sb-1","phase":"Pending"{extra}}}"#)
    }

    #[test]
    fn a_claim_response_carries_its_namespace() {
        let r: ClaimResponse =
            serde_json::from_str(&response_json(r#","namespace":"team-a""#)).unwrap();
        assert_eq!(r.namespace.as_deref(), Some("team-a"));
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["namespace"], "team-a");
    }

    #[test]
    fn an_old_claim_response_without_namespace_is_detectable() {
        let r: ClaimResponse = serde_json::from_str(&response_json("")).unwrap();
        assert_eq!(
            r.namespace, None,
            "absent is None, not an empty or default namespace"
        );
        assert!(serde_json::to_value(&r).unwrap().get("namespace").is_none());
    }

    #[test]
    fn the_namespace_error_codes_are_stable_strings() {
        assert_eq!(error_code::NAMESPACE_REQUIRED, "namespace_required");
        assert_eq!(error_code::INVALID_NAMESPACE, "invalid_namespace");
    }

    #[test]
    fn is_dns_label_is_an_rfc_1123_label() {
        for ok in ["a", "team-a", "a1", &"a".repeat(63)] {
            assert!(is_dns_label(ok), "{ok}");
        }
        for bad in ["", "-a", "a-", "Team", "a.b", "a_b", "a b", &"a".repeat(64)] {
            assert!(!is_dns_label(bad), "{bad}");
        }
    }

    // ----- Red-team review 2026-11-19: canonical paths and bounded globs -------------------------------------------

    #[test]
    fn an_ordinary_path_is_canonical() {
        for path in [
            "/",
            "/v1/messages",
            "/v1/messages/",
            "/platform/services.git/info/refs",
            "/a%20b/c%2Bd",
            "/a%7Eb",
            "/caf\u{e9}/\u{65e5}\u{672c}",
            "/a.b/..c/c../.../.hidden",
            "/a~b/c;d=e/f:g/@h/i,j",
        ] {
            assert!(path_is_canonical(path), "{path:?} is refused");
        }
    }

    #[test]
    fn a_dot_segment_is_not_canonical() {
        for path in [
            "/..", "/.", "/a/..", "/a/../b", "/a/./b", "/a/b/.", "/../a", "/a/../",
        ] {
            assert!(!path_is_canonical(path), "{path:?} is admitted");
        }
    }

    #[test]
    fn an_encoded_dot_slash_or_backslash_is_not_canonical_in_either_case() {
        for path in [
            "/a/%2e%2e/b",
            "/a/%2E%2E/b",
            "/a/.%2e/b",
            "/a/%2e/b",
            "/a/b%2ejson",
            "/a%2fb",
            "/a%2Fb",
            "/a/..%2fb",
            "/a%5cb",
            "/a%5Cb",
            "/a/..%5c..%5cb",
        ] {
            assert!(!path_is_canonical(path), "{path:?} is admitted");
        }
    }

    #[test]
    fn a_backslash_an_empty_segment_or_a_relative_path_is_not_canonical() {
        for path in [
            "/a\\b",
            "/a\\..\\b",
            "\\a",
            "//",
            "//a",
            "/a//b",
            "/a//",
            "",
            "a/b",
            "*",
        ] {
            assert!(!path_is_canonical(path), "{path:?} is admitted");
        }
    }

    #[test]
    fn a_malformed_escape_is_not_canonical() {
        for path in [
            "/a%",
            "/a%2",
            "/a%zz",
            "/a%2g/b",
            "/%",
            "/a%+1",
            "/a%\u{e9}9",
        ] {
            assert!(!path_is_canonical(path), "{path:?} is admitted");
        }
    }

    #[test]
    fn a_control_character_raw_or_encoded_is_not_canonical() {
        for path in [
            "/a\0b",
            "/a\nb",
            "/a\rb",
            "/a\tb",
            "/a\u{7f}b",
            "/a\u{85}b",
            "/a%00b",
            "/a%0ab",
            "/a%0D%0Ab",
            "/a%7fb",
        ] {
            assert!(!path_is_canonical(path), "{path:?} is admitted");
        }
    }

    #[test]
    fn a_rule_with_more_than_one_double_star_is_refused_at_validation() {
        for path in [
            "/",
            "/v1/messages",
            "/api/**",
            "/**/notes",
            "/a/*/b/*/c",
            "/**",
        ] {
            assert_eq!(rule("GET", path).validate(), Ok(()), "{path:?}");
        }
        for path in ["/**/**", "/a/**/b/**", "/**/a/**/b/**"] {
            let err = rule("GET", path).validate().unwrap_err();
            assert!(err.contains("`**`"), "{path:?}: {err}");
        }
        // `**` inside a segment is a literal, not a wildcard, so it does not count.
        assert_eq!(rule("GET", "/a**/b**").validate(), Ok(()));
        let long = "/a".repeat(MAX_PATH_SEGMENTS + 1);
        assert!(rule("GET", &long).validate().is_err());
        assert_eq!(
            rule("GET", &"/a".repeat(MAX_PATH_SEGMENTS)).validate(),
            Ok(())
        );
    }

    #[test]
    fn a_path_of_more_segments_than_the_cap_matches_no_rule() {
        let at_cap = "/a".repeat(MAX_PATH_SEGMENTS);
        let over = "/a".repeat(MAX_PATH_SEGMENTS + 1);
        for pattern in ["/**", "/a/**", "/**/a"] {
            assert!(rule("GET", pattern).matches("GET", &at_cap), "{pattern:?}");
            assert!(!rule("GET", pattern).matches("GET", &over), "{pattern:?}");
        }
        assert!(
            !inject_route(vec![rule("*", "/**")]).admits("GET", &over),
            "a route admits nothing its rules do not"
        );
    }

    #[test]
    fn a_glob_with_several_double_stars_still_means_what_it_says_and_does_not_backtrack() {
        // The matcher is linear in each of the pattern and the path, so a rule that slipped
        // past validation costs a request nothing more.
        assert!(rule("GET", "/**/a/**/b").matches("GET", "/x/a/y/z/b"));
        assert!(rule("GET", "/**/a/**/b").matches("GET", "/a/b"));
        assert!(!rule("GET", "/**/a/**/b").matches("GET", "/b/a"));
        assert!(rule("GET", "/**/**").matches("GET", "/"));
        assert!(rule("GET", "/*/**/*").matches("GET", "/a/b"));
        assert!(!rule("GET", "/*/**/*").matches("GET", "/a"));
        let hostile = "/**/x".repeat(16);
        let path = "/a".repeat(MAX_PATH_SEGMENTS);
        assert!(!rule("GET", &hostile).matches("GET", &path));
    }

    #[test]
    fn a_timestamp_written_by_an_earlier_broker_still_parses() {
        // Earlier brokers wrote `expires_at` as RFC 3339 with the fraction trimmed to three, six
        // or nine digits and a `Z`, or with a `+00:00` offset in the Kubernetes store: a guest or
        // CLI reading them during a rolling upgrade gets the same instant either way.
        let at = |s: &str| {
            serde_json::from_value::<Timestamp>(serde_json::Value::String(s.into())).unwrap()
        };
        let whole = at("2026-11-15T16:46:49Z");
        assert_eq!(
            whole,
            "2026-11-15T16:46:49+00:00".parse::<Timestamp>().unwrap()
        );
        assert_eq!(
            at("2026-11-15T16:46:49.500Z"),
            at("2026-11-15T16:46:49.5+00:00")
        );
        assert!(at("2026-11-15T16:46:49.123456789Z") > at("2026-11-15T16:46:49.123456Z"));
        assert!(
            serde_json::from_value::<Timestamp>(serde_json::Value::String(
                "2026-11-15T16:46:49".into()
            ))
            .is_err(),
            "a timestamp with no offset is refused"
        );
    }
}
