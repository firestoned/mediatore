// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Persistence boundary for mediatore (ADR-0012, the store's shape; ADR-0034, where it
//! lives).
//!
//! The server only ever talks to [`ClaimStore`]. The shipped implementation is `KubeStore`
//! in `mediatore-claims` (the Kubernetes API: the record on the `AgentSandbox`, the
//! session in a Secret, the nodes and floors as resources); `MemoryStore` is for `dev_mode`
//! and tests, and the conformance suite pins the behaviour both must share. Refresh material enters the store only as a [`seal::Sealed`] envelope.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::Arc;

use async_trait::async_trait;
use jiff::Timestamp;
use mediatore_proto::{
    ClaimReport, LogBatch, LogEntry, LogGap, Provider, Subject, Workload, WorkloadExit,
};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

#[cfg(test)]
mod conformance;
pub mod seal;

pub use seal::Sealed;

/// Errors from any store implementation.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// No record with that key.
    #[error("not found: {0}")]
    NotFound(String),
    /// A record with that key already exists and the write was not an update.
    #[error("conflict: {0}")]
    Conflict(String),
    /// Backend failure.
    #[error("backend: {0}")]
    Backend(String),
}

/// What a record written before ADR-0046 reads as: the single namespace the broker had
/// configured then. The API layer maps it to that namespace (ADR-0046 decision 9); the store
/// only gives it a fixed, documented value.
pub const FALLBACK_NAMESPACE: &str = "sandboxes";

/// The serde default of [`ClaimRecord::namespace`].
#[must_use]
pub fn fallback_namespace() -> String {
    FALLBACK_NAMESPACE.to_owned()
}

/// One claim mediatore has brokered. The request fields are a copy of the `AgentSandbox`
/// spec (ADR-0008); the resource is their source of truth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimRecord {
    /// Kubernetes UID of the `VirtualMachineClaim`.
    pub uid: Uuid,
    /// Kubernetes object name.
    pub name: String,
    /// The namespace the claim lives in (ADR-0046 decision 9). A record written before the
    /// ADR has none and reads as [`FALLBACK_NAMESPACE`].
    #[serde(default = "fallback_namespace")]
    pub namespace: String,
    /// Who the claim is for.
    pub subject: Subject,
    /// SPIRE registration entry id, once created.
    pub entry_id: Option<String>,
    /// SPIRE node SPIFFE ID of the bound VM, once known.
    pub node_id: Option<String>,
    /// Audiences the sandbox may request.
    pub audiences: Vec<String>,
    /// What the sandbox runs once identity is established.
    #[serde(default)]
    pub workload: Workload,
    /// Requested lifetime; the deadline counts from bind.
    pub ttl_seconds: u32,
    /// Refresh material for the token backend, sealed (ADR-0012 decision 3). Never
    /// plaintext: the type has no constructor that takes any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh: Option<Sealed>,
    /// When mediatore created the claim.
    pub created_at: Timestamp,
    /// Bind deadline, once bound.
    pub expires_at: Option<Timestamp>,
    /// Set on release or revocation; a revoked claim never issues again.
    pub revoked_at: Option<Timestamp>,
    /// The `AgentSandbox` the record came from (ADR-0013): the associated data that opens
    /// `refresh`. `None` for a record the dev binder wrote, which seals with its own UID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_uid: Option<Uuid>,
    /// The notaio policy the sandbox named (ADR-0026 decision 6): the `SandboxPolicy`'s `uid`,
    /// its incarnation, as the verified bundle in the cache spelled it when the claim was
    /// created. `None` for a sandbox naming no policy, or one with no verified bundle then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_uid: Option<String>,
    /// The version of that bundle. Set with `policy_uid`, never alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bundle_version: Option<u64>,
    /// What the guest pulled and loaded before it started the workload, once it reported
    /// (ADR-0029 decision 5): the image digest, the two tables' hashes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<ClaimReport>,
    /// How the workload ended, when its restart policy ended the claim (ADR-0033
    /// decision 2); `None` for a claim that ran to its deadline or was released by hand.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit: Option<WorkloadExit>,
    /// The caller's delegated credentials, by audience (ADR-0035): sealed envelopes with the
    /// sandbox UID as associated data, like `refresh`. Emptied on release and revocation.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub delegations: BTreeMap<String, DelegatedSession>,
}

/// One delegated credential on a record (ADR-0035 decision 3): its envelope, and when the
/// bearer inside dies, which bounds every issue from it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegatedSession {
    /// The `DelegationPlain` of the claim request, sealed.
    pub envelope: Sealed,
    /// When the bearer dies, if the caller said.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
}

impl ClaimRecord {
    /// The UID a sealer binds this record's refresh envelope to.
    #[must_use]
    pub fn seal_binding(&self) -> Uuid {
        self.sandbox_uid.unwrap_or(self.uid)
    }

    /// True when tokens may still be issued for this claim.
    #[must_use]
    pub fn is_live(&self, now: Timestamp) -> bool {
        self.revoked_at.is_none() && self.expires_at.is_none_or(|e| e > now)
    }

    /// When the claim ended: its revocation, or its deadline once that has passed. `None`
    /// while it may still issue, or while it was never bound and never revoked.
    #[must_use]
    pub fn ended_at(&self) -> Option<Timestamp> {
        self.revoked_at.or(self.expires_at)
    }
}

/// One attested VM known to mediatore.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRecord {
    /// EK public-key hash; primary key.
    pub ek_hash: String,
    /// SPIRE node SPIFFE ID.
    pub node_id: String,
    /// Guest DMI UUID, matched against banlieue `providerID`.
    pub dmi_uuid: Uuid,
    /// Informational.
    pub hostname: String,
    /// Informational.
    pub provider: Option<Provider>,
    /// A banned node is never bound again, even if still Ready.
    pub banned: bool,
    /// First registration time.
    pub registered_at: Timestamp,
}

/// A delegated upstream session between the API call that received it and the record
/// it ends up in (ADR-0013 decision 2). Keyed by the `AgentSandbox` UID, which is also the
/// envelope's associated data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRecord {
    /// The sandbox the session was delegated for.
    pub sandbox_uid: Uuid,
    /// Who delegated it.
    pub subject: Subject,
    /// The issuer whose token endpoint refreshes it.
    pub issuer: String,
    /// The refresh token, sealed with `sandbox_uid`.
    pub refresh: Sealed,
    /// When it was delegated; stale sessions are swept.
    pub created_at: Timestamp,
    /// The audience this is for (ADR-0035): `None` is the issuer's session, `Some` a
    /// delegated credential for that audience, one Secret each.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<String>,
    /// When a delegated bearer dies, if the caller said.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
}

/// The version floor of one notaio policy (ADR-0026 decision 5): which incarnation it holds
/// (the policy's `uid`), the highest bundle version accepted for it, and that bundle's
/// `issuedAt`. The rule that moves it is notaio's (`next_floor`); the store keeps it and
/// refuses a write decided from a floor that has moved since.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyFloor {
    /// The policy's namespace.
    pub namespace: String,
    /// The policy's name.
    pub name: String,
    /// The incarnation: the `SandboxPolicy`'s `uid`.
    pub uid: String,
    /// The highest bundle version accepted for that incarnation.
    pub version: u64,
    /// `issuedAt` of the bundle the floor was last moved by, kept to the nanosecond.
    pub issued_at: Timestamp,
}

/// What bounds a claim's stored output (ADR-0045 decision 4): the caller's configuration,
/// passed with every append so the store itself holds no setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogLimits {
    /// The newest record text kept per claim; the oldest records beyond it are dropped and
    /// counted in [`LogChunk::truncated_before`].
    pub max_bytes: usize,
}

/// What an append did (ADR-0045 decision 8: idempotent writes).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LogAppend {
    /// Records stored.
    pub stored: usize,
    /// Records at or below the claim's highest stored `seq`, a retried batch, ignored.
    pub ignored: usize,
}

/// A claim's stored output, or the part of it after a cursor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogChunk {
    /// Bytes of record text the ring dropped from the front since the claim started.
    pub truncated_before: u64,
    /// Records and gaps, in sequence.
    pub entries: Vec<LogEntry>,
    /// The highest `seq` stored for the claim, whatever the cursor; `None` when nothing is.
    pub last_seq: Option<u64>,
}

/// Storage of a workload's output (ADR-0045 decisions 4, 6, 7 and 8): a bounded ring per
/// claim, written by the claim's node through the broker, read by the claim's owner, swept
/// after the claim's retention. [`ClaimStore`] requires it, so the one store object serves
/// both; the broker's `logs.enabled` decides whether anything is ever written.
#[async_trait]
pub trait LogStore: Send + Sync + 'static {
    /// Append a batch to the ring of `rec`'s claim. Records at or below the highest stored
    /// `seq` are ignored (a retried batch is a no-op). When at least one record is new and
    /// the batch carries dropped counts, a [`LogEntry::Gap`] is stored before its records.
    /// The oldest records beyond `limits.max_bytes` are dropped and counted. The batch is
    /// the caller's to validate (`LogBatch::validate`); the store trusts its shape.
    async fn append_logs(
        &self,
        rec: &ClaimRecord,
        batch: &LogBatch,
        limits: &LogLimits,
    ) -> Result<LogAppend, StoreError>;
    /// The claim's stored output: everything, or with `since` the records whose `seq` is
    /// greater, together with the gaps immediately before the first of them. A claim with
    /// nothing stored is an empty chunk, not an error.
    async fn read_logs(&self, claim_uid: Uuid, since: Option<u64>) -> Result<LogChunk, StoreError>;
    /// Remove the claim's output; nothing stored is success.
    async fn delete_logs(&self, claim_uid: Uuid) -> Result<(), StoreError>;
    /// Remove the output of every claim whose record is gone or ended
    /// ([`ClaimRecord::ended_at`]) before `before` (ADR-0045 decision 7). Returns how many
    /// claims' output went.
    async fn sweep_logs(&self, before: Timestamp) -> Result<usize, StoreError>;
}

/// Storage contract.
#[async_trait]
pub trait ClaimStore: LogStore {
    /// Insert a new claim. Fails with `Conflict` if the UID exists.
    async fn put_claim(&self, rec: ClaimRecord) -> Result<(), StoreError>;
    /// Fetch by UID.
    async fn get_claim(&self, uid: Uuid) -> Result<ClaimRecord, StoreError>;
    /// Fetch by namespace and Kubernetes name: a name in one namespace never returns another's
    /// record (ADR-0046 decision 9).
    async fn get_claim_by_name(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<ClaimRecord, StoreError>;
    /// Replace an existing claim record.
    async fn update_claim(&self, rec: ClaimRecord) -> Result<(), StoreError>;
    /// Mark revoked and drop the refresh envelope; idempotent (the first timestamp wins).
    async fn revoke_claim(&self, uid: Uuid, at: Timestamp) -> Result<(), StoreError>;
    /// The live claim bound to a node (by the node's SPIRE agent SPIFFE ID).
    async fn get_claim_by_node(&self, node_id: &str) -> Result<ClaimRecord, StoreError>;
    /// All claims.
    async fn list_claims(&self) -> Result<Vec<ClaimRecord>, StoreError>;

    /// Register a node. Fails with `Conflict` if the EK hash is known with a different DMI UUID.
    async fn put_node(&self, rec: NodeRecord) -> Result<(), StoreError>;
    /// Fetch by EK hash.
    async fn get_node(&self, ek_hash: &str) -> Result<NodeRecord, StoreError>;
    /// Fetch by DMI UUID.
    async fn get_node_by_dmi(&self, dmi_uuid: Uuid) -> Result<NodeRecord, StoreError>;
    /// Ban a node.
    async fn ban_node(&self, ek_hash: &str) -> Result<(), StoreError>;
    /// All registered nodes.
    async fn list_nodes(&self) -> Result<Vec<NodeRecord>, StoreError>;
    /// Remove a node by EK hash (ADR-0039: its VM is gone). A node that is not there is
    /// success, so a retried or racing collection is harmless; no other row is touched.
    async fn delete_node(&self, ek_hash: &str) -> Result<(), StoreError>;

    /// Remove every claim record that ended ([`ClaimRecord::ended_at`]) before `before`,
    /// after the retention window (ADR-0034 decision 4: the audit is the log line the
    /// store writes as it does so). Returns how many.
    async fn sweep(&self, before: Timestamp) -> Result<usize, StoreError>;
    /// Park a delegated session until the reconciler creates the record. `Conflict` if
    /// the sandbox already has one.
    async fn put_session(&self, rec: SessionRecord) -> Result<(), StoreError>;
    /// Remove and return the issuer's session for `sandbox_uid`, if any (one transaction).
    async fn take_session(&self, sandbox_uid: Uuid) -> Result<Option<SessionRecord>, StoreError>;
    /// Remove and return every delegated credential parked for `sandbox_uid` (ADR-0035),
    /// each taken once, in audience order.
    async fn take_delegations(&self, sandbox_uid: Uuid) -> Result<Vec<SessionRecord>, StoreError>;
    /// Remove every session parked for `sandbox_uid`, the issuer's and the delegations;
    /// nothing to remove is fine.
    async fn delete_session(&self, sandbox_uid: Uuid) -> Result<(), StoreError>;
    /// Remove every session delegated before `before`. Returns how many.
    async fn sweep_sessions(&self, before: Timestamp) -> Result<usize, StoreError>;
    /// The floor held for a policy, if one was ever recorded.
    async fn get_policy_floor(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Option<PolicyFloor>, StoreError>;
    /// Move a policy's floor from `held`, what the caller read and decided from (`None` for no
    /// floor yet), to `next`, which names the same policy. Compare and set: `Conflict` when the
    /// stored floor is no longer `held`, because another replica moved it in between; read it
    /// again and decide again. So no two writers can move a floor down.
    async fn advance_policy_floor(
        &self,
        held: Option<&PolicyFloor>,
        next: PolicyFloor,
    ) -> Result<(), StoreError>;

    /// A round trip to the backend; what `/healthz` reports.
    async fn ping(&self) -> Result<(), StoreError>;
}

/// `Conflict` when `next` names another policy than `held`: a caller bug, never written.
fn same_policy(held: Option<&PolicyFloor>, next: &PolicyFloor) -> Result<(), StoreError> {
    match held {
        Some(h)
            if (h.namespace.as_str(), h.name.as_str())
                != (next.namespace.as_str(), next.name.as_str()) =>
        {
            Err(StoreError::Conflict(format!(
                "floor of {}/{} written as {}/{}",
                h.namespace, h.name, next.namespace, next.name
            )))
        }
        _ => Ok(()),
    }
}

/// In-memory store. Not durable; for `dev_mode` and tests.
#[derive(Default)]
pub struct MemoryStore {
    claims: RwLock<HashMap<Uuid, ClaimRecord>>,
    nodes: RwLock<HashMap<String, NodeRecord>>,
    sessions: RwLock<HashMap<(Uuid, Option<String>), SessionRecord>>,
    floors: RwLock<HashMap<(String, String), PolicyFloor>>,
    logs: RwLock<HashMap<Uuid, LogRing>>,
}

/// One claim's output in memory (ADR-0045 decision 11): the same cap, ownership and sweep
/// rules as the Secret ring, so the fake is no more permissive than the real thing.
#[derive(Debug, Default)]
struct LogRing {
    entries: VecDeque<LogEntry>,
    /// Record text bytes in `entries`.
    bytes: usize,
    truncated_before: u64,
    last_seq: Option<u64>,
}

impl LogRing {
    /// Append the new records of `batch` (those above `last_seq`), the gap first when any is
    /// new and bytes were dropped, then drop the oldest beyond `max_bytes`.
    fn append(&mut self, batch: &LogBatch, max_bytes: usize) -> LogAppend {
        let new: Vec<&mediatore_proto::LogRecord> = batch
            .records
            .iter()
            .filter(|r| self.last_seq.is_none_or(|l| r.seq > l))
            .collect();
        let ignored = batch.records.len() - new.len();
        if new.is_empty() {
            return LogAppend { stored: 0, ignored };
        }
        if batch.dropped_stdout > 0 || batch.dropped_stderr > 0 {
            self.entries.push_back(LogEntry::Gap(LogGap {
                lost_stdout: batch.dropped_stdout,
                lost_stderr: batch.dropped_stderr,
            }));
        }
        for r in &new {
            self.bytes += r.text.len();
            self.last_seq = Some(r.seq);
            self.entries.push_back(LogEntry::Record((*r).clone()));
        }
        while self.bytes > max_bytes {
            let Some(front) = self.entries.pop_front() else {
                break;
            };
            let n = front.text_bytes();
            self.bytes -= n;
            self.truncated_before += n as u64;
        }
        LogAppend {
            stored: new.len(),
            ignored,
        }
    }

    /// Everything, or what follows `since` with the gaps right before it (see
    /// [`LogStore::read_logs`]).
    fn read(&self, since: Option<u64>) -> LogChunk {
        let entries: Vec<LogEntry> = match since {
            None => self.entries.iter().cloned().collect(),
            Some(since) => {
                let first = self
                    .entries
                    .iter()
                    .position(|e| e.seq().is_some_and(|s| s > since));
                match first {
                    None => Vec::new(),
                    Some(mut start) => {
                        while start > 0 && self.entries[start - 1].seq().is_none() {
                            start -= 1;
                        }
                        self.entries.iter().skip(start).cloned().collect()
                    }
                }
            }
        };
        LogChunk {
            truncated_before: self.truncated_before,
            entries,
            last_seq: self.last_seq,
        }
    }
}

#[async_trait]
impl LogStore for MemoryStore {
    async fn append_logs(
        &self,
        rec: &ClaimRecord,
        batch: &LogBatch,
        limits: &LogLimits,
    ) -> Result<LogAppend, StoreError> {
        let mut m = self.logs.write().await;
        Ok(m.entry(rec.uid)
            .or_default()
            .append(batch, limits.max_bytes))
    }

    async fn read_logs(&self, claim_uid: Uuid, since: Option<u64>) -> Result<LogChunk, StoreError> {
        Ok(self
            .logs
            .read()
            .await
            .get(&claim_uid)
            .map(|r| r.read(since))
            .unwrap_or_default())
    }

    async fn delete_logs(&self, claim_uid: Uuid) -> Result<(), StoreError> {
        self.logs.write().await.remove(&claim_uid);
        Ok(())
    }

    async fn sweep_logs(&self, before: Timestamp) -> Result<usize, StoreError> {
        let claims = self.claims.read().await;
        let mut logs = self.logs.write().await;
        let n = logs.len();
        logs.retain(|uid, _| {
            claims
                .get(uid)
                .is_some_and(|rec| rec.ended_at().is_none_or(|e| e >= before))
        });
        Ok(n - logs.len())
    }
}

impl MemoryStore {
    /// Construct an empty store behind an `Arc`.
    #[must_use]
    pub fn shared() -> Arc<Self> {
        Arc::new(Self::default())
    }
}

#[async_trait]
impl ClaimStore for MemoryStore {
    async fn put_claim(&self, rec: ClaimRecord) -> Result<(), StoreError> {
        let mut m = self.claims.write().await;
        if m.contains_key(&rec.uid) {
            return Err(StoreError::Conflict(rec.uid.to_string()));
        }
        m.insert(rec.uid, rec);
        Ok(())
    }

    async fn get_claim(&self, uid: Uuid) -> Result<ClaimRecord, StoreError> {
        self.claims
            .read()
            .await
            .get(&uid)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(uid.to_string()))
    }

    async fn get_claim_by_name(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<ClaimRecord, StoreError> {
        self.claims
            .read()
            .await
            .values()
            .find(|c| c.namespace == namespace && c.name == name)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(name.to_string()))
    }

    async fn update_claim(&self, rec: ClaimRecord) -> Result<(), StoreError> {
        let mut m = self.claims.write().await;
        if !m.contains_key(&rec.uid) {
            return Err(StoreError::NotFound(rec.uid.to_string()));
        }
        m.insert(rec.uid, rec);
        Ok(())
    }

    async fn revoke_claim(&self, uid: Uuid, at: Timestamp) -> Result<(), StoreError> {
        let mut m = self.claims.write().await;
        let rec = m
            .get_mut(&uid)
            .ok_or_else(|| StoreError::NotFound(uid.to_string()))?;
        rec.revoked_at.get_or_insert(at);
        rec.refresh = None;
        rec.delegations.clear();
        Ok(())
    }

    async fn get_claim_by_node(&self, node_id: &str) -> Result<ClaimRecord, StoreError> {
        let now = Timestamp::now();
        self.claims
            .read()
            .await
            .values()
            .filter(|c| c.node_id.as_deref() == Some(node_id) && c.is_live(now))
            .max_by_key(|c| c.created_at)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(node_id.to_owned()))
    }

    async fn list_claims(&self) -> Result<Vec<ClaimRecord>, StoreError> {
        Ok(self.claims.read().await.values().cloned().collect())
    }

    async fn put_node(&self, rec: NodeRecord) -> Result<(), StoreError> {
        let mut m = self.nodes.write().await;
        if let Some(existing) = m.get(&rec.ek_hash) {
            if existing.dmi_uuid != rec.dmi_uuid {
                // Same TPM, different VM: cloned TPM state. Refuse loudly.
                return Err(StoreError::Conflict(format!(
                    "ek_hash {} already registered for dmi {}",
                    rec.ek_hash, existing.dmi_uuid
                )));
            }
            return Ok(());
        }
        m.insert(rec.ek_hash.clone(), rec);
        Ok(())
    }

    async fn get_node(&self, ek_hash: &str) -> Result<NodeRecord, StoreError> {
        self.nodes
            .read()
            .await
            .get(ek_hash)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(ek_hash.to_string()))
    }

    async fn get_node_by_dmi(&self, dmi_uuid: Uuid) -> Result<NodeRecord, StoreError> {
        self.nodes
            .read()
            .await
            .values()
            .find(|n| n.dmi_uuid == dmi_uuid)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(dmi_uuid.to_string()))
    }

    async fn ban_node(&self, ek_hash: &str) -> Result<(), StoreError> {
        let mut m = self.nodes.write().await;
        let n = m
            .get_mut(ek_hash)
            .ok_or_else(|| StoreError::NotFound(ek_hash.to_string()))?;
        n.banned = true;
        Ok(())
    }

    async fn list_nodes(&self) -> Result<Vec<NodeRecord>, StoreError> {
        Ok(self.nodes.read().await.values().cloned().collect())
    }

    async fn delete_node(&self, ek_hash: &str) -> Result<(), StoreError> {
        self.nodes.write().await.remove(ek_hash);
        Ok(())
    }

    async fn sweep(&self, before: Timestamp) -> Result<usize, StoreError> {
        let mut claims = self.claims.write().await;
        let gone: Vec<Uuid> = claims
            .values()
            .filter(|c| c.ended_at().is_some_and(|e| e < before))
            .map(|c| c.uid)
            .collect();
        for uid in &gone {
            let c = claims.remove(uid).expect("selected above");
            tracing::info!(claim_uid = %c.uid, name = %c.name, subject = %c.subject.id, "claim swept after its retention");
        }
        Ok(gone.len())
    }

    async fn put_session(&self, rec: SessionRecord) -> Result<(), StoreError> {
        let mut m = self.sessions.write().await;
        let key = (rec.sandbox_uid, rec.audience.clone());
        if m.contains_key(&key) {
            return Err(StoreError::Conflict(rec.sandbox_uid.to_string()));
        }
        m.insert(key, rec);
        Ok(())
    }

    async fn take_session(&self, sandbox_uid: Uuid) -> Result<Option<SessionRecord>, StoreError> {
        Ok(self.sessions.write().await.remove(&(sandbox_uid, None)))
    }

    async fn take_delegations(&self, sandbox_uid: Uuid) -> Result<Vec<SessionRecord>, StoreError> {
        let mut m = self.sessions.write().await;
        let keys: Vec<(Uuid, Option<String>)> = m
            .keys()
            .filter(|(uid, audience)| *uid == sandbox_uid && audience.is_some())
            .cloned()
            .collect();
        let mut out: Vec<SessionRecord> = keys.iter().filter_map(|k| m.remove(k)).collect();
        out.sort_by(|a, b| a.audience.cmp(&b.audience));
        Ok(out)
    }

    async fn delete_session(&self, sandbox_uid: Uuid) -> Result<(), StoreError> {
        self.sessions
            .write()
            .await
            .retain(|(uid, _), _| *uid != sandbox_uid);
        Ok(())
    }

    async fn sweep_sessions(&self, before: Timestamp) -> Result<usize, StoreError> {
        let now = Timestamp::now();
        let mut m = self.sessions.write().await;
        let n = m.len();
        // Old (the grace period) or expired (ADR-0043 decision 4: a credential stops being useful when it expires).
        m.retain(|_, s| s.created_at >= before && s.expires_at.is_none_or(|e| e > now));
        let mut swept = n - m.len();
        // The same rule for an envelope already on a bound claim's record: stored no longer than it is useful
        // (the operator's rule, ADR-0043 decision 4), which can be before the claim ends.
        for rec in self.claims.write().await.values_mut() {
            let held = rec.delegations.len();
            rec.delegations
                .retain(|_, d| d.expires_at.is_none_or(|e| e > now));
            swept += held - rec.delegations.len();
        }
        Ok(swept)
    }

    async fn get_policy_floor(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Option<PolicyFloor>, StoreError> {
        Ok(self
            .floors
            .read()
            .await
            .get(&(namespace.to_string(), name.to_string()))
            .cloned())
    }

    async fn advance_policy_floor(
        &self,
        held: Option<&PolicyFloor>,
        next: PolicyFloor,
    ) -> Result<(), StoreError> {
        same_policy(held, &next)?;
        let mut m = self.floors.write().await;
        let key = (next.namespace.clone(), next.name.clone());
        if m.get(&key) != held {
            return Err(StoreError::Conflict(format!(
                "the floor of {}/{} moved",
                key.0, key.1
            )));
        }
        m.insert(key, next);
        Ok(())
    }

    async fn ping(&self) -> Result<(), StoreError> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    crate::conformance::suite!(memory, MemoryStore::default());
}
