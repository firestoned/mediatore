// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Persistence boundary for mediatore (ADR-0012).
//!
//! The server only ever talks to [`ClaimStore`]. [`sql::SqlStore`] is the shipped
//! implementation, one query set over SQLite or PostgreSQL chosen by the URL; `MemoryStore`
//! is for `dev_mode` and tests, and the conformance suite holds it to the SQL store's
//! behaviour. Refresh material enters the store only as a [`seal::Sealed`] envelope.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mediatore_proto::{Provider, Subject, Workload};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

#[cfg(test)]
mod conformance;
pub mod seal;
pub mod sql;

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

/// One claim mediatore has brokered. The request fields are a copy of the `AgentSandbox`
/// spec (ADR-0008); the resource is their source of truth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimRecord {
    /// Kubernetes UID of the `VirtualMachineClaim`.
    pub uid: Uuid,
    /// Kubernetes object name.
    pub name: String,
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
    pub created_at: DateTime<Utc>,
    /// Bind deadline, once bound.
    pub expires_at: Option<DateTime<Utc>>,
    /// Set on release or revocation; a revoked claim never issues again.
    pub revoked_at: Option<DateTime<Utc>>,
    /// The `AgentSandbox` the record came from (ADR-0013): the associated data that opens
    /// `refresh`. `None` for a record the dev binder wrote, which seals with its own UID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_uid: Option<Uuid>,
}

impl ClaimRecord {
    /// The UID a sealer binds this record's refresh envelope to.
    #[must_use]
    pub fn seal_binding(&self) -> Uuid {
        self.sandbox_uid.unwrap_or(self.uid)
    }

    /// True when tokens may still be issued for this claim.
    #[must_use]
    pub fn is_live(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && self.expires_at.is_none_or(|e| e > now)
    }

    /// When the claim ended: its revocation, or its deadline once that has passed. `None`
    /// while it may still issue, or while it was never bound and never revoked.
    #[must_use]
    pub fn ended_at(&self) -> Option<DateTime<Utc>> {
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
    pub registered_at: DateTime<Utc>,
}

/// What survives a claim row: written when [`ClaimStore::sweep`] removes it (ADR-0012
/// decision 4). mediatore never deletes these.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimAudit {
    /// The claim's UID.
    pub uid: Uuid,
    /// The claim's name.
    pub name: String,
    /// Who it was for.
    pub subject: Subject,
    /// The node it was bound to, if it ever was.
    pub node_id: Option<String>,
    /// When the record was created.
    pub created_at: DateTime<Utc>,
    /// The bind deadline, if it was bound.
    pub expires_at: Option<DateTime<Utc>>,
    /// When it was revoked, if it was.
    pub revoked_at: Option<DateTime<Utc>>,
    /// When the row was swept.
    pub swept_at: DateTime<Utc>,
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
    pub created_at: DateTime<Utc>,
}

/// Storage contract.
#[async_trait]
pub trait ClaimStore: Send + Sync + 'static {
    /// Insert a new claim. Fails with `Conflict` if the UID exists.
    async fn put_claim(&self, rec: ClaimRecord) -> Result<(), StoreError>;
    /// Fetch by UID.
    async fn get_claim(&self, uid: Uuid) -> Result<ClaimRecord, StoreError>;
    /// Fetch by Kubernetes name.
    async fn get_claim_by_name(&self, name: &str) -> Result<ClaimRecord, StoreError>;
    /// Replace an existing claim record.
    async fn update_claim(&self, rec: ClaimRecord) -> Result<(), StoreError>;
    /// Mark revoked and drop the refresh envelope; idempotent (the first timestamp wins).
    async fn revoke_claim(&self, uid: Uuid, at: DateTime<Utc>) -> Result<(), StoreError>;
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

    /// Remove every claim row that ended ([`ClaimRecord::ended_at`]) before `before`,
    /// writing a [`ClaimAudit`] row for each in the same transaction. Returns how many.
    async fn sweep(&self, before: DateTime<Utc>) -> Result<usize, StoreError>;
    /// Every audit row, oldest sweep first.
    async fn list_audit(&self) -> Result<Vec<ClaimAudit>, StoreError>;
    /// Park a delegated session until the reconciler creates the record. `Conflict` if
    /// the sandbox already has one.
    async fn put_session(&self, rec: SessionRecord) -> Result<(), StoreError>;
    /// Remove and return the session for `sandbox_uid`, if any (one transaction).
    async fn take_session(&self, sandbox_uid: Uuid) -> Result<Option<SessionRecord>, StoreError>;
    /// Remove the session for `sandbox_uid`; nothing to remove is fine.
    async fn delete_session(&self, sandbox_uid: Uuid) -> Result<(), StoreError>;
    /// Remove every session delegated before `before`. Returns how many.
    async fn sweep_sessions(&self, before: DateTime<Utc>) -> Result<usize, StoreError>;
    /// A round trip to the backend; what `/healthz` reports.
    async fn ping(&self) -> Result<(), StoreError>;
}

/// In-memory store. Not durable; for `dev_mode` and tests.
#[derive(Default)]
pub struct MemoryStore {
    claims: RwLock<HashMap<Uuid, ClaimRecord>>,
    nodes: RwLock<HashMap<String, NodeRecord>>,
    audit: RwLock<Vec<ClaimAudit>>,
    sessions: RwLock<HashMap<Uuid, SessionRecord>>,
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

    async fn get_claim_by_name(&self, name: &str) -> Result<ClaimRecord, StoreError> {
        self.claims
            .read()
            .await
            .values()
            .find(|c| c.name == name)
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

    async fn revoke_claim(&self, uid: Uuid, at: DateTime<Utc>) -> Result<(), StoreError> {
        let mut m = self.claims.write().await;
        let rec = m
            .get_mut(&uid)
            .ok_or_else(|| StoreError::NotFound(uid.to_string()))?;
        rec.revoked_at.get_or_insert(at);
        rec.refresh = None;
        Ok(())
    }

    async fn get_claim_by_node(&self, node_id: &str) -> Result<ClaimRecord, StoreError> {
        let now = Utc::now();
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

    async fn sweep(&self, before: DateTime<Utc>) -> Result<usize, StoreError> {
        let mut claims = self.claims.write().await;
        let mut audit = self.audit.write().await;
        let swept_at = Utc::now();
        let gone: Vec<Uuid> = claims
            .values()
            .filter(|c| c.ended_at().is_some_and(|e| e < before))
            .map(|c| c.uid)
            .collect();
        for uid in &gone {
            let c = claims.remove(uid).expect("selected above");
            audit.push(ClaimAudit {
                uid: c.uid,
                name: c.name,
                subject: c.subject,
                node_id: c.node_id,
                created_at: c.created_at,
                expires_at: c.expires_at,
                revoked_at: c.revoked_at,
                swept_at,
            });
        }
        Ok(gone.len())
    }

    async fn list_audit(&self) -> Result<Vec<ClaimAudit>, StoreError> {
        Ok(self.audit.read().await.clone())
    }

    async fn put_session(&self, rec: SessionRecord) -> Result<(), StoreError> {
        let mut m = self.sessions.write().await;
        if m.contains_key(&rec.sandbox_uid) {
            return Err(StoreError::Conflict(rec.sandbox_uid.to_string()));
        }
        m.insert(rec.sandbox_uid, rec);
        Ok(())
    }

    async fn take_session(&self, sandbox_uid: Uuid) -> Result<Option<SessionRecord>, StoreError> {
        Ok(self.sessions.write().await.remove(&sandbox_uid))
    }

    async fn delete_session(&self, sandbox_uid: Uuid) -> Result<(), StoreError> {
        self.sessions.write().await.remove(&sandbox_uid);
        Ok(())
    }

    async fn sweep_sessions(&self, before: DateTime<Utc>) -> Result<usize, StoreError> {
        let mut m = self.sessions.write().await;
        let n = m.len();
        m.retain(|_, s| s.created_at >= before);
        Ok(n - m.len())
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
