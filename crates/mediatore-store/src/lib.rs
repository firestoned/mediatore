//! Persistence boundary for mediatore.
//!
//! The server only ever talks to [`ClaimStore`]; `MemoryStore` is for tests and single-node
//! homelab use. A `sqlx`-backed implementation (PostgreSQL at work, SQLite at home) slots in
//! behind the same trait.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mediatore_proto::{Provider, Subject};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

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

/// One claim mediatore has brokered.
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
    /// Encrypted refresh material for the token backend. Never plaintext.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_ciphertext: Option<Vec<u8>>,
    /// When mediatore created the claim.
    pub created_at: DateTime<Utc>,
    /// Bind deadline, once bound.
    pub expires_at: Option<DateTime<Utc>>,
    /// Set on release or revocation; a revoked claim never issues again.
    pub revoked_at: Option<DateTime<Utc>>,
}

impl ClaimRecord {
    /// True when tokens may still be issued for this claim.
    #[must_use]
    pub fn is_live(&self, now: DateTime<Utc>) -> bool {
        self.revoked_at.is_none() && self.expires_at.is_none_or(|e| e > now)
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
    /// Mark revoked; idempotent.
    async fn revoke_claim(&self, uid: Uuid, at: DateTime<Utc>) -> Result<(), StoreError>;

    /// Register a node. Fails with `Conflict` if the EK hash is known with a different DMI UUID.
    async fn put_node(&self, rec: NodeRecord) -> Result<(), StoreError>;
    /// Fetch by EK hash.
    async fn get_node(&self, ek_hash: &str) -> Result<NodeRecord, StoreError>;
    /// Fetch by DMI UUID.
    async fn get_node_by_dmi(&self, dmi_uuid: Uuid) -> Result<NodeRecord, StoreError>;
    /// Ban a node.
    async fn ban_node(&self, ek_hash: &str) -> Result<(), StoreError>;
}

/// In-memory store. Not durable; fine for tests and `--dev`.
#[derive(Default)]
pub struct MemoryStore {
    claims: RwLock<HashMap<Uuid, ClaimRecord>>,
    nodes: RwLock<HashMap<String, NodeRecord>>,
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
        let rec = m.get_mut(&uid).ok_or_else(|| StoreError::NotFound(uid.to_string()))?;
        rec.revoked_at.get_or_insert(at);
        rec.refresh_ciphertext = None;
        Ok(())
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
        let n = m.get_mut(ek_hash).ok_or_else(|| StoreError::NotFound(ek_hash.to_string()))?;
        n.banned = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(ek: &str, dmi: Uuid) -> NodeRecord {
        NodeRecord {
            ek_hash: ek.into(),
            node_id: format!("spiffe://td/spire/agent/tpm/{ek}"),
            dmi_uuid: dmi,
            hostname: "h".into(),
            provider: Some(Provider::Libvirt),
            banned: false,
            registered_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn duplicate_ek_with_other_dmi_is_conflict() {
        let s = MemoryStore::default();
        s.put_node(node("ek1", Uuid::new_v4())).await.unwrap();
        let err = s.put_node(node("ek1", Uuid::new_v4())).await.unwrap_err();
        assert!(matches!(err, StoreError::Conflict(_)));
    }

    #[tokio::test]
    async fn revoke_drops_refresh_material() {
        let s = MemoryStore::default();
        let uid = Uuid::new_v4();
        s.put_claim(ClaimRecord {
            uid,
            name: "claim-1".into(),
            subject: Subject { issuer: "i".into(), id: "u".into(), display: None },
            entry_id: None,
            node_id: None,
            audiences: vec![],
            refresh_ciphertext: Some(vec![1, 2, 3]),
            created_at: Utc::now(),
            expires_at: None,
            revoked_at: None,
        })
        .await
        .unwrap();
        s.revoke_claim(uid, Utc::now()).await.unwrap();
        let rec = s.get_claim(uid).await.unwrap();
        assert!(rec.refresh_ciphertext.is_none());
        assert!(!rec.is_live(Utc::now()));
    }
}
