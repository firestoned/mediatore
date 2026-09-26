//! SPIRE server API boundary.
//!
//! mediatore creates exactly two kinds of registration entry:
//! * a node bootstrap entry `spiffe://<td>/banlieue/node/<ek-hash>` for the in-guest agent
//!   (selectors `unix:uid:0` + `unix:path:/usr/local/bin/mediatore-guest`), and
//! * a claim entry `spiffe://<td>/banlieue/claim/<uid>` for the jailed workload
//!   (selector `unix:user:<sandbox user>`).
//!
//! The gRPC implementation over `spire-api-sdk` is the next step; `Noop` lets the rest of
//! the server run in `--dev` mode.

use async_trait::async_trait;
use uuid::Uuid;

/// Trust domain plus the path prefixes we own.
#[derive(Debug, Clone)]
pub struct Naming {
    /// e.g. `sandbox.rbc.internal`
    pub trust_domain: String,
}

impl Naming {
    /// `spiffe://<td>/banlieue/node/<ek-hash>`
    #[must_use]
    pub fn node_id(&self, ek_hash: &str) -> String {
        format!("spiffe://{}/banlieue/node/{ek_hash}", self.trust_domain)
    }

    /// `spiffe://<td>/banlieue/claim/<uid>`
    #[must_use]
    pub fn claim_id(&self, uid: Uuid) -> String {
        format!("spiffe://{}/banlieue/claim/{uid}", self.trust_domain)
    }

    /// `spiffe://<td>/mediatore`
    #[must_use]
    pub fn broker_id(&self) -> String {
        format!("spiffe://{}/mediatore", self.trust_domain)
    }

    /// Parse a claim UID out of a peer SPIFFE ID, if it is one of ours.
    #[must_use]
    pub fn claim_uid_from(&self, spiffe_id: &str) -> Option<Uuid> {
        let prefix = format!("spiffe://{}/banlieue/claim/", self.trust_domain);
        spiffe_id.strip_prefix(&prefix).and_then(|s| Uuid::parse_str(s).ok())
    }
}

/// An attested agent as `ListAgents` reports it.
#[derive(Debug, Clone)]
pub struct Agent {
    /// Agent SPIFFE ID, e.g. `spiffe://<td>/spire/agent/tpm/<ek-hash>`.
    pub spiffe_id: String,
    /// Attestation type (`tpm`, `k8s_psat`, ...).
    pub attestation_type: String,
}

/// Errors from the SPIRE API.
#[derive(Debug, thiserror::Error)]
pub enum SpireError {
    /// Transport or RPC error.
    #[error("rpc: {0}")]
    Rpc(String),
    /// Entry already exists (idempotent callers ignore this).
    #[error("entry exists: {0}")]
    Exists(String),
    /// Not wired yet.
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
}

/// Registration entry operations mediatore needs.
#[async_trait]
pub trait EntryManager: Send + Sync + 'static {
    /// List attested agents.
    async fn list_agents(&self) -> Result<Vec<Agent>, SpireError>;
    /// Create (or find) the node bootstrap entry. Returns the entry id.
    async fn ensure_node_entry(&self, parent_id: &str, node_id: &str) -> Result<String, SpireError>;
    /// Create the claim entry. Returns the entry id.
    async fn create_claim_entry(
        &self,
        parent_id: &str,
        claim_id: &str,
        unix_user: &str,
    ) -> Result<String, SpireError>;
    /// Delete an entry by id; idempotent.
    async fn delete_entry(&self, entry_id: &str) -> Result<(), SpireError>;
}

/// Logs what it would do. For `--dev` and tests.
#[derive(Debug, Default)]
pub struct Noop;

#[async_trait]
impl EntryManager for Noop {
    async fn list_agents(&self) -> Result<Vec<Agent>, SpireError> {
        Ok(vec![])
    }

    async fn ensure_node_entry(&self, parent_id: &str, node_id: &str) -> Result<String, SpireError> {
        tracing::info!(parent_id, node_id, "noop: ensure node entry");
        Ok(format!("noop-{node_id}"))
    }

    async fn create_claim_entry(
        &self,
        parent_id: &str,
        claim_id: &str,
        unix_user: &str,
    ) -> Result<String, SpireError> {
        tracing::info!(parent_id, claim_id, unix_user, "noop: create claim entry");
        Ok(format!("noop-{claim_id}"))
    }

    async fn delete_entry(&self, entry_id: &str) -> Result<(), SpireError> {
        tracing::info!(entry_id, "noop: delete entry");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claim_uid_roundtrip() {
        let n = Naming { trust_domain: "sandbox.test".into() };
        let uid = Uuid::new_v4();
        assert_eq!(n.claim_uid_from(&n.claim_id(uid)), Some(uid));
        assert_eq!(n.claim_uid_from("spiffe://sandbox.test/mediatore"), None);
        assert_eq!(n.claim_uid_from("spiffe://other.test/banlieue/claim/x"), None);
    }
}
