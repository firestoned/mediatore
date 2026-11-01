// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Claim lifecycle: the `AgentSandbox` resource (ADR-0008) and the watch on banlieue's
//! `VirtualMachineClaim` (ADR-0011).
//!
//! An `AgentSandbox` ([`sandbox`]) is the request: its reconciler creates and owns one claim
//! and the store record keyed by the claim's UID. On `Bound`: resolve the node by the EK
//! hash of the certificate banlieue mirrored onto the claim, declare the claim's
//! registration entry (ADR-0006) and record it. On `Releasing`/`Failed`/deletion: retract
//! the entry and revoke the record. Order: entry first, then refresh material. The state
//! machine and the [`Reconciler`] are here; the typed watches over `banlieue-api` are
//! [`watch`], and [`lease`] elects the replica that runs them.

use std::sync::Arc;

use chrono::Utc;
use mediatore_proto::ClaimPhase;
use mediatore_spire::{EntryKind, EntryManager, Naming};
use mediatore_store::{ClaimStore, StoreError};
use uuid::Uuid;

#[cfg(test)]
pub(crate) mod fakes;
pub mod lease;
pub mod policy;
pub mod sandbox;
pub mod watch;

/// Decision for one observed claim.
#[derive(Debug, PartialEq, Eq)]
pub enum Action {
    /// Create the SPIRE entry and store its id.
    Bind,
    /// Delete the entry, revoke the record.
    Release,
    /// Nothing to do.
    Hold,
}

/// Pure function of the observed phase and what we already recorded.
///
/// * `Bound` with no entry yet → `Bind`
/// * `Releasing` / `Failed` / deleted with an entry → `Release`
/// * everything else → `Hold`
#[must_use]
pub fn next_action(phase: Option<ClaimPhase>, has_entry: bool, deleting: bool) -> Action {
    match (phase, has_entry, deleting) {
        (_, true, true) | (Some(ClaimPhase::Releasing | ClaimPhase::Failed), true, _) => {
            Action::Release
        }
        (Some(ClaimPhase::Bound), false, false) => Action::Bind,
        _ => Action::Hold,
    }
}

/// Wiring the watcher needs.
pub struct Reconciler {
    /// Persistence.
    pub store: Arc<dyn ClaimStore>,
    /// SPIRE entries.
    pub spire: Arc<dyn EntryManager>,
    /// SPIFFE naming.
    pub naming: Naming,
}

impl Reconciler {
    /// Handle a bind: declare the entry for `claim_uid` under the agent of the node whose
    /// EK hash is `ek_hash`, and start the claim's TTL clock. Returns only once the entry
    /// is set on the SPIRE server; a masked or refused entry is an error and the claim
    /// stays unbound.
    pub async fn bind(&self, claim_uid: Uuid, ek_hash: &str) -> anyhow::Result<()> {
        let mut rec = self.store.get_claim(claim_uid).await?;
        if rec.entry_id.is_some() {
            return Ok(()); // idempotent on restart
        }
        let user = rec.subject.sandbox_username();
        let entry = self
            .spire
            .create_claim_entry(ek_hash, claim_uid, &user)
            .await?;
        rec.entry_id = Some(entry);
        rec.node_id = Some(self.naming.agent_id(ek_hash));
        rec.expires_at.get_or_insert_with(|| {
            Utc::now() + chrono::Duration::seconds(i64::from(rec.ttl_seconds))
        });
        self.store.update_claim(rec).await?;
        tracing::info!(%claim_uid, ek_hash, "claim bound: entry set");
        Ok(())
    }

    /// Handle a release: entry first, then refresh material.
    pub async fn release(&self, claim_uid: Uuid) -> anyhow::Result<()> {
        let rec = match self.store.get_claim(claim_uid).await {
            Ok(r) => r,
            Err(StoreError::NotFound(_)) => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        if let Some(entry) = &rec.entry_id {
            self.spire.delete_entry(entry).await?;
        }
        self.store.revoke_claim(claim_uid, Utc::now()).await?;
        tracing::info!(%claim_uid, "claim released: entry retracted, tokens cut off");
        Ok(())
    }

    /// Retract every claim entry whose claim is unknown or revoked (ADR-0006 decision 9).
    /// Node entries are left alone: they live as long as the VM. Returns how many were
    /// retracted.
    pub async fn sweep_orphans(&self) -> anyhow::Result<usize> {
        let mut retracted = 0;
        for entry in self.spire.list_entries().await? {
            if entry.kind != EntryKind::Claim {
                continue;
            }
            let orphan = match entry.claim_uid {
                None => true,
                Some(uid) => match self.store.get_claim(uid).await {
                    Ok(rec) => rec.revoked_at.is_some(),
                    Err(StoreError::NotFound(_)) => true,
                    Err(e) => return Err(e.into()),
                },
            };
            if orphan {
                tracing::warn!(name = %entry.name, claim_uid = ?entry.claim_uid, "orphaned claim entry retracted");
                self.spire.delete_entry(&entry.name).await?;
                retracted += 1;
            }
        }
        Ok(retracted)
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use mediatore_proto::{Subject, Workload};
    use mediatore_spire::{MemoryEntries, claim_entry_name};
    use mediatore_store::{ClaimRecord, MemoryStore};

    use super::*;

    const EK: &str = "72c566555391e835a15c522680b51ec3b840561ed70af5605a5ae4835f040ee8";

    #[test]
    fn precedence() {
        assert_eq!(
            next_action(Some(ClaimPhase::Bound), false, false),
            Action::Bind
        );
        assert_eq!(
            next_action(Some(ClaimPhase::Bound), true, false),
            Action::Hold
        );
        assert_eq!(
            next_action(Some(ClaimPhase::Bound), true, true),
            Action::Release
        );
        assert_eq!(
            next_action(Some(ClaimPhase::Releasing), true, false),
            Action::Release
        );
        assert_eq!(
            next_action(Some(ClaimPhase::Failed), false, false),
            Action::Hold
        );
        assert_eq!(next_action(None, false, false), Action::Hold);
    }

    fn record(uid: Uuid) -> ClaimRecord {
        ClaimRecord {
            uid,
            name: format!("claim-{uid}"),
            subject: Subject {
                issuer: "https://idp.test".into(),
                id: "octocat".into(),
                display: None,
            },
            entry_id: None,
            node_id: None,
            audiences: vec![],
            workload: Workload::default(),
            ttl_seconds: 600,
            refresh: None,
            created_at: Utc::now(),
            expires_at: None,
            revoked_at: None,
            sandbox_uid: None,
        }
    }

    fn reconciler() -> (Reconciler, Arc<MemoryEntries>, Arc<MemoryStore>) {
        let entries = Arc::new(MemoryEntries::default());
        let store = MemoryStore::shared();
        let r = Reconciler {
            store: store.clone(),
            spire: entries.clone(),
            naming: Naming {
                trust_domain: "sandbox.test".into(),
            },
        };
        (r, entries, store)
    }

    #[tokio::test]
    async fn bind_declares_the_entry_and_records_the_agent() {
        let (r, entries, store) = reconciler();
        let uid = Uuid::new_v4();
        store.put_claim(record(uid)).await.unwrap();
        r.bind(uid, EK).await.unwrap();
        let rec = store.get_claim(uid).await.unwrap();
        assert_eq!(
            rec.entry_id.as_deref(),
            Some(claim_entry_name(uid).as_str())
        );
        assert_eq!(
            rec.node_id.as_deref(),
            Some(format!("spiffe://sandbox.test/spire/agent/tpm/{EK}").as_str())
        );
        assert!(rec.expires_at.is_some());
        assert_eq!(entries.names(), vec![claim_entry_name(uid)]);
        // Idempotent: a second bind declares nothing new.
        r.bind(uid, EK).await.unwrap();
        assert_eq!(entries.names().len(), 1);
    }

    #[tokio::test]
    async fn bind_with_a_bad_ek_hash_leaves_the_claim_unbound() {
        let (r, entries, store) = reconciler();
        let uid = Uuid::new_v4();
        store.put_claim(record(uid)).await.unwrap();
        assert!(r.bind(uid, "3f9a").await.is_err());
        assert!(store.get_claim(uid).await.unwrap().entry_id.is_none());
        assert_eq!(entries.names(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn release_retracts_then_revokes() {
        let (r, entries, store) = reconciler();
        let uid = Uuid::new_v4();
        store.put_claim(record(uid)).await.unwrap();
        r.bind(uid, EK).await.unwrap();
        r.release(uid).await.unwrap();
        assert_eq!(entries.names(), Vec::<String>::new());
        assert!(store.get_claim(uid).await.unwrap().revoked_at.is_some());
        r.release(uid).await.unwrap(); // idempotent
        r.release(Uuid::new_v4()).await.unwrap(); // unknown claim is fine
    }

    #[tokio::test]
    async fn sweep_retracts_entries_whose_claim_is_gone_or_revoked() {
        let (r, entries, store) = reconciler();
        let live = Uuid::new_v4();
        let revoked = Uuid::new_v4();
        let unknown = Uuid::new_v4();
        store.put_claim(record(live)).await.unwrap();
        store.put_claim(record(revoked)).await.unwrap();
        r.bind(live, EK).await.unwrap();
        r.bind(revoked, EK).await.unwrap();
        store.revoke_claim(revoked, Utc::now()).await.unwrap();
        // An entry declared by a previous broker instance for a claim this store never saw.
        entries
            .create_claim_entry(EK, unknown, "sb-0123456789ab")
            .await
            .unwrap();
        entries.ensure_node_entry(EK).await.unwrap();

        assert_eq!(r.sweep_orphans().await.unwrap(), 2);
        let mut left = entries.names();
        left.sort();
        let mut want = vec![claim_entry_name(live), mediatore_spire::node_entry_name(EK)];
        want.sort();
        assert_eq!(left, want);
        assert_eq!(r.sweep_orphans().await.unwrap(), 0);
    }
}
