// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Claim lifecycle: the `AgentSandbox` resource (ADR-0008) and the watch on banlieue's
//! `VirtualMachineClaim` (ADR-0011).
//!
//! An `AgentSandbox` ([`sandbox`]) is the request: its reconciler creates and owns one claim
//! and the store record keyed by the claim's UID. On `Bound`: resolve the node by its node
//! key (the EK hash of the certificate banlieue mirrored onto the claim, or for a machine of
//! an `x509pop` pool the key of its agent ID, ADR-0049), declare the claim's registration
//! entry (ADR-0006) under that node's stored agent ID and record it. On `Releasing`/`Failed`/deletion: retract
//! the entry and revoke the record. Order: entry first, then refresh material. The state
//! machine and the [`Reconciler`] are here; the typed watches over `banlieue-api` are
//! [`watch`], and [`lease`] elects the replica that runs them.

use std::sync::Arc;

use jiff::Timestamp;
use mediatore_proto::ClaimPhase;
use mediatore_spire::{EntryKind, EntryManager, Naming, NodeIdentity};
use mediatore_store::{ClaimStore, Modified, StoreError, modify_claim};
use uuid::Uuid;

pub mod audience;
pub mod crd_formats;
pub mod credential;
#[cfg(test)]
pub(crate) mod fakes;
pub mod follow;
pub mod kubestore;
pub mod lease;
pub mod nodegc;
pub mod policy;
pub mod sandbox;
pub mod shadow;
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
    /// Handle a bind: declare the entry for `claim_uid` under the agent of `node` (its
    /// stored agent ID, never one recomputed from its key: ADR-0049 decision 8), record that
    /// agent ID as the claim's node, and start the claim's TTL clock. Returns only once the entry
    /// is set on the SPIRE server; a masked or refused entry is an error and the claim
    /// stays unbound.
    ///
    /// The record is written compare and set (ADR-0057 decision 5): what is decided, is
    /// decided on the record as it is when it is written. An entry id already there is done
    /// and nothing is written; otherwise the entry id and the node are set, and the deadline
    /// only if none is set. A claim released (or gone) under the bind gets the entry it has
    /// just been given retracted before this returns, and the bind is an error.
    pub async fn bind(&self, claim_uid: Uuid, node: &NodeIdentity) -> anyhow::Result<()> {
        let rec = self.store.get_claim(claim_uid).await?;
        if rec.entry_id.is_some() {
            return Ok(()); // idempotent on restart
        }
        if rec.revoked_at.is_some() {
            anyhow::bail!("claim {claim_uid} is released; no entry is declared for it");
        }
        let user = rec.subject.sandbox_username();
        // The SVID never outlives the claim (ADR-0027 decision 7): the clock starts now.
        let claim_ttl = std::time::Duration::from_secs(u64::from(rec.ttl_seconds));
        let entry = self
            .spire
            .create_claim_entry(node, claim_uid, &user, claim_ttl)
            .await?;
        let node_id = node.agent_id.clone();
        let outcome = modify_claim(self.store.as_ref(), claim_uid, |mut fresh| {
            if fresh.entry_id.is_some() {
                return None;
            }
            fresh.entry_id = Some(entry.clone());
            fresh.node_id = Some(node_id.clone());
            if fresh.expires_at.is_none() {
                fresh.expires_at = Some(
                    Timestamp::now()
                        + jiff::SignedDuration::from_secs(i64::from(fresh.ttl_seconds)),
                );
            }
            Some(fresh)
        })
        .await;
        match outcome {
            Ok(Modified::Written | Modified::Unchanged) => {
                tracing::info!(%claim_uid, node_key = %node.key, agent_id = %node.agent_id, "claim bound: entry set");
                Ok(())
            }
            Ok(Modified::Released) | Err(StoreError::NotFound(_)) => {
                // Released under the bind: nothing was written, and the entry declared a
                // moment ago must not outlive the release that did not see it.
                self.spire.delete_entry(&entry).await?;
                tracing::warn!(%claim_uid, node_key = %node.key, "claim released while it was being bound; its entry is retracted");
                anyhow::bail!("claim {claim_uid} was released while it was being bound")
            }
            // Every attempt lost to another write, or the store failed: the claim stays
            // unbound and the controller requeues.
            Err(e) => Err(e.into()),
        }
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
        self.store.revoke_claim(claim_uid, Timestamp::now()).await?;
        tracing::info!(%claim_uid, "claim released: entry retracted, tokens cut off");
        Ok(())
    }

    /// Retract every claim entry whose claim is unknown or revoked (ADR-0006 decision 9).
    /// Node entries are not this sweep's: they live as long as a VM publishes their hash, and
    /// the watcher retracts them once none does (ADR-0039 decision 7). Returns how many were
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
    use jiff::Timestamp;
    use mediatore_proto::{Subject, Workload};
    use mediatore_spire::{EntryRef, MemoryEntries, NodeAttestation, SpireError, claim_entry_name};
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
            rendered: None,
            follow: None,
            uid,
            name: format!("claim-{uid}"),
            namespace: "sandboxes".into(),
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
            created_at: Timestamp::now(),
            expires_at: None,
            revoked_at: None,
            sandbox_uid: None,
            policy_uid: None,
            bundle_version: None,
            report: None,
            exit: None,
            delegations: std::collections::BTreeMap::new(),
            version: None,
        }
    }

    fn naming() -> Naming {
        Naming {
            trust_domain: "sandbox.test".into(),
        }
    }

    /// The TPM node the binds here go under.
    fn node() -> NodeIdentity {
        NodeIdentity::of(&naming(), &NodeAttestation::Tpm { ek_hash: EK.into() }).unwrap()
    }

    fn x509pop_node() -> NodeIdentity {
        let att = NodeAttestation::X509pop {
            issuer_cn: "hv-01".into(),
            subject_cn: "vm-1".into(),
        };
        NodeIdentity::of(&naming(), &att).unwrap()
    }

    fn reconciler() -> (Reconciler, Arc<MemoryEntries>, Arc<MemoryStore>) {
        let entries = Arc::new(MemoryEntries::in_trust_domain("sandbox.test"));
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
        r.bind(uid, &node()).await.unwrap();
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
        r.bind(uid, &node()).await.unwrap();
        assert_eq!(entries.names().len(), 1);
    }

    /// What lands on the record while `create_claim_entry` is in flight, which is between a
    /// bind's first read and its write.
    #[derive(Clone, Copy)]
    enum Meanwhile {
        /// The claim is released.
        Released,
        /// Another writer sets the deadline.
        Deadline(Timestamp),
    }

    /// Entries that let another writer in while a claim entry is being declared.
    struct Interleaved {
        inner: Arc<MemoryEntries>,
        store: Arc<MemoryStore>,
        meanwhile: Meanwhile,
    }

    #[async_trait::async_trait]
    impl EntryManager for Interleaved {
        async fn ensure_node_entry(
            &self,
            attestation: &NodeAttestation,
        ) -> Result<String, SpireError> {
            self.inner.ensure_node_entry(attestation).await
        }

        async fn create_claim_entry(
            &self,
            node: &NodeIdentity,
            claim_uid: Uuid,
            unix_user: &str,
            claim_ttl: std::time::Duration,
        ) -> Result<String, SpireError> {
            let entry = self
                .inner
                .create_claim_entry(node, claim_uid, unix_user, claim_ttl)
                .await?;
            match self.meanwhile {
                Meanwhile::Released => {
                    self.store
                        .revoke_claim(claim_uid, Timestamp::now())
                        .await
                        .unwrap();
                }
                Meanwhile::Deadline(at) => {
                    let mut rec = self.store.get_claim(claim_uid).await.unwrap();
                    rec.expires_at = Some(at);
                    self.store.update_claim(rec).await.unwrap();
                }
            }
            Ok(entry)
        }

        async fn delete_entry(&self, name: &str) -> Result<(), SpireError> {
            self.inner.delete_entry(name).await
        }

        async fn list_entries(&self) -> Result<Vec<EntryRef>, SpireError> {
            self.inner.list_entries().await
        }
    }

    fn interleaved(meanwhile: Meanwhile) -> (Reconciler, Arc<MemoryEntries>, Arc<MemoryStore>) {
        let entries = Arc::new(MemoryEntries::in_trust_domain("sandbox.test"));
        let store = MemoryStore::shared();
        let r = Reconciler {
            store: store.clone(),
            spire: Arc::new(Interleaved {
                inner: entries.clone(),
                store: store.clone(),
                meanwhile,
            }),
            naming: Naming {
                trust_domain: "sandbox.test".into(),
            },
        };
        (r, entries, store)
    }

    #[tokio::test]
    async fn a_bind_that_loses_to_a_release_retracts_its_entry_and_binds_nothing() {
        let (r, entries, store) = interleaved(Meanwhile::Released);
        let uid = Uuid::new_v4();
        store.put_claim(record(uid)).await.unwrap();
        assert!(
            r.bind(uid, &node()).await.is_err(),
            "a bind that lost to a release is an error"
        );
        assert!(
            entries.names().is_empty(),
            "the entry it declared is retracted before it returns"
        );
        let rec = store.get_claim(uid).await.unwrap();
        let unbound = rec.entry_id.is_none() && rec.node_id.is_none() && rec.expires_at.is_none();
        assert!(unbound, "nothing of the bind is on the record");
        assert!(rec.revoked_at.is_some(), "and the release stands");
        // A bind of a claim already released declares nothing at all.
        assert!(r.bind(uid, &node()).await.is_err());
        assert!(entries.names().is_empty(), "no entry for a released claim");
    }

    #[tokio::test]
    async fn a_bind_that_meets_a_conflict_binds_once_and_keeps_the_first_deadline() {
        // Another writer moved the record between this bind's read and its write, and set a
        // deadline. The bind decides on the record as it then is: the entry and the node
        // are set once, the deadline that is there is kept.
        let deadline = Timestamp::now() + jiff::SignedDuration::from_secs(120);
        let (r, entries, store) = interleaved(Meanwhile::Deadline(deadline));
        let uid = Uuid::new_v4();
        store.put_claim(record(uid)).await.unwrap();
        r.bind(uid, &node()).await.unwrap();
        let rec = store.get_claim(uid).await.unwrap();
        let bound = rec.entry_id.as_deref() == Some(claim_entry_name(uid).as_str())
            && rec.node_id.is_some();
        assert!(bound, "the entry and the node are on the record");
        assert_eq!(rec.expires_at, Some(deadline), "the first deadline is kept");
        assert_eq!(entries.names().len(), 1);
        // A second bind finds the entry id and writes nothing.
        let before = rec.version;
        r.bind(uid, &node()).await.unwrap();
        assert_eq!(entries.names().len(), 1, "bound once");
        let again = store.get_claim(uid).await.unwrap();
        assert!(
            again.version == before,
            "nothing was written the second time"
        );
        assert_eq!(again.expires_at, Some(deadline));
    }

    #[tokio::test]
    async fn bind_under_an_agent_that_is_no_agent_of_this_trust_domain_leaves_the_claim_unbound() {
        let (r, entries, store) = reconciler();
        let uid = Uuid::new_v4();
        store.put_claim(record(uid)).await.unwrap();
        let x509pop = x509pop_node();
        for bad in [
            // A key that is no key.
            NodeIdentity::stored("3f9a", "spiffe://sandbox.test/spire/agent/tpm/3f9a"),
            // A stored agent ID of another trust domain, and one that is no agent's.
            NodeIdentity::stored(EK, &format!("spiffe://other.test/spire/agent/tpm/{EK}")),
            NodeIdentity::stored(EK, "spiffe://sandbox.test/spire/server"),
            // A key that is not the agent's: a TPM key over an x509pop agent, and an
            // x509pop agent's key over another x509pop agent.
            NodeIdentity::stored(EK, &x509pop.agent_id),
            NodeIdentity::stored(
                &x509pop.key,
                "spiffe://sandbox.test/spire/agent/x509pop/hv-02/vm-1",
            ),
        ] {
            assert!(r.bind(uid, &bad).await.is_err());
            let rec = store.get_claim(uid).await.unwrap();
            assert!(rec.entry_id.is_none() && rec.node_id.is_none());
            assert_eq!(entries.names(), Vec::<String>::new());
        }
    }

    #[tokio::test]
    async fn bind_under_an_x509pop_node_parents_the_entry_to_its_stored_agent_id() {
        // ADR-0049 decision 8: the claim's entry is parented to the stored agent ID and
        // the record carries it, never `spire/agent/tpm/<key>` recomputed from the key.
        let (r, entries, store) = reconciler();
        let uid = Uuid::new_v4();
        store.put_claim(record(uid)).await.unwrap();
        let node = x509pop_node();
        r.bind(uid, &node).await.unwrap();
        let agent = "spiffe://sandbox.test/spire/agent/x509pop/hv-01/vm-1";
        let rec = store.get_claim(uid).await.unwrap();
        assert_eq!(rec.node_id.as_deref(), Some(agent));
        assert_eq!(
            entries.parent_of(&claim_entry_name(uid)).as_deref(),
            Some(agent)
        );
        assert_eq!(store.get_claim_by_node(agent).await.unwrap().uid, uid);
        assert!(
            store
                .get_claim_by_node(&r.naming.agent_id(&node.key))
                .await
                .is_err(),
            "nothing is recorded under a tpm agent ID made from the key"
        );
    }

    #[tokio::test]
    async fn release_retracts_then_revokes() {
        let (r, entries, store) = reconciler();
        let uid = Uuid::new_v4();
        store.put_claim(record(uid)).await.unwrap();
        r.bind(uid, &node()).await.unwrap();
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
        r.bind(live, &node()).await.unwrap();
        r.bind(revoked, &node()).await.unwrap();
        store.revoke_claim(revoked, Timestamp::now()).await.unwrap();
        // An entry declared by a previous broker instance for a claim this store never saw.
        entries
            .create_claim_entry(
                &node(),
                unknown,
                "sb-0123456789ab",
                std::time::Duration::from_hours(1),
            )
            .await
            .unwrap();
        entries
            .ensure_node_entry(&NodeAttestation::Tpm { ek_hash: EK.into() })
            .await
            .unwrap();

        assert_eq!(r.sweep_orphans().await.unwrap(), 2);
        let mut left = entries.names();
        left.sort();
        let mut want = vec![claim_entry_name(live), mediatore_spire::node_entry_name(EK)];
        want.sort();
        assert_eq!(left, want);
        assert_eq!(r.sweep_orphans().await.unwrap(), 0);
    }
}
