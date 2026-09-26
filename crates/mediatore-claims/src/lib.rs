// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Claim lifecycle: watch banlieue `VirtualMachineClaim`s and react.
//!
//! On `Bound`: resolve the bound VM's `providerID` to a registered node (by DMI UUID),
//! cross-check the EK hash against `status.tpmEndorsementCertificates` when present, create
//! the claim's SPIRE entry, and record it. On `Releasing`/`Failed`/deletion: delete the entry
//! and revoke the record. Order: entry first, then refresh material.
//!
//! The typed CRD watch depends on `banlieue-api`; until that pin exists this crate holds the
//! state machine and a `run` that connects to the cluster and stops.

use std::sync::Arc;

use chrono::Utc;
use mediatore_proto::ClaimPhase;
use mediatore_spire::{EntryManager, Naming};
use mediatore_store::{ClaimStore, StoreError};
use uuid::Uuid;

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
    /// Handle a bind: create the entry for `claim_uid` under the node's SPIRE agent ID,
    /// and start the claim's TTL clock.
    pub async fn bind(&self, claim_uid: Uuid, node_id: &str) -> anyhow::Result<()> {
        let mut rec = self.store.get_claim(claim_uid).await?;
        if rec.entry_id.is_some() {
            return Ok(()); // idempotent on restart
        }
        let spiffe_id = self.naming.claim_id(claim_uid);
        let user = rec.subject.sandbox_username();
        let entry_id = match self
            .spire
            .create_claim_entry(node_id, &spiffe_id, &user)
            .await
        {
            Ok(id) | Err(mediatore_spire::SpireError::Exists(id)) => id,
            Err(e) => return Err(e.into()),
        };
        rec.entry_id = Some(entry_id);
        rec.node_id = Some(node_id.to_owned());
        rec.expires_at.get_or_insert_with(|| {
            Utc::now() + chrono::Duration::seconds(i64::from(rec.ttl_seconds))
        });
        self.store.update_claim(rec).await?;
        tracing::info!(%claim_uid, node_id, "claim bound: SPIRE entry created");
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
        tracing::info!(%claim_uid, "claim released: entry deleted, tokens cut off");
        Ok(())
    }
}

/// Connect to the cluster. The typed watch on `VirtualMachineClaim` is added once
/// `banlieue-api` is pinned; for now this proves the client wiring and returns.
pub async fn run(_r: Reconciler) -> anyhow::Result<()> {
    let client = kube::Client::try_default().await?;
    let version = client.apiserver_version().await?;
    tracing::info!(git = %version.git_version, "connected to the API server; claim watcher not wired yet");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
