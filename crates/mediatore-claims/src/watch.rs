// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The claim watcher (ADR-0011): banlieue's `VirtualMachineClaim` and `VirtualMachine`
//! events drive [`Reconciler::bind`] and [`Reconciler::release`] and declare node entries.
//!
//! One [`Watcher`] holds the reconciler and the per-claim state (when a `Bound` claim was
//! first seen unresolved). Its two reconcile functions are plain async methods, tested
//! against the in-memory store and entries; [`run`] wraps them in kube-runtime
//! `Controller`s and is meant to execute on the replica holding the Lease
//! (`crate::lease`).
//!
//! What binds a claim: its `metadata.uid` is the claim UID, and the node is the one that
//! registered under the EK hash of the certificate banlieue mirrored onto the claim.
//! Nothing else is consulted (decision 2). Unresolved for longer than
//! `resolve_timeout` fails the claim: record revoked, claim deleted (decision 3).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use banlieue_api::banlieue::{ClaimPhase as BanlieuePhase, LABEL_POOL, VirtualMachine, VirtualMachineClaim};
use futures::StreamExt;
use kube::api::{DeleteParams, ListParams};
use kube::runtime::controller::{Action, Controller};
use kube::runtime::watcher;
use kube::{Api, Client, ResourceExt};
use mediatore_proto::ClaimPhase;
use mediatore_proto::ek::ek_hash_from_pems;
use mediatore_spire::SpireError;
use mediatore_store::StoreError;
use uuid::Uuid;

use crate::{Action as Intent, Reconciler, next_action};

/// Label mediatore puts on every object it creates; the watcher looks at nothing else.
pub const MANAGED_BY_SELECTOR: &str = "app.kubernetes.io/managed-by=mediatore";

/// Timings (ADR-0011 decisions 3 and 4).
#[derive(Clone, Debug)]
pub struct WatcherConfig {
    /// Between resyncs: release records whose claim is gone, sweep orphan entries.
    pub resync: Duration,
    /// How long a `Bound` claim may stay unresolved before it is failed.
    pub resolve_timeout: Duration,
    /// Between retries while unresolved.
    pub requeue: Duration,
}

impl Default for WatcherConfig {
    fn default() -> Self {
        Self {
            resync: Duration::from_secs(300),
            resolve_timeout: Duration::from_secs(60),
            requeue: Duration::from_secs(5),
        }
    }
}

/// The two writes the watcher makes to claims through the API, behind a trait so the
/// reconcile logic is tested without a cluster.
#[async_trait]
pub trait ClaimsApi: Send + Sync + 'static {
    /// Delete a claim; one that is already gone is success.
    async fn delete_claim(&self, namespace: &str, name: &str) -> Result<(), WatchError>;
    /// UIDs of every managed claim that exists, for the resync.
    async fn list_claim_uids(&self) -> Result<HashSet<Uuid>, WatchError>;
}

/// The real thing.
pub struct KubeClaimsApi {
    client: Client,
}

impl KubeClaimsApi {
    /// Over this client.
    pub fn new(client: Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl ClaimsApi for KubeClaimsApi {
    async fn delete_claim(&self, namespace: &str, name: &str) -> Result<(), WatchError> {
        let api = Api::<VirtualMachineClaim>::namespaced(self.client.clone(), namespace);
        match api.delete(name, &DeleteParams::default()).await {
            Ok(_) => Ok(()),
            Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
            Err(e) => Err(WatchError::Api(e.to_string())),
        }
    }

    async fn list_claim_uids(&self) -> Result<HashSet<Uuid>, WatchError> {
        let api = Api::<VirtualMachineClaim>::all(self.client.clone());
        let list = api
            .list(&ListParams::default().labels(MANAGED_BY_SELECTOR))
            .await
            .map_err(|e| WatchError::Api(e.to_string()))?;
        Ok(list.items.iter().filter_map(claim_uid_of).collect())
    }
}

/// Why a reconcile pass did not complete. The controller requeues on every variant.
#[derive(Debug, thiserror::Error)]
pub enum WatchError {
    /// Store.
    #[error("store: {0}")]
    Store(#[from] StoreError),
    /// Entries.
    #[error("entries: {0}")]
    Spire(#[from] SpireError),
    /// The reconciler.
    #[error("{0}")]
    Reconcile(String),
    /// The Kubernetes API.
    #[error("kubernetes api: {0}")]
    Api(String),
}

impl From<anyhow::Error> for WatchError {
    fn from(e: anyhow::Error) -> Self {
        Self::Reconcile(e.to_string())
    }
}

/// Where a `Bound` claim stands with respect to a node.
#[derive(Debug, PartialEq, Eq)]
enum Resolution {
    /// A registered, unbanned node with this EK.
    Node(String),
    /// Not resolvable yet; may become so (no certificate, node not registered).
    NotYet(&'static str),
    /// Never resolvable: fail now.
    Refused(String),
}

/// The reconciler, the claims API and the per-claim wait clock.
pub struct Watcher {
    reconciler: Reconciler,
    claims: Arc<dyn ClaimsApi>,
    cfg: WatcherConfig,
    first_unresolved: Mutex<HashMap<Uuid, Instant>>,
    declared: Mutex<HashSet<String>>,
}

impl Watcher {
    /// Over these.
    pub fn new(reconciler: Reconciler, claims: Arc<dyn ClaimsApi>, cfg: WatcherConfig) -> Self {
        Self {
            reconciler,
            claims,
            cfg,
            first_unresolved: Mutex::new(HashMap::new()),
            declared: Mutex::new(HashSet::new()),
        }
    }

    /// Timings.
    pub fn config(&self) -> &WatcherConfig {
        &self.cfg
    }

    /// One pass over a claim object. Idempotent: a repeated event with no change is a
    /// `Hold`.
    pub async fn reconcile_claim(&self, claim: &VirtualMachineClaim) -> Result<Action, WatchError> {
        let name = claim.name_any();
        let namespace = claim.namespace().unwrap_or_default();
        let Some(uid) = claim_uid_of(claim) else {
            tracing::warn!(%name, %namespace, "claim without a UUID uid; ignored");
            return Ok(Action::await_change());
        };
        let phase = phase_of(claim);
        let deleting = claim.metadata.deletion_timestamp.is_some();
        let record = match self.reconciler.store.get_claim(uid).await {
            Ok(r) => r,
            Err(StoreError::NotFound(_)) => {
                tracing::debug!(%uid, %name, %namespace, ?phase, "claim without a record; held");
                return Ok(Action::await_change());
            }
            Err(e) => return Err(e.into()),
        };
        match next_action(Some(phase), record.entry_id.is_some(), deleting) {
            Intent::Hold => {
                self.forget(uid);
                Ok(Action::await_change())
            }
            Intent::Release => {
                self.reconciler.release(uid).await?;
                self.forget(uid);
                Ok(Action::await_change())
            }
            Intent::Bind => match self.resolve(claim).await? {
                Resolution::Node(ek_hash) => {
                    self.reconciler.bind(uid, &ek_hash).await?;
                    self.forget(uid);
                    Ok(Action::await_change())
                }
                Resolution::Refused(reason) => self.fail(claim, uid, &reason).await,
                Resolution::NotYet(reason) => {
                    let waited = self.waited(uid);
                    if waited >= self.cfg.resolve_timeout {
                        self.fail(claim, uid, reason).await
                    } else {
                        tracing::info!(%uid, %name, %namespace, reason, waited_secs = waited.as_secs(), "claim bound but unresolved; retrying");
                        Ok(Action::requeue(self.cfg.requeue))
                    }
                }
            },
        }
    }

    /// The node for a `Bound` claim: the registered node whose EK hash is that of the
    /// certificate banlieue mirrored onto the claim.
    async fn resolve(&self, claim: &VirtualMachineClaim) -> Result<Resolution, WatchError> {
        let certs = claim
            .status
            .as_ref()
            .map_or(&[][..], |s| s.tpm_endorsement_certificates.as_slice());
        if certs.is_empty() {
            return Ok(Resolution::NotYet("no endorsement certificate on the claim"));
        }
        let ek_hash = match ek_hash_from_pems(certs) {
            Ok(h) => h,
            Err(e) => return Ok(Resolution::Refused(format!("endorsement certificate: {e}"))),
        };
        match self.reconciler.store.get_node(&ek_hash).await {
            Ok(node) if node.banned => Ok(Resolution::Refused(format!("node {ek_hash} is banned"))),
            Ok(_) => Ok(Resolution::Node(ek_hash)),
            Err(StoreError::NotFound(_)) => Ok(Resolution::NotYet("no node registered for the claim's EK")),
            Err(e) => Err(e.into()),
        }
    }

    /// Decision 3: the record is revoked (no entry was ever created for it) and the claim
    /// deleted, which makes banlieue destroy the member.
    async fn fail(&self, claim: &VirtualMachineClaim, uid: Uuid, reason: &str) -> Result<Action, WatchError> {
        let name = claim.name_any();
        let namespace = claim.namespace().unwrap_or_default();
        tracing::warn!(%uid, %name, %namespace, reason, "claim failed: record revoked, claim deleted");
        self.reconciler.release(uid).await?;
        self.claims.delete_claim(&namespace, &name).await?;
        self.forget(uid);
        Ok(Action::await_change())
    }

    /// How long this claim has been `Bound` without a node, from the first unresolved pass.
    fn waited(&self, uid: Uuid) -> Duration {
        let mut seen = self.first_unresolved.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        seen.entry(uid).or_insert_with(Instant::now).elapsed()
    }

    fn forget(&self, uid: Uuid) {
        self.first_unresolved
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&uid);
    }

    /// One pass over a pool member: a published endorsement certificate gets a node entry
    /// (ADR-0011 decision 5). No certificate, no entry. Declared once per resync.
    pub async fn reconcile_machine(&self, vm: &VirtualMachine) -> Result<Action, WatchError> {
        let name = vm.name_any();
        let certs = vm
            .status
            .as_ref()
            .map_or(&[][..], |s| s.tpm_endorsement_certificates.as_slice());
        if certs.is_empty() {
            tracing::debug!(vm = %name, "no endorsement certificate yet; no node entry");
            return Ok(Action::await_change());
        }
        let ek_hash = match ek_hash_from_pems(certs) {
            Ok(h) => h,
            Err(e) => {
                tracing::warn!(vm = %name, error = %e, "endorsement certificate unusable; no node entry");
                return Ok(Action::await_change());
            }
        };
        if self
            .declared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&ek_hash)
        {
            return Ok(Action::await_change());
        }
        let entry = self.reconciler.spire.ensure_node_entry(&ek_hash).await?;
        self.declared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(ek_hash.clone());
        tracing::info!(vm = %name, %ek_hash, %entry, "node entry declared");
        Ok(Action::await_change())
    }

    /// Decision 4's backstop: release every bound record whose claim no longer exists,
    /// then sweep orphan entries. Returns (records released, entries swept).
    pub async fn resync(&self) -> Result<(usize, usize), WatchError> {
        let existing = self.claims.list_claim_uids().await?;
        let mut released = 0;
        for rec in self.reconciler.store.list_claims().await? {
            let bound = rec.entry_id.is_some() && rec.revoked_at.is_none();
            if bound && !existing.contains(&rec.uid) {
                tracing::warn!(uid = %rec.uid, "claim object gone; releasing its record");
                self.reconciler.release(rec.uid).await?;
                released += 1;
            }
        }
        let swept = self.reconciler.sweep_orphans().await?;
        self.declared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        Ok((released, swept))
    }
}

/// The claim UID (ADR-0011 decision 1): the object's `metadata.uid`.
#[must_use]
pub fn claim_uid_of(claim: &VirtualMachineClaim) -> Option<Uuid> {
    claim.metadata.uid.as_deref().and_then(|u| Uuid::parse_str(u).ok())
}

/// banlieue's phase as mediatore's; an absent status is `Pending`.
#[must_use]
pub fn phase_of(claim: &VirtualMachineClaim) -> ClaimPhase {
    match claim.status.as_ref().map(|s| s.phase) {
        None | Some(BanlieuePhase::Pending) => ClaimPhase::Pending,
        Some(BanlieuePhase::Bound) => ClaimPhase::Bound,
        Some(BanlieuePhase::Releasing) => ClaimPhase::Releasing,
        Some(BanlieuePhase::Failed) => ClaimPhase::Failed,
    }
}

/// Both controllers and the resync ticker, until the first one ends (they do not end on
/// their own). Run this on the Lease holder only.
pub async fn run(client: Client, watcher: Arc<Watcher>) -> anyhow::Result<()> {
    let requeue = watcher.config().requeue;
    let claims = Controller::new(
        Api::<VirtualMachineClaim>::all(client.clone()),
        watcher::Config::default().labels(MANAGED_BY_SELECTOR),
    )
    .run(
        |claim, w: Arc<Watcher>| async move { w.reconcile_claim(&claim).await },
        move |claim, err, _| {
            tracing::warn!(claim = %claim.name_any(), error = %err, "claim reconcile failed; retrying");
            Action::requeue(requeue)
        },
        watcher.clone(),
    )
    .for_each(|r| async move {
        if let Err(e) = r {
            tracing::warn!(error = %e, "claim controller");
        }
    });
    let machines = Controller::new(
        Api::<VirtualMachine>::all(client),
        watcher::Config::default().labels(LABEL_POOL),
    )
    .run(
        |vm, w: Arc<Watcher>| async move { w.reconcile_machine(&vm).await },
        move |vm, err, _| {
            tracing::warn!(vm = %vm.name_any(), error = %err, "machine reconcile failed; retrying");
            Action::requeue(requeue)
        },
        watcher.clone(),
    )
    .for_each(|r| async move {
        if let Err(e) = r {
            tracing::warn!(error = %e, "machine controller");
        }
    });
    let resync = async {
        let mut tick = tokio::time::interval(watcher.config().resync);
        tick.tick().await;
        loop {
            tick.tick().await;
            match watcher.resync().await {
                Ok((released, swept)) => tracing::info!(released, swept, "resync"),
                Err(e) => tracing::warn!(error = %e, "resync failed"),
            }
        }
    };
    tracing::info!("claim watcher running");
    tokio::select! {
        () = claims => {}
        () = machines => {}
        () = resync => {}
    }
    anyhow::bail!("claim watcher stopped")
}

#[cfg(test)]
mod tests {
    use chrono::Utc;
    use mediatore_proto::{Subject, Workload};
    use mediatore_spire::{EntryManager, MemoryEntries, Naming, claim_entry_name, node_entry_name};
    use mediatore_store::{ClaimRecord, ClaimStore, MemoryStore, NodeRecord};
    use mediatore_testkit::ek::{RSA_EK_HASH, RSA_EK_PEM};
    use serde_json::json;

    use super::*;

    const UID: &str = "6b0a3e9c-1f4d-4c2e-9a7b-0d1e2f3a4b5c";

    struct FakeClaims {
        existing: Mutex<HashSet<Uuid>>,
        deleted: Mutex<Vec<(String, String)>>,
    }

    #[async_trait]
    impl ClaimsApi for FakeClaims {
        async fn delete_claim(&self, namespace: &str, name: &str) -> Result<(), WatchError> {
            self.deleted.lock().unwrap().push((namespace.into(), name.into()));
            Ok(())
        }
        async fn list_claim_uids(&self) -> Result<HashSet<Uuid>, WatchError> {
            Ok(self.existing.lock().unwrap().clone())
        }
    }

    struct Rig {
        watcher: Watcher,
        store: Arc<MemoryStore>,
        entries: Arc<MemoryEntries>,
        claims: Arc<FakeClaims>,
    }

    fn rig(cfg: WatcherConfig) -> Rig {
        let store = Arc::new(MemoryStore::default());
        let entries = Arc::new(MemoryEntries::default());
        let claims = Arc::new(FakeClaims {
            existing: Mutex::new(HashSet::new()),
            deleted: Mutex::new(vec![]),
        });
        let reconciler = Reconciler {
            store: store.clone(),
            spire: entries.clone(),
            naming: Naming {
                trust_domain: "sandbox.test".into(),
            },
        };
        let watcher = Watcher::new(reconciler, claims.clone(), cfg);
        Rig {
            watcher,
            store,
            entries,
            claims,
        }
    }

    fn record(uid: Uuid) -> ClaimRecord {
        ClaimRecord {
            uid,
            name: "claim-x".into(),
            subject: Subject {
                issuer: "https://issuer.example.com".into(),
                id: "octocat".into(),
                display: None,
            },
            entry_id: None,
            node_id: None,
            audiences: vec![],
            workload: Workload {
                image: "ghcr.io/example/workload:1".into(),
                args: vec!["sh".into()],
            },
            ttl_seconds: 600,
            refresh_ciphertext: None,
            created_at: Utc::now(),
            expires_at: None,
            revoked_at: None,
        }
    }

    fn node(ek_hash: &str, banned: bool) -> NodeRecord {
        NodeRecord {
            ek_hash: ek_hash.into(),
            node_id: format!("spiffe://sandbox.test/spire/agent/tpm/{ek_hash}"),
            dmi_uuid: Uuid::new_v4(),
            hostname: "member".into(),
            provider: None,
            banned,
            registered_at: Utc::now(),
        }
    }

    fn claim(phase: &str, certs: &[&str], deleting: bool) -> VirtualMachineClaim {
        let mut meta = json!({
            "name": "claim-x", "namespace": "sandboxes", "uid": UID,
            "labels": { "app.kubernetes.io/managed-by": "mediatore" }
        });
        if deleting {
            meta["deletionTimestamp"] = json!("2026-10-13T12:00:00Z");
        }
        serde_json::from_value(json!({
            "metadata": meta,
            "spec": { "poolRef": { "name": "pool" }, "subject": { "issuer": "https://issuer.example.com", "id": "octocat" }, "ttlSeconds": 600 },
            "status": { "phase": phase, "tpmEndorsementCertificates": certs }
        }))
        .unwrap()
    }

    fn machine(certs: &[&str]) -> VirtualMachine {
        serde_json::from_value(json!({
            "metadata": { "name": "member-1", "namespace": "sandboxes", "uid": Uuid::new_v4().to_string(), "labels": { "banlieue.io/pool": "pool" } },
            "spec": { "classRef": { "name": "small" }, "imageRef": { "name": "sandbox" } },
            "status": { "tpmEndorsementCertificates": certs }
        }))
        .unwrap()
    }

    fn uid() -> Uuid {
        Uuid::parse_str(UID).unwrap()
    }

    #[test]
    fn the_claim_uid_is_the_objects_uid_and_phases_map_one_to_one() {
        assert_eq!(claim_uid_of(&claim("Bound", &[], false)), Some(uid()));
        let mut no_uid = claim("Bound", &[], false);
        no_uid.metadata.uid = Some("not-a-uuid".into());
        assert_eq!(claim_uid_of(&no_uid), None);
        for (b, m) in [
            ("Pending", ClaimPhase::Pending),
            ("Bound", ClaimPhase::Bound),
            ("Releasing", ClaimPhase::Releasing),
            ("Failed", ClaimPhase::Failed),
        ] {
            assert_eq!(phase_of(&claim(b, &[], false)), m, "{b}");
        }
        let mut no_status = claim("Bound", &[], false);
        no_status.status = None;
        assert_eq!(phase_of(&no_status), ClaimPhase::Pending);
    }

    #[tokio::test]
    async fn a_bound_claim_with_a_registered_node_is_bound_by_its_ek() {
        let r = rig(WatcherConfig::default());
        r.store.put_claim(record(uid())).await.unwrap();
        r.store.put_node(node(RSA_EK_HASH, false)).await.unwrap();
        let action = r.watcher.reconcile_claim(&claim("Bound", &[RSA_EK_PEM], false)).await.unwrap();
        assert_eq!(action, Action::await_change());
        let rec = r.store.get_claim(uid()).await.unwrap();
        assert_eq!(rec.entry_id.as_deref(), Some(claim_entry_name(uid()).as_str()));
        assert_eq!(rec.node_id.as_deref(), Some(node(RSA_EK_HASH, false).node_id.as_str()));
        assert!(rec.expires_at.is_some());
        assert!(r.entries.names().contains(&claim_entry_name(uid())));
        // a repeated event is a no-op
        let again = r.watcher.reconcile_claim(&claim("Bound", &[RSA_EK_PEM], false)).await.unwrap();
        assert_eq!(again, Action::await_change());
        assert_eq!(r.entries.names().len(), 1);
    }

    #[tokio::test]
    async fn a_claim_without_a_record_binds_nothing() {
        let r = rig(WatcherConfig::default());
        r.store.put_node(node(RSA_EK_HASH, false)).await.unwrap();
        let action = r.watcher.reconcile_claim(&claim("Bound", &[RSA_EK_PEM], false)).await.unwrap();
        assert_eq!(action, Action::await_change());
        assert_eq!(r.entries.names(), Vec::<String>::new());
        assert_eq!(*r.claims.deleted.lock().unwrap(), Vec::<(String, String)>::new());
    }

    #[tokio::test]
    async fn unresolved_is_retried_then_failed_after_the_timeout() {
        let r = rig(WatcherConfig {
            resolve_timeout: Duration::from_millis(60),
            requeue: Duration::from_millis(5),
            ..WatcherConfig::default()
        });
        r.store.put_claim(record(uid())).await.unwrap();
        // no certificate yet
        let action = r.watcher.reconcile_claim(&claim("Bound", &[], false)).await.unwrap();
        assert_eq!(action, Action::requeue(Duration::from_millis(5)));
        // certificate, but the node never registered
        let action = r.watcher.reconcile_claim(&claim("Bound", &[RSA_EK_PEM], false)).await.unwrap();
        assert_eq!(action, Action::requeue(Duration::from_millis(5)));
        assert_eq!(*r.claims.deleted.lock().unwrap(), Vec::<(String, String)>::new());
        tokio::time::sleep(Duration::from_millis(70)).await;
        let action = r.watcher.reconcile_claim(&claim("Bound", &[RSA_EK_PEM], false)).await.unwrap();
        assert_eq!(action, Action::await_change());
        let rec = r.store.get_claim(uid()).await.unwrap();
        assert!(rec.revoked_at.is_some(), "record revoked");
        assert!(rec.entry_id.is_none(), "no entry was ever declared");
        assert_eq!(r.entries.names(), Vec::<String>::new());
        assert_eq!(*r.claims.deleted.lock().unwrap(), vec![("sandboxes".to_owned(), "claim-x".to_owned())]);
    }

    #[tokio::test]
    async fn a_banned_node_or_an_unusable_certificate_fails_the_claim_at_once() {
        for (certs, banned) in [(vec![RSA_EK_PEM], true), (vec!["-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"], false)] {
            let r = rig(WatcherConfig::default());
            r.store.put_claim(record(uid())).await.unwrap();
            r.store.put_node(node(RSA_EK_HASH, banned)).await.unwrap();
            let action = r.watcher.reconcile_claim(&claim("Bound", &certs, false)).await.unwrap();
            assert_eq!(action, Action::await_change());
            assert!(r.store.get_claim(uid()).await.unwrap().revoked_at.is_some());
            assert_eq!(r.claims.deleted.lock().unwrap().len(), 1);
            assert_eq!(r.entries.names(), Vec::<String>::new());
        }
    }

    #[tokio::test]
    async fn releasing_failed_and_deletion_retract_the_entry_and_cut_off() {
        for (phase, deleting) in [("Releasing", false), ("Failed", false), ("Bound", true)] {
            let r = rig(WatcherConfig::default());
            r.store.put_claim(record(uid())).await.unwrap();
            r.store.put_node(node(RSA_EK_HASH, false)).await.unwrap();
            r.watcher.reconcile_claim(&claim("Bound", &[RSA_EK_PEM], false)).await.unwrap();
            assert_eq!(r.entries.names().len(), 1);
            let action = r.watcher.reconcile_claim(&claim(phase, &[RSA_EK_PEM], deleting)).await.unwrap();
            assert_eq!(action, Action::await_change(), "{phase} deleting={deleting}");
            assert_eq!(r.entries.names(), Vec::<String>::new(), "{phase}: entry retracted");
            assert!(r.store.get_claim(uid()).await.unwrap().revoked_at.is_some(), "{phase}: revoked");
            assert_eq!(*r.claims.deleted.lock().unwrap(), Vec::<(String, String)>::new(), "release never deletes the claim");
        }
    }

    #[tokio::test]
    async fn a_pending_claim_is_held_and_a_released_one_stays_released() {
        let r = rig(WatcherConfig::default());
        r.store.put_claim(record(uid())).await.unwrap();
        r.store.put_node(node(RSA_EK_HASH, false)).await.unwrap();
        assert_eq!(r.watcher.reconcile_claim(&claim("Pending", &[], false)).await.unwrap(), Action::await_change());
        assert_eq!(r.entries.names(), Vec::<String>::new());
        // released once, then Bound again (cannot happen in banlieue, must not rebind here)
        r.watcher.reconcile_claim(&claim("Bound", &[RSA_EK_PEM], false)).await.unwrap();
        r.watcher.reconcile_claim(&claim("Releasing", &[RSA_EK_PEM], false)).await.unwrap();
        r.watcher.reconcile_claim(&claim("Bound", &[RSA_EK_PEM], false)).await.unwrap();
        assert_eq!(r.entries.names(), Vec::<String>::new(), "a revoked record is never bound again");
    }

    #[tokio::test]
    async fn a_member_with_a_certificate_gets_a_node_entry_and_one_without_gets_nothing() {
        let r = rig(WatcherConfig::default());
        assert_eq!(r.watcher.reconcile_machine(&machine(&[])).await.unwrap(), Action::await_change());
        assert_eq!(r.entries.names(), Vec::<String>::new());
        assert_eq!(r.watcher.reconcile_machine(&machine(&["garbage"])).await.unwrap(), Action::await_change());
        assert_eq!(r.entries.names(), Vec::<String>::new(), "an unusable certificate declares nothing");
        r.watcher.reconcile_machine(&machine(&[RSA_EK_PEM])).await.unwrap();
        r.watcher.reconcile_machine(&machine(&[RSA_EK_PEM])).await.unwrap();
        assert_eq!(r.entries.names(), vec![node_entry_name(RSA_EK_HASH)]);
    }

    #[tokio::test]
    async fn resync_releases_bound_records_whose_claim_is_gone_and_sweeps_orphans() {
        let r = rig(WatcherConfig::default());
        let gone = uid();
        let kept = Uuid::new_v4();
        let unbound = Uuid::new_v4();
        for u in [gone, kept, unbound] {
            r.store.put_claim(record(u)).await.unwrap();
        }
        r.store.put_node(node(RSA_EK_HASH, false)).await.unwrap();
        r.watcher.reconcile_claim(&claim("Bound", &[RSA_EK_PEM], false)).await.unwrap();
        let mut kept_claim = claim("Bound", &[RSA_EK_PEM], false);
        kept_claim.metadata.uid = Some(kept.to_string());
        r.watcher.reconcile_claim(&kept_claim).await.unwrap();
        // an entry nobody's record knows about
        r.entries.create_claim_entry(RSA_EK_HASH, Uuid::new_v4(), "sb-0123456789ab").await.unwrap();
        r.claims.existing.lock().unwrap().insert(kept);
        let (released, swept) = r.watcher.resync().await.unwrap();
        assert_eq!((released, swept), (1, 1));
        assert!(r.store.get_claim(gone).await.unwrap().revoked_at.is_some());
        assert!(r.store.get_claim(kept).await.unwrap().revoked_at.is_none());
        assert!(r.store.get_claim(unbound).await.unwrap().revoked_at.is_none(), "never-bound records are not the resync's call");
        assert_eq!(r.entries.names(), vec![claim_entry_name(kept)]);
    }
}
