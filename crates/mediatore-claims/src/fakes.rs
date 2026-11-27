// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Test doubles shared by the `watch` and `sandbox` tests: a fake of the writes the
//! controllers make through the Kubernetes API, and a rig wiring it to the in-memory store
//! and entries. The fake is no more permissive than the API server: an object that does
//! not exist cannot be patched, a create on a taken name returns the existing object (as
//! the 409 path does), and a deletion can be held back the way banlieue's finalizer holds a
//! claim.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use banlieue_api::banlieue::{Provider, VirtualMachine, VirtualMachineClaim};
use jiff::Timestamp;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use kube::ResourceExt;
use mediatore_spire::{MemoryEntries, Naming};
use mediatore_store::{MemoryStore, NodeRecord};
use uuid::Uuid;

use crate::Reconciler;
use crate::policy::BundleCache;
use crate::sandbox::{AgentSandbox, AgentSandboxStatus, FINALIZER};
use crate::watch::{ClaimsApi, WatchError, Watcher, WatcherConfig, claim_uid_of};

type Key = (String, String);

/// The API server, as far as the controllers write to it.
#[derive(Default)]
pub(crate) struct FakeClaims {
    claims: Mutex<HashMap<Key, VirtualMachineClaim>>,
    sandboxes: Mutex<HashMap<Key, AgentSandbox>>,
    /// Claim UIDs reported by `list_claim_uids` beyond those in `claims`.
    existing: Mutex<HashSet<Uuid>>,
    deleted: Mutex<Vec<Key>>,
    hold_deleted: Mutex<bool>,
    patches: Mutex<usize>,
    /// The pool member VMs `list_machines` reports.
    machines: Mutex<Vec<VirtualMachine>>,
    /// Make `list_machines` fail, as an unreachable API server does.
    fail_machines: Mutex<bool>,
    /// The `Provider`s that exist, by namespace and name.
    providers: Mutex<HashMap<Key, Provider>>,
    /// Make every read of a `Provider` fail, as an unreachable API server (or a role
    /// without the verb) does.
    fail_providers: Mutex<bool>,
    /// How many times the `Provider`s were listed.
    provider_reads: Mutex<usize>,
    /// How many times one machine was fetched.
    machine_reads: Mutex<usize>,
}

fn key(namespace: &str, name: &str) -> Key {
    (namespace.to_owned(), name.to_owned())
}

impl FakeClaims {
    pub(crate) fn sandbox(&self, namespace: &str, name: &str) -> Option<AgentSandbox> {
        self.sandboxes
            .lock()
            .unwrap()
            .get(&key(namespace, name))
            .cloned()
    }

    pub(crate) fn put_machine(&self, vm: VirtualMachine) {
        self.machines.lock().unwrap().push(vm);
    }

    pub(crate) fn fail_machine_listing(&self, fail: bool) {
        *self.fail_machines.lock().unwrap() = fail;
    }

    /// Replace the pool member VMs that exist.
    pub(crate) fn set_machines(&self, vms: Vec<VirtualMachine>) {
        *self.machines.lock().unwrap() = vms;
    }

    /// Create or replace a `Provider`.
    pub(crate) fn put_provider(&self, provider: Provider) {
        let k = key(
            &provider.namespace().unwrap_or_default(),
            &provider.name_any(),
        );
        self.providers.lock().unwrap().insert(k, provider);
    }

    pub(crate) fn remove_provider(&self, namespace: &str, name: &str) {
        self.providers.lock().unwrap().remove(&key(namespace, name));
    }

    pub(crate) fn fail_provider_reads(&self, fail: bool) {
        *self.fail_providers.lock().unwrap() = fail;
    }

    /// How many times a `Provider` was read.
    pub(crate) fn provider_reads(&self) -> usize {
        *self.provider_reads.lock().unwrap()
    }

    /// How many times one machine was fetched.
    pub(crate) fn machine_reads(&self) -> usize {
        *self.machine_reads.lock().unwrap()
    }

    fn read_provider(&self) -> Result<(), WatchError> {
        *self.provider_reads.lock().unwrap() += 1;
        if *self.fail_providers.lock().unwrap() {
            return Err(WatchError::Api(
                "providers.banlieue.io is forbidden or unreachable".into(),
            ));
        }
        Ok(())
    }

    pub(crate) fn put_sandbox(&self, sb: AgentSandbox) {
        let k = key(&sb.namespace().unwrap_or_default(), &sb.name_any());
        self.sandboxes.lock().unwrap().insert(k, sb);
    }

    pub(crate) fn claim(&self, namespace: &str, name: &str) -> Option<VirtualMachineClaim> {
        self.claims
            .lock()
            .unwrap()
            .get(&key(namespace, name))
            .cloned()
    }

    pub(crate) fn put_claim(&self, claim: VirtualMachineClaim) {
        let k = key(&claim.namespace().unwrap_or_default(), &claim.name_any());
        self.claims.lock().unwrap().insert(k, claim);
    }

    pub(crate) fn remove_claim(&self, namespace: &str, name: &str) {
        self.claims.lock().unwrap().remove(&key(namespace, name));
    }

    /// Merge `status` into the claim's status, as banlieue's controller would.
    pub(crate) fn patch_claim_status(
        &self,
        namespace: &str,
        name: &str,
        status: &serde_json::Value,
    ) {
        let mut claims = self.claims.lock().unwrap();
        let claim = claims.get_mut(&key(namespace, name)).expect("claim exists");
        let mut v = serde_json::to_value(&*claim).unwrap();
        let st = v["status"]
            .as_object_mut()
            .map(std::mem::take)
            .unwrap_or_default();
        let mut merged = serde_json::Value::Object(st);
        for (k, val) in status.as_object().unwrap() {
            merged[k] = val.clone();
        }
        v["status"] = merged;
        *claim = serde_json::from_value(v).unwrap();
    }

    /// Whether `delete_claim` marks the claim deleting (a finalizer holds it) rather than
    /// removing it outright.
    pub(crate) fn hold_deleted_claims(&self, hold: bool) {
        *self.hold_deleted.lock().unwrap() = hold;
    }

    pub(crate) fn mark_existing(&self, uid: Uuid) {
        self.existing.lock().unwrap().insert(uid);
    }

    pub(crate) fn deleted(&self) -> Vec<Key> {
        self.deleted.lock().unwrap().clone()
    }

    /// How many sandbox patches (status or finalizer) were made.
    pub(crate) fn patches(&self) -> usize {
        *self.patches.lock().unwrap()
    }
}

#[async_trait]
impl ClaimsApi for FakeClaims {
    async fn delete_claim(&self, namespace: &str, name: &str) -> Result<(), WatchError> {
        self.deleted.lock().unwrap().push(key(namespace, name));
        let mut claims = self.claims.lock().unwrap();
        if *self.hold_deleted.lock().unwrap() {
            if let Some(c) = claims.get_mut(&key(namespace, name)) {
                c.metadata.deletion_timestamp =
                    Some(Time(k8s_openapi::jiff::Timestamp::UNIX_EPOCH));
            }
        } else {
            claims.remove(&key(namespace, name));
        }
        Ok(())
    }

    async fn list_machines(&self) -> Result<Vec<VirtualMachine>, WatchError> {
        if *self.fail_machines.lock().unwrap() {
            return Err(WatchError::Api("the API server is unreachable".into()));
        }
        Ok(self.machines.lock().unwrap().clone())
    }

    async fn get_machine(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Option<VirtualMachine>, WatchError> {
        *self.machine_reads.lock().unwrap() += 1;
        if *self.fail_machines.lock().unwrap() {
            return Err(WatchError::Api("the API server is unreachable".into()));
        }
        Ok(self
            .machines
            .lock()
            .unwrap()
            .iter()
            .find(|vm| vm.namespace().as_deref() == Some(namespace) && vm.name_any() == name)
            .cloned())
    }

    async fn list_providers(&self) -> Result<Vec<Provider>, WatchError> {
        self.read_provider()?;
        Ok(self.providers.lock().unwrap().values().cloned().collect())
    }

    async fn list_claim_uids(&self) -> Result<HashSet<Uuid>, WatchError> {
        let mut all = self.existing.lock().unwrap().clone();
        all.extend(
            self.claims
                .lock()
                .unwrap()
                .values()
                .filter_map(claim_uid_of),
        );
        Ok(all)
    }

    async fn get_claim(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Option<VirtualMachineClaim>, WatchError> {
        Ok(self.claim(namespace, name))
    }

    async fn create_claim(
        &self,
        mut claim: VirtualMachineClaim,
    ) -> Result<VirtualMachineClaim, WatchError> {
        let k = key(&claim.namespace().unwrap_or_default(), &claim.name_any());
        let mut claims = self.claims.lock().unwrap();
        if let Some(existing) = claims.get(&k) {
            return Ok(existing.clone());
        }
        claim
            .metadata
            .uid
            .get_or_insert_with(|| Uuid::new_v4().to_string());
        claim.metadata.creation_timestamp = Some(Time(Timestamp::now()));
        claims.insert(k, claim.clone());
        Ok(claim)
    }

    async fn patch_sandbox_status(
        &self,
        namespace: &str,
        name: &str,
        status: &AgentSandboxStatus,
    ) -> Result<(), WatchError> {
        let mut sbs = self.sandboxes.lock().unwrap();
        let sb = sbs
            .get_mut(&key(namespace, name))
            .ok_or_else(|| WatchError::Api(format!("agentsandboxes \"{name}\" not found")))?;
        // A merge patch, as the API server applies it: the reconciler's patch never names the
        // record (ADR-0034) or the trip summary (ADR-0069 decision 9), so what the store wrote
        // of each stays.
        let kept = sb.status.as_ref().and_then(|held| held.record.clone());
        let trips = sb.status.as_ref().and_then(|held| held.tripwires.clone());
        let mut next = status.clone();
        if next.record.is_none() {
            next.record = kept;
        }
        if next.tripwires.is_none() {
            next.tripwires = trips;
        }
        sb.status = Some(next);
        *self.patches.lock().unwrap() += 1;
        Ok(())
    }

    async fn set_sandbox_finalizer(
        &self,
        sb: &AgentSandbox,
        present: bool,
    ) -> Result<(), WatchError> {
        let name = sb.name_any();
        let mut sbs = self.sandboxes.lock().unwrap();
        let held = sbs
            .get_mut(&key(&sb.namespace().unwrap_or_default(), &name))
            .ok_or_else(|| WatchError::Api(format!("agentsandboxes \"{name}\" not found")))?;
        let mut fins: Vec<String> = held
            .finalizers()
            .iter()
            .filter(|f| *f != FINALIZER)
            .cloned()
            .collect();
        if present {
            fins.push(FINALIZER.into());
        }
        held.metadata.finalizers = Some(fins);
        *self.patches.lock().unwrap() += 1;
        Ok(())
    }
}

pub(crate) struct Rig {
    pub(crate) watcher: Watcher,
    pub(crate) store: Arc<MemoryStore>,
    pub(crate) entries: Arc<MemoryEntries>,
    pub(crate) claims: Arc<FakeClaims>,
}

/// A rig with no `policy` section: no bundle is read, no sandbox compared.
pub(crate) fn rig(cfg: WatcherConfig) -> Rig {
    rig_with(cfg, None)
}

/// A rig whose watcher reads `bundles`, the cache a reflector fills.
pub(crate) fn rig_with(cfg: WatcherConfig, bundles: Option<Arc<BundleCache>>) -> Rig {
    let store = Arc::new(MemoryStore::default());
    let entries = Arc::new(MemoryEntries::in_trust_domain("sandbox.test"));
    let claims = Arc::new(FakeClaims::default());
    let reconciler = Reconciler {
        store: store.clone(),
        spire: entries.clone(),
        naming: Naming {
            trust_domain: "sandbox.test".into(),
        },
    };
    let mut watcher = Watcher::new(reconciler, claims.clone(), cfg);
    if let Some(bundles) = bundles {
        watcher = watcher.with_bundles(bundles);
    }
    Rig {
        watcher,
        store,
        entries,
        claims,
    }
}

/// A registered TPM node: keyed by its EK hash, with the agent ID that hash gives.
pub(crate) fn node(ek_hash: &str, banned: bool) -> NodeRecord {
    NodeRecord {
        ek_hash: ek_hash.into(),
        node_id: format!("spiffe://sandbox.test/spire/agent/tpm/{ek_hash}"),
        dmi_uuid: Uuid::new_v4(),
        hostname: "member".into(),
        provider: None,
        banned,
        registered_at: Timestamp::now(),
    }
}
