// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The claim watcher (ADR-0011): banlieue's `VirtualMachineClaim` and `VirtualMachine`
//! events drive [`Reconciler::bind`] and [`Reconciler::release`] and declare node entries.
//!
//! One [`Watcher`] holds the reconciler and the per-claim state (when a `Bound` claim was
//! first seen unresolved). Its reconcile functions (two here, the `AgentSandbox` one in
//! [`crate::sandbox`]) are plain async methods, tested against the in-memory store and
//! entries; [`run`] wraps them in kube-runtime `Controller`s and is meant to execute on
//! the replica holding the Lease (`crate::lease`).
//!
//! What binds a claim: its `metadata.uid` is the claim UID, and the node is the one that
//! registered under the EK hash of the certificate banlieue mirrored onto the claim.
//! Nothing else is consulted (decision 2). A machine of a pool the operator listed in
//! `watcher.x509pop_pools` has no EK to go by (ADR-0049 decisions 9 and 10): its node is the
//! one registered under the key of the `x509pop` agent ID its host's CA and its
//! `attestationSubject` give, and its EK is never consulted, whatever it publishes. Unresolved for longer than
//! `resolve_timeout` fails the claim: record revoked, claim deleted (decision 3).

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use banlieue_api::banlieue::{
    ClaimPhase as BanlieuePhase, LABEL_POOL, Provider, VirtualMachine, VirtualMachineClaim,
};
use futures::{Stream, StreamExt};
use kube::api::{DeleteParams, ListParams, Patch, PatchParams, PostParams};
use kube::runtime::controller::{self, Action, Controller};
use kube::runtime::reflector::{self, ObjectRef, Store, reflector};
use kube::runtime::{WatchStreamExt as _, watcher};
use kube::{Api, Client, ResourceExt};
use mediatore_proto::ClaimPhase;
use mediatore_proto::ek::ek_hash_from_pems;
use mediatore_spire::x509pop::{X509popInput, agent_id_for, certificate_identities, node_key};
use mediatore_spire::{NODE_ENTRY_PREFIX, NodeAttestation, NodeIdentity, SpireError};
use mediatore_store::StoreError;
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::nodegc::{self, MAX_DELETIONS_PER_PASS, ek_hashes_of};
use crate::policy::{BundleCache, PolicyKey};
use crate::sandbox::{AgentSandbox, AgentSandboxStatus, FINALIZER};
use crate::shadow::Audience;
use crate::{Action as Intent, Reconciler, next_action};

/// Label mediatore puts on every object it creates; the watcher looks at nothing else.
pub const MANAGED_BY_SELECTOR: &str = "app.kubernetes.io/managed-by=mediatore";

/// Timings (ADR-0011 decisions 3 and 4) and what an `AgentSandbox` may ask for
/// (ADR-0008 decision 7). The defaults configure nothing: a sandbox naming any audience
/// or issuer is refused until `mediatore.yaml` lists them (fail closed).
#[derive(Clone, Debug)]
pub struct WatcherConfig {
    /// Between resyncs: release records whose claim is gone, sweep orphan entries.
    pub resync: Duration,
    /// How long a `Bound` claim may stay unresolved before it is failed.
    pub resolve_timeout: Duration,
    /// Between retries while unresolved, and between polls of a sandbox whose claim is
    /// `Bound` but whose entry is not set yet.
    pub requeue: Duration,
    /// Audiences mediatore serves, as configured; a sandbox may request a subset, and the
    /// shadow comparison (ADR-0026 decision 7) reads what each would allow.
    pub audiences: Vec<Audience>,
    /// ADR-0053: per scoped audience, its rules per namespace. A sandbox in a namespace an audience
    /// does not list may not name it (refused as not configured), and the shadow comparison reads that
    /// namespace's rules. An audience absent from the map is unscoped.
    pub scopes: std::collections::BTreeMap<
        String,
        std::collections::BTreeMap<String, Vec<mediatore_proto::EndpointRule>>,
    >,
    /// Issuers mediatore trusts; a sandbox's subject must come from one.
    pub issuers: Vec<String>,
    /// `sandboxes.declarative_issuers`, resolved (ADR-0072 decision 4): the issuers a sandbox
    /// the broker did not create through its API may name. With one issuer and the key not
    /// written, that issuer; with two or more and the key not written, none; written, exactly
    /// the list. A sandbox created by hand naming any other is refused before its claim.
    pub declarative_issuers: Vec<String>,
    /// `sandboxes.max_ttl_seconds` (ADR-0008 decision 9, amended 2026-11-26): the longest
    /// lifetime a sandbox may ask for, with or without a policy. A `ttlSeconds` above it fails
    /// the sandbox before any claim exists; a policy's lease only narrows it.
    pub max_ttl_seconds: u32,
    /// Per audience of `role: registry`, the registries it serves (ADR-0063 decision 2): with gateways, a sandbox
    /// whose image is on a registry none of its audiences in this map serves fails before any claim exists. `None`
    /// without gateways, where nothing is refused by registry.
    pub registry_audiences:
        Option<std::collections::BTreeMap<String, std::collections::BTreeSet<String>>>,
    /// The registries that are gateway-placed audiences (ADR-0043 decision 1), by the name an image reference carries,
    /// each with its audience: a sandbox whose image is on one must name that audience.
    pub placed_registries: std::collections::BTreeMap<String, String>,
    /// How long a claim row outlives its claim before the resync sweeps it into the audit
    /// table (ADR-0012 decision 4).
    pub retention: Duration,
    /// `policy.egress` (ADR-0030): decides whether a bundle's direct egress is `P006` or,
    /// as the broker serves it, only its unservable entries are `P007`.
    pub egress_mode: crate::policy::EgressMode,
    /// `policy.audiences` (ADR-0053 decisions 9 to 16): under `Enforce` a sandbox is refused unless
    /// its policy resolves to a verified bundle that grants what it asks for.
    pub audiences_mode: crate::policy::EgressMode,
    /// `policy.sources` (ADR-0054): which policy namespaces each sandbox namespace draws
    /// from. The default maps nothing, so every namespace draws from itself alone.
    pub policy_sources: crate::policy::PolicySources,
    /// The audiences served from the requester's own credential (`via: delegated`,
    /// ADR-0035). A sandbox naming one whose delegation did not reach its record is
    /// refused before the claim binds a VM.
    pub delegated_audiences: std::collections::BTreeSet<String>,
    /// A node younger than this is never collected (ADR-0039): its registration may
    /// precede its VM's published endorsement certificate. `store.node_grace_secs`.
    pub node_grace: Duration,
    /// `logs.enabled` (ADR-0045 decision 11): whether this broker stores a workload's output.
    /// Off, a sandbox whose `workload.logs` is `true` is refused before any claim exists.
    pub logs_enabled: bool,
    /// `logs.retention` (ADR-0045 decision 4): how long a claim's stored output outlives the
    /// claim's end before the resync sweeps it. Only read when `logs_enabled`.
    pub logs_retention: Duration,
    /// ADR-0055: under `policy.audience_definitions.mode: bundles`, the audience catalog, which
    /// then answers every audience question here in place of `audiences`, `scopes` and
    /// `delegated_audiences` (empty in that mode). `None`: the file answers.
    pub catalog: Option<std::sync::Arc<crate::audience::LiveCatalog>>,
    /// `watcher.x509pop_pools` (ADR-0049 decision 9): the pools, as `<namespace>/<pool>`,
    /// whose machines attest with `x509pop`. A machine is of the pool its `banlieue.io/pool`
    /// label names, in its own namespace. Every other machine is `tpm`. Empty by default:
    /// then nothing here reads a Provider or a machine's subject.
    pub x509pop_pools: std::collections::BTreeSet<String>,
    /// `watcher.provider_namespace` (ADR-0049 decision 10, banlieue ADR-0133): where a
    /// machine's Provider is looked for when the machine's own namespace holds none.
    pub provider_namespace: Option<String>,
}

impl WatcherConfig {
    /// The catalog's definition of `audience` as a sandbox in `namespace` resolves it now.
    fn resolved(&self, audience: &str, namespace: &str) -> Option<crate::audience::Audience> {
        let catalog = self.catalog.as_ref()?.snapshot();
        catalog
            .resolve(namespace, audience, jiff::Timestamp::now())
            .ok()
            .map(|a| (**a).clone())
    }

    /// Under the catalog, whether a sandbox in `namespace` must wait: the platform namespace or
    /// its own has not completed its first list, so a missing audience may simply be unread. Its
    /// spec is immutable, so a refusal now would be for good.
    #[must_use]
    pub fn audiences_unread(&self, namespace: &str) -> bool {
        self.catalog
            .as_ref()
            .is_some_and(|c| !c.ready_for(namespace))
    }

    /// Whether a sandbox in `namespace` may name `audience` at all: configured and in scope
    /// (the file), or resolvable from there (the catalog, ADR-0055 decision 3).
    #[must_use]
    pub fn usable(&self, audience: &str, namespace: &str) -> bool {
        if self.catalog.is_some() {
            return self.resolved(audience, namespace).is_some();
        }
        self.audiences.iter().any(|c| c.name == audience) && self.scope_allows(audience, namespace)
    }

    /// Whether `audience` is served from the requester's own credential for a sandbox in
    /// `namespace` (ADR-0035).
    #[must_use]
    pub fn is_delegated(&self, audience: &str, namespace: &str) -> bool {
        if self.catalog.is_some() {
            return self.resolved(audience, namespace).is_some_and(|a| {
                a.definition.credential.backend == mediatore_policy::types::Backend::Delegated
            });
        }
        self.delegated_audiences.contains(audience)
    }

    /// ADR-0053 decision 4: may a sandbox in `namespace` name `audience`? An unscoped audience is
    /// usable everywhere; a scoped one only where it lists the namespace.
    #[must_use]
    pub fn scope_allows(&self, audience: &str, namespace: &str) -> bool {
        self.scopes
            .get(audience)
            .is_none_or(|per| per.contains_key(namespace))
    }

    /// ADR-0053 decision 11: whether `bundle` grants a sandbox in `namespace` the audience in a way the
    /// broker's own configuration (the ceiling, the namespace's file grant, the endpoints) leaves usable.
    #[must_use]
    pub fn grants(
        &self,
        namespace: &str,
        audience: &str,
        bundle: &mediatore_policy::BundlePayload,
    ) -> bool {
        let Some(grant) = bundle.content.audiences.iter().find(|g| g.name == audience) else {
            return false;
        };
        if self.catalog.is_some() {
            // ADR-0055 decision 6: the definition's rules are the ceiling, its endpoints the egress.
            // Decision 3: a team audience only by a policy of its own namespace.
            return self.resolved(audience, namespace).is_some_and(|a| {
                (a.kind == crate::audience::AudienceKind::Platform
                    || bundle.content.policy.namespace == a.namespace)
                    && crate::policy::effective_grant(&a.rules, None, &a.endpoints, grant).is_some()
            });
        }
        let Some(configured) = self.audiences.iter().find(|a| a.name == audience) else {
            return false;
        };
        let file = self
            .scopes
            .get(audience)
            .and_then(|per| per.get(namespace))
            .map(Vec::as_slice);
        crate::policy::effective_grant(&configured.rules, file, &configured.egress, grant).is_some()
    }

    /// The audiences as a sandbox in `namespace` meets them (ADR-0053 decision 8): the ones its
    /// namespace may use, a scoped one carrying that namespace's rules, so the shadow comparison
    /// judges what the claim can actually do.
    #[must_use]
    pub fn audiences_in(&self, namespace: &str) -> Vec<Audience> {
        if let Some(live) = &self.catalog {
            let catalog = live.snapshot();
            let now = jiff::Timestamp::now();
            return catalog
                .visible_from(namespace, now)
                .filter(|a| {
                    catalog
                        .resolve(namespace, &a.name, now)
                        .is_ok_and(|r| std::sync::Arc::ptr_eq(r, a))
                })
                .map(|a| Audience {
                    name: a.name.clone(),
                    max_ttl: i64::from(a.definition.max_ttl_seconds),
                    egress: a.endpoints.clone(),
                    rules: a.rules.clone(),
                })
                .collect();
        }
        self.audiences
            .iter()
            .filter(|a| self.scope_allows(&a.name, namespace))
            .map(|a| {
                let mut a = a.clone();
                if let Some(rules) = self.scopes.get(&a.name).and_then(|per| per.get(namespace)) {
                    a.rules = rules.clone();
                }
                a
            })
            .collect()
    }
}

impl Default for WatcherConfig {
    fn default() -> Self {
        Self {
            resync: Duration::from_mins(5),
            resolve_timeout: Duration::from_secs(60),
            requeue: Duration::from_secs(5),
            audiences: vec![],
            scopes: std::collections::BTreeMap::new(),
            issuers: vec![],
            declarative_issuers: vec![],
            max_ttl_seconds: mediatore_proto::DEFAULT_MAX_TTL_SECONDS,
            registry_audiences: None,
            placed_registries: std::collections::BTreeMap::new(),
            retention: Duration::from_hours(1),
            egress_mode: crate::policy::EgressMode::default(),
            audiences_mode: crate::policy::EgressMode::default(),
            policy_sources: crate::policy::PolicySources::default(),
            delegated_audiences: std::collections::BTreeSet::new(),
            catalog: None,
            node_grace: Duration::from_mins(10),
            logs_enabled: false,
            logs_retention: Duration::from_hours(1),
            x509pop_pools: std::collections::BTreeSet::new(),
            provider_namespace: None,
        }
    }
}

/// What the controllers write through the API (claims, and the `AgentSandbox` status and
/// finalizer), behind a trait so the reconcile logic is tested without a cluster.
#[async_trait]
pub trait ClaimsApi: Send + Sync + 'static {
    /// Delete a claim; one that is already gone is success.
    async fn delete_claim(&self, namespace: &str, name: &str) -> Result<(), WatchError>;
    /// UIDs of every managed claim that exists, for the resync.
    async fn list_claim_uids(&self) -> Result<HashSet<Uuid>, WatchError>;
    /// Every pool member VM that exists, for collecting the nodes of those that do not
    /// (ADR-0039). A failed listing is an error, never an empty list.
    async fn list_machines(&self) -> Result<Vec<VirtualMachine>, WatchError>;
    /// One pool member VM, if it exists: the machine a `Bound` claim names, read to learn
    /// its pool and, for an `x509pop` pool, what its node entry was declared from.
    async fn get_machine(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Option<VirtualMachine>, WatchError>;
    /// Every `Provider` in the cluster, for the host CA each asserts (ADR-0049 decision
    /// 10): the one a machine was placed on, and every other one, since two that assert
    /// different CAs under one common name are refused both. A failed listing is an error,
    /// never an empty list.
    async fn list_providers(&self) -> Result<Vec<Provider>, WatchError>;
    /// One claim, if it exists.
    async fn get_claim(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Option<VirtualMachineClaim>, WatchError>;
    /// Create a claim; a name already taken returns the existing object.
    async fn create_claim(
        &self,
        claim: VirtualMachineClaim,
    ) -> Result<VirtualMachineClaim, WatchError>;
    /// Replace a sandbox's status (the `status` subresource).
    async fn patch_sandbox_status(
        &self,
        namespace: &str,
        name: &str,
        status: &AgentSandboxStatus,
    ) -> Result<(), WatchError>;
    /// Add or remove mediatore's finalizer on a sandbox, against the version `sandbox`
    /// carries (a concurrent change is a conflict, retried by the controller).
    async fn set_sandbox_finalizer(
        &self,
        sandbox: &AgentSandbox,
        present: bool,
    ) -> Result<(), WatchError>;
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

    async fn list_machines(&self) -> Result<Vec<VirtualMachine>, WatchError> {
        Api::<VirtualMachine>::all(self.client.clone())
            .list(&ListParams::default().labels(LABEL_POOL))
            .await
            .map(|list| list.items)
            .map_err(|e| WatchError::Api(e.to_string()))
    }

    async fn get_machine(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Option<VirtualMachine>, WatchError> {
        Api::<VirtualMachine>::namespaced(self.client.clone(), namespace)
            .get_opt(name)
            .await
            .map_err(|e| WatchError::Api(e.to_string()))
    }

    async fn list_providers(&self) -> Result<Vec<Provider>, WatchError> {
        Api::<Provider>::all(self.client.clone())
            .list(&ListParams::default())
            .await
            .map(|list| list.items)
            .map_err(|e| WatchError::Api(e.to_string()))
    }

    async fn get_claim(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Option<VirtualMachineClaim>, WatchError> {
        Api::<VirtualMachineClaim>::namespaced(self.client.clone(), namespace)
            .get_opt(name)
            .await
            .map_err(|e| WatchError::Api(e.to_string()))
    }

    async fn create_claim(
        &self,
        claim: VirtualMachineClaim,
    ) -> Result<VirtualMachineClaim, WatchError> {
        let namespace = claim.namespace().unwrap_or_default();
        let api = Api::<VirtualMachineClaim>::namespaced(self.client.clone(), &namespace);
        match api.create(&PostParams::default(), &claim).await {
            Ok(created) => Ok(created),
            Err(kube::Error::Api(e)) if e.code == 409 => api
                .get(&claim.name_any())
                .await
                .map_err(|e| WatchError::Api(e.to_string())),
            Err(e) => Err(WatchError::Api(e.to_string())),
        }
    }

    async fn patch_sandbox_status(
        &self,
        namespace: &str,
        name: &str,
        status: &AgentSandboxStatus,
    ) -> Result<(), WatchError> {
        Api::<AgentSandbox>::namespaced(self.client.clone(), namespace)
            .patch_status(
                name,
                &PatchParams::default(),
                &Patch::Merge(serde_json::json!({ "status": status })),
            )
            .await
            .map(|_| ())
            .map_err(|e| WatchError::Api(e.to_string()))
    }

    async fn set_sandbox_finalizer(
        &self,
        sandbox: &AgentSandbox,
        present: bool,
    ) -> Result<(), WatchError> {
        let namespace = sandbox.namespace().unwrap_or_default();
        let mut finalizers: Vec<String> = sandbox
            .finalizers()
            .iter()
            .filter(|f| *f != FINALIZER)
            .cloned()
            .collect();
        if present {
            finalizers.push(FINALIZER.to_owned());
        }
        // A merge patch carrying the resourceVersion is an optimistic update: a concurrent
        // change is a 409, and the controller retries.
        let patch = serde_json::json!({ "metadata": {
            "resourceVersion": sandbox.resource_version(),
            "finalizers": finalizers,
        }});
        Api::<AgentSandbox>::namespaced(self.client.clone(), &namespace)
            .patch(
                &sandbox.name_any(),
                &PatchParams::default(),
                &Patch::Merge(patch),
            )
            .await
            .map(|_| ())
            .map_err(|e| WatchError::Api(e.to_string()))
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
    /// A registered, unbanned node: its key and its stored agent ID.
    Node(NodeIdentity),
    /// Not resolvable yet; may become so (no certificate, node not registered).
    NotYet(String),
    /// Never resolvable: fail now.
    Refused(String),
}

/// How a pool member attests, as far as what it publishes says. Which of the two attestors
/// applies is never read from here: it is the pool list's statement (ADR-0049 decision 9),
/// and this is what that attestor's data gives.
#[derive(Debug, PartialEq, Eq)]
enum MachineNode {
    /// The attestation its node entry is declared from.
    Known(NodeAttestation),
    /// Nothing to go by yet; the cause, which may pass and is the machine's own to bring (no
    /// certificate, no subject, no placement): a machine still being provisioned.
    NotYet(String),
    /// Nothing to go by yet because the machine's Provider is not found: the cause, which
    /// may pass and is the administrators' (a Provider deleted and applied again).
    NoProvider(String),
    /// What is published cannot give a node; the cause, which does not pass by waiting.
    Unusable(String),
}

/// The `Provider`s as one pass reads them: listed once, on first need, and kept for the
/// pass (a machine reconcile, a claim resolution, one collection), however many machines of
/// an `x509pop` pool it looks at.
#[derive(Default)]
struct ProviderPass {
    all: Option<Vec<Provider>>,
}

/// What a listed pool's machines give a collection pass.
struct LiveKeys {
    /// The node key of every machine that gives one, of both kinds.
    keys: HashSet<String>,
    /// Some machine of an `x509pop` pool gave none because something is only missing (its
    /// subject, its placement, its Provider): the x509pop keys are not all there.
    x509pop_incomplete: bool,
}

/// A machine's Provider among `all`, with the namespace it was found in: the one of that
/// name in the machine's namespace when that namespace holds any Provider at all, and only
/// when it holds none, the one in `shared` (`watcher.provider_namespace`) if that is set
/// (banlieue ADR-0133 decision 1, which the controller that placed the machine follows).
fn provider_of<'p>(
    all: &'p [Provider],
    namespace: &str,
    shared: Option<&str>,
    name: &str,
) -> Option<(String, &'p Provider)> {
    let within = |ns: &str| {
        let ns = ns.to_owned();
        all.iter()
            .filter(move |p| p.namespace().as_deref() == Some(ns.as_str()))
    };
    let from = if within(namespace).next().is_some() {
        namespace
    } else {
        shared.filter(|shared| *shared != namespace)?
    };
    within(from)
        .find(|p| p.name_any() == name)
        .map(|p| (from.to_owned(), p))
}

/// Another Provider than `own` that asserts, inline, a *different* certificate under the
/// common name `cn`: `<namespace>/<name>` of the first in name order. The same certificate
/// on two Providers is one CA said twice and is no rival. The agent ID is issuer-qualified
/// by name (ADR-0049 decision 2), so two CAs under one name could each mint the other
/// host's guests' identities: neither is given a node entry.
fn rival_host_ca(
    all: &[Provider],
    own: (&str, &str),
    cn: &str,
    fingerprint: &str,
) -> Option<String> {
    let mut rivals: Vec<String> = all
        .iter()
        .filter(|p| {
            (
                p.namespace().unwrap_or_default().as_str(),
                p.name_any().as_str(),
            ) != own
        })
        .filter(|p| {
            p.spec
                .attestation
                .as_ref()
                .and_then(|a| a.host_ca.as_ref())
                .and_then(|ca| ca.inline.as_deref())
                .and_then(|pem| certificate_identities(pem).ok())
                .is_some_and(|ids| ids.iter().any(|(n, f)| n == cn && f != fingerprint))
        })
        .map(|p| format!("{}/{}", p.namespace().unwrap_or_default(), p.name_any()))
        .collect();
    rivals.sort();
    rivals.into_iter().next()
}

/// `<namespace>/<pool>` of a pool member: the pool its `banlieue.io/pool` label names.
fn pool_key(vm: &VirtualMachine) -> Option<String> {
    let pool = vm.labels().get(LABEL_POOL)?;
    Some(format!("{}/{pool}", vm.namespace().unwrap_or_default()))
}

/// The reconciler, the claims API and the per-claim wait clock.
pub struct Watcher {
    pub(crate) reconciler: Reconciler,
    pub(crate) claims: Arc<dyn ClaimsApi>,
    pub(crate) cfg: WatcherConfig,
    /// notaio's verified bundles (ADR-0026), filled by the reflector on every replica;
    /// `None` with no `policy` section, and then no sandbox is compared.
    pub(crate) bundles: Option<Arc<BundleCache>>,
    first_unresolved: Mutex<HashMap<Uuid, Instant>>,
    declared: Mutex<HashSet<String>>,
}

impl Watcher {
    /// Over these, with an empty bundle cache.
    pub fn new(reconciler: Reconciler, claims: Arc<dyn ClaimsApi>, cfg: WatcherConfig) -> Self {
        Self {
            reconciler,
            claims,
            cfg,
            bundles: None,
            first_unresolved: Mutex::new(HashMap::new()),
            declared: Mutex::new(HashSet::new()),
        }
    }

    /// With the reflector's cache: a record created for a sandbox naming a policy carries
    /// the bundle it was admitted under (ADR-0026 decision 6), and every sandbox is compared
    /// with its policy's bundle (decision 7).
    #[must_use]
    pub fn with_bundles(mut self, bundles: Arc<BundleCache>) -> Self {
        self.bundles = Some(bundles);
        self
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
                // A Bound claim's record may be about to arrive (the sandbox reconciler
                // writes it right after creating the claim, ADR-0008); nothing else raises
                // an event here when it does, so poll. Anything not Bound has nothing to do.
                tracing::debug!(%uid, %name, %namespace, ?phase, "claim without a record; held");
                return Ok(if phase == ClaimPhase::Bound && !deleting {
                    Action::requeue(self.cfg.requeue)
                } else {
                    Action::await_change()
                });
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
                Resolution::Node(node) => {
                    self.reconciler.bind(uid, &node).await?;
                    self.forget(uid);
                    Ok(Action::await_change())
                }
                Resolution::Refused(reason) => self.fail(claim, uid, &reason).await,
                Resolution::NotYet(reason) => {
                    let waited = self.waited(uid);
                    if waited >= self.cfg.resolve_timeout {
                        self.fail(claim, uid, &reason).await
                    } else {
                        tracing::info!(%uid, %name, %namespace, reason, waited_secs = waited.as_secs(), "claim bound but unresolved; retrying");
                        Ok(Action::requeue(self.cfg.requeue))
                    }
                }
            },
        }
    }

    /// Whether the operator listed this machine's pool as `x509pop` (ADR-0049 decision 9).
    /// The one question that chooses the attestor; nothing a machine publishes does.
    fn is_x509pop(&self, vm: &VirtualMachine) -> bool {
        !self.cfg.x509pop_pools.is_empty()
            && pool_key(vm).is_some_and(|key| self.cfg.x509pop_pools.contains(&key))
    }

    /// The node for a `Bound` claim: the registered node whose key is that of the
    /// attestation the claim's machine gives. With no `x509pop` pool configured that is the
    /// EK hash of the certificate banlieue mirrored onto the claim, and nothing else is read.
    /// With some, the claim's machine is read first and its pool decides: a machine of a
    /// listed pool resolves by its `x509pop` attestation alone (ADR-0049 decision 9), any
    /// other by the claim's certificate as before.
    async fn resolve(&self, claim: &VirtualMachineClaim) -> Result<Resolution, WatchError> {
        let attestation = match self.claim_node(claim).await? {
            MachineNode::Known(att) => att,
            MachineNode::NotYet(reason) | MachineNode::NoProvider(reason) => {
                return Ok(Resolution::NotYet(reason));
            }
            MachineNode::Unusable(reason) => return Ok(Resolution::Refused(reason)),
        };
        // The pair of functions the broker's node registration uses (decision 8).
        let naming = &self.reconciler.naming;
        let (key, agent_id) = match (
            node_key(naming, &attestation),
            agent_id_for(naming, &attestation),
        ) {
            (Ok(key), Ok(agent_id)) => (key, agent_id),
            (Err(e), _) | (_, Err(e)) => return Ok(Resolution::Refused(e.to_string())),
        };
        match self.reconciler.store.get_node(&key).await {
            Ok(node) if node.banned => Ok(Resolution::Refused(format!("node {key} is banned"))),
            // The entry is parented to the stored agent ID, which must be the one this
            // machine attests under: a record that says otherwise is not this machine's.
            Ok(node) if node.node_id != agent_id => Ok(Resolution::Refused(format!(
                "node {key} is registered under another agent ID than its machine attests as"
            ))),
            Ok(node) => Ok(Resolution::Node(NodeIdentity::stored(
                &node.ek_hash,
                &node.node_id,
            ))),
            Err(StoreError::NotFound(_)) => Ok(Resolution::NotYet(match attestation {
                NodeAttestation::Tpm { .. } => "no node registered for the claim's EK".into(),
                NodeAttestation::X509pop { .. } => {
                    "no node registered for the machine's x509pop identity".into()
                }
            })),
            Err(e) => Err(e.into()),
        }
    }

    /// What a `Bound` claim's node is resolved from. See [`Self::resolve`].
    async fn claim_node(&self, claim: &VirtualMachineClaim) -> Result<MachineNode, WatchError> {
        if self.cfg.x509pop_pools.is_empty() {
            return Ok(Self::tpm_node(claim_certificates(claim), "claim"));
        }
        let namespace = claim.namespace().unwrap_or_default();
        let Some(machine) = claim
            .status
            .as_ref()
            .and_then(|s| s.virtual_machine_ref.as_ref())
            .map(|r| r.name.as_str())
        else {
            return Ok(MachineNode::NotYet("the claim names no machine yet".into()));
        };
        let Some(vm) = self.claims.get_machine(&namespace, machine).await? else {
            return Ok(MachineNode::NotYet(format!(
                "the claim's machine {namespace}/{machine} does not exist"
            )));
        };
        if self.is_x509pop(&vm) {
            self.x509pop_node(&vm).await
        } else {
            Ok(Self::tpm_node(claim_certificates(claim), "claim"))
        }
    }

    /// The TPM attestation a set of endorsement certificates gives (ADR-0011 decision 2);
    /// `on` says where they were read, for the reason.
    fn tpm_node(certs: &[String], on: &str) -> MachineNode {
        if certs.is_empty() {
            return MachineNode::NotYet(format!("no endorsement certificate on the {on}"));
        }
        match ek_hash_from_pems(certs) {
            Ok(ek_hash) => MachineNode::Known(NodeAttestation::Tpm { ek_hash }),
            Err(e) => MachineNode::Unusable(format!("endorsement certificate: {e}")),
        }
    }

    /// The `x509pop` attestation of a machine of a listed pool (ADR-0049 decisions 9 and
    /// 10): its `status.attestationSubject` under the common name of the host CA its
    /// Provider asserts inline. Every cause for there being none is named, and none of them
    /// falls back to the machine's EK.
    ///
    /// # Errors
    /// A Provider could not be read. That is not a verdict on the machine.
    async fn x509pop_node(&self, vm: &VirtualMachine) -> Result<MachineNode, WatchError> {
        self.x509pop_node_in(&mut ProviderPass::default(), vm).await
    }

    /// [`Self::x509pop_node`] within a pass that looks at several machines: the Providers
    /// are listed once for all of them.
    async fn x509pop_node_in(
        &self,
        pass: &mut ProviderPass,
        vm: &VirtualMachine,
    ) -> Result<MachineNode, WatchError> {
        let namespace = vm.namespace().unwrap_or_default();
        let name = vm.name_any();
        let status = vm.status.as_ref();
        let Some(subject) = status.and_then(|s| s.attestation_subject.clone()) else {
            return Ok(MachineNode::NotYet(format!(
                "machine {namespace}/{name} is of an x509pop pool and publishes no attestationSubject"
            )));
        };
        let Some(provider_name) = status
            .and_then(|s| s.scheduled.as_ref())
            .map(|p| p.provider_name.as_str())
        else {
            return Ok(MachineNode::NotYet(format!(
                "machine {namespace}/{name} is of an x509pop pool and is not placed on a Provider yet"
            )));
        };
        if pass.all.is_none() {
            pass.all = Some(self.claims.list_providers().await?);
        }
        let all = pass.all.as_deref().unwrap_or_default();
        let shared = self.cfg.provider_namespace.as_deref();
        let Some((provider_namespace, provider)) =
            provider_of(all, &namespace, shared, provider_name)
        else {
            return Ok(MachineNode::NoProvider(format!(
                "machine {namespace}/{name} is of an x509pop pool and its Provider {provider_name} was not found"
            )));
        };
        let whose = format!("Provider {provider_namespace}/{provider_name}");
        let Some(host_ca) = provider
            .spec
            .attestation
            .as_ref()
            .and_then(|a| a.host_ca.as_ref())
        else {
            return Ok(MachineNode::Unusable(format!(
                "{whose} asserts no spec.attestation.hostCa, so its guests have no x509pop identity"
            )));
        };
        if host_ca.config_map_ref.is_some() || host_ca.secret_ref.is_some() {
            return Ok(MachineNode::Unusable(format!(
                "{whose}: spec.attestation.hostCa must be inline; a configMapRef or secretRef is not read (ADR-0049 decision 10)"
            )));
        }
        let Some(host_ca_pem) = host_ca.inline.clone() else {
            return Ok(MachineNode::Unusable(format!(
                "{whose}: spec.attestation.hostCa.inline is not set"
            )));
        };
        let input = X509popInput {
            host_ca_pem,
            attestation_subject: subject,
        };
        let attestation = match input.attestation() {
            Ok(att) => att,
            // The message names the rule broken and the certificate's common name at most,
            // never the certificate.
            Err(e) => {
                return Ok(MachineNode::Unusable(format!(
                    "{whose}: the host CA or machine {namespace}/{name}'s attestationSubject is unusable: {e}"
                )));
            }
        };
        // Two Providers that assert different CAs under this one's common name: the name
        // is what confines a host to its own guests (decision 2), so neither gets an entry.
        if let NodeAttestation::X509pop { issuer_cn, .. } = &attestation
            && let Some((_, fingerprint)) = certificate_identities(&input.host_ca_pem)
                .ok()
                .and_then(|ids| ids.into_iter().next())
            && let Some(rival) = rival_host_ca(
                all,
                (&provider_namespace, provider_name),
                issuer_cn,
                &fingerprint,
            )
        {
            return Ok(MachineNode::Unusable(format!(
                "two Providers assert host CAs named {issuer_cn:?} with different certificates ({provider_namespace}/{provider_name} and {rival}); a host CA's common name must be unique"
            )));
        }
        Ok(MachineNode::Known(attestation))
    }

    /// Whether a machine was created less than the node grace ago (`store.node_grace_secs`,
    /// the grace a young node gets). One with no creation timestamp is not young.
    fn is_young(&self, vm: &VirtualMachine) -> bool {
        let grace = jiff::SignedDuration::try_from(self.cfg.node_grace)
            .unwrap_or(jiff::SignedDuration::MAX);
        vm.metadata
            .creation_timestamp
            .as_ref()
            .is_some_and(|created| jiff::Timestamp::now().duration_since(created.0) < grace)
    }

    /// What a pool member's node entry is declared from: by the pool list, the machine's
    /// `x509pop` attestation or the TPM one of its endorsement certificates.
    async fn machine_node(&self, vm: &VirtualMachine) -> Result<MachineNode, WatchError> {
        if self.is_x509pop(vm) {
            self.x509pop_node(vm).await
        } else {
            let certs = vm
                .status
                .as_ref()
                .map_or(&[][..], |s| s.tpm_endorsement_certificates.as_slice());
            Ok(Self::tpm_node(certs, "machine"))
        }
    }

    /// The node key every pool member VM gives, of both kinds, computed with the functions
    /// that declare the node entries: what keeps a node and its entry from collection.
    ///
    /// A listed machine whose host CA is unusable (withdrawn from its Provider, renamed, no
    /// longer a CA with a path length of zero, a rival under its name) protects nothing:
    /// that is an administrator's act, and the entries under the old name are meant to go.
    /// One for which something is only *missing* protects nothing either, but may mark the
    /// set incomplete, and a pass with an incomplete set removes no x509pop node or entry.
    /// Its Provider not found always does: a Provider deleted and applied again must not
    /// cost every idle guest of its host its identity. Its own subject or placement missing
    /// does only while the machine is young ([`Self::is_young`]): a machine still being
    /// provisioned, not one that never will be, which would otherwise stop the collection
    /// of every x509pop pool for as long as it existed.
    ///
    /// # Errors
    /// The Providers could not be listed: no set, so nothing is collected on a guess.
    async fn live_node_keys(&self, machines: &[VirtualMachine]) -> Result<LiveKeys, WatchError> {
        let (listed, unlisted): (Vec<&VirtualMachine>, Vec<&VirtualMachine>) =
            machines.iter().partition(|vm| self.is_x509pop(vm));
        let mut live = LiveKeys {
            keys: ek_hashes_of(unlisted),
            x509pop_incomplete: false,
        };
        let mut pass = ProviderPass::default();
        for vm in listed {
            match self.x509pop_node_in(&mut pass, vm).await? {
                MachineNode::Known(att) => match node_key(&self.reconciler.naming, &att) {
                    Ok(key) => {
                        live.keys.insert(key);
                    }
                    Err(e) => {
                        tracing::warn!(vm = %vm.name_any(), error = %e, "x509pop attestation unusable; it protects no node");
                    }
                },
                // The administrators' object is missing: held whatever the machine's age.
                MachineNode::NoProvider(reason) => {
                    tracing::info!(vm = %vm.name_any(), %reason, "an x509pop machine gives no key yet; no x509pop node or entry is collected in this pass");
                    live.x509pop_incomplete = true;
                }
                // The machine's own data is missing: held while it is young, the grace a
                // young node gets. Past that it is a machine that never got there (or one
                // only labelled into the pool), and it holds nothing.
                MachineNode::NotYet(reason) if self.is_young(vm) => {
                    tracing::info!(vm = %vm.name_any(), %reason, "an x509pop machine gives no key yet; no x509pop node or entry is collected in this pass");
                    live.x509pop_incomplete = true;
                }
                MachineNode::NotYet(reason) => {
                    tracing::info!(vm = %vm.name_any(), %reason, "an x509pop machine older than the node grace still gives no key; it does not hold the collection");
                }
                MachineNode::Unusable(reason) => {
                    tracing::debug!(vm = %vm.name_any(), %reason, "no x509pop identity; it protects no node");
                }
            }
        }
        Ok(live)
    }

    /// Decision 3: the record is revoked (no entry was ever created for it) and the claim
    /// deleted, which makes banlieue destroy the member.
    async fn fail(
        &self,
        claim: &VirtualMachineClaim,
        uid: Uuid,
        reason: &str,
    ) -> Result<Action, WatchError> {
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
        let mut seen = self
            .first_unresolved
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
    ///
    /// A member of an `x509pop` pool (ADR-0049 decision 9) gets the `x509pop` node entry of
    /// its subject under its host's CA and never a TPM one; with no subject, no Provider or
    /// no usable host CA it gets none at all, the cause is logged, and the pass comes back
    /// at the resync interval, because what is missing is on another object (the Provider)
    /// whose change raises no event here. The same interval picks up a host CA whose common
    /// name changed: the new key's entry is declared, and the old one is retracted by
    /// [`Self::collect_node_entries`].
    pub async fn reconcile_machine(&self, vm: &VirtualMachine) -> Result<Action, WatchError> {
        let name = vm.name_any();
        let x509pop = self.is_x509pop(vm);
        let after = if x509pop {
            Action::requeue(self.cfg.resync)
        } else {
            Action::await_change()
        };
        let attestation = match self.machine_node(vm).await? {
            MachineNode::Known(att) => att,
            MachineNode::NotYet(reason) | MachineNode::NoProvider(reason) => {
                if x509pop {
                    tracing::info!(vm = %name, %reason, "no node entry yet");
                } else {
                    tracing::debug!(vm = %name, %reason, "no node entry yet");
                }
                return Ok(after);
            }
            MachineNode::Unusable(reason) => {
                tracing::warn!(vm = %name, %reason, "no node entry");
                return Ok(after);
            }
        };
        let key = match node_key(&self.reconciler.naming, &attestation) {
            Ok(key) => key,
            Err(e) => {
                tracing::warn!(vm = %name, error = %e, "attestation unusable; no node entry");
                return Ok(after);
            }
        };
        if self
            .declared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&key)
        {
            return Ok(after);
        }
        let entry = self
            .reconciler
            .spire
            .ensure_node_entry(&attestation)
            .await?;
        self.declared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key.clone());
        match &attestation {
            NodeAttestation::Tpm { .. } => {
                tracing::info!(vm = %name, ek_hash = %key, %entry, "node entry declared");
            }
            NodeAttestation::X509pop {
                issuer_cn,
                subject_cn,
            } => {
                tracing::info!(vm = %name, node_key = %key, %issuer_cn, %subject_cn, %entry, "x509pop node entry declared");
            }
        }
        Ok(after)
    }

    /// Remove the nodes whose VM no longer exists in banlieue (ADR-0039), returning how
    /// many. A node is its VM's by its node key, of either kind ([`Self::live_node_keys`]). The decision is [`nodegc::nodes_to_delete`]; this gathers its inputs and acts
    /// on it, on the replica holding the Lease. A failed listing of the nodes, the VMs or
    /// the claims removes nothing (the error is the caller's to log); one failed deletion
    /// is logged and the pass goes on, the next pass retries it.
    ///
    /// # Errors
    /// The nodes, the VMs or the claims could not be listed, or a Provider not read.
    pub async fn collect_nodes(&self) -> Result<usize, WatchError> {
        let store = &self.reconciler.store;
        let nodes = store.list_nodes().await?;
        if nodes.is_empty() {
            return Ok(0);
        }
        let live = self
            .live_node_keys(&self.claims.list_machines().await?)
            .await?;
        let now = jiff::Timestamp::now();
        let busy = self.busy_node_ids(now).await?;
        let doomed = nodegc::nodes_to_delete(&nodegc::Inputs {
            nodes: &nodes,
            live_node_keys: &live.keys,
            busy_node_ids: &busy,
            now,
            grace: jiff::SignedDuration::try_from(self.config().node_grace)
                .unwrap_or(jiff::SignedDuration::MAX),
            cap: MAX_DELETIONS_PER_PASS,
            hold_x509pop: live.x509pop_incomplete,
        });
        let mut removed = 0;
        for key in doomed {
            match store.delete_node(&key).await {
                Ok(()) => {
                    let hostname = nodes
                        .iter()
                        .find(|n| n.ek_hash == key)
                        .map_or("", |n| n.hostname.as_str());
                    tracing::info!(node_key = %key, %hostname, "node removed: its VM is gone");
                    removed += 1;
                }
                Err(e) => {
                    tracing::warn!(node_key = %key, error = %e, "node not removed; the next pass retries");
                }
            }
        }
        Ok(removed)
    }

    /// The SPIRE agent ID of every node a claim that has not ended is bound to.
    async fn busy_node_ids(&self, now: jiff::Timestamp) -> Result<HashSet<String>, WatchError> {
        Ok(self
            .reconciler
            .store
            .list_claims()
            .await?
            .iter()
            .filter(|c| c.ended_at().is_none_or(|ended| ended > now))
            .filter_map(|c| c.node_id.clone())
            .collect())
    }

    /// Retract the node entries whose VM is gone (ADR-0039 decision 7), returning how
    /// many. A node entry is declared from a VM's endorsement certificate, or for a machine
    /// of an `x509pop` pool from its subject and its host's CA (ADR-0049 decision 9), and
    /// nothing else removed it, so one was left per VM ever created. An `x509pop` entry also
    /// goes when its machine's key changed (its host CA's common name did) or its machine no
    /// longer has a usable host CA. The decision is
    /// [`nodegc::node_entries_to_delete`]; on the replica holding the Lease, like the node
    /// collection. A failed listing retracts nothing; one failed retraction is logged and the
    /// pass goes on.
    ///
    /// # Errors
    /// The entries, the VMs, the nodes or the claims could not be listed, or a Provider not
    /// read.
    pub async fn collect_node_entries(&self) -> Result<usize, WatchError> {
        let entries = self.reconciler.spire.list_entries().await?;
        if !entries.iter().any(|e| nodegc::node_entry_key(e).is_some()) {
            return Ok(0);
        }
        let live = self
            .live_node_keys(&self.claims.list_machines().await?)
            .await?;
        let nodes = self.reconciler.store.list_nodes().await?;
        let now = jiff::Timestamp::now();
        let busy = self.busy_node_ids(now).await?;
        let doomed = nodegc::node_entries_to_delete(&nodegc::EntryInputs {
            entries: &entries,
            live_node_keys: &live.keys,
            busy_node_ids: &busy,
            nodes: &nodes,
            now,
            grace: jiff::SignedDuration::try_from(self.config().node_grace)
                .unwrap_or(jiff::SignedDuration::MAX),
            cap: MAX_DELETIONS_PER_PASS,
            hold_x509pop: live.x509pop_incomplete,
        });
        let mut retracted = 0;
        for name in doomed {
            match self.reconciler.spire.delete_entry(&name).await {
                Ok(()) => {
                    let key = name.strip_prefix(NODE_ENTRY_PREFIX).unwrap_or(&name);
                    // Declared again should a VM give this key once more.
                    self.declared
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .remove(key);
                    tracing::info!(node_key = %key, entry = %name, "node entry retracted: no VM gives its key");
                    retracted += 1;
                }
                Err(e) => {
                    tracing::warn!(entry = %name, error = %e, "node entry not retracted; the next pass retries");
                }
            }
        }
        Ok(retracted)
    }

    /// Remove every sealed envelope that is past its expiry or whose session was parked and never taken for longer than
    /// the grace period (ADR-0013 decision 2, ADR-0043 decision 4): the parked ones, and those already on a bound claim's
    /// record. Returns how many went. Run on its own short timer and again by every resync.
    ///
    /// # Errors
    /// The store refused.
    pub async fn sweep_envelopes(&self) -> Result<usize, WatchError> {
        let swept = self
            .reconciler
            .store
            .sweep_sessions(
                jiff::Timestamp::now() - jiff::SignedDuration::from_secs(SESSION_GRACE_SECS),
            )
            .await?;
        if swept > 0 {
            tracing::info!(swept, "expired or stale envelopes swept");
        }
        Ok(swept)
    }

    /// Decision 4's backstop: release every bound record whose claim no longer exists,
    /// then sweep orphan entries, then sweep the rows of claims that ended before the
    /// retention window, the audit line logged (ADR-0034). Returns (records released,
    /// entries swept, rows archived).
    ///
    /// First, the entries admission self-check again (ADR-0056 decision 5): a policy removed,
    /// unbound or renamed under a running broker is noticed here, on the replica holding
    /// the Lease, and not only at the next start. A failure is logged as an error and
    /// stops new entries from being declared (the gate is the entry manager's,
    /// `mediatore_spire::Gated`); it releases nothing that is bound, and the rest of the
    /// pass, which only retracts and sweeps, goes on.
    pub async fn resync(&self) -> Result<(usize, usize, usize), WatchError> {
        if let Err(e) = self.reconciler.spire.self_check().await {
            tracing::error!(
                error = %e,
                "the entries admission self-check failed at resync: no new entry is declared until it passes, and nothing bound is released on its account (ADR-0056 decision 5)"
            );
        }
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
        let before = jiff::SignedDuration::try_from(self.config().retention)
            .ok()
            .and_then(|d| jiff::Timestamp::now().checked_sub(d).ok())
            .unwrap_or(jiff::Timestamp::MIN);
        let archived = self.reconciler.store.sweep(before).await?;
        self.sweep_envelopes().await?;
        // The stored output of ended and vanished claims (ADR-0045 decisions 4 and 7).
        if self.config().logs_enabled {
            let before = jiff::SignedDuration::try_from(self.config().logs_retention)
                .ok()
                .and_then(|d| jiff::Timestamp::now().checked_sub(d).ok())
                .unwrap_or(jiff::Timestamp::MIN);
            let logs = self.reconciler.store.sweep_logs(before).await?;
            if logs > 0 {
                tracing::info!(
                    claims = logs,
                    "stored workload output swept after its retention (ADR-0045)"
                );
            }
        }
        self.declared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        Ok((released, swept, archived))
    }
}

/// How long a parked session may wait for its record before the resync sweeps it.
const SESSION_GRACE_SECS: i64 = 3600;

/// How often envelopes past their expiry are swept (the operator's rule, 2026-11-15, ADR-0043 decision 4: no secret is
/// stored longer than its claim's TTL). A timer of its own, because the resync's interval is minutes, and a secret
/// stored past its expiry until the next resync would be stored longer than the rule allows.
pub const ENVELOPE_SWEEP_SECS: u64 = 15;

/// The endorsement certificates banlieue mirrored onto a claim.
fn claim_certificates(claim: &VirtualMachineClaim) -> &[String] {
    claim
        .status
        .as_ref()
        .map_or(&[][..], |s| s.tpm_endorsement_certificates.as_slice())
}

/// The claim UID (ADR-0011 decision 1): the object's `metadata.uid`.
#[must_use]
pub fn claim_uid_of(claim: &VirtualMachineClaim) -> Option<Uuid> {
    claim
        .metadata
        .uid
        .as_deref()
        .and_then(|u| Uuid::parse_str(u).ok())
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

/// One tick per policy whose bundle changed (admitted at a new version, dropped), from
/// the reflector's cache. Each tick reconciles every sandbox: kube's per-object trigger is
/// behind an unstable feature, the sandboxes are few, and a pass over one that names
/// another policy patches nothing. A subscriber that lagged ticks once for what it missed.
fn bundle_changes(changes: broadcast::Receiver<PolicyKey>) -> impl Stream<Item = ()> {
    futures::stream::unfold(changes, |mut changes| async move {
        match changes.recv().await {
            Ok((namespace, policy)) => {
                tracing::debug!(%namespace, %policy, "bundle changed; sandboxes compared again");
                Some(((), changes))
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                tracing::warn!(
                    missed = n,
                    "bundle changes missed; sandboxes compared again"
                );
                Some(((), changes))
            }
            Err(broadcast::error::RecvError::Closed) => None,
        }
    })
}

/// Whether an error from a watch stream is routine: a watch that expired (`410 Gone`, "too
/// old resource version") is re-listed by the watcher on its own and deserves no warning.
pub(crate) fn watch_error_is_routine(err: &watcher::Error) -> bool {
    matches!(err, watcher::Error::WatchError(status) if status.code == 410)
}

/// Whether an error from a controller's stream deserves a warning. Routine, and logged at
/// debug: an expired watch; a reconcile scheduled for an object deleted meanwhile (the
/// object left the store between the event and the pass); a failed reconcile, which the
/// error policy has already warned about and requeued. Everything else is warned.
pub(crate) fn deserves_warning<R: std::error::Error + 'static>(
    err: &controller::Error<R, watcher::Error>,
) -> bool {
    match err {
        controller::Error::QueueError(e) => !watch_error_is_routine(e),
        controller::Error::ObjectNotFound(_) | controller::Error::ReconcilerFailed(..) => false,
        controller::Error::RunnerError(_) => true,
    }
}

/// One line per stream error, at the level [`deserves_warning`] says.
fn log_stream_error<R: std::error::Error + 'static>(
    controller: &str,
    err: &controller::Error<R, watcher::Error>,
) {
    if deserves_warning(err) {
        tracing::warn!(error = %err, "{controller} controller");
    } else {
        tracing::debug!(error = %err, "{controller} controller: routine");
    }
}
/// Whether `next` differs from `prev` in `status.tripwires` and in nothing the reconciler
/// reads (ADR-0069 decision 9): the trip summary is the store's, written apart from the record
/// and never by a pass, so an event that carries only a new one has nothing to reconcile.
/// `metadata.resourceVersion` and `metadata.managedFields` move with every write and are not
/// compared. False when the summary is the same (a re-list hands the same object again, and
/// that still reconciles) and when anything else changed, the record included.
#[must_use]
pub fn differs_only_in_tripwires(prev: &AgentSandbox, next: &AgentSandbox) -> bool {
    let trips = |sb: &AgentSandbox| sb.status.as_ref().and_then(|s| s.tripwires.clone());
    trips(prev) != trips(next) && without_tripwires(prev) == without_tripwires(next)
}

/// `sb` as the reconciler compares it: without the trip summary and the two metadata fields
/// that every write moves.
fn without_tripwires(sb: &AgentSandbox) -> AgentSandbox {
    let mut sb = sb.clone();
    sb.metadata.resource_version = None;
    sb.metadata.managed_fields = None;
    if let Some(status) = sb.status.as_mut() {
        status.tripwires = None;
    }
    sb
}

/// How many sandboxes [`TripwiresFilter`] may remember beyond those the reflector holds
/// before it forgets the ones that are gone.
const FILTER_SLACK: usize = 64;

/// The sandbox controller's watch filter (ADR-0069 decision 9): the last object seen of each
/// sandbox, so that an event which [`differs_only_in_tripwires`] from it is kept from the
/// reconciler. Everything else passes, a first sight and an unchanged re-list included.
#[derive(Default)]
struct TripwiresFilter {
    last: HashMap<ObjectRef<AgentSandbox>, AgentSandbox>,
}

impl TripwiresFilter {
    /// Whether `sb` reaches the reconciler, remembering it either way: a second summary
    /// after a first is compared with the first.
    fn admit(&mut self, sb: &AgentSandbox) -> bool {
        let key = ObjectRef::from_obj(sb);
        let only_trips = self
            .last
            .get(&key)
            .is_some_and(|prev| differs_only_in_tripwires(prev, sb));
        self.last.insert(key, sb.clone());
        !only_trips
    }

    /// Forget the sandboxes the reflector no longer holds, once there are more remembered
    /// than it holds by [`FILTER_SLACK`]: the stream carries no deletion to forget one by.
    fn prune(&mut self, held: &Store<AgentSandbox>) {
        if self.last.len() > held.len().saturating_add(FILTER_SLACK) {
            self.last.retain(|key, _| held.get(key).is_some());
        }
    }
}

/// `objects` without the events that differ only in `status.tripwires` from the last one seen
/// of the same sandbox. Errors pass: the controller's backoff is driven by them.
fn without_tripwire_only_events<S>(
    objects: S,
    held: Store<AgentSandbox>,
) -> impl Stream<Item = Result<AgentSandbox, watcher::Error>>
where
    S: Stream<Item = Result<AgentSandbox, watcher::Error>>,
{
    let mut filter = TripwiresFilter::default();
    objects.filter(move |event| {
        let pass = match event {
            Ok(sb) => {
                filter.prune(&held);
                filter.admit(sb)
            }
            Err(_) => true,
        };
        std::future::ready(pass)
    })
}

/// The sandbox controller over every namespace: what [`Controller::new`] builds (a reflector
/// over the watch, the applied objects as the trigger), with the events that carry only a new
/// trip summary taken out of the trigger (ADR-0069 decision 9). The reflector's store still
/// holds every object as last seen, so a pass reads the latest whatever triggered it.
fn sandbox_controller(client: Client) -> Controller<AgentSandbox> {
    let writer = reflector::store::Writer::<AgentSandbox>::default();
    let held = writer.as_reader();
    let objects = reflector(
        writer,
        watcher(Api::<AgentSandbox>::all(client), watcher::Config::default()),
    )
    .applied_objects();
    Controller::for_stream(without_tripwire_only_events(objects, held.clone()), held)
}

/// After each resync: the nodes of VMs that are gone, then their node entries (ADR-0039,
/// decisions 1 and 7), each logged and neither stopping the loop.
async fn collect_gone(watcher: &Watcher) {
    match watcher.collect_nodes().await {
        Ok(0) => {}
        Ok(removed) => tracing::info!(removed, "nodes of gone VMs collected"),
        Err(e) => tracing::warn!(error = %e, "node collection failed; nothing removed"),
    }
    match watcher.collect_node_entries().await {
        Ok(0) => {}
        Ok(retracted) => tracing::info!(retracted, "node entries of gone VMs retracted"),
        Err(e) => {
            tracing::warn!(error = %e, "node entry collection failed; nothing retracted");
        }
    }
}

/// The three controllers (claims, pool members, sandboxes) and the resync ticker, until
/// the first one ends (they do not end on their own). Run this on the Lease holder only.
pub async fn run(client: Client, watcher: Arc<Watcher>) -> anyhow::Result<()> {
    let requeue = watcher.config().requeue;
    let sandboxes = sandbox_controller(client.clone())
        // A change to the owned claim (banlieue's status writes, its deletion) reconciles the
        // sandbox that owns it.
        .owns(
            Api::<VirtualMachineClaim>::all(client.clone()),
            watcher::Config::default().labels(MANAGED_BY_SELECTOR),
        );
    // A change to a policy's bundle reconciles every sandbox naming that policy (ADR-0026
    // decision 7), after the reflector on this replica admitted it, so the comparison never
    // runs against a cache that has not caught up.
    let sandboxes = match watcher.bundles.as_ref() {
        Some(bundles) => sandboxes.reconcile_all_on(bundle_changes(bundles.subscribe())),
        None => sandboxes,
    };
    let sandboxes = sandboxes
    .run(
        |sb, w: Arc<Watcher>| async move { w.reconcile_sandbox(&sb).await },
        move |sb, err, _| {
            tracing::warn!(sandbox = %sb.name_any(), error = %err, "sandbox reconcile failed; retrying");
            Action::requeue(requeue)
        },
        watcher.clone(),
    )
    .for_each(|r| async move {
        if let Err(e) = r {
            log_stream_error("sandbox", &e);
        }
    });
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
            log_stream_error("claim", &e);
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
            log_stream_error("machine", &e);
        }
    });
    let resync = async {
        let mut tick = tokio::time::interval(watcher.config().resync);
        tick.tick().await;
        loop {
            tick.tick().await;
            match watcher.resync().await {
                Ok((released, swept, archived)) => {
                    tracing::info!(released, swept, archived, "resync");
                }
                Err(e) => tracing::warn!(error = %e, "resync failed"),
            }
            collect_gone(&watcher).await;
        }
    };
    let envelopes = async {
        let mut tick = tokio::time::interval(Duration::from_secs(ENVELOPE_SWEEP_SECS));
        tick.tick().await;
        loop {
            tick.tick().await;
            if let Err(e) = watcher.sweep_envelopes().await {
                tracing::warn!(error = %e, "envelope sweep failed; nothing removed");
            }
        }
    };
    tracing::info!("claim watcher running");
    tokio::select! {
        () = claims => {}
        () = machines => {}
        () = sandboxes => {}
        () = resync => {}
        () = envelopes => {}
    }
    anyhow::bail!("claim watcher stopped")
}

#[cfg(test)]
mod tests {
    use jiff::Timestamp;
    use mediatore_proto::{Subject, Workload};
    use mediatore_spire::{EntryManager, claim_entry_name, node_entry_name};
    use mediatore_store::{ClaimRecord, ClaimStore};
    use mediatore_testkit::ek::{RSA_EK_HASH, RSA_EK_PEM};
    use mediatore_testkit::x509pop::HostCa;
    use rcgen::{BasicConstraints, IsCa};
    use serde_json::json;

    use super::*;
    use crate::fakes::{node, rig};

    type StreamError = controller::Error<WatchError, watcher::Error>;

    // ---------- ADR-0069 decision 9: the sandbox controller's watch filter ----------

    fn watched_sandbox(name: &str, version: &str) -> AgentSandbox {
        let mut sb = AgentSandbox::new(
            name,
            crate::sandbox::AgentSandboxSpec {
                subject: crate::sandbox::SandboxSubject {
                    issuer: "https://idp.example".into(),
                    id: "octocat".into(),
                    display: None,
                },
                pool_ref: Some(banlieue_api::common::LocalObjectReference {
                    name: "pool".into(),
                }),
                pool_selector: None,
                selection: None,
                ttl_seconds: 600,
                audiences: vec![],
                workload: crate::sandbox::SandboxWorkload {
                    image: "registry.internal:5000/x:1".into(),
                    args: vec![],
                    restart: None,
                    logs: false,
                },
                policy_ref: None,
            },
        );
        sb.metadata.namespace = Some("sandboxes".into());
        sb.metadata.uid = Some(Uuid::new_v4().to_string());
        sb.metadata.resource_version = Some(version.into());
        sb.status = Some(AgentSandboxStatus::default());
        sb
    }

    /// `sb` after the store folded `count` uses onto it: a new summary, a new version, and
    /// the managed fields a status write moves.
    fn folded(sb: &AgentSandbox, count: u64, version: &str) -> AgentSandbox {
        use mediatore_proto::trip::{
            TripEffect, TripEntry, TripKind, TripSource, TripSummary, TripTarget,
        };
        let at = jiff::Timestamp::from_second(1_800_000_000).unwrap();
        let mut summary = TripSummary::default();
        summary.fold(
            &[TripEntry {
                effect: TripEffect::WouldTrip,
                kind: TripKind::Port,
                trap: Some("redis".into()),
                class: None,
                target: Some(TripTarget::Port(6379)),
                source: TripSource::Drawn,
                source_address: None,
                containment_ms: None,
                count,
                first_at: at,
                last_at: at,
            }],
            at,
        );
        let mut next = sb.clone();
        next.metadata.resource_version = Some(version.into());
        next.metadata.managed_fields = Some(vec![
            k8s_openapi::apimachinery::pkg::apis::meta::v1::ManagedFieldsEntry {
                manager: Some(format!("mediatore-{version}")),
                ..Default::default()
            },
        ]);
        next.status.get_or_insert_default().tripwires =
            Some(crate::sandbox::TripwiresStatus::from(&summary));
        next
    }

    #[tokio::test]
    async fn an_event_that_differs_only_in_tripwires_does_not_reach_the_reconciler_and_any_other_change_does()
     {
        let first = watched_sandbox("sb-1", "1");
        let fold_1 = folded(&first, 1, "2");
        let fold_2 = folded(&fold_1, 5, "3");
        // The record, a mirrored field, a label, the spec's generation, a deletion: each is a
        // change the reconciler must see, with or without a new summary beside it.
        let mut recorded = fold_2.clone();
        recorded.metadata.resource_version = Some("4".into());
        recorded.status.as_mut().unwrap().reason = Some("tripped: port".into());
        let mut labelled = recorded.clone();
        labelled.metadata.resource_version = Some("5".into());
        labelled.metadata.labels = Some([("a".to_owned(), "b".to_owned())].into());
        let mut both = folded(&labelled, 9, "6");
        both.status.as_mut().unwrap().entry_set = true;
        let mut deleting = both.clone();
        deleting.metadata.resource_version = Some("7".into());
        deleting.metadata.deletion_timestamp = Some(
            k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(jiff::Timestamp::UNIX_EPOCH),
        );
        let other = watched_sandbox("sb-2", "1");
        let other_fold = folded(&other, 1, "2");

        // The pure rule.
        assert!(differs_only_in_tripwires(&first, &fold_1));
        assert!(differs_only_in_tripwires(&fold_1, &fold_2));
        assert!(
            !differs_only_in_tripwires(&first, &first),
            "the same object"
        );
        assert!(!differs_only_in_tripwires(&fold_2, &recorded));
        assert!(!differs_only_in_tripwires(&recorded, &labelled));
        assert!(!differs_only_in_tripwires(&labelled, &both));
        assert!(!differs_only_in_tripwires(&both, &deleting));
        let mut moved = first.clone();
        moved.metadata.resource_version = Some("9".into());
        assert!(
            !differs_only_in_tripwires(&first, &moved),
            "a version alone is no summary: it reconciles, as before"
        );

        // The stream the controller is triggered by.
        let events = vec![
            first.clone(),      // a first sight: reconciled
            fold_1.clone(),     // a summary alone: kept back
            other.clone(),      // another sandbox's first sight
            fold_2.clone(),     // a second summary, compared with the first: kept back
            fold_2.clone(),     // a re-list hands the same object again: reconciled
            other_fold.clone(), // the other sandbox's summary: kept back
            recorded.clone(),
            labelled.clone(),
            both.clone(),
            deleting.clone(),
        ];
        let held = reflector::store::Writer::<AgentSandbox>::default().as_reader();
        let stream = without_tripwire_only_events(
            futures::stream::iter(events.into_iter().map(Ok)).chain(futures::stream::iter([Err(
                watcher::Error::NoResourceVersion,
            )])),
            held,
        );
        let passed: Vec<Result<AgentSandbox, watcher::Error>> = stream.collect().await;
        let versions: Vec<(String, String)> = passed
            .iter()
            .filter_map(|r| r.as_ref().ok())
            .map(|sb| (sb.name_any(), sb.resource_version().unwrap_or_default()))
            .collect();
        let expected: Vec<(String, String)> = [
            ("sb-1", "1"),
            ("sb-2", "1"),
            ("sb-1", "3"),
            ("sb-1", "4"),
            ("sb-1", "5"),
            ("sb-1", "6"),
            ("sb-1", "7"),
        ]
        .iter()
        .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
        .collect();
        assert_eq!(versions, expected);
        assert!(
            passed.last().is_some_and(Result::is_err),
            "an error of the watch passes: the backoff is driven by it"
        );
    }

    #[test]
    fn the_filter_forgets_sandboxes_the_reflector_no_longer_holds() {
        let held = reflector::store::Writer::<AgentSandbox>::default().as_reader();
        let mut filter = TripwiresFilter::default();
        for n in 0..=FILTER_SLACK {
            assert!(filter.admit(&watched_sandbox(&format!("sb-{n}"), "1")));
            filter.prune(&held);
        }
        assert!(
            filter.last.is_empty(),
            "past the slack, what the store lacks goes"
        );
    }

    fn expired_watch(code: u16) -> StreamError {
        controller::Error::QueueError(watcher::Error::WatchError(
            kube::core::Status::failure("too old resource version: 1 (2)", "Expired")
                .with_code(code)
                .boxed(),
        ))
    }

    #[test]
    fn an_expired_watch_a_vanished_object_and_a_failed_pass_are_routine_and_the_rest_warn() {
        let gone = kube::runtime::reflector::ObjectRef::<VirtualMachineClaim>::new("gone")
            .within("sandboxes")
            .erase();
        assert!(!deserves_warning(&expired_watch(410)));
        assert!(!deserves_warning(&StreamError::ObjectNotFound(Box::new(
            gone.clone()
        ))));
        assert!(!deserves_warning(&StreamError::ReconcilerFailed(
            WatchError::Reconcile("held".into()),
            Box::new(gone)
        )));
        assert!(deserves_warning(&expired_watch(403)));
        assert!(deserves_warning(&expired_watch(500)));
        assert!(deserves_warning(&StreamError::QueueError(
            watcher::Error::NoResourceVersion
        )));
        assert!(watch_error_is_routine(&watcher::Error::WatchError(
            kube::core::Status::failure("gone", "Expired")
                .with_code(410)
                .boxed()
        )));
        assert!(!watch_error_is_routine(&watcher::Error::NoResourceVersion));
    }

    const UID: &str = "6b0a3e9c-1f4d-4c2e-9a7b-0d1e2f3a4b5c";

    fn record(uid: Uuid) -> ClaimRecord {
        ClaimRecord {
            tripped: None,
            rendered: None,
            follow: None,
            uid,
            name: "claim-x".into(),
            namespace: "sandboxes".into(),
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
                restart: mediatore_proto::RestartPolicy::Always,
                logs: false,
            },
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
        let action = r
            .watcher
            .reconcile_claim(&claim("Bound", &[RSA_EK_PEM], false))
            .await
            .unwrap();
        assert_eq!(action, Action::await_change());
        let rec = r.store.get_claim(uid()).await.unwrap();
        assert_eq!(
            rec.entry_id.as_deref(),
            Some(claim_entry_name(uid()).as_str())
        );
        assert_eq!(
            rec.node_id.as_deref(),
            Some(node(RSA_EK_HASH, false).node_id.as_str())
        );
        assert!(rec.expires_at.is_some());
        assert!(r.entries.names().contains(&claim_entry_name(uid())));
        // a repeated event is a no-op
        let again = r
            .watcher
            .reconcile_claim(&claim("Bound", &[RSA_EK_PEM], false))
            .await
            .unwrap();
        assert_eq!(again, Action::await_change());
        assert_eq!(r.entries.names().len(), 1);
    }

    #[tokio::test]
    async fn a_claim_without_a_record_binds_nothing() {
        let r = rig(WatcherConfig {
            requeue: Duration::from_millis(5),
            ..WatcherConfig::default()
        });
        r.store.put_node(node(RSA_EK_HASH, false)).await.unwrap();
        // Bound: polled, in case the record is about to be written.
        let action = r
            .watcher
            .reconcile_claim(&claim("Bound", &[RSA_EK_PEM], false))
            .await
            .unwrap();
        assert_eq!(action, Action::requeue(Duration::from_millis(5)));
        // Pending: nothing to wait for.
        let action = r
            .watcher
            .reconcile_claim(&claim("Pending", &[], false))
            .await
            .unwrap();
        assert_eq!(action, Action::await_change());
        assert_eq!(r.entries.names(), Vec::<String>::new());
        assert_eq!(r.claims.deleted(), Vec::<(String, String)>::new());
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
        let action = r
            .watcher
            .reconcile_claim(&claim("Bound", &[], false))
            .await
            .unwrap();
        assert_eq!(action, Action::requeue(Duration::from_millis(5)));
        // certificate, but the node never registered
        let action = r
            .watcher
            .reconcile_claim(&claim("Bound", &[RSA_EK_PEM], false))
            .await
            .unwrap();
        assert_eq!(action, Action::requeue(Duration::from_millis(5)));
        assert_eq!(r.claims.deleted(), Vec::<(String, String)>::new());
        tokio::time::sleep(Duration::from_millis(70)).await;
        let action = r
            .watcher
            .reconcile_claim(&claim("Bound", &[RSA_EK_PEM], false))
            .await
            .unwrap();
        assert_eq!(action, Action::await_change());
        let rec = r.store.get_claim(uid()).await.unwrap();
        assert!(rec.revoked_at.is_some(), "record revoked");
        assert!(rec.entry_id.is_none(), "no entry was ever declared");
        assert_eq!(r.entries.names(), Vec::<String>::new());
        assert_eq!(
            r.claims.deleted(),
            vec![("sandboxes".to_owned(), "claim-x".to_owned())]
        );
    }

    #[tokio::test]
    async fn a_banned_node_or_an_unusable_certificate_fails_the_claim_at_once() {
        for (certs, banned) in [
            (vec![RSA_EK_PEM], true),
            (
                vec!["-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"],
                false,
            ),
        ] {
            let r = rig(WatcherConfig::default());
            r.store.put_claim(record(uid())).await.unwrap();
            r.store.put_node(node(RSA_EK_HASH, banned)).await.unwrap();
            let action = r
                .watcher
                .reconcile_claim(&claim("Bound", &certs, false))
                .await
                .unwrap();
            assert_eq!(action, Action::await_change());
            assert!(r.store.get_claim(uid()).await.unwrap().revoked_at.is_some());
            assert_eq!(r.claims.deleted().len(), 1);
            assert_eq!(r.entries.names(), Vec::<String>::new());
        }
    }

    #[tokio::test]
    async fn releasing_failed_and_deletion_retract_the_entry_and_cut_off() {
        for (phase, deleting) in [("Releasing", false), ("Failed", false), ("Bound", true)] {
            let r = rig(WatcherConfig::default());
            r.store.put_claim(record(uid())).await.unwrap();
            r.store.put_node(node(RSA_EK_HASH, false)).await.unwrap();
            r.watcher
                .reconcile_claim(&claim("Bound", &[RSA_EK_PEM], false))
                .await
                .unwrap();
            assert_eq!(r.entries.names().len(), 1);
            let action = r
                .watcher
                .reconcile_claim(&claim(phase, &[RSA_EK_PEM], deleting))
                .await
                .unwrap();
            assert_eq!(
                action,
                Action::await_change(),
                "{phase} deleting={deleting}"
            );
            assert_eq!(
                r.entries.names(),
                Vec::<String>::new(),
                "{phase}: entry retracted"
            );
            assert!(
                r.store.get_claim(uid()).await.unwrap().revoked_at.is_some(),
                "{phase}: revoked"
            );
            assert_eq!(
                r.claims.deleted(),
                Vec::<(String, String)>::new(),
                "release never deletes the claim"
            );
        }
    }

    #[tokio::test]
    async fn a_pending_claim_is_held_and_a_released_one_stays_released() {
        let r = rig(WatcherConfig::default());
        r.store.put_claim(record(uid())).await.unwrap();
        r.store.put_node(node(RSA_EK_HASH, false)).await.unwrap();
        assert_eq!(
            r.watcher
                .reconcile_claim(&claim("Pending", &[], false))
                .await
                .unwrap(),
            Action::await_change()
        );
        assert_eq!(r.entries.names(), Vec::<String>::new());
        // released once, then Bound again (cannot happen in banlieue, must not rebind here)
        r.watcher
            .reconcile_claim(&claim("Bound", &[RSA_EK_PEM], false))
            .await
            .unwrap();
        r.watcher
            .reconcile_claim(&claim("Releasing", &[RSA_EK_PEM], false))
            .await
            .unwrap();
        r.watcher
            .reconcile_claim(&claim("Bound", &[RSA_EK_PEM], false))
            .await
            .unwrap();
        assert_eq!(
            r.entries.names(),
            Vec::<String>::new(),
            "a revoked record is never bound again"
        );
    }

    #[tokio::test]
    async fn a_member_with_a_certificate_gets_a_node_entry_and_one_without_gets_nothing() {
        let r = rig(WatcherConfig::default());
        assert_eq!(
            r.watcher.reconcile_machine(&machine(&[])).await.unwrap(),
            Action::await_change()
        );
        assert_eq!(r.entries.names(), Vec::<String>::new());
        assert_eq!(
            r.watcher
                .reconcile_machine(&machine(&["garbage"]))
                .await
                .unwrap(),
            Action::await_change()
        );
        assert_eq!(
            r.entries.names(),
            Vec::<String>::new(),
            "an unusable certificate declares nothing"
        );
        r.watcher
            .reconcile_machine(&machine(&[RSA_EK_PEM]))
            .await
            .unwrap();
        r.watcher
            .reconcile_machine(&machine(&[RSA_EK_PEM]))
            .await
            .unwrap();
        assert_eq!(r.entries.names(), vec![node_entry_name(RSA_EK_HASH)]);
    }

    #[tokio::test]
    async fn expired_envelopes_are_swept_on_their_own_and_the_rest_stay() {
        // The operator's rule (ADR-0043 decision 4): no secret is stored longer than its claim's TTL. The sweep that
        // enforces it runs on a short timer of its own, not only inside the resync, whose interval is minutes.
        let r = rig(WatcherConfig::default());
        let sealed = || mediatore_store::Sealed {
            key_id: "k".into(),
            nonce: vec![0; 12],
            ciphertext: vec![1, 2, 3],
            format: mediatore_store::seal::FORMAT_SLOT,
        };
        let subject = || Subject {
            issuer: "https://idp.example".into(),
            id: "octocat".into(),
            display: None,
        };
        let parked = |expires_at| mediatore_store::SessionRecord {
            sandbox_uid: Uuid::new_v4(),
            subject: subject(),
            issuer: String::new(),
            refresh: sealed(),
            created_at: Timestamp::now(),
            audience: Some("registry".into()),
            expires_at,
        };
        let gone = parked(Some(Timestamp::now() - jiff::SignedDuration::from_secs(1)));
        let kept = parked(Some(Timestamp::now() + jiff::SignedDuration::from_mins(10)));
        r.store.put_session(gone.clone()).await.unwrap();
        r.store.put_session(kept.clone()).await.unwrap();
        // And one already on a bound claim's record.
        let bound = Uuid::new_v4();
        let mut rec = record(bound);
        rec.delegations.insert(
            "registry".into(),
            mediatore_store::DelegatedSession {
                envelope: sealed(),
                expires_at: Some(Timestamp::now() - jiff::SignedDuration::from_secs(1)),
            },
        );
        r.store.put_claim(rec).await.unwrap();

        assert_eq!(r.watcher.sweep_envelopes().await.unwrap(), 2);
        assert_eq!(
            r.store.take_delegations(gone.sandbox_uid).await.unwrap(),
            Vec::new()
        );
        assert_eq!(
            r.store
                .take_delegations(kept.sandbox_uid)
                .await
                .unwrap()
                .len(),
            1,
            "an envelope with time left stays"
        );
        assert_eq!(
            r.store.get_claim(bound).await.unwrap().delegations,
            std::collections::BTreeMap::new()
        );
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
        r.watcher
            .reconcile_claim(&claim("Bound", &[RSA_EK_PEM], false))
            .await
            .unwrap();
        let mut kept_claim = claim("Bound", &[RSA_EK_PEM], false);
        kept_claim.metadata.uid = Some(kept.to_string());
        r.watcher.reconcile_claim(&kept_claim).await.unwrap();
        // an entry nobody's record knows about
        r.entries
            .create_claim_entry(
                &NodeIdentity::stored(RSA_EK_HASH, &node(RSA_EK_HASH, false).node_id),
                Uuid::new_v4(),
                "sb-0123456789ab",
                std::time::Duration::from_hours(1),
            )
            .await
            .unwrap();
        r.claims.mark_existing(kept);
        let (released, swept, archived) = r.watcher.resync().await.unwrap();
        assert_eq!((released, swept, archived), (1, 1, 0));
        assert!(r.store.get_claim(gone).await.unwrap().revoked_at.is_some());
        assert!(r.store.get_claim(kept).await.unwrap().revoked_at.is_none());
        assert!(
            r.store
                .get_claim(unbound)
                .await
                .unwrap()
                .revoked_at
                .is_none(),
            "never-bound records are not the resync's call"
        );
        assert_eq!(r.entries.names(), vec![claim_entry_name(kept)]);
    }

    /// ADR-0056 decision 5 and open question 7: the Lease holder repeats the self-check at
    /// each resync. When it fails, no new entry is declared (a claim that would bind does
    /// not, a pool member gets no node entry), what is bound stays bound with its entry,
    /// and declaring resumes once the policy answers again.
    #[tokio::test]
    async fn a_failed_self_check_at_resync_stops_new_entries_and_releases_nothing() {
        let store = Arc::new(mediatore_store::MemoryStore::default());
        let entries = Arc::new(mediatore_spire::MemoryEntries::default());
        let gated = Arc::new(mediatore_spire::Gated::new(entries.clone()));
        let claims = Arc::new(crate::fakes::FakeClaims::default());
        let watcher = Watcher::new(
            Reconciler {
                store: store.clone(),
                spire: gated.clone(),
                naming: mediatore_spire::Naming {
                    trust_domain: "sandbox.test".into(),
                },
            },
            claims.clone(),
            WatcherConfig::default(),
        );
        // As at start: proven before anything is declared.
        gated.self_check().await.unwrap();

        let bound = uid();
        let waiting = Uuid::new_v4();
        for u in [bound, waiting] {
            store.put_claim(record(u)).await.unwrap();
            claims.mark_existing(u);
        }
        store.put_node(node(RSA_EK_HASH, false)).await.unwrap();
        watcher
            .reconcile_claim(&claim("Bound", &[RSA_EK_PEM], false))
            .await
            .unwrap();
        assert_eq!(entries.names(), vec![claim_entry_name(bound)]);

        // The policy no longer binds the broker; the resync notices and goes on.
        entries.answer_self_check_with(Some(mediatore_spire::SelfCheckError::Admitted(
            "mediatore-selfcheck-0".into(),
        )));
        let (released, swept, _) = watcher.resync().await.unwrap();
        assert_eq!((released, swept), (0, 0), "nothing is released or swept");
        assert!(!gated.is_proven());
        let kept = store.get_claim(bound).await.unwrap();
        assert!(
            kept.revoked_at.is_none() && kept.entry_id.is_some(),
            "what is bound stays bound"
        );

        // A claim that would bind now does not, and a pool member gets no node entry.
        let mut second = claim("Bound", &[RSA_EK_PEM], false);
        second.metadata.uid = Some(waiting.to_string());
        let refused = watcher.reconcile_claim(&second).await.unwrap_err();
        assert!(refused.to_string().contains("unproven"), "{refused}");
        let refused = watcher
            .reconcile_machine(&machine(&[RSA_EK_PEM]))
            .await
            .unwrap_err();
        assert!(refused.to_string().contains("unproven"), "{refused}");
        assert_eq!(
            entries.names(),
            vec![claim_entry_name(bound)],
            "no new entry, and the bound claim's entry is still declared"
        );
        assert!(store.get_claim(waiting).await.unwrap().entry_id.is_none());

        // The policy binds the broker again: the next resync proves it and binding resumes.
        entries.answer_self_check_with(None);
        watcher.resync().await.unwrap();
        assert!(gated.is_proven());
        watcher.reconcile_claim(&second).await.unwrap();
        assert!(store.get_claim(waiting).await.unwrap().entry_id.is_some());
    }

    #[tokio::test]
    async fn a_resync_archives_rows_whose_claim_ended_before_the_retention() {
        let r = rig(WatcherConfig {
            retention: Duration::ZERO,
            ..WatcherConfig::default()
        });
        let ended = uid();
        let live = Uuid::new_v4();
        for u in [ended, live] {
            r.store.put_claim(record(u)).await.unwrap();
            r.claims.mark_existing(u);
        }
        r.store.revoke_claim(ended, Timestamp::now()).await.unwrap();
        let (released, swept, archived) = r.watcher.resync().await.unwrap();
        assert_eq!((released, swept, archived), (0, 0, 1));
        assert!(matches!(
            r.store.get_claim(ended).await,
            Err(mediatore_store::StoreError::NotFound(_))
        ));
        assert!(r.store.get_claim(live).await.is_ok());
    }

    // ----- collecting the nodes of VMs that are gone (ADR-0039) -------------------------------------------------------

    /// A node registered an hour ago, past the default grace.
    fn old_node(ek: &str) -> mediatore_store::NodeRecord {
        let mut n = node(ek, false);
        n.registered_at = Timestamp::now() - jiff::SignedDuration::from_hours(1);
        n
    }

    #[tokio::test]
    async fn a_node_whose_vm_is_gone_is_collected_and_one_whose_vm_exists_is_kept_on_every_pass() {
        let r = rig(WatcherConfig::default());
        r.store.put_node(old_node(RSA_EK_HASH)).await.unwrap();
        r.store.put_node(old_node("gone-ek")).await.unwrap();
        r.claims.put_machine(machine(&[RSA_EK_PEM]));
        assert_eq!(r.watcher.collect_nodes().await.unwrap(), 1);
        assert!(matches!(
            r.store.get_node("gone-ek").await,
            Err(StoreError::NotFound(_))
        ));
        assert!(r.store.get_node(RSA_EK_HASH).await.is_ok());
        for _ in 0..3 {
            assert_eq!(r.watcher.collect_nodes().await.unwrap(), 0);
        }
        assert!(
            r.store.get_node(RSA_EK_HASH).await.is_ok(),
            "its VM still publishes the hash"
        );
    }

    #[tokio::test]
    async fn a_failed_vm_listing_collects_nothing_and_says_so() {
        let r = rig(WatcherConfig::default());
        r.store.put_node(old_node("gone-ek")).await.unwrap();
        r.claims.put_machine(machine(&[RSA_EK_PEM]));
        r.claims.fail_machine_listing(true);
        assert!(r.watcher.collect_nodes().await.is_err());
        assert!(
            r.store.get_node("gone-ek").await.is_ok(),
            "no list, no deletion"
        );
    }

    #[tokio::test]
    async fn a_banned_node_a_node_with_an_active_claim_and_a_young_node_are_kept() {
        let r = rig(WatcherConfig::default());
        let mut banned = old_node("banned-ek");
        banned.banned = true;
        r.store.put_node(banned).await.unwrap();
        let busy = old_node("busy-ek");
        let mut rec = record(uid());
        rec.node_id = Some(busy.node_id.clone());
        rec.entry_id = Some("entry".into());
        rec.expires_at = Some(Timestamp::now() + jiff::SignedDuration::from_mins(10));
        r.store.put_claim(rec).await.unwrap();
        r.store.put_node(busy).await.unwrap();
        r.store.put_node(node("young-ek", false)).await.unwrap();
        // Another VM is live, so the list is not empty and only the rules decide.
        r.claims.put_machine(machine(&[RSA_EK_PEM]));
        assert_eq!(r.watcher.collect_nodes().await.unwrap(), 0);
        for ek in ["banned-ek", "busy-ek", "young-ek"] {
            assert!(r.store.get_node(ek).await.is_ok(), "{ek} was kept");
        }
    }

    #[tokio::test]
    async fn a_claim_that_ended_no_longer_protects_its_node() {
        let r = rig(WatcherConfig::default());
        let n = old_node("ended-ek");
        let mut rec = record(uid());
        rec.node_id = Some(n.node_id.clone());
        rec.entry_id = Some("entry".into());
        rec.revoked_at = Some(Timestamp::now() - jiff::SignedDuration::from_mins(5));
        r.store.put_claim(rec).await.unwrap();
        r.store.put_node(n).await.unwrap();
        r.claims.put_machine(machine(&[RSA_EK_PEM]));
        assert_eq!(r.watcher.collect_nodes().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn the_grace_is_the_configured_one() {
        let r = rig(WatcherConfig {
            node_grace: Duration::from_hours(2),
            ..WatcherConfig::default()
        });
        r.store.put_node(old_node("gone-ek")).await.unwrap();
        r.claims.put_machine(machine(&[RSA_EK_PEM]));
        assert_eq!(
            r.watcher.collect_nodes().await.unwrap(),
            0,
            "registered an hour ago, inside two hours of grace"
        );
    }

    // ----- retracting the node entries of VMs that are gone (ADR-0039 decision 7) --------------------------------------

    #[tokio::test]
    async fn a_node_entry_whose_vm_is_gone_is_retracted_and_one_whose_vm_exists_is_kept() {
        let r = rig(WatcherConfig::default());
        let gone: String = std::iter::repeat_n('a', 64).collect();
        for ek_hash in [RSA_EK_HASH.to_owned(), gone] {
            r.entries
                .ensure_node_entry(&NodeAttestation::Tpm { ek_hash })
                .await
                .unwrap();
        }
        r.claims.put_machine(machine(&[RSA_EK_PEM]));
        assert_eq!(r.watcher.collect_node_entries().await.unwrap(), 1);
        assert_eq!(r.entries.names(), vec![node_entry_name(RSA_EK_HASH)]);
        for _ in 0..3 {
            assert_eq!(r.watcher.collect_node_entries().await.unwrap(), 0);
        }
        assert_eq!(
            r.entries.names(),
            vec![node_entry_name(RSA_EK_HASH)],
            "its VM still publishes the hash"
        );
    }

    #[tokio::test]
    async fn a_retracted_node_entry_is_declared_again_when_its_vm_comes_back() {
        let r = rig(WatcherConfig::default());
        let vm = machine(&[RSA_EK_PEM]);
        r.watcher.reconcile_machine(&vm).await.unwrap();
        assert_eq!(r.entries.names(), vec![node_entry_name(RSA_EK_HASH)]);
        // No VM lists it, no node and no claim: the empty list is believed and the entry goes.
        assert_eq!(r.watcher.collect_node_entries().await.unwrap(), 1);
        assert_eq!(r.entries.names(), Vec::<String>::new());
        // The VM publishes its certificate again: the entry is declared again, not skipped as
        // one already declared.
        r.watcher.reconcile_machine(&vm).await.unwrap();
        assert_eq!(r.entries.names(), vec![node_entry_name(RSA_EK_HASH)]);
    }

    #[tokio::test]
    async fn a_failed_vm_listing_retracts_no_node_entry() {
        let r = rig(WatcherConfig::default());
        r.entries
            .ensure_node_entry(&NodeAttestation::Tpm {
                ek_hash: RSA_EK_HASH.into(),
            })
            .await
            .unwrap();
        r.claims.fail_machine_listing(true);
        assert!(r.watcher.collect_node_entries().await.is_err());
        assert_eq!(
            r.entries.names(),
            vec![node_entry_name(RSA_EK_HASH)],
            "no list, no retraction"
        );
    }

    #[tokio::test]
    async fn no_node_entries_means_no_listing_of_vms() {
        let r = rig(WatcherConfig::default());
        r.claims.fail_machine_listing(true);
        assert_eq!(r.watcher.collect_node_entries().await.unwrap(), 0);
    }

    #[tokio::test]
    async fn no_nodes_means_no_listing_of_vms() {
        let r = rig(WatcherConfig::default());
        r.claims.fail_machine_listing(true);
        assert_eq!(r.watcher.collect_nodes().await.unwrap(), 0);
    }

    // ----- machines of an x509pop pool (ADR-0049 decisions 9 and 10) ---------------------------------------------------

    const X509POP_POOL: &str = "fc";
    const HOST: &str = "hv-01";
    const SUBJECT: &str = "3f0c2a1e-7b1d-4e0a-9c55-0a1b2c3d4e5f";

    /// `watcher.x509pop_pools: [sandboxes/fc]`.
    fn listed() -> WatcherConfig {
        WatcherConfig {
            x509pop_pools: [format!("sandboxes/{X509POP_POOL}")].into(),
            ..WatcherConfig::default()
        }
    }

    /// A member of `pool` in `sandboxes` that publishes **both** an endorsement certificate
    /// and (when given) an attestation subject, placed (when given) on a Provider: what a
    /// Cloud Hypervisor guest with a vTPM and a signer looks like (banlieue ADR-0146).
    fn member(pool: &str, subject: Option<&str>, provider: Option<&str>) -> VirtualMachine {
        let mut status = json!({ "tpmEndorsementCertificates": [RSA_EK_PEM] });
        if let Some(subject) = subject {
            status["attestationSubject"] = json!(subject);
        }
        if let Some(provider) = provider {
            status["scheduled"] = json!({
                "providerName": provider, "providerClass": "cloud-hypervisor", "failureDomain": "fd-1"
            });
        }
        serde_json::from_value(json!({
            "metadata": { "name": "member-1", "namespace": "sandboxes", "uid": Uuid::new_v4().to_string(), "labels": { "banlieue.io/pool": pool } },
            "spec": { "classRef": { "name": "small" }, "imageRef": { "name": "sandbox" } },
            "status": status
        }))
        .unwrap()
    }

    /// A listed machine with everything its node entry needs.
    fn x509pop_member() -> VirtualMachine {
        member(X509POP_POOL, Some(SUBJECT), Some(HOST))
    }

    /// A `Provider` whose `spec.attestation` is `attestation` (`null` for none).
    fn provider(namespace: &str, name: &str, attestation: &serde_json::Value) -> Provider {
        let mut spec = json!({
            "providerClassRef": { "name": "cloud-hypervisor" },
            "connection": { "endpoint": "https://hv-01.home.example:8443" }
        });
        if !attestation.is_null() {
            spec["attestation"] = attestation.clone();
        }
        serde_json::from_value(json!({
            "apiVersion": "banlieue.io/v1alpha1", "kind": "Provider",
            "metadata": { "name": name, "namespace": namespace },
            "spec": spec
        }))
        .unwrap()
    }

    /// The Provider `hv-01` in `sandboxes` asserting `ca` inline.
    fn provider_with(ca: &HostCa) -> Provider {
        provider(
            "sandboxes",
            HOST,
            &json!({ "hostCa": { "inline": ca.pem() } }),
        )
    }

    /// A `Bound` claim on `member-1`, carrying the machine's endorsement certificate as
    /// banlieue mirrors it.
    fn claim_on_member() -> VirtualMachineClaim {
        let mut c = claim("Bound", &[RSA_EK_PEM], false);
        let status = c.status.as_mut().unwrap();
        status.virtual_machine_ref =
            Some(serde_json::from_value(json!({ "name": "member-1" })).unwrap());
        status.attestation_subject = Some(SUBJECT.into());
        c
    }

    fn naming() -> mediatore_spire::Naming {
        mediatore_spire::Naming {
            trust_domain: "sandbox.test".into(),
        }
    }

    /// The identity `subject` has under a host CA named `issuer`.
    fn x509pop_identity(issuer: &str, subject: &str) -> NodeIdentity {
        NodeIdentity::of(
            &naming(),
            &NodeAttestation::X509pop {
                issuer_cn: issuer.into(),
                subject_cn: subject.into(),
            },
        )
        .unwrap()
    }

    /// The node an x509pop guest registered as.
    fn x509pop_node_record(id: &NodeIdentity) -> mediatore_store::NodeRecord {
        let mut n = node(&id.key, false);
        n.node_id.clone_from(&id.agent_id);
        n
    }

    #[tokio::test]
    async fn a_machine_of_a_listed_pool_gets_an_x509pop_node_entry_and_never_a_tpm_one() {
        let r = rig(listed());
        r.claims.put_provider(provider_with(&HostCa::new(HOST)));
        let action = r
            .watcher
            .reconcile_machine(&x509pop_member())
            .await
            .unwrap();
        // Polled: a change to the Provider raises no event on the machine.
        assert_eq!(action, Action::requeue(WatcherConfig::default().resync));
        let id = x509pop_identity(HOST, SUBJECT);
        assert_eq!(
            r.entries.names(),
            vec![node_entry_name(&id.key)],
            "one entry, named by the x509pop node key, and none for the EK it also publishes"
        );
        assert_eq!(
            r.entries.parent_of(&node_entry_name(&id.key)),
            Some(format!(
                "spiffe://sandbox.test/spire/agent/x509pop/{HOST}/{SUBJECT}"
            ))
        );
        // Declared once.
        r.watcher
            .reconcile_machine(&x509pop_member())
            .await
            .unwrap();
        assert_eq!(r.entries.names().len(), 1);
    }

    #[tokio::test]
    async fn an_unlisted_machine_is_tpm_exactly_as_before_even_when_it_has_an_attestation_subject()
    {
        // The choice is the pool list's, never which data is present (decision 9). Not
        // listed: no list at all, another pool of the namespace, the same pool name in
        // another namespace.
        for pools in [
            vec![],
            vec![format!("sandboxes/{X509POP_POOL}")],
            vec!["elsewhere/pool".to_owned()],
        ] {
            let r = rig(WatcherConfig {
                x509pop_pools: pools.into_iter().collect(),
                ..WatcherConfig::default()
            });
            r.claims.put_provider(provider_with(&HostCa::new(HOST)));
            let vm = member("pool", Some(SUBJECT), Some(HOST));
            assert_eq!(
                r.watcher.reconcile_machine(&vm).await.unwrap(),
                Action::await_change()
            );
            assert_eq!(r.entries.names(), vec![node_entry_name(RSA_EK_HASH)]);
            assert_eq!(
                r.entries.parent_of(&node_entry_name(RSA_EK_HASH)),
                Some(node(RSA_EK_HASH, false).node_id)
            );
            assert_eq!(r.claims.provider_reads(), 0, "no Provider is read for it");
            // And its claim binds by the EK on the claim.
            r.claims.put_machine(vm);
            r.store.put_claim(record(uid())).await.unwrap();
            r.store.put_node(node(RSA_EK_HASH, false)).await.unwrap();
            r.watcher.reconcile_claim(&claim_on_member()).await.unwrap();
            let rec = r.store.get_claim(uid()).await.unwrap();
            assert_eq!(
                rec.node_id.as_deref(),
                Some(node(RSA_EK_HASH, false).node_id.as_str())
            );
            assert_eq!(r.claims.provider_reads(), 0);
        }
    }

    #[tokio::test]
    async fn with_no_x509pop_pool_configured_no_machine_and_no_provider_is_ever_read() {
        // The default is today's behaviour exactly: the claim's own status is all a bind
        // reads, and the collections read the VM list alone.
        let r = rig(WatcherConfig::default());
        r.claims.fail_provider_reads(true);
        r.store.put_claim(record(uid())).await.unwrap();
        r.store.put_node(old_node(RSA_EK_HASH)).await.unwrap();
        // A claim that names no machine binds, as it always has.
        r.watcher
            .reconcile_claim(&claim("Bound", &[RSA_EK_PEM], false))
            .await
            .unwrap();
        assert!(r.store.get_claim(uid()).await.unwrap().entry_id.is_some());
        let vm = member(X509POP_POOL, Some(SUBJECT), Some(HOST));
        r.watcher.reconcile_machine(&vm).await.unwrap();
        r.claims.put_machine(vm);
        r.watcher.collect_nodes().await.unwrap();
        r.watcher.collect_node_entries().await.unwrap();
        assert_eq!(r.claims.machine_reads(), 0);
        assert_eq!(r.claims.provider_reads(), 0);
    }

    #[tokio::test]
    async fn a_bound_claim_of_a_listed_pool_is_bound_under_its_x509pop_node() {
        let r = rig(listed());
        r.claims.put_provider(provider_with(&HostCa::new(HOST)));
        r.claims.put_machine(x509pop_member());
        let id = x509pop_identity(HOST, SUBJECT);
        r.store.put_claim(record(uid())).await.unwrap();
        r.store.put_node(x509pop_node_record(&id)).await.unwrap();
        let action = r.watcher.reconcile_claim(&claim_on_member()).await.unwrap();
        assert_eq!(action, Action::await_change());
        let rec = r.store.get_claim(uid()).await.unwrap();
        assert_eq!(rec.node_id.as_deref(), Some(id.agent_id.as_str()));
        assert_eq!(
            r.entries.parent_of(&claim_entry_name(uid())),
            Some(id.agent_id.clone()),
            "the claim's entry is parented to the x509pop agent"
        );
        assert_eq!(r.claims.deleted(), Vec::<(String, String)>::new());
    }

    #[tokio::test]
    async fn a_claim_of_a_listed_pool_never_binds_to_the_tpm_node_of_its_machines_ek() {
        // The machine publishes an EK, the claim mirrors it, and a node is registered under
        // that EK: everything a TPM bind needs. The pool is listed, so none of it counts.
        let r = rig(WatcherConfig {
            requeue: Duration::from_millis(5),
            ..listed()
        });
        r.claims.put_provider(provider_with(&HostCa::new(HOST)));
        r.claims.put_machine(x509pop_member());
        r.store.put_claim(record(uid())).await.unwrap();
        r.store.put_node(node(RSA_EK_HASH, false)).await.unwrap();
        let action = r.watcher.reconcile_claim(&claim_on_member()).await.unwrap();
        assert_eq!(action, Action::requeue(Duration::from_millis(5)));
        assert_eq!(
            r.watcher.resolve(&claim_on_member()).await.unwrap(),
            Resolution::NotYet("no node registered for the machine's x509pop identity".into())
        );
        let rec = r.store.get_claim(uid()).await.unwrap();
        assert!(rec.entry_id.is_none() && rec.node_id.is_none());
        assert_eq!(r.entries.names(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn a_node_registered_under_another_agent_id_than_its_machine_attests_as_is_refused() {
        // The record under the machine's key carries a tpm agent ID made from that key: what
        // a broker before ADR-0049 decision 8 would have stored. Nothing is parented to it.
        let r = rig(listed());
        r.claims.put_provider(provider_with(&HostCa::new(HOST)));
        r.claims.put_machine(x509pop_member());
        let id = x509pop_identity(HOST, SUBJECT);
        r.store.put_claim(record(uid())).await.unwrap();
        r.store.put_node(node(&id.key, false)).await.unwrap();
        let resolved = r.watcher.resolve(&claim_on_member()).await.unwrap();
        assert!(
            matches!(&resolved, Resolution::Refused(why) if why.contains("another agent ID")),
            "refused, and for that reason"
        );
        r.watcher.reconcile_claim(&claim_on_member()).await.unwrap();
        assert!(r.store.get_claim(uid()).await.unwrap().revoked_at.is_some());
        assert_eq!(r.entries.names(), Vec::<String>::new());
    }

    /// What a listed machine with something missing must come to, whatever is missing: no
    /// node entry of either kind, and its claim not bound, although the machine publishes an
    /// EK, the claim mirrors it and a node is registered under that EK. `wait` says whether
    /// the cause may pass (the claim is retried until the resolve timeout) or not (it fails
    /// at once). The reason names the cause.
    async fn refused_with(r: &crate::fakes::Rig, vm: VirtualMachine, wait: bool, names: &[&str]) {
        let found = r.watcher.x509pop_node(&vm).await.unwrap();
        let ((MachineNode::NotYet(reason) | MachineNode::NoProvider(reason), true)
        | (MachineNode::Unusable(reason), false)) = (&found, wait)
        else {
            panic!("the machine was not judged as expected (wait={wait})")
        };
        for word in names {
            assert!(reason.contains(word), "the reason does not name {word:?}");
        }
        r.watcher.reconcile_machine(&vm).await.unwrap();
        assert_eq!(
            r.entries.names(),
            Vec::<String>::new(),
            "no node entry, and no TPM one in its place"
        );
        r.claims.set_machines(vec![vm]);
        r.store.put_claim(record(uid())).await.unwrap();
        r.store.put_node(node(RSA_EK_HASH, false)).await.unwrap();
        let action = r.watcher.reconcile_claim(&claim_on_member()).await.unwrap();
        let rec = r.store.get_claim(uid()).await.unwrap();
        assert!(rec.entry_id.is_none() && rec.node_id.is_none(), "unbound");
        assert_eq!(r.entries.names(), Vec::<String>::new());
        if wait {
            assert_eq!(action, Action::requeue(r.watcher.config().requeue));
            assert!(rec.revoked_at.is_none(), "left unbound, retried");
            tokio::time::sleep(r.watcher.config().resolve_timeout + Duration::from_millis(10))
                .await;
            r.watcher.reconcile_claim(&claim_on_member()).await.unwrap();
        }
        let rec = r.store.get_claim(uid()).await.unwrap();
        assert!(rec.revoked_at.is_some(), "the claim is failed");
        assert!(rec.entry_id.is_none());
        assert_eq!(r.claims.deleted().len(), 1);
        assert_eq!(r.entries.names(), Vec::<String>::new());
    }

    /// A rig with the pool listed and short timings, so a cause that may pass times out.
    fn listed_rig() -> crate::fakes::Rig {
        rig(WatcherConfig {
            resolve_timeout: Duration::from_millis(40),
            requeue: Duration::from_millis(5),
            ..listed()
        })
    }

    #[tokio::test]
    async fn a_listed_machine_with_no_attestation_subject_gets_no_entry_and_its_claim_is_not_bound()
    {
        let r = listed_rig();
        r.claims.put_provider(provider_with(&HostCa::new(HOST)));
        let vm = member(X509POP_POOL, None, Some(HOST));
        refused_with(&r, vm, true, &["attestationSubject", "member-1"]).await;
    }

    #[tokio::test]
    async fn a_listed_machine_not_placed_on_a_provider_gets_no_entry_and_its_claim_is_not_bound() {
        let r = listed_rig();
        r.claims.put_provider(provider_with(&HostCa::new(HOST)));
        let vm = member(X509POP_POOL, Some(SUBJECT), None);
        refused_with(&r, vm, true, &["not placed on a Provider", "member-1"]).await;
    }

    #[tokio::test]
    async fn a_listed_machine_whose_provider_does_not_exist_gets_no_entry_and_its_claim_is_not_bound()
     {
        let r = listed_rig();
        refused_with(&r, x509pop_member(), true, &["Provider hv-01", "not found"]).await;
    }

    #[tokio::test]
    async fn a_listed_machine_whose_provider_asserts_no_host_ca_gets_no_entry_and_its_claim_fails()
    {
        // No attestation block at all, and one that anchors only the TPM path.
        for attestation in [
            serde_json::Value::Null,
            json!({ "ekTrustBundle": { "inline": HostCa::new(HOST).pem() } }),
        ] {
            let r = listed_rig();
            r.claims
                .put_provider(provider("sandboxes", HOST, &attestation));
            refused_with(
                &r,
                x509pop_member(),
                false,
                &["Provider sandboxes/hv-01", "no spec.attestation.hostCa"],
            )
            .await;
        }
    }

    #[tokio::test]
    async fn a_listed_machine_whose_host_ca_is_a_reference_gets_no_entry_and_its_claim_fails() {
        // Decision 10: inline only. A reference is refused by name, never resolved, and an
        // inline value beside one does not rescue it.
        let ca = HostCa::new(HOST);
        for host_ca in [
            json!({ "configMapRef": { "name": "host-ca" } }),
            json!({ "secretRef": { "name": "host-ca", "key": "ca.crt" } }),
            json!({ "inline": ca.pem(), "configMapRef": { "name": "host-ca" } }),
        ] {
            let r = listed_rig();
            r.claims
                .put_provider(provider("sandboxes", HOST, &json!({ "hostCa": host_ca })));
            refused_with(
                &r,
                x509pop_member(),
                false,
                &[
                    "Provider sandboxes/hv-01",
                    "must be inline",
                    "configMapRef or secretRef",
                ],
            )
            .await;
        }
    }

    #[tokio::test]
    async fn a_listed_machine_whose_host_ca_is_refused_gets_no_entry_and_its_claim_fails() {
        // What `host_ca_common_name` refuses (decision 2): a CA that may sign further CAs, a
        // certificate that is no CA, two certificates, a name outside the alphabet, garbage.
        let two = format!("{}{}", HostCa::new(HOST).pem(), HostCa::new("hv-02").pem());
        for pem in [
            HostCa::with_constraints(HOST, IsCa::Ca(BasicConstraints::Unconstrained))
                .pem()
                .to_owned(),
            HostCa::with_constraints(HOST, IsCa::Ca(BasicConstraints::Constrained(1)))
                .pem()
                .to_owned(),
            HostCa::with_constraints(HOST, IsCa::ExplicitNoCa)
                .pem()
                .to_owned(),
            two,
            HostCa::new("hv 01").pem().to_owned(),
            "not a certificate".to_owned(),
            String::new(),
        ] {
            let r = listed_rig();
            r.claims.put_provider(provider(
                "sandboxes",
                HOST,
                &json!({ "hostCa": { "inline": pem } }),
            ));
            refused_with(
                &r,
                x509pop_member(),
                false,
                &["Provider sandboxes/hv-01", "unusable"],
            )
            .await;
        }
    }

    #[tokio::test]
    async fn a_listed_machine_whose_subject_cannot_be_a_path_segment_gets_no_entry_and_its_claim_fails()
     {
        let r = listed_rig();
        r.claims.put_provider(provider_with(&HostCa::new(HOST)));
        let vm = member(X509POP_POOL, Some("../other-host/vm"), Some(HOST));
        refused_with(&r, vm, false, &["attestationSubject", "unusable"]).await;
    }

    #[tokio::test]
    async fn a_claim_of_a_listed_configuration_that_names_no_machine_or_a_missing_one_waits() {
        let r = listed_rig();
        r.store.put_claim(record(uid())).await.unwrap();
        r.store.put_node(node(RSA_EK_HASH, false)).await.unwrap();
        // No virtualMachineRef: the pool cannot be known, so the EK is not consulted either.
        let unnamed = claim("Bound", &[RSA_EK_PEM], false);
        assert_eq!(
            r.watcher.resolve(&unnamed).await.unwrap(),
            Resolution::NotYet("the claim names no machine yet".into())
        );
        // A machine that does not exist.
        let resolved = r.watcher.resolve(&claim_on_member()).await.unwrap();
        assert!(
            matches!(&resolved, Resolution::NotYet(why) if why.contains("sandboxes/member-1") && why.contains("does not exist")),
            "waits, naming the machine"
        );
        assert_eq!(r.entries.names(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn the_provider_is_its_own_namespaces_and_the_provider_namespaces_only_when_that_holds_none()
     {
        // banlieue ADR-0133 decision 1, which placed the machine: a namespace holding any
        // Provider is the whole candidate set.
        let shared = |ca: &HostCa| {
            provider(
                "banlieue-providers",
                HOST,
                &json!({ "hostCa": { "inline": ca.pem() } }),
            )
        };
        let with_fallback = || {
            rig(WatcherConfig {
                provider_namespace: Some("banlieue-providers".into()),
                ..listed()
            })
        };
        let known = |issuer: &str| {
            MachineNode::Known(NodeAttestation::X509pop {
                issuer_cn: issuer.into(),
                subject_cn: SUBJECT.into(),
            })
        };
        // None in its own namespace, no provider namespace configured: not found.
        let r = rig(listed());
        r.claims.put_provider(shared(&HostCa::new("shared-ca")));
        assert!(matches!(
            r.watcher.x509pop_node(&x509pop_member()).await.unwrap(),
            MachineNode::NoProvider(_)
        ));
        // None in its own namespace, a provider namespace configured: found there.
        let r = with_fallback();
        r.claims.put_provider(shared(&HostCa::new("shared-ca")));
        assert_eq!(
            r.watcher.x509pop_node(&x509pop_member()).await.unwrap(),
            known("shared-ca")
        );
        // Its own namespace holds the Provider: that one, not the shared one of the name.
        r.claims.put_provider(provider_with(&HostCa::new("own-ca")));
        assert_eq!(
            r.watcher.x509pop_node(&x509pop_member()).await.unwrap(),
            known("own-ca")
        );
        // Its own namespace holds another Provider only: no fallback to the shared one.
        let r = with_fallback();
        r.claims.put_provider(shared(&HostCa::new("shared-ca")));
        r.claims.put_provider(provider(
            "sandboxes",
            "another",
            &json!({ "hostCa": { "inline": HostCa::new("another-ca").pem() } }),
        ));
        assert!(matches!(
            r.watcher.x509pop_node(&x509pop_member()).await.unwrap(),
            MachineNode::NoProvider(_)
        ));
    }

    #[tokio::test]
    async fn a_provider_that_cannot_be_read_is_an_error_and_nothing_is_declared_bound_or_collected()
    {
        let r = rig(listed());
        r.claims.put_provider(provider_with(&HostCa::new(HOST)));
        let id = x509pop_identity(HOST, SUBJECT);
        // A node and its entry, both an hour old, and the machine that gives their key.
        let mut registered = x509pop_node_record(&id);
        registered.registered_at = Timestamp::now() - jiff::SignedDuration::from_hours(1);
        r.store.put_node(registered).await.unwrap();
        r.watcher
            .reconcile_machine(&x509pop_member())
            .await
            .unwrap();
        r.claims.put_machine(x509pop_member());
        r.store.put_claim(record(uid())).await.unwrap();

        r.claims.fail_provider_reads(true);
        assert!(
            r.watcher
                .reconcile_machine(&x509pop_member())
                .await
                .is_err()
        );
        assert!(r.watcher.reconcile_claim(&claim_on_member()).await.is_err());
        assert!(r.watcher.collect_nodes().await.is_err());
        assert!(r.watcher.collect_node_entries().await.is_err());
        assert!(
            r.store.get_node(&id.key).await.is_ok(),
            "no read, no deletion"
        );
        assert_eq!(r.entries.names(), vec![node_entry_name(&id.key)]);
        let rec = r.store.get_claim(uid()).await.unwrap();
        assert!(rec.entry_id.is_none() && rec.revoked_at.is_none());
        assert_eq!(r.claims.deleted(), Vec::<(String, String)>::new());
    }

    #[tokio::test]
    async fn an_x509pop_node_and_its_entry_live_as_long_as_their_machine_gives_their_key() {
        let r = rig(listed());
        r.claims.put_provider(provider_with(&HostCa::new(HOST)));
        let id = x509pop_identity(HOST, SUBJECT);
        let mut registered = x509pop_node_record(&id);
        registered.registered_at = Timestamp::now() - jiff::SignedDuration::from_hours(1);
        r.store.put_node(registered).await.unwrap();
        r.watcher
            .reconcile_machine(&x509pop_member())
            .await
            .unwrap();
        // A TPM machine beside it, so the VM list is never empty.
        let tpm = machine(&[RSA_EK_PEM]);
        r.claims.set_machines(vec![x509pop_member(), tpm.clone()]);
        for _ in 0..3 {
            assert_eq!(r.watcher.collect_nodes().await.unwrap(), 0);
            assert_eq!(r.watcher.collect_node_entries().await.unwrap(), 0);
        }
        assert!(r.store.get_node(&id.key).await.is_ok());
        assert_eq!(r.entries.names(), vec![node_entry_name(&id.key)]);
        // The machine is gone: its EK was never what kept anything.
        r.claims.set_machines(vec![tpm]);
        assert_eq!(r.watcher.collect_nodes().await.unwrap(), 1);
        assert_eq!(r.watcher.collect_node_entries().await.unwrap(), 1);
        assert!(matches!(
            r.store.get_node(&id.key).await,
            Err(StoreError::NotFound(_))
        ));
        assert_eq!(r.entries.names(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn an_ek_a_listed_machine_publishes_keeps_no_tpm_node_or_entry_alive() {
        // The live set is computed by the pool list too: a listed machine's EK is no key.
        let r = rig(listed());
        r.claims.put_provider(provider_with(&HostCa::new(HOST)));
        r.store.put_node(old_node(RSA_EK_HASH)).await.unwrap();
        r.entries
            .ensure_node_entry(&NodeAttestation::Tpm {
                ek_hash: RSA_EK_HASH.into(),
            })
            .await
            .unwrap();
        r.claims.put_machine(x509pop_member());
        assert_eq!(r.watcher.collect_nodes().await.unwrap(), 1);
        assert_eq!(r.watcher.collect_node_entries().await.unwrap(), 1);
        assert_eq!(r.entries.names(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn a_host_ca_under_a_new_common_name_moves_the_node_entry_to_the_new_key() {
        let r = rig(listed());
        r.claims.put_provider(provider_with(&HostCa::new(HOST)));
        r.claims.put_machine(x509pop_member());
        r.watcher
            .reconcile_machine(&x509pop_member())
            .await
            .unwrap();
        let old = x509pop_identity(HOST, SUBJECT);
        assert_eq!(r.entries.names(), vec![node_entry_name(&old.key)]);
        // The administrator replaces the host's CA with one of another name.
        r.claims
            .put_provider(provider_with(&HostCa::new("hv-01-2027")));
        let new = x509pop_identity("hv-01-2027", SUBJECT);
        assert_ne!(old.key, new.key);
        // The old entry is no machine's: retracted, with nothing else live.
        assert_eq!(r.watcher.collect_node_entries().await.unwrap(), 1);
        assert_eq!(r.entries.names(), Vec::<String>::new());
        // The machine's next pass declares the entry under the new key.
        r.watcher
            .reconcile_machine(&x509pop_member())
            .await
            .unwrap();
        assert_eq!(r.entries.names(), vec![node_entry_name(&new.key)]);
        assert_eq!(
            r.entries.parent_of(&node_entry_name(&new.key)),
            Some(new.agent_id)
        );
        assert_eq!(r.watcher.collect_node_entries().await.unwrap(), 0);
        // The host CA withdrawn from the Provider (banlieue's revocation): a deliberate act,
        // the machine gives no key at all and its entry goes.
        r.claims
            .put_provider(provider("sandboxes", HOST, &serde_json::Value::Null));
        assert_eq!(r.watcher.collect_node_entries().await.unwrap(), 1);
        assert_eq!(r.entries.names(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn a_provider_gone_for_a_pass_and_back_costs_no_x509pop_node_or_entry() {
        // A Provider deleted and applied again (a GitOps sync): for a pass its machines
        // give no key because something is missing, not because anything was withdrawn.
        // Nothing x509pop is collected on that; a TPM node whose VM is gone still is.
        let r = rig(listed());
        let ca = HostCa::new(HOST);
        r.claims.put_provider(provider_with(&ca));
        let id = x509pop_identity(HOST, SUBJECT);
        let mut registered = x509pop_node_record(&id);
        registered.registered_at = Timestamp::now() - jiff::SignedDuration::from_hours(1);
        r.store.put_node(registered).await.unwrap();
        r.store.put_node(old_node("gone-ek")).await.unwrap();
        r.watcher
            .reconcile_machine(&x509pop_member())
            .await
            .unwrap();
        // Another host's machine of the pool, its Provider untouched throughout.
        let other_ca = HostCa::new("hv-02");
        r.claims.put_provider(provider(
            "sandboxes",
            "hv-02",
            &json!({ "hostCa": { "inline": other_ca.pem() } }),
        ));
        let mut other = member(X509POP_POOL, Some("other-subject"), Some("hv-02"));
        other.metadata.name = Some("member-2".into());
        r.watcher.reconcile_machine(&other).await.unwrap();
        r.claims.set_machines(vec![x509pop_member(), other.clone()]);
        let both = r.entries.names();
        assert_eq!(both.len(), 2);

        r.claims.remove_provider("sandboxes", HOST);
        assert_eq!(
            r.watcher.collect_nodes().await.unwrap(),
            1,
            "the TPM node whose VM is gone, and no x509pop one"
        );
        assert_eq!(r.watcher.collect_node_entries().await.unwrap(), 0);
        assert!(r.store.get_node(&id.key).await.is_ok());
        assert_eq!(r.entries.names(), both, "no entry retracted");
        // The machine's own pass declares nothing and forgets nothing meanwhile.
        r.watcher
            .reconcile_machine(&x509pop_member())
            .await
            .unwrap();
        assert_eq!(r.entries.names(), both);

        // Back, the same certificate: nothing to collect, and nothing to declare again.
        r.claims.put_provider(provider_with(&ca));
        assert_eq!(r.watcher.collect_nodes().await.unwrap(), 0);
        assert_eq!(r.watcher.collect_node_entries().await.unwrap(), 0);
        r.watcher
            .reconcile_machine(&x509pop_member())
            .await
            .unwrap();
        assert_eq!(r.entries.names(), both);
        let still_declared = r.watcher.declared.lock().unwrap().contains(&id.key);
        assert!(still_declared, "the entry was never taken for retracted");
    }

    /// `vm` as created `ago` before now; `None` leaves it with no creation timestamp.
    fn created(mut vm: VirtualMachine, ago: Option<jiff::SignedDuration>) -> VirtualMachine {
        vm.metadata.creation_timestamp = ago.map(|ago| {
            k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(Timestamp::now() - ago)
        });
        vm
    }

    /// A rig with the pool listed, the host's Provider in place, a live listed machine, and
    /// the hour-old node of an x509pop machine that is gone: what a collection would take.
    async fn rig_with_a_dead_x509pop_node() -> crate::fakes::Rig {
        let r = rig(listed());
        r.claims.put_provider(provider_with(&HostCa::new(HOST)));
        let gone = x509pop_identity(HOST, "gone-subject");
        let mut registered = x509pop_node_record(&gone);
        registered.registered_at = Timestamp::now() - jiff::SignedDuration::from_hours(1);
        r.store.put_node(registered).await.unwrap();
        r
    }

    #[tokio::test]
    async fn a_young_listed_machine_still_being_provisioned_holds_the_x509pop_collection_and_an_old_one_does_not()
     {
        // No subject yet, or not placed yet: a machine on its way. It holds the collection
        // of x509pop nodes while it is younger than the node grace (ten minutes by default),
        // and not a moment longer: a machine that never gets there, or one labelled into a
        // listed pool by whoever may label machines, must not stop the collection for good.
        // A machine with no creation timestamp is not young.
        let unprovisioned = || {
            let mut no_subject = member(X509POP_POOL, None, Some(HOST));
            no_subject.metadata.name = Some("member-2".into());
            let mut not_placed = member(X509POP_POOL, Some("another-subject"), None);
            not_placed.metadata.name = Some("member-3".into());
            [no_subject, not_placed]
        };
        for pending in unprovisioned() {
            let r = rig_with_a_dead_x509pop_node().await;
            let young = created(pending.clone(), Some(jiff::SignedDuration::from_mins(9)));
            r.claims.set_machines(vec![x509pop_member(), young]);
            assert_eq!(r.watcher.collect_nodes().await.unwrap(), 0, "held");
            // Provisioned: the set is whole, and the node whose machine is gone goes.
            r.claims.set_machines(vec![x509pop_member()]);
            assert_eq!(r.watcher.collect_nodes().await.unwrap(), 1);
        }
        for age in [Some(jiff::SignedDuration::from_mins(11)), None] {
            for pending in unprovisioned() {
                let r = rig_with_a_dead_x509pop_node().await;
                r.claims
                    .set_machines(vec![x509pop_member(), created(pending, age)]);
                assert_eq!(
                    r.watcher.collect_nodes().await.unwrap(),
                    1,
                    "past the grace it holds nothing: the dead node is collected"
                );
            }
        }
    }

    #[tokio::test]
    async fn the_grace_a_machine_being_provisioned_holds_for_is_the_node_grace() {
        let r = rig(WatcherConfig {
            node_grace: Duration::from_hours(2),
            ..listed()
        });
        r.claims.put_provider(provider_with(&HostCa::new(HOST)));
        let gone = x509pop_identity(HOST, "gone-subject");
        let mut registered = x509pop_node_record(&gone);
        registered.registered_at = Timestamp::now() - jiff::SignedDuration::from_hours(3);
        r.store.put_node(registered).await.unwrap();
        let mut pending = member(X509POP_POOL, None, Some(HOST));
        pending.metadata.name = Some("member-2".into());
        let hour_old = created(pending.clone(), Some(jiff::SignedDuration::from_hours(1)));
        r.claims.set_machines(vec![x509pop_member(), hour_old]);
        assert_eq!(
            r.watcher.collect_nodes().await.unwrap(),
            0,
            "inside two hours"
        );
        let older = created(pending, Some(jiff::SignedDuration::from_hours(3)));
        r.claims.set_machines(vec![x509pop_member(), older]);
        assert_eq!(r.watcher.collect_nodes().await.unwrap(), 1);
    }

    #[tokio::test]
    async fn a_missing_provider_holds_the_x509pop_collection_whatever_the_machines_age() {
        // The Provider is the administrators': one deleted and applied again must cost no
        // guest its identity, however long its machines have existed.
        for age in [
            Some(jiff::SignedDuration::from_mins(1)),
            Some(jiff::SignedDuration::from_hours(24 * 30)),
            None,
        ] {
            let r = rig_with_a_dead_x509pop_node().await;
            let mut orphan = member(X509POP_POOL, Some("another-subject"), Some("hv-gone"));
            orphan.metadata.name = Some("member-2".into());
            r.claims
                .set_machines(vec![x509pop_member(), created(orphan, age)]);
            for _ in 0..3 {
                assert_eq!(r.watcher.collect_nodes().await.unwrap(), 0, "held");
            }
        }
    }

    #[tokio::test]
    async fn two_providers_asserting_different_cas_under_one_name_get_no_entry_either() {
        // Decision 2: the issuer's common name is what confines a host to its own guests.
        // Two CAs under one name, on Providers of two namespaces: neither host's machines
        // get an entry, and the reason names the name and both Providers.
        let r = listed_rig();
        r.claims.put_provider(provider_with(&HostCa::new(HOST)));
        r.claims.put_provider(provider(
            "team-b",
            "hv-elsewhere",
            &json!({ "hostCa": { "inline": HostCa::new(HOST).pem() } }),
        ));
        refused_with(
            &r,
            x509pop_member(),
            false,
            &[
                "two Providers assert host CAs named \"hv-01\"",
                "sandboxes/hv-01",
                "team-b/hv-elsewhere",
            ],
        )
        .await;
        // The other Provider's own machine is refused the same way.
        let r = rig(WatcherConfig {
            x509pop_pools: ["team-b/fc".to_owned()].into(),
            ..WatcherConfig::default()
        });
        r.claims.put_provider(provider_with(&HostCa::new(HOST)));
        r.claims.put_provider(provider(
            "team-b",
            "hv-elsewhere",
            &json!({ "hostCa": { "inline": HostCa::new(HOST).pem() } }),
        ));
        let mut theirs = member(X509POP_POOL, Some(SUBJECT), Some("hv-elsewhere"));
        theirs.metadata.namespace = Some("team-b".into());
        let found = r.watcher.x509pop_node(&theirs).await.unwrap();
        assert!(
            matches!(&found, MachineNode::Unusable(why) if why.contains("two Providers assert")),
            "refused from the other side too"
        );
        r.watcher.reconcile_machine(&theirs).await.unwrap();
        assert_eq!(r.entries.names(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn the_same_host_ca_on_two_providers_is_one_ca_and_a_rival_that_goes_frees_the_name() {
        let r = rig(listed());
        let ca = HostCa::new(HOST);
        r.claims.put_provider(provider_with(&ca));
        // The same certificate asserted again (a host serving two namespaces), and beside
        // it CAs of other names and a Provider with nothing to say.
        r.claims.put_provider(provider(
            "team-b",
            HOST,
            &json!({ "hostCa": { "inline": ca.pem() } }),
        ));
        r.claims.put_provider(provider(
            "team-b",
            "hv-02",
            &json!({ "hostCa": { "inline": HostCa::new("hv-02").pem() } }),
        ));
        r.claims
            .put_provider(provider("team-b", "plain", &serde_json::Value::Null));
        r.watcher
            .reconcile_machine(&x509pop_member())
            .await
            .unwrap();
        let id = x509pop_identity(HOST, SUBJECT);
        assert_eq!(r.entries.names(), vec![node_entry_name(&id.key)]);
        // A rival appears: the entry is retracted at the next collection (a withdrawal of
        // trust, not something missing), and declared again once the rival is gone.
        r.claims.put_machine(x509pop_member());
        r.claims.put_provider(provider(
            "team-c",
            "impostor",
            &json!({ "hostCa": { "inline": HostCa::new(HOST).pem() } }),
        ));
        assert_eq!(r.watcher.collect_node_entries().await.unwrap(), 1);
        r.watcher
            .reconcile_machine(&x509pop_member())
            .await
            .unwrap();
        assert_eq!(r.entries.names(), Vec::<String>::new());
        r.claims.remove_provider("team-c", "impostor");
        r.watcher
            .reconcile_machine(&x509pop_member())
            .await
            .unwrap();
        assert_eq!(r.entries.names(), vec![node_entry_name(&id.key)]);
    }

    #[tokio::test]
    async fn the_providers_are_listed_once_for_a_whole_pass_however_many_machines_it_reads() {
        let r = rig(listed());
        r.claims.put_provider(provider_with(&HostCa::new(HOST)));
        let machines: Vec<VirtualMachine> = (0..5)
            .map(|i| {
                let mut vm = member(X509POP_POOL, Some(&format!("subject-{i}")), Some(HOST));
                vm.metadata.name = Some(format!("member-{i}"));
                vm
            })
            .collect();
        r.store.put_node(old_node("gone-ek")).await.unwrap();
        r.claims.set_machines(machines.clone());
        assert_eq!(r.watcher.collect_nodes().await.unwrap(), 1);
        assert_eq!(
            r.claims.provider_reads(),
            1,
            "one listing for five machines"
        );
        r.watcher.reconcile_machine(&machines[0]).await.unwrap();
        assert_eq!(
            r.claims.provider_reads(),
            2,
            "and one for a machine's own pass"
        );
    }

    #[tokio::test]
    async fn two_listed_machines_that_give_one_key_share_one_node_entry_until_both_are_gone() {
        // banlieue gives every machine its own subject (its UID). Two machines publishing
        // one subject under one host CA are one x509pop identity as far as SPIRE can tell:
        // one node entry, declared once, kept while either machine exists. What stops the
        // second machine from *being* the node is the registration: a second DMI UUID under
        // a registered node key is a 409 (the store's conformance cases).
        let r = rig(listed());
        r.claims.put_provider(provider_with(&HostCa::new(HOST)));
        let first = x509pop_member();
        let mut second = x509pop_member();
        second.metadata.name = Some("member-2".into());
        r.watcher.reconcile_machine(&first).await.unwrap();
        r.watcher.reconcile_machine(&second).await.unwrap();
        let id = x509pop_identity(HOST, SUBJECT);
        assert_eq!(r.entries.names(), vec![node_entry_name(&id.key)]);
        // A TPM machine beside them, so the VM list is never empty.
        let tpm = machine(&[RSA_EK_PEM]);
        r.claims
            .set_machines(vec![first, second.clone(), tpm.clone()]);
        assert_eq!(r.watcher.collect_node_entries().await.unwrap(), 0);
        r.claims.set_machines(vec![second, tpm.clone()]);
        assert_eq!(
            r.watcher.collect_node_entries().await.unwrap(),
            0,
            "one of the two still gives the key"
        );
        r.claims.set_machines(vec![tpm]);
        assert_eq!(r.watcher.collect_node_entries().await.unwrap(), 1);
        assert_eq!(r.entries.names(), Vec::<String>::new());
    }

    #[tokio::test]
    async fn an_x509pop_node_entry_under_a_live_claim_is_kept_when_its_machine_is_gone() {
        let r = rig(listed());
        r.claims.put_provider(provider_with(&HostCa::new(HOST)));
        let id = x509pop_identity(HOST, SUBJECT);
        r.watcher
            .reconcile_machine(&x509pop_member())
            .await
            .unwrap();
        let mut rec = record(uid());
        rec.node_id = Some(id.agent_id.clone());
        rec.entry_id = Some("entry".into());
        rec.expires_at = Some(Timestamp::now() + jiff::SignedDuration::from_mins(10));
        r.store.put_claim(rec).await.unwrap();
        // Another VM is live, so the list is believed and only the guards decide.
        r.claims.put_machine(machine(&[RSA_EK_PEM]));
        assert_eq!(r.watcher.collect_node_entries().await.unwrap(), 0);
        assert_eq!(r.entries.names(), vec![node_entry_name(&id.key)]);
    }

    // ADR-0055: under `bundles` the watcher reads the audience catalog, not the file.

    mod catalog {
        use std::sync::Arc;

        use jiff::Timestamp;
        use mediatore_policy::types::{
            AudienceCredential, AudienceDefinition, Backend, CredentialFormat, Placement,
        };
        use mediatore_testkit::policy::{audience_configmap, fresh_bundle, signed_audience};

        use crate::audience::{AudienceReflector, LiveCatalog};
        use crate::watch::WatcherConfig;

        const PLATFORM: &str = "sandbox-platform";

        fn def(backend: Backend, endpoint: &str) -> AudienceDefinition {
            AudienceDefinition {
                credential: AudienceCredential {
                    backend,
                    placement: Placement::Proxy,
                    format: CredentialFormat::Bearer,
                    source: None,
                    header: None,
                    extra_headers: Vec::new(),
                    refresh: None,
                },
                endpoints: vec![endpoint.into()],
                rules: Vec::new(),
                max_ttl_seconds: 300,
                ca_ref: None,
            }
        }

        async fn live(entries: &[(&str, &str, AudienceDefinition)]) -> Arc<LiveCatalog> {
            let keys = signed_audience(
                Timestamp::now(),
                1,
                PLATFORM,
                "x",
                def(Backend::None, "x.example:443"),
            )
            .keys;
            let r = AudienceReflector::new(
                mediatore_store::MemoryStore::shared(),
                keys,
                PLATFORM.into(),
                vec![
                    PLATFORM.into(),
                    "team-a".into(),
                    "team-b".into(),
                    "conformance".into(),
                ],
            );
            for (ns, name, d) in entries {
                let a = signed_audience(Timestamp::now(), 1, ns, name, d.clone());
                r.applied(&audience_configmap(ns, name, &a.envelope)).await;
            }
            r.live()
        }

        #[tokio::test]
        async fn a_team_audience_is_usable_in_its_namespace_and_a_platform_one_everywhere() {
            let cfg = WatcherConfig {
                catalog: Some(
                    live(&[
                        ("team-a", "registry", def(Backend::None, "r.example:443")),
                        (PLATFORM, "shared", def(Backend::Delegated, "s.example:443")),
                    ])
                    .await,
                ),
                ..WatcherConfig::default()
            };
            assert!(cfg.usable("registry", "team-a"));
            assert!(!cfg.usable("registry", "team-b"));
            assert!(cfg.usable("shared", "team-b"));
            assert!(!cfg.usable("nowhere", "team-a"));
            assert!(cfg.is_delegated("shared", "team-a"));
            assert!(!cfg.is_delegated("registry", "team-a"));
            let mut seen: Vec<String> = cfg
                .audiences_in("team-a")
                .into_iter()
                .map(|a| a.name)
                .collect();
            seen.sort();
            assert_eq!(seen, ["registry", "shared"]);
            let seen: Vec<String> = cfg
                .audiences_in("team-b")
                .into_iter()
                .map(|a| a.name)
                .collect();
            assert_eq!(seen, ["shared"]);
            // A file audience counts for nothing once the catalog serves.
            let cfg = WatcherConfig {
                audiences: vec![crate::shadow::Audience::named("registry")],
                ..cfg
            };
            assert!(!cfg.usable("registry", "team-b"));
        }

        /// ADR-0055 decision 3: a team audience is granted only by a policy of its own namespace;
        /// a platform audience by a policy of any namespace the sandbox draws from.
        #[tokio::test]
        async fn a_team_audience_is_granted_only_by_a_policy_of_its_own_namespace() {
            let bundle = fresh_bundle(Timestamp::now(), 1).payload;
            let policy_ns = bundle.content.policy.namespace.clone();
            let granted = &bundle.content.audiences[0];
            let endpoint = granted.endpoints[0].clone();
            let team = |ns: &str| (ns.to_owned(), def(Backend::None, &endpoint));
            let cfg_with = |entries: Vec<(String, AudienceDefinition)>| async move {
                let entries: Vec<(&str, &str, AudienceDefinition)> = entries
                    .iter()
                    .map(|(ns, d)| (ns.as_str(), granted.name.as_str(), d.clone()))
                    .collect();
                WatcherConfig {
                    catalog: Some(live(&entries).await),
                    ..WatcherConfig::default()
                }
            };
            let cfg = cfg_with(vec![team("team-a")]).await;
            assert!(
                !cfg.grants("team-a", &granted.name, &bundle),
                "another namespace's policy"
            );
            assert!(!cfg.grants("team-b", &granted.name, &bundle));
            let cfg = cfg_with(vec![team(&policy_ns)]).await;
            assert!(
                cfg.grants(&policy_ns, &granted.name, &bundle),
                "its own namespace's policy"
            );
            let cfg = cfg_with(vec![team(PLATFORM)]).await;
            assert!(
                cfg.grants("team-a", &granted.name, &bundle),
                "a platform audience"
            );
        }
    }
}
