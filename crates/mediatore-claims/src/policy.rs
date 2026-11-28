// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The bundle reflector (ADR-0026 decision 3): notaio's signed policy bundles, read from the
//! `ConfigMap`s it labels in each configured namespace, verified, their floor moved in the
//! store, and only then cached for the comparison. Every replica runs it, outside the Lease:
//! each needs the cache it will read (decision 4). A bundle that fails any step is logged
//! with its reason and changes nothing; an expired one leaves the cache. Nothing here admits,
//! refuses or mints: in this phase the cache is read by the comparison alone.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration;

use futures::StreamExt as _;
use jiff::Timestamp;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::runtime::WatchStreamExt as _;
use kube::runtime::watcher::{self, Event};
use kube::{Api, Client, ResourceExt};
/// A verified bundle's payload, as the cache hands it out.
pub use mediatore_policy::BundlePayload;
use mediatore_policy::{Envelope, Refusal, TrustedKeys, admit};
use mediatore_proto::Endpoint;
use mediatore_store::ClaimStore;
use tokio::sync::broadcast;

/// The label notaio puts on the `ConfigMap`s it writes; the reflector watches nothing else.
pub const BUNDLE_SELECTOR: &str = "app.kubernetes.io/managed-by=notaio";
/// The `ConfigMap` key holding the DSSE envelope.
pub const BUNDLE_KEY: &str = "bundle.dsse.json";
/// Between sweeps of expired bundles out of the cache.
const SWEEP_EVERY: Duration = Duration::from_secs(60);

/// What became of one `ConfigMap` delivery.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Verified, the floor written, the payload cached.
    Admitted {
        /// `<namespace>/<policy>`.
        policy: String,
        /// The bundle's version.
        version: u64,
    },
    /// Verified or decided against; the cache and the floor are as they were.
    Refused {
        /// notaio's error name, or this crate's (`Misplaced`, `Store`, `Contended`).
        code: &'static str,
    },
    /// Not a bundle notaio would write; nothing was done with it.
    Ignored(&'static str),
}

/// One admitted bundle, with the `ConfigMap` it came from.
#[derive(Debug, Clone)]
struct Verified {
    payload: Arc<BundlePayload>,
    configmap: String,
}

/// Whether a policy's direct `egress[]` reaches the gateway (ADR-0030 decision 4). The
/// broker's own configuration, never cluster state; `shadow` unless an operator turns it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EgressMode {
    /// Serve the audience endpoints only and log what the bundle would have added.
    #[default]
    Shadow,
    /// Serve the union of the audience endpoints and the bundle's servable direct egress.
    Enforce,
}

impl EgressMode {
    /// The value as the configuration spells it, for the broker's start-up log: an
    /// operator reads the mode off the log instead of inferring it from the start succeeding.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Shadow => "shadow",
            Self::Enforce => "enforce",
        }
    }
}

impl std::fmt::Display for EgressMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A direct `egress[]` entry the gateway cannot enforce exactly, and why (ADR-0030 decision 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotServed {
    /// The entry as the bundle spells it.
    pub endpoint: String,
    /// A stable, secret-free reason.
    pub reason: &'static str,
}

/// A bundle's direct `egress[]` sorted into what the gateway can serve and what it cannot.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DirectEgress {
    /// Exact `host:port` entries with a DNS host, lowercased, sorted, deduplicated.
    pub served: Vec<Endpoint>,
    /// Entries refused, in bundle order.
    pub not_served: Vec<NotServed>,
}

/// Sort `bundle`'s direct `egress[]` (ADR-0030 decision 3). The gateway matches the CONNECT
/// authority exactly and sees no path, so an entry is served only when it is a DNS
/// `host:port` with no wildcard and no `rules`; anything else is reported, never
/// reinterpreted.
#[must_use]
pub fn direct_egress(bundle: &BundlePayload) -> DirectEgress {
    let mut out = DirectEgress::default();
    for entry in &bundle.content.egress {
        let refuse = |reason| NotServed {
            endpoint: entry.endpoint.clone(),
            reason,
        };
        if !entry.rules.is_empty() {
            out.not_served.push(refuse("has_rules"));
            continue;
        }
        let Ok(mut endpoint) = entry.endpoint.parse::<Endpoint>() else {
            out.not_served.push(refuse("not_host_port"));
            continue;
        };
        if endpoint.host.contains('*') {
            out.not_served.push(refuse("wildcard"));
            continue;
        }
        if endpoint.host.parse::<std::net::IpAddr>().is_ok() {
            out.not_served.push(refuse("ip_literal"));
            continue;
        }
        endpoint.host = endpoint.host.to_ascii_lowercase();
        out.served.push(endpoint);
    }
    out.served.sort();
    out.served.dedup();
    out
}

/// What a claim may do with one audience under a verified bundle (ADR-0053 decision 11): the
/// bundle's grant bounded by the broker's own configuration, never wider than either.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveAudience {
    /// What the proxy and the gateway admit at the audience's endpoints.
    pub rules: Vec<mediatore_proto::EndpointRule>,
    /// The endpoints the claim may reach for it: the audience's `egress` the grant lists.
    pub egress: Vec<Endpoint>,
    /// The longest a token or placed credential may live, when the grant sets `ttlSeconds`.
    pub ttl_cap: Option<i64>,
}

/// ADR-0053 decision 11: the effective grant of `grant` for an audience the broker configures
/// with `ceiling` (its top-level `rules`), `file_grant` (its `namespaces` entry for the claim's
/// namespace, when it has one) and `egress`.
///
/// - **Rules.** A bundle rule is kept only if a ceiling rule covers it and, when there is a file
///   grant, a rule of that covers it too. A grant with no rules reads as notaio reads it, every
///   method and path, so the effective rules are the file grant or else the ceiling. A grant with
///   rules **none of which survive** is `None`: the audience is unusable, because an empty list would
///   mean every path.
/// - **Endpoints.** `egress` intersected with the grant's `endpoints` (spelled `host:port`).
/// - **Lifetime.** The grant's `ttlSeconds`.
#[must_use]
pub fn effective_grant(
    ceiling: &[mediatore_proto::EndpointRule],
    file_grant: Option<&[mediatore_proto::EndpointRule]>,
    egress: &[Endpoint],
    grant: &mediatore_policy::types::AudienceGrant,
) -> Option<EffectiveAudience> {
    use crate::shadow::rule_covers;
    let inside = |rule: &mediatore_proto::EndpointRule| {
        (ceiling.is_empty() || ceiling.iter().any(|c| rule_covers(c, rule)))
            && file_grant.is_none_or(|f| f.iter().any(|g| rule_covers(g, rule)))
    };
    let rules = if grant.rules.is_empty() {
        file_grant.unwrap_or(ceiling).to_vec()
    } else {
        let kept: Vec<_> = grant
            .rules
            .iter()
            .map(|r| mediatore_proto::EndpointRule {
                method: r.method.clone(),
                path: r.path.clone(),
            })
            .filter(inside)
            .collect();
        if kept.is_empty() {
            return None;
        }
        kept
    };
    let egress = egress
        .iter()
        .filter(|e| {
            grant
                .endpoints
                .iter()
                .any(|g| g.eq_ignore_ascii_case(&e.to_string()))
        })
        .cloned()
        .collect();
    Some(EffectiveAudience {
        rules,
        egress,
        ttl_cap: grant.ttl_seconds.map(i64::from),
    })
}

/// A policy, as `(namespace, name)`.
pub type PolicyKey = (String, String);

/// The error code of a `policyRef` that does not resolve (ADR-0054 decision 4): the front
/// door's `400` and the first word of the sandbox's `status.reason`.
pub const POLICY_NOT_RESOLVED: &str = "policy_not_resolved";

/// What a requester is told when the policy named does not resolve, on both paths (ADR-0054
/// decision 4). One sentence for a policy that exists nowhere, one held by a namespace the
/// sandbox may not draw from, and one held twice: the answer never says where else a name
/// exists.
#[must_use]
pub fn not_resolved(policy: &str, sandbox_namespace: &str) -> String {
    format!(
        "no verified bundle for policy {policy} in the namespaces {sandbox_namespace} draws its policies from"
    )
}

/// Which policy namespaces a sandbox namespace draws from (`policy.sources`, ADR-0054
/// decisions 1 and 2). A namespace with no entry draws from itself and from nowhere else;
/// an entry is the whole of that namespace's sources, its own included only if listed. The
/// broker's configuration, never cluster state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicySources {
    entries: BTreeMap<String, Vec<String>>,
}

impl PolicySources {
    /// The mapping as `policy.sources` spells it: sandbox namespace to the policy namespaces
    /// it draws from. A namespace listed twice in one entry counts once.
    #[must_use]
    pub fn new(entries: BTreeMap<String, Vec<String>>) -> Self {
        let entries = entries
            .into_iter()
            .map(|(namespace, listed)| {
                let mut sources: Vec<String> = Vec::with_capacity(listed.len());
                for source in listed {
                    if !sources.contains(&source) {
                        sources.push(source);
                    }
                }
                (namespace, sources)
            })
            .collect();
        Self { entries }
    }

    /// The namespaces `sandbox_namespace` finds a policy in: its entry, or itself alone.
    #[must_use]
    pub fn sources_of<'a>(&'a self, sandbox_namespace: &'a str) -> Vec<&'a str> {
        self.entries.get(sandbox_namespace).map_or_else(
            || vec![sandbox_namespace],
            |listed| listed.iter().map(String::as_str).collect(),
        )
    }

    /// Whether a sandbox in `sandbox_namespace` may run under a policy of `policy_namespace`:
    /// the one question the reconciler, the front door and the gateway answer all ask.
    #[must_use]
    pub fn draws_from(&self, sandbox_namespace: &str, policy_namespace: &str) -> bool {
        self.entries.get(sandbox_namespace).map_or_else(
            || sandbox_namespace == policy_namespace,
            |listed| listed.iter().any(|n| n == policy_namespace),
        )
    }

    /// The namespaces that have an entry, for the start log.
    pub fn mapped(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }
}

/// What a `policyRef` came to in the sources of the sandbox's namespace (ADR-0054 decisions
/// 1, 3 and 4). Anything but `Found` grants nothing; none of them is a lookup somewhere else.
#[derive(Debug, Clone)]
pub enum Resolution {
    /// Exactly one source holds a verified, unexpired bundle of that name.
    Found(Arc<BundlePayload>),
    /// No source holds one: the policy is nowhere, expired, or in a namespace this sandbox
    /// does not draw from.
    NotFound,
    /// More than one source holds the name; the order of the list never decides.
    Ambiguous,
    /// A source has not completed its first list on this replica: neither a refusal nor a
    /// pass.
    NotRead,
}

impl Resolution {
    /// The bundle, when the name resolved.
    #[must_use]
    pub fn found(&self) -> Option<&Arc<BundlePayload>> {
        if let Self::Found(bundle) = self {
            Some(bundle)
        } else {
            None
        }
    }
}

/// The verified bundles, by policy. Shared with the comparison; a bundle past its
/// `notAfter` is never handed out. Every change to a policy's entry (admitted at another
/// version, dropped) is announced to subscribers, so the sandboxes naming that policy are
/// compared again; and each namespace is marked once its first list completed, so the
/// comparison can tell "no bundle" from "not read yet".
#[derive(Debug)]
pub struct BundleCache {
    inner: RwLock<HashMap<PolicyKey, Verified>>,
    synced: RwLock<HashSet<String>>,
    changed: broadcast::Sender<PolicyKey>,
    /// The namespaces the reflector reads (ADR-0026 decision 3), in the order listed. Where
    /// bundles are read and nothing more: which of them a sandbox may draw from is
    /// [`PolicySources`]' (ADR-0054 decision 1).
    namespaces: Vec<String>,
}

/// How many changes a slow subscriber may fall behind before it is told it lagged.
const CHANGES_BUFFERED: usize = 256;

impl Default for BundleCache {
    fn default() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            synced: RwLock::new(HashSet::new()),
            changed: broadcast::channel(CHANGES_BUFFERED).0,
            namespaces: Vec::new(),
        }
    }
}

impl BundleCache {
    /// A cache for a reflector over `namespaces`, in the order they are listed.
    #[must_use]
    pub fn watching(namespaces: Vec<String>) -> Self {
        Self {
            namespaces,
            ..Self::default()
        }
    }

    /// The namespaces watched, in the order listed.
    #[must_use]
    pub fn namespaces(&self) -> &[String] {
        &self.namespaces
    }

    /// Changes to come: the policy whose entry was admitted at a new version or dropped.
    /// A receiver that falls behind gets `Lagged` and should compare everything again.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<PolicyKey> {
        self.changed.subscribe()
    }

    /// Whether the first list of `namespace`'s bundles completed, so a policy with no entry
    /// has no verified bundle rather than one not read yet.
    #[must_use]
    pub fn synced(&self, namespace: &str) -> bool {
        self.synced
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(namespace)
    }

    /// The sources of `sandbox_namespace` that this cache reads. A source the reflector does
    /// not watch holds nothing and never will: it is skipped, not waited for.
    fn watched_sources<'a>(
        &self,
        sources: &'a PolicySources,
        sandbox_namespace: &'a str,
    ) -> Vec<&'a str> {
        sources
            .sources_of(sandbox_namespace)
            .into_iter()
            .filter(|s| self.namespaces.iter().any(|w| w == s))
            .collect()
    }

    /// The watched sources of `sandbox_namespace` whose first list has not completed here:
    /// while one remains, a policy that namespace names may simply not have been read yet
    /// (ADR-0054 decision 4). No other watched namespace is waited for.
    #[must_use]
    pub fn unread_sources(&self, sources: &PolicySources, sandbox_namespace: &str) -> Vec<String> {
        let listed = self.synced.read().unwrap_or_else(PoisonError::into_inner);
        self.watched_sources(sources, sandbox_namespace)
            .into_iter()
            .filter(|s| !listed.contains(*s))
            .map(str::to_owned)
            .collect()
    }

    /// The verified bundle a sandbox's `policyRef` names (ADR-0054 decisions 1 to 4, amending
    /// ADR-0026 decision 6): looked up in the sources of the sandbox's own namespace and in no
    /// other watched namespace. The one function for the rule, so the reconciler and the
    /// front door cannot disagree about it. Fail closed: a name two sources hold is
    /// `Ambiguous`, and while a source is unread the answer is `NotRead`, never a bundle
    /// found in the sources read so far (the unread one may hold the name too).
    #[must_use]
    pub fn resolve(
        &self,
        sources: &PolicySources,
        sandbox_namespace: &str,
        name: &str,
        now: Timestamp,
    ) -> Resolution {
        if !self.unread_sources(sources, sandbox_namespace).is_empty() {
            return Resolution::NotRead;
        }
        let mut held = self
            .watched_sources(sources, sandbox_namespace)
            .into_iter()
            .filter_map(|s| self.get(s, name, now));
        match (held.next(), held.next()) {
            (Some(bundle), None) => Resolution::Found(bundle),
            (None, _) => Resolution::NotFound,
            (Some(_), Some(_)) => Resolution::Ambiguous,
        }
    }

    /// The watched namespaces outside the sources of `sandbox_namespace` that hold a valid
    /// bundle named `name`. For the broker's own log (ADR-0054 decision 4): during a migration
    /// that line is the instruction. Never part of an answer to a requester.
    #[must_use]
    pub fn held_outside(
        &self,
        sources: &PolicySources,
        sandbox_namespace: &str,
        name: &str,
        now: Timestamp,
    ) -> Vec<String> {
        self.namespaces
            .iter()
            .filter(|n| !sources.draws_from(sandbox_namespace, n))
            .filter(|n| self.get(n, name, now).is_some())
            .cloned()
            .collect()
    }

    fn mark_synced(&self, namespace: &str) {
        self.synced
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(namespace.to_owned());
    }

    fn announce(&self, key: PolicyKey) {
        // No subscriber is not an error: the reflector runs on every replica, the
        // comparison only on the leader.
        let _ = self.changed.send(key);
    }

    /// The verified bundle of `namespace/name` if one is cached and still valid at `now`.
    #[must_use]
    pub fn get(&self, namespace: &str, name: &str, now: Timestamp) -> Option<Arc<BundlePayload>> {
        let map = self.read();
        map.get(&(namespace.to_owned(), name.to_owned()))
            .filter(|v| v.payload.meta.not_after > now)
            .map(|v| v.payload.clone())
    }

    /// The verified bundle of the policy whose `uid` is `uid`, if one is cached and still
    /// valid at `now`: the claim's bundle, found from the record (ADR-0030 decision 2). The
    /// current bundle, never the version the claim was created under.
    #[must_use]
    pub fn by_uid(&self, uid: &str, now: Timestamp) -> Option<Arc<BundlePayload>> {
        self.read()
            .values()
            .filter(|v| v.payload.meta.not_after > now && v.payload.content.policy.uid == uid)
            .map(|v| v.payload.clone())
            .max_by_key(|p| p.meta.version)
    }

    /// How many bundles are cached, expired ones included until the next sweep.
    #[must_use]
    pub fn len(&self) -> usize {
        self.read().len()
    }

    /// Whether nothing is cached.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// A writer that panicked mid-insert leaves a map that is still whole (one entry at a
    /// time), so a poisoned lock is read through rather than propagated.
    fn read(&self) -> RwLockReadGuard<'_, HashMap<PolicyKey, Verified>> {
        self.inner.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> RwLockWriteGuard<'_, HashMap<PolicyKey, Verified>> {
        self.inner.write().unwrap_or_else(PoisonError::into_inner)
    }

    /// Insert, announcing the policy when its bundle is new or differs from the one held.
    fn put(&self, key: PolicyKey, v: Verified) {
        let changed = {
            let mut map = self.write();
            let same = map.get(&key).is_some_and(|held| {
                held.payload.meta.version == v.payload.meta.version
                    && held.payload.content_digest == v.payload.content_digest
            });
            map.insert(key.clone(), v);
            !same
        };
        if changed {
            self.announce(key);
        }
    }

    /// Drop every entry `keep` rejects, announcing each; the keys dropped.
    fn retain(&self, keep: impl Fn(&PolicyKey, &Verified) -> bool) -> Vec<PolicyKey> {
        let dropped = {
            let mut map = self.write();
            let mut dropped = Vec::new();
            map.retain(|k, v| {
                let kept = keep(k, v);
                if !kept {
                    dropped.push(k.clone());
                }
                kept
            });
            dropped
        };
        for key in &dropped {
            self.announce(key.clone());
        }
        dropped
    }
}

/// The reflector: the configured keys and namespaces, the store the floor lives in, and
/// the cache it fills.
pub struct BundleReflector {
    store: Arc<dyn ClaimStore>,
    keys: TrustedKeys,
    namespaces: Vec<String>,
    cache: Arc<BundleCache>,
}

impl BundleReflector {
    /// A reflector over `namespaces` (ADR-0026 decision 3) trusting `keys` (decision 2).
    #[must_use]
    pub fn new(store: Arc<dyn ClaimStore>, keys: TrustedKeys, namespaces: Vec<String>) -> Self {
        Self {
            store,
            keys,
            cache: Arc::new(BundleCache::watching(namespaces.clone())),
            namespaces,
        }
    }

    /// The cache the comparison reads.
    #[must_use]
    pub fn cache(&self) -> Arc<BundleCache> {
        self.cache.clone()
    }

    /// The namespaces watched.
    #[must_use]
    pub fn namespaces(&self) -> &[String] {
        &self.namespaces
    }

    /// A `ConfigMap` seen (added, changed, or listed at start), at the current time.
    pub async fn applied(&self, cm: &ConfigMap) -> Outcome {
        self.applied_at(cm, Timestamp::now()).await
    }

    /// [`applied`](Self::applied) with the clock injected: verify at `now`, decide and write
    /// the floor, then cache (decision 4). Logs the outcome; never the envelope.
    pub async fn applied_at(&self, cm: &ConfigMap, now: Timestamp) -> Outcome {
        let name = cm.name_any();
        let namespace = cm.namespace().unwrap_or_default();
        if !self.namespaces.contains(&namespace) {
            return ignored(&namespace, &name, "a namespace not in policy.namespaces");
        }
        let Some(text) = cm.data.as_ref().and_then(|d| d.get(BUNDLE_KEY)) else {
            if cm
                .data
                .as_ref()
                .is_some_and(|d| d.contains_key(crate::audience::AUDIENCE_KEY))
            {
                // notaio's audience bundle, under the same label: the audience reflector's
                // (ADR-0055), and not worth a line here on every delivery.
                return Outcome::Ignored("an audience bundle");
            }
            return ignored(&namespace, &name, "no bundle.dsse.json");
        };
        let Ok(envelope) = serde_json::from_str::<Envelope>(text) else {
            return ignored(&namespace, &name, "the envelope does not parse");
        };
        // The bundle must be the one of the policy its object is named for (`<policy>-bundle`, notaio v0.8.0-rc.1):
        // a valid bundle copied under another policy's name is refused, nothing cached and no floor moved.
        match admit(
            self.store.as_ref(),
            &envelope,
            &namespace,
            &name,
            &self.keys,
            now,
        )
        .await
        {
            Ok(payload) => {
                let policy = payload.content.policy.name.clone();
                let version = payload.meta.version;
                tracing::info!(
                    namespace = %namespace,
                    configmap = %name,
                    policy = %policy,
                    version,
                    not_after = %payload.meta.not_after,
                    "policy bundle admitted"
                );
                self.cache.put(
                    (namespace.clone(), policy.clone()),
                    Verified {
                        payload: Arc::new(payload),
                        configmap: name,
                    },
                );
                Outcome::Admitted {
                    policy: format!("{namespace}/{policy}"),
                    version,
                }
            }
            Err(refusal) => {
                let code = refusal.code();
                let reason = match &refusal {
                    Refusal::Bundle(e) => e.to_string(),
                    other => other.to_string(),
                };
                tracing::warn!(
                    namespace = %namespace,
                    configmap = %name,
                    code,
                    reason = %reason,
                    "policy bundle refused; nothing changed"
                );
                Outcome::Refused { code }
            }
        }
    }

    /// The `ConfigMap` is gone: its policy leaves the cache (the floor stays, decision 5).
    /// `true` when something was dropped.
    pub fn deleted(&self, cm: &ConfigMap) -> bool {
        let name = cm.name_any();
        let namespace = cm.namespace().unwrap_or_default();
        let dropped = self
            .cache
            .retain(|k, v| !(k.0 == namespace && v.configmap == name));
        for (ns, policy) in &dropped {
            tracing::info!(namespace = %ns, policy = %policy, configmap = %name, "policy bundle gone");
        }
        !dropped.is_empty()
    }

    /// The watch on `namespace` listed everything again (a restart, a reconnect): a cached
    /// bundle whose `ConfigMap` was not among `seen` was deleted while the watch was away.
    pub fn resynced(&self, namespace: &str, seen: &HashSet<String>) -> usize {
        let dropped = self
            .cache
            .retain(|k, v| k.0 != namespace || seen.contains(&v.configmap));
        self.cache.mark_synced(namespace);
        for (ns, policy) in &dropped {
            tracing::info!(namespace = %ns, policy = %policy, "policy bundle gone since the last list");
        }
        dropped.len()
    }

    /// Drop bundles past their `notAfter` at `now`; how many.
    pub fn sweep(&self, now: Timestamp) -> usize {
        let dropped = self.cache.retain(|_, v| v.payload.meta.not_after > now);
        for (ns, policy) in &dropped {
            tracing::info!(namespace = %ns, policy = %policy, "policy bundle expired");
        }
        dropped.len()
    }
}

fn ignored(namespace: &str, name: &str, why: &'static str) -> Outcome {
    tracing::info!(
        namespace,
        configmap = name,
        why,
        "configmap ignored: not a bundle"
    );
    Outcome::Ignored(why)
}

/// One watch per configured namespace and the expiry sweep, until a watch ends (they do
/// not end on their own). Run this on every replica.
pub async fn run(client: Client, reflector: Arc<BundleReflector>) -> anyhow::Result<()> {
    let mut watches = Vec::new();
    for ns in reflector.namespaces() {
        let api = Api::<ConfigMap>::namespaced(client.clone(), ns);
        let r = reflector.clone();
        let ns = ns.clone();
        watches.push(Box::pin(async move {
            let mut seen = HashSet::new();
            let mut events =
                watcher::watcher(api, watcher::Config::default().labels(BUNDLE_SELECTOR))
                    .default_backoff()
                    .boxed();
            while let Some(event) = events.next().await {
                match event {
                    Ok(Event::Init) => seen.clear(),
                    Ok(Event::InitApply(cm)) => {
                        seen.insert(cm.name_any());
                        r.applied(&cm).await;
                    }
                    Ok(Event::InitDone) => {
                        r.resynced(&ns, &seen);
                    }
                    Ok(Event::Apply(cm)) => {
                        r.applied(&cm).await;
                    }
                    Ok(Event::Delete(cm)) => {
                        r.deleted(&cm);
                    }
                    Err(e) if crate::watch::watch_error_is_routine(&e) => {
                        tracing::debug!(namespace = %ns, error = %e, "bundle watch: routine");
                    }
                    Err(e) => tracing::warn!(namespace = %ns, error = %e, "bundle watch"),
                }
            }
            anyhow::bail!("the bundle watch on {ns} ended")
        }));
    }
    let sweep = async {
        let mut tick = tokio::time::interval(SWEEP_EVERY);
        tick.tick().await;
        loop {
            tick.tick().await;
            reflector.sweep(Timestamp::now());
        }
    };
    tracing::info!(namespaces = ?reflector.namespaces(), "policy bundle reflector running");
    tokio::select! {
        (r, _, _) = futures::future::select_all(watches) => r,
        () = sweep => anyhow::bail!("the bundle sweep ended"),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
    use mediatore_policy::{TrustedKey, trusted_keys};
    use mediatore_store::{MemoryStore, PolicyFloor};
    use sandboxpolicy_bundle::conformance::{self, Suite, Vector};

    use super::*;

    fn suite() -> Suite {
        conformance::suite().expect("notaio's vectors parse")
    }

    fn vector<'a>(suite: &'a Suite, name: &str) -> &'a Vector {
        suite
            .vectors
            .iter()
            .find(|v| v.name == name)
            .unwrap_or_else(|| panic!("vector {name}"))
    }

    fn keys(suite: &Suite) -> TrustedKeys {
        let configured: Vec<TrustedKey> = suite
            .trusted_keys
            .iter()
            .map(|k| TrustedKey {
                id: k.key_id.clone(),
                public_key: k.public_key.clone(),
            })
            .collect();
        trusted_keys(&configured).unwrap()
    }

    fn configmap(namespace: &str, name: &str, data: Option<(&str, String)>) -> ConfigMap {
        ConfigMap {
            metadata: ObjectMeta {
                name: Some(name.into()),
                namespace: Some(namespace.into()),
                labels: Some(BTreeMap::from([(
                    "app.kubernetes.io/managed-by".to_string(),
                    "notaio".to_string(),
                )])),
                ..ObjectMeta::default()
            },
            data: data.map(|(k, v)| BTreeMap::from([(k.to_string(), v)])),
            ..ConfigMap::default()
        }
    }

    fn bundle_configmap(suite: &Suite, name: &str, v: &Vector) -> ConfigMap {
        configmap(
            &suite.policy.namespace,
            name,
            Some((BUNDLE_KEY, serde_json::to_string(&v.envelope).unwrap())),
        )
    }

    struct Rig {
        suite: Suite,
        store: Arc<MemoryStore>,
        reflector: BundleReflector,
    }

    fn rig() -> Rig {
        let suite = suite();
        let store = Arc::new(MemoryStore::default());
        let reflector = BundleReflector::new(
            store.clone(),
            keys(&suite),
            vec![suite.policy.namespace.clone()],
        );
        Rig {
            suite,
            store,
            reflector,
        }
    }

    impl Rig {
        async fn floor(&self) -> Option<PolicyFloor> {
            self.store
                .get_policy_floor(&self.suite.policy.namespace, &self.suite.policy.name)
                .await
                .unwrap()
        }

        fn cached(&self, now: Timestamp) -> Option<Arc<BundlePayload>> {
            self.reflector
                .cache()
                .get(&self.suite.policy.namespace, &self.suite.policy.name, now)
        }
    }

    // ----- ADR-0054: which policies a namespace may name -----

    /// A reflector over some namespaces with the conformance policy signed now into some of
    /// them, each copy with a uid of its own.
    struct Tenants {
        reflector: BundleReflector,
        policy: String,
        now: Timestamp,
    }

    async fn tenants(watched: &[&str], holding: &[&str]) -> Tenants {
        let now = Timestamp::now();
        let fresh = mediatore_testkit::policy::fresh_bundle(now, 1);
        let policy = fresh.payload.content.policy.name.clone();
        let reflector = BundleReflector::new(
            Arc::new(MemoryStore::default()),
            fresh.keys,
            watched.iter().map(|n| (*n).to_owned()).collect(),
        );
        for namespace in holding {
            let mut content = fresh.payload.content.clone();
            content.policy.namespace = (*namespace).to_owned();
            content.policy.uid = uuid::Uuid::new_v4().to_string();
            let signed = mediatore_testkit::policy::signed_bundle(now, 1, content);
            let cm = mediatore_testkit::policy::bundle_configmap(
                namespace,
                "agent-bundle",
                &signed.envelope,
            );
            let outcome = reflector.applied_at(&cm, now).await;
            assert!(
                matches!(outcome, Outcome::Admitted { .. }),
                "{namespace}: {outcome:?}"
            );
        }
        Tenants {
            reflector,
            policy,
            now,
        }
    }

    impl Tenants {
        /// The first list of each of `namespaces` completed.
        fn listed(&self, namespaces: &[&str]) {
            for namespace in namespaces {
                self.reflector
                    .resynced(namespace, &HashSet::from(["agent-bundle".to_owned()]));
            }
        }

        /// What a sandbox in `from` gets for the policy, as a word and the namespace of the
        /// bundle found.
        fn asked(&self, sources: &PolicySources, from: &str) -> (&'static str, Option<String>) {
            outcome_of(
                &self
                    .reflector
                    .cache()
                    .resolve(sources, from, &self.policy, self.now),
            )
        }
    }

    fn outcome_of(resolution: &Resolution) -> (&'static str, Option<String>) {
        match resolution {
            Resolution::Found(b) => ("found", Some(b.content.policy.namespace.clone())),
            Resolution::NotFound => ("not found", None),
            Resolution::Ambiguous => ("ambiguous", None),
            Resolution::NotRead => ("not read", None),
        }
    }

    fn sources(entries: &[(&str, &[&str])]) -> PolicySources {
        PolicySources::new(
            entries
                .iter()
                .map(|(namespace, listed)| {
                    (
                        (*namespace).to_owned(),
                        listed.iter().map(|n| (*n).to_owned()).collect(),
                    )
                })
                .collect(),
        )
    }

    #[tokio::test]
    async fn a_policy_is_resolved_in_the_sandboxs_own_namespace_and_nowhere_else() {
        let t = tenants(&["team-a", "team-b"], &["team-a"]).await;
        t.listed(&["team-a", "team-b"]);
        let unmapped = PolicySources::default();
        assert_eq!(unmapped.sources_of("team-a"), ["team-a"]);
        assert_eq!(
            t.asked(&unmapped, "team-a"),
            ("found", Some("team-a".to_owned()))
        );
        // Another watched namespace, and one the reflector does not read at all (a pool's):
        // the fallback across `policy.namespaces` is gone.
        assert_eq!(t.asked(&unmapped, "team-b"), ("not found", None));
        assert_eq!(t.asked(&unmapped, "pool-ns"), ("not found", None));
        let cache = t.reflector.cache();
        let other = cache.resolve(&unmapped, "team-a", "no-such-policy", t.now);
        assert_eq!(outcome_of(&other), ("not found", None));
        assert!(
            other.found().is_none(),
            "nothing but Found carries a bundle"
        );
    }

    #[tokio::test]
    async fn a_policy_in_another_watched_namespace_is_not_found_without_a_sources_entry() {
        let t = tenants(&["team-a", "team-b"], &["team-b"]).await;
        t.listed(&["team-a", "team-b"]);
        let unmapped = PolicySources::default();
        assert_eq!(t.asked(&unmapped, "team-a"), ("not found", None));
        assert!(!unmapped.draws_from("team-a", "team-b"));
        assert!(unmapped.draws_from("team-b", "team-b"));
        // The operator's log can say where the name is; the answer above cannot.
        let cache = t.reflector.cache();
        assert_eq!(
            cache.held_outside(&unmapped, "team-a", &t.policy, t.now),
            ["team-b"]
        );
        assert_eq!(
            cache.held_outside(&unmapped, "team-b", &t.policy, t.now),
            Vec::<String>::new()
        );
        // With the entry, it is found, and nothing is outside any more.
        let mapped = sources(&[("team-a", &["team-b"])]);
        assert_eq!(
            t.asked(&mapped, "team-a"),
            ("found", Some("team-b".to_owned()))
        );
        assert_eq!(
            cache.held_outside(&mapped, "team-a", &t.policy, t.now),
            Vec::<String>::new()
        );
    }

    #[tokio::test]
    async fn a_sources_entry_is_the_whole_of_a_namespaces_sources_its_own_included_only_if_listed()
    {
        // The policy lives in the sandbox namespace itself; the entry names another.
        let t = tenants(&["infra", "infra-policies"], &["infra"]).await;
        t.listed(&["infra", "infra-policies"]);
        let replaced = sources(&[("infra", &["infra-policies"])]);
        assert_eq!(replaced.sources_of("infra"), ["infra-policies"]);
        assert!(!replaced.draws_from("infra", "infra"));
        assert_eq!(t.asked(&replaced, "infra"), ("not found", None));
        // Listed, its own namespace is a source again.
        let both = sources(&[("infra", &["infra-policies", "infra"])]);
        assert_eq!(t.asked(&both, "infra"), ("found", Some("infra".to_owned())));
        // An entry says nothing about any other namespace.
        assert_eq!(replaced.sources_of("infra-policies"), ["infra-policies"]);
        assert_eq!(replaced.mapped().collect::<Vec<_>>(), ["infra"]);
        // A namespace written twice in one entry is one source, never an ambiguity with itself.
        let twice = sources(&[("infra", &["infra", "infra"])]);
        assert_eq!(
            t.asked(&twice, "infra"),
            ("found", Some("infra".to_owned()))
        );
    }

    #[tokio::test]
    async fn a_name_held_by_two_sources_is_ambiguous_whatever_the_order() {
        let t = tenants(&["team-a", "team-b"], &["team-a", "team-b"]).await;
        t.listed(&["team-a", "team-b"]);
        for listed in [["team-a", "team-b"], ["team-b", "team-a"]] {
            let mapped = sources(&[("infra", &listed)]);
            assert_eq!(t.asked(&mapped, "infra"), ("ambiguous", None), "{listed:?}");
        }
        // Each namespace on its own still finds its own.
        assert_eq!(
            t.asked(&PolicySources::default(), "team-b"),
            ("found", Some("team-b".to_owned()))
        );
    }

    #[tokio::test]
    async fn a_namespace_is_not_read_until_its_own_sources_listed_and_no_other_is_waited_for() {
        let t = tenants(&["team-a", "team-b"], &["team-a"]).await;
        let unmapped = PolicySources::default();
        let cache = t.reflector.cache();
        // Cached already, but the first list has not completed: not an answer yet.
        assert_eq!(t.asked(&unmapped, "team-a"), ("not read", None));
        assert_eq!(cache.unread_sources(&unmapped, "team-a"), ["team-a"]);
        t.listed(&["team-a"]);
        assert_eq!(
            t.asked(&unmapped, "team-a"),
            ("found", Some("team-a".to_owned())),
            "team-b is still unread and is not this namespace's source"
        );
        assert_eq!(
            cache.unread_sources(&unmapped, "team-a"),
            Vec::<String>::new()
        );
        // A namespace drawing from both waits for both, even with the name already found in
        // the one that was read: the other may hold it too.
        let mapped = sources(&[("infra", &["team-a", "team-b"])]);
        assert_eq!(t.asked(&mapped, "infra"), ("not read", None));
        assert_eq!(cache.unread_sources(&mapped, "infra"), ["team-b"]);
        t.listed(&["team-b"]);
        assert_eq!(
            t.asked(&mapped, "infra"),
            ("found", Some("team-a".to_owned()))
        );
        // A namespace the reflector does not watch is never waited for: nothing is there.
        assert_eq!(t.asked(&unmapped, "pool-ns"), ("not found", None));
    }

    #[tokio::test]
    async fn an_expired_bundle_in_a_source_is_not_found() {
        let t = tenants(&["team-a"], &["team-a"]).await;
        t.listed(&["team-a"]);
        let unmapped = PolicySources::default();
        let cache = t.reflector.cache();
        let later = t.now + jiff::SignedDuration::from_hours(2);
        assert_eq!(
            outcome_of(&cache.resolve(&unmapped, "team-a", &t.policy, t.now)),
            ("found", Some("team-a".to_owned()))
        );
        assert_eq!(
            outcome_of(&cache.resolve(&unmapped, "team-a", &t.policy, later)),
            ("not found", None)
        );
        // Expired on both sides of a mapping is not an ambiguity either.
        let t = tenants(&["team-a", "team-b"], &["team-a", "team-b"]).await;
        t.listed(&["team-a", "team-b"]);
        let mapped = sources(&[("infra", &["team-a", "team-b"])]);
        let cache = t.reflector.cache();
        assert_eq!(
            outcome_of(&cache.resolve(&mapped, "infra", &t.policy, later)),
            ("not found", None)
        );
    }

    #[tokio::test]
    async fn a_bundle_in_another_policys_configmap_is_refused_and_moves_nothing() {
        // notaio v0.8.0-rc.1 (its ADR-0008 decision 7): the consumer asks for one policy, by the object notaio writes
        // for it (`<policy>-bundle`), and refuses a valid bundle of any other. Copied under another name, a policy's
        // bundle is no bundle of the policy that name is for.
        let r = rig();
        let v = vector(&r.suite, "accepted-first-sight");
        for name in ["other-agent-bundle", "agent", "agent-bundle-copy"] {
            let cm = bundle_configmap(&r.suite, name, v);
            assert_eq!(
                r.reflector.applied_at(&cm, v.now).await,
                Outcome::Refused {
                    code: "WrongSubject"
                },
                "{name}"
            );
        }
        assert!(r.cached(v.now).is_none(), "nothing reached the cache");
        assert!(r.floor().await.is_none(), "no floor moved");
        // Under its own name it is admitted.
        let cm = bundle_configmap(&r.suite, "agent-bundle", v);
        assert!(matches!(
            r.reflector.applied_at(&cm, v.now).await,
            Outcome::Admitted { .. }
        ));
    }

    #[tokio::test]
    async fn a_change_to_a_policys_bundle_is_announced_and_a_namespace_is_synced_by_its_first_list()
    {
        let r = rig();
        let cache = r.reflector.cache();
        let mut changes = cache.subscribe();
        let key = (
            r.suite.policy.namespace.clone(),
            r.suite.policy.name.clone(),
        );
        assert!(!cache.synced(&key.0), "nothing listed yet");

        let v = vector(&r.suite, "accepted-first-sight");
        let cm = bundle_configmap(&r.suite, "agent-bundle", v);
        r.reflector.applied_at(&cm, v.now).await;
        assert_eq!(changes.try_recv().unwrap(), key, "admitted: announced");
        // The same bundle delivered again changes nothing and announces nothing.
        r.reflector.applied_at(&cm, v.now).await;
        assert!(changes.try_recv().is_err(), "a re-delivery is silent");
        // A refusal announces nothing either.
        let forged = vector(&r.suite, "refused-forged-signature");
        r.reflector
            .applied_at(
                &bundle_configmap(&r.suite, "agent-bundle", forged),
                forged.now,
            )
            .await;
        assert!(changes.try_recv().is_err(), "a refusal is silent");
        // The first list completing marks the namespace, and dropping the policy announces it.
        r.reflector.resynced(&key.0, &HashSet::new());
        assert!(cache.synced(&key.0));
        assert!(!cache.synced("elsewhere"));
        assert_eq!(changes.try_recv().unwrap(), key, "dropped: announced");
        assert!(r.cached(v.now).is_none());
        // (A bundle admitted at another version is announced too: the sandbox tests, which
        // sign their own, check that.)
    }

    #[tokio::test]
    async fn a_bundle_that_verifies_is_cached_under_its_policy_and_its_floor_written() {
        let r = rig();
        let v = vector(&r.suite, "accepted-first-sight");
        let cm = bundle_configmap(&r.suite, "agent-bundle", v);
        assert_eq!(
            r.reflector.applied_at(&cm, v.now).await,
            Outcome::Admitted {
                policy: format!("{}/{}", r.suite.policy.namespace, r.suite.policy.name),
                version: 3,
            }
        );
        let cached = r.cached(v.now).expect("cached");
        assert_eq!(cached.meta.version, 3);
        assert_eq!(cached.content.policy.name, r.suite.policy.name);
        let floor = r.floor().await.expect("the floor was written");
        assert_eq!(
            (floor.version, floor.uid.as_str()),
            (3, cached.content.policy.uid.as_str())
        );
        // Another policy, or another namespace, is not what was cached.
        assert!(
            r.reflector
                .cache()
                .get(&r.suite.policy.namespace, "other", v.now)
                .is_none()
        );
        assert!(
            r.reflector
                .cache()
                .get("elsewhere", &r.suite.policy.name, v.now)
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_configmap_that_is_not_a_bundle_is_ignored_and_changes_nothing() {
        let r = rig();
        let ns = r.suite.policy.namespace.clone();
        let now = vector(&r.suite, "accepted-first-sight").now;
        assert_eq!(
            r.reflector
                .applied_at(&configmap(&ns, "notes", None), now)
                .await,
            Outcome::Ignored("no bundle.dsse.json")
        );
        assert_eq!(
            r.reflector
                .applied_at(&configmap(&ns, "notes", Some(("README", "hi".into()))), now)
                .await,
            Outcome::Ignored("no bundle.dsse.json")
        );
        assert_eq!(
            r.reflector
                .applied_at(
                    &configmap(&ns, "broken", Some((BUNDLE_KEY, "{not json".into()))),
                    now
                )
                .await,
            Outcome::Ignored("the envelope does not parse")
        );
        // A namespace the configuration does not list is never read, even if delivered.
        let v = vector(&r.suite, "accepted-first-sight");
        let mut cm = bundle_configmap(&r.suite, "agent-bundle", v);
        cm.metadata.namespace = Some("elsewhere".into());
        assert_eq!(
            r.reflector.applied_at(&cm, now).await,
            Outcome::Ignored("a namespace not in policy.namespaces")
        );
        assert!(r.reflector.cache().is_empty());
        assert_eq!(r.floor().await, None);
    }

    #[tokio::test]
    async fn a_refused_bundle_leaves_the_cache_and_the_floor_as_they_were() {
        let r = rig();
        let good = vector(&r.suite, "accepted-first-sight");
        r.reflector
            .applied_at(&bundle_configmap(&r.suite, "agent-bundle", good), good.now)
            .await;
        let before = r.floor().await.expect("a floor");
        for (name, code) in [
            ("refused-untrusted-key", "NoValidSignature"),
            ("refused-forged-signature", "NoValidSignature"),
            ("refused-digest-mismatch", "DigestMismatch"),
            ("refused-malformed", "Malformed"),
        ] {
            let v = vector(&r.suite, name);
            assert_eq!(
                r.reflector
                    .applied_at(&bundle_configmap(&r.suite, "agent-bundle", v), v.now)
                    .await,
                Outcome::Refused { code },
                "{name}"
            );
        }
        // The same envelope delivered as expired: refused at the clock, and the cached copy
        // is not replaced by it.
        let expired = vector(&r.suite, "refused-expired");
        assert_eq!(
            r.reflector
                .applied_at(
                    &bundle_configmap(&r.suite, "agent-bundle", expired),
                    expired.now
                )
                .await,
            Outcome::Refused { code: "Expired" }
        );
        assert_eq!(r.floor().await, Some(before));
        assert_eq!(r.cached(good.now).unwrap().meta.version, 3);
    }

    #[tokio::test]
    async fn a_replay_below_the_floor_is_refused_and_a_redelivery_is_not() {
        let r = rig();
        let v = vector(&r.suite, "accepted-first-sight");
        // The floor a newer bundle left behind, as another replica or an earlier run wrote it.
        let held = vector(&r.suite, "refused-downgrade").floor.clone().unwrap();
        r.store
            .advance_policy_floor(
                None,
                PolicyFloor {
                    namespace: r.suite.policy.namespace.clone(),
                    name: r.suite.policy.name.clone(),
                    uid: held.uid,
                    version: held.version,
                    issued_at: held.issued_at,
                },
            )
            .await
            .unwrap();
        let cm = bundle_configmap(&r.suite, "agent-bundle", v);
        assert_eq!(
            r.reflector.applied_at(&cm, v.now).await,
            Outcome::Refused { code: "Downgrade" }
        );
        assert!(
            r.cached(v.now).is_none(),
            "a replay never reaches the cache"
        );
        assert_eq!(r.floor().await.unwrap().version, 4);

        // The same bundle at the same floor is a re-delivery (a resync, a restart): admitted
        // again, the floor untouched.
        let r = rig();
        assert!(matches!(
            r.reflector.applied_at(&cm, v.now).await,
            Outcome::Admitted { .. }
        ));
        assert!(matches!(
            r.reflector.applied_at(&cm, v.now).await,
            Outcome::Admitted { .. }
        ));
        assert_eq!(r.reflector.cache().len(), 1);
    }

    #[tokio::test]
    async fn a_deleted_configmap_drops_its_policy_from_the_cache_and_keeps_the_floor() {
        let r = rig();
        let v = vector(&r.suite, "accepted-first-sight");
        let cm = bundle_configmap(&r.suite, "agent-bundle", v);
        r.reflector.applied_at(&cm, v.now).await;
        // Another ConfigMap's deletion is not this policy's.
        let other = configmap(&r.suite.policy.namespace, "other-bundle", None);
        assert!(!r.reflector.deleted(&other));
        assert!(r.cached(v.now).is_some());
        assert!(r.reflector.deleted(&cm));
        assert!(r.cached(v.now).is_none());
        assert!(
            r.floor().await.is_some(),
            "the floor outlives the bundle (decision 5)"
        );
        // A second delete finds nothing.
        assert!(!r.reflector.deleted(&cm));
    }

    #[tokio::test]
    async fn a_relist_without_the_configmap_drops_its_policy() {
        let r = rig();
        let v = vector(&r.suite, "accepted-first-sight");
        let cm = bundle_configmap(&r.suite, "agent-bundle", v);
        r.reflector.applied_at(&cm, v.now).await;
        let ns = r.suite.policy.namespace.clone();
        // Seen again: kept. Another namespace's relist: not this entry's business.
        assert_eq!(
            r.reflector
                .resynced(&ns, &HashSet::from(["agent-bundle".to_string()])),
            0
        );
        assert_eq!(r.reflector.resynced("elsewhere", &HashSet::new()), 0);
        assert!(r.cached(v.now).is_some());
        assert_eq!(r.reflector.resynced(&ns, &HashSet::new()), 1);
        assert!(r.cached(v.now).is_none());
    }

    #[tokio::test]
    async fn an_expired_bundle_is_never_handed_out_and_the_sweep_drops_it() {
        let r = rig();
        let v = vector(&r.suite, "accepted-first-sight");
        r.reflector
            .applied_at(&bundle_configmap(&r.suite, "agent-bundle", v), v.now)
            .await;
        let not_after = r.cached(v.now).unwrap().meta.not_after;
        assert!(not_after > v.now);
        assert!(
            r.cached(not_after).is_none(),
            "at notAfter the bundle is gone for readers"
        );
        assert_eq!(r.reflector.sweep(v.now), 0);
        assert_eq!(r.reflector.cache().len(), 1);
        assert_eq!(r.reflector.sweep(not_after), 1);
        assert!(r.reflector.cache().is_empty());
    }

    fn bundle_with_egress(entries: &[(&str, bool)]) -> BundlePayload {
        let mut b = mediatore_testkit::policy::fresh_bundle(Timestamp::now(), 1).payload;
        b.content.egress = entries
            .iter()
            .map(|(endpoint, with_rules)| {
                mediatore_policy::types::EgressRule {
                    endpoint: (*endpoint).into(),
                    rules: if *with_rules {
                        vec![mediatore_policy::types::EndpointRule {
                            method: "GET".into(),
                            path: "/**".into(),
                        }]
                    } else {
                        vec![]
                    },
                }
                .into()
            })
            .collect();
        b
    }

    #[test]
    fn the_egress_mode_prints_as_the_configuration_spells_it() {
        assert_eq!(EgressMode::Shadow.as_str(), "shadow");
        assert_eq!(EgressMode::Enforce.to_string(), "enforce");
        assert_eq!(EgressMode::default(), EgressMode::Shadow);
        let parsed: EgressMode = serde_json::from_str("\"enforce\"").unwrap();
        assert_eq!(parsed.to_string(), "enforce");
    }

    #[test]
    fn direct_egress_serves_only_what_the_gateway_can_match_exactly() {
        let b = bundle_with_egress(&[
            ("Repo.Home.Example:443", false),
            ("api.home.example:443", false),
            ("api.home.example:443", false),
            ("*.home.example:443", false),
            ("192.0.2.7:443", false),
            ("[2001:db8::1]:443", false),
            ("nohost", false),
            ("only-some.home.example:443", true),
        ]);
        let d = direct_egress(&b);
        let served: Vec<String> = d.served.iter().map(ToString::to_string).collect();
        assert_eq!(served, ["api.home.example:443", "repo.home.example:443"]);
        let reasons: Vec<(&str, &str)> = d
            .not_served
            .iter()
            .map(|n| (n.endpoint.as_str(), n.reason))
            .collect();
        assert_eq!(
            reasons,
            [
                ("*.home.example:443", "wildcard"),
                ("192.0.2.7:443", "ip_literal"),
                ("[2001:db8::1]:443", "ip_literal"),
                ("nohost", "not_host_port"),
                ("only-some.home.example:443", "has_rules"),
            ]
        );
    }

    #[test]
    fn a_bundle_is_found_by_its_policy_uid_while_valid() {
        let cache = BundleCache::default();
        let fresh = mediatore_testkit::policy::fresh_bundle(Timestamp::now(), 3).payload;
        let uid = fresh.content.policy.uid.clone();
        let key = (
            fresh.content.policy.namespace.clone(),
            fresh.content.policy.name.clone(),
        );
        cache.put(
            key,
            Verified {
                payload: Arc::new(fresh),
                configmap: "cm".into(),
            },
        );
        let now = Timestamp::now();
        assert_eq!(cache.by_uid(&uid, now).map(|p| p.meta.version), Some(3));
        assert!(cache.by_uid("some-other-uid", now).is_none());
        assert!(
            cache
                .by_uid(&uid, now + jiff::SignedDuration::from_hours(3))
                .is_none(),
            "an expired bundle is never handed out"
        );
    }

    // ----- ADR-0053 decision 11: the effective grant -----

    fn rule(method: &str, path: &str) -> mediatore_proto::EndpointRule {
        mediatore_proto::EndpointRule {
            method: method.into(),
            path: path.into(),
        }
    }

    fn grant(
        rules: &[(&str, &str)],
        endpoints: &[&str],
        ttl: Option<u32>,
    ) -> mediatore_policy::types::AudienceGrant {
        let mut g = mediatore_testkit::policy::fresh_bundle(Timestamp::now(), 1)
            .payload
            .content
            .audiences[0]
            .grant
            .clone();
        g.rules = rules
            .iter()
            .map(|(m, p)| mediatore_policy::types::EndpointRule {
                method: (*m).into(),
                path: (*p).into(),
            })
            .collect();
        g.endpoints = endpoints.iter().map(|e| (*e).to_owned()).collect();
        g.ttl_seconds = ttl;
        g
    }

    fn ep(s: &str) -> Endpoint {
        s.parse().unwrap()
    }

    #[test]
    fn a_bundle_rule_the_ceiling_does_not_cover_is_dropped() {
        let ceiling = [rule("GET", "/a/**")];
        let g = grant(&[("GET", "/a/x"), ("GET", "/b/y")], &["h.test:443"], None);
        let e = effective_grant(&ceiling, None, &[ep("h.test:443")], &g).unwrap();
        assert_eq!(e.rules, vec![rule("GET", "/a/x")]);
    }

    #[test]
    fn a_grant_with_rules_none_of_which_survive_the_ceiling_makes_the_audience_unusable() {
        // An empty list would mean every path; the broker never produces one from a non-empty grant.
        let ceiling = [rule("GET", "/a/**")];
        let g = grant(&[("GET", "/b/**"), ("POST", "/a/x")], &["h.test:443"], None);
        assert!(effective_grant(&ceiling, None, &[ep("h.test:443")], &g).is_none());
    }

    #[test]
    fn a_grant_with_no_rules_reads_as_the_ceiling() {
        let ceiling = [rule("GET", "/a/**")];
        let g = grant(&[], &["h.test:443"], None);
        let e = effective_grant(&ceiling, None, &[ep("h.test:443")], &g).unwrap();
        assert_eq!(e.rules, ceiling.to_vec());
        // And with no ceiling either, the broker's own reading holds: every path.
        let open = effective_grant(&[], None, &[ep("h.test:443")], &g).unwrap();
        assert_eq!(open.rules, vec![]);
    }

    #[test]
    fn a_file_grant_and_a_bundle_grant_intersect() {
        let ceiling = [rule("*", "/**")];
        let file = [rule("GET", "/a/**")];
        let g = grant(&[("GET", "/a/x"), ("GET", "/b/y")], &["h.test:443"], None);
        let e = effective_grant(&ceiling, Some(&file), &[ep("h.test:443")], &g).unwrap();
        assert_eq!(
            e.rules,
            vec![rule("GET", "/a/x")],
            "the file grant bounds the bundle's"
        );
        let none = grant(&[], &["h.test:443"], None);
        let e = effective_grant(&ceiling, Some(&file), &[ep("h.test:443")], &none).unwrap();
        assert_eq!(
            e.rules,
            file.to_vec(),
            "a grant with no rules is the file grant"
        );
    }

    #[test]
    fn endpoints_are_the_intersection_and_the_lifetime_the_grants() {
        let g = grant(&[("GET", "/**")], &["a.test:443"], Some(120));
        let e = effective_grant(&[], None, &[ep("a.test:443"), ep("b.test:443")], &g).unwrap();
        assert_eq!(
            e.egress,
            vec![ep("a.test:443")],
            "an endpoint the grant omits is dropped"
        );
        assert_eq!(e.ttl_cap, Some(120));
        let none = grant(&[("GET", "/**")], &[], None);
        let e = effective_grant(&[], None, &[ep("a.test:443")], &none).unwrap();
        assert!(
            e.egress.is_empty(),
            "a grant listing no endpoint admits none"
        );
        assert_eq!(e.ttl_cap, None);
    }

    /// notaio v0.9.0 reads schema v3 and v4 and nothing else (its ADR-0026 decision 4): a
    /// bundle of a schema notaio does not write, signed under a trusted key, is refused by the
    /// reflector with nothing cached and no floor moved, whichever payload type it travels
    /// under. The same bytes saying `v4` are admitted, so each refusal is the schema's alone.
    #[tokio::test]
    async fn a_bundle_of_a_schema_notaio_does_not_write_is_refused_and_moves_nothing() {
        use mediatore_testkit::policy::{bundle_configmap, signed_bundle_v4, signed_raw};
        use sandboxpolicy_bundle::{PAYLOAD_TYPE_V3, PAYLOAD_TYPE_V4, SCHEMA_V4};

        let now = Timestamp::now();
        let v4 = signed_bundle_v4(
            now,
            1,
            mediatore_testkit::policy::fresh_bundle(now, 1)
                .payload
                .content,
            &["team-a"],
        );
        let policy = v4.payload.content.policy.clone();
        let store = Arc::new(MemoryStore::default());
        let reflector =
            BundleReflector::new(store.clone(), v4.keys, vec![policy.namespace.clone()]);
        let object = format!("{}-bundle", policy.name);
        let mut payload = serde_json::to_value(&v4.payload).unwrap();
        payload["schema"] = "sandbox.firestoned.io/bundle/v5".into();
        let v5 = serde_json::to_vec(&payload).unwrap();
        for (payload_type, code) in [
            (PAYLOAD_TYPE_V4, "Schema"),
            (PAYLOAD_TYPE_V3, "Schema"),
            (
                "application/vnd.firestoned.sandboxpolicy.bundle.v5+json",
                "PayloadType",
            ),
        ] {
            let cm = bundle_configmap(&policy.namespace, &object, &signed_raw(payload_type, &v5));
            assert_eq!(
                reflector.applied_at(&cm, now).await,
                Outcome::Refused { code },
                "{payload_type}"
            );
            assert!(reflector.cache().is_empty(), "{payload_type}");
            assert_eq!(
                store
                    .get_policy_floor(&policy.namespace, &policy.name)
                    .await
                    .unwrap(),
                None,
                "{payload_type}"
            );
        }
        payload["schema"] = SCHEMA_V4.into();
        let cm = bundle_configmap(
            &policy.namespace,
            &object,
            &signed_raw(PAYLOAD_TYPE_V4, &serde_json::to_vec(&payload).unwrap()),
        );
        assert!(
            matches!(
                reflector.applied_at(&cm, now).await,
                Outcome::Admitted { version: 1, .. }
            ),
            "the control: the same bytes as v4"
        );
    }
}
