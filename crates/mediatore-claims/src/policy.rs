// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The bundle reflector (ADR-0026 decision 3): notaio's signed policy bundles, read from the
//! `ConfigMap`s it labels in each configured namespace, verified, their floor moved in the
//! store, and only then cached for the comparison. Every replica runs it, outside the Lease:
//! each needs the cache it will read (decision 4). A bundle that fails any step is logged
//! with its reason and changes nothing; an expired one leaves the cache. Nothing here admits,
//! refuses or mints: in this phase the cache is read by the comparison alone.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::time::Duration;

use chrono::{DateTime, Utc};
use futures::StreamExt as _;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::runtime::WatchStreamExt as _;
use kube::runtime::watcher::{self, Event};
use kube::{Api, Client, ResourceExt};
use mediatore_policy::{BundlePayload, Envelope, Refusal, TrustedKeys, admit};
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

/// A policy, as `(namespace, name)`.
pub type PolicyKey = (String, String);

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
}

/// How many changes a slow subscriber may fall behind before it is told it lagged.
const CHANGES_BUFFERED: usize = 256;

impl Default for BundleCache {
    fn default() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
            synced: RwLock::new(HashSet::new()),
            changed: broadcast::channel(CHANGES_BUFFERED).0,
        }
    }
}

impl BundleCache {
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
    pub fn get(
        &self,
        namespace: &str,
        name: &str,
        now: DateTime<Utc>,
    ) -> Option<Arc<BundlePayload>> {
        let map = self.read();
        map.get(&(namespace.to_owned(), name.to_owned()))
            .filter(|v| v.payload.meta.not_after > now)
            .map(|v| v.payload.clone())
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
            namespaces,
            cache: Arc::new(BundleCache::default()),
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
        self.applied_at(cm, Utc::now()).await
    }

    /// [`applied`](Self::applied) with the clock injected: verify at `now`, decide and write
    /// the floor, then cache (decision 4). Logs the outcome; never the envelope.
    pub async fn applied_at(&self, cm: &ConfigMap, now: DateTime<Utc>) -> Outcome {
        let name = cm.name_any();
        let namespace = cm.namespace().unwrap_or_default();
        if !self.namespaces.contains(&namespace) {
            return ignored(&namespace, &name, "a namespace not in policy.namespaces");
        }
        let Some(text) = cm.data.as_ref().and_then(|d| d.get(BUNDLE_KEY)) else {
            return ignored(&namespace, &name, "no bundle.dsse.json");
        };
        let Ok(envelope) = serde_json::from_str::<Envelope>(text) else {
            return ignored(&namespace, &name, "the envelope does not parse");
        };
        match admit(self.store.as_ref(), &envelope, &namespace, &self.keys, now).await {
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
    pub fn sweep(&self, now: DateTime<Utc>) -> usize {
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
            reflector.sweep(Utc::now());
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

        fn cached(&self, now: DateTime<Utc>) -> Option<Arc<BundlePayload>> {
            self.reflector
                .cache()
                .get(&self.suite.policy.namespace, &self.suite.policy.name, now)
        }
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
}
