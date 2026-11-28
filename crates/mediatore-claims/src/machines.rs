// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! The machine cache (ADR-0078): which pool member holds which address on the sandbox
//! segment, so a probe's source address can be named on its audit line.
//!
//! Filled by two watches on every replica, outside the Lease ([`run`]): banlieue's
//! `VirtualMachine` labelled `banlieue.io/pool` and the `VirtualMachineClaim`s mediatore
//! created, in every namespace. The routes read it from memory ([`MachineCache::attribute`]);
//! nothing here reads the Kubernetes API or the store on a request.
//!
//! What it answers is a hint and never a verdict: a source address on a shared segment can be
//! forged (ADR-0070 decision 5). Only exactly one holder is ever named; an incomplete listing,
//! no holder and several holders name nothing.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Debug;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use banlieue_api::banlieue::{
    ClaimPhase as BanlieuePhase, LABEL_POOL, VirtualMachine, VirtualMachineClaim,
};
use banlieue_api::common::{MachineAddressType, PowerState};
use futures::StreamExt as _;
use kube::runtime::WatchStreamExt as _;
use kube::runtime::watcher::{self, Event};
use kube::{Api, Client, Resource, ResourceExt};
use mediatore_proto::ek::ek_hash_from_pems;
use serde::de::DeserializeOwned;
use uuid::Uuid;

use crate::watch::{MANAGED_BY_SELECTOR, claim_uid_of};

/// The most names `tripwires.segment_hosts` may declare.
pub const MAX_SEGMENT_HOSTS: usize = 64;
/// The most addresses one declared host may hold.
pub const MAX_HOST_ADDRESSES: usize = 16;
/// The most bytes of a declared host's name.
pub const MAX_HOST_NAME: usize = 63;

/// A pool member a source address was matched to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    /// The `VirtualMachine`'s namespace.
    pub namespace: String,
    /// The `VirtualMachine`'s name.
    pub name: String,
    /// Its node key: the EK hash of a TPM member. `None` for a member of an `x509pop` pool
    /// (its key needs its Provider's CA, which the cache does not hold) or one that publishes
    /// no usable certificate.
    pub node_key: Option<String>,
    /// The UID of the one managed claim `Bound` to it, if there is exactly one.
    pub claim_uid: Option<Uuid>,
}

/// Who holds a source address, as far as the cache can tell (ADR-0078 decision 3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Attribution {
    /// No live member and no declared host holds it, the event had no address, or the
    /// cache has not completed its first listing.
    Unattributed,
    /// More than one candidate holds it; none is named.
    Ambiguous,
    /// Exactly one live pool member holds it, and no declared host.
    Member(Member),
    /// Exactly one declared host holds it (`tripwires.segment_hosts`), and no live member.
    Host(String),
}

impl Attribution {
    /// The value of the line's `attribution` field.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Unattributed => "unattributed",
            Self::Ambiguous => "ambiguous",
            Self::Member(_) => "member",
            Self::Host(_) => "host",
        }
    }
}

type Key = (String, String);

/// What the cache keeps of one pool member (decision 2).
#[derive(Debug, Clone)]
struct Machine {
    live: bool,
    addresses: Vec<IpAddr>,
    node_key: Option<String>,
}

/// One listing's worth of both kinds, and whether each was completed once.
#[derive(Debug, Default)]
struct View {
    machines: HashMap<Key, Machine>,
    machines_listed: bool,
    /// By the claim's namespace and name: the machine it is `Bound` to and its UID, for a
    /// claim that is `Bound`, not being deleted and names a machine.
    claims: HashMap<Key, (Key, Uuid)>,
    claims_listed: bool,
}

/// The machine cache (ADR-0078 decision 1). [`MachineCache::default`] has no declared host and
/// has listed nothing, so it names nothing.
#[derive(Debug, Default)]
pub struct MachineCache {
    view: RwLock<View>,
    x509pop_pools: BTreeSet<String>,
    hosts: BTreeMap<IpAddr, String>,
}

/// An address as the cache compares it: an IPv4-mapped IPv6 address is the IPv4 one.
fn canonical(ip: IpAddr) -> IpAddr {
    ip.to_canonical()
}

fn host_name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_HOST_NAME
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-')
}

impl Machine {
    /// What the cache keeps of `vm` (decision 2). `x509pop`: its pool is listed in
    /// `watcher.x509pop_pools`, so its EK is never read.
    fn of(vm: &VirtualMachine, x509pop: bool) -> Self {
        let status = vm.status.as_ref();
        let live = vm.metadata.deletion_timestamp.is_none()
            && status
                .and_then(|s| s.observed_power_state.as_ref())
                .is_none_or(|p| *p == PowerState::PoweredOn);
        let mut addresses: Vec<IpAddr> = status
            .into_iter()
            .flat_map(|s| {
                s.addresses
                    .iter()
                    .filter(|a| a.address_type == MachineAddressType::InternalIP)
                    .map(|a| a.address.as_str())
                    .chain(s.held_addresses.iter().map(|h| h.address.as_str()))
            })
            .filter_map(|a| a.parse::<IpAddr>().ok().map(canonical))
            .collect();
        addresses.sort_unstable();
        addresses.dedup();
        let node_key = if x509pop {
            None
        } else {
            status
                .map(|s| s.tpm_endorsement_certificates.as_slice())
                .filter(|certs| !certs.is_empty())
                .and_then(|certs| ek_hash_from_pems(certs).ok())
        };
        Self {
            live,
            addresses,
            node_key,
        }
    }
}

/// The namespace and name of an object.
fn key_of<K: Resource>(o: &K) -> Key {
    (
        o.meta().namespace.clone().unwrap_or_default(),
        o.meta().name.clone().unwrap_or_default(),
    )
}

/// What the cache keeps of a managed claim: the machine it is `Bound` to and its UID, for a
/// claim `Bound`, not being deleted and naming a machine; else nothing.
fn binding_of(claim: &VirtualMachineClaim) -> Option<(Key, Uuid)> {
    if claim.metadata.deletion_timestamp.is_some() {
        return None;
    }
    let status = claim.status.as_ref()?;
    if status.phase != BanlieuePhase::Bound {
        return None;
    }
    let machine = status.virtual_machine_ref.as_ref()?;
    let uid = claim_uid_of(claim)?;
    Some((
        (claim.namespace().unwrap_or_default(), machine.name.clone()),
        uid,
    ))
}

impl MachineCache {
    /// A cache for a broker whose `watcher.x509pop_pools` are `x509pop_pools` (as
    /// `<namespace>/<pool>`) and whose `tripwires.segment_hosts` are `hosts` (decision 5).
    ///
    /// # Errors
    /// A host name outside `[a-z0-9.-]{1,63}`, more than [`MAX_SEGMENT_HOSTS`] names, more than
    /// [`MAX_HOST_ADDRESSES`] addresses under one, a name with none, or an address under two
    /// names.
    pub fn new(
        x509pop_pools: BTreeSet<String>,
        hosts: &BTreeMap<String, Vec<IpAddr>>,
    ) -> Result<Self, String> {
        if hosts.len() > MAX_SEGMENT_HOSTS {
            return Err(format!("more than {MAX_SEGMENT_HOSTS} names"));
        }
        let mut by_address = BTreeMap::new();
        for (name, addresses) in hosts {
            if !host_name_ok(name) {
                return Err(format!(
                    "the name {name:?} is not 1 to {MAX_HOST_NAME} bytes of [a-z0-9.-]"
                ));
            }
            let own: BTreeSet<IpAddr> = addresses.iter().copied().map(canonical).collect();
            if own.is_empty() {
                return Err(format!("{name} holds no address"));
            }
            if own.len() > MAX_HOST_ADDRESSES {
                return Err(format!(
                    "{name} holds more than {MAX_HOST_ADDRESSES} addresses"
                ));
            }
            for ip in own {
                if let Some(other) = by_address.insert(ip, name.clone()) {
                    return Err(format!("{ip} is declared under both {other} and {name}"));
                }
            }
        }
        Ok(Self {
            view: RwLock::default(),
            x509pop_pools,
            hosts: by_address,
        })
    }

    fn is_x509pop(&self, vm: &VirtualMachine) -> bool {
        !self.x509pop_pools.is_empty()
            && vm.labels().get(LABEL_POOL).is_some_and(|pool| {
                self.x509pop_pools
                    .contains(&format!("{}/{pool}", vm.namespace().unwrap_or_default()))
            })
    }

    fn write(&self) -> std::sync::RwLockWriteGuard<'_, View> {
        self.view
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The member `vm` was created or changed.
    pub fn apply_machine(&self, vm: &VirtualMachine) {
        let m = Machine::of(vm, self.is_x509pop(vm));
        self.write().machines.insert(key_of(vm), m);
    }

    /// The member `vm` is gone.
    pub fn delete_machine(&self, vm: &VirtualMachine) {
        self.write().machines.remove(&key_of(vm));
    }

    /// A complete listing of the members: replaces every member, and marks them listed.
    pub fn replace_machines<'a>(&self, vms: impl IntoIterator<Item = &'a VirtualMachine>) {
        let machines = vms
            .into_iter()
            .map(|vm| (key_of(vm), Machine::of(vm, self.is_x509pop(vm))))
            .collect();
        let mut view = self.write();
        view.machines = machines;
        view.machines_listed = true;
    }

    /// The managed claim `claim` was created or changed.
    pub fn apply_claim(&self, claim: &VirtualMachineClaim) {
        let k = key_of(claim);
        let mut view = self.write();
        match binding_of(claim) {
            Some(b) => view.claims.insert(k, b),
            None => view.claims.remove(&k),
        };
    }

    /// The managed claim `claim` is gone.
    pub fn delete_claim(&self, claim: &VirtualMachineClaim) {
        self.write().claims.remove(&key_of(claim));
    }

    /// A complete listing of the managed claims: replaces every claim, and marks them listed.
    pub fn replace_claims<'a>(&self, claims: impl IntoIterator<Item = &'a VirtualMachineClaim>) {
        let claims = claims
            .into_iter()
            .filter_map(|c| binding_of(c).map(|b| (key_of(c), b)))
            .collect();
        let mut view = self.write();
        view.claims = claims;
        view.claims_listed = true;
    }

    /// Who holds `address` (decision 3): exactly one live member or declared host is named,
    /// none or several name nothing, and nothing is named before both kinds were listed once.
    /// Never reads anything but memory.
    #[must_use]
    pub fn attribute(&self, address: Option<&str>) -> Attribution {
        let Some(ip) = address
            .and_then(|a| a.parse::<IpAddr>().ok())
            .map(canonical)
        else {
            return Attribution::Unattributed;
        };
        let view = self
            .view
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !(view.machines_listed && view.claims_listed) {
            return Attribution::Unattributed;
        }
        let mut members = view
            .machines
            .iter()
            .filter(|(_, m)| m.live && m.addresses.contains(&ip));
        let host = self.hosts.get(&ip);
        match (members.next(), members.next(), host) {
            (None, _, None) => Attribution::Unattributed,
            (None, _, Some(name)) => Attribution::Host(name.clone()),
            (Some(((namespace, name), m)), None, None) => {
                let mut bound = view
                    .claims
                    .values()
                    .filter(|(vm, _)| vm.0 == *namespace && vm.1 == *name)
                    .map(|(_, uid)| *uid);
                let claim_uid = match (bound.next(), bound.next()) {
                    (Some(uid), None) => Some(uid),
                    _ => None,
                };
                Attribution::Member(Member {
                    namespace: namespace.clone(),
                    name: name.clone(),
                    node_key: m.node_key.clone(),
                    claim_uid,
                })
            }
            _ => Attribution::Ambiguous,
        }
    }
}

/// Follow one kind into the cache: each event applied or deleted, a relist gathered and
/// applied whole at its end (decision 4). Ends only when the stream does, which it does not.
async fn follow<K>(
    api: Api<K>,
    labels: &str,
    what: &'static str,
    cache: &MachineCache,
    apply: fn(&MachineCache, &K),
    delete: fn(&MachineCache, &K),
    replace: fn(&MachineCache, &[K]),
) -> anyhow::Result<()>
where
    K: Resource + Clone + DeserializeOwned + Debug + Send + 'static,
{
    let mut events = watcher::watcher(api, watcher::Config::default().labels(labels))
        .default_backoff()
        .boxed();
    let mut relist: Option<Vec<K>> = None;
    while let Some(event) = events.next().await {
        match event {
            Ok(Event::Init) => relist = Some(Vec::new()),
            Ok(Event::InitApply(o)) => relist.get_or_insert_with(Vec::new).push(o),
            Ok(Event::InitDone) => {
                let all = relist.take().unwrap_or_default();
                tracing::debug!(
                    what,
                    objects = all.len(),
                    "machine cache: a complete listing"
                );
                replace(cache, &all);
            }
            Ok(Event::Apply(o)) => apply(cache, &o),
            Ok(Event::Delete(o)) => delete(cache, &o),
            Err(e) if crate::watch::watch_error_is_routine(&e) => {
                tracing::debug!(what, error = %e, "machine cache watch: routine");
            }
            Err(e) => {
                tracing::warn!(what, error = %e, "machine cache watch failed; the last complete view still answers (ADR-0078)");
            }
        }
    }
    anyhow::bail!("the machine cache's watch on {what} ended")
}

/// Both watches, on every replica (decision 1), until one ends (they do not end on their own).
///
/// # Errors
/// A watch ended.
pub async fn run(client: Client, cache: Arc<MachineCache>) -> anyhow::Result<()> {
    let machines = follow(
        Api::<VirtualMachine>::all(client.clone()),
        LABEL_POOL,
        "virtualmachines",
        &cache,
        MachineCache::apply_machine,
        MachineCache::delete_machine,
        |c, all| c.replace_machines(all),
    );
    let claims = follow(
        Api::<VirtualMachineClaim>::all(client),
        MANAGED_BY_SELECTOR,
        "virtualmachineclaims",
        &cache,
        MachineCache::apply_claim,
        MachineCache::delete_claim,
        |c, all| c.replace_claims(all),
    );
    tracing::info!("machine cache running: probes' source addresses are named from it (ADR-0078)");
    tokio::select! {
        r = machines => r,
        r = claims => r,
    }
}

#[cfg(test)]
mod tests {
    use mediatore_testkit::ek::{RSA_EK_HASH, RSA_EK_PEM};
    use serde_json::{Value, json};

    use super::*;

    const POOL: &str = "pool";

    /// A pool member `name` in `sandboxes` at `addresses` (`InternalIP`), with the test kit's
    /// endorsement certificate.
    fn vm(name: &str, addresses: &[&str]) -> VirtualMachine {
        vm_with(name, addresses, &json!({}))
    }

    fn vm_with(name: &str, addresses: &[&str], extra: &Value) -> VirtualMachine {
        let mut status = json!({
            "tpmEndorsementCertificates": [RSA_EK_PEM],
            "addresses": addresses.iter().map(|a| json!({ "type": "InternalIP", "address": a })).collect::<Vec<_>>(),
        });
        for (k, v) in extra
            .get("status")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            status[k] = v.clone();
        }
        let mut metadata = json!({
            "name": name, "namespace": "sandboxes", "uid": Uuid::new_v4().to_string(),
            "labels": { "banlieue.io/pool": POOL }
        });
        for (k, v) in extra
            .get("metadata")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
        {
            metadata[k] = v.clone();
        }
        serde_json::from_value(json!({
            "metadata": metadata,
            "spec": { "classRef": { "name": "small" }, "imageRef": { "name": "sandbox" } },
            "status": status
        }))
        .unwrap()
    }

    /// A managed claim `name` in `sandboxes`, in `phase`, naming `machine`.
    fn claim(name: &str, uid: Uuid, phase: &str, machine: Option<&str>) -> VirtualMachineClaim {
        let mut status = json!({ "phase": phase });
        if let Some(m) = machine {
            status["virtualMachineRef"] = json!({ "name": m });
        }
        serde_json::from_value(json!({
            "metadata": {
                "name": name, "namespace": "sandboxes", "uid": uid.to_string(),
                "labels": { "app.kubernetes.io/managed-by": "mediatore" }
            },
            "spec": { "poolRef": { "name": POOL }, "subject": { "issuer": "https://issuer.example.com", "id": "octocat" }, "ttlSeconds": 600 },
            "status": status
        }))
        .unwrap()
    }

    fn hosts(pairs: &[(&str, &[&str])]) -> BTreeMap<String, Vec<IpAddr>> {
        pairs
            .iter()
            .map(|(n, a)| {
                (
                    (*n).to_owned(),
                    a.iter().map(|a| a.parse().unwrap()).collect(),
                )
            })
            .collect()
    }

    /// A cache with these members and claims, both listed.
    fn listed(vms: &[VirtualMachine], claims: &[VirtualMachineClaim]) -> MachineCache {
        let c = MachineCache::new(BTreeSet::new(), &BTreeMap::new()).unwrap();
        c.replace_machines(vms);
        c.replace_claims(claims);
        c
    }

    fn member(name: &str, claim_uid: Option<Uuid>) -> Attribution {
        Attribution::Member(Member {
            namespace: "sandboxes".into(),
            name: name.into(),
            node_key: Some(RSA_EK_HASH.into()),
            claim_uid,
        })
    }

    #[test]
    fn one_live_member_holding_the_address_is_named_with_its_node_and_bound_claim() {
        let uid = Uuid::new_v4();
        let c = listed(
            &[
                vm("member-1", &["192.0.2.10"]),
                vm("member-2", &["192.0.2.11"]),
            ],
            &[claim("sb-1", uid, "Bound", Some("member-1"))],
        );
        assert_eq!(
            c.attribute(Some("192.0.2.10")),
            member("member-1", Some(uid))
        );
        assert_eq!(c.attribute(Some("192.0.2.11")), member("member-2", None));
        assert_eq!(c.attribute(Some("192.0.2.10")).as_str(), "member");
    }

    #[test]
    fn an_address_nobody_holds_or_no_address_is_unattributed() {
        let c = listed(&[vm("member-1", &["192.0.2.10"])], &[]);
        assert_eq!(c.attribute(Some("192.0.2.99")), Attribution::Unattributed);
        assert_eq!(c.attribute(None), Attribution::Unattributed);
        assert_eq!(
            c.attribute(Some("not an address")),
            Attribution::Unattributed
        );
        assert_eq!(Attribution::Unattributed.as_str(), "unattributed");
    }

    #[test]
    fn several_live_members_holding_one_address_name_none() {
        let c = listed(
            &[
                vm("member-1", &["192.0.2.10"]),
                vm("member-2", &["192.0.2.10"]),
            ],
            &[],
        );
        assert_eq!(c.attribute(Some("192.0.2.10")), Attribution::Ambiguous);
        assert_eq!(Attribution::Ambiguous.as_str(), "ambiguous");
        // Never the newer by guess: both live, both stay candidates whatever their age.
        let older = vm_with(
            "member-1",
            &["192.0.2.10"],
            &json!({ "metadata": { "creationTimestamp": "2026-11-01T00:00:00Z" } }),
        );
        let newer = vm_with(
            "member-2",
            &["192.0.2.10"],
            &json!({ "metadata": { "creationTimestamp": "2026-11-28T00:00:00Z" } }),
        );
        let c = listed(&[older, newer], &[]);
        assert_eq!(c.attribute(Some("192.0.2.10")), Attribution::Ambiguous);
    }

    #[test]
    fn a_reused_address_goes_to_the_newer_live_member() {
        // The old member stopped, or is being deleted, and still reports the address; banlieue
        // gave it to a newer member, which is the one named.
        for old_state in [
            json!({ "status": { "observedPowerState": "PoweredOff" } }),
            json!({ "status": { "observedPowerState": "Suspended" } }),
            json!({ "metadata": { "deletionTimestamp": "2026-11-28T10:00:00Z", "finalizers": ["banlieue.io/vm"] } }),
        ] {
            let old = vm_with("member-old", &["192.0.2.10"], &old_state);
            let new = vm("member-new", &["192.0.2.10"]);
            let c = listed(&[old, new], &[]);
            assert_eq!(
                c.attribute(Some("192.0.2.10")),
                member("member-new", None),
                "{old_state}"
            );
        }
        // And by events: the old one deleted, the new one applied.
        let c = listed(&[vm("member-old", &["192.0.2.10"])], &[]);
        assert_eq!(c.attribute(Some("192.0.2.10")), member("member-old", None));
        c.apply_machine(&vm("member-new", &["192.0.2.10"]));
        assert_eq!(c.attribute(Some("192.0.2.10")), Attribution::Ambiguous);
        c.delete_machine(&vm("member-old", &["192.0.2.10"]));
        assert_eq!(c.attribute(Some("192.0.2.10")), member("member-new", None));
        // A member whose status no longer lists the address stops holding it.
        c.apply_machine(&vm("member-new", &["192.0.2.12"]));
        assert_eq!(c.attribute(Some("192.0.2.10")), Attribution::Unattributed);
        assert_eq!(c.attribute(Some("192.0.2.12")), member("member-new", None));
    }

    #[test]
    fn nothing_is_named_before_both_listings_complete() {
        let c = MachineCache::new(BTreeSet::new(), &hosts(&[("host-a", &["192.0.2.1"])])).unwrap();
        c.apply_machine(&vm("member-1", &["192.0.2.10"]));
        assert_eq!(c.attribute(Some("192.0.2.10")), Attribution::Unattributed);
        assert_eq!(c.attribute(Some("192.0.2.1")), Attribution::Unattributed);
        c.replace_machines(&[vm("member-1", &["192.0.2.10"])]);
        assert_eq!(
            c.attribute(Some("192.0.2.10")),
            Attribution::Unattributed,
            "the claims are not listed yet"
        );
        c.replace_claims(&[]);
        assert_eq!(c.attribute(Some("192.0.2.10")), member("member-1", None));
        assert_eq!(
            c.attribute(Some("192.0.2.1")),
            Attribution::Host("host-a".into())
        );
        // The default cache never lists anything: it names nothing.
        assert_eq!(
            MachineCache::default().attribute(Some("192.0.2.10")),
            Attribution::Unattributed
        );
    }

    #[test]
    fn a_relist_replaces_the_view_whole() {
        let c = listed(
            &[
                vm("member-1", &["192.0.2.10"]),
                vm("member-2", &["192.0.2.11"]),
            ],
            &[],
        );
        c.replace_machines(&[vm("member-2", &["192.0.2.11"])]);
        assert_eq!(c.attribute(Some("192.0.2.10")), Attribution::Unattributed);
        assert_eq!(c.attribute(Some("192.0.2.11")), member("member-2", None));
    }

    #[test]
    fn the_bound_claim_is_the_one_managed_claim_bound_to_the_member() {
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        let m = vm("member-1", &["192.0.2.10"]);
        // Pending, released, failed, or naming no machine: no claim.
        for (phase, machine) in [
            ("Pending", None),
            ("Releasing", Some("member-1")),
            ("Failed", Some("member-1")),
            ("Bound", None),
        ] {
            let c = listed(
                std::slice::from_ref(&m),
                &[claim("sb-1", a, phase, machine)],
            );
            assert_eq!(
                c.attribute(Some("192.0.2.10")),
                member("member-1", None),
                "{phase}"
            );
        }
        // Bound, then released by events.
        let c = listed(std::slice::from_ref(&m), &[]);
        c.apply_claim(&claim("sb-1", a, "Bound", Some("member-1")));
        assert_eq!(c.attribute(Some("192.0.2.10")), member("member-1", Some(a)));
        c.apply_claim(&claim("sb-1", a, "Releasing", Some("member-1")));
        assert_eq!(c.attribute(Some("192.0.2.10")), member("member-1", None));
        c.apply_claim(&claim("sb-1", a, "Bound", Some("member-1")));
        c.delete_claim(&claim("sb-1", a, "Bound", Some("member-1")));
        assert_eq!(c.attribute(Some("192.0.2.10")), member("member-1", None));
        // A claim being deleted is not bound.
        let mut deleting = claim("sb-1", a, "Bound", Some("member-1"));
        deleting.metadata.deletion_timestamp =
            Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                k8s_openapi::jiff::Timestamp::UNIX_EPOCH,
            ));
        c.apply_claim(&deleting);
        assert_eq!(c.attribute(Some("192.0.2.10")), member("member-1", None));
        // Two claims bound to one machine name neither.
        let c = listed(
            &[m],
            &[
                claim("sb-1", a, "Bound", Some("member-1")),
                claim("sb-2", b, "Bound", Some("member-1")),
            ],
        );
        assert_eq!(c.attribute(Some("192.0.2.10")), member("member-1", None));
    }

    #[test]
    fn a_member_of_an_x509pop_pool_has_no_node_key_whatever_it_publishes() {
        let pools = [format!("sandboxes/{POOL}")].into_iter().collect();
        let c = MachineCache::new(pools, &BTreeMap::new()).unwrap();
        c.replace_machines(&[vm("member-1", &["192.0.2.10"])]);
        c.replace_claims(&[]);
        assert_eq!(
            c.attribute(Some("192.0.2.10")),
            Attribution::Member(Member {
                namespace: "sandboxes".into(),
                name: "member-1".into(),
                node_key: None,
                claim_uid: None,
            })
        );
    }

    #[test]
    fn held_addresses_count_and_other_address_types_do_not() {
        let m = vm_with(
            "member-1",
            &[],
            &json!({ "status": {
                "addresses": [
                    { "type": "ExternalIP", "address": "203.0.113.5" },
                    { "type": "Hostname", "address": "member-1" },
                    { "type": "InternalIP", "address": "not-an-ip" },
                ],
                "heldAddresses": [{ "interface": "eth0", "networkClass": "segment", "address": "192.0.2.20" }]
            } }),
        );
        let c = listed(&[m], &[]);
        assert_eq!(c.attribute(Some("192.0.2.20")), member("member-1", None));
        assert_eq!(c.attribute(Some("203.0.113.5")), Attribution::Unattributed);
    }

    #[test]
    fn an_ipv4_mapped_address_is_the_ipv4_one() {
        let c = listed(&[vm("member-1", &["192.0.2.10"])], &[]);
        assert_eq!(
            c.attribute(Some("::ffff:192.0.2.10")),
            member("member-1", None)
        );
        let c = listed(&[vm("member-1", &["2001:db8::10"])], &[]);
        assert_eq!(
            c.attribute(Some("2001:db8:0::10")),
            member("member-1", None)
        );
    }

    #[test]
    fn a_declared_host_is_named_and_a_member_on_its_address_makes_it_ambiguous() {
        let c = MachineCache::new(
            BTreeSet::new(),
            &hosts(&[
                ("host-a", &["192.0.2.1", "2001:db8::1"]),
                ("gw-1", &["192.0.2.2"]),
            ]),
        )
        .unwrap();
        c.replace_machines(&[vm("member-1", &["192.0.2.2"])]);
        c.replace_claims(&[]);
        assert_eq!(
            c.attribute(Some("192.0.2.1")),
            Attribution::Host("host-a".into())
        );
        assert_eq!(
            c.attribute(Some("2001:db8::1")),
            Attribution::Host("host-a".into())
        );
        assert_eq!(c.attribute(Some("192.0.2.1")).as_str(), "host");
        assert_eq!(c.attribute(Some("192.0.2.2")), Attribution::Ambiguous);
    }

    #[test]
    fn declared_hosts_out_of_bounds_are_refused() {
        let none = BTreeSet::new;
        for (bad, why) in [
            (
                hosts(&[("Host-A", &["192.0.2.1"])]),
                "a name outside the grammar",
            ),
            (hosts(&[("host_a", &["192.0.2.1"])]), "an underscore"),
            (hosts(&[("", &["192.0.2.1"])]), "an empty name"),
            (
                hosts(&[(&"a".repeat(64), &["192.0.2.1"])]),
                "a name too long",
            ),
            (hosts(&[("host-a", &[])]), "a name with no address"),
            (
                hosts(&[
                    ("host-a", &["192.0.2.1"]),
                    ("host-b", &["::ffff:192.0.2.1"]),
                ]),
                "one address under two names",
            ),
        ] {
            assert!(MachineCache::new(none(), &bad).is_err(), "{why}");
        }
        let many: BTreeMap<String, Vec<IpAddr>> = (0..=MAX_SEGMENT_HOSTS)
            .map(|n| {
                (
                    format!("host-{n}"),
                    vec![IpAddr::from([192, 0, 2, u8::try_from(n).unwrap()])],
                )
            })
            .collect();
        assert!(MachineCache::new(none(), &many).is_err(), "too many names");
        let wide: BTreeMap<String, Vec<IpAddr>> = [(
            "host-a".to_owned(),
            (0..=MAX_HOST_ADDRESSES)
                .map(|n| IpAddr::from([192, 0, 2, u8::try_from(n).unwrap()]))
                .collect(),
        )]
        .into_iter()
        .collect();
        assert!(
            MachineCache::new(none(), &wide).is_err(),
            "too many addresses"
        );
        // The same address twice under one name is one address.
        assert!(
            MachineCache::new(none(), &hosts(&[("host-a", &["192.0.2.1", "192.0.2.1"])])).is_ok()
        );
    }

    #[tokio::test]
    async fn the_fake_api_servers_machines_fill_the_cache_as_a_listing() {
        // The same objects the claim watcher's fake lists, as a complete listing.
        let api = crate::fakes::FakeClaims::default();
        api.put_machine(vm("member-1", &["192.0.2.10"]));
        let listed = crate::watch::ClaimsApi::list_machines(&api).await.unwrap();
        let c = MachineCache::default();
        c.replace_machines(&listed);
        c.replace_claims(&[]);
        assert_eq!(c.attribute(Some("192.0.2.10")), member("member-1", None));
    }
}
