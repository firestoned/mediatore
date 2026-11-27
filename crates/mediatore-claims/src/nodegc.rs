// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Collecting the `SandboxNode`s of VMs that no longer exist (ADR-0039), and their SPIRE node
//! entries (ADR-0039 decision 7, amended 2026-11-23).
//!
//! A node is registered once per VM, named by its node key, and nothing used to remove it:
//! the register grew by one object per VM ever created. The rule here is the whole
//! decision, a pure function so every guard has a test of its own: a node goes only when no
//! banlieue VM still gives its node key, and never while it is banned, young, or
//! referenced by a claim that has not ended. [`crate::watch::Watcher::collect_nodes`] feeds
//! it from the cluster and the store, on the replica holding the Lease.
//!
//! The node key is the EK hash of a VM that attests with its TPM, and the hash of the agent
//! ID of one that attests with `x509pop` (ADR-0049 decision 7). The rules do not tell the two
//! apart: the watcher computes the live keys of both kinds with the functions that declare
//! the node entries, and an entry's key is read from its name and held to its parent.

use std::collections::HashSet;

use banlieue_api::banlieue::VirtualMachine;
use jiff::{SignedDuration, Timestamp};
use mediatore_proto::ek::ek_hash_from_pems;
use mediatore_spire::x509pop::{is_x509pop_agent_id, node_key_of_agent_id};
use mediatore_spire::{EntryKind, EntryRef, NODE_ENTRY_PREFIX};
use mediatore_store::NodeRecord;

/// The most nodes one pass removes. A bug, a partial VM list or an operator error then
/// costs a bounded number of records, which re-register on the guest's next start.
pub const MAX_DELETIONS_PER_PASS: usize = 20;

/// What one pass knows.
pub struct Inputs<'a> {
    /// Every registered node.
    pub nodes: &'a [NodeRecord],
    /// The node key every banlieue VM currently gives: its EK hash, or the key of its
    /// x509pop agent ID.
    pub live_node_keys: &'a HashSet<String>,
    /// The SPIRE agent ID of every node a claim that has not ended is bound to.
    pub busy_node_ids: &'a HashSet<String>,
    /// The time of the pass.
    pub now: Timestamp,
    /// A node younger than this is never collected: a registration may precede its VM's
    /// published endorsement certificate.
    pub grace: SignedDuration,
    /// The most to return.
    pub cap: usize,
    /// Leave every x509pop node alone in this pass: some machine of an `x509pop` pool could
    /// not be given a key because something it needs is only missing (its Provider, its
    /// placement, its subject), so the live keys are not all there. What a Provider deleted
    /// and applied again looks like; acting on it would empty a host's register.
    pub hold_x509pop: bool,
}

/// The node keys of the nodes to remove, oldest registration first, at most `cap`.
///
/// Kept: a banned node (a ban is a security record, removed by an operator), a node inside
/// the grace, a node whose VM still gives its key, a node an unended claim is bound
/// to. An empty VM list is not believed while any node is young or any claim is active:
/// it is what a failed or lagging list looks like, and acting on it would empty the
/// register. And no x509pop node goes in a pass that could not compute every x509pop
/// machine's key (`hold_x509pop`).
#[must_use]
pub fn nodes_to_delete(i: &Inputs<'_>) -> Vec<String> {
    let aged = |n: &NodeRecord| i.now.duration_since(n.registered_at) >= i.grace;
    if i.live_node_keys.is_empty()
        && (!i.busy_node_ids.is_empty() || i.nodes.iter().any(|n| !aged(n)))
    {
        return Vec::new();
    }
    let spared = |n: &NodeRecord| i.hold_x509pop && is_x509pop_agent_id(&n.node_id);
    let mut doomed: Vec<&NodeRecord> = i
        .nodes
        .iter()
        .filter(|n| {
            !n.banned
                && aged(n)
                && !i.live_node_keys.contains(&n.ek_hash)
                && !i.busy_node_ids.contains(&n.node_id)
                && !spared(n)
        })
        .collect();
    doomed.sort_by(|a, b| {
        a.registered_at
            .cmp(&b.registered_at)
            .then_with(|| a.ek_hash.cmp(&b.ek_hash))
    });
    doomed
        .into_iter()
        .take(i.cap)
        .map(|n| n.ek_hash.clone())
        .collect()
}

/// The node key of a node entry: the key its name carries, when the entry is parented to
/// the agent that key belongs to (the TPM agent of that same hash, or an x509pop agent whose
/// ID hashes to it, ADR-0049 decision 7). Any other entry is not this rule's and is never
/// retracted by it: a claim entry, an entry with no parent, or one whose name and parent do
/// not agree, which mediatore did not declare that way.
#[must_use]
pub fn node_entry_key(e: &EntryRef) -> Option<&str> {
    if e.kind != EntryKind::Node {
        return None;
    }
    let key = e.name.strip_prefix(NODE_ENTRY_PREFIX)?;
    let parent = e.parent_id.as_deref()?;
    (node_key_of_agent_id(parent).as_deref() == Some(key)).then_some(key)
}

/// What one pass over the node entries knows.
pub struct EntryInputs<'a> {
    /// Every entry mediatore has declared.
    pub entries: &'a [EntryRef],
    /// The node key every banlieue VM currently gives: its EK hash, or the key of its
    /// x509pop agent ID.
    pub live_node_keys: &'a HashSet<String>,
    /// The SPIRE agent ID of every node a claim that has not ended is bound to.
    pub busy_node_ids: &'a HashSet<String>,
    /// Every registered node: a young one holds its entry, as it holds its record.
    pub nodes: &'a [NodeRecord],
    /// The time of the pass.
    pub now: Timestamp,
    /// The node grace, for the young nodes.
    pub grace: SignedDuration,
    /// The most to return.
    pub cap: usize,
    /// Leave every x509pop node entry alone in this pass, as [`Inputs::hold_x509pop`] leaves
    /// the nodes: the live keys of the x509pop machines are not all known.
    pub hold_x509pop: bool,
}

/// The names of the node entries to retract, in name order, at most `cap` (ADR-0039
/// decision 7). A node entry is declared from what a VM publishes (its endorsement
/// certificate, ADR-0011; or its attestation subject under its host's CA, ADR-0049), so it
/// lives as long as some VM gives its key; past that it gives an agent that cannot exist, or
/// may no longer attest, an identity, and nothing else will ever remove it. An x509pop
/// entry's key changes when its host CA's common name does, and the entry under the old name
/// goes by this same rule.
///
/// Kept: an entry whose key a VM gives, one an unended claim's node is under, one whose
/// node registered inside the grace. An empty VM list is believed only as
/// [`nodes_to_delete`] believes it, and no x509pop entry goes under `hold_x509pop`.
#[must_use]
pub fn node_entries_to_delete(i: &EntryInputs<'_>) -> Vec<String> {
    let young = |n: &NodeRecord| i.now.duration_since(n.registered_at) < i.grace;
    if i.live_node_keys.is_empty() && (!i.busy_node_ids.is_empty() || i.nodes.iter().any(young)) {
        return Vec::new();
    }
    // The key of every busy node, whichever way its agent attested. A busy ID that is not
    // an agent ID of either shape protects no entry (and still stops an empty VM list from
    // being believed, above).
    let busy: HashSet<String> = i
        .busy_node_ids
        .iter()
        .filter_map(|id| node_key_of_agent_id(id))
        .collect();
    let held: HashSet<&str> = i
        .nodes
        .iter()
        .filter(|n| young(n))
        .map(|n| n.ek_hash.as_str())
        .collect();
    let mut doomed: Vec<&str> = i
        .entries
        .iter()
        .filter(|e| {
            let spared = i.hold_x509pop && e.parent_id.as_deref().is_some_and(is_x509pop_agent_id);
            !spared
                && node_entry_key(e).is_some_and(|key| {
                    !i.live_node_keys.contains(key) && !busy.contains(key) && !held.contains(key)
                })
        })
        .map(|e| e.name.as_str())
        .collect();
    doomed.sort_unstable();
    doomed.into_iter().take(i.cap).map(str::to_owned).collect()
}

/// The EK hash each VM publishes, computed exactly as the claim binding does
/// ([`ek_hash_from_pems`] over the endorsement certificates banlieue mirrors onto the VM).
/// A VM with no certificate yet, or an unusable one, protects no node. For the VMs that
/// attest with their TPM only: the watcher leaves out those of an `x509pop` pool, whose key
/// is not an EK hash even when they publish a certificate (ADR-0049 decision 9).
#[must_use]
pub fn ek_hashes_of<'a>(machines: impl IntoIterator<Item = &'a VirtualMachine>) -> HashSet<String> {
    machines
        .into_iter()
        .filter_map(|vm| {
            let certs = vm
                .status
                .as_ref()
                .map_or(&[][..], |s| s.tpm_endorsement_certificates.as_slice());
            if certs.is_empty() {
                return None;
            }
            match ek_hash_from_pems(certs) {
                Ok(hash) => Some(hash),
                Err(e) => {
                    tracing::warn!(error = %e, "endorsement certificate unusable; it protects no node");
                    None
                }
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use jiff::{SignedDuration, Timestamp};
    use mediatore_store::NodeRecord;
    use uuid::Uuid;

    use banlieue_api::banlieue::VirtualMachine;
    use mediatore_testkit::ek::{RSA_EK_HASH, RSA_EK_PEM};
    use serde_json::json;

    use mediatore_spire::{EntryKind, EntryRef};

    use sha2::Digest as _;

    use super::{
        EntryInputs, Inputs, MAX_DELETIONS_PER_PASS, ek_hashes_of, node_entries_to_delete,
        node_entry_key, nodes_to_delete,
    };

    fn at(minutes: i64) -> Timestamp {
        "2026-11-15T00:00:00Z".parse::<Timestamp>().unwrap() + SignedDuration::from_mins(minutes)
    }

    /// A node registered at minute `registered`.
    fn node(ek: &str, registered: i64) -> NodeRecord {
        NodeRecord {
            ek_hash: ek.into(),
            node_id: format!("spiffe://sandbox.test/spire/agent/tpm/{ek}"),
            dmi_uuid: Uuid::new_v4(),
            hostname: format!("member-{ek}"),
            provider: None,
            banned: false,
            registered_at: at(registered),
        }
    }

    fn none() -> Vec<String> {
        Vec::new()
    }

    fn set(items: &[&str]) -> HashSet<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    /// Ten minutes of grace; the pass runs at minute 100.
    fn pass(nodes: &[NodeRecord], live: &HashSet<String>, busy: &HashSet<String>) -> Vec<String> {
        nodes_to_delete(&Inputs {
            nodes,
            live_node_keys: live,
            busy_node_ids: busy,
            now: at(100),
            grace: SignedDuration::from_mins(10),
            cap: MAX_DELETIONS_PER_PASS,
            hold_x509pop: false,
        })
    }

    #[test]
    fn a_node_whose_vm_is_gone_and_is_past_the_grace_is_collected() {
        let nodes = [node("gone", 0), node("alive", 0)];
        assert_eq!(
            pass(&nodes, &set(&["alive"]), &set(&[])),
            vec!["gone".to_owned()]
        );
    }

    #[test]
    fn a_node_whose_vm_still_exists_is_kept_on_every_pass() {
        let nodes = [node("alive", 0)];
        let live = set(&["alive"]);
        for _ in 0..3 {
            assert_eq!(pass(&nodes, &live, &set(&[])), none());
        }
    }

    #[test]
    fn a_banned_node_is_a_security_record_and_is_never_collected() {
        let mut banned = node("gone", 0);
        banned.banned = true;
        assert_eq!(pass(&[banned], &set(&["other"]), &set(&[])), none());
    }

    #[test]
    fn a_node_younger_than_the_grace_is_kept_and_one_exactly_at_it_is_not() {
        // Registered at minute 91: nine minutes old, inside the ten of grace.
        assert_eq!(
            pass(&[node("fresh", 91)], &set(&["other"]), &set(&[])),
            none()
        );
        // Registered at minute 90: exactly ten minutes old, eligible.
        assert_eq!(
            pass(&[node("edge", 90)], &set(&["other"]), &set(&[])),
            vec!["edge".to_owned()]
        );
    }

    #[test]
    fn a_node_an_unended_claim_still_references_is_kept() {
        let n = node("gone", 0);
        let busy = set(&[n.node_id.as_str()]);
        assert_eq!(pass(&[n], &set(&["other"]), &busy), none());
    }

    #[test]
    fn at_most_the_cap_is_collected_in_a_pass_oldest_first() {
        let nodes: Vec<NodeRecord> = (0..30).map(|i| node(&format!("n{i:02}"), i)).collect();
        // Another VM is live, so the list is not empty and every node is eligible by age.
        let doomed = pass(&nodes, &set(&["other"]), &set(&[]));
        assert_eq!(doomed.len(), MAX_DELETIONS_PER_PASS);
        let want: Vec<String> = (0..MAX_DELETIONS_PER_PASS)
            .map(|i| format!("n{i:02}"))
            .collect();
        assert_eq!(doomed, want, "the oldest registrations go first");
    }

    #[test]
    fn an_empty_vm_list_collects_nothing_while_a_node_is_young_or_a_claim_is_active() {
        let live = set(&[]);
        // A young node beside old ones: the VM list may not have caught up.
        let nodes = [node("old", 0), node("young", 95)];
        assert_eq!(pass(&nodes, &live, &set(&[])), none());
        // An active claim: an empty VM list while one runs is not believed.
        let old = node("old", 0);
        let busy = set(&["spiffe://sandbox.test/spire/agent/tpm/someone-else"]);
        assert_eq!(pass(&[old], &live, &busy), none());
    }

    #[test]
    fn an_empty_vm_list_with_only_old_nodes_and_no_claim_collects_them_up_to_the_cap() {
        let nodes: Vec<NodeRecord> = (0..3).map(|i| node(&format!("n{i}"), i)).collect();
        assert_eq!(pass(&nodes, &set(&[]), &set(&[])).len(), 3);
    }

    #[test]
    fn no_nodes_collect_nothing() {
        assert_eq!(pass(&[], &set(&["x"]), &set(&[])), none());
    }

    fn vm(certs: &[&str]) -> VirtualMachine {
        serde_json::from_value(json!({
            "metadata": { "name": "member", "namespace": "sandboxes", "uid": Uuid::new_v4().to_string() },
            "spec": { "classRef": { "name": "small" }, "imageRef": { "name": "sandbox" } },
            "status": { "tpmEndorsementCertificates": certs }
        }))
        .unwrap()
    }

    #[test]
    fn a_vm_publishes_the_hash_the_claim_binding_computes_and_one_without_protects_nothing() {
        let mut no_status = vm(&[]);
        no_status.status = None;
        let live = ek_hashes_of(&[
            vm(&[RSA_EK_PEM]),
            vm(&[]),
            vm(&["not a certificate"]),
            no_status,
        ]);
        assert_eq!(live, set(&[RSA_EK_HASH]));
    }

    #[test]
    fn a_node_registered_under_a_vms_hash_is_kept_by_that_vm_only() {
        let nodes = [node(RSA_EK_HASH, 0)];
        let with_vm = ek_hashes_of(&[vm(&[RSA_EK_PEM]), vm(&[])]);
        assert_eq!(pass(&nodes, &with_vm, &set(&[])), none());
        // Its VM gone, another VM without a certificate yet: still not protected.
        let other_only = ek_hashes_of(&[vm(&[])]);
        assert_eq!(
            pass(&nodes, &other_only, &set(&[])),
            vec![RSA_EK_HASH.to_owned()],
            "no certificate, no protection; an empty list with only old nodes and no claim is believed"
        );
    }

    // ----- node entries (decision 7) -------------------------------------------------------

    /// A 64-hex EK hash made of one repeated digit.
    fn ek(d: char) -> String {
        std::iter::repeat_n(d, 64).collect()
    }

    /// A TPM node entry, parented to the agent of its own hash.
    fn tpm_entry(ek: &str) -> EntryRef {
        EntryRef {
            name: format!("mediatore-node-{ek}"),
            kind: EntryKind::Node,
            claim_uid: None,
            parent_id: Some(format!("spiffe://sandbox.test/spire/agent/tpm/{ek}")),
        }
    }

    fn entry_pass(
        entries: &[EntryRef],
        live: &HashSet<String>,
        busy: &HashSet<String>,
        nodes: &[NodeRecord],
    ) -> Vec<String> {
        node_entries_to_delete(&EntryInputs {
            entries,
            live_node_keys: live,
            busy_node_ids: busy,
            nodes,
            now: at(100),
            grace: SignedDuration::from_mins(10),
            cap: MAX_DELETIONS_PER_PASS,
            hold_x509pop: false,
        })
    }

    #[test]
    fn a_node_entry_whose_vm_is_gone_is_retracted_and_one_whose_vm_publishes_is_kept() {
        let (gone, alive) = (ek('a'), ek('b'));
        let entries = [tpm_entry(&gone), tpm_entry(&alive)];
        assert_eq!(
            entry_pass(&entries, &set(&[&alive]), &set(&[]), &[]),
            vec![format!("mediatore-node-{gone}")]
        );
    }

    #[test]
    fn a_node_entry_under_an_unended_claim_or_a_young_node_is_kept() {
        let (busy, young) = (ek('c'), ek('d'));
        let entries = [tpm_entry(&busy), tpm_entry(&young)];
        let claim_node = format!("spiffe://sandbox.test/spire/agent/tpm/{busy}");
        // Another VM is live, so the list is believed and only the guards decide.
        let got = entry_pass(
            &entries,
            &set(&[&ek('e')]),
            &set(&[&claim_node]),
            &[node(&young, 95)],
        );
        assert_eq!(got, none());
    }

    #[test]
    fn an_empty_vm_list_retracts_nothing_while_a_claim_is_active_or_a_node_is_young() {
        let entries = [tpm_entry(&ek('a'))];
        let busy = format!("spiffe://sandbox.test/spire/agent/tpm/{}", ek('f'));
        assert_eq!(entry_pass(&entries, &set(&[]), &set(&[&busy]), &[]), none());
        assert_eq!(
            entry_pass(&entries, &set(&[]), &set(&[]), &[node(&ek('f'), 95)]),
            none()
        );
        assert_eq!(
            entry_pass(&entries, &set(&[]), &set(&[]), &[node(&ek('f'), 0)]),
            vec![format!("mediatore-node-{}", ek('a'))],
            "only old nodes and no claim: the empty list is believed"
        );
    }

    /// An x509pop node entry as the watcher declares it: named by the SHA-256 of the agent
    /// ID it is parented to. Returns the entry and its key.
    fn x509pop_entry(issuer: &str, subject: &str) -> (EntryRef, String) {
        let parent = format!("spiffe://sandbox.test/spire/agent/x509pop/{issuer}/{subject}");
        let key = hex::encode(sha2::Sha256::digest(parent.as_bytes()));
        let entry = EntryRef {
            name: format!("mediatore-node-{key}"),
            kind: EntryKind::Node,
            claim_uid: None,
            parent_id: Some(parent),
        };
        (entry, key)
    }

    #[test]
    fn a_claim_entry_an_unparented_entry_and_one_whose_name_is_not_its_parents_key_are_not_this_rules()
     {
        // Until ADR-0049 decision 9 an x509pop node entry was "not this rule's". It now is
        // (the tests below); what stays outside is everything the watcher did not declare
        // as a node entry of either kind, and none of it is ever retracted here.
        let claim = EntryRef {
            name: "mediatore-claim-6f1e0000-0000-4000-8000-0000000000c1".into(),
            kind: EntryKind::Claim,
            claim_uid: Some(Uuid::nil()),
            parent_id: Some(format!("spiffe://sandbox.test/spire/agent/tpm/{}", ek('a'))),
        };
        // Named by a hash that is not the hash of its x509pop parent.
        let misnamed = EntryRef {
            name: format!("mediatore-node-{}", ek('b')),
            kind: EntryKind::Node,
            claim_uid: None,
            parent_id: Some("spiffe://sandbox.test/spire/agent/x509pop/hv-01/vm-uid".into()),
        };
        let unparented = EntryRef {
            parent_id: None,
            ..tpm_entry(&ek('c'))
        };
        // A TPM parent of another hash, a parent with a third segment, another attestor.
        let other_hash = EntryRef {
            parent_id: Some(format!("spiffe://sandbox.test/spire/agent/tpm/{}", ek('e'))),
            ..tpm_entry(&ek('d'))
        };
        let (mut three_segments, _) = x509pop_entry("hv-01", "vm-1");
        three_segments.parent_id = three_segments.parent_id.map(|p| format!("{p}/extra"));
        let join_token = EntryRef {
            parent_id: Some("spiffe://sandbox.test/spire/agent/join_token/abc".into()),
            ..tpm_entry(&ek('f'))
        };
        let all = [
            claim,
            misnamed,
            unparented,
            other_hash,
            three_segments,
            join_token,
        ];
        for e in &all {
            assert!(
                node_entry_key(e).is_none(),
                "not a node entry of either kind"
            );
        }
        assert_eq!(entry_pass(&all, &set(&[&ek('z')]), &set(&[]), &[]), none());
    }

    #[test]
    fn an_x509pop_node_entry_is_this_rules_and_goes_when_no_vm_gives_its_key() {
        let (gone, gone_key) = x509pop_entry("hv-01", "vm-gone");
        let (alive, alive_key) = x509pop_entry("hv-01", "vm-alive");
        assert_eq!(node_entry_key(&gone), Some(gone_key.as_str()));
        assert_eq!(node_entry_key(&alive), Some(alive_key.as_str()));
        let entries = [gone.clone(), alive, tpm_entry(&ek('a'))];
        assert_eq!(
            entry_pass(&entries, &set(&[&alive_key, &ek('a')]), &set(&[]), &[]),
            vec![gone.name.clone()],
            "the one whose machine is gone, and neither the live x509pop one nor the tpm one"
        );
    }

    #[test]
    fn an_x509pop_node_entry_whose_hosts_ca_was_renamed_goes_and_the_one_under_the_new_name_stays()
    {
        // The key is a hash of the issuer and subject names: the same machine under a CA
        // with another common name is another key, and the old entry is no VM's.
        let (old, _) = x509pop_entry("hv-01", "vm-1");
        let (new, new_key) = x509pop_entry("hv-01-2027", "vm-1");
        assert_eq!(
            entry_pass(&[old.clone(), new], &set(&[&new_key]), &set(&[]), &[]),
            vec![old.name]
        );
    }

    #[test]
    fn an_x509pop_node_entry_under_an_unended_claim_or_a_young_node_is_kept() {
        let (busy, _) = x509pop_entry("hv-01", "vm-busy");
        let (young, young_key) = x509pop_entry("hv-01", "vm-young");
        let claim_node = busy.parent_id.clone().unwrap();
        let mut young_node = node(&young_key, 95);
        young_node.node_id = young.parent_id.clone().unwrap();
        // Another VM is live, so the list is believed and only the guards decide.
        let got = entry_pass(
            &[busy, young],
            &set(&[&ek('e')]),
            &set(&[&claim_node]),
            &[young_node],
        );
        assert_eq!(got, none());
    }

    #[test]
    fn an_empty_vm_list_retracts_no_x509pop_entry_while_a_claim_is_active_or_a_node_is_young() {
        let (entry, _) = x509pop_entry("hv-01", "vm-1");
        let (_, other_key) = x509pop_entry("hv-02", "vm-9");
        let busy = "spiffe://sandbox.test/spire/agent/x509pop/hv-02/vm-9";
        let entries = [entry.clone()];
        assert_eq!(entry_pass(&entries, &set(&[]), &set(&[busy]), &[]), none());
        assert_eq!(
            entry_pass(&entries, &set(&[]), &set(&[]), &[node(&other_key, 95)]),
            none()
        );
        assert_eq!(
            entry_pass(&entries, &set(&[]), &set(&[]), &[node(&other_key, 0)]),
            vec![entry.name],
            "only old nodes and no claim: the empty list is believed"
        );
    }

    #[test]
    fn a_pass_that_could_not_key_every_x509pop_machine_removes_no_x509pop_node_or_entry() {
        // The Provider of a host is gone for a moment (deleted and applied again): its
        // machines give no key, and nothing of any x509pop node goes. TPM nodes and entries
        // are judged as on any pass.
        let (entry, key) = x509pop_entry("hv-01", "vm-1");
        let mut x509pop = node(&key, 0);
        x509pop.node_id = entry.parent_id.clone().unwrap();
        let tpm = node(&ek('a'), 0);
        let live = set(&[&ek('z')]);
        let hold = |hold_x509pop: bool| {
            let nodes = nodes_to_delete(&Inputs {
                nodes: &[x509pop.clone(), tpm.clone()],
                live_node_keys: &live,
                busy_node_ids: &set(&[]),
                now: at(100),
                grace: SignedDuration::from_mins(10),
                cap: MAX_DELETIONS_PER_PASS,
                hold_x509pop,
            });
            let entries = node_entries_to_delete(&EntryInputs {
                entries: &[entry.clone(), tpm_entry(&ek('a'))],
                live_node_keys: &live,
                busy_node_ids: &set(&[]),
                nodes: &[],
                now: at(100),
                grace: SignedDuration::from_mins(10),
                cap: MAX_DELETIONS_PER_PASS,
                hold_x509pop,
            });
            (nodes, entries)
        };
        let tpm_entry_name = format!("mediatore-node-{}", ek('a'));
        assert_eq!(hold(true), (vec![ek('a')], vec![tpm_entry_name.clone()]));
        let (mut nodes, mut entries) = hold(false);
        nodes.sort();
        entries.sort();
        let mut want_nodes = vec![ek('a'), key.clone()];
        want_nodes.sort();
        let mut want_entries = vec![tpm_entry_name, entry.name.clone()];
        want_entries.sort();
        assert_eq!((nodes, entries), (want_nodes, want_entries));
    }

    #[test]
    fn an_x509pop_node_is_kept_by_its_key_and_collected_without_it() {
        let (entry, key) = x509pop_entry("hv-01", "vm-1");
        let mut n = node(&key, 0);
        n.node_id = entry.parent_id.unwrap();
        assert_eq!(pass(&[n.clone()], &set(&[&key]), &set(&[])), none());
        assert_eq!(
            pass(&[n.clone()], &set(&[&ek('a')]), &set(&[])),
            vec![key.clone()],
            "an EK hash some other VM publishes does not keep it"
        );
        let busy = set(&[n.node_id.as_str()]);
        assert_eq!(pass(&[n], &set(&[&ek('a')]), &busy), none());
    }

    #[test]
    fn at_most_the_cap_is_retracted_in_one_pass_in_name_order() {
        let entries: Vec<EntryRef> = "0123456789abcdef0123456789"
            .chars()
            .enumerate()
            .map(|(i, d)| tpm_entry(&format!("{d}{}", &ek(if i < 16 { '1' } else { '2' })[1..])))
            .collect();
        let got = entry_pass(&entries, &set(&[&ek('9')]), &set(&[]), &[]);
        assert_eq!(got.len(), MAX_DELETIONS_PER_PASS);
        let mut sorted = got.clone();
        sorted.sort();
        assert_eq!(got, sorted);
    }
}
