// Copyright (c) 2026 Erick Bourgeois, mediatore
// SPDX-License-Identifier: Apache-2.0

//! Collecting the `SandboxNode`s of VMs that no longer exist (ADR-0039), and their SPIRE node
//! entries (ADR-0039 decision 7, amended 2026-11-23).
//!
//! A node is registered once per VM, named by its EK hash, and nothing used to remove it:
//! the register grew by one object per VM ever created. The rule here is the whole
//! decision, a pure function so every guard has a test of its own: a node goes only when no
//! banlieue VM still publishes its EK hash, and never while it is banned, young, or
//! referenced by a claim that has not ended. [`crate::watch::Watcher::collect_nodes`] feeds
//! it from the cluster and the store, on the replica holding the Lease.

use std::collections::HashSet;

use banlieue_api::banlieue::VirtualMachine;
use jiff::{SignedDuration, Timestamp};
use mediatore_proto::ek::{ek_hash_from_pems, is_ek_hash};
use mediatore_spire::{EntryKind, EntryRef};
use mediatore_store::NodeRecord;

/// The most nodes one pass removes. A bug, a partial VM list or an operator error then
/// costs a bounded number of records, which re-register on the guest's next start.
pub const MAX_DELETIONS_PER_PASS: usize = 20;

/// What one pass knows.
pub struct Inputs<'a> {
    /// Every registered node.
    pub nodes: &'a [NodeRecord],
    /// The EK hash every banlieue VM currently publishes.
    pub live_ek_hashes: &'a HashSet<String>,
    /// The SPIRE agent ID of every node a claim that has not ended is bound to.
    pub busy_node_ids: &'a HashSet<String>,
    /// The time of the pass.
    pub now: Timestamp,
    /// A node younger than this is never collected: a registration may precede its VM's
    /// published endorsement certificate.
    pub grace: SignedDuration,
    /// The most to return.
    pub cap: usize,
}

/// The EK hashes of the nodes to remove, oldest registration first, at most `cap`.
///
/// Kept: a banned node (a ban is a security record, removed by an operator), a node inside
/// the grace, a node whose VM still publishes its hash, a node an unended claim is bound
/// to. An empty VM list is not believed while any node is young or any claim is active:
/// it is what a failed or lagging list looks like, and acting on it would empty the
/// register.
#[must_use]
pub fn nodes_to_delete(i: &Inputs<'_>) -> Vec<String> {
    let aged = |n: &NodeRecord| i.now.duration_since(n.registered_at) >= i.grace;
    if i.live_ek_hashes.is_empty()
        && (!i.busy_node_ids.is_empty() || i.nodes.iter().any(|n| !aged(n)))
    {
        return Vec::new();
    }
    let mut doomed: Vec<&NodeRecord> = i
        .nodes
        .iter()
        .filter(|n| {
            !n.banned
                && aged(n)
                && !i.live_ek_hashes.contains(&n.ek_hash)
                && !i.busy_node_ids.contains(&n.node_id)
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

/// The EK hash of a TPM guest's node entry: the hash its name carries, when the entry is
/// parented to the TPM agent of that same hash. Any other entry is not this rule's: a claim
/// entry, or an x509pop node entry (ADR-0049), whose name is a hash of something else.
#[must_use]
pub fn tpm_node_entry_ek(e: &EntryRef) -> Option<&str> {
    if e.kind != EntryKind::Node {
        return None;
    }
    let ek = e.name.strip_prefix("mediatore-node-")?;
    let parent = e.parent_id.as_deref()?;
    (is_ek_hash(ek) && parent.ends_with(&format!("/spire/agent/tpm/{ek}"))).then_some(ek)
}

/// What one pass over the node entries knows.
pub struct EntryInputs<'a> {
    /// Every entry mediatore has declared.
    pub entries: &'a [EntryRef],
    /// The EK hash every banlieue VM currently publishes.
    pub live_ek_hashes: &'a HashSet<String>,
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
}

/// The names of the TPM node entries to retract, in name order, at most `cap` (ADR-0039
/// decision 7). A node entry is declared from a VM's published endorsement certificate
/// (ADR-0011), so it lives as long as some VM publishes its hash; past that it gives an agent
/// that cannot exist an identity, and nothing else will ever remove it.
///
/// Kept: an entry whose hash a VM publishes, one an unended claim's node is under, one whose
/// node registered inside the grace. An empty VM list is believed only as
/// [`nodes_to_delete`] believes it.
#[must_use]
pub fn node_entries_to_delete(i: &EntryInputs<'_>) -> Vec<String> {
    let young = |n: &NodeRecord| i.now.duration_since(n.registered_at) < i.grace;
    if i.live_ek_hashes.is_empty() && (!i.busy_node_ids.is_empty() || i.nodes.iter().any(young)) {
        return Vec::new();
    }
    let busy: HashSet<&str> = i
        .busy_node_ids
        .iter()
        .filter_map(|id| id.rsplit_once("/spire/agent/tpm/").map(|(_, ek)| ek))
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
            tpm_node_entry_ek(e).is_some_and(|ek| {
                !i.live_ek_hashes.contains(ek) && !busy.contains(ek) && !held.contains(ek)
            })
        })
        .map(|e| e.name.as_str())
        .collect();
    doomed.sort_unstable();
    doomed.into_iter().take(i.cap).map(str::to_owned).collect()
}

/// The EK hash each VM publishes, computed exactly as the claim binding does
/// ([`ek_hash_from_pems`] over the endorsement certificates banlieue mirrors onto the VM).
/// A VM with no certificate yet, or an unusable one, protects no node.
#[must_use]
pub fn ek_hashes_of(machines: &[VirtualMachine]) -> HashSet<String> {
    machines
        .iter()
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

    use super::{
        EntryInputs, Inputs, MAX_DELETIONS_PER_PASS, ek_hashes_of, node_entries_to_delete,
        nodes_to_delete, tpm_node_entry_ek,
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
            live_ek_hashes: live,
            busy_node_ids: busy,
            now: at(100),
            grace: SignedDuration::from_mins(10),
            cap: MAX_DELETIONS_PER_PASS,
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
            live_ek_hashes: live,
            busy_node_ids: busy,
            nodes,
            now: at(100),
            grace: SignedDuration::from_mins(10),
            cap: MAX_DELETIONS_PER_PASS,
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

    #[test]
    fn claim_entries_and_x509pop_node_entries_are_not_this_rules() {
        let claim = EntryRef {
            name: "mediatore-claim-6f1e0000-0000-4000-8000-0000000000c1".into(),
            kind: EntryKind::Claim,
            claim_uid: Some(Uuid::nil()),
            parent_id: Some(format!("spiffe://sandbox.test/spire/agent/tpm/{}", ek('a'))),
        };
        let x509pop = EntryRef {
            name: format!("mediatore-node-{}", ek('b')),
            kind: EntryKind::Node,
            claim_uid: None,
            parent_id: Some("spiffe://sandbox.test/spire/agent/x509pop/host-ca/vm-uid".into()),
        };
        let unparented = EntryRef {
            parent_id: None,
            ..tpm_entry(&ek('c'))
        };
        for e in [&claim, &x509pop, &unparented] {
            assert_eq!(tpm_node_entry_ek(e), None, "{}", e.name);
        }
        assert_eq!(
            entry_pass(
                &[claim, x509pop, unparented],
                &set(&[&ek('z')]),
                &set(&[]),
                &[]
            ),
            none()
        );
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
