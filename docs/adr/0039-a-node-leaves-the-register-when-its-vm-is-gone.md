<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0039: A node leaves the register when its VM is gone

**Status:** Accepted, implemented in the repository 2026-11-15 (the store's `delete_node`, the pure rule `nodegc::nodes_to_delete`, `Watcher::collect_nodes` on the resync ticker, `store.node_grace_secs`, their pinned tests; the live proof is a pool recycled under load and the register staying the size of the pool) · **Date:** 2026-11-15

Roadmap 05 (the store). Completes [ADR-0034](0034-the-kubernetes-api-as-the-brokers-store.md)
decision 3, which made an attested node a `SandboxNode` and gave claims a retention window
(decision 4) but no lifecycle for nodes. Changes no token shape, no SPIFFE ID and no entry
shape; adds one authority to the broker, deleting a node record, within the RBAC it
already holds (`deploy/base/rbac.yaml` grants every verb on `sandboxnodes`).

## Context

A guest registers its node once, at its first start (`POST /v1/nodes`, ADR-0018 and
ADR-0019). The record is named by the EK hash, so a VM replaced by another, a pool
recreated, or a one-shot claim whose VM the pool discards, each leaves a record behind and
adds another when its successor registers. Nothing deleted one: the store interface had
`put_node`, `get_node`, `get_node_by_dmi`, `ban_node` and `list_nodes`, a `SandboxNode` has
no owner reference and no finalizer, and ADR-0034 decision 3 says only that it "holds what
`nodes` held", a table that was never pruned either. A homelab pool recreated a few times
and used for a handful of claims held twenty-five records for three VMs after five hours
(the deployment's testing log, T-54, F-36). With one-shot claims, which end their VM, the register grows by
one object per claim without bound.

It is not a binding hazard: a claim binds to a live VM through that VM's published
endorsement certificate. It is unbounded growth in the broker's namespace, a noisy
`list_nodes`, and rows that still read `banned: false` for hardware that no longer exists.

Deleting is not free of risk. The record is load-bearing for a live node: every call a
guest makes over its node identity (`GET /v1/me`, `POST /v1/me/report`, `POST /v1/me/exit`)
first fetches its `SandboxNode` and answers `403 node not registered` without it
(`claim_of_node_peer` in `crates/mediatore-api/src/lib.rs`). A live node whose record is
removed gets that `403` until its guest restarts and registers again. The rule below is
built so that does not happen to a node whose VM exists.

## Decision

1. **A node is collected when no banlieue VM publishes its EK hash.** On the replica that
   holds the watcher's Lease, once per resync (`watcher.resync_secs`, five minutes by
   default), the broker lists the pool member `VirtualMachine`s and computes each one's EK
   hash exactly as the claim binding does (`ek_hash_from_pems` over the endorsement
   certificates banlieue mirrors onto the VM, `nodegc::ek_hashes_of`). A `SandboxNode`
   whose hash no VM publishes is deleted. A VM with no certificate yet, or an unusable one,
   publishes nothing, so it protects no node and the unusable one is logged.

2. **The rule is a pure function, with a guard for each way it could do harm.**
   `nodegc::nodes_to_delete` takes the nodes, the live hashes, the nodes an unended claim is
   bound to, the time, the grace and a cap, and returns the hashes to delete. It never
   returns:
   - a **banned** node: a ban is a security record, kept until an operator removes it;
   - a node **younger than the grace** (`store.node_grace_secs`, default 600, zero refused):
     a registration may precede its VM's published certificate;
   - a node an **unended claim** is bound to (a record whose revocation or deadline is not
     yet past), so a claim never loses its node under it;
   - more than **`MAX_DELETIONS_PER_PASS`** (20), oldest registration first: a bug, a
     partial list or an operator error costs a bounded number of records, which come back
     when the guest registers again.
   An **empty VM list** is not believed while any node is younger than the grace or any
   claim is active: it is what a failed or lagging list looks like, and acting on it would
   empty the register. With only old nodes and no claim it is believed, and the stale
   register drains at the cap per pass.

3. **A listing that fails removes nothing.** Listing the nodes, the VMs or the claims is
   an error that ends the pass with a warning; there is no fallback to "no VMs". One
   failed deletion is logged and the pass goes on; the next pass retries it.

4. **`delete_node` is idempotent and in the contract.** `ClaimStore::delete_node(ek_hash)`
   removes the row and succeeds when it is not there, in the memory store, the Kubernetes
   store (a `404` is success) and the conformance suite (the row goes, no other row is
   touched, the DMI UUID and the hash are free for a machine that registers again).

5. **What a live guest does if its record goes anyway** (read in `crates/mediatore-guest/src/guest.rs`,
   not assumed). An idle guest polling `GET /v1/me` treats any status but success and `404`
   as fatal (`wait_for_subject`): the `403` ends the process, systemd restarts it
   (`Restart=on-failure`), and it registers again, so the record comes back and the guest is
   waiting again within seconds. A guest with a claim bound does not re-register: its report
   and its exit would be refused, the exit is logged as not having reached the broker
   ("the claim ends at its deadline"), and the claim stalls until then. That is why decision
   2 holds a node whose VM publishes its hash, a node a live claim is bound to, and a young
   node, and why a test pins that a node whose VM exists is kept across passes.

6. **Observability.** One info line per removal, `node removed: its VM is gone`, with the
   EK hash and the hostname (a hash and a name, no secret), and one per pass that removed
   any, with the count.

## Consequences

- The register is bounded by the pool plus the grace: it stops growing with churn.
- The broker gains the authority to delete node records, which it already had by RBAC and
  now exercises. Threat model: deleting a live node is a denial of service on one
  member, bounded by decision 2; a manipulated VM list is the way to abuse it, bounded by
  the cap and by the reach of whoever can already list `virtualmachines` for the
  broker's ServiceAccount (A-11, R-26).
- A node removed while its VM was merely unlisted is back when its guest registers again,
  with a new `registeredAt`: the record is a cache of what attestation proved, not the
  proof.
- No RBAC change: the broker's ClusterRole already has `delete` on `sandboxnodes`. The code
  needs a release (the live broker predates it). (Released in v0.2.5; the live proof is
  roadmap 05's.)
- A ban on a node whose VM is gone stays until an operator deletes it: the safe side of a
  security record, noisier than the alternative, and visible as `BANNED true`.

## Alternatives rejected

- **An owner reference from the `SandboxNode` to the `VirtualMachine`.** Kubernetes would
  collect the node with the VM, but the registration is a guest call over mTLS with no VM
  in hand: the broker would have to resolve the VM at register time, a new coupling, and a
  VM replaced under the same name would orphan or wrongly keep records.
- **An age limit alone.** Simple, and wrong in both directions: a long-lived VM loses its
  node, a short-lived one leaves it for the whole window.
- **A finalizer-held retention like a claim's.** There is nothing to audit in a node
  record that the log line does not already carry, and a node has no end of its own to
  hang a window on.
- **Collecting on every registration.** Puts the VM list on the hot path of a guest call
  and makes the guest's registration the trigger of other nodes' deletion.
- **Deleting banned nodes whose VM is gone.** A ban is a decision someone made; the
  broker does not make it again in the other direction.
