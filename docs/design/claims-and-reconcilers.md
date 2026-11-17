<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Claims and reconcilers

The claim lifecycle, in `crates/mediatore-claims`. Two objects are in play, and keeping them apart is the point of
the design.

| Object | Owned by | Meaning |
| --- | --- | --- |
| `AgentSandbox` (`mediatore.io`) | mediatore | the **request**: who it is for, which pool, how long, which audiences, what to run, under which policy |
| `VirtualMachineClaim` (`banlieue.io`) | banlieue | the **VM**: created and owned by the `AgentSandbox`'s reconciler, bound to a pool member by banlieue |

mediatore never schedules a VM. It asks banlieue for one by creating a claim, and it reacts to what banlieue does to
that claim. Both objects, and the store record keyed by the claim's UID, are handled by one `Watcher`
(`watch.rs`).

## The request: `AgentSandbox`

`sandbox.rs` defines the resource (`AgentSandboxSpec`, `AgentSandboxStatus`, `SandboxPhase`) and its reconciler
(`Watcher::reconcile_sandbox`). A sandbox moves through four phases:

| Phase | Means |
| --- | --- |
| `Pending` | no claim yet, or the claim is waiting for a Ready pool member |
| `Bound` | the claim is bound to a member; `ready` says whether the registration entry is set as well |
| `Releasing` | the TTL was reached or the sandbox was deleted; tokens are cut off |
| `Failed` | terminal: the request was refused, the claim failed, or the claim is gone |

A sandbox is **never given a second VM.** If its claim is gone after it was created (expired and destroyed, or failed
by the watcher) the sandbox fails and stays failed.

### What is refused before any claim exists

`Watcher::refuse` fails a sandbox, with a reason in its status and no claim created, when:

- `ttlSeconds` is zero;
- it names an audience the broker is not configured to serve;
- its subject's issuer is not one the broker trusts;
- its image does not parse, or its registry is not one the pool reaches (ADR-0029);
- its image is on a registry that is a gateway-placed audience and the sandbox does not name that audience
  (ADR-0043).

Once a claim has been created the request was accepted under the configuration of that moment, and a later change
does not flap a bound sandbox between `Failed` and its mirrored status. A bound claim whose record lacks a delegation
that a `delegated` audience requires is refused too (`refuse_without_delegation`), so a claim never runs without
the credential it was promised.

### Deletion

A sandbox carries a finalizer (`FINALIZER`). Deleting it runs `finalize_sandbox`: it releases the record, deletes the
claim it owns, and waits for banlieue to destroy the member. A sandbox that **had a record** then keeps its finalizer for
the store's retention window (ADR-0034 decision 4), so what happened to it can still be read, and the store's sweep
releases it with an audit line. One that was **never bound** has its parked envelopes dropped and goes at once.

## The VM: the claim watcher

The watcher runs three controllers and two timers (`watch::run`):

| Controller or timer | Reacts to | Does |
| --- | --- | --- |
| claims | a `VirtualMachineClaim` | `reconcile_claim`: on `Bound`, resolve the node, declare the claim's entry, record it; on `Releasing`, `Failed` or deletion, retract the entry and revoke the record |
| machines | a pool member (`VirtualMachine`) | `reconcile_machine`: declare the node's bootstrap entry as soon as the VM publishes its endorsement certificate |
| sandboxes | an `AgentSandbox` | `reconcile_sandbox`, above; also woken by a policy bundle change |
| resync | every `WatcherConfig::resync` (5 minutes by default) | `resync`: release bound records whose claim is gone, sweep orphan entries, sweep ended sandboxes past retention (held by the finalizer until then; an audit line is logged, ADR-0034), collect nodes of gone VMs |
| envelope sweep | every 15 seconds (`ENVELOPE_SWEEP_SECS`) | `sweep_envelopes`: remove sealed envelopes past their expiry |

**On `Bound`.** The claim carries the certificate banlieue mirrored from the VM. The watcher computes its EK hash,
finds the node that registered under that hash, declares the claim's registration entry for the sandbox user
(`spiffe://<td>/banlieue/claim/<uid>`), waits for the SPIRE Controller Manager to report it set, and records the
entry in the store. **The order is entry first, then refresh material**, on bind and on release: on release the
identity is retracted before the record's secrets are revoked.

**Idempotence.** `next_action` is a pure function of the observed claim; a repeated event with no change is a `Hold`.
The state machine (`Reconciler::bind`, `release`, `sweep_orphans`) is tested without a cluster against fakes
(`fakes.rs`).

**The resync is a backstop**, not the mechanism: a record whose claim object vanished without an event is released
here, and an entry no record knows about is swept.

## One replica acts: the Lease

`lease.rs` elects the replica that runs the watcher with a `coordination.k8s.io` Lease (ADR-0011). The holder renews
every third of the lease duration and stops its work the moment a renewal does not go through, so two replicas never
bind at once. `run_as_leader` wraps `watch::run`, so the controllers, the resync, the envelope sweep and node
collection are all the holder's work. The policy-bundle reflector is the exception: it runs on **every** replica,
outside the Lease, because each replica needs the cache it will verify against (see [Policy](policy.md)).

## Collecting nodes of VMs that are gone

A node registers once per VM, named by its EK hash. `nodegc.rs` (ADR-0039) decides which `SandboxNode` resources to
delete, as a pure function so each guard has its own test: a node goes only when no banlieue VM still publishes its EK
hash, and **never** while it is banned, younger than the grace period (`node_grace`, 10 minutes by default, since a
registration can precede its VM's published certificate), or referenced by a claim that has not ended. A pass deletes
at most `MAX_DELETIONS_PER_PASS` (20), so a bug, a partial VM list or an operator error costs a bounded number of
records, which re-register on the guest's next start.

## Rules this part keeps

- A refusal creates nothing: no claim, no record, no envelope.
- Entry first on bind, entry first on release.
- One replica binds at a time; a lost renewal stops the work at once.
- The record is the store's, written in `kubestore.rs` and nowhere else; the sandbox's mirrored status is compared
  and patched without it.

## Read next

ADR-0008 (the CRD), ADR-0011 (the watcher and the Lease), ADR-0033 (the one-shot workload and the claim released when
it is done), ADR-0034 (the store), ADR-0039 (node collection). Threat model TB-2 (to the Kubernetes API) and TB-3 (the
entries). Guide: [Requesting a sandbox](../guides/requesting-a-sandbox.md).
