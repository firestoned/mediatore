<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0079: A tripped VM held for its operator, running and cut, for a bounded time

**Status:** Proposed · **Date:** 2026-11-28

Answers [ADR-0069](0069-tripwires-on-the-vm-a-decoy-the-workload-takes-ends-its-sandbox.md)'s
open question 3 ("Quarantine, if a responder's need for a live VM proves real") and revisits the
alternative it rejected ("Quarantine (the VM kept frozen for inspection)"). Amends ADR-0069
decision 9 (after a trip the reconciler deletes the `VirtualMachineClaim` at once) and decision 7
(the teardown after a trip wipes the sandbox's filesystem). Builds on
[ADR-0034](0034-the-kubernetes-api-as-the-brokers-store.md) (the record on the `AgentSandbox`
and its retention sweep), [ADR-0039](0039-a-node-leaves-the-register-when-its-vm-is-gone.md)
(node entries), [ADR-0010](0010-no-inbound-to-sandboxes.md) (no inbound path to a sandbox) and
banlieue's claim contract. Changes no token shape and no SPIFFE ID. It adds a field to the
record and to the `AgentSandbox` status, a key to the broker's `tripwires` section and one to
`GET /v1/me`'s `traps`, and changes what a trip leaves behind, so the full ADD cycle and a
threat-model pass apply when it is accepted.

## Context

What a trip under `enforce` does today, from the code:

1. On the VM (`decide`, `crates/mediatore-guest/src/trip.rs`): the sandbox uid's table is
   replaced by a drop of everything that uid sends (`drop_all_ruleset`), then the supervision
   kills the jail and every process of the sandbox user (`kill_sandbox_processes`,
   `crates/mediatore-guest/src/supervise.rs`). Measured on the build host: the cut 54 ms after
   the verdict, every process of the uid gone about 250 ms after it.
2. The guest reports on `POST /v1/me/trip` and waits at most `REPORT_WAIT` (120 s) for the
   acknowledgement, then tears down: `teardown_after(.., tripped = true)` keeps the cut table
   and the sandbox user, **unmounts the claim's tmpfs and removes `work`, `layers`, `rootfs`,
   `egress` and `home`** (`crates/mediatore-guest/src/supervise.rs`).
3. The broker (`end_claim`, `crates/mediatore-api/src/trip.rs`) writes `tripped` on the record
   by compare-and-set and releases the claim: the claim's entry is retracted and the record
   revoked (`Reconciler::release`, `crates/mediatore-claims/src/lib.rs`). From then on the
   claim's token is refused, `GET /v1/me` is `404 no_claim` for the node, and a gateway refuses
   the claim's egress.
4. The reconciler (`fail_tripped`, `crates/mediatore-claims/src/sandbox.rs`) deletes the
   `VirtualMachineClaim` and marks the sandbox `Failed` with `Tripped=True`. banlieue's claim
   contract (`banlieue-api` v0.6.0, `virtualmachineclaim.rs`): "Bound once, ever. The member it
   binds is never handed to another subject, never returned to the warm set, and never reused.
   Release is always destruction"; "Deleting the claim destroys the VM"; "`ttlSeconds` is a hard
   deadline [...] At expiry the member is deleted whether or not the consumer is finished".
5. What remains: the audit lines (`trip reported`, `claim ended by a trip`), the record's
   `tripped` and `status.tripwires` on the `AgentSandbox` until the retention sweep deletes it
   (`store.retention_secs` after the release), and the workload's output the broker took (for
   60 s after the trip, `LOGS_AFTER_A_TRIP`).

Three facts shape any quarantine:

- **Everything of the claim is in RAM.** The sandbox filesystem is a tmpfs per claim
  ([ADR-0021](0021-sandbox-filesystem-tmpfs-and-rootfs-from-the-registry.md),
  `crates/mediatore-guest/src/sandboxfs.rs`): the unpacked rootfs, `/work`, the home with the
  bait files, the egress proxy's state. The member's disk is the VM image (Kairos,
  [ADR-0023](0023-sandbox-vm-image-kairos-derivative.md)) and the guest's journal. So a VM
  **stopped with its disk keeps nothing a responder wants**: a power-off destroys the tmpfs.
- **The guest wipes the tmpfs itself** (step 2), within about two minutes of the trip. A VM kept
  past that holds nothing either, whatever banlieue does.
- **mediatore cannot keep a VM past its claim's deadline.** The deadline is banlieue's, counted
  from binding, and the broker's RBAC on `virtualmachineclaims` is `get`, `list`, `watch`,
  `create` and `delete` (`deploy/base/rbac.yaml`): it can delete a claim early, never extend one.
  It has no verb on a `VirtualMachine`'s power state (`get`, `list`, `watch` only).

And a fact about the trips themselves: ADR-0070's claim-scoped `protocol` classes at `trip` end
a claim through the same `end_claim`, decided by the broker. The guest is not told: its jail is
not cut and its workload is not killed on the VM. Today the VM's destruction is what stops that
workload. A quarantine that kept such a VM would keep a live workload.

## Decision

1. **Off by default, the operator's setting alone.** `tripwires.quarantine.hold_secs` in the
   broker's configuration (`TripwiresSection`, `crates/mediatore/src/config.rs`), default `0`
   (off). A value above `MAX_QUARANTINE_SECS` (14 400, four hours, a constant in
   `crates/mediatore-proto/src/trip.rs`) refuses the broker at start, as does any value while
   `policy.traps` is `off` other than `0` (it would do nothing, and a setting that does nothing
   silently is a trap for the operator). It is not in the sandbox's spec, the policy bundle or
   any `SandboxAudience`: no tenant can turn it on, off, or lengthen it.
   `tripwires.quarantine.max_held` (default `2`, at most `16`) bounds how many VMs are held at
   once by this broker (decision 6).

2. **What is held: the VM, powered, the sandbox uid cut and dead, its tmpfs kept read-only.**
   The recommendation is **running, network-cut**, not "stopped with its disk": the disk holds
   only the image, and everything the workload touched is on the claim's tmpfs, in RAM. On the
   VM nothing of containment changes: the cut first, the kill after, as today. What changes is
   the teardown after a trip, when the claim was handed `traps.quarantine: true` in `GET /v1/me`
   (a new optional field of `TrapsPolicy`, `crates/mediatore-proto/src/trip.rs`; an older guest
   ignores it): `teardown_after` keeps the tmpfs mounted and remounts it `ro,nosuid,nodev,noexec`
   (`sandboxfs::freeze`, new, `crates/mediatore-guest/src/sandboxfs.rs`), keeps the cut table and
   the sandbox user as today, and removes nothing. A new `Cleanup::KeepForQuarantine`
   (`crates/mediatore-guest/src/supervise.rs`) carries it. The guest then stays up and logs one
   line at `warn` naming the claim UID and that the VM is held; it starts nothing. When the VM
   is destroyed the tmpfs goes with it.

3. **Only a trip the VM contained is held.** The broker sets the hold only when the record's
   `tripped` came from a node's `POST /v1/me/trip`, its first event is of kind `port`, `route`,
   `credential` or `denied`, and that event carried `containment_ms` (the guest's `nft` cut
   succeeded; a cut that failed reports none, `cut` in `trip.rs`). `end_claim` puts
   `contained: true` on the `Tripped` it writes (a new field of `Tripped`,
   `crates/mediatore-proto/src/trip.rs`; absent reads as `false`). A `protocol` or `segment`
   trip, a trip whose cut was not confirmed, and a record that could not be written are never
   held: the VM is destroyed at once as today, since destruction is the only thing that stops a
   workload the VM did not stop itself.

4. **Containment and the claim's end never wait on the hold.** `end_claim` is unchanged in
   order: `tripped`, then the release (entry retracted, record revoked), then the fold. From
   that moment the claim SVID cannot be renewed (its current one lives at most
   `MAX_CLAIM_SVID_TTL`, fifteen minutes, and the broker refuses it anyway), its token is
   refused at `POST /v1/token`, `GET /v1/me` is `404 no_claim`, and a gateway refuses its
   egress, exactly as for a destroyed VM. The hold is decided after all of that, by the
   reconciler, and only delays the deletion of the `VirtualMachineClaim`.

5. **The reconciler holds the claim, then deletes it.** In `fail_tripped`
   (`crates/mediatore-claims/src/sandbox.rs`), when the hold is on, `tripped.contained` is
   true, and fewer than `max_held` sandboxes are held, the reconciler writes
   `status.quarantine: {since, until}` on the `AgentSandbox` (a new status field,
   `QuarantineStatus`, both served versions, written with the rest of the status by the
   broker's ServiceAccount, which alone may write the status:
   `deploy/base/admission/agentsandbox-status.yaml`), sets the condition `Quarantined=True` with
   the `until` time, and requeues at `until` without deleting the claim. `until` is the earlier
   of `tripped.recorded_at + hold_secs` and the claim's banlieue deadline (bound time plus
   `ttlSeconds`): mediatore never extends a claim, so a trip near the end of a claim's lifetime
   gets a short hold or none. At `until` the reconciler deletes the claim as it does today, and
   banlieue destroys the VM. The status write and the delete are each logged at `warn` with the
   claim UID, the sandbox, `since` and `until` (`quarantine started`, `quarantine ended`).
   A `status.quarantine` this build cannot read is read as absent and the claim is deleted:
   an unreadable hold fails towards destruction.

6. **At most `max_held` at once; past it, destruction.** The count is the reconciler's own
   (it runs on the replica holding the Lease): sandboxes in its reflector with
   `status.quarantine.until` in the future. A trip that finds the count full is destroyed as
   today, logged at `warn` (`quarantine refused: max_held reached`). So a tenant who trips
   deliberately, claim after claim, can hold at most `max_held` pool members, never a pool.

7. **The owner cannot shorten the hold; only the operator can.** Deleting the `AgentSandbox`
   (the owner's RBAC, or `DELETE /v1/claims/{name}`) sets its deletion timestamp, and
   `finalize_sandbox` (`crates/mediatore-claims/src/sandbox.rs`) does not delete a held claim
   before `until`: it requeues, the sandbox stays `Terminating` with `Quarantined=True`, and the
   finalizer holds the owned claim from garbage collection (`blockOwnerDeletion`, `claim_for`).
   The retention sweep's deletion is held the same way. The operator ends a hold early by
   deleting the `VirtualMachineClaim` (banlieue's RBAC, which tenants should not hold: see
   Consequences); the reconciler then finds the claim gone and finishes as `fail_tripped` does.
   No annotation, route or CLI verb ends or extends a hold.

8. **No new way into the VM.** The image gains no login, no `sshd`, no listener, no inbound
   rule ([ADR-0010](0010-no-inbound-to-sandboxes.md)); the broker gains no route that reaches a
   VM. Inspection is with the access the operator already has at the host: the provider's
   console and the hypervisor's own tools (a memory dump, a snapshot) where the provider has
   them. Nothing about that access is mediatore's, and this ADR documents it for the runbook,
   no more. The workload's identity is gone (decision 4), and the node's goes too:

9. **The held VM loses its node identity.** Once `LOGS_AFTER_A_TRIP` (60 s) has passed after
   `tripped.recorded_at`, the watcher retracts the member's node entry and declares none for it
   again while its claim's sandbox carries `status.quarantine` (`crates/mediatore-claims/src/watch.rs`,
   beside the node-entry declaration; `nodegc.rs` keeps its node record until the VM is gone, as
   ADR-0039 says). The node SVID the guest holds then expires at its lifetime (the SPIRE
   server's default for a node entry, since the entry sets none) and cannot be renewed. A held
   VM's root, honest or not, then has no identity the broker, the relay or a gateway accepts.
   banlieue never binds the member again ("Bound once, ever"), so no claim can reach it.

10. **What the owner sees.** `mediatore sandbox get` and `GET /v1/claims/{name}` show
    `quarantined until <time>` after the trip line (`crates/mediatore-client/src/cli.rs`), and
    the docs say plainly that the operator holds the VM, and with it the workload's files, until
    then. The owner's data is held longer than they asked; they are told.

## Security analysis

| Boundary | Threat | STRIDE | Control |
| --- | --- | --- | --- |
| TB-12 / TB-7 | A held VM's workload goes on acting (a second process, a timer) | T/I/E | Decision 2: nothing of the containment changes; the cut and the kill of every process of the uid come first, the user kept, the tmpfs remounted `noexec` and read-only. Decision 3: a trip the VM did not contain is never held |
| TB-7 / TB-14 | A process that escaped to root before the trip uses the held VM (ADR-0070's actor) | E/I | Root's host table is unchanged (only the broker, the relay and the registry); decision 9 takes the node identity away after 60 s; decision 6 bounds how many such VMs exist; the hold is at most four hours and never past the claim's deadline. The residue is a new accepted risk: a compromised root keeps a VM, its CPU and its host-table reach, for the hold |
| TB-6 | A held VM's guest, or a root impersonating it, calls the node routes | S/E | `claim_of_node_peer` already answers `404 no_claim` for a tripped record; decision 9 removes the identity itself; banlieue never rebinds the member |
| TB-2 | The owner (who may be the attacker) deletes the sandbox to destroy the evidence | T/R | Decision 7: the finalizer holds the claim until `until`; only the operator's delete of the `VirtualMachineClaim` ends it |
| TB-2 | Deliberate trips hold pool members until the pool is full | D | Decision 6 (`max_held`); a held member counts against the pool's `maxReplicas` (banlieue: "Hard ceiling on members of any phase, claimed ones included") |
| TB-2 | A tenant turns quarantine on, or lengthens it, for its own sandbox | E | Decision 1: the broker's configuration only; the status is written by the broker's ServiceAccount alone |
| TB-9 | The hold leaves the workload's files (route data, the owner's repository, the bait) on a live VM longer | I | Read-only and `noexec`; bounded by decision 1 and the claim's deadline; operator access only (decision 8); the owner told (decision 10). The bait is valid nowhere |
| TB-6 | A hold that is never released (a reconciler that stops) | D | banlieue's `ttlSeconds` destroys the member at the claim's deadline whatever mediatore does |

## Consequences

- With the hold off, nothing changes, byte for byte: the guest is handed no `quarantine`, the
  teardown wipes as before, the reconciler deletes at once.
- With it on, a responder has a powered VM whose sandbox filesystem is as the workload left it,
  read-only, for at most `hold_secs` and never past the claim's deadline.
- One more VM per held trip, for the hold, counted in its pool. A pool sized at
  `warmReplicas` plus expected claims with no headroom loses that much capacity.
- Tenants must hold no `delete` on `virtualmachineclaims` in their namespaces, or the owner can
  end a hold (and today can already destroy a running claim's VM behind mediatore). The
  deploying guide is to say so.
- The record gains `tripped.contained`; the status gains `quarantine` and the condition
  `Quarantined`; `GET /v1/me`'s `traps` gains `quarantine`. The CRD schema changes in both
  served versions. A CRD not yet upgraded prunes `status.quarantine`, which this build reads as
  no hold and deletes the claim: the upgrade order is the CRDs, then the broker.
- The rollout order of ADR-0069 holds (guests first): an older guest wipes the tmpfs whatever
  the broker says, and a hold of such a VM keeps nothing.
- The threat-model pass adds a component behaviour (the guest's frozen tmpfs), an asset (the
  held VM and its contents), rows under TB-2, TB-6, TB-7, TB-9, TB-12 and TB-14, and an
  accepted risk (a compromised root kept running for the hold).

## Alternatives rejected

- **Stopped with its disk** (banlieue's `PoweredOff`): the disk is the image; the claim's
  files are on a tmpfs that a power-off destroys. It would keep the journal and nothing else.
  Also not mediatore's to do: its RBAC has no write on `VirtualMachine`.
- **Suspended** (banlieue's `Suspended`, the RAM kept by the hypervisor): the best evidence of
  all and no running code, but mediatore cannot set it (no verb on `VirtualMachine`, and a pool
  owns its members' spec), and whether each provider implements it for a claimed member is
  banlieue's to state. Revisit when banlieue exposes a hold or a suspend on a claim.
- **A disk or memory snapshot taken by mediatore**: needs a provider API mediatore does not
  call, and a store for the snapshot whose readers would be a new population.
- **The guest copies the tmpfs to the broker**: the bait, the owner's files and anything the
  workload wrote would leave the VM to a new store; ADR-0069 keeps every draw on the VM.
- **Freezing the jail instead of killing it** (cgroup freezer): ADR-0069 decision 7 rejected
  it, and nothing here needs a process alive: the files are what is kept.
- **A hold set per sandbox or per policy**: a tenant could set or avoid it.
- **Extending the claim's deadline for the hold**: not possible through banlieue's API, and a
  hold that can outlive its claim's stated lifetime is a hold that can be stretched.

## What must be proven

- Hermetic (`make check`): the configuration's refusals
  (`quarantine_above_the_hard_bound_or_under_off_refuses_the_broker`); `end_claim` writes
  `contained` only for a contained VM kind with `containment_ms`
  (`a_protocol_trip_or_an_unconfirmed_cut_is_never_marked_contained`); the reconciler holds then
  deletes (`a_contained_trip_holds_the_claim_until_the_hold_then_deletes_it`), never past the
  claim's deadline (`the_hold_ends_at_the_claims_deadline_when_that_comes_first`), refuses past
  `max_held` (`a_trip_past_max_held_is_destroyed_at_once`), holds through the owner's delete and
  the retention sweep (`deleting_a_held_sandbox_waits_for_the_hold`), and deletes on an
  unreadable hold (`an_unreadable_quarantine_status_deletes_the_claim`); the guest's teardown
  keeps and freezes the tmpfs only when told (`teardown_after_a_trip_keeps_the_tmpfs_read_only_under_quarantine`,
  `teardown_without_quarantine_is_unchanged_byte_for_byte`); the watcher withholds the node
  entry of a held member after the grace (`a_held_member_gets_no_node_entry_after_the_logs_grace`).
- e2e (`crates/mediatore/tests/e2e_sandbox.rs`): a tripped claim's record is released and its
  token refused at once while the claim object stays; `status.quarantine` and `Quarantined` shown.
- kind (`make kind-e2e-sandbox`): the status field and condition in both served versions; a
  held sandbox whose owner deletes it stays `Terminating` until `until`; the claim deleted then.
- Live, on the build host (`crates/mediatore/tests/jail_exec_live.rs`): after a trip under
  quarantine no process of the uid remains, the tmpfs is mounted read-only and `noexec`, and the
  uid still sends nothing.
- Live on the homelab, before `hold_secs` is set anywhere: a tripped pool VM held, its node
  entry gone after the grace, the operator reading the frozen tmpfs from the host's console, the
  VM destroyed at `until`, the pool refilled.

## Open questions

1. **Is the need real?** ADR-0069 asked for quarantine only "if a responder's need for a live VM
   proves real". Recommendation: accept this ADR as the design and build it only when an
   operator asks for it after a real `enforce` trip; until then the audit lines and the status
   are the record.
2. **`hold_secs` hard bound.** Recommendation: four hours, the length of a working session for
   a responder; anything longer is a forensic image, which is the hypervisor's job.
3. **Should the guest write a manifest of the frozen tmpfs** (paths, sizes, SHA-256, no
   content) to its journal at the start of a hold, so the operator knows what is there before
   opening the console? Recommendation: not now. It adds a walk of a workload-built tree as
   root; revisit with the first real responder's request.
4. **Suspend instead of running.** Recommendation: ask banlieue for a claim-level suspend (RAM
   kept, no CPU) and switch to it when available; until then, running and cut.
5. **`max_held` per subject as well as per broker.** Recommendation: per broker only; a subject
   that trips repeatedly is a finding for the operator, who already reads the audit lines.
