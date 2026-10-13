<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0011: The claim watcher binds and releases on `VirtualMachineClaim` events, resolves the node by its EK, and runs on one leader

**Status:** Accepted · **Date:** 2026-10-13

Roadmap 03. Builds on [ADR-0002](0002-separate-project-from-banlieue.md) (banlieue's
types are a pinned dependency), [ADR-0004](0004-spiffe-identity-scheme.md) (the claim and
node identities), [ADR-0006](0006-registration-entries-as-clusterstaticentry.md) (entries)
and prepares [ADR-0008](0008-agentsandbox-crd-owned-by-mediatore.md), whose reconciler
runs on the loop this ADR introduces.

## Context

Until now a claim was bound by the dev binder: `POST /v1/claims` under `dev_mode` picked a
free registered node and `POST /v1/nodes` picked a pending claim. Outside `dev_mode`
nothing bound anything. The real signal is banlieue's: a `VirtualMachineClaim` moves to
`Bound` with `status.virtualMachineRef` set, and to `Releasing` or `Failed` when the member
goes away. mediatore has to turn `Bound` into a claim entry for the right node and
`Releasing`, `Failed` or deletion into retraction and cut-off (`Reconciler::bind` and
`Reconciler::release` exist and are tested; nothing drives them).

Four things had to be decided.

**Which node is "the right node".** The roadmap had planned providerID → DMI UUID (both
byte orders on vSphere) → registered node. banlieue's `VirtualMachine` publishes neither
a DMI UUID nor a providerID; those live on the provider-specific infrastructure CRs, one
type per backend, which mediatore does not read. What the claim does mirror, since
banlieue ADR-0045, is the member's vTPM endorsement certificate
(`status.tpmEndorsementCertificates`, copied from the `VirtualMachine`). Its
SubjectPublicKeyInfo hash is exactly the node identity (ADR-0006: the tpm attestor's agent
ID, the `/banlieue/node/<ek>` SVID, the key of the node record a guest registers under).

**Which store record a claim object is.** ADR-0004 names the workload identity
`spiffe://<td>/banlieue/claim/<claim-uid>` without saying where the UID comes from.

**What happens when a bound member never registers.** A claim can be `Bound` to a VM
whose guest agent never calls `POST /v1/nodes` (image without the agent, no vTPM, a
broken boot). Guessing a node is the one thing the broker must never do.

**Two replicas.** `deploy/base/deployment.yaml` runs two, and a watcher that binds from
both would race on entries and on the store.

## Decision

**1. The claim UID is the `VirtualMachineClaim`'s `metadata.uid`.** That UUID is the
`<claim-uid>` of ADR-0004, the store record's key, and the claim UID the entry carries.
mediatore watches only claims labelled `app.kubernetes.io/managed-by=mediatore`, the label
it puts on everything it creates (ADR-0006 uses it on entries; ADR-0008 will put it on the
claims it creates). A claim without the label is not fetched at all. A labelled claim with
no store record is held and logged at debug (today that is a restart, §8 R-5; after
ADR-0008 the record exists before the claim does).

**2. The node is resolved by EK hash, never by address, name or UUID.** On `Bound`, the
watcher hashes the claim's `status.tpmEndorsementCertificates` with the same
`ek_hash_from_pems` the guest and the attestor use and looks up the registered node under
that hash. Found and not banned: `Reconciler::bind(uid, ek)`. The EK cross-check the
roadmap asked for is therefore not a separate step: the certificate banlieue mirrored is
the only input, so a node that registered with a different EK is simply not found.

**3. Unresolved is bounded: 60 seconds, then the claim is failed.** While the claim has no
certificate yet or its EK has no registered node, the watcher requeues every five seconds.
When `watcher.resolve_timeout_secs` (default 60) has passed since the claim was first seen
`Bound`, the watcher revokes the record (no entry was ever created) and deletes the
`VirtualMachineClaim`, which makes banlieue destroy the member. The log carries the claim
UID and the reason. A VM nobody can identify is not a sandbox.

**4. Release follows banlieue's phases, with the sweep as backstop.** `Releasing`,
`Failed` or a deletion timestamp on a claim that has an entry → `Reconciler::release`
(entry deleted, record revoked, tokens refused from that instant). At every resync
(`watcher.resync_secs`, default 300) the leader additionally releases every live record
whose claim no longer exists and runs `Reconciler::sweep_orphans`, so a claim deleted
while no watcher was running is still cut off.

**5. Node entries are declared from `VirtualMachine` events.** A pool member
(`banlieue.io/pool` label) whose `status.tpmEndorsementCertificates` is non-empty gets
`EntryManager::ensure_node_entry(ek)`; a member without a certificate gets nothing and can
never attest (ADR-0006). This is the trigger ADR-0006 left to the watcher. Declaring is
idempotent (409 is tolerated), so a restart re-declares harmlessly.

**6. One leader, elected with a `coordination.k8s.io` Lease.** The loop runs only on the
replica holding `Lease` `mediatore-watcher` in the broker's namespace
(`watcher.lease_duration_secs`, default 15; renewed every third of that). A replica that
fails to renew stops its controllers before another can acquire. RBAC for leases is a
namespaced `Role` (`deploy/base/rbac.yaml`), not the ClusterRole: `create` cannot be
restricted by resource name, so the grant is bounded by the namespace instead. The user
API stays stateless and runs on every replica.

**7. The loop is kube-runtime's `Controller`, one per resource, on the `banlieue-api` pin.**
`banlieue-api` is a git dependency pinned by commit (banlieue PR #98 of 2026-10-13, which
makes the crate depend on kube's `derive` feature only: with kube's default features it
dragged the `ring` provider into this graph and `cargo deny` refused it; the pin moves to
the merge commit, then to a tag when banlieue cuts a release with `VirtualMachineClaim`),
so schema drift is a compile error (ADR-0002). `cargo deny` already allows that one git source. The watcher runs only
outside `dev_mode`; under `dev_mode` the dev binder is unchanged and the dev loop needs no
cluster.

## Security analysis

| Boundary | Threat | S/T/R/I/D/E | Control |
| --- | --- | --- | --- |
| mediatore → Kubernetes API (TB-2) | A claim bound to the wrong node: identity issued to a VM the subject did not get | S/E | Node resolution only by the EK banlieue mirrored, looked up among nodes that registered with that EK over mTLS (decision 2); nothing is guessed, unresolved fails closed (decision 3) |
| mediatore → Kubernetes API | A claim object forged to look like mediatore's (label set by someone else) | S | The label only selects what the watcher looks at; binding still needs a store record for that UID, which only mediatore writes, and a registered node for the EK. banlieue's claim-subject policy governs who may create claims at all |
| mediatore → Kubernetes API | Two replicas bind or release the same claim concurrently | T/D | Lease leader election (decision 6); `bind` is idempotent and `KubeEntryManager` tolerates 409 as a second line |
| mediatore → Kubernetes API | A deleted claim keeps minting tokens | E | `Releasing`/`Failed`/deletion → release; resync releases records whose claim is gone and sweeps orphan entries (decision 4) |
| mediatore → Kubernetes API | Broker SA used to delete arbitrary claims | D | RBAC already grants `delete` on `virtualmachineclaims` (ADR-0008 needs it); the watcher deletes only a claim it holds a record for and could not resolve within the timeout, logged with the UID |
| VM → SPIRE server (TB-4) | A VM without a vTPM becomes a node | S | No certificate, no entry (decision 5); the entries admission policy still bounds the shape |
| mediatore → Kubernetes API | Lease stolen or held by a stale replica | D | Lease is namespaced and the Role grants only `get`, `create`, `update` on it; a stale holder expires after `lease_duration_secs` and the new leader starts from a resync |

## Consequences

- `banlieue-api` enters the tree (with `schemars`); `cargo deny` sources already allow the
  repository. The CRDs the kind tier needs are rendered from that same pin by a
  test-only binary in `mediatore-testkit`, never copied by hand.
- A sandbox is bound by what banlieue decided and what the VM proved about itself, in that
  order; the dev binder survives only under `dev_mode`.
- Until ADR-0008 lands, nothing outside `dev_mode` creates store records, so the watcher
  binds nothing in production yet; the node-entry trigger and the leader election are live
  from this ADR on. The kind tier proves those two against a real cluster.
- The roadmap's DMI route is dropped, not deferred: `NodeRecord.dmi_uuid` stays for audit
  and for the cloned-TPM check (two registrations of one EK with different DMI UUIDs are
  refused, threat model TB-4), not for resolution.
