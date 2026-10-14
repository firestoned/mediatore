<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0008: AgentSandbox is a mediatore CRD, reconciled by mediatore

**Status:** Accepted · **Date:** 2026-10-12 · **Accepted:** 2026-10-14

Supersedes banlieue
[ADR-0055](https://github.com/firestoned/banlieue/blob/main/docs/adr/0055-agentsandbox.md)
(`AgentSandbox`: the agent layer owns a claim, not a member), which designed this object in
banlieue's repository under `agent.banlieue.io` and was never built. Its decisions carry over
here, restated against mediatore; the differences are called out. Amends
[ADR-0002](0002-separate-project-from-banlieue.md) (mediatore now serves one CRD of its own)
and narrows roadmap 05 (the persistent store). Related:
[ADR-0004](0004-spiffe-identity-scheme.md) (SPIFFE IDs keyed by the claim UID),
[ADR-0006](0006-registration-entries-as-clusterstaticentry.md) (entries as
`ClusterStaticEntry`), [ADR-0009](0009-kubernetes-orchestrates-vms-run-agents.md) and
[ADR-0010](0010-no-inbound-to-sandboxes.md) (the platform decisions, moved here with this
one).

## Context

banlieue's API now ends at `VirtualMachineClaim`. A pool keeps warm, single-use VMs; a claim
hands one to one subject and destroys it on release. Both are infrastructure, useful to CI and
build isolation as much as to agents, and banlieue
[ADR-0097](https://github.com/firestoned/banlieue/blob/main/docs/adr/0097-api-ends-at-virtualmachineclaim.md)
(2026-10-12) decided that nothing agent-shaped is added above them in that repository.

An agent sandbox still needs a request object above the claim. Two designs of that object
existed, and neither was built:

| | banlieue ADR-0055 | mediatore today |
| --- | --- | --- |
| Shape | `AgentSandbox` CR, `agent.banlieue.io/v1alpha1` | `POST /v1/claims` body (`ClaimRequest`) and a `ClaimRecord` row |
| Carries | pool, issuer/audience policy, runtime image, TTL | `pool_ref`, `audiences`, `workload`, `ttl_seconds`, subject |
| Lives in | the Kubernetes API | the claim store (in memory; sqlx planned, roadmap 05) |
| Creates | one `VirtualMachineClaim`, owned | one `VirtualMachineClaim` (planned, roadmap 03) |
| Requestable by | anything with RBAC on the CR | only a caller of mediatore's user API |

They are the same object. ADR-0055 left its largest question open on purpose (its decision 9:
is the broker the agent controller, or a separate service?). mediatore is the broker, and the
only reader of the one field ADR-0055 added that a claim does not already carry: which
issuers and audiences a sandbox's tokens may come from. Keeping the CRD in banlieue would
leave an agent-specific API in an infrastructure project whose only consumer lives here.

A request held only in mediatore's store has a different limitation: a sandbox can be asked
for only through mediatore's HTTPS API, by a caller holding a human login. GitOps, a CI
pipeline or an app-only service has no declarative way to ask for one.

## Decision

**1. `AgentSandbox` is a namespaced CRD in mediatore's API group, `mediatore.io/v1alpha1`,
served by mediatore.** The group matches the `mediatore.io/` label prefix already in use
(ADR-0006). The type lives in `mediatore-claims`, beside the watcher that reconciles it, and
is generated to `deploy/base/crds/` under the same code-first rule banlieue uses: the Rust
type is the source of truth and the YAML is never edited by hand.

**2. mediatore is both the broker and the AgentSandbox controller.** This answers banlieue
ADR-0055 decision 9. The reconciler runs in the existing binary, on the same leader-elected
loop that roadmap 03 adds for the claim watcher. There is no second controller and no second
deployment. The user API stays stateless.

**3. Composition, not duplication: an `AgentSandbox` creates and owns exactly one
`VirtualMachineClaim`.** Carried over unchanged from ADR-0055 decision 2. mediatore never
patches a pool member, never writes banlieue's claim label and never reads a member's
`resourceVersion` for a bind. banlieue's bind-once invariant (banlieue ADR-0047 decision 1)
stays in exactly one controller, banlieue's, and mediatore cannot violate it structurally.
The claim is created in the `AgentSandbox`'s namespace with an `ownerReference` back to it.

**4. Two front doors, one object.** `POST /v1/claims` stops writing a store row as the
record of a request and instead creates an `AgentSandbox` with `spec.subject` taken from the
validated token. A declarative caller creates the same object directly. Every downstream
step (claim, bind, entry, token) starts from the `AgentSandbox`, so the two paths cannot
diverge.

**5. `spec.subject` is pinned to the caller at admission.** This is the decision the
declarative path depends on. A `ValidatingAdmissionPolicy`
(`deploy/base/admission/agentsandbox-subject.yaml`) requires `spec.subject.id` and
`spec.subject.issuer` to match the requesting user, with the same `usernamePrefix` mapping
banlieue's claim-subject policy uses (banlieue ADR-0047 decision 10). The exceptions are
mediatore's own ServiceAccount, which acts for the subjects it has validated tokens for, and
an explicit, empty-by-default list of broker principals. Without this policy, anyone with
`create` on `agentsandboxes` could attribute a sandbox, and the tokens it mints, to anyone.
mediatore's ServiceAccount is then the only principal that creates the
`VirtualMachineClaim`, and banlieue's policy already has to allow it as a broker.

**6. `AgentSandbox` never carries a credential.** Carried over from ADR-0055 decision 3.
Policy by value, credentials by reference. A custom resource is readable by anyone with
namespace read and lands in the API server audit log, so a token field would be a token
disclosure. Refresh material stays in the store, encrypted (roadmap 05), and never appears
on the object.

**7. The spec is the request mediatore already accepts:**

| Field | Meaning | Source today |
| --- | --- | --- |
| `subject` | issuer, id, display; pinned by decision 5 | `Subject` |
| `poolRef` | the `VirtualMachinePool` to claim from; copied to the claim | `ClaimRequest.pool_ref` |
| `ttlSeconds` | passed through to the claim, which enforces it (decision 9) | `ClaimRequest.ttl_seconds` |
| `audiences` | downstream audiences the sandbox may request tokens for; must be a subset of mediatore's configured audiences, rejected otherwise | `ClaimRequest.audiences` |
| `workload` | OCI rootfs and args for the jail | `ClaimRequest.workload` |

Issuer policy (ADR-0055 decision 4) is not a per-object field in this version: the issuers
mediatore accepts are its configuration, and the subject's issuer must be one of them. A
per-sandbox issuer allowlist is added only when a deployment needs one.

**8. The agent runtime comes from the VM image; the workload comes from `spec.workload`.**
This refines ADR-0055 decision 5, which only covered the first half. `mediatore-guest`, the
jail and their dependencies are baked into the pool's `VMImage`, so a warm member has nothing
to install at bind. What the jail runs is an OCI rootfs that `mediatore-guest` unpacks after
the subject is known (roadmap 06). That is a pull on the bind path, and it is the workload's,
not the platform's.

**9. One TTL, enforced by the claim.** Carried over from ADR-0055 decision 6.
`spec.ttlSeconds` is copied to the claim, and expiry is banlieue's job: only the claim can
destroy the VM. mediatore observes the claim leaving `Bound` and cuts off issuance then, as
it already does.

**10. A finalizer holds the `AgentSandbox` until its claim and its entry are gone.**
Extends ADR-0055 decision 7 with mediatore's own state. On deletion mediatore deletes the
claim's `ClusterStaticEntry` (ADR-0006), revokes the store row, deletes the claim, and
removes the finalizer only when the claim no longer exists. A caller watching the object it
created never sees success while the VM, or an identity that can still mint tokens for it,
remains. The ADR-0006 orphan sweep stays as the backstop.

**11. Status mirrors the claim and mediatore's own state; it is never derived
independently.** Carried over from ADR-0055 decision 8. Phase, addresses, expiry and the
bound VM come from the claim's status. mediatore adds one fact it alone knows: whether the
claim's registration entry is set (ADR-0006 decision 5). An `AgentSandbox` is `Ready` only
when the claim is `Bound` **and** the entry is set. `GET /v1/claims/{name}` answers from this
status.

**12. The store keeps what cannot be on a CR.** The non-secret request fields move to the
`AgentSandbox`. The store keeps refresh ciphertext, revocation timestamps, node records and
audit rows. Roadmap 05 narrows accordingly; its restart-recovery test still holds, and
revocations still survive a restart.

## Consequences

- A sandbox can be requested declaratively by anything with RBAC on `agentsandboxes`, and
  decision 5 keeps that from becoming a way to impersonate a subject.
- mediatore grows from broker to broker plus controller: one CRD, one reconciler, one
  admission policy, RBAC on `agentsandboxes` and on `virtualmachineclaims` (`create`,
  `delete`, `get`, `list`, `watch`). ADR-0002's dependency direction is unchanged:
  mediatore depends on `banlieue-api`, banlieue never imports mediatore.
- banlieue's surface shrinks. `agent.banlieue.io` is never created, ADR-0055 is marked
  superseded there, and banlieue's threat model keeps treating the broker as an external
  claim consumer, which is what mediatore is.
- Two objects exist per sandbox, as ADR-0055 accepted. The cost buys a bind-once invariant
  that only banlieue can violate.
- The readiness caveat from ADR-0055 still applies: a sandbox is only as ready as the pool's
  readiness signal. Pools that serve sandboxes must use `GuestReady` (banlieue ADR-0043),
  and mediatore's AgentSandbox user guide says so.
- Built in roadmap 08 (2026-10-14), after roadmap 03; the threat-model pass
  (`docs/security/threat-model.md`) ran with it. The implementation notes below record the
  choices the decisions left open.
- Rejected: keeping the request only in the store (no declarative path); a separate
  controller project (a second binary and a second release to coordinate claim creation,
  with no isolation gain because both would hold the same RBAC); leaving the CRD in banlieue
  (its only consumer would be another repository).

## Implementation notes (2026-10-14)

What roadmap 08 fixed within the decisions above, so a reader of the code finds it here:

- **One claim per sandbox, ever.** The claim is named after the `AgentSandbox` and created
  in its namespace, so creation is idempotent without a status round trip. Once
  `status.claimRef` is set, a claim that later disappears (banlieue deleted it after the
  TTL, or the watcher failed it) turns the sandbox `Failed`; it is never recreated. A new
  VM is a new request.
- **The store record follows the claim's UID.** The reconciler creates the claim, then
  writes the `ClaimRecord` keyed by the claim's `metadata.uid` (decision 12; ADR-0011
  decision 1). The claim watcher requeues a `Bound` claim it has no record for, so a
  record written late, after a restart between the two steps, is still picked up.
- **Fail closed at reconcile, before any claim exists.** A sandbox naming an audience
  outside `audiences` in `mediatore.yaml`, or an issuer outside `issuers`, is marked
  `Failed` with the reason in `status.reason` and creates nothing. The user API refuses
  the same request with `400 unknown_audience` before creating the resource.
- **`spec` is immutable.** The admission policy freezes the whole spec on update, not only
  `subject`: every other field is read once, when the claim is created, so an edit would
  appear to work and change nothing.
- **Status** carries `phase` (mirrored from the claim: `Pending`, `Bound`, `Releasing`,
  `Failed`), `claimRef`, `claimUid`, `virtualMachineRef`, `addresses`, `boundAt`,
  `expiresAt`, `entrySet`, `ready` (decision 11), `reason` and `observedGeneration`. The
  user API's `ClaimResponse` gains `ready`.
- **Namespace.** `POST /v1/claims` creates the resource in `sandboxes.namespace` from
  `mediatore.yaml`; the pool it names must live there, since `poolRef` is a same-namespace
  reference on the claim.
- **RBAC** on `agentsandboxes` is get, list, watch, patch (the finalizer), create and
  delete (the user API, decisions 4 and 5), plus `agentsandboxes/status` and
  `agentsandboxes/finalizers` (the claim's `ownerReference` sets `blockOwnerDeletion`,
  which the API server's owner-references admission plugin checks against the latter).
- **Finalizer** `mediatore.io/sandbox`. Deletion releases the record (entry first), deletes
  the claim and removes the finalizer only on a later pass that finds no claim.

