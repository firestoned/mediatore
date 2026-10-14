<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 08: AgentSandbox CRD and reconciler

**Status: done (2026-10-14).** Built [ADR-0008](../../docs/adr/0008-agentsandbox-crd-owned-by-mediatore.md):
`AgentSandbox` (`mediatore.io/v1alpha1`) becomes the record of a sandbox request, reconciled
by mediatore, which creates and owns the one `VirtualMachineClaim` behind it. The design came
from banlieue's ADR-0055, which was never built there and is superseded by ADR-0008.

Depends on roadmap 03 (the claim watcher, the `banlieue-api` pin and leader election). Narrows
roadmap 05: the store keeps only what cannot sit on a custom resource.

- [x] ADR-0008 accepted (2026-10-14), with implementation notes for what the decisions
      left open (one claim per sandbox ever, the record keyed by the claim's UID, the whole
      spec immutable, refusals at reconcile)
- [x] `AgentSandbox` type in `mediatore-claims` (`src/sandbox.rs`; spec: `subject`,
      `poolRef`, `ttlSeconds`, `audiences`, `workload`; status mirrors the claim plus
      `entrySet` and `ready`); the `crdgen` binary writes `deploy/base/crds/` (`make crds`),
      and a unit test fails on a stale file
- [x] Reconciler on the roadmap 03 leader-elected loop (`Watcher::reconcile_sandbox`, a
      third `Controller` owning the claims): create the owned claim, write the record,
      mirror the status, `ready` only when the claim is `Bound` and the entry is set
- [x] Finalizer `mediatore.io/sandbox`: retract the entry, revoke the record, delete the
      claim, let the object go only on a pass that finds no claim (decision 10); the
      ADR-0006 orphan sweep stays as the backstop
- [x] `ValidatingAdmissionPolicy` `deploy/base/admission/agentsandbox-subject.yaml`:
      `spec.subject.id` must match the caller unless the caller is mediatore's
      ServiceAccount or a listed broker (decision 5), the spec immutable afterwards; the
      kind tier exercises the default denial, the impersonated stranger, both exemptions
      and the immutability
- [x] Audiences (and the subject's issuer) outside mediatore's configuration refused at
      reconcile, `Failed` with a reason and no claim; `POST /v1/claims` refuses with `400`
      before creating anything
- [x] `POST /v1/claims` creates an `AgentSandbox` in `sandboxes.namespace`; `GET` answers
      from its status (`ready` added to the response); `DELETE` deletes it
      (`crates/mediatore/tests/e2e_sandbox.rs` over `MemorySandboxes`)
- [x] RBAC: `agentsandboxes` get, list, watch, patch, create, delete; `agentsandboxes/status`
      patch; `agentsandboxes/finalizers` update (the owner reference's `blockOwnerDeletion`);
      `virtualmachineclaims` unchanged. Create and delete are the user API's, which the
      roadmap's first draft had not listed
- [x] Live test: `make kind-e2e-sandbox` (`dev/kind/sandbox-e2e.sh`): the policy, an
      `AgentSandbox` becoming an owned claim and a record, the claim bound to a claim entry
      with the guest fetching the subject over its node SVID, a refused audience, deletion
      leaving no claim and no entry
- [x] User guide: [requesting a sandbox](../../docs/guides/requesting-a-sandbox.md)
      (declaratively and through the API), the `brokers` lists on both policies, and why
      the pool must use `GuestReady`
- [x] Threat model pass (2026-10-14): TB-1 and TB-2 rows for the resource, the policy and
      the RBAC; A-7 widened; R-5 reworded; stamp to a built ADR-0008
