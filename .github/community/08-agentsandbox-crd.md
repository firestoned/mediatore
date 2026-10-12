<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 08: AgentSandbox CRD and reconciler

**Status: not started.** Build [ADR-0008](../../docs/adr/0008-agentsandbox-crd-owned-by-mediatore.md):
`AgentSandbox` (`mediatore.io/v1alpha1`) becomes the record of a sandbox request, reconciled
by mediatore, which creates and owns the one `VirtualMachineClaim` behind it. The design came
from banlieue's ADR-0055, which was never built there and is superseded by ADR-0008.

Depends on roadmap 03 (the claim watcher, the `banlieue-api` pin and leader election). Narrows
roadmap 05: the store keeps only what cannot sit on a custom resource.

- [ ] ADR-0008 accepted (Proposed 2026-10-12)
- [ ] `AgentSandbox` type in `mediatore-claims` (spec: `subject`, `poolRef`, `ttlSeconds`,
      `audiences`, `workload`; status mirrors the claim plus "entry set"); a `crdgen` binary
      writes `deploy/base/crds/`, never hand-edited
- [ ] Reconciler on the roadmap 03 leader-elected loop: create the owned claim, mirror its
      status, `Ready` only when the claim is `Bound` and the `ClusterStaticEntry` is set
- [ ] Finalizer: delete the entry, revoke the store row, delete the claim, release only once
      the claim is gone (decision 10); the ADR-0006 orphan sweep stays as the backstop
- [ ] `ValidatingAdmissionPolicy` `deploy/base/admission/agentsandbox-subject.yaml`:
      `spec.subject` must match the caller unless the caller is mediatore's ServiceAccount or
      a listed broker (decision 5), with tests for each exception and the default-deny case
- [ ] Audiences outside mediatore's configured set rejected (admission or reconcile, fail
      closed)
- [ ] `POST /v1/claims` creates an `AgentSandbox`; `GET` and `DELETE` act on it
- [ ] RBAC: `agentsandboxes` (get, list, watch, status and finalizer updates) and
      `virtualmachineclaims` (create, delete, get, list, watch); nothing else added
- [ ] Live test against a cluster with banlieue's CRDs: `kubectl apply` of an `AgentSandbox`
      binds, a subject mismatch is denied at admission, deletion leaves no claim and no entry
- [ ] User guide: requesting a sandbox declaratively, and why the pool must use `GuestReady`
- [ ] Threat model pass (new CRD, new admission policy, new RBAC; the declarative path is a
      new way to attribute a sandbox to a subject)
