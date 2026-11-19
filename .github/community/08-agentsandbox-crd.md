<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 08: AgentSandbox CRD and reconciler

**Status: done (2026-10-14).** Built [ADR-0008](../../docs/adr/0008-agentsandbox-crd-owned-by-mediatore.md):
`AgentSandbox` (`mediatore.io/v1beta1` since [ADR-0048](../../docs/adr/0048-agentsandbox-served-as-v1beta1.md), 2026-11-18; `v1alpha1` before, and still served beside it, deprecated, since [ADR-0049](../../docs/adr/0049-agentsandbox-served-as-v1alpha1-and-v1beta1.md)) becomes the record of a sandbox request, reconciled
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
- [x] [ADR-0044](../../docs/adr/0044-a-sandbox-selects-its-pool-by-label.md) (2026-11-16):
      `spec.poolRef` optional beside `spec.poolSelector` (banlieue's `LabelSelector`, `{}` for
      every pool in the namespace), exactly one by CEL on the sandbox as on the claim;
      `status.poolRef` and the `Pool` column show the pool bound from; `POST /v1/claims`
      takes `pool_ref` or `pool_selector` and refuses neither-or-both with `400 invalid_pool`;
      `mediatore sandbox create` takes `--pool` or `--pool-selector key=value`, and with
      neither sends the empty selector. Lands with the `banlieue-api` tag that carries
      banlieue ADR-0132
- [x] [ADR-0045](../../docs/adr/0045-a-sandbox-workloads-output-streamed-to-its-owner.md) (2026-11-17):
      `spec.workload.logs`, the requester's opt-in to output capture (one optional boolean,
      default false, rendered by `make crds`); `POST /v1/me/logs` from the claim's node
      (`400` for a malformed batch or a claim that did not opt in, `413`, `429` with
      `Retry-After: 1`, `501` with `logs.enabled` off, a late batch `204`); the `LogStore`
      trait required by `ClaimStore`, the memory ring and the Secret ring
      (`mediatore-logs-<claim uid>-<segment>`, 64 KiB segments, `logs.max_bytes`, owner
      reference to the sandbox, swept `logs.retention_secs` after the claim at resync and
      with the audit sweep); `GET /v1/claims/{name}/logs` as NDJSON (`follow`, `since`,
      `tail`) under the claim's subject and namespace checks, one audit line per read and
      never the content; `--logs` on `sandbox create`, `mediatore sandbox logs`; a create
      with `logs: true` on a broker with logs off is `501`, a declarative one `Failed` at
      reconcile. The guest side is roadmap 06's item. Not yet run live
- [x] [ADR-0047](../../docs/adr/0047-a-sandbox-chooses-its-member-by-strategy.md) (2026-11-18):
      `spec.selection.strategy` (`LongestReady`, `MostAvailable`, `Spread`; banlieue ADR-0135),
      optional, banlieue's own type, copied verbatim to the claim, absent kept absent;
      `selection` on `POST /v1/claims` (an unknown value is a parse error, `422`),
      `--strategy` on `sandbox create`; the CRD re-rendered; the kind sandbox tier gains the
      `Spread` sandbox and the refused `Pack`. Lands with `banlieue-api` v0.5.10. The outcome
      is on the claim's `Bound` condition, not mirrored. Not yet run live
- [x] [ADR-0048](../../docs/adr/0048-agentsandbox-served-as-v1beta1.md) (2026-11-18):
      `mediatore.io/v1beta1`, the one served and stored version; the schema unchanged;
      `v1alpha1` not served (a manifest naming it is refused by the API server); the admission
      policy matches `v1beta1`; owner references from the type; the kind tiers' manifests and
      the guides moved. Not yet applied live. Decision 1 and the cut-over amended by ADR-0049
- [x] [ADR-0049](../../docs/adr/0049-agentsandbox-served-as-v1alpha1-and-v1beta1.md) (2026-11-18):
      `v1alpha1` served again beside `v1beta1`, deprecated with a warning naming `v1beta1`,
      a copy of the one type's version made at render time (`sandbox::crd()`), conversion
      `None`, `v1beta1` stored; the admission policy names both versions, kept equal to the
      served ones by a unit test; the cut-over is a plain apply. The kind sandbox tier creates
      a `v1alpha1` sandbox (policy, warning, read as `v1beta1`, claim owned through `v1beta1`,
      spec frozen). Not yet applied live
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
- [x] `POST /v1/claims` creates an `AgentSandbox` in `sandboxes.namespace` (since ADR-0046,
      with `sandboxes.namespaces` set, in the namespace `ClaimRequest.namespace` names and
      the caller's groups admit); `GET` answers
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
