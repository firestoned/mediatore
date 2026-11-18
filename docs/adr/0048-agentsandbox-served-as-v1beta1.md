<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0048: AgentSandbox is served as v1beta1

**Status:** Accepted and implemented 2026-11-18 (proposed the same day; `mediatore.io/v1beta1` the one served and stored version, `v1alpha1` no longer served) · **Date:** 2026-11-18

Roadmap 08 (the `AgentSandbox` CRD). Amends
[ADR-0008](0008-agentsandbox-crd-owned-by-mediatore.md) decision 1 (the group and version).

## Context

`AgentSandbox` has been `mediatore.io/v1alpha1` since ADR-0008 (2026-10-12). Since then its
spec grew by addition alone: `policyRef` (ADR-0026), `workload.restart` (ADR-0033),
`poolSelector` beside an optional `poolRef` (ADR-0044), `workload.logs` (ADR-0045),
`selection` (ADR-0047); its status by `poolRef`, `record` and the fields ADR-0034 keeps on
the resource. It has been reconciled live on the core cluster since 2026-10-31, through the
v0.2.x releases and v0.3.0, with every change kept wire compatible for the manifests already
written. `v1alpha1` says "this may change incompatibly without notice", which stopped being
how the type is treated some releases ago. Erick's decision, 2026-11-18, after ADR-0047 added
one more optional field: the version should say what the type is, a beta API whose fields are
added and never taken away.

A Kubernetes CRD version is a name on a schema. Two things make a rename more than a name:
the API server keeps `status.storedVersions` and refuses a CRD change that drops a version
still listed there, and every client that speaks the old version (a manifest, a
`ValidatingAdmissionPolicy`'s match rule, an owner reference) stops matching.

## Decision

1. **`mediatore.io/v1beta1` is the one version served and stored.** The Rust type is the
   same; the derive's version changes, the CRD is re-rendered (`make crds`), and the schema is
   byte for byte the `v1alpha1` one under the new name. `v1alpha1` is not served beside it:
   a manifest that still names it is refused by the API server (`no matches for kind
   "AgentSandbox" in version "mediatore.io/v1alpha1"`), which is the loud failure wanted,
   never a silent read under another version.

2. **No conversion, because nothing long-lived exists to convert.** An `AgentSandbox` lives
   its claim's TTL and is swept `store.retention_secs` after the claim ends (ADR-0034); it is
   a request, not a record of lasting state. A cluster upgrading therefore cuts over with no
   object of the old version left, rather than carrying a conversion webhook for objects that
   expire within hours. The procedure is in the consequences.

3. **Everything that names the version moves with it.** The admission policy
   (`deploy/base/admission/agentsandbox-subject.yaml`) matches `v1beta1` exactly, as it
   matched `v1alpha1` exactly: a resource of a version the policy does not name would be
   ungoverned, so the match is never widened to `*`. The owner reference a claim and a
   log segment carry (`kubestore.rs`, `sandbox.rs`) is taken from the type
   (`AgentSandbox::api_version`), so it cannot drift from the derive again. The kind tiers'
   manifests, the guides and CALM say `v1beta1`.

4. **The promise of beta.** From `v1beta1` on, a field is added optional with a default that
   means "as before", and no field is removed or renamed within the version. A change that
   cannot keep that promise is a new version served beside this one, with conversion, under
   its own ADR. The HTTP API (`/v1/claims`, ADR-0008 decision 4) has its own versioning and is
   unchanged by this ADR.

5. **`SandboxNode` and `PolicyFloor` stay `v1alpha1`.** They are the broker's store
   (ADR-0034), written and read by the broker alone, not an API anyone else writes; their
   version is a statement about the store's schema, which ADR-0034 owns.

## Consequences

- **Not wire compatible for declarative requesters.** A manifest, a GitOps repository or a
  CI job that writes `apiVersion: mediatore.io/v1alpha1` must say `v1beta1`. The fields are
  unchanged. A request through `POST /v1/claims` sees no difference.
- **The CRD and the broker move together.** A broker of this version serves and watches
  `v1beta1` only; applied against the old CRD it finds no such version and reconciles nothing,
  loudly in its log. The CRD goes first, the broker right after, in one release.
- **The cut-over on a cluster that has the old CRD.** The API server refuses to apply the new
  CRD while `status.storedVersions` lists `v1alpha1`, so the order is: let every
  `AgentSandbox` end and be swept, or delete the remaining ones (the finalizer retracts their
  entries and claims); check `kubectl get agentsandboxes -A` is empty; then either delete the
  CRD (`kubectl delete crd agentsandboxes.mediatore.io`, nothing is lost since no object
  exists) and apply the base, or patch the status
  (`kubectl patch crd agentsandboxes.mediatore.io --subresource=status --type=merge -p
  '{"status":{"storedVersions":["v1beta1"]}}'` after applying a CRD that serves both for the
  patch, which this release does not ship). The core cluster had no `AgentSandbox` on
  2026-11-18, so the cut-over there is the delete-and-apply form.
- **The kind tiers prove it.** `make kind-e2e-sandbox`, `kind-e2e-policy`, `kind-e2e-gateway`
  and the Dex tier create `v1beta1` resources against the real API server with the policy
  matching that version.
- **Not done here.** No version is served beside `v1beta1`; the first change that needs one
  writes the conversion ADR. `v1` waits for the type to be judged complete, not for time.
