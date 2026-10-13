<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 03: Claim watcher against banlieue

**Status: in progress.** Replace the dev binder with the real thing: watch
`VirtualMachineClaim`, bind on Bound, release on Releasing/Failed/deletion.
Decisions: [ADR-0011](../../docs/adr/0011-claim-watcher.md) (2026-10-13).

- [x] `banlieue-api` pinned in `[workspace.dependencies]` by commit (banlieue PR #98,
      2026-10-13: the crate on kube's `derive` feature only, so `ring` stays out of this
      graph; re-pin to the merge commit, then to a tag when banlieue cuts one). Schema
      drift is a compile error (ADR-0002)
- [x] kube-runtime `Controller` on `VirtualMachineClaim` (managed-by label) driving
      `Reconciler::{bind,release}` (`crates/mediatore-claims/src/watch.rs`); the claim
      UID is the object's `metadata.uid`
- [x] Node resolution: by the EK hash of `status.tpmEndorsementCertificates`, which
      banlieue mirrors onto the claim, against the node that registered it; the
      providerID / DMI route was dropped (the `VirtualMachine` publishes neither, ADR-0011).
      Unresolved: requeue every 5 s, fail after `watcher.resolve_timeout_secs` (60) by
      revoking the record and deleting the claim, never guess
- [x] EK cross-check: by construction, the mirrored certificate is the only input
- [x] Node entry trigger: a `Controller` on `VirtualMachine` (`banlieue.io/pool` label)
      declares `ensure_node_entry` from a published certificate; no certificate, no
      entry. The orphan sweep and the release of records whose claim is gone run on the
      leader at `watcher.resync_secs` (300)
- [x] Leader election: `coordination.k8s.io` Lease `mediatore-watcher` in the broker's
      namespace (`crates/mediatore-claims/src/lease.rs`; namespaced Role in
      `deploy/base/rbac.yaml`); the user API stays stateless on every replica
- [x] kind tier: `make kind-e2e-watcher` installs banlieue's CRDs rendered from the pin
      (`mediatore-testkit`'s `banlieue-crds`), then proves the Lease, the node-entry
      trigger through the admission policy, a member without a certificate getting
      nothing, and a labelled claim without a record binding nothing
- [ ] `POST /v1/claims` creating the resource: moved to roadmap 08, where the resource is
      an `AgentSandbox` (ADR-0008 decision 4); building it against `VirtualMachineClaim`
      first would be built twice
- [ ] banlieue side: revise ADR-0049 (SPIRE attestation supersedes quote-over-nonce;
      retire `status.nonce`) — tracked here, implemented in the banlieue repo
- [x] Threat model pass (2026-10-13): TB-2 gains five rows, TB-4 one; stamp to ADR-0011
