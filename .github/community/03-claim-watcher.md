<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 03: Claim watcher against banlieue

**Status: in progress.** The watcher itself was done on 2026-11-07; ADR-0049's `x509pop`
node entries and registration were built on 2026-11-27 (the last section) and one item of
theirs is open: a booted guest on a real host. Replace the dev binder with the real thing: watch
`VirtualMachineClaim`, bind on Bound, release on Releasing/Failed/deletion.
Decisions: [ADR-0011](../../docs/adr/0011-claim-watcher.md) (2026-10-13).

- [x] `banlieue-api` pinned in `[workspace.dependencies]` by commit (banlieue PR #98,
      2026-10-13: the crate on kube's `derive` feature only, so `ring` stays out of this
      graph; re-pin to the merge commit, then to a tag when banlieue cuts one; the pin is
      the `v0.5.9` tag since ADR-0044). Schema drift is a compile error (ADR-0002)
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
- [x] `POST /v1/claims` creating the resource: done in roadmap 08 (2026-10-14), where the
      resource is an `AgentSandbox` (ADR-0008 decision 4) and the reconciler creates the
      claim and the record
- [x] banlieue side: revise ADR-0049 (SPIRE attestation supersedes quote-over-nonce;
      retire `status.nonce`): tracked here, done in banlieue #142 (v0.4.14, 2026-11-07);
      the controller no longer mints the nonce and the field is deprecated, never set.
      mediatore never read it; the pin moved to the v0.4.14 tag in the same change (and
      to v0.5.9 with ADR-0044)
- [x] Threat model pass (2026-10-13): TB-2 gains five rows, TB-4 one; stamp to ADR-0011

## ADR-0049: `x509pop` node entries and registration (2026-11-27)

A guest without a vTPM attests with SPIRE's `x509pop` attestor, with a certificate its host
signs for the guest's own key
([ADR-0049](../../docs/adr/0049-a-guest-without-a-vtpm-attests-with-x509pop-and-a-certificate-its-host-signs.md)).
The guest's helper (`mediatore node-cert`, #168) was released in v0.4.0; decisions 8 to 11,
which are ADR-0050's decision 6 taken into ADR-0049, were built on 2026-11-27.

- [x] The node identity of either kind in one place: `NodeAttestation`, `node_key` and
      `agent_id_for`, shared by the watcher and the broker, and `NodeIdentity`, which every
      entry manager validates before it parents a claim's entry
      (`crates/mediatore-spire/src/x509pop.rs`)
- [x] Registration (decision 8): `POST /v1/nodes` carries the attestation, tagged by kind;
      absent means `tpm`, so a guest up to v0.4.0 registers unchanged; an unknown kind or
      field is `400 invalid_attestation`; names that do not hash to the peer's node ID are
      `403` (`register_node`, `crates/mediatore-api/src/lib.rs`; e2e in
      `crates/mediatore/tests/e2e_dev.rs` and `e2e_mtls.rs`)
- [x] Which pools (decision 9): `watcher.x509pop_pools`, a list of `<namespace>/<pool>`. A
      machine of a listed pool gets an `x509pop` node entry from its `attestationSubject`
      and never a TPM one; with anything missing or refused it gets none, its claim is
      failed with the reason, and it never falls back to its EK
      (`crates/mediatore-claims/src/watch.rs`, one test per cause)
- [x] The host CA (decision 10): read inline from the machine's `Provider`, in its own
      namespace or in `watcher.provider_namespace` when that namespace holds none, from one
      listing of every namespace per pass (two Providers asserting different CAs under one
      name are refused both); a `configMapRef` or `secretRef` is refused; the ClusterRole
      gains `list` on `providers` and nothing else (`deploy/base/rbac.yaml`)
- [x] The entries admission policy admits the second parent shape (decision 11,
      `deploy/base/admission/clusterstaticentry-mediatore.yaml`); it cannot hold an
      `x509pop` node entry's key to its parent, which is threat model R-71
- [x] Node and node-entry collection by node key of either kind
      (`crates/mediatore-claims/src/nodegc.rs`)
- [x] The guest: `--node-attestation tpm|x509pop`, the names read from the leaf
      `node-cert` wrote (`crates/mediatore-guest/src/guest.rs`, `identity.rs`); the pool
      layer `image/cloud-config-deployment-x509pop.example.yaml`
- [x] The server: `deploy/spire-x509pop`, a kustomize component beside `deploy/spire-tpm`
- [x] Fix round (2026-11-27): the Providers listed in every namespace once per pass
      (`ProviderPass`), and two that assert different certificates under one common name
      give neither's machines an entry; with the pool list set, every `Bound` claim resolved
      through its `status.virtualMachineRef` machine; a pass collects no x509pop node or
      entry (`hold_x509pop`, `nodegc.rs`) while a listed machine's Provider is not found,
      whatever the machine's age (`MachineNode::NoProvider`), or while a listed machine with
      no subject or placement yet is younger than the node grace, `store.node_grace_secs`
      since its creation (`Watcher::is_young`, `watch.rs`); an older one holds nothing, so
      the hold that is left without a bound is a machine placed on a Provider that does not
      exist; the
      first record under a node key stands, another agent ID being `409
      node_identity_conflict` (`NodeRecord::registration_conflict`,
      `crates/mediatore-store/src/lib.rs`); the guest reads its certificate's names again
      before every registration attempt; `mediatore x509pop-bundle check <file>...` for the
      server's bundle files (`check_x509pop_bundle`, `crates/mediatore/src/main.rs`), run
      by the operator and the kind tier and enforced on no server
- [x] Decision 12: the egress proxy installs the address-family filter (unix and inet
      only) before anything else and proves it (`seccomp::restrict_families`,
      `crates/mediatore-guest/src/seccomp.rs`, called first in `egress::run`)
- [x] Proven on the build host (2026-11-27, after the fix round and the bound on the
      hold): `make check` green, and after `make kind-delete`,
      `make kind-e2e-ci KIND_E2E_SUITES="kind-e2e-tpm kind-e2e-x509pop kind-e2e-gateway"`
      exit 0: `make kind-e2e-tpm` PASS (the TPM path this touches, attested as
      `spiffe://sandbox.test/spire/agent/tpm/635102b3e8d66a197f56b6f96a19ac15460e6c60e090619b0eb3aef74014e3fe`
      on the merged tree, where `make check` passed 1439 tests and `make kind-e2e-sandbox` passed too),
      the new `make kind-e2e-x509pop` PASS (a real SPIRE server and agent under
      `spiffe://sandbox.test/spire/agent/x509pop/kind-host/<machine uid>`, the watcher's
      entry, the real guest registering with `--node-attestation x509pop`, a claim bound
      with its entry parented to that agent, the bundle check passing the server's ConfigMap
      and refusing two bundles it must refuse) and `make kind-e2e-gateway` PASS (the
      admission dry runs for the new parent shape on a real API server, and every proxy's
      family filter line). In the x509pop tier the leaf is made with `openssl`, since a pod
      has no vsock
- [x] Threat model pass (2026-11-27): TB-19 new (the guest to its host's signer), A-34 to
      A-38, R-71 to R-77; TB-2, TB-3, TB-4, TB-6 and TB-9 extended; stamp bumped
- [ ] A guest booted on a Cloud Hypervisor or Firecracker host from the `x509pop` layer:
      the certificate fetched from banlieue's real signer over vsock, the agent attested,
      the node registered and a claim bound, end to end through the broker. Not proven
      anywhere yet (the helper against the real signer was proven on its own, #168)
