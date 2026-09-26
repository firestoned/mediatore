<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 03: Claim watcher against banlieue

**Status: not started.** Replace the dev binder with the real thing: watch
`VirtualMachineClaim`, bind on Bound, release on Releasing/Failed/deletion.

- [ ] banlieue publishes a tag; pin `banlieue-api` in `[workspace.dependencies]`
      (schema drift becomes a compile error, ADR-0002)
- [ ] kube-rs watcher on `VirtualMachineClaim` driving `Reconciler::{bind,release}`
      (the state machine and `next_action()` already exist and are tested)
- [ ] Node resolution per runbook 7.4: `providerID` → DMI UUID (both byte orders on
      vSphere) → registered node; requeue up to 60 s then fail the claim, never guess
- [ ] EK cross-check against `status.tpmEndorsementCertificates` (ADR-0045) when present
- [ ] `POST /v1/claims` switches from dev-store-only to creating the CR; leader
      election for the watcher (API stays stateless)
- [ ] banlieue side: revise ADR-0049 (SPIRE attestation supersedes quote-over-nonce;
      retire `status.nonce`) — tracked here, implemented in the banlieue repo
- [ ] Threat model pass (TB-2 controls become real)
