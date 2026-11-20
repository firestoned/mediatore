<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0004: SPIFFE identity scheme and sandbox username derivation

**Status:** Implemented · **Date:** 2026-09-26 · **Implemented:** 2026-09-26 (roadmap 00:
`mediatore_spire::Naming`, `mediatore_proto::Subject::sandbox_username`) · **Amended:**
2026-11-03 by [ADR-0028](0028-egress-gateway-envoy-with-spiffe-identity.md) decision 4
(a fifth identity, the egress gateway's `spiffe://<td>/gateway`); 2026-11-09 by
[ADR-0034](0034-the-kubernetes-api-as-the-brokers-store.md) (the node register is a
`SandboxNode` resource, not a table); 2026-11-19 by
[ADR-0053](0053-the-gateways-authorizer-has-an-identity-of-its-own.md) (a sixth
identity, `spiffe://<td>/gateway/authorizer`, so `/gateway` is no longer a leaf)

## Context

Every component in the sandbox trust chain needs a stable, verifiable name, and three of
them (the broker, the in-guest agent, the SPIRE selector) must independently derive the
same Linux username for a subject. Both are one-way doors: the trust domain is baked into
every SVID, and the username scheme is baked into registration entries, `useradd` calls
and nftables rules on running VMs. The runbook's open decisions #1 and #2 required an ADR
before building; the dev-mode loop now implements both, so the decision is recorded here.

Constraints:

- Linux usernames are at most 32 characters, `[a-z_][a-z0-9_-]*`.
- Entra's `sub` is pairwise (per-app) and opaque; its `oid` is the stable subject key.
  Dex with GitHub (`useLoginAsID: true`) puts the stable key in `preferred_username`.
- A username must not collide across issuers even when two issuers know the same login.

## Decision

**Trust domain.** One per environment, org-scoped and stable, never a hostname
(e.g. `sandbox.home.example` in the homelab). It is configuration (`trust_domain`),
not code.

**SPIFFE ID paths**, implemented in `mediatore-spire::Naming`:

| ID | Held by | Created by |
| --- | --- | --- |
| `spiffe://<td>/spire/agent/tpm/<ek-hash>` | the SPIRE agent on the VM | TPM node attestation |
| `spiffe://<td>/banlieue/node/<ek-hash>` | the in-guest agent (root) | broker, on seeing a new tpm agent |
| `spiffe://<td>/banlieue/claim/<claim-uid>` | the jailed workload | broker, on claim Bound |
| `spiffe://<td>/mediatore` | broker pods | ClusterSPIFFEID (k8s PSAT) |

The agent ID is the parent of both workload entries on a node. The `<ek-hash>` is the
SHA-256 of the endorsement public key, computed identically by the SPIRE TPM attestor
plugin and by `mediatore-guest`.

*Amended 2026-11-03 by [ADR-0028](0028-egress-gateway-envoy-with-spiffe-identity.md)
decision 4:* the table gains `spiffe://<td>/gateway`, held by the egress gateway VMs
(exactly that id, nothing under it; `Naming::gateway_id` in
`crates/mediatore-spire/src/lib.rs`), declared by the operator as `ClusterStaticEntry`
objects under each gateway VM's own TPM agent, never by the broker.

*Amended 2026-11-19 by
[ADR-0053](0053-the-gateways-authorizer-has-an-identity-of-its-own.md) decision 1:* the
table gains `spiffe://<td>/gateway/authorizer`, held by `mediatore gateway` as its client
identity to the broker (`Naming::gateway_authorizer_id`, `is_gateway_authorizer`), declared the
same way; the two gateway IDs are each matched exactly and neither predicate accepts the other,
so "nothing under it" now reads "nothing under it but the authorizer's".

**Username derivation**, implemented in `mediatore-proto::Subject::sandbox_username`:
`sb-` followed by the first 12 lowercase hex characters of
`sha256(issuer || "|" || subject.id)`, where `subject.id` is `oid` on Entra and
`preferred_username` (the GitHub login) on Dex. The human-readable name (UPN or login)
goes in GECOS, never in the username. 15 characters total, always a valid username,
issuer-scoped so `octocat` at two issuers yields two users.

## Consequences

- The broker, the guest agent and the SPIRE `unix:user` selector agree by construction:
  all three call the same function in `mediatore-proto`.
- 48 bits of hash suffix makes accidental collision negligible at sandbox scale; a
  malicious collision requires controlling the issuer string, which the VAP issuer
  allowlist prevents.
- Changing the trust domain or the derivation later invalidates every registration entry
  and every provisioned user; both would be a new major version and a drained pool.
- Node SPIFFE IDs carry no provider name; the broker's `nodes` table records the
  provider for audit instead (runbook, Provider variants). (Amended 2026-11-09 by
  ADR-0034: the register is a `SandboxNode` resource, and the provider is its
  `spec.provider`; `crates/mediatore-claims/src/kubestore.rs`.)
