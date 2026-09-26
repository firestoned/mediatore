<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0004: SPIFFE identity scheme and sandbox username derivation

**Status:** Accepted · **Date:** 2026-09-26

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
  provider for audit instead (runbook, Provider variants).
