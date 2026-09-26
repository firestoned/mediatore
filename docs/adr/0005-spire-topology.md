<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0005: SPIRE runs on a dedicated identity tier, nested per environment

**Status:** Accepted · **Date:** 2026-09-26

## Context

The SPIRE server is the root of workload identity: whoever controls it can mint an SVID
for any node or claim in the trust domain. Running it inside the workload/management
cluster puts that power inside the blast radius of ordinary cluster administration —
anyone who can exec into pods in that cluster can reach the signing key. Enterprises
treat comparable systems (PKI, AD) as their own tier, owned by an identity/security
team with separate change control.

SPIRE supports this natively: a **root server** issues intermediate CAs to
**downstream (nested) servers**, one per environment or cluster; agents and workloads
only ever talk to their downstream server, and everything chains to one trust domain.
Federation (bundle exchange between trust domains) is a different tool, for genuinely
separate organisations — not needed here.

Two couplings constrain the design:

1. VMs reach a SPIRE server on TCP 8081 and mediatore reaches the entry API over gRPC —
   both are plain endpoints, so nothing in mediatore requires colocation.
2. mediatore's own SVID comes from the `k8s_psat` node attestor, so the server that
   issues it must be able to validate ServiceAccount tokens from mediatore's cluster.
   That naturally places a downstream server in (or scoped to) the management cluster.

## Decision

**Desired (enterprise) state:**

- A **root SPIRE server** runs on a dedicated identity cluster (`auth.example.com`
  style), HA, PostgreSQL-backed, its CA keyed through an `UpstreamAuthority` plugin
  against an HSM / KMS / corporate PKI. It issues intermediate CAs only; no agent or
  workload talks to it directly.
- A **downstream SPIRE server per environment** (one for the sandbox management
  cluster) holds the TPM attestor, the EK trust bundle and the `k8s_psat` config for
  its own cluster. mediatore's `admin_ids` entry-management rights are granted on the
  downstream server only, so a compromised broker can forge entries in its own tier,
  never org-wide.
- One trust domain across the whole tree; no federation.

**Homelab collapse:** a single SPIRE server on the banlieue management cluster
plays the downstream role, with root, nesting and HSM elided. Everything mediatore-facing is identical: an endpoint for
attestation, an endpoint for entries.

**mediatore consequence:** the SPIRE server address is configuration
(`spire.endpoint`), never assumed in-cluster; the entry manager must work against a
remote server. The threat model records the collapsed homelab posture explicitly.

## Consequences

- Compromise containment: the root key never lives where sandboxes are administered;
  the downstream server's intermediate is revocable/rotatable from above.
- Operational cost: a second cluster and an upstream-authority integration exist
  before production; the homelab deliberately defers both.
- The runbook's Part 1 (single in-cluster server) is the homelab collapse of this
  topology, not the target.
- Threat-model R-4 (broker as single trust point) gains its planned mitigation home:
  HSM-backed keys live at the root, per this topology.
