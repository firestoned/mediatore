<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Roadmap detail docs

Reading order matches the numeric prefix: contiguous from `00`, two digits,
lowercase-hyphen names, renumbered as a whole run when one is inserted or
retired (fix every `roadmap NN` reference in the same commit). The status
board is [`ROADMAPS.md`](../../ROADMAPS.md) at the repo root.

| # | Doc | One line |
| --- | --- | --- |
| 00 | [00-dev-mode-loop.md](00-dev-mode-loop.md) | The loop, end to end, with every network edge faked and fail-closed |
| 01 | [01-spiffe-mtls-and-entries.md](01-spiffe-mtls-and-entries.md) | Real peer identity (SPIFFE mTLS) and entries as `ClusterStaticEntry`, no gRPC |
| 02 | [02-spire-on-the-cluster.md](02-spire-on-the-cluster.md) | A SPIRE server VMs can attest to (the broker on the cluster first, then TPM attestation) |
| 03 | [03-claim-watcher.md](03-claim-watcher.md) | Watch real `VirtualMachineClaim`s; bind on Bound |
| 04 | [04-token-backends-live.md](04-token-backends-live.md) | Entra OBO at work, Dex-refreshed STS at home |
| 05 | [05-persistent-store.md](05-persistent-store.md) | Claims and nodes that survive a broker restart |
| 06 | [06-guest-hardening.md](06-guest-hardening.md) | Rootfs unpack, network policy, Landlock, live-VM proof |
| 07 | [07-egress-proxy.md](07-egress-proxy.md) | Phase 2: tokens the workload never sees |
| 08 | [08-agentsandbox-crd.md](08-agentsandbox-crd.md) | `AgentSandbox` as mediatore's CRD; the declarative way to ask for a sandbox |
| 09 | [09-notaio-bundles-in-shadow.md](09-notaio-bundles-in-shadow.md) | notaio's signed policy bundles, verified and compared with each sandbox, enforcing nothing yet |
| 10 | [10-egress-gateway.md](10-egress-gateway.md) | Envoy gateway on banlieue's proxy VMs, authorizing each tunnel by claim SPIFFE ID |
| 11 | [11-policy-egress-at-the-gateway.md](11-policy-egress-at-the-gateway.md) | A verified bundle's direct egress served at the gateway, behind `policy.egress` |
| 12 | [12-claude-end-to-end.md](12-claude-end-to-end.md) | Every configuration the path to the Anthropic API depends on: Dex, SPIRE, notaio, the policies, the broker, the gateways |
| 13 | [13-declarative-agentsandbox-credentials.md](13-declarative-agentsandbox-credentials.md) | How a resource a requester applies can carry a person's own credential without it sitting in the cluster in the clear: four options, a recommendation, the questions. Design only |
| 14 | [14-secret-expiry-at-the-ttl.md](14-secret-expiry-at-the-ttl.md) | A stored secret removed right on its TTL, not up to a poll interval after: the envelope stays in Kubernetes, five ways to drive its deletion, a spike to choose. Spike only |
| 15 | [15-observability.md](15-observability.md) | OTLP traces and metrics for every component under sixteen invariants: no secret in a signal, no new listener or route, push only over SVID mutual TLS, off by default, never on the request path |

Dependency shape: 01 unblocks 02 (the agents need something to present SVIDs
to) and 03–05 build on both; 06 needs 02; 07 builds on 04; 08 builds on 03 and narrows 05; 09 builds on 05 and 08; 10 needs 02 and 06's image work, and 07 builds on 10; 15 needs 01, 05 and 10.
