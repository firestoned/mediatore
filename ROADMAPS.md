<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Roadmaps

High-level status board. One row per roadmap; task-level detail lives in the
linked doc under [`.github/community/`](.github/community/). Update the row in
the same commit that changes a roadmap item's state.

| # | Roadmap | Status | Detail |
| --- | --- | --- | --- |
| 00 | Dev-mode loop | ✅ done | [00-dev-mode-loop.md](.github/community/00-dev-mode-loop.md) |
| 01 | SPIFFE mTLS + SPIRE entries | ✅ done | [01-spiffe-mtls-and-entries.md](.github/community/01-spiffe-mtls-and-entries.md) |
| 02 | SPIRE on the homelab cluster | 🔶 in progress | [02-spire-on-the-cluster.md](.github/community/02-spire-on-the-cluster.md) |
| 03 | Claim watcher against banlieue | ✅ done | [03-claim-watcher.md](.github/community/03-claim-watcher.md) |
| 04 | Token backends live (OBO + Dex/STS) | 🔶 in progress | [04-token-backends-live.md](.github/community/04-token-backends-live.md) |
| 05 | Persistent store (ADR-0012; the Kubernetes API as the store, ADR-0034) | 🔶 in progress (ADR-0039's live proof: a recycled pool with the `SandboxNode` register settling at the pool's size, once a release carries it) | [05-persistent-store.md](.github/community/05-persistent-store.md) |
| 06 | Guest completion + hardening | 🔶 in progress | [06-guest-hardening.md](.github/community/06-guest-hardening.md) |
| 07 | Credential-injecting egress proxy | 🔶 in progress | [07-egress-proxy.md](.github/community/07-egress-proxy.md) |
| 08 | AgentSandbox CRD and reconciler (ADR-0008; ADR-0045's broker and CLI side, 2026-11-17; ADR-0047's `spec.selection` and ADR-0048's `v1beta1`, 2026-11-18) | ✅ done | [08-agentsandbox-crd.md](.github/community/08-agentsandbox-crd.md) |
| 09 | notaio bundles, verified in shadow (ADR-0026) | ✅ done | [09-notaio-bundles-in-shadow.md](.github/community/09-notaio-bundles-in-shadow.md) |
| 10 | Egress gateway (Envoy, SPIFFE identity, ADR-0028) | ✅ done | [10-egress-gateway.md](.github/community/10-egress-gateway.md) |
| 11 | A policy's direct egress at the gateway (ADR-0030) | 🔶 in progress | [11-policy-egress-at-the-gateway.md](.github/community/11-policy-egress-at-the-gateway.md) |
| 12 | The end-to-end flow to the Anthropic API (Dex, SPIRE, notaio, the policies, the broker, the gateways) | 🔶 in progress | [12-claude-end-to-end.md](.github/community/12-claude-end-to-end.md) |
| 13 | Declarative `AgentSandbox` and a person's credential (design; ADR-0043 is its sibling for the registry pull) | ⛔ not started | [13-declarative-agentsandbox-credentials.md](.github/community/13-declarative-agentsandbox-credentials.md) |
| 14 | A stored secret expires right on its TTL (a spike: the envelope stays in Kubernetes, how its deletion is driven) | ⛔ not started | [14-secret-expiry-at-the-ttl.md](.github/community/14-secret-expiry-at-the-ttl.md) |

Statuses: ✅ done · 🔶 in progress · ⛔ not started · 📄 reference doc.
ADRs are separate and live in [`docs/adr/`](docs/adr/).
