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
| 03 | Claim watcher against banlieue | 🔶 in progress | [03-claim-watcher.md](.github/community/03-claim-watcher.md) |
| 04 | Token backends live (OBO + Dex/STS) | 🔶 in progress | [04-token-backends-live.md](.github/community/04-token-backends-live.md) |
| 05 | Persistent store (sqlx, ADR-0012) | ✅ done | [05-persistent-store.md](.github/community/05-persistent-store.md) |
| 06 | Guest completion + hardening | 🔶 in progress | [06-guest-hardening.md](.github/community/06-guest-hardening.md) |
| 07 | Credential-injecting egress proxy | 🔶 in progress | [07-egress-proxy.md](.github/community/07-egress-proxy.md) |
| 08 | AgentSandbox CRD and reconciler (ADR-0008) | ✅ done | [08-agentsandbox-crd.md](.github/community/08-agentsandbox-crd.md) |
| 09 | notaio bundles, verified in shadow (ADR-0026) | 🔶 in progress | [09-notaio-bundles-in-shadow.md](.github/community/09-notaio-bundles-in-shadow.md) |

Statuses: ✅ done · 🔶 in progress · ⛔ not started · 📄 reference doc.
ADRs are separate and live in [`docs/adr/`](docs/adr/).
