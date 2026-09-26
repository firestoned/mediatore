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
| 01 | [01-spiffe-mtls-and-entries.md](01-spiffe-mtls-and-entries.md) | Real peer identity and real registration entries |
| 02 | [02-spire-on-the-cluster.md](02-spire-on-the-cluster.md) | A SPIRE server VMs can attest to (runbook Parts 1–3) |
| 03 | [03-claim-watcher.md](03-claim-watcher.md) | Watch real `VirtualMachineClaim`s; bind on Bound |
| 04 | [04-token-backends-live.md](04-token-backends-live.md) | Entra OBO at work, Dex-refreshed STS at home |
| 05 | [05-persistent-store.md](05-persistent-store.md) | Claims and nodes that survive a broker restart |
| 06 | [06-guest-hardening.md](06-guest-hardening.md) | Rootfs unpack, network policy, seccomp, live-VM proof |
| 07 | [07-egress-proxy.md](07-egress-proxy.md) | Phase 2: tokens the workload never sees |

Dependency shape: 01 unblocks 02 (the agents need something to present SVIDs
to) and 03–05 build on both; 06 needs 02; 07 is design-only until 04 exists.
