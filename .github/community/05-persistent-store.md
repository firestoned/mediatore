<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 05: Persistent store

**Status: not started.** Claims, nodes and revocations that survive a broker restart;
deletes threat-model accepted risk **R-5**.
Under [ADR-0008](../../docs/adr/0008-agentsandbox-crd-owned-by-mediatore.md) the non-secret
request fields (subject, pool, TTL, audiences, workload) live on the `AgentSandbox` resource
instead (roadmap 08); the store keeps refresh ciphertext, revocations, node records and audit
rows.

- [ ] sqlx behind the existing `ClaimStore` trait: PostgreSQL (work) and SQLite
      (homelab) — both are configuration, not code paths (runbook 4b.7)
- [ ] Refresh material encrypted before it reaches the store: OpenBao transit at work,
      `age`-encrypted key file at home; the broker never holds the wrapping key
- [ ] Row TTL sweeper (delete 1 h after claim expiry); audit rows survive per
      runbook 9.3
- [ ] Restart-recovery test: revoke, restart, `/v1/token` still refuses; bind,
      restart, entry not duplicated (idempotency already in `Reconciler::bind`)
- [ ] Migrations checked in; `make check` runs the suite against SQLite in memory
