<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 05: Persistent store

**Status: reopened 2026-11-09** for [ADR-0034](../../docs/adr/0034-the-kubernetes-api-as-the-brokers-store.md),
the Kubernetes API as the store (the `AgentSandbox` status as the record, a Secret per
sandbox for the sealed session, `SandboxNode` and `PolicyFloor` resources, the finalizer as
the retention window, no database and no SQLite in the binary); the items are at the end.
What stands below was done 2026-10-14. Built [ADR-0012](../../docs/adr/0012-persistent-store.md):
claims, nodes and revocations survive a broker restart; threat-model accepted risk **R-5**
deleted. Under [ADR-0008](../../docs/adr/0008-agentsandbox-crd-owned-by-mediatore.md) the
non-secret request fields live on the `AgentSandbox` resource and the row keeps a copy;
the store is where the refresh envelope, revocations, node records and audit rows live.

- [x] sqlx behind the existing `ClaimStore` trait: one query set over the `Any` driver,
      PostgreSQL (work) and SQLite (homelab, one replica) as configuration
      (`store.url`, `MEDIATORE_STORE_URL`), not code paths (`mediatore-store::sql`)
- [x] Refresh material encrypted before it reaches the store: the `Sealed` envelope type
      (key id, nonce, AES-256-GCM with the claim UID as associated data) is the only form
      the record accepts; `LocalKeySealer` over a key file from a Secret
      (`store.sealing.key_file`, `mediatore-store::seal`). The OpenBao transit sealer,
      where the broker never holds the wrapping key, moved to roadmap 04 with the first
      plaintext to seal
- [x] Row TTL sweeper: `ClaimStore::sweep` at every resync, `store.retention_secs` after
      the claim ended (default 1 h); each swept row leaves a `claim_audit` row mediatore
      never deletes (runbook 9.3)
- [x] Restart-recovery tests: revoke, reopen, still revoked; bind, reopen, entry id kept
      (`a_reopened_file_keeps_revocations_nodes_and_entries`); the kind sandbox tier
      restarts the broker on PostgreSQL with a sandbox `Ready` and finds nothing redone
- [x] Migrations checked in (`crates/mediatore-store/migrations/{sqlite,postgres}`),
      embedded in the binary, checksummed, applied at start; `make check` runs the
      conformance suite over `MemoryStore` and SQLite in memory, `make kind-e2e-store`
      over PostgreSQL 18 with `sslmode=verify-full`
- [x] Fail closed: no URL outside `dev_mode` and the broker does not start; PostgreSQL
      without `verify-full` refused; a memory SQLite refused; `/healthz` false when the
      store is unreachable
- [x] User guide: [the store](../../docs/guides/the-store.md)
- [x] Threat model pass (2026-10-14): new boundary TB-9, assets A-10 and A-11, R-5
      deleted, R-4 widened, R-10 new; stamp to ADR-0012

## ADR-0034: the Kubernetes API as the store (2026-11-09)

Why: RUSTSEC-2026-0459 in the C SQLite that `libsqlite3-sys` bundles, unreachable through
sqlx without a waiver or a fork; and a Kubernetes-native broker never needed a second
datastore.

- [x] ADR-0034 accepted (2026-11-09); CALM: the database node and relation gone, the claim
      store described as the API's
- [x] `KubeStore` behind `ClaimStore`: claims on the `AgentSandbox` status with the claim-uid
      and node labels, sessions as Secrets owned by the sandbox, nodes and floors as
      resources; `Conflict` from `resourceVersion` on the floors
- [x] `SandboxNode` and `PolicyFloor` CRDs from `crdgen`, RBAC for them and for Secrets
- [x] Retention by the finalizer, the sweep logging the audit line; `list_audit` and the
      audit table gone
- [x] sqlx, both migration sets, the SQLite file test, `store.url`, the `mediatore-store`
      Secret, `kind-postgres` and `kind-e2e-store` removed; the store proven on a real API
      server by the kind tiers (the mappings unit-tested, the conformance suite over the
      in-memory store)
- [ ] The store guide rewritten, the deploying guide, README, the threat model (TB-9 as the
      API server, etcd at rest; full pass)
- [ ] The homelab cutover: drain, upgrade, recycle; the one-shot live run (ADR-0033); then
      v0.2.0
