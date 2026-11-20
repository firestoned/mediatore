<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 05: Persistent store

**Status: done 2026-11-09** (reopened the same day) for [ADR-0034](../../docs/adr/0034-the-kubernetes-api-as-the-brokers-store.md),
the Kubernetes API as the store (the `AgentSandbox` status as the record, a Secret per
sandbox for the sealed session, `SandboxNode` and `PolicyFloor` resources, the finalizer as
the retention window, no database and no SQLite in the binary); the items are at the end.
Reopened 2026-11-19 for ADR-0057 (the record written by compare-and-set and bound to its
sandbox: built, its items and what is left at the end).
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
- [x] The store guide rewritten, the deploying guide, README, the threat model (TB-9 as the
      API server, etcd at rest; full pass) (PR #97)
- [x] The homelab cutover: drain, upgrade, recycle; the one-shot live run (ADR-0033); then
      v0.2.0 (2026-11-09: v0.2.0 cut, the broker on the Kubernetes store, the pool on the
      v0.2.0 image, `sandbox-57d995da` run once and released by its exit; the sandbox
      Service's `externalTrafficPolicy: Local` the one lesson, PR #99; `docs/guides/testing.md`
      runs 6 and 7)

## ADR-0039: a node leaves the register when its VM is gone (2026-11-15)

- [x] Finding F-36: `SandboxNode` objects were never deleted (25 records for 3 VMs after five
      hours of pool churn); ADR-0039 accepted; CALM (`rel-watcher-node-gc`); `delete_node` in
      the store contract and both backends; `nodegc::nodes_to_delete` and
      `Watcher::collect_nodes` on the resync ticker; `store.node_grace_secs`; threat model full
      pass (TB-9, A-11, R-26).
- [ ] The live proof: a recycled pool with `kubectl get sandboxnodes` settling at the pool's
      size, on v0.2.5 or later (no RBAC change: the role already has `delete`).

## ADR-0057: a record written by compare-and-set and bound to its sandbox (2026-11-19)

- [x] [ADR-0057](../../docs/adr/0057-a-claims-record-written-by-compare-and-set-and-bound-to-its-sandbox.md)
      accepted and implemented (2026-11-19): `RecordVersion` on every read, `update_claim`
      conditional on it in both stores, `modify_claim` (four attempts) and each caller's second
      decision, the release with no precondition, the status before the Secrets in every write
- [x] `status.record.sandboxUid` and `namespace`, compared on every read; the CRD re-rendered
      in both served versions (apply it before the broker)
- [x] The session envelope bound to its slot (format 2), format 1 still read, a delegation's
      expiry inside the envelope, the transit probe refusing a key that does not bind the slot
- [x] The new cases shared by both stores (`crates/mediatore-store/src/shared_cases.rs`), the
      fake API server refusing a stale resource version
- [x] The store guide (the order of an upgrade, `503 record_busy`) and the threat model: full
      pass, TB-9 and TB-10, R-46 and R-47 new, R-36 corrected
- [x] The reconciler's half of the binding: a sandbox whose record names another sandbox is
      `Failed` (`record_not_own`) and its claim deleted (`refuse_foreign_record`; its test
      passed in the day's second gate run)
- [ ] The two live steps in the kind tiers: a stale resource version refused with `409` as the
      broker's ServiceAccount (`dev/kind/sandbox-e2e.sh`), a session Secret carrying format `2`
      after the first issue (`dev/kind/dex-e2e.sh`); and the conflict count per caller
- [ ] The rest of the conformance suite over `KubeStore` on the fake API server
- [ ] Reading format 1, and a record without `sandboxUid`, removed the release after
- Deferred, not built: decision 8, a MAC over the record (threat model R-46 carries its three
  triggers)
