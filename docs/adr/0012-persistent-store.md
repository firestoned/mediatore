<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0012: One sqlx store over SQLite or PostgreSQL, refresh material sealed before it, rows swept into an audit table

**Status:** Accepted · **Date:** 2026-10-14

Roadmap 05. Builds on [ADR-0008](0008-agentsandbox-crd-owned-by-mediatore.md) (the
request fields live on the `AgentSandbox` resource; the store keeps what cannot sit on a
custom resource), [ADR-0011](0011-claim-watcher.md) (the resync loop on the leader, which
runs the sweeper) and [ADR-0003](0003-token-backends.md) (refresh material is stored
encrypted and never returned).

## Context

`crates/mediatore-store` has had one implementation, `MemoryStore`, since ADR-0002. Every
restart of the broker lost the node registry, every revocation and, once roadmap 04 produces
it, every piece of refresh material. The threat model carried that as accepted risk R-5,
narrowed by ADR-0008 (records are rebuilt from the resource) but still real: a revocation
that does not survive a restart is a weak revocation, and a member that has to register
again before its claim can be rebound leaves a `Bound` sandbox not `ready` for as long as
the guest takes to notice.

The deployment has two shapes. At work, PostgreSQL with change control and backups. In
the homelab, one replica and no appetite for a database per component; the roadmap had
always said SQLite there. Both must be configuration, not code paths: a store bug fixed
for one engine and not the other is the kind of drift a two-backend design invites.

Four things had to be decided.

**One implementation or two.** sqlx is typed per engine; two implementations means two
copies of every query and two conformance runs. Its `Any` driver runs one query set on
either engine but supports only the primitive column types, and the DDL still differs.

**What the store may hold in the clear.** The record carries the token backend's refresh
material (Entra OBO refresh tokens, the Dex refresh token). ADR-0003 says ciphertext
only; nothing said what the ciphertext is, what key seals it, or who holds that key.

**What happens to a row after the claim is gone.** A row per claim ever brokered grows
without bound and keeps subjects and node identities around with no reader. Runbook 9.3
asks for an audit trail that survives the row.

**What a restart must guarantee.** Idempotent bind existed (`Reconciler::bind` returns
early on a record with an entry); nothing proved that a revoked claim stays revoked or
that an entry is not declared twice across a restart.

## Decision

**1. One implementation, `SqlStore`, over sqlx's `Any` driver.** The engine is the
`store.url` scheme: `sqlite:` or `postgres:`. Every query is written once, in the subset
both engines run: `TEXT`, `INTEGER` (`BIGINT` on PostgreSQL) and a byte column (`BLOB`,
`BYTEA`); UUIDs as text; timestamps as integer microseconds since the epoch, so range
comparisons are integer comparisons; the structured fields (subject, audiences, workload)
as JSON text. Placeholders are `$1`, `$2`, in ascending order and each used once, which
both engines bind positionally. The DDL differs by column type, so there is one migration
set per engine, embedded in the binary, versioned and checksummed by sqlx, applied at
startup under sqlx's migration lock. A migration that fails stops the process. The
in-memory store stays for `dev_mode` and tests.

**2. No in-memory store outside `dev_mode`.** `store.url` is required there; the process
refuses to start without it, and refuses `sqlite::memory:` (as lossy as `MemoryStore`).
The URL carries a password for PostgreSQL, so it comes from the environment
(`MEDIATORE_STORE_URL`, a Secret in `deploy/base/deployment.yaml`) and overrides the
config file; it is never logged, only its scheme and host. PostgreSQL is reached only
over TLS: outside `dev_mode` the URL must say `sslmode=verify-full`, and the client is
rustls on aws-lc-rs through sqlx's `tls-rustls-aws-lc-rs` feature, so the key exchange
is the same post-quantum-first offer as every other client in the binary (ADR-0007; the
homelab datastore already accepts only X25519MLKEM768). SQLite is for one replica: two
pods with two files are two stores, and the API on one would not see what the watcher
wrote on the other. The SQLite pool runs in WAL mode with a busy timeout; the
`deploy/base` Deployment keeps two replicas and therefore expects PostgreSQL. SQLite is
a documented single-replica variant, not a shipped overlay.

**3. Refresh material is a sealed envelope, typed.** `ClaimRecord::refresh` is
`Option<Sealed>`, not bytes: the key id that sealed it, a 96-bit nonce and the AES-256-GCM
ciphertext. The store cannot be handed plaintext by type. `Sealer::seal(claim_uid, plaintext)`
and `unseal(claim_uid, &Sealed)` bind the envelope to the claim UID as associated data,
so an envelope moved onto another claim's row does not open. The first implementation is
`LocalKeySealer`: a 32-byte key from `store.sealing.key_file` (a Secret volume), named by
the file's SHA-256 prefix, read at startup and held in memory. That is the homelab shape
and it means the broker holds the wrapping key; the work shape, where it does not, is an
OpenBao transit implementation of the same trait, and it lands with roadmap 04, the first
roadmap that has a plaintext to seal (Entra OBO and Dex refresh tokens). Revocation drops
the envelope, as it did the bytes. No key, no sealing: a backend that needs to persist
refresh material without a configured sealer fails that claim, it does not store plaintext.

**4. Rows are swept into an audit table, never dropped.** `ClaimStore::sweep(before)`
deletes every claim row whose claim ended (expired, or revoked without ever binding)
before `before`, and writes one row to `claim_audit` first, in the same transaction: the
UID, name, subject, node, the created, bound-until and revoked timestamps and when it was
swept. The leader calls it at every resync with `now - store.retention_secs` (default one
hour, runbook 9.3). The audit table has no delete path in mediatore; retention there is
the operator's, by SQL. Node rows are not swept: a node that registered is known until
an operator bans or removes it.

**5. Restart recovery is a contract, tested.** The same conformance suite runs over
`MemoryStore` and over `SqlStore` on SQLite in memory in `make check`, and over PostgreSQL
in kind (`make kind-e2e-store`, which also runs the whole live suite with the broker on
PostgreSQL over `verify-full`). It proves: a revoked claim stays revoked and `/v1/token`
refuses it after a reopen; a bound claim's entry is not declared twice after a reopen; a
node that registered is found after a reopen; a sealed envelope opens only for its claim;
a swept claim leaves an audit row and no claim row. R-5 is deleted. The fake is held to
the real thing: any behaviour the SQL store has that `MemoryStore` lacks is added to
`MemoryStore` in the same change (`rules/testing.md`).

**6. The record is still a copy.** ADR-0008 moved the request fields to the resource. The
row keeps a copy of subject, audiences, workload and TTL so that `/v1/me` and `/v1/token`
answer from the store without a Kubernetes round trip on the sandbox path. The resource
is the source of truth: the reconciler writes the row from it and never the other way.

## Consequences

- `crates/mediatore-store` gains `SqlStore` (`src/sql.rs`), the migrations
  (`migrations/sqlite/`, `migrations/postgres/`), the `Sealed` envelope and `Sealer`
  trait with `LocalKeySealer` (`src/seal.rs`), `ClaimStore::sweep`, `::list_audit` and
  `::ping`, and the conformance suite. sqlx 0.9 enters the tree with `runtime-tokio`,
  `tls-rustls-aws-lc-rs`, `sqlite-bundled`, `postgres`, `any` and `migrate`; no macros
  (the migrator is built from `include_str!`), no MySQL, so no `rsa` from this path.
  `cargo deny` stays clean and `ring` stays out.
- `crates/mediatore` gains the `store` section: `url`, `retention_secs`, `max_connections`,
  `sealing.key_file`. `/healthz` on the user listener pings the store, so a broker that
  lost its database is not ready.
- `deploy/base/deployment.yaml` reads `MEDIATORE_STORE_URL` from Secret `mediatore-store`;
  the kind overlay runs PostgreSQL 18 with a TLS certificate the tier generates and the
  broker on `verify-full` against it, so every kind tier runs on the real store.
- The threat model's R-5 is deleted; TB-1 and TB-6 cite the store's revocation and the
  sweep; a new boundary row covers the broker to database leg (credentials in a Secret,
  TLS `verify-full`, no plaintext refresh material at rest).
- Roadmap 04 implements the transit sealer and the first caller of `Sealer`; until then
  `LocalKeySealer` is tested and wired at startup but seals nothing.
- A second migration set is the price of one query set. A query that works on SQLite
  and not PostgreSQL is caught by the kind tier, not by `make check`.
