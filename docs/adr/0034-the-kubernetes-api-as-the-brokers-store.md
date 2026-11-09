<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0034: The Kubernetes API as the broker's store: the resource is the record, no database

**Status:** Accepted · **Date:** 2026-11-09 (accepted the same day)

Roadmap 05 reopened (the store). Supersedes the engine decisions of
[ADR-0012](0012-persistent-store.md) (one sqlx query set over SQLite or PostgreSQL, the
audit table) and keeps its others: refresh material is sealed before it is stored
([ADR-0013](0013-dex-session-delegation.md), [ADR-0015](0015-transit-sealer.md)), ended
claims outlive their end for a retention window, the leader's resync sweeps. Completes
what [ADR-0008](0008-agentsandbox-crd-owned-by-mediatore.md) began: the request is a
resource, and now so is everything the broker remembers about it. Changes no token, no
SPIFFE ID, no route of either API; changes the storage contract and the deployment
topology (no database).

## Context

ADR-0012 gave the broker a database because the `AgentSandbox` could not hold everything:
the sealed refresh material, the node registry, the policy floors, the audit rows. SQLite
was the one-replica homelab shape, PostgreSQL the shape for more. The homelab has run
SQLite since, on a PVC, and the kind tiers run PostgreSQL.

On 2026-11-09 RustSec published RUSTSEC-2026-0459: the C SQLite that `libsqlite3-sys`
bundles into the static binary discloses uninitialized memory on a database file written by
a less trusted party. No such party writes the broker's file, so the exposure was nil; the
fix was not reachable, since sqlx-sqlite 0.9.0 pins `libsqlite3-sys` below the patched
line, and the only ways through were a waiver or a fork of sqlx. The question that
followed was the better one: why does a Kubernetes-native broker, which already depends on
the API server for its resources, its leader lease and its SPIRE entries, carry a second
datastore with a C library in it?

It need not. Every table of ADR-0012 has a natural home in the API:

| ADR-0012 table | Where it goes |
| --- | --- |
| `claims` | the `AgentSandbox`'s status: the resource is the record |
| the sealed refresh envelope on the row | a Secret per sandbox, owned by the `AgentSandbox` |
| `sessions` (parked until the record exists) | the same Secret, before the record claims it |
| `nodes` | a `SandboxNode` resource per attested node |
| `policy_floors` | a `PolicyFloor` resource per policy |
| `claim_audit` | the ended `AgentSandbox`, held for the retention window, and the broker's log |

## Decision

1. **The `AgentSandbox` is the claim record.** What ADR-0012 kept in the `claims` row and
   the resource did not already mirror moves into `status`: the entry id, the node, the
   policy uid and bundle version, the revocation time, the guest's report, the workload's
   exit. Two labels make the record findable the way the store finds it: the claim's UID
   (banlieue's `VirtualMachineClaim` UID, the key of every record) and the node's EK hash
   while the claim is bound. Reads are gets and label-selected lists; writes are status
   patches, which carry no resourceVersion and compose from any replica. The admission
   policy that freezes `spec` is untouched; `status` is the broker's alone.

2. **The sealed session is a Secret, owned by its sandbox.** `POST /v1/claims` parks the
   delegated session as a Secret named by the sandbox's UID in the broker's namespace,
   with an owner reference to the `AgentSandbox` so it is garbage-collected with it. The
   reconciler claims it when it writes the record (today's `take_session`), and from then on
   the Secret is the claim's refresh envelope, rotated in place at every mint. Revocation
   empties it (ADR-0012's "drop the refresh envelope"). The Secret holds the `Sealed`
   envelope as the row did: key id, nonce, ciphertext, and the subject and issuer beside
   it. etcd holds ciphertext; the sealing key is where it was (the local key or OpenBao
   transit). An operator who wants Secrets encrypted at rest as well enables it on the
   API server; the guide says so and says it is a second layer, not the first.
   (Clarified at implementation, 2026-11-09: an owner reference cannot cross a namespace,
   the API server treats one that does as absent and collects the dependent. The Secret
   carries the reference when the sandboxes live in the broker's namespace, and the
   retention sweep of decision 4 deletes it with the sandbox either way.)

3. **`SandboxNode` and `PolicyFloor`, two CRDs in the broker's namespace.** `SandboxNode`
   is named by the EK hash and holds what `nodes` held: the node's SPIFFE ID, the DMI UUID
   (also a label, for the clone check), hostname, provider, `banned`, the registration
   time. `PolicyFloor` is named `<policy namespace>.<policy name>` and holds the policy's
   incarnation uid, the highest version accepted and its `issuedAt`; the compare-and-set
   that ADR-0026 needs is the resource's own `resourceVersion`: a write decided from a
   floor another replica has since moved is a `409`, which the store reports as `Conflict`
   as it does today. Both are rendered by `crdgen` beside the `AgentSandbox`, both print
   their columns, both are readable with `kubectl`.

4. **Retention is the finalizer; the audit is the resource and the log.** Today a row
   outlives its claim by `store.retention_secs` and is then copied to `claim_audit`. Now the
   reconciler's finalizer holds an ended `AgentSandbox` (released, expired, failed, deleted
   by its subject or by the workload's exit) with its final status for that window, and the
   leader's resync removes the finalizer when the window has passed, logging one line with
   what the audit row held: name, subject, node, the times, the report, the exit. `kubectl
   get agentsandboxes` shows what ran recently; the cluster's log pipeline keeps the rest.
   The audit table and `list_audit` go. A sandbox deleted before it was ever bound is let go
   at once, as its row was.

5. **`dev_mode` keeps the in-memory store; nothing else keeps a database.** `MemoryStore`
   stays for the dev loop and the tests, where no cluster exists. Outside `dev_mode` the
   store is the Kubernetes API and there is nothing to configure: `store.url` and the
   `mediatore-store` Secret go, `store.retention_secs` and `store.sealing` stay. The
   `sqlx` dependency, both migration sets, the SQLite file test and the kind PostgreSQL go
   with them; with `libsqlite3-sys` out of the tree the advisory that prompted this is
   moot, waived nowhere.

6. **The cutover is at a release boundary, with no migration tool.** Claims are ephemeral;
   the node registry refills as members boot (a running member re-registers after the
   pool is recycled once); the floors are relearned from the current bundles, which are
   the highest versions by construction; the audit rows of the release-candidate runs are
   the SQLite file's, kept in the operator's backups. The guide says to drain the pool,
   upgrade, recycle.

## Consequences

- `crates/mediatore-store`: `ClaimStore` unchanged in shape, `sql.rs`, the migrations and
  `sqlite_file.rs` removed, the conformance suite kept for `MemoryStore`; `ClaimAudit` and
  `list_audit` removed. `crates/mediatore-claims`, where the `AgentSandbox` type lives:
  `KubeStore` implementing `ClaimStore` (unit tests pin the mappings record to status,
  envelope to Secret, node and floor to resource; the kind tiers prove it on a real API
  server, since a record needs an `AgentSandbox` to live on), `AgentSandboxStatus` gains
  `record`, `SandboxNode` and `PolicyFloor` beside `AgentSandbox`, `crdgen` renders three files, the
  finalizer's release waits for the retention, the resync sweeps by removing finalizers.
  `deploy/base`: RBAC for the two resources and for Secrets in the namespace; no store
  Secret, no `MEDIATORE_STORE_URL`. The Makefile loses `kind-postgres` and `kind-e2e-store`;
  the kind sandbox tier proves the store. CALM: the database node and its relation go,
  the API server's relation widens. The threat model: TB-9 rewritten (the API server as
  the store: RBAC on Secrets, status writes, etcd at rest), TB-10 (OpenBao transit)
  unchanged, the SQLite rows gone; a full pass.
- Two replicas need no database any more; the watcher lease stays the one leader election.
- Backups are the cluster's: the kine dump already holds every record.
- Rejected: PostgreSQL only (a database the broker depends on, which not every cluster
  has); the waiver (a risk accepted for a dependency we did not need); a fork of sqlx (a
  thing to own for a dependency we did not need); a ConfigMap for the floors (a resource
  per policy reads better and conflicts never cross policies); the audit as a CRD (the
  log is where audit lines go, and the resource is there for the retention window).
