<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# The store

mediatore keeps what cannot sit on an `AgentSandbox` resource in a database
([ADR-0012](../adr/0012-persistent-store.md)): the record of each claim it brokered (a
copy of the request fields, the SPIRE entry id, the node, the bind deadline, the
revocation), the registry of attested nodes, sealed refresh material once a token backend
produces some, and an audit row for every claim row that has been swept. One
implementation serves two engines; which one is a URL.

## Choosing an engine

```yaml
store:
  url: sqlite:///var/lib/mediatore/store.db?mode=rwc   # one replica
  # url: postgres://mediatore:...@db.home.example:5432/mediatore?sslmode=verify-full
  retention_secs: 3600
  max_connections: 8
```

`MEDIATORE_STORE_URL` in the environment overrides `url`, which is how the PostgreSQL
password stays in a Secret: `deploy/base/deployment.yaml` reads it from Secret
`mediatore-store`, key `url`, which the operator creates:

```sh
kubectl -n banlieue-system create secret generic mediatore-store \
  --from-literal=url='postgres://mediatore:<password>@db.home.example:5432/mediatore?sslmode=verify-full&sslrootcert=/etc/mediatore-pg/ca.pem'
```

The broker never logs the URL, only its scheme and host.

**PostgreSQL** is for anything with more than one replica, which is what `deploy/base`
ships. Outside `dev_mode` the URL must say `sslmode=verify-full`; the broker refuses to
start otherwise. The client is rustls on aws-lc-rs and offers the post-quantum hybrid
first, as every other client in the binary does, so a server that accepts only
X25519MLKEM768 works. Mount the CA that signed the server's certificate (a ConfigMap is
fine; it is public) and name it with `sslrootcert`.

**SQLite** is for one replica: a file on a volume, WAL mode, a busy timeout. Two pods
with two files are two stores, and the API on one would not see what the watcher wrote
on the other. Set `replicas: 1` in an overlay and give the pod a writable volume for
the file; the base Deployment's root filesystem is read-only. A memory SQLite
(`sqlite::memory:`) is refused outside `dev_mode`: it is as lossy as the in-memory
store.

**Under `dev_mode`** no URL means the in-memory store, as before. Any supported URL is
accepted there too, memory included.

## Migrations

The schema ships inside the binary, one migration set per engine, and is applied at
startup under sqlx's migration lock. Each migration is checksummed; a migration whose
text changed after it ran fails the start, which is the point. There is nothing to run
by hand before upgrading, and no downgrade path: back up before you upgrade.

The database role mediatore connects as needs `SELECT`, `INSERT`, `UPDATE` and `DELETE`
on `claims` and `nodes`, `SELECT` and `INSERT` on `claim_audit`, and DDL for the
migrations. Do not grant `DELETE` on `claim_audit`: mediatore never issues it, and the
grant is what would let a compromised broker erase a trail.

## What survives a restart

Everything in the store. A revoked claim stays revoked and `/v1/token` keeps refusing
it. A bound claim keeps its entry id, so the reconciler declares nothing twice. A node
that registered is still known, so its claim rebinds without the guest registering
again. The `make kind-e2e-sandbox` tier restarts the broker on PostgreSQL with a sandbox
`Ready` and asserts exactly that: still `Ready`, no second record, no second entry.

## Refresh material

A claim row holds refresh material only as a sealed envelope: the id of the key that
sealed it, a fresh nonce, and the AES-256-GCM ciphertext with the claim's UID as
associated data, so an envelope copied onto another claim's row does not open. The
record type has no plaintext field. Revocation drops the envelope.

There are two sealers, and `store.sealing` names exactly one of them.

The local sealer takes its key from a file (the homelab shape, one replica):

```yaml
store:
  sealing:
    key_file: /etc/mediatore-sealing/key
```

The file is 32 raw bytes or 64 hex characters (`openssl rand -hex 32`), mounted from a
Secret. The broker reads it at start, logs the key id (the first 16 hex characters of
the key's SHA-256, never the key), and fails the start on a missing or malformed file.
The wrapping key is in the broker's memory for as long as it runs.

The transit sealer ([ADR-0015](../adr/0015-transit-sealer.md)) leaves the key in
OpenBao (the work shape):

```yaml
store:
  sealing:
    transit:
      url: https://openbao.home.example:8200
      ca_file: /etc/mediatore-openbao/ca.pem   # the CA its certificate chains to
      mount: transit                           # default
      key: mediatore                           # a key created with derived=true
      role: mediatore                          # the Kubernetes auth role
      token_file: /var/run/secrets/openbao/token   # default: the projected token
```

Sealing is `transit/encrypt/<key>` and unsealing `transit/decrypt/<key>`, with the
binding UID as the derivation `context`, so the envelope opens only for its claim exactly
as the local sealer's associated data arranges. The envelope's `key_id` is
`transit:<mount>/<key>`, its ciphertext the `vault:vN:...` string OpenBao returned, so a
key rotated at OpenBao (`bao write -f transit/keys/mediatore/rotate`) keeps old
envelopes readable until the administrator raises `min_decryption_version`; the broker
re-seals every session at its next refresh anyway. The broker logs in at
`auth/kubernetes/login` with the projected ServiceAccount token the base Deployment
mounts (audience `openbao`), keeps the OpenBao token in memory until its lease nears
its end, and exchanges it again at once on a 403. At start it seals and unseals a probe,
so a wrong URL, CA, role, policy, mount or key, or a key created without `derived`,
stops the process. The URL must be `https` outside `dev_mode`. OpenBao being away is
`503 sealer_unavailable` on the request that needed it and revokes nothing. On the
OpenBao side the broker's policy needs `update` on the two paths and nothing else; the
kind fixture (`dev/kind/openbao-setup.sh`) is the reference for the role and the key.

With no `sealing` section nothing can be persisted: a backend that needs to store
refresh material fails that claim rather than store plaintext.

A session issuer ([ADR-0013](../adr/0013-dex-session-delegation.md)) is where envelopes
come from today: the refresh token `POST /v1/claims` receives is sealed with the
`AgentSandbox` UID (the associated data, so the envelope opens only for that sandbox's
record) and parked in `sessions` until the reconciler creates the record and moves it
there; `claims.sandbox_uid` records which UID opens it. Every `POST /v1/token` opens the
envelope, refreshes upstream, and re-seals the rotated token. A session no record ever
took (a refused or deleted sandbox) is removed by the reconciler, and anything older than
an hour is swept at resync. An issuer with a `session` block and no `sealing` section refuses
to start.

An Entra issuer ([ADR-0016](../adr/0016-entra-on-behalf-of.md), [the Entra
path](the-entra-path.md)) fills the same envelope from the other direction: nothing is
delegated by the caller, the bearer is exchanged On-Behalf-Of at claim creation and the
refresh token Entra issues to mediatore is what gets sealed. Every issue refreshes it for
the audience's resource and re-seals what comes back. An issuer with an `entra` block
needs a `sealing` section for the same reason.

## Retention and the audit table

A claim row outlives its claim by `retention_secs` (default one hour). At every resync
the leader sweeps the rows whose claim ended (revoked, or past its deadline) before that
window into `claim_audit`: the UID, name, subject, node, the created, bound-until and
revoked timestamps, and when it was swept. The envelope is not copied. Node rows are
never swept: a node that registered is known until an operator removes it.

mediatore never deletes from `claim_audit`. Retention there is yours, by SQL:

```sql
DELETE FROM claim_audit WHERE swept_at < (EXTRACT(EPOCH FROM now() - INTERVAL '1 year') * 1000000)::bigint;
```

Timestamps are microseconds since the epoch in every table.

## Health

`GET /healthz` on the user listener pings the store and answers `503 store_unavailable`
when it cannot, so a broker that lost its database leaves the Service until it is back.
