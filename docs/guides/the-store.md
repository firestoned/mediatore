<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# The store

mediatore keeps what it remembers about a claim in the Kubernetes API, and nowhere else
([ADR-0034](../adr/0034-the-kubernetes-api-as-the-brokers-store.md), superseding the
database of [ADR-0012](../adr/0012-persistent-store.md)): the resource is the record.
There is no database to run, no URL to configure and no SQLite in the binary. Under
`dev_mode`, where there is no cluster, an in-memory store stands in and nothing survives
a restart.

## Where each thing lives

| What | Where | Found by |
| --- | --- | --- |
| The claim record: the SPIRE entry id, the bound node, the bind deadline, the revocation, the policy incarnation and bundle version the claim was created under, the guest's report, the workload's exit | `AgentSandbox.status.record`, written by the store alone (the reconciler's mirroring leaves it out of its patches) | the label `mediatore.io/claim-uid` (the claim's UID, the record's key) and `mediatore.io/node` (a digest of the bound node's SPIFFE ID) |
| The sealed session: the delegated refresh token, sealed with the sandbox's UID | Secret `mediatore-session-<sandbox uid>` in the sandboxes' namespace, owned by the `AgentSandbox` so it goes with it; parked by `POST /v1/claims`, claimed by the reconciler when it writes the record, rotated in place at every mint, emptied on revocation | its name; the labels `mediatore.io/sandbox-uid` and `mediatore.io/session` (`parked` or `claimed`) |
| The attested nodes: EK hash, the agent's SPIFFE ID, DMI UUID, hostname, provider, banned | `SandboxNode`, named by the EK hash | its name; the label `mediatore.io/dmi-uuid` for the clone check |
| The version floor of each notaio policy ([ADR-0026](../adr/0026-notaio-bundles-verified-in-shadow.md) decision 5) | `PolicyFloor`, named `<policy namespace>.<policy name>` | its name; moved by compare-and-set on `resourceVersion`, so two replicas cannot move a floor down |

The request fields (subject, audiences, workload, TTL, policy) are the `AgentSandbox`'s
spec, frozen at admission; the record keeps no copy. `kubectl get agentsandboxes
-o yaml` shows a sandbox's whole record; `kubectl get sandboxnodes` and `kubectl get
policyfloors` the other two.

```yaml
store:
  retention_secs: 3600   # how long an ended claim stays on its AgentSandbox
  sealing:               # the sealer for refresh material, below
    key_file: /etc/mediatore-sealing/key
```

## What survives a restart

Everything: it is the cluster's state. A revoked claim stays revoked and `/v1/token`
keeps refusing it. A bound claim keeps its entry id, so the reconciler declares nothing
twice. A node that registered is still known, so its claim rebinds without the guest
registering again. The version floor of each notaio policy stays where it was, so a bundle
older than one already accepted is still refused. The `make kind-e2e-sandbox` tier
restarts the broker with a sandbox `Ready` and asserts exactly that: still `Ready`, no
second record, no second entry. Two replicas need no shared database for any of it; the
watcher Lease stays the one leader election.

Backups are the cluster's: the etcd (or kine) backup that holds every other resource holds
these. An operator who wants the session Secrets encrypted at rest as well enables
encryption at rest on the API server; it is a second layer, since the Secret holds
ciphertext either way (below).

## RBAC

The broker's ServiceAccount patches `agentsandboxes/status` and the resource's labels and
finalizers (as before), has every verb on `sandboxnodes` and `policyfloors` (a
ClusterRole), and `get`, `list`, `create`, `update`, `patch` and `delete` on Secrets in
the sandboxes' namespace alone (a Role): `deploy/base/rbac.yaml`. The broker reads no
Secret elsewhere.

## Refresh material

A claim holds refresh material only as a sealed envelope: the id of the key that sealed
it, a fresh nonce, and the AES-256-GCM ciphertext with the sandbox's UID as associated
data, so an envelope copied onto another sandbox's Secret does not open. The record type
has no plaintext field. Revocation empties the envelope.

There are two sealers, and `store.sealing` names exactly one of them.

The local sealer takes its key from a file (the homelab shape):

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
binding UID as the derivation `context`, so the envelope opens only for its sandbox
exactly as the local sealer's associated data arranges. The envelope's `key_id` is
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
record) and parked in the sandbox's Secret until the reconciler creates the record and
claims it; from then on the Secret is the claim's envelope. (`status.record.policyUid` and
`bundleVersion` beside it hold the notaio policy a sandbox named and the verified bundle
current when its claim was created, [ADR-0026](../adr/0026-notaio-bundles-verified-in-shadow.md)
decision 6; both absent for a sandbox naming none.) Every `POST /v1/token` opens the
envelope, refreshes upstream, and re-seals the rotated token. A session no record ever
claimed (a refused or deleted sandbox) is removed by the reconciler, and a parked one older
than an hour is swept at resync. An issuer with a `session` block and no `sealing` section
refuses to start.

An Entra issuer ([ADR-0016](../adr/0016-entra-on-behalf-of.md), [the Entra
path](the-entra-path.md)) fills the same envelope from the other direction: nothing is
delegated by the caller, the bearer is exchanged On-Behalf-Of at claim creation and the
refresh token Entra issues to mediatore is what gets sealed. Every issue refreshes it for
the audience's resource and re-seals what comes back. An issuer with an `entra` block
needs a `sealing` section for the same reason.

## Retention and the audit

An ended claim (released, expired, failed, deleted by its subject or by the workload's
exit) stays on its `AgentSandbox` for `retention_secs` (default one hour): the
reconciler's finalizer holds the resource with its final status, so `kubectl get
agentsandboxes` shows what ran recently, exit and report included. At every resync the
leader sweeps the sandboxes whose claim ended before that window: one log line per
sandbox with what an audit row used to hold (the claim UID, name, subject, node, the
created, bound-until and revoked timestamps, whether a report and an exit were recorded),
then the resource is deleted if nobody had, and the finalizer released. The envelope is
never logged. The cluster's log pipeline keeps the lines; there is no audit table and
nothing for mediatore to delete from. Nodes are never swept: a node that registered is
known until an operator deletes its `SandboxNode`.

`retention_secs: 0` means an ended claim is swept at the next resync, which is how the
kind tiers run.

## Health

`GET /healthz` on the user listener lists one `AgentSandbox` and answers
`503 store_unavailable` when the API server does not answer, so a broker cut off from the
cluster leaves the Service until it is back.
