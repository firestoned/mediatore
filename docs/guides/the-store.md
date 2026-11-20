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
| The sealed session: the delegated refresh token, sealed with the sandbox's UID | Secret `mediatore-session-<sandbox uid>` in the broker's own namespace, owned by the `AgentSandbox` when the sandboxes live there too (an owner reference cannot cross a namespace), deleted by the retention sweep otherwise; parked by `POST /v1/claims`, claimed by the reconciler when it writes the record, rotated in place at every mint, deleted on revocation | its name; the labels `mediatore.io/sandbox-uid` and `mediatore.io/session` (`parked` or `claimed`) |
| The attested nodes: EK hash, the agent's SPIFFE ID, DMI UUID, hostname, provider, banned | `SandboxNode` in the broker's namespace, named by the EK hash | its name; the label `mediatore.io/dmi-uuid` for the clone check |
| The workload's output, when the requester opted in with `workload.logs` ([ADR-0045](../adr/0045-a-sandbox-workloads-output-streamed-to-its-owner.md)): the redacted stdout and stderr lines, with their sequence numbers, and the gaps where the guest's queue overflowed | Secrets `mediatore-logs-<claim uid>-<segment>` in the broker's own namespace, 64 KiB of text each, sealed per batch ([ADR-0052](../adr/0052-a-sandbox-workloads-stored-output-sealed-per-batch-with-the-transit-key.md)), owned by the `AgentSandbox` when it lives there too, the oldest deleted beyond `logs.max_bytes`; swept `logs.retention_secs` after the claim ended, or with the claim's audit sweep, or at once when the record is gone | the labels `mediatore.io/logs=segment`, `mediatore.io/claim-uid` and `mediatore.io/sandbox-uid` |
| The version floor of each notaio policy ([ADR-0026](../adr/0026-notaio-bundles-verified-in-shadow.md) decision 5) | `PolicyFloor` in the broker's namespace, named `<policy namespace>.<policy name>` | its name; moved by compare-and-set on `resourceVersion`, so two replicas cannot move a floor down |

The request fields (subject, audiences, workload, TTL, policy) are the `AgentSandbox`'s
spec, frozen at admission; the record keeps no copy. `kubectl get agentsandboxes
-o yaml` shows a sandbox's whole record; `kubectl get sandboxnodes` and `kubectl get
policyfloors` the other two.

```yaml
store:
  retention_secs: 3600   # how long an ended claim stays on its AgentSandbox
  node_grace_secs: 600   # a registered node is never collected before this (ADR-0039)
  sealing:               # the sealer for refresh material, below
    key_file: /etc/mediatore-sealing/key
logs:                    # the workload output ring (ADR-0045), below; off by default
  enabled: true
  max_bytes: 1048576     # the newest output kept per claim; at least 65536, at most 4 MiB
  retention_secs: 3600   # how long after the claim ended it is kept; default: store.retention_secs
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

## Writes of a record

Since [ADR-0057](../adr/0057-a-claims-record-written-by-compare-and-set-and-bound-to-its-sandbox.md)
a write of an existing record is a compare-and-set. The store hands out a record with the
version it was read at (the `AgentSandbox`'s `resourceVersion`), an update is accepted only
if the object is still at that version, and a caller that loses reads again and decides again,
four times at most. A release is the one write with no precondition: it lands over any state,
and anything decided before it and written after it is refused. In every write the status is
written before the Secrets, and an update never creates a Secret, so once a release has
returned no session Secret of the sandbox exists and none can come back.

What an operator sees of it:

- A guest's report or a session refresh that lost four times in a row answers
  `503 record_busy` and writes nothing; the guest sends its report again, and the next
  `POST /v1/token` refreshes again. A refresh that ends this way has rotated the token
  upstream without storing it: whether the issuer still takes the old one is the issuer's
  rotation policy, and where it does not the claim is released like any refused session.
- A report for a claim that was released in the meantime is `404 no_claim`. An exit always
  releases its claim, whether or not its record write landed.
- `status.record` carries `sandboxUid` and `namespace`, written once when the record is
  created. A record that names another object (a status put back by a restore under a new UID,
  a copied manifest) is not read as that sandbox's record: the broker logs it at `warn`.
  This is a consistency check, not a signature: whoever may write a status can
  write the right UID, which is why the status admission policy matters
  (`deploy/base/admission/agentsandbox-status.yaml`).
- Upgrading across this change has an order. Apply the CRD first: an API server on the old
  schema prunes the two new fields from the status. Then stop every broker replica and start
  the new ones, as one step and not as a rolling update: a broker from before the change
  cannot open a session sealed by one after it (the next section), and can leave a Secret the
  claim no longer opens.

## RBAC

The broker's ServiceAccount patches `agentsandboxes/status` and the resource's labels and
finalizers (as before), has every verb on `sandboxnodes` and `policyfloors` (a
ClusterRole), and `get`, `list`, `create`, `update`, `patch` and `delete` on Secrets in
its own namespace alone (a Role): `deploy/base/rbac.yaml`. The broker reads no Secret
elsewhere. The broker's namespace is the client's default, the ServiceAccount's in a
pod, so nothing names it in the configuration. The sandboxes may live anywhere the
controller watches: `sandboxes.namespace` is where `POST /v1/claims` creates them (or, since
v0.3.0, the namespace the request names, one of `sandboxes.namespaces`,
[ADR-0046](../adr/0046-who-may-claim-a-list-of-groups-and-a-namespace-to-groups-mapping.md)),
and a sandbox applied in another namespace gets its record where it is.

## Refresh material

A claim holds refresh material only as a sealed envelope: the id of the key that sealed
it, a fresh nonce, and the AES-256-GCM ciphertext, bound to the sandbox and to its slot.
Since [ADR-0057](../adr/0057-a-claims-record-written-by-compare-and-set-and-bound-to-its-sandbox.md)
the associated data is a label, the sandbox's UID and the slot (the issuer's session, or a
delegated credential with its audience), so an envelope copied onto another sandbox's Secret
does not open, and neither does one sandbox's delegation presented as another audience's or as
the issuer's session. A Secret sealed this way carries the data key `format` with the value
`2`; one sealed before the change has no such key, is bound to the bare UID, and still opens
until its claim ends (the issuer's session is sealed again, as format 2, at the claim's next
issue). A delegation's expiry is sealed inside its envelope and is the one the broker
believes; the copy in clear on the Secret is for the sweep and for `kubectl`. The record type
has no plaintext field. Revocation deletes the envelope's Secret.

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
      auth_mount: kubernetes                   # default; where the Kubernetes auth method is mounted, the login is
                                               # `POST /v1/auth/<auth_mount>/login` (a platform that mounts it per cluster names it)
      token_file: /var/run/secrets/openbao/token   # default: the projected token
```

Sealing is `transit/encrypt/<key>` and unsealing `transit/decrypt/<key>`, with the
same bytes the local sealer uses as associated data (the label, the UID and the slot) as the
derivation `context`, so the envelope opens only for its sandbox and its slot. The envelope's `key_id` is
`transit:<mount>/<key>`, its ciphertext the `vault:vN:...` string OpenBao returned, so a
key rotated at OpenBao (`bao write -f transit/keys/mediatore/rotate`) keeps old
envelopes readable until the administrator raises `min_decryption_version`; the broker
re-seals every session at its next refresh anyway. The broker logs in at
`auth/<auth_mount>/login` (`kubernetes` by default) with the projected ServiceAccount
token the base Deployment mounts (audience `openbao`), keeps the OpenBao token in memory
until its lease nears its end, and exchanges it again at once on a 403. At start it seals
and unseals a probe, so a wrong URL, CA, role, policy, mount or key, a key created
without `derived`, or a key that does not keep one slot's envelope from opening as another's,
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
nothing for mediatore to delete from.

## Workload output

A sandbox created with `workload.logs: true` (`--logs`;
[ADR-0045](../adr/0045-a-sandbox-workloads-output-streamed-to-its-owner.md)) has what it
prints shipped by the guest, already redacted, to `POST /v1/me/logs`, and the broker keeps it
in a ring of Secrets in its own namespace: `mediatore-logs-<claim uid>-<segment>`, 64 KiB of
record text per segment, the oldest segment deleted once the claim's total passes
`logs.max_bytes` (default 1 MiB, ceiling 4 MiB, floor one segment; a value outside refuses to
start). The reader is told how many bytes went that way. Secrets, not ConfigMaps, because the
output may hold what redaction missed, and sealed besides
([ADR-0052](../adr/0052-a-sandbox-workloads-stored-output-sealed-per-batch-with-the-transit-key.md)):
the broker seals each accepted batch with the same OpenBao transit key as the sessions (one
`encrypt` per batch, a separate derivation context so a session ciphertext and an output blob
never open as each other), and a segment's `entries` are those sealed blobs, one per line, with
only the sequence range, the text byte count and the key id in clear (the segment is marked
`mediatore.io/seal: v1`). A read opens only the blobs it returns (at most four transit calls in
flight; a cursor skips the blobs behind it; a tail starts from the newest). If OpenBao cannot be
reached the write and the read are a `503`, the guest retries the same batch, and nothing is
stored in clear; a blob that does not open for the claim, or a segment without the marker, is
shown to the owner as an unreadable gap and never served. A claim that keeps printing costs at
most two such writes a second, each with its one `encrypt` (the node's batch limit, `429`
beyond it); one that prints now and then costs a write when it does. `logs.enabled: true` without
`store.sealing` refuses to start. The Role needs no new verb and OpenBao no new policy. The segments carry an owner reference to the
`AgentSandbox` when the sandbox lives in the broker's namespace, so garbage collection takes
them with it; otherwise the sweep does. They go `logs.retention_secs` after the claim ended
(default `store.retention_secs`), with the claim's audit sweep, or at once when no record
exists for them. `logs.enabled` is `false` by default: both routes answer `501` and a claim
that opts in is refused at creation, so nothing is ever stored by surprise. Only the claim's
subject reads the output through the broker, `GET /v1/claims/{name}/logs`; anyone with `get`
on Secrets in the broker's namespace sees ciphertext, and decrypting it takes acting as the
broker at OpenBao (its ServiceAccount token, a shell in its pod, the OpenBao operator), which is
break-glass and visible in the audit logs of both. Under `dev_mode` the in-memory store keeps
the same ring with the same cap and sweep rules (it is memory, not a store at rest).

## Nodes

A node registers once, when its guest starts, as a `SandboxNode` named by the EK hash. Since
[ADR-0039](../adr/0039-a-node-leaves-the-register-when-its-vm-is-gone.md) the leader
removes it when its VM is gone: at each resync it lists the pool member `VirtualMachine`s,
computes the EK hash each publishes the way the claim binding does, and deletes a
`SandboxNode` no VM publishes. It never deletes a banned node (an operator removes a ban),
a node younger than `store.node_grace_secs` (default 600; zero is refused), a node a claim
that has not ended is bound to, or more than twenty in one pass, and it removes nothing when
the VM list cannot be read or is empty while a node is young or a claim is active. A node
removed too early comes back when its guest registers again; a guest waiting for a claim
restarts and does that within seconds. One log line per removal:
`node removed: its VM is gone`. Nothing to configure beyond the grace; the broker's role
already holds `delete` on `sandboxnodes`.

`retention_secs: 0` means an ended claim is swept at the next resync, which is how the
kind tiers run.

## Health

`GET /healthz` on the user listener lists one `AgentSandbox` and answers
`503 store_unavailable` when the API server does not answer, so a broker cut off from the
cluster leaves the Service until it is back.
