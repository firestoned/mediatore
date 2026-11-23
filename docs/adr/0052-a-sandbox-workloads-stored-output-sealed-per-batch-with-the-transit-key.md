<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0052: A sandbox workload's stored output is sealed per batch with the transit key

**Status:** Accepted and implemented 2026-11-19, released in v0.4.0 (amended at implementation: decision 3's trim and segment size count a fixed overhead per sealed batch as well as its text, found while mapping the controls; the first live run of the sealed path is still to come) · **Date:** 2026-11-19

Amends [ADR-0045](0045-a-sandbox-workloads-output-streamed-to-its-owner.md) decision 6 (where the
output is stored) and retires the reasoning of its R-39. Builds on
[ADR-0015](0015-transit-sealer.md) (the transit sealer), [ADR-0013](0013-dex-session-delegation.md)
and [ADR-0034](0034-the-kubernetes-api-as-the-brokers-store.md) (the Kubernetes API as the store).
Changes no identity, no token shape, no SPIFFE ID and no wire route: the guest still posts the
same `LogBatch` to the same `POST /v1/me/logs` over the node SVID, and the owner still reads the
same `GET /v1/claims/{name}/logs`. It changes what the broker writes into the Secrets and what it
does to read them back, and it adds no OpenBao policy: the broker already holds `encrypt` and
`decrypt` on its transit key.

## Context

ADR-0045 stores a claim's output in a ring of `Secret` segments, `mediatore-logs-<claim
uid>-<n>`, whose `entries` key is the NDJSON of the records. It chose Secrets for "encryption at
rest where the cluster has it", and recorded as R-39 that the output is not sealed, giving two
reasons: it "must be served by any replica without a key round trip", and "sealing would not
change who can read it through the API".

The first live run of ADR-0045 on the shared cluster (2026-11-19, a workload printing 1675
records of which 4 carried planted fake secrets) showed what that leaves:

- The segment decodes with a plain `base64 -d` to readable text. Redaction in the VM removed
  the planted values, so what is stored is what redaction let through, which is R-38's
  residue: whatever the redactor could not recognise, in clear, in etcd and in every backup of it.
- Whether etcd encrypts Secrets is a property of the cluster's apiserver configuration. The
  operator of this feature may not control it, cannot observe it from the Kubernetes API, and
  has no way to make mediatore's own claim ("encrypted at rest") true without it.
- Both of R-39's reasons are weaker than they read. Every broker replica already reaches the
  same OpenBao transit key (the session Secrets are sealed by it and any replica unseals them:
  `store.sealing.transit`, `TransitSealer`), so a key round trip is the normal path, not a new
  one. And sealing does not change who can read through the API, but it does change who can
  read without it: an administrator with `get secrets`, an etcd snapshot, a backup, a
  volume-level copy.

The sealer already exists and already binds a ciphertext to a claim: `Sealer::seal(claim_uid,
plaintext)` and `unseal`, over a derived transit key (the context is the claim's UID, so a
ciphertext opens for that claim only), probed at start-up (a seal and unseal under a random
binding, and a refusal under another).

## Decision

The broker seals each stored batch of the claim's output with the transit sealer it already
holds, and unseals only what a read returns. Seven numbered decisions; each has its control, its
home and its proof.

1. **Seal per batch, in the broker, with the same key.** When `POST /v1/me/logs` is accepted,
   the broker seals the accepted records as one blob with the configured `Sealer` (the same mount,
   key and role as the session Secrets; no new OpenBao policy, no new key) before anything is
   written. The guest and the wire are unchanged: the node already reaches the broker over mTLS
   (the VM never holds a key, and has no route to OpenBao). A batch the segment cannot hold is
   split into chunks of at most 64 KiB of plaintext (the segment cap), each sealed on its own,
   so a maximum batch (256 KiB) costs at most 5 transit calls and a typical one costs 1. The
   broker's memory holds the plaintext of a batch for the length of the call and no longer.

2. **A separate context for the output.** The transit context for a log blob is `"mediatore-logs"
   || 0x00 || claim UID bytes`, not the bare UID the session Secrets use, so a blob from one
   place can never be opened as the other, and a session ciphertext cannot be presented as
   output. `Sealer` gains a purpose argument; the sessions' context is left exactly as it is,
   so every sealed session already stored still opens. The start-up probe is extended to the new
   context (round trip, and a refusal under another claim UID), so a transit key created without
   derivation fails at start, as today.

3. **What stays in clear, and what is sealed.** In the Secret, `data.entries` becomes the
   sealed blobs, one JSON object per line: `{"first": <seq>, "last": <seq>, "bytes": <plaintext
   bytes>, "sealed": {"key_id", "nonce", "ciphertext"}}`. The annotations on the Secret
   (`first-seq`, `last-seq`, `bytes`, `segment`, `truncated-before`) stay as they are, and a new
   `mediatore.io/seal: v1` marks the format. Only sequence numbers, sizes and the key id are in
   clear: no text, no stream, no timestamp. This is what lets the broker append, trim, skip
   and count without a transit call:
   - **append** reads the open segment's blob list (not its contents), adds the new sealed
     blobs and writes the Secret back on `resourceVersion` as today; ingest needs `encrypt` only,
     never `decrypt`;
   - **trim** drops whole segments as ADR-0045 does, by a segment's weight: its record text
     plus 256 bytes per sealed batch (`BLOB_OVERHEAD`, `crates/mediatore-claims/src/kubestore.rs`),
     which is what a batch really costs in the Secret beyond its text (the line's keys, the key id,
     the nonce, the transit header and base64). Counting text alone, as ADR-0045 did, would let a
     workload printing a line a second (one tiny batch a second) grow one Secret toward the
     object cap and one claim's ring without bound, since the cap would never be reached. The
     same weight decides when a segment is rolled, so a segment holds at most 64 KiB of weight
     and about 256 tiny batches. What the owner is told was dropped (`truncated_before`) stays
     record text bytes. So `logs.max_bytes` is text plus 256 bytes per batch; for ordinary
     batches (tens of KiB) the difference is under 1 percent. The Secret itself is about 1.4
     times its text (base64 of the ciphertext and the frame), far under the object cap;
   - **an authenticated unseal checks the header.** The decrypted batch carries its own first
     and last `seq`; a blob whose clear header differs from them is rejected, so a writer of the
     Secret cannot reorder, relabel or splice blobs to change what the owner reads.

4. **Reads unseal only what they return, and fail closed.** A read unseals the blobs whose
   `last` is above the cursor (`since`), newest first for `tail` (stopping once `n` records are
   in hand), with a bound of 4 transit calls in flight and the order kept. A `follow` re-reads
   every two seconds from its cursor, so its transit calls track the new data, not the size of
   the ring. Then:
   - transit unavailable on a read: `503`, never a partial success and never plaintext
     (ADR-0045 decision 7 already says a store that cannot be read is a `503`; the sealer is
     part of the store now);
   - transit unavailable on an ingest: `503` to the guest, which retries the same `seq` range
     with its backoff (ADR-0045 decision 8; the write is idempotent on `seq`), so nothing is
     stored unsealed and nothing is lost within the guest's 1 MiB queue;
   - a blob that does not open (`Rejected`: wrong claim, tampered, retired key) or a segment
     without the seal marker is **not served**: the owner gets a `LogGap` with reason
     `unreadable` where it was, and the broker logs the segment name and the claim UID at `warn`
     (never content). A plaintext segment in a claim's ring is not trusted as the claim's
     output, whoever wrote it.

5. **Sealing is required whenever the output is kept.** `logs.enabled: true` without a configured
   sealer (`store.sealing`) is refused at start-up (`Config::validate`, with the other `logs`
   refusals of ADR-0045 decision 11); there is no option to store the output in clear. A claim that
   opts in on a broker with logs off is still refused `501`. In `dev_mode` the in-memory ring is
   unchanged: it is memory, not a store at rest, and the dev sealer exists for the session path
   already; the fake must refuse what the real store refuses (`.claude/rules/testing.md` rule 2),
   so the memory ring is exercised through the same seal and unseal calls in the tests.

6. **No migration, by design.** The only broker release that stores output is
   `0.4.0-rc.2`, a release candidate; its plaintext segments have no seal marker, are never
   served after this change (decision 4) and are removed by the retention sweep
   (`logs.retention_secs`) or with their `AgentSandbox`. No reader of both formats is
   written.

7. **The read path is asynchronous end to end (a defect also fixed on `main` by #142 while this change was written).** The live run
   also found that the owner's read of a stored ring larger than 31 records ended early: the
   response was built through a bounded channel of 32 with `try_send`, and a full channel was
   taken for a departed reader (`records_sent=32 reason=Client`). Unsealing makes the read loop
   await anyway, so the sends become `send().await` with backpressure (the same fix landed on `main` in #142, and the
   two were reconciled at rebase), and `Closed` (the reader went) is told apart from a slow reader. The proof is a test that stores more than 32 records
   and reads all of them, and that a slow reader still gets every record in order.

## Consequences

- The stored output is ciphertext in etcd, in snapshots and in `kubectl get secret -o yaml`:
  `entries` holds `vault:v1:` envelopes and sequence ranges, and reading it needs the transit
  key. The claim "encrypted at rest" becomes true of mediatore's own storage whatever the
  apiserver's encryption provider does, and no longer depends on a cluster setting the operator
  cannot see.
- It raises the bar, it does not remove it. Whoever can act as the broker to OpenBao (its
  ServiceAccount token, a shell in its pod, the OpenBao operator) can decrypt, because the
  transit context is not a secret and OpenBao does not restrict it per claim. R-39 is narrowed,
  not deleted: its subject becomes "the broker's identity at OpenBao" instead of "`get` on
  Secrets". Redaction stays the first layer and R-38 is unchanged.
- Costs: one `encrypt` per batch (about one a second per printing claim; at most 5 for a maximum
  batch), at most 4 concurrent `decrypt`s per read, and a read of a long ring depends on
  OpenBao being up. The ingest latency gains one OpenBao round trip, inside the guest's one
  second cadence. OpenBao load scales with the number of claims that print at once; the
  deployment guide gets a sizing line.
- The two replicas still share one store: the ciphertext is in the API, any replica unseals it
  with the same key. Nothing is held in a replica's memory between calls.
- New code: the log-blob format and the sealed append and read in `crates/mediatore-claims`
  (`kubestore.rs`), the purpose argument in `crates/mediatore-store/src/seal.rs`, the start-up
  probe and the `logs` refusal in `crates/mediatore/src/config.rs`, the async read in
  `crates/mediatore-api`. Tests: a stored segment contains none of a batch's text; a blob
  opens only for its own claim and purpose; a session ciphertext is refused as a blob; a
  header that disagrees with the plaintext is rejected; OpenBao down gives `503` on ingest and
  on read and writes nothing; a plaintext segment is a gap and is never served; and, for the
  defect, a read of more than 32 records. The live proof is the 2026-11-19 run repeated: the
  Secret shows `vault:v1:` and none of the printed strings, and the owner's full read returns
  every record.
- Threat model: TB-1, TB-6 and TB-9 rows for the output (A-27) change from "unsealed Secret" to
  "sealed Secret"; R-39 is rewritten as above; a new row covers the transit dependency on the
  read path (availability, not confidentiality: a fail-closed `503`); the stamp is bumped to
  ADR-0052 when this is implemented. No unremediated finding is recorded here.
- *Revisit when* the deployment wants a key per claim that the broker cannot use after the
  claim ends (sealing to a key the broker deletes at release), which would make a released
  claim's output unreadable even to the broker, or when OpenBao load from busy claims is the
  complaint (then batch sealing into larger blobs, one per segment rewrite, is the lever).
