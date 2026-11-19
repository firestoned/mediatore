<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0057: A claim's record written by compare-and-set and bound to its sandbox

**Status:** Proposed · **Date:** 2026-11-19

Roadmap 05 (the store). Amends [ADR-0034](0034-the-kubernetes-api-as-the-brokers-store.md)
decision 1 (it reverses one sentence: "writes are status patches, which carry no resourceVersion
and compose from any replica") and decision 2 (the order of a write, and what a session Secret's
ciphertext is bound to), and finishes what its amendment of 2026-11-19 left open. Amends
[ADR-0012](0012-persistent-store.md) decision 5 (the conformance suite gains the cases below and a
second store to run over), [ADR-0015](0015-transit-sealer.md) decision 2 (what the transit
`context` is for a session), [ADR-0035](0035-a-requesters-own-session-delegated-at-claim-time.md)
decision 3 and [ADR-0043](0043-a-persons-registry-credential-is-placed-at-the-gateway-the-vm-never-sees-it.md)
decision 4 (where a delegation's expiry is believed from). Follows
[ADR-0052](0052-a-sandbox-workloads-stored-output-sealed-per-batch-with-the-transit-key.md)
decision 2, which gave the sealer a purpose. Changes no token, no SPIFFE ID and no route of either
API. It changes the storage contract, which is why it is an ADR and not a fix.

Three changes are recorded together because they are one contract seen from three sides: when a
write of a record is accepted (decisions 1 to 6), whose word a record read from a status is
(decisions 7 and 8), and what a stored envelope is bound to (decisions 9 to 11). The second is
argued and then recommended for deferral; if the maintainer agrees, decision 8 leaves this ADR for
one of its own (open question 2).

## Context

ADR-0034 made the `AgentSandbox` the claim record and its Secrets the sealed sessions. Three
limits of that contract are known, and the fixes of 2026-11-19 narrowed each without closing it.

**A write of a record has no precondition.** `ClaimStore::update_claim` takes a whole
`ClaimRecord` and writes it. Its callers read the record, decide, and write: the reconciler's
bind (`Reconciler::bind`, `crates/mediatore-claims/src/lib.rs`), the guest's report and exit and a
session refresh (`report`, `exit`, `refresh_session`, `crates/mediatore-api/src/lib.rs`), on any
replica. Since 2026-11-19 an update reads the sandbox again and refuses to write over a released
record, in both stores, and writes the status before the Secrets. What is left is the interval
between that read and the write: a release landing inside it is not seen, and the update that
follows writes a record decided before the release. The 15-second envelope sweep removes what
such a write leaves on a released record, which bounds the result and does not prevent it.
`put_claim` and `revoke_claim` still write the Secrets before the status, so a failure between
the two leaves the Secrets and the record disagreeing in the direction that keeps material.
`PolicyFloor` has had the right shape since ADR-0034 decision 3: a write decided from a floor
that has moved is a `409` and a `Conflict`.

**A record is believed because it is on a status.** The store reads `status.record` and takes it
as its own earlier write. Who may write a status is RBAC, and since 2026-11-19 an admission
policy that admits the broker's ServiceAccount alone, whatever a namespace Role grants
(`deploy/base/admission/agentsandbox-status.yaml`); `finalize_sandbox` releases a record only
when it is the deleting sandbox's own (`crates/mediatore-claims/src/sandbox.rs`). The contract
still has no way to tell a record the broker wrote from one it did not, for a writer the
admission policy does not stop. Those writers are few and are named in decision 8, because who
they are decides whether a cryptographic check is worth its cost.

**Every session envelope of a sandbox has one binding.** `ClaimRecord::seal_binding` is the
sandbox UID, and `SealPurpose::Session` makes the sealing context that UID and nothing else
(`crates/mediatore-store/src/seal.rs`). The issuer's session and each delegated credential
(ADR-0035) of one sandbox are therefore sealed under the same context, and what tells them apart
is the Secret's name and its audience label, which are not authenticated. A delegation's
`expires_at` is stored in clear beside the ciphertext and on the status, and the issue path
bounds a credential by that clear value. A principal who can write Secrets in the broker's
namespace (A-11) cannot read an envelope, but the contract does not stop an envelope of a
sandbox from being presented under another audience of the same sandbox, or its stated expiry
from being moved. The threat model's TB-10 row says "the binding UID"; it is the sandbox UID
alone, with no audience in it.

## Decision

1. **A record carries the version it was read at.** `ClaimRecord` gains `version`, an opaque
   value set by the store on every read (`get_claim`, `get_claim_by_name`, `get_claim_by_node`,
   `list_claims`) and never serialised into a stored shape. In `KubeStore` it is the
   `AgentSandbox`'s `metadata.resourceVersion` as read; in `MemoryStore` it is a counter per
   record, moved by every write. A caller never builds or compares one; it hands back the record
   it was given. A record built by `record_for` for `put_claim` has none.
   Files: `crates/mediatore-store/src/lib.rs`, `crates/mediatore-claims/src/kubestore.rs`
   (`record_from`).

2. **Every update of an existing record is conditional on that version.** `update_claim`
   writes only if the stored record is still at the version the caller's copy carries. In
   `KubeStore` the status patch names `metadata.resourceVersion`, which the API server checks and
   answers with a `409`; the store reports it as `StoreError::Conflict`, as `advance_policy_floor`
   does. In `MemoryStore` the comparison and the write happen under the one lock. An update whose
   record carries no version is a caller's bug and is a `Conflict` that writes nothing. A released
   record stays final: an update of one is a `Conflict` whatever version it names.
   The resource version is the object's, not the record's, so a write by the reconciler's mirror
   or of a label moves it too. That is accepted: a conflict costs a read and a second decision,
   and the callers of decision 5 are written to make it.
   Files: `crates/mediatore-claims/src/kubestore.rs` (`update_claim`, `write_record`),
   `crates/mediatore-store/src/lib.rs` (`MemoryStore::update_claim`).

3. **A release carries no precondition, and so cannot lose.** `revoke_claim` is the one write
   that is right over every earlier state: it sets `revokedAt` when none is set and drops the
   refresh material, as a status patch that names only those fields and no resource version.
   Whatever landed before it, it lands on top. Whatever was decided before it and arrives after,
   arrives with a version the release has moved, and is refused by decision 2. No interleaving
   leaves a released record live. Two releases racing each other may each write a timestamp, a
   few milliseconds apart; either is a correct release time, and "the first timestamp wins" is
   kept for every release that reads an already released record, which is all the conformance
   suite could ever show.
   Files: `crates/mediatore-claims/src/kubestore.rs` (`revoke_claim`),
   `crates/mediatore-store/src/lib.rs`.

4. **The status is written before the Secrets, in every write, and an update never creates a
   Secret.** The record is the marker; the Secrets follow it.
   - `put_claim`: the labels, then the record (conditional on the sandbox still carrying none),
     then the Secrets it took from the parked session and delegations. A failure before the
     record leaves a label and no record, which every lookup already treats as no record. A
     failure after it leaves a record whose Secrets the sweep already answers for. A conflict that
     is only a moved resource version, with still no record on the sandbox, is retried inside
     `put_claim` with the record in hand, because the parked session was taken to build that
     record and a returned error would lose it.
   - `revoke_claim`: the status first (decision 3), then every Secret labelled with the sandbox
     UID is deleted. A release of an already released record still runs the deletion, so a retry
     finishes what a failed first attempt left. Between the two steps a Secret can exist beside
     a released record; nothing issues from it (`ClaimRecord::is_live`), and the envelope sweep
     removes it within one pass if the deletion never completes.
   - `update_claim`: the status (decision 2), then the Secrets, each replaced in place and never
     created. A Secret that is absent at an update is an envelope a release or the sweep deleted,
     and it stays deleted: the update is a `Conflict`. An update that changes only an envelope
     (a rotated refresh token) writes no status; it reads the sandbox once more, refuses when the
     version has moved or the record is released, and then replaces the Secret. With the release
     ordered as above, this holds: once a release has returned, no Secret of the sandbox exists
     and none can be written.
   Files: `crates/mediatore-claims/src/kubestore.rs` (`put_claim`, `revoke_claim`,
   `write_envelope`, `write_one_envelope`, `envelope_write`).

5. **A caller that meets a conflict reads again and decides again, and each caller's second
   decision is written down.** The store crate gains one helper, `modify_claim`: read the record,
   hand it to the caller's closure, write what the closure returns, and on `Conflict` start again,
   at most four times. The closure sees the fresh record every time, so "decide again" is the
   same code as "decide". What each caller decides:

   | Caller | On the fresh record | When the record is released or gone | When the attempts run out |
   | --- | --- | --- | --- |
   | `Reconciler::bind` | an entry id already there: done, nothing written. Otherwise set the entry id and the node, and the deadline only if none is set | the entry it has just declared is retracted before it returns, and the bind is an error: the claim stays unbound | an error; the controller requeues |
   | `report` | the report is put on the fresh record; nothing else of the caller's copy is carried over | `404 no_claim`, as for a node with no live claim | `503`, nothing written; the guest may send it again |
   | `exit` | the exit is put on the fresh record | `204`: the claim has ended already, the exit is in the log line and not on the record | the release goes ahead all the same: a claim is never left to its deadline because its record was busy |
   | `refresh_session` | the freshly sealed envelope is put on the fresh record | the envelope is dropped unsealed and unstored, no token is minted, and the answer is the one a released claim gets | `503`, nothing minted; the envelope is dropped |
   | the reconciler's mirror | not a caller of `update_claim`. It patches the status fields it derives and never the record, with no precondition, and derives them again from a fresh read on the next pass | the next pass mirrors the released record | does not apply |

   The mirror stays unconditional on purpose: it is a projection, wrong for at most one pass, and
   a precondition on it would make it fight the store for nothing. A unit test pins that its
   patch never names `record`.
   Files: `crates/mediatore-store/src/lib.rs` (`modify_claim`), `crates/mediatore-claims/src/lib.rs`
   (`Reconciler::bind`), `crates/mediatore-api/src/lib.rs` (`report`, `exit`, `refresh_session`),
   `crates/mediatore-claims/src/sandbox.rs` (`mirror`, unchanged, pinned).

6. **Both stores are held to it by the same cases.** The conformance suite gains the cases
   listed under "What must be proven", and stops being `MemoryStore`'s alone: the cases are made
   available to `mediatore-claims`, which runs them over `KubeStore` on its fake API server,
   through an adapter that creates the `AgentSandbox` a case's record names. The fake API server
   must then refuse a patch that names a stale `metadata.resourceVersion` with a `409`, as it
   already does for the replace of an output segment, and must answer `404` to a patch of a
   Secret that is gone. `MemoryStore` must refuse everything `KubeStore` refuses
   (`.claude/rules/testing.md` rule 2): the version check, the versionless update, the final
   released record. The kind tier stays the proof on a real API server.
   Files: `crates/mediatore-store/src/conformance.rs`, `crates/mediatore-claims/src/kubestore.rs`
   (the `fake` module of its tests).

7. **The record names the sandbox it was written for.** `status.record` gains `sandboxUid` and
   `namespace`, written by `put_claim` from the object. On every read the store compares them
   with the object the record is on (`metadata.uid`, `metadata.namespace`); a record that names
   another object is not a record: the read is `NotFound`, the store logs the sandbox, the claim
   UID and the two UIDs at `warn`, and `put_claim` on that sandbox is a `Conflict`, so the
   reconciler fails the sandbox and deletes its claim and never writes a second record over the
   first. A record written before this ADR has neither field and reads as before until its claim
   ends; the release after the one that ships this refuses it.
   This is not a cryptographic check, and a writer who can write a status can write the right
   UID. It is here for what it does cover with no key and no cost: a status carried onto another
   object by a tool (a restore that creates objects again under new UIDs, a copied manifest
   applied by an administrator) is refused, where today it is believed. It is also the first
   field decision 8 would cover.
   Files: `crates/mediatore-claims/src/kubestore.rs` (`RecordStatus`, `record_from`,
   `record_status_from`, `carries_claim`, `put_claim`), `crates/mediatore-claims/src/sandbox.rs`
   (the failed sandbox), `deploy/base/crds` (rendered by `crdgen`).

8. **A MAC over the record's identity: designed here, and recommended for deferral.**

   *Who is left.* With the admission policy bound, a status is written by the broker's
   ServiceAccount and by: a principal admission does not apply to, or who can change or unbind
   the policy; a principal who can act as the broker's ServiceAccount; a writer of the datastore
   beneath the API server; and a restore from a backup, which writes whatever the backup held.
   The first three can also reach the sealer as the broker does (the projected token in the
   transit shape, the key file in the local shape), so they can make whatever tag the broker can
   make. A restore puts back records the broker did write, with their tags: a MAC gives
   authenticity, not freshness, and an earlier record of the same sandbox verifies. What a MAC
   adds is therefore one case: a writer of statuses who cannot act as the broker, on a cluster
   where the admission policy is absent, unbound, or does not list a served version.

   *The design, so that it is not designed twice.*
   - **What is covered.** A fixed, length-prefixed encoding of: a format label, the claim UID,
     the sandbox UID, the namespace and the name, the subject's issuer and id, `createdAt`, and,
     once bound, the node's SPIFFE ID, the entry id and `expiresAt`. These are the fields that
     say whose claim it is, on which object, on which node, until when, and which registration
     entry a release retracts. All are written at most twice in a claim's life: at `put_claim`
     and at the bind.
   - **What is left out, and why.** `revokedAt`: a release must not need the sealer to be up, and
     covering it would buy nothing, since removing it is the replay a MAC does not stop; the rule
     is instead one-way, a record with `revokedAt` is ended whether or not its tag verifies. The
     report and the exit: they are what the guest said, they decide nothing, and covering them
     would put a sealer call on a path the guest drives. `refresh` and the delegation list: they
     point at Secrets whose contents carry their own authentication (decision 9), so a forged
     pointer opens nothing. The policy uid and bundle version: audit fields today; they join the
     covered set in the ADR that makes a refusal depend on them. The audiences, the workload and
     the TTL: they are the spec's, frozen by the admission policy on the spec, and are not on the
     record.
   - **How the tag is made.** A new `SealPurpose::Record`, whose context is a label and the
     sandbox UID. The tag is the SHA-256 of the encoding, sealed like any envelope and stored as
     `status.record.seal`; verifying is unsealing it and comparing digests in constant time. On
     transit that is one `encrypt` and one `decrypt` on the key the broker already uses, under the
     policy it already holds, with the key never leaving OpenBao. The local sealer does the same
     with AES-256-GCM and the context as associated data. The transit engine also offers a keyed
     hash (`POST <mount>/hmac/<key>` returns a versioned tag, `POST <mount>/verify/<key>` checks
     one); it is the alternative, rejected below for two reasons that open question 3 asks the
     maintainer to confirm.
   - **When it is checked.** Whenever a record is read from a status. A tag that does not verify
     (`SealError::Rejected`, `UnknownKey`) is no record, with decision 7's log line and
     decision 7's consequence for `put_claim`. A sealer that does not answer
     (`SealError::Unavailable`) is `StoreError::Unavailable` and a `503`, never "no record": an
     outage must not read as a cluster full of forgeries.
   - **What it costs.** Two sealer calls per claim to write. To read, one call per record state
     per replica, with the result cached by the digest and the tag (not by the resource version,
     which the mirror moves without changing a covered field); after a restart, one call per
     record on the first sweep. And a new dependency: today a record read needs the API server
     alone, and with this every first read of a record needs the sealer too.
   - **Rotation.** A rotated transit key verifies old tags until the administrator raises
     `min_decryption_version`; a record's tag is remade only at the bind, so raising it strands
     live records, which then read as no record. The rule for the guide would be: not before the
     longest claim TTL plus the retention has passed since the rotation. There is no broker-wide
     maximum TTL to compute that from (out of scope, below). A changed local key strands every
     record at once, as it already strands every envelope.

   *The recommendation: defer.* The admission policy closed the case that was found. What a MAC
   adds beyond it is a second control for a cluster where the first is missing, bought with a
   sealer call on the read path, a new way for an outage or a rotation to end live claims, and a
   verification cache to get right. Decision 7 takes the part that is free. Build this when one
   of these becomes true: a deployment must run without the admission policy (an API server
   before 1.30); a second controller is given `agentsandboxes/status`; or the datastore's
   operator stops being the cluster's administrator. Until then the limit is recorded as an
   accepted risk with those three as its *Revisit when*.
   Files, if built: `crates/mediatore-store/src/seal.rs` (`SealPurpose::Record`, the probe),
   `crates/mediatore-claims/src/kubestore.rs` (`RecordStatus::seal`, `record_from`, the cache).

9. **A session envelope is bound to its slot as well as its sandbox.** A new sealing context for
   everything `SealPurpose::Session` seals today:

   ```
   "mediatore-session" 0x00 | sandbox UID, 16 bytes | slot
   slot = 0x00                       the issuer's session
   slot = 0x01 | audience, UTF-8     a delegated credential for that audience
   ```

   The UID has a fixed length and the audience is last, so no two inputs give the same bytes, and
   the tag byte keeps an audience of any spelling apart from the issuer's slot. It is the
   associated data of the local sealer and, in base64, the `context` parameter of the transit
   sealer's `encrypt` and `decrypt`, in place of the bare UID. An envelope of one audience does
   not open as another's, nor as the issuer's session, nor the reverse; ADR-0052's output context
   is untouched and stays apart from all of them. The start-up probe of `TransitSealer::connect`
   gains the round trip and the three refusals, so a key that does not bind the slot stops the
   start. The API seals a delegation under its audience when it parks it, and the issue path
   opens it under the audience it was asked for, so nothing in clear chooses the context.
   Files: `crates/mediatore-store/src/seal.rs` (`SealPurpose`, `context`, the probe),
   `crates/mediatore-api/src/lib.rs` (`seal_delegation`, the session park, `refresh_session`,
   `delegated_token`), `crates/mediatore-testkit/src/transit.rs`.

10. **A versioned format, so what is stored still opens.** `Sealed` gains `format`: absent or `1`
    is the bare sandbox UID of ADR-0013, `2` is decision 9's context. Everything sealed from this
    change on is `2`; nothing seals `1` again (the helper that did is removed, so a call site
    that would is a compile error). A stored `1` is read as `1`. The issuer's session is sealed
    again at every refresh (ADR-0013 decision 4) and becomes `2` at the claim's next issue. A
    delegation is sealed once and never again, so a `1` stays a `1` until its claim ends, which
    bounds the old format by the claim's TTL. The marker is in clear and proves nothing by
    itself: a `2` marked `1`, or a `1` marked `2`, is opened under the wrong context and does not
    open. Reading `1` is removed in the release after the one that ships `2`, said in its notes,
    like ADR-0034's cutover; from then on a `1` is `Rejected`.
    Files: `crates/mediatore-store/src/seal.rs` (`Sealed`),
    `crates/mediatore-claims/src/kubestore.rs` (`envelope_data`, `envelope_of`, `session_secret`).

11. **A delegation's expiry is believed from inside the envelope.** `DelegationPlain` gains
    `expires_at`, the instant `parked_expiry` computes today, sealed with the credential. For a
    format `2` delegation the issue path bounds the credential by that value and by the record's
    deadline, and reads no clear expiry. The clear `expires_at` on the Secret and on the status
    stays, as what the envelope sweep and `kubectl` read: the sweep opens no envelope, and that
    stays true. A clear value moved earlier deletes a Secret sooner, which a writer of Secrets
    can do anyway; moved later it keeps ciphertext stored until the claim ends and its Secrets
    go, and extends no use. The issuer's session carries no expiry inside: what bounds its use is
    the record (`is_live`), its stored expiry moves at the bind without the envelope being
    opened (`session_expiry`), and an inner copy would have to be re-sealed there for no gain.
    Files: `crates/mediatore-proto/src/lib.rs` (`DelegationPlain`),
    `crates/mediatore-api/src/lib.rs` (`seal_delegation`, `delegated_token`).

12. **Out of scope.**
    - An issuer-qualified `sub` in the tokens the STS mints: a token-shape change, its own ADR.
    - A broker-wide maximum claim TTL: a configuration key and a refusal at claim time, no ADR
      needed; decisions 8 and 10 would both be easier to state with one.

## STRIDE, TB-9 and TB-10

Every control below is one this ADR proposes. None is built; the file is where it will be.

| Boundary | Threat | STRIDE | Control (not yet built) |
| --- | --- | --- | --- |
| TB-9 | A write decided before a release lands after it, and the record or its Secrets come back | T/E | The update is conditional on the version read (`update_claim`, `crates/mediatore-claims/src/kubestore.rs`; `MemoryStore::update_claim`, `crates/mediatore-store/src/lib.rs`); the release carries no precondition (`revoke_claim`); an update never creates a Secret (`write_one_envelope`). Not yet built |
| TB-9 | Two replicas writing one record from the same read, one silently undoing the other | T | The same compare-and-set; the loser reads again and decides again (`modify_claim`, `crates/mediatore-store/src/lib.rs`). Not yet built |
| TB-9 | A failure between the status and the Secrets leaving material without a marker | I | Status before Secrets in `put_claim`, `revoke_claim` and `update_claim`; a repeated release finishes the deletion (`crates/mediatore-claims/src/kubestore.rs`). Not yet built |
| TB-9 | A conflict turned into a claim that cannot be released, or an exit that ends nothing | D | The release has no precondition; `exit` releases whether or not its record write landed (`crates/mediatore-api/src/lib.rs`). Not yet built |
| TB-9 | The in-memory store accepting a write the Kubernetes store refuses | T | The same conformance cases over both stores (`crates/mediatore-store/src/conformance.rs`, run from `crates/mediatore-claims/src/kubestore.rs` on the fake API server). Not yet built |
| TB-9 | A status carried onto another object and read as that object's record | S/T | `status.record.sandboxUid` and `namespace` compared with the object on every read (`record_from`, `crates/mediatore-claims/src/kubestore.rs`). Not yet built. A writer who sets the right UID is not stopped by this: A-11, and decision 8 |
| TB-9 | A record written by a principal other than the broker, where the admission policy does not apply | S/T/E | Today: `deploy/base/admission/agentsandbox-status.yaml` and RBAC. Proposed and recommended for deferral: a sealed digest of the record's identity (`SealPurpose::Record`, `crates/mediatore-store/src/seal.rs`). Not built, and not scheduled if decision 8's recommendation is taken; then an accepted risk in §8 |
| TB-9 | An earlier, authentic record of the same sandbox put back (a restore) | T/E | Not closed by any decision here. Bounded by the record's own deadline, by the release having deleted the Secrets and retracted the entry, and by the envelope and orphan sweeps. To be written as an accepted risk in §8 |
| TB-9 | A session Secret's contents exchanged with another Secret of the same sandbox | S/T | The slot in the sealing context (`SealPurpose::context`, `crates/mediatore-store/src/seal.rs`); the issue path opens under the audience asked for (`delegated_token`, `crates/mediatore-api/src/lib.rs`). Not yet built |
| TB-9 | A delegation's stated expiry moved later in the Secret or on the status | T/E | The expiry inside the sealed `DelegationPlain` is the one the issue path reads (`crates/mediatore-proto/src/lib.rs`, `delegated_token`). Not yet built |
| TB-9 | The format marker rewritten to have an envelope opened under the weaker context | T | The marker chooses a context and proves nothing: an envelope opens only under the context it was sealed with; format `1` is no longer read one release later (`Sealed::format`, `crates/mediatore-store/src/seal.rs`). Not yet built |
| TB-10 | A transit key that does not bind the slot, so the audience binding silently does not hold | S | The start-up probe seals under one audience and refuses to start if the envelope opens under another, under the issuer's slot or as format `1` (`TransitSealer::connect`, `crates/mediatore-store/src/seal.rs`). Not yet built |
| TB-10 | The fake OpenBao accepting a context the real one would refuse | T | `FakeTransit` keeps deriving by the exact context bytes (`crates/mediatore-testkit/src/transit.rs`); a case pins the format `2` bytes. Not yet built |
| TB-10 | A wider OpenBao policy asked for by this change | E | None is: decisions 9 to 11 use `encrypt` and `decrypt` on the one key, as today. Decision 8, if built as designed, would also need nothing new |
| TB-10 | (Decision 8 only.) OpenBao away read as "no record", ending live claims | D | `SealError::Unavailable` is `StoreError::Unavailable` and a `503`, never `NotFound`. Not built; part of the deferred design |

## Consequences

- `ClaimStore`'s shape does not change; its contract does. `ClaimRecord` gains one field that is
  never stored. Every caller of `update_claim` moves to `modify_claim`, and a direct call is left
  only where the caller has no second decision to make.
- Conflicts become ordinary. The mirror, a label write and a guest's report all move the same
  resource version, so an update can lose to a write that changed nothing it cared about. Four
  attempts is a guess to be measured in the kind tier; if the rate matters, the lever is fewer
  writes of the object (the mirror already skips a patch that would set nothing), not a weaker
  precondition.
- A session refresh that loses its race four times answers `503` with a refresh token already
  rotated upstream and not stored. The claim's next issue then presents the old token. Whether
  the issuer still takes it is the issuer's rotation policy; where it does not, the claim is
  released as any refused session is. This exists today in a milder form (a failed store write
  after a rotation) and becomes a little more likely. It is said in the guide.
- `bind` retracts its own entry when the claim was released under it, where today the orphan
  sweep does so later.
- RBAC is unchanged: the broker already patches `agentsandboxes/status` and Secrets in its
  namespace, and a conditional patch needs no further verb. No OpenBao policy changes.
- The CRD gains two optional fields under `status.record` (decision 7), in both served versions
  with one schema (ADR-0049); `make crds` output is committed with the change.
- Stored envelopes keep opening across the upgrade (decision 10). No drain is needed for the
  envelopes; a record without decision 7's fields is read until its claim ends.
- CALM (`docs/architecture/calm/architecture.json`): no node and no relation is added or
  removed. The description of the broker's relation to the API server says "conditional writes"
  and that of its relation to OpenBao names the slot. `make calm-validate` and
  `make calm-diagrams` pass before implementation.
- Threat model, the full pass after implementation (`.claude/rules/threat-modeling.md`): the
  TB-6 row on issuance after release loses its "not built" sentence; TB-9 gains the rows above
  and its "written by the store alone" row is reworded to say what is and is not checked on a
  read; TB-10's context rows name the slot and the sandbox UID; A-11 is reworded for what a
  writer of Secrets and of statuses can no longer do; R-33 and R-36 are re-read; two accepted
  risks are added (the unauthenticated record, with decision 8's triggers as *Revisit when*; the
  restore). The Mermaid diagram needs no change. The stamp is bumped with the ADR range.
- The TPM attestation path is not touched (`.claude/rules/testing.md`): no file on that list
  changes, so `make kind-e2e-tpm` is not required.

## Alternatives rejected

- **Keep the read-then-write and let the sweep clean up.** That is today. The sweep bounds how
  long a Secret outlives a release; it does not make a release final, and "final" is what the
  rest of the broker assumes.
- **A counter inside `status.record`, checked by a JSON Patch `test`.** It would conflict only
  with writes of the record, not of the object. Rejected: the resource version is what the API
  server already checks and what `PolicyFloor` and the output segments already use, a failed
  `test` is not a `409`, and the fake API server would have to learn a second patch dialect to
  stay as strict as the real one.
- **A conditional mirror.** It would conflict with the store on every bind for no safety: the
  mirror writes nothing that decides anything.
- **A conditional release with a retry loop.** It can be made to win, but only by arguing about
  who retries how often. A write that is correct over any state needs no precondition.
- **Serialise every write of a record through the leader.** The reports, the exits and the
  refreshes arrive at any replica; routing them to one adds a hop and a single point, to get what
  the API server gives for free.
- **A lease or lock object per claim.** A second object to create, renew and clean for every
  claim, and a holder that dies holding it.
- **For decision 8, the transit engine's keyed hash (`hmac` and `verify`).** A smaller tag and
  the name fits. Rejected as the carrier because it needs two more paths in the broker's OpenBao
  policy, which every deployment would have to grant before upgrading, and because those calls
  take no derivation context, so the binding to the sandbox would rest on the encoding alone. The
  sealed digest uses the `Sealer` as it is, in both shapes, and gets the context binding and the
  versioned rotation the envelopes have.
- **For decision 8, a check against the owned `VirtualMachineClaim`.** The reconciler has it;
  the store on the token path does not, and would pay a second read per issue. It would bind the
  claim UID to the sandbox and say nothing of the node or the deadline.
- **For decision 8, a key held by the broker for MACs alone.** A second key to mount, rotate and
  lose, in the process, when ADR-0015 exists to keep keys out of it.
- **For decision 9, the audience inside the plaintext instead of the context.** It works, but
  the check then happens after the envelope is opened and depends on every reader remembering
  it. In the context, a wrong audience does not open at all.
- **For decision 10, try format `2` and fall back to `1`.** Two sealer calls for every old
  envelope, and no moment at which `1` stops being accepted.
- **For decision 10, no reader of both formats (drain at upgrade).** ADR-0052 could do that for
  a release candidate's output. Sessions of running claims are not disposable in the same way,
  and the reader of `1` is the code that exists today.
- **For decision 11, an expiry inside the issuer's session too.** Its stored expiry moves at the
  bind; an inner copy would need the envelope opened and sealed again there, in the reconciler,
  which holds no session sealer today.

## What must be proven

Tests first, by name. Each is red before its decision is implemented.

Conformance, `crates/mediatore-store/src/conformance.rs`, over `MemoryStore` and over `KubeStore`
on the fake API server:

- `a_record_read_twice_carries_a_version_and_a_write_moves_it`
- `an_update_from_a_stale_version_is_a_conflict_and_writes_nothing`
- `two_updates_from_one_read_land_once`
- `an_update_without_a_version_is_a_conflict`
- `a_release_between_a_read_and_its_update_is_never_overwritten`
- `a_release_lands_whatever_version_anyone_holds`
- `a_second_release_keeps_the_first_timestamp_and_still_drops_what_is_left`
- `an_update_never_puts_back_an_envelope_the_release_dropped`
- `modify_claim_decides_again_on_the_fresh_record_and_stops_at_a_released_one`
- `modify_claim_gives_up_after_its_attempts_with_a_conflict`

`KubeStore` on the fake API server, `crates/mediatore-claims/src/kubestore.rs`:

- `the_fake_api_server_refuses_a_status_patch_on_a_stale_resource_version`
- `an_update_names_the_resource_version_it_read_and_a_409_is_a_conflict`
- `a_release_patch_names_no_resource_version_and_only_the_fields_it_sets`
- `a_put_writes_the_labels_then_the_status_then_the_secrets`
- `a_put_retries_a_moved_resource_version_and_keeps_the_session_it_took`
- `a_release_marks_the_status_before_it_deletes_the_secrets`
- `a_release_of_a_released_record_still_deletes_what_is_left`
- `an_update_never_creates_an_envelope_secret`
- `an_envelope_only_update_on_a_released_or_moved_record_is_a_conflict`
- `a_record_naming_another_sandbox_is_not_found_and_is_never_overwritten`
- `a_record_without_a_sandbox_uid_still_reads_until_its_claim_ends`
- `an_envelope_round_trips_its_format_through_the_secret_and_an_absent_one_is_1`

The reconciler and the API, `crates/mediatore-claims/src/lib.rs`,
`crates/mediatore-claims/src/sandbox.rs`, `crates/mediatore/tests/e2e_dev.rs` and
`crates/mediatore/tests/e2e_session.rs`:

- `a_bind_that_loses_to_a_release_retracts_its_entry_and_binds_nothing`
- `a_bind_that_meets_a_conflict_binds_once_and_keeps_the_first_deadline`
- `the_mirrors_patch_never_names_the_record`
- `a_sandbox_whose_record_names_another_sandbox_is_failed_and_its_claim_deleted`
- `a_report_after_a_release_is_no_claim_and_writes_nothing`
- `an_exit_whose_record_write_conflicts_still_releases_the_claim`
- `a_refresh_that_loses_to_a_release_mints_nothing_and_stores_nothing`
- `a_delegation_presented_under_another_audience_of_its_sandbox_is_refused`
- `a_delegations_clear_expiry_moved_later_issues_nothing_past_the_sealed_one`
- `a_claim_whose_session_was_sealed_as_format_1_refreshes_and_is_stored_as_2`

The sealer, `crates/mediatore-store/src/seal.rs` and `crates/mediatore/tests/transit_sealer.rs`:

- `the_format_2_context_is_the_label_the_uid_and_the_slot` (the bytes, pinned)
- `a_delegation_opens_only_for_its_audience_and_never_as_the_issuers_session`
- `no_two_slots_of_any_spelling_share_a_context`
- `a_format_1_envelope_still_opens_under_the_bare_uid_and_a_relabelled_one_does_not`
- `an_output_blob_opens_under_no_session_slot`
- `the_probe_at_startup_refuses_a_key_that_does_not_bind_the_slot`

Live, on the build host, since no fake shows what a real API server does with a conditional
status patch on a custom resource:

- the kind sandbox tier (`make kind-e2e-sandbox`, `dev/kind/sandbox-e2e.sh`), which has been the
  store's tier since ADR-0034 removed `kind-e2e-store`: a status patch as the broker's
  ServiceAccount naming a stale resource version is a `409`; a released sandbox has no session
  Secret and a later update writes none; the record carries `sandboxUid`; the restart step still
  finds the record and redoes nothing;
- the kind Dex tier (`make kind-e2e-dex`, the transit sealer against a real OpenBao and a real
  refresh): a session Secret carries format `2` after the first issue, and the broker starts
  against the derived key with the extended probe.

Not shown by any of these, and to be said as such in the threat-model pass: the race itself on a
real cluster. The unit cases drive each interleaving in turn; the kind tier shows the API
server's half of the bargain.

## Open questions

1. **Build decision 8 now, or defer it?** Recommendation: defer, and build decision 7. The
   admission policy closed what was found; a MAC adds a second control for a cluster where the
   policy is missing, and costs a sealer call on reads, a cache, and a way for a rotation to end
   live claims. Write the limit down as an accepted risk with the three triggers.
2. **Should decision 8 be its own ADR?** Recommendation: yes. Decisions 1 to 6 and 9 to 11
   tighten a contract with no new dependency; decision 8 adds one on the read path and a failure
   mode of its own, and deserves its own status line. If it is deferred, this ADR is accepted
   without it and keeps decision 8 only as a pointer; "bound to its sandbox" in the title is then
   carried by decision 7 and decision 9.
3. **If decision 8 is built: the sealed digest, or the transit keyed hash?** Recommendation: the
   sealed digest. Two things to confirm on the OpenBao release the kind fixture pins before
   closing this: that `hmac` and `verify` accept a key created `derived`, and that they take no
   context. If both paths would be granted anyway and the binding in the encoding is thought
   enough, the keyed hash is the smaller tag.
4. **Are four attempts right, and how often does the mirror cost a caller one?** Recommendation:
   ship four, count conflicts per caller in the kind sandbox tier, and decide from the number.
5. **Should the whole conformance suite run over `KubeStore` on the fake API server, or only the
   new cases?** Recommendation: the new cases with this change, the rest as a follow-up under
   roadmap 05. The adapter is the cost, and it is paid once.
6. **When does format `1` stop being read?** Recommendation: one release after `2` ships. With
   no broker-wide maximum TTL there is no number to wait for, only "every claim that was running
   has ended"; the release notes say to check that no session Secret without the marker is left.
7. **Is "either timestamp" acceptable for two releases that race?** Recommendation: yes. The
   alternative is a precondition on the release, which is what decision 3 exists to avoid.
8. **Should a release retract the entry named by the claim's UID instead of the one the record
   names?** The name is a function of the UID. Recommendation: yes, as a change of its own with
   its test; it removes one more field whose value is taken from the status on trust, and it is
   independent of everything above.
9. **Should the broker check at start that the status admission policy is bound?**
   Recommendation: yes, outside `dev_mode`, and with the entries policy in the same check. It
   needs read access to the admission resources, which is a new grant, so it is not decided here.
