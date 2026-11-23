<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0064: A claim's egress, summarised on its sandbox's status

**Status:** Proposed (no implementation yet; the threat-model pass is owed before it is accepted)
· **Date:** 2026-11-22

Roadmap 10 (the gateway) and roadmap 08 (the `AgentSandbox` CRD). Amends
[ADR-0062](0062-the-gateway-reports-its-decisions-to-the-broker.md) decision 5 ("the broker logs
and keeps nothing") and its consequence "a false report changes no verdict and no state", and
answers its open question 1 (the owner's view) without a route. Adds one optional field to the
`AgentSandbox` status under [ADR-0048](0048-agentsandbox-served-as-v1beta1.md) decision 4 and
[ADR-0049](0049-agentsandbox-served-as-v1alpha1-and-v1beta1.md) decision 5. Writes it by the
compare-and-set of [ADR-0057](0057-a-claims-record-written-by-compare-and-set-and-bound-to-its-sandbox.md)
decision 2. Changes no token shape, no SPIFFE ID, no route and no stored part of the claim
record (`status.record`). It changes what the store writes, which is why it is an ADR.

## Context

ADR-0062 gives the broker one line per gateway decision: which gateway (as it named itself)
decided which claim's tunnel or inject request, to which authority, with which verdict. The
broker logs the line and keeps nothing. A reader of the broker's log can answer "where did this
claim go"; nobody else can.

A new reader wants it live. Recess, a client that already lists and watches `AgentSandbox`
objects with the user's own kubeconfig, gains an administrator's "watch" view of every live
sandbox: per claim, which gateway carried its traffic, to which authorities, and what was
refused. It has no access to the broker's log and should not need it. Today there is nothing it
can read: the broker keeps nothing, the gateway's journal stays on the gateway VM, and the claim
record says nothing about egress.

What already exists and shapes the answer:

- **The `AgentSandbox` is the claim's record and is already watched.** ADR-0034 put the record on
  its status; the reconciler mirrors the claim's phase, node and addresses there. Every client
  that may `get` the sandbox (its owner, a namespace reader the cluster grants, an administrator)
  already sees all of it, through the API server's RBAC, with `watch` for free.
- **Only the broker writes that status.** `deploy/base/admission/agentsandbox-status.yaml` admits
  a write of `agentsandboxes/status` from the broker's ServiceAccount alone, whatever a Role
  grants, for both served versions.
- **Writes of the record are conditional.** ADR-0057 decision 2: an update names the
  `resourceVersion` it read and loses with a `409` to any write that moved the object. Its callers
  retry through `modify_claim`, at most `MODIFY_ATTEMPTS` (4) times. The reconciler's mirror
  writes without a precondition and never names `record`.
- **Two replicas.** `deploy/base/deployment.yaml` runs the broker with `replicas: 2`. A gateway's
  batches reach either. The `AgentSandbox` controller runs on the Lease holder only (ADR-0011);
  the store's claim lookup (`sandbox_of_claim`, `crates/mediatore-claims/src/kubestore.rs`) runs
  on both, from a hint cache and, on a miss, a cluster-wide list by the claim UID label.
- **The reported authority is the workload's choice.** ADR-0062 decision 5 checks its shape (at
  most 261 bytes of the characters a `host[:port]` holds), not its value. A workload that sends
  `CONNECT` to ten thousand hosts produces ten thousand distinct authorities.
- **Roadmap 15 decided how components are joined.** By the claim UID (`mediatore.claim.uid`) on
  every span, not by a propagated trace context ("Why correlation by claim UID, not by propagated
  context"), and with invariants that bear on this: I-4 (workload-controlled bytes, "a refused
  host" by name, never become attribute values), I-6 (incoming trace context is not trusted),
  I-7 (trace context never leaves the trust domain), I-12 (OTel is an extra copy that may lose
  data, never the source of truth) and I-14 (claim UID never a metric label).

## Decision

1. **The broker folds each accepted decision into a summary on the claim's sandbox.** ADR-0062
   decision 5 stands as written up to the `204` and the log line. After them, each decision of an
   accepted batch is also handed to a fold, a per-replica map from claim UID to a pending
   summary. The `204` is returned before the fold is touched, and handing a decision to it never
   waits: the fold is behind a bounded queue, as the gateway's reporter is (ADR-0062 decision 4),
   and a full queue drops the decision and counts it. The log line stays the record; the summary
   is a view of it.

2. **The shape.** One optional field, `status.egress`, on the one `AgentSandbox` type, so on
   `v1beta1` and `v1alpha1` alike (ADR-0049 decision 2):

   ```yaml
   status:
     egress:
       updatedAt: "2026-11-22T14:42:03Z"   # the broker's clock, at the write
       routes:                             # at most 32
       - gateway: gateway-02               # as the gateway named itself (ADR-0062 decision 3)
         kind: tunnel                      # tunnel | inject
         authority: pypi.org:443
         verdict: allow                    # allow | deny
         count: 14
         firstAt: "2026-11-22T14:40:11.204Z"   # the gateway's clock
         lastAt: "2026-11-22T14:41:58.469Z"
       - gateway: gateway-02
         kind: inject
         authority: api.anthropic.com
         audience: anthropic               # present when a route matched
         verdict: deny
         reason: not_allowed               # deny only
         count: 3
         firstAt: "2026-11-22T14:41:02.118Z"
         lastAt: "2026-11-22T14:41:40.007Z"
       overflow: 3                         # decisions folded that no entry counts
   ```

   - An entry's key is `(gateway, kind, authority, audience, verdict, reason)`; two decisions with
     the same key are one entry. `audience` is in the key because one authority can match more
     than one route; it is absent where ADR-0062 omits it (a tunnel, an inject with no route).
     `reason` is absent on an allow.
   - `count` is the number of decisions folded into the entry, saturating at 2^53 - 1. `firstAt`
     and `lastAt` are the smallest and the largest `at` among them, as the gateway stamped it.
   - `overflow` is the number of decisions folded into this summary that no entry counts: those
     whose key found no room and the counts of entries evicted (decision 4). So the sum of every
     `count` plus `overflow` is the number of decisions this summary has taken in. It is absent
     while zero.
   - `updatedAt` is when the broker last wrote the summary, on its own clock. A reader compares
     it with now to tell a quiet claim from a broker that stopped folding.
   - `served` from ADR-0062 (where the allowlist came from) is not carried: it is the gateway's
     cache behaviour, not the claim's egress, and it would split entries for no reader.
   - The list's order is `lastAt` descending, then the key; a reader must not depend on more.
   - No count of decisions lost before the broker heard of them: ADR-0062 counts a gateway's
     queue drops per gateway, not per claim, and sends the count nowhere but the gateway's log
     (open question 1). The summary is therefore a lower bound on the claim's egress, never a
     complete record.

3. **Coalesced, at most one write per claim per replica per five seconds.** The fold keeps a
   pending summary per claim, built the same way as the stored one. A replica writes a claim's
   pending summary when it has one and at least `egress_summary.every_secs` (default 5, minimum
   2) have passed since that replica's last write of that claim. Across the replica a writer
   task issues at most `egress_summary.writes_per_sec` (default 20) status writes; a claim it
   does not reach in a tick keeps its pending summary for the next. So the API server sees at
   most two writes per claim per five seconds with two replicas, and at most forty a second from
   the broker as a whole, whatever the gateways send. Nothing on the gateway's path, the
   decision's path or the request's path waits for any of it. `egress_summary.enabled: false`
   turns the fold off and leaves ADR-0062 exactly as it was.

4. **Bounded: 32 entries, and a workload cannot grow the object.** When a decision's key is not
   in a summary that already holds 32 entries:
   - if the summary holds a `deny` entry, the `deny` entry with the oldest `lastAt` is evicted,
     its `count` is added to `overflow`, and the new key takes its place;
   - otherwise (32 `allow` entries) the decision is added to `overflow` and no entry changes.

   An `allow` entry is never evicted to make room: allowed authorities are bounded by what the
   claim's policy lets through, so they are the stable part of the picture. Refusals are where a
   workload chooses the bytes, so a workload spraying hosts churns the refusals and shows the
   most recent ones, while `overflow` grows and says how much is not shown. The object's growth is
   bounded by the entry count and ADR-0062's field limits: under 16 KiB in the worst case. The
   same rule applies to a pending summary and to the merge of decision 5. The fold as a whole
   holds pending summaries for at most `egress_summary.max_claims` (default 4096) claims per
   replica; a decision for a claim past that is dropped and counted.

5. **Concurrency: compare-and-set on the resource version, re-read and re-merge.** A write is
   ADR-0057 decision 2's shape, applied to `status.egress` alone: read the sandbox, merge the
   replica's pending summary into the stored `status.egress` (counts add, `firstAt` is the
   minimum, `lastAt` the maximum, `overflow` adds, then decision 4's bound), and send a status
   merge patch that names `metadata.resourceVersion` as read and `status.egress` and nothing else.
   A `409` reads again and merges again, at most `MODIFY_ATTEMPTS` (4) times. Because the merge
   adds deltas, two replicas folding the same claim never overwrite each other: each adds what it
   holds to what is there. When the attempts run out, the pending summary is kept for the next
   tick (decision 3), not dropped. A pending summary is dropped only by decision 6, by the
   `max_claims` bound, or by the replica stopping; each drop is counted, and the count is logged
   once a minute while it is not zero, at `warn`, without claim UIDs.

   The record's writers and the mirror never name `egress`, and the fold never names `record`,
   the mirror's fields, or anything else. A unit test pins all three patches, as ADR-0057
   decision 5 pins the mirror's.

6. **A claim the broker cannot place is dropped; its log line stays.** The fold finds the sandbox
   with the store's lookup by claim UID (the hint cache, then the list). When no sandbox carries a
   record for the UID, the pending summary is dropped and the UID is remembered as unknown for 60
   seconds, so further decisions for it are dropped at the fold without another list. When the
   sandbox is being deleted (`metadata.deletionTimestamp` set), it is dropped too: the finalizer
   (`finalize_sandbox`, `crates/mediatore-claims/src/sandbox.rs`) is not raced for a view. A
   released record whose sandbox still exists keeps its summary and still takes the decisions
   that arrive late (a gateway's batch is up to two seconds behind): that is the end of the
   claim's story, and the fold does not touch the record. In every case ADR-0062's log line has already been written.

7. **The reconciler does not wake for it.** A status write is an event on the `AgentSandbox`
   watch, and the controller has no filter today (`crates/mediatore-claims/src/watch.rs`), so
   every fold would cost a reconcile on the Lease holder. The controller's watch gains a filter
   that drops an event whose object differs from the last one seen only in `status.egress` and
   `metadata.resourceVersion` (and `managedFields`). Whatever else changes still reconciles.

8. **The CRD gains the field, optional, in both served versions, with its bounds in the
   schema.** `status.egress` is added to `AgentSandboxStatus` (`crates/mediatore-claims/src/sandbox.rs`)
   and rendered into `deploy/base/crds/mediatore.io_agentsandboxes.yaml`, which by ADR-0049
   decision 2 copies it into `v1alpha1`. The schema states `maxItems: 32` and
   `x-kubernetes-list-type: atomic` on `routes` (the list is written whole), `maxLength` on each
   string as ADR-0062 decision 5 limits it, the two enums, and `minimum: 0` on the counts. It is
   additive and optional: an older broker leaves it absent and an older reader ignores it. The
   admission policy is unchanged: it already admits the broker alone to the status. No RBAC
   changes.

9. **Who reads it: whoever may `get` the sandbox.** That is the owner, a namespace reader the
   cluster grants `agentsandboxes` to, and an administrator; the base manifests aggregate no
   `AgentSandbox` read into `view` or `edit`, so each is a deliberate grant. No new route, no new
   authorization rule, no new store. The summary names the hosts the owner's own workload
   reached or tried, never a path, a query, a header or a credential. A namespace reader already
   sees the sandbox's spec (its policy) and its record (its node and its delegations' audiences),
   so the allowed authorities add little; the refused ones are new, and are the workload's
   choice (decision 4). That is accepted for a reader the cluster already trusts with the sandbox,
   and is the threat-model pass's to record (Consequences). A namespace that wants egress hidden
   from its readers narrows their grant to the sandbox, as it would for the record.

10. **The summary is attribution, not proof.** `gateway` is what a gateway said its name is
    (ADR-0062 decision 3), `firstAt` and `lastAt` are its clock, and anything holding the
    authorizer identity may report decisions that were not made. The summary decides nothing:
    no reconcile, no verdict, no token reads it, and a unit test pins that the store's record
    reader (`record_of`) never reads it. The complete record of a decision is the gateway's
    journal line; the broker's `info` line is the second copy; the summary is a bounded,
    lossy view of the second.

11. **OpenTelemetry is not the carrier, and a `traceparent` joins nothing.** The answer to "can
    we use OTel headers for tracing" is: not to correlate a claim, and not to carry its egress.
    - A `traceparent` Recess sends on `POST /v1/claims` is not trusted as a parent (I-6): the
      broker starts a new root and records at most a span link to it. It is never forwarded:
      not to the gateway, not to an audience, and the egress proxy and the inject listener strip
      any the workload sends (I-7). It cannot follow a claim's traffic, because nothing carries
      it there.
    - The join key across components is the claim UID. Recess reads it from the sandbox's
      `status.claimUid` (the answer to `POST /v1/claims` may come before the claim has one), and
      every span of roadmap 15 carries it as `mediatore.claim.uid`. A trace view of a claim is a
      query on that attribute.
    - When roadmap 15 lands, each folded decision may also be exported as a span event or a log
      record carrying `mediatore.claim.uid`, the kind, the verdict, the reason code and the
      audience. Not the authority: I-4 forbids a workload-chosen host as an attribute value, so
      OTel cannot carry what this view shows. And not as the source: OTel is an extra copy that
      may lose data (I-10, I-12); the UI reads the status.

## Consequences

- **A live view under existing RBAC.** Recess, `kubectl get agentsandbox -o yaml`, or any watch
  sees which gateways carried a claim, to which authorities, and what was refused, within about
  five seconds plus the gateway's two, with no new route, credential or store.
- **More writes to the API server and etcd.** At most two per active claim per five seconds,
  forty a second for the broker as a whole, each a status patch of under 16 KiB, and each a
  watch event to every watcher of the sandbox. A cluster with many busy claims raises
  `every_secs` or lowers `writes_per_sec`; one that wants none sets `enabled: false`.
- **More conflicts for the record's writers.** Each fold moves the resource version, so a
  `report`, an `exit`, a `refresh_session` or a bind decided just before it loses with a `409`
  and decides again (ADR-0057 decision 5). At one fold per five seconds per replica the second
  attempt almost always lands; a refresh that loses four times answers `503 record_busy` as it
  does today. ADR-0057 accepted that the mirror moves the version; this adds a second such
  writer, and the tests of ADR-0057 decision 6 gain a case with a fold landing between a read
  and a write.
- **A false report now writes state.** ADR-0062's "a false report changes no verdict and no
  state" no longer holds in full: a holder of the authorizer identity can put up to 32 entries of
  well-formed attribution into the status of any claim whose UID it knows, at the rate of
  decision 3. It cannot touch the record, the mirror's fields, or any other object (decision 5's
  patch), and it cannot make the object grow (decision 4). Unknown UIDs cost one list each per
  60 seconds (decision 6). The same identity already decides every tunnel.
- **Workload-chosen strings reach the status.** A refused authority is bytes the workload chose,
  within a `host[:port]` charset: no markup, no line breaks, at most 261 bytes. A reader that
  renders the summary renders it as text. A workload could use refused authorities as a narrow
  channel to the sandbox's readers; those are its owner and the people the cluster trusts with
  the sandbox, who can already read far more of it.
- **Losses are possible and counted.** A broker restart loses up to `every_secs` of pending
  folds; a full queue, the `max_claims` bound and decision 6 drop and count. The log line of each
  decision is unaffected. The summary is a lower bound, and the UI says so.
- **The threat-model pass is owed** before this is accepted, and it touches: §3 (a new asset on
  the status: the claim's destinations), TB-2 and TB-9 (a new status writer path and what it may
  name), TB-6 and A-28 (the authorizer identity's reach now includes a status write), §7 (the patch
  scope test, the schema bounds, the event filter) and §8 (the workload-to-reader channel of
  refused authorities, and namespace readers seeing destinations, each with a *Revisit when*).
- **CALM and docs.** The broker to Kubernetes API relationship gains the egress summary in its
  description (`docs/architecture/calm/architecture.json`); `docs/design/gateway.md` and
  `docs/design/broker-api.md` describe the fold. No new node or relationship.

## Alternatives rejected

- **A read route on the broker (`GET /v1/gateway/decisions`, or a stream, or ADR-0062 open
  question 1's `GET /v1/claims/{name}/egress`).** It needs a place to keep decisions, and with
  two replicas each holds half: a reader must ask both or see half, and a restart empties it. It
  needs an authorization rule of its own (owner, namespace, administrator) that RBAC on the
  sandbox already is, a new route on TB-1 to defend, and for "live" a long-lived connection per
  viewer. Recess already watches the sandbox.
- **An external log collector.** ADR-0062 already leaves it to operations, and it remains a good
  way to keep the complete record. It is not mediatore's: a deployment without one has no view,
  the owner never has one, and Recess would need credentials to a system outside the cluster's
  RBAC.
- **OpenTelemetry as the carrier.** I-4 forbids the authority as an attribute value, so OTel
  cannot carry the field the view is about; I-12 makes OTel a copy that may lose data, not the
  source a UI reads; and a backend's query permissions are not the sandbox's RBAC. Decision 11
  keeps it as an extra copy of the rest.
- **A propagated `traceparent` as the join.** Roadmap 15 rejected it: it makes a value a requester
  writes an input to the broker's tracing and gives the workload a way to attach to it. The
  claim UID is already on every side.
- **A separate object per claim (a `SandboxEgress` resource or a ConfigMap, owned by the
  sandbox).** It would not move the sandbox's resource version, so no extra conflicts for the
  record's writers and no event filter. It costs a second resource for Recess to watch and join,
  RBAC and an admission policy of its own (or it is writable by whoever may write ConfigMaps in
  the namespace), an object to create and garbage-collect per claim, and a second place a
  reader must be granted. The conflicts it saves are rare at decision 3's rate.
- **Kubernetes Events on the sandbox.** They aggregate repeats, but by message text, expire
  after an hour by default, are rate-limited by the API server, need `events` read RBAC, and
  would make the UI parse a message. They are a history, not a current summary.
- **A write per decision, or per batch.** The rate would follow the workload's traffic, which is
  the workload's choice. Coalescing makes it follow the clock.
- **Server-side apply, one entry per replica, no precondition.** Each replica would own its own
  sub-summary and never conflict with the other. Pod names change on every restart, so dead
  replicas' entries stay until something prunes them, the reader must sum, and the record's
  writers conflict all the same. Compare-and-set with an additive merge gives one summary for the
  same cost.
- **Unbounded routes, or evict the oldest entry whatever its verdict.** Unbounded lets a workload
  grow the object to etcd's limit. Evicting allows lets a spray of refused hosts push the
  claim's real destinations out of view.

## What must be proven

- The `204` of `POST /v1/gateway/decisions` does not wait on the fold: a fold whose store blocks
  leaves the route's latency unchanged, and a full fold queue drops and counts.
- Two replicas folding the same claim concurrently, on the fake API server and on kind: the sum
  of `count` plus `overflow` equals the decisions accepted by both, with no `409` lost.
- The bound: 10 000 distinct refused authorities leave 32 entries, every `allow` entry intact,
  and `overflow` equal to the rest.
- The patch scope: the fold's patch names only `status.egress` and the resource version; the
  mirror's and the record's patches never name `egress`; `record_of` never reads it.
- A fold landing between a record writer's read and write makes that writer decide again and
  succeed (ADR-0057 decision 6's suite, both stores).
- The event filter: a sandbox changed only in `status.egress` is not reconciled; one changed
  elsewhere is.
- An unknown claim UID costs one list per 60 seconds, however many decisions name it; a deleting
  sandbox is not written.
- The CRD renders the field in both versions with its bounds, and the API server refuses a
  33-entry list.

## Open questions

1. **Losses the broker never hears of.** A gateway's queue drops (ADR-0062 decision 4) are
   counted per gateway and logged there. Carrying a per-claim drop count in the batch (a
   `dropped` map in `GatewayDecisions`) would let the summary say how incomplete it is, at the
   cost of a per-claim counter on the gateway and a change to ADR-0062 decision 2. Left out until
   a reader needs it; the summary is a lower bound either way.
2. **Defaults under load.** Five seconds and twenty writes a second are a guess for tens of busy
   claims. The kind tier should measure the API server's cost at a few hundred before the
   defaults are accepted.
3. **A gateway's identity of its own** (ADR-0062 open question 2) would make `gateway`
   authenticated rather than claimed. Nothing here depends on it; the field would keep its name
   and shape.
