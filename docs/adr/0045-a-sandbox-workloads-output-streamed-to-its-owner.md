<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0045: A sandbox workload's output, redacted in the VM and streamed to its owner

**Status:** Accepted and implemented 2026-11-17 (proposed the same day; amended at implementation: the capture is a per-sandbox opt-in, `workload.logs`, beside the broker's `logs.enabled`, and decisions 2, 9, 11 and 12 say what was built where it differs from the proposal) · **Date:** 2026-11-17

Roadmap 06 (the guest) and roadmap 08 (the `AgentSandbox` CRD). Adds routes to both APIs
beside `POST /v1/me/exit` ([ADR-0033](0033-a-one-shot-workload-the-restart-policy-and-the-claim-released-when-it-is-done.md))
and `GET /v1/claims/{name}`, and a new kind of object to the broker's store
([ADR-0034](0034-the-kubernetes-api-as-the-brokers-store.md)). Changes no identity, no token
shape and no SPIFFE ID. It adds one boolean to the `AgentSandbox` spec (`workload.logs`, the
requester's opt-in; decision 12). It does move workload-produced data across TB-6 in the
direction VM to broker, and it makes the broker a holder of data the workload chose to print,
which the threat model absorbs (TB-1, TB-6 and TB-9 rows, R-38 and R-39).

## Context

`mediatore sandbox create` starts a workload and the only result a requester can read back is
the exit code (`status.record.exit`, reported by the guest with `POST /v1/me/exit`,
ADR-0033 decision 2; `crates/mediatore-guest/src/report.rs`, handler `exit` in
`crates/mediatore-api/src/lib.rs`). Nothing captures what the jailed workload prints. The
guest spawns `nsjail` with the inherited stdio (`crates/mediatore-guest/src/supervise.rs`,
`tokio::process::Command::new("nsjail")` with no `Stdio` set), so stdout and stderr land on the
VM console and nowhere else; the operator's testing guide says as much (the workload's stdout is
only visible on the VM console). A one-shot agent (`restart: never`) whose answer is its
output is therefore unusable by anyone but an operator with console access to the hypervisor.

The shape of the answer is constrained from outside. banlieue ADR-0082 gives a sandbox no
inbound access, so there is no exec, attach or logs-over-the-network into the VM, and mediatore
does not ask for one. The channel that exists is the one the guest already uses: node SVID
mTLS to the broker's sandbox API (`POST /v1/me/report`, `POST /v1/me/exit`, `GET /v1/me`),
outbound from the VM through the control relay (ADR-0027; ADR-0029, ADR-0037).

The data is hazardous in a way the exit code is not. A workload is handed credentials in
several forms (the phantom token it presents to the egress proxy, ADR-0025 and
[ADR-0040](0040-the-gateway-places-an-audiences-credential-the-pool-never-holds-it.md);
environment values the requester asked for; tokens the egress proxy fetched for it with
`POST /v1/token`, since ADR-0025 decision 5 the jail has no route to the broker), and a
workload, or a library it calls in debug mode, can print them. The broker also keeps its
records in the Kubernetes API (ADR-0034), where an object is capped near 1 MiB by etcd and
every write is replicated, so unbounded output cannot simply be appended to the claim.

## Decision

The in-VM `mediatore-guest` (root, the parent of the jail) tees the workload's stdout and
stderr, redacts them, and ships them to the broker over the node SVID. The broker stores a
bounded copy and serves it to the claim's owner. Four layers are required; each is a numbered
decision with its control, its home and its proof.

**Two switches, both off by default.** The requester opts a sandbox in with
`workload.logs: true` (`--logs` on `mediatore sandbox create`, `logs: true` under `workload`
on `POST /v1/claims` and on `spec.workload` of an `AgentSandbox`); the operator turns the
store on with `logs.enabled: true` in `mediatore.yaml` (decision 11). A sandbox that does not
opt in runs exactly as before: the guest spawns the jail with inherited stdio, nothing is
captured, redacted or shipped, and the owner's `logs` read is an empty stream. A sandbox that
opts in on a broker whose store is off is refused before any claim exists (`501
not_implemented` at `POST /v1/claims`; `Failed` with the reason at reconcile for a declarative
one), never run with its output silently dropped. The opt-in is per sandbox because the
output is the requester's data and its capture a cost they choose, and because an agent
whose task involves confidential material should be able to say that nothing it prints
leaves the VM.

1. **Capture and ship (guest, `crates/mediatore-guest/src/logs.rs`, `supervise.rs`).** When
   `GET /v1/me` says `workload.logs`, `supervise::run` spawns `nsjail` with `Stdio::piped()`
   on stdout and stderr and adds `--quiet`: nsjail writes its own diagnostics to its stderr,
   which under capture is the workload's pipe, so its informational lines are silenced and
   only its warnings and fatal messages (a refused mount, a confinement failure) reach the
   owner as stderr records, which is wanted. Without the opt-in nsjail runs exactly as before. Two reader tasks drain the pipes line by line
   (a line over 64 KiB is split) and each line is passed through the redactor (decision 2),
   written through to the VM console as today (the operator's view is unchanged), and queued
   as a record `{seq, stream, ts, text}`. `seq` is a per-claim `u64` assigned in the order
   the guest's readers produced the records. A batcher posts the queue to the broker every 2
   seconds or at 32 KiB, whichever comes first, with `POST /v1/me/logs` (decision 9).
   Proof: a unit test of the supervisor with a fake child that writes to both streams and a
   fake broker client that records the batches.

2. **Redaction at the guest, before output leaves the VM (`crates/mediatore-guest`, a
   `redact` module).** Redaction is best effort, not a guarantee, and is documented as such in
   the CLI help, the guide and the threat model. What is redacted, replaced by the literal
   `[REDACTED]`:
   - the exact value of every secret the guest placed in the jail: the phantom token, and
     every environment value the guest marks secret-bearing when it builds the jail
     environment (a new `JailSpec::env`; today `JailSpec` in `crates/mediatore-guest/src/jail.rs`
     has no such field and the environment is built from `phantom` and `proxy_port`), each
     matched literally and also in its standard base64 and percent-encoded forms;
   - by shape, whatever the set does not know: a JWT (three base64url segments, the first
     starting `eyJ`), an `Authorization: Bearer|Basic <value>` header value, and a PEM block
     from `-----BEGIN ... PRIVATE KEY-----` to its `END` line.

   Matching is per whole line (`redact.rs`): the reader redacts the line and splits an
   overlong one after, so a secret inside a line is caught however the pipe was read; a PEM
   block is dropped from its `BEGIN` line on, until its `END` line or the end of the output,
   since a partial key must not leak. The tokens the egress proxy obtains from the broker
   (`POST /v1/token`) are not in the literal set: since ADR-0025 they live in the proxy's
   process and never in the guest's, and handing them to the guest for matching would be a
   second holder of every downstream token. They are caught by shape (a JWT, an
   `Authorization` value), which covers what the configured backends issue; an opaque
   non-JWT token printed bare by the workload is not, and that is one of the stated limits
   below.
   Values under 8 bytes are not added to the literal set (a short environment value would
   redact ordinary words and teach users to distrust the tool); the shape rules still apply.
   What it cannot catch: a secret the workload transforms (split across lines or writes,
   hex or reversed, encrypted, hashed to something still useful), a credential the guest never
   saw (one the workload derived or fetched itself from a destination the policy allows), and
   personal or proprietary data that is not a credential at all. The consequence for the threat
   model is a stated one: **redaction reduces the exposure, it does not bound it**, so the
   security argument must not rest on it. What bounds the exposure is decision 5 (the output is
   readable only by the principal the credentials were issued for) and decision 4 (a cap and a
   TTL). A secret that escapes redaction reaches the claim's owner, who is already entitled to
   the claim's credentials, and the broker's Secrets, which are already the broker's trust
   domain (ADR-0034 decision 2). The threat model records that as an accepted risk (R-38) with a
   *Revisit when* of "output is readable by anyone but the owner". Proof: the unit tests of
   `redact.rs` (each rule, the PEM case, the short-value exemption, a secret containing
   another) and of `logs.rs` (a known phantom fed through the reader is absent from the queued
   records; every credential-bearing key `JailSpec::env()` emits has its value in
   `JailSpec::secret_values()`, so a new credential cannot be placed unredacted).

3. **Ordering and interleaving.** stdout and stderr are two pipes, so their true interleaving
   is not recoverable; the guarantee is per stream, in order, plus the arrival order at the
   guest's readers (`seq`), which is what `logs` prints. Each record carries its stream, and the
   CLI prints stderr lines unmodified to stderr and stdout lines to stdout, so `2>&1` merges
   them the way a terminal would. A pty was considered and rejected (Rejected below).
   Text is lossy UTF-8 (invalid bytes become U+FFFD) so the wire stays JSON. A gap (decision
   8) is a line of its own between the records, `{lost_stdout, lost_stderr}` (`LogGap`,
   `crates/mediatore-proto`), stored and served where it happened.

4. **A size cap per claim and a TTL, at the broker (`crates/mediatore-claims`,
   `crates/mediatore-api`, `mediatore.yaml` under `logs:`).** The store keeps the newest
   `logs.max_bytes` per claim (default 1 MiB, hard ceiling 4 MiB; a config above the ceiling is
   refused at startup) and drops the oldest records beyond it, a ring. A reader is told the
   output was truncated (the first record it gets has a `truncated_before` count and the
   response carries the dropped byte count). A batch over 256 KiB is refused `413`, and a node
   is limited to one batch per second per claim (`429` with `Retry-After: 1`; the guest honours
   it), so a workload cannot turn the broker into a write amplifier. The TTL is
   `logs.retention_secs` (default: the ended claim's retention window of ADR-0034,
   `store.retention_secs`); the leader's resync sweeps expired output (`Watcher::resync`,
   `crates/mediatore-claims/src/watch.rs`, calling `sweep_logs`). Output of a live claim cannot
   outlive the claim's deadline plus that window. The ring is behind a trait, `LogStore`
   (`crates/mediatore-store/src/lib.rs`, required by `ClaimStore` so the one store object
   serves both), with the limits passed on every append (`LogLimits`) so the store holds no
   setting. Proof: the store conformance suite (`crates/mediatore-store/src/conformance.rs`)
   that overfills the ring and sees the oldest dropped and the count right, and the sweep
   cases; e2e for `413` and `429`.

5. **RBAC: only the claim's owner reads it (`crates/mediatore-api`).** The route
   `GET /v1/claims/{name}/logs` (decision 9) goes through the same check as
   `GET /v1/claims/{name}`: the caller's validated token must carry the issuer and subject
   recorded on the claim (`rec.subject`, or `spec.subject` of the `AgentSandbox`), else
   `403 forbidden` with the same message as today. There is no role, group or scope that
   widens it. Specifically:
   - **Declarative requesters** (a sandbox written with `kubectl`, whose `spec.subject` the
     admission policy sets to the Kubernetes identity that wrote it) can read the output only
     by presenting a mediatore token whose subject equals `spec.subject`. A Kubernetes
     identity has no such token, so in practice they cannot read it through the broker, and
     this ADR does not give them a `kubectl` path: the output is stored in Secrets only the
     broker's ServiceAccount may read (decision 6). This is the fail-closed reading, and the
     open question below asks whether it is wanted.
   - **Brokers and admins** have no API override: the broker's own identity does not
     appear on the user route, and no admin audience or group is introduced. An operator with
     cluster-admin on the broker's namespace can read the Secrets directly; that is break-glass,
     visible in the Kubernetes audit log, and recorded as an accepted risk, not a mediatore
     feature.
   - **The node** can write its claim's output (decision 9) and read none of it.
   - Where output storage is not enabled (decision 11), the route is
     `501 not_implemented` for everyone.

   Proof: e2e in `crates/mediatore/tests/e2e_dev.rs` with the negative cases the repo's testing
   rules ask for: another subject (`403`), no token (`401`), a node SVID on the user route, a
   user token and a claim SVID on the node route, and a released claim (the owner still reads
   inside the retention window; a non-owner still does not).

6. **Where the output is stored: Secrets, owned by the `AgentSandbox`, in 64 KiB segments.**
   The broker writes the output to a ring of Secrets in its own namespace, named by the
   sandbox's UID and a segment number, labelled with the claim's UID and a kind label, each an
   owner reference to the `AgentSandbox` so they are garbage-collected with it (as the session
   Secret is, ADR-0034 decision 2). A segment is at most 64 KiB, the ring has `max_bytes / 64
   KiB` of them at most, and the broker appends to the open segment, rolls to a new one at the
   limit and deletes the oldest beyond the cap. A write conflict (two replicas, ADR-0034's
   leader and followers both accept the node's calls) is retried on `resourceVersion`. Writes
   are batched by the guest (decision 1), so a claim causes at most one object write about
   every 2 seconds, bounded again by the rate limit of decision 4. Reasons, against the
   alternatives:
   - Secrets, not ConfigMaps: the output may hold what redaction missed, so it takes the
     protection the session Secrets already have (encryption at rest where the cluster has it,
     RBAC separate from ConfigMaps' wide read grants), and the broker's Role already covers
     Secrets in its namespace.
   - Not the `AgentSandbox` status: the whole object is capped near 1 MiB, every status patch
     rewrites it, and status is readable by whoever may `get` sandboxes in the namespace
     (banlieue RBAC), a far wider audience than the owner.
   - Not broker memory: the broker runs two replicas (`deploy/base/deployment.yaml`) and the
     owner's read may land on the replica that did not take the write; a restart loses it.
   - Not a database, an object store or a PVC: each is a new dependency, exactly what
     ADR-0034 removed.
   The cost is real and accepted: etcd holds up to 4 MiB per live claim at the ceiling and
   about 1 MiB at the default, at one write per two seconds while the workload prints. The
   defaults are sized for a one-shot agent's output, not for a build log; a workload that
   needs more should use the egress to ship its own logs. *Revisit when* output volume, not
   correctness, is the complaint: the store sits behind a small trait, so an object store can
   replace the Secrets without changing a route. As built (`KubeStore`,
   `crates/mediatore-claims/src/kubestore.rs`): Secrets `mediatore-logs-<claim uid>-<segment>`
   labelled `mediatore.io/logs=segment`, `mediatore.io/claim-uid` and
   `mediatore.io/sandbox-uid`, the entries as NDJSON in `data`, the ring's counters as
   annotations; trimming is by whole segment, so what the owner is told was dropped is
   counted in 64 KiB steps, never less than what went.

7. **Released claims, and no tail in `status.record`.** Releasing a claim (the owner's
   `DELETE`, the deadline, a workload exit under ADR-0033) does not delete the output: the
   `AgentSandbox` is held for the retention window (ADR-0034 decision 1), the Secrets live as
   long as it does, and the owner can read the output of a finished claim until then, which is
   the whole point for a one-shot workload. When the `AgentSandbox` is garbage-collected so are
   the Secrets; the leader's sweep also removes any orphan by its kind label. A late batch
   after release (the guest flushing as the claim ends) is accepted from the bound node until
   the claim is released and answered `204` and dropped after, like a late exit
   (ADR-0033 decision 2). No bounded tail goes into `status.record` or `WorkloadExit`: status
   is readable by far more principals than the owner (see decision 6), the redaction caveat
   makes copying output into the widest-readable object the wrong place to be wrong, and the
   store above already serves the post-mortem. The exit code stays the only workload result on
   the record. If the store is unavailable for a read, the owner gets `503`, never a stale or
   partial success.

8. **Backpressure and loss: the workload never waits for mediatore, and loss is counted, not
   hidden.** The guest's reader tasks always drain the pipes, so a slow or unreachable broker
   cannot block a workload on a full pipe. Records are queued in the guest up to 1 MiB; beyond
   that the oldest queued records are dropped and a per-stream `dropped` byte count is kept and
   sent with the next batch, so the reader sees an explicit gap (`[N bytes lost before this
   point]`), not silence. A failed post is retried with capped exponential backoff (1 s to 30
   s) and the same `seq` range, which the broker accepts idempotently (a batch whose records are
   all at or below the claim's highest stored `seq` is a `204` no-op). On workload exit the
   guest flushes, bounded to 5 seconds, **before** it posts `POST /v1/me/exit` (the exit
   releases the claim), and tears down whether or not the flush completed, as it does for the
   exit today. `501 not_implemented` from the node route (feature off) makes the guest stop
   shipping and keep the console copy, one `info` line. Delivery is therefore at-least-once
   with idempotent writes and bounded, counted loss; it is not a durable log, and the guide
   says so.

9. **The wire, and the CLI.**
   - **Node API (node SVID, `crates/mediatore-proto`, `crates/mediatore-api`):**
     `POST /v1/me/logs` with `LogBatch { records: Vec<LogRecord>, dropped_stdout: u64,
     dropped_stderr: u64 }` and `LogRecord { seq: u64, stream: LogStream (stdout|stderr),
     ts: Timestamp, text: String }` (jiff's `Timestamp`, as built in `crates/mediatore-proto`).
     The node must be the one the claim is bound to (`claim_of_node_peer`, as `exit` does);
     another identity is refused. `204` on accept
     (including a late batch, dropped), `413`, `429`, `400` for a malformed batch (a `seq` not
     strictly increasing, a record over 64 KiB) and `501 not_implemented` when the feature is
     off. The broker re-validates sizes and does not trust the guest's redaction to be present;
     it does not redact again (it cannot know the secrets), and says so in a doc comment.
     A batch for a claim that did not opt in is `400 logs_not_requested`.
   - **User API (user token, same audience and gate as the other user routes):**
     `GET /v1/claims/{name}/logs?follow={bool}&since={seq}&tail={n}` (and `namespace`, as the
     other claim routes, ADR-0046), answered as `application/x-ndjson`: the first line a
     `LogHeader { truncated_before: u64, claim_phase }`, then one `LogRecord` or `LogGap` per
     line in sequence, and a last line `{"end": true, "reason": "claim_ended" | "ttl" |
     "client"}` when the stream finishes (`LogLine`, `crates/mediatore-proto`, is the union
     the CLI parses). Without `follow` it returns what is stored and ends (`client` on a live
     claim, `claim_ended` on one that ended); with `follow` it streams until the claim ends,
     the reader goes, or the broker is drained, and sends an empty line every 15 seconds so
     proxies do not cut it. As built the follower re-reads the store every two seconds (the
     guest's batch cadence) rather than watching the segment Secrets, which the proposal had
     said: a watch per follower against the API server was more machinery than the first
     release needs, and the store trait does not fix the mechanism. `tail=n` limits to the
     last `n` records. A `follow` on a claim that has ended returns the stored output and
     ends; a record swept mid-follow ends the stream with `ttl`.
   - **CLI (`crates/mediatore-client`):** `mediatore sandbox logs [-f|--follow] [--tail <n>]
     [--since <seq>] [--timestamps] <claim>`. It prints stdout records to stdout and stderr
     records to stderr, so a shell can split them; a truncation or a gap is one line on stderr,
     and its exit status is `0` when the stream ends cleanly (the workload's exit code stays on
     `sandbox get`). With `-f` Ctrl-C ends the read, not the claim.
   - The CLI help says redaction is best effort and the output is kept for a bounded time.

10. **Audit: an entry for every read, never the content (`crates/mediatore-api`).** Each
    request to the user route logs, at `info`, `claim_uid`, `subject` (the caller's, as
    validated), `name`, `follow`, `since`, `tail`, and on completion `bytes_sent` and
    `records_sent` and `duration_ms`; a refusal logs at `warn` with the reason (`forbidden`,
    `no_claim`, `not_implemented`). The line is made before the first byte is sent, so a read
    that is cut off still leaves an entry, and a follow logs once at the start and once at the
    end. Content, and anything derived from it, is never logged: no text, no excerpt, no
    hash, no first line. The writes (node batches) log `claim_uid`, `records`, `bytes` at
    `debug`, and a rate-limit or a truncation at `info`. Proof: a test that captures the
    tracing output of an e2e read and asserts the entry carries the claim UID and subject and
    that none of the printed text appears in it.

11. **Configuration and fail closed.** `logs.enabled` (default `false`), `logs.max_bytes`
    (default 1 MiB, floor one 64 KiB segment, ceiling 4 MiB), `logs.retention_secs` (default
    `store.retention_secs`) in `mediatore.yaml` (`LogsSection`, `crates/mediatore/src/config.rs`),
    with the refusals of decision 4 at startup. Disabled, both routes answer `501
    not_implemented`, a `POST /v1/claims` with `workload.logs: true` is refused `501` before
    anything is created, a declarative sandbox with it is `Failed` at reconcile with the reason
    (`Watcher::refuse`, `crates/mediatore-claims/src/sandbox.rs`), and the guest keeps the
    console copy; the broker's Role is unchanged by merely deploying this release and the CRD
    gains one optional boolean (decision 12). A sandbox that did not opt in has nothing
    captured whatever the broker's setting. In `dev_mode` the
    `MemoryStore` gets an in-memory ring with the same cap, TTL and ownership rules (the fake
    must be no more permissive than the real thing, `.claude/rules/testing.md` rule 2); the dev
    binder's behaviour is otherwise unchanged. A node route used when the broker does not know
    the feature is a `404`, which the guest treats like `501`.

12. **The CRD and banlieue.** One optional field, `spec.workload.logs` (boolean, default
    false), the requester's opt-in, immutable with the rest of the spec and rendered into
    `deploy/base/crds/mediatore.io_agentsandboxes.yaml` by `make crds`; no status field
    changes and no banlieue-side change is needed. The output lives in Secrets keyed by the
    claim's UID, outside the resource; `status.record.exit` is unchanged; `banlieue-api`
    types, the `VirtualMachineClaim` and the pool are untouched. The only deploy change is in
    mediatore's own manifests: the broker's Role already creates, updates, lists, watches and
    deletes Secrets in its namespace (ADR-0034), so the new label and segment names need no new
    verb; the guide states which broker release the node routes need (an older broker answers
    `404`, which the guest treats as off).

## Consequences

- A requester can run `mediatore sandbox create --logs ... && mediatore sandbox logs -f <claim>`,
  and read a finished one-shot workload's output for the retention window. Nothing about inbound
  access to the sandbox changes (banlieue ADR-0082): the VM only initiates, over the channel
  it already has.
- New code: `Workload.logs`, `LogBatch`, `LogRecord`, `LogGap`, `LogEntry`, `LogHeader`,
  `LogEndLine`, `LogLine`, `LogStream` and the limits (`crates/mediatore-proto`); the capture,
  the `redact` module and the shipper (`crates/mediatore-guest/src/logs.rs`, `redact.rs`,
  `supervise.rs`); the `LogStore` trait and the memory ring (`crates/mediatore-store`), the
  Secret ring (`crates/mediatore-claims/src/kubestore.rs`) and the sweep (`watch.rs`);
  `POST /v1/me/logs`, `GET /v1/claims/{name}/logs` and the `logs:` config
  (`crates/mediatore-api`, `crates/mediatore/src/config.rs`); `--logs` and `sandbox logs`
  (`crates/mediatore-client`).
- The broker now holds workload-produced data that may contain secrets the redactor missed,
  for up to the retention window, and etcd carries up to 4 MiB per claim. The threat model
  carries: TB-6 rows (a node writing output, bounded by the node's own claim, the opt-in,
  size and rate), TB-1 rows (the owner reading, the subject check, the refusal when the store
  is off), TB-9 rows (the Secret ring, its labels and garbage collection), R-38 (redaction is
  best effort) and R-39 (a cluster administrator can read the segments). No unremediated
  finding is recorded here; this ADR states design limits, not a vulnerability.
- The guest's redaction set is only as good as its list of what the jail was given. Every new
  way of placing a credential (a new audience backend, a new delegated secret) must add its
  value to the set; a test that fails when a credential-bearing environment key is not marked
  secret-bearing is part of the implementation.
- Not source compatible for the guest's `supervise::run` (it takes the capture and owns the
  pipes when there is one), and wire compatible for everything else: an old guest never
  calls the new routes and ignores `workload.logs`, an old broker answers them `404` and
  drops the unknown field, an old CLI has no `logs` command.
- Not done here: a log of the guest's or the egress proxy's own diagnostics (operators have the
  console and the pool's logging); search, structured fields or per-line timestamps from the
  workload; a durable or long-term log; any admin or cross-subject read.
- Rejected:
  - **Exec, attach or a logs endpoint on the VM**, a pull from the broker into the sandbox:
    contradicts banlieue ADR-0082 (no inbound) and adds an inbound credential to the pool.
  - **A pty for the workload** (exact interleaving): the workload sees a terminal (colour,
    buffering and prompts change), the stream tag is lost, and the jail's confinement of the
    controlling terminal is a new surface.
  - **Redaction at the broker only**: the broker never holds the phantom or the delegated
    secrets in a form it can match, and the VM-to-broker hop would carry the unredacted data.
  - **The guest writing the output to the `AgentSandbox` status**: the node has no Kubernetes
    identity and should not get one (ADR-0033 rejected the same), and see decision 6.
  - **A tail in `status.record`**: decision 7.
  - **Broker memory, a PVC, a database or an object store** as the store: decision 6.
  - **A role that lets operators or admins read through the API**: it would be a standing
    cross-subject read of data redaction cannot clean; the break-glass is the cluster's.
  - **Drop-newest on a full queue**: the end of the output (the answer, the error) matters
    more than the start.

## Open questions

- Should a declarative requester (a sandbox applied with `kubectl`) be able to read output at
  all? Decision 5 says not through mediatore until their token subject matches; an option is
  an annotation on the sandbox naming an OIDC subject allowed to read, set at admission. The
  opt-in field does not answer this: a declarative sandbox may set `workload.logs: true` and
  its output is then stored and readable by nobody through the API until it is swept, which
  is the fail-closed reading. Roadmap 13's design is where it belongs.
- The defaults (1 MiB, 4 MiB ceiling, retention equal to the claim's) are set, not measured;
  a live run with a chatty agent (the research agent of `docs/guides/research-agent-walkthrough.md`
  with `--logs`) should confirm them, and the two-second re-read of a follower should be
  watched against the API server's request rate with several followers.

## Follow-on work

- [x] CALM: the log flow (guest to broker over the node route, the Secret ring in TB-9,
      the user read route) in `docs/architecture/calm/architecture.json`.
- [x] Tests first (`.claude/rules/testing.md`): redactor units; capture, queue and shipper
      units; the store conformance (ring, cap, replay, gap, cursor, sweep); e2e in `e2e_dev.rs`
      with the negative cases; an audit line test asserting no content is logged; the
      secret-bearing environment key test.
- [x] Decisions 1 to 12 implemented; `make check`.
- [x] Docs: README status table, `docs/guides` (requesting a sandbox, running workloads, the
      store, testing), the `logs:` block in the example configurations.
- [x] Threat-model full pass (2026-11-17), stamp bumped to this ADR.
- [ ] A live run with `--logs` on the core cluster (a release carrying the node routes), and
      the defaults measured against it.
