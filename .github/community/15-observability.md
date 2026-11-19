<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 15: Observability (OpenTelemetry) that never weakens security or speed

**Status: not started** (opened 2026-11-19). Traces, metrics and exported logs for every component on the path a
sandbox takes: the user API, the sandbox API, the reconcilers, the store, the token backends, OpenBao, the gateway
(Envoy and the authorizer), the guest, the egress proxy and the boot of a pool VM. The order of priorities is fixed and
is the whole point of this roadmap:

1. **Security.** No telemetry signal may carry a credential, open a listener, add a network route, give the workload a
   channel, or be trusted as input. Where a signal and a security property conflict, the signal is dropped.
2. **Speed.** Telemetry is off the request path: nothing awaits an exporter, every queue is bounded and drops when
   full, and the cost of a disabled callsite is what `tracing` already pays today.
3. **Insight.** Only then, what we can see.

Depends on roadmap 01 (SVIDs, for authenticated export), roadmap 10 (the gateway) and roadmap 05 (the store, so the
lifecycle has stable claim UIDs). Touches ADR-0010 (no inbound to sandboxes), ADR-0014 (one binary), ADR-0028 (the
gateway, no admin interface) and ADR-0045 / ADR-0052 (workload output, which is **not** telemetry).

## Where it is today

- Every role logs through `tracing_subscriber::fmt()` to stderr (`crates/mediatore/src/main.rs`), filtered by
  `RUST_LOG`. No spans are exported, no metrics exist, no `#[instrument]` is used, and no trace context
  (`traceparent`) is read or sent anywhere.
- The audit lines (one per token issue, per claim create, per log read, per sweep; `crates/mediatore-api/src/lib.rs`)
  are the system of record, and tests capture them to prove a credential is never logged (ADR-0040).
- Secret types redact their `Debug` (`Secret` in `crates/mediatore-proto/src/lib.rs`, `Phantom`, `TransitSealer`,
  `ClientAssertion`, `Validator`, the OpenBao `Client`).
- Envoy on the gateway writes one access-log line per tunnel to stdout and has **no admin interface** (ADR-0028); its
  stats are therefore unreadable today.
- The guest's view of a claim (attest, register, pull, unpack, ruleset, jail) exists only in the VM's journal.

## The invariants

These are the acceptance criteria of every phase, written before any code. A change that cannot meet one does not
ship that signal.

| # | Invariant | How it is enforced (not merely intended) |
| --- | --- | --- |
| I-1 | **No secret in any signal.** Tokens, refresh material, phantoms, passwords, assertions, private keys, envelopes, `Authorization` and `Cookie` values never appear in a span, an event, a metric label or an exemplar | Three layers: secret types have no `Display` and a redacting `Debug` (existing); an **allowlist export layer** drops every field whose key is not in the closed schema (I-3); a **canary test** plants known secret values on every path and scans every exported signal for them (phase 1) |
| I-2 | **No new listener, anywhere.** No `/metrics` endpoint, no Envoy admin, no zPages, no pprof | Push only (OTLP). A test asserts the broker's bound sockets are exactly today's set with telemetry on; the gateway's `check.sh` asserts no admin block |
| I-3 | **A closed attribute schema.** Exported attributes are drawn from one enum in `mediatore-telemetry` (claim UID, SPIFFE ID, audience, backend, issuer name, namespace, pool, result, error code, phase, HTTP method and route template). Anything else is dropped at export, not at the callsite | The export layer, plus a unit test that the schema has no key matching `token\|secret\|password\|key\|auth\|cookie\|refresh\|assertion` |
| I-4 | **Workload-controlled bytes never become attribute values.** A refused host, a path, a header, an image tag, a log line, an upstream's error text: never. Only our enums, counts and durations | The schema's value types: a refusal is `error.code=host_not_in_routes`, not the host. Attributes from free text do not compile (the setters take enums or validated identifiers) |
| I-5 | **Foreign errors are not exported as text.** `Display` of a `kube`, `reqwest`, OpenBao or IdP error stays in the local stderr log; the exported signal carries our error code | Exported events carry the callsite's name and allowlisted fields, never the formatted message (I-3's layer) |
| I-6 | **Incoming trace context is not trusted across a boundary.** `traceparent` and `tracestate` from a user (TB-1), a declarative requester, the workload or a destination start nothing: the broker begins a new root and at most records a span link. W3C **baggage is never read or sent** | A propagator that is a no-op on extract at every external listener; e2e test: a request carrying `traceparent` and `baggage` produces a root span with a fresh trace ID |
| I-7 | **Trace context never leaves the trust domain.** No `traceparent` to an IdP, Entra, OpenBao's public paths, a registry or an audience; the egress proxy and the inject listener strip any the workload sent | Outbound clients built without a propagator; the egress proxy and `inject.yaml.in` remove `traceparent`, `tracestate`, `baggage`, `b3`, `x-b3-*`, `x-cloud-trace-context`; tests on both |
| I-8 | **No new route from a pool VM or a jail.** The guest and the egress proxy never dial a collector. Their signals ride the node SVID to the broker through the relay leg that already exists (ADR-0027), or they are not sent | The pool ruleset (ADR-0020, ADR-0029) is unchanged by this roadmap, asserted by `image/check.sh`; the jail emits nothing at all |
| I-9 | **Authenticated, encrypted export.** OTLP over HTTP/protobuf (no gRPC, see below), TLS 1.3 on aws-lc-rs, mutual TLS with the component's SVID, the collector's SPIFFE ID pinned. No bearer in an environment variable, no plaintext, no `insecure` | `Config::parse` refuses an `http://` endpoint, a missing collector SPIFFE ID or an unknown key, and the process does not start (fail closed on configuration) |
| I-10 | **Telemetry failure never fails a request.** An exporter that is down, slow or refusing costs a dropped batch and a counter, never a blocked task, a retry storm or a `5xx` | Bounded batch queues with drop on full, an export timeout, exponential backoff with a cap; a test with a black-hole collector shows the token path's latency unchanged |
| I-11 | **Off by default.** No `telemetry` section means no exporter, no extra task, no extra allocation. `dev_mode` may use a stdout exporter; nothing else may | Default config tested; the CLI (`login`, `sandbox`, `session`) **never** exports anything, on or off |
| I-12 | **Audit stays where it is.** The audit lines remain on stderr and stay the record; OTel is an extra copy that may lose data, never the source of truth | Existing audit tests unchanged; no audit line moves behind the export layer |
| I-13 | **A person's identity is not exported by default.** The token `sub`, email and groups stay in the audit log. `telemetry.include_subject` (default `false`) is the operator's explicit choice, recorded in the threat model | Schema gate on the subject key, off unless configured; test |
| I-14 | **Bounded cardinality and memory.** Claim UID, subject and SPIFFE ID are span attributes only, **never metric labels**. Every metric's label set is a fixed enum product, so the series count is known at compile time | A test enumerates every instrument's possible label combinations and asserts a ceiling |
| I-15 | **Random identifiers only.** Trace and span IDs come from the OS CSPRNG, never derived from a claim UID, a token or a time | The SDK's default ID generator, asserted not to be replaced |
| I-16 | **The workload's output is not telemetry.** ADR-0045 output never enters an OTel pipeline; only its counts (batches, bytes, refusals) do | Separate code paths; the canary test plants a secret in workload output too |

### Why OTLP over HTTP, not gRPC

The project avoids gRPC outside Envoy's ext_authz exception. OTLP/HTTP with protobuf bodies is a first-class OTLP
transport, reuses the workspace's `reqwest` with `rustls-no-provider` on aws-lc-rs (ADR-0007), and keeps `tonic` and
`ring` out of the graph. `cargo deny` already bans `ring`; the phase 0 spike proves the chosen `opentelemetry-otlp`
features pull neither.

### Why correlation by claim UID, not by propagated context

The tempting design threads one trace through the whole lifecycle by putting `traceparent` in the `AgentSandbox`, the
claim and the guest's requests. That makes a value a requester can write (a declarative `AgentSandbox`, TB-2) into an
input of our tracing, and it gives the workload's side a way to attach to the broker's traces. Instead each component
starts its own traces, and every span carries `mediatore.claim.uid`. The backend joins them on that attribute. Inside
one process, ordinary parent and child spans apply. The cost is that a lifecycle view is a query rather than one trace,
and that is the right trade.

## The signals, component by component

| Component | Spans | Metrics (labels are enums only) | Never |
| --- | --- | --- | --- |
| User API (TB-1) | One root per request: route template, method, result, error code, namespace, claim UID once known | Requests by route and status class; duration histogram; namespace-gate refusals by code | The bearer, the body, query strings, the caller's `traceparent` as a parent |
| Sandbox API (TB-6) | Token issue: audience, backend, result, the upstream refresh as a child span | Issues by audience and backend and result; issue duration; refresh duration and failures by code | The issued token, the refresh token, the assertion |
| Reconcilers (claims, `AgentSandbox`, SPIRE entries) | One span per reconcile: kind, result, requeue reason (enum) | Reconcile duration and errors by kind; queue depth; Lease held (gauge 0 or 1); claims by phase (gauge) | Object specs, annotations, status messages |
| Store and sweeps (TB-9) | Kubernetes calls as child spans: verb and resource kind | API call duration by verb and kind; envelopes swept; log ring segments and bytes; time from `expires_at` to deletion (roadmap 14's figure) | Secret data, envelope bytes |
| OpenBao (TB-10, TB-16) | seal, unseal, sign as child spans: operation and result | Duration and errors by operation | Plaintext, ciphertext, the OpenBao token, key names beyond the configured mount |
| IdP and Entra (TB-5) | JWKS fetch, refresh, OBO exchange: issuer name, result, error code | Duration and failures by issuer and code; JWKS cache age | The IdP's `error_description` text, any token, the client assertion |
| Bundle reflector (ADR-0026) | Verify and admit: policy, result | Verifications by result; current floor version per policy (bounded by configured policies) | Bundle payloads, signatures |
| STS | Mint: audience, result | Mints by audience | The signing key handle, the minted token |
| Authorizer (`mediatore gateway`) | One span per check: claim UID, decision, refusal code, cache hit or miss | Checks by decision and code; cache size, hit ratio, stale-serve count, broker fetch duration | The authority the workload asked for (a refused one is workload-controlled), the injected credential |
| Envoy (data plane, inject, relay) | None in the first cut (see the spike) | Tunnels opened, duration, bytes, by response flag; inject requests by audience and status | Headers, SNI of a refused tunnel, any admin listener |
| Guest | A **boot and claim timeline**: attest, register, `GuestReady`, pull, unpack, ruleset, egress proxy ready, jail start, jail exit, cleanup, each a duration and a result code | Phase durations; pull bytes and layers; exit code class | Image tags (the digest is already in the audit log), environment, file paths inside the rootfs |
| Egress proxy | None exported directly (I-8) | Requests by audience and result; refusals by code; token refreshes by audience | Hosts or paths the workload asked for, the phantom, the real token |
| Jailed workload | Nothing | Nothing | Everything |
| CLI | Nothing exported. Prints the server's request ID on an error for support correlation | Nothing | Anything off the machine |

The guest and the egress proxy hand their numbers to the guest, which sends one bounded, typed summary per claim (and
one at boot) to the broker over the node SVID: a new route on the sandbox API, shape-checked, size-capped and
rate-limited like `POST /v1/me/logs`, and `501` unless telemetry is enabled. The broker attaches it to the claim's UID
and exports it. That is an API surface change, so it is its own ADR.

## Speed budget

Measured, not asserted. Phase 0 records a baseline on the build host; every later phase is gated against it.

- **Disabled** (no `telemetry` section): token issue p50 and p99 within noise of the baseline, no new task, no new
  allocation per request (verified with a counting allocator in a bench).
- **Enabled, 10% head sampling**: token issue p99 within **+2% or +100 µs**, whichever is larger; claim create p99
  within +2%; the authorizer's check p99 within +50 µs.
- **Enabled, collector black-holed**: the same figures as enabled (I-10). Memory bounded by the configured queue.
- **Binary size**: the one binary (ADR-0014) grows by a recorded figure; if the growth matters for the VM image, the
  exporter goes behind a cargo feature the broker and gateway builds enable and the guest build does not (the guest
  does not export, I-8).
- Sampling: parent-based ratio at the root, chosen by the operator. Refusals and errors are kept by **tail sampling in
  the collector**, so no request can force itself into the sample (I-6). Metrics are never sampled.

## Phases

### Phase 0: decide (ADR, CALM, spike)

- [ ] Spike: `opentelemetry`, `opentelemetry_sdk`, `opentelemetry-otlp` (`http-proto`, the `reqwest` client) and
      `tracing-opentelemetry` on the workspace's `reqwest`; `cargo deny check` green with no `ring`, no `tonic`, no
      `openssl`; licenses on the allowlist; binary size delta recorded
- [ ] Spike: what Envoy can push without an admin interface and without gRPC: the OpenTelemetry tracer's HTTP
      service, the stats sinks it offers, and whether the gateway's authorizer or a loopback collector should carry
      Envoy's numbers. Verify against the pinned Envoy's documentation, not memory; the Envoy gRPC exception covers
      ext_authz only, and widening it is a decision for the ADR
- [ ] Baseline: the latency and allocation figures of the speed budget, on the build host, recorded in this doc
- [ ] ADR: telemetry export (OTLP/HTTP, SVID mutual TLS, the collector's SPIFFE ID, off by default, invariants I-1 to
      I-16, correlation by claim UID). New SPIFFE ID for the collector, so ADR-0004's scheme is touched
- [ ] ADR: the guest's telemetry summary on the sandbox API (shape, caps, rate, `501` when off)
- [ ] CALM: the collector node, the export flows from the broker and the gateway; `make calm-validate`,
      `make calm-diagrams`

### Phase 1: foundations (`mediatore-telemetry`)

- [ ] Test first: the canary harness in `mediatore-testkit` (an in-memory span, metric and log exporter, a set of
      planted secrets, a scanner that fails on any hit in any attribute, event or label)
- [ ] The closed attribute schema (I-3, I-4, I-13) and its unit tests
- [ ] The allowlist export layer for `tracing` (I-1, I-5): exports callsite name and schema fields, drops the rest
- [ ] The exporter: OTLP/HTTP, SVID mutual TLS through `mediatore-tls`, bounded batch queue, drop on full, timeout,
      capped backoff, dropped-signal counter (I-9, I-10)
- [ ] The no-op propagator at every external listener and on every outbound client (I-6, I-7)
- [ ] `telemetry` config section: endpoint, collector SPIFFE ID, sampling ratio, queue sizes, `include_subject`;
      `deny_unknown_fields`; refusals for plaintext and missing identity, each with a test
- [ ] Wire into `main.rs` beside the existing `fmt` layer, which stays exactly as it is (I-12)
- [ ] Benches for the disabled and enabled paths; the counting-allocator check

### Phase 2: the broker

- [ ] Request spans and RED metrics on the user API and the sandbox API (e2e: canary scan over `e2e_dev.rs` and
      `e2e_mtls.rs` with telemetry on; a request with `traceparent` and `baggage` gets a fresh root)
- [ ] Token issue, refresh, OBO, STS, OpenBao and Kubernetes client spans
- [ ] Reconciler, Lease, sweep and store metrics; the envelope deletion lag as a histogram (roadmap 14 uses it)
- [ ] Bundle reflector metrics
- [ ] The cardinality ceiling test (I-14)
- [ ] Speed budget re-measured against the baseline

### Phase 3: the gateway

- [ ] Authorizer spans and metrics, exported with the gateway SVID
- [ ] Envoy's numbers by the route the spike chose; the admin interface stays off (`image/gateway/check.sh`)
- [ ] Strip trace headers on the inject listener (I-7), with a test in kind
- [ ] The gateway's nftables egress gains the collector, by address, from the operator's environment file; no other
      rule changes
- [ ] Access-log lines unchanged; header-free as today

### Phase 4: the guest and the egress proxy

- [ ] The boot and claim timeline in the guest, as typed durations
- [ ] Egress proxy counters, handed to the guest over the existing local channel; trace headers from the jail stripped
      (I-7)
- [ ] The telemetry summary route on the sandbox API and the broker's export of it; `501` when off
- [ ] `image/check.sh`: the pool ruleset is byte-identical to before this phase (I-8)
- [ ] TPM attestation path untouched: if any change lands in a file `rules/testing.md` lists, `make kind-e2e-tpm` on the
      build host before handing back

### Phase 5: the reference deployment

- [ ] `deploy/observability`: a kustomize component with a reference OpenTelemetry Collector (rendered once, no Helm),
      its `ClusterSPIFFEID`, a `NetworkPolicy` admitting only the broker and the gateways, and a processor chain of
      `memory_limiter`, the `redaction` processor with the same allowlist as defence in depth, tail sampling that keeps
      errors and refusals, and `batch`
- [ ] `make kind-e2e-otel`: the collector in kind with a file exporter; run the full loop (claim, attest, token,
      gateway tunnel, inject, logs, release); scan the file for the canaries and for any key outside the schema; fail
      loudly if the file is missing (a skip never reports success)
- [ ] Dashboards and alerts as JSON beside the component: claim lifecycle by phase, issue latency and failures by
      audience, authorizer decisions, OpenBao latency, Lease flaps, sweep lag, dropped-signal counter
- [ ] `docs/guides/observability.md`: what is exported, what never is, how to point it at a collector, the invariants

### Phase 6: threat model and live proof

- [ ] Threat model full pass: a new boundary (component to collector), the telemetry stream as an asset with its
      sensitivity (claim UIDs, SPIFFE IDs, timings; subjects only if enabled), the collector's operator as an actor,
      STRIDE rows, §7 hardening citing the files that enforce I-1 to I-16, §8 accepted risks (below), the diagram, the
      stamp
- [ ] Live on the homelab: the loop run with telemetry on and the collector up, then with the collector down; the speed
      budget re-measured; results recorded here (no hostnames or addresses)

## Risks this roadmap expects to accept (for the threat model to decide)

- **Traffic analysis.** Timings and counts per claim tell the collector's operator when and how much a sandbox worked.
  Bounded by who may read the backend; the content never travels.
- **The telemetry backend is a lower-trust store than the audit log.** Hence I-13 and the claim UID, not the person, as
  the join key.
- **A lost signal.** By design (I-10); the audit log is the record.

## Not in this roadmap

- Profiling (continuous or on demand): a listener or a privileged agent, both against I-2
- Exporting workload output (ADR-0045) through OTel, ever
- Telemetry from the CLI, ever
- Tracing inside the jail or offering the workload an OTLP endpoint
- SPIRE's, OpenBao's and notaio's own telemetry: their charts and threat models own it; the reference collector may
  receive it, configured by the operator
