<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0076: A failed image pull is retried, shown to the owner, and ends the claim with a reason

**Status:** Accepted and implemented 2026-11-27 (hermetic proof only; what a live run must still
show is under *What must be proven*) · **Date:** 2026-11-27

Amends [ADR-0033](0033-a-one-shot-workload-the-restart-policy-and-the-claim-released-when-it-is-done.md)
decision 2 (`POST /v1/me/exit` gains an optional `reason`),
[ADR-0063](0063-the-image-pull-goes-through-the-claims-proxy-and-the-gateway-like-any-egress.md)
decision 9 (the pull's deadline is shared by its attempts) and
[ADR-0028](0028-egress-gateway-envoy-with-spiffe-identity.md) decision 7 (for the pull listener
alone, a gateway's refusal is followed by the next gateway). Uses
[ADR-0045](0045-a-sandbox-workloads-output-streamed-to-its-owner.md)'s output
stream for the guest's own lines.

## Context

Live, 2026-11-27: two claims sat 15 and 14 minutes "pulling" after a host reboot and never
started. Every gateway admitted the tunnel to the registry, and nothing reached the registry. The
owner saw nothing in `mediatore sandbox logs`, and each claim ended only at its deadline.

What the guest did on a failed pull (`crates/mediatore-guest/src/guest.rs`, `serve_claim`):

- the pull was one attempt, bounded by ADR-0063 decision 9 (a 10 s connect, a 60 s idle read, a
  900 s whole pull);
- its error was returned from `mediatore guest`, which exited with a failure. systemd
  (`Restart=on-failure`, `image/systemd/mediatore-guest.service`) started it again five seconds
  later; it registered, found the same claim on `GET /v1/me`, and pulled again. So a pull that
  cannot succeed crash-loops until the claim's deadline, and the claim is never ended;
- the error went to the VM's journal only. The owner's output stream starts with the workload, so
  a claim that never got a workload shows nothing;
- the proxy's pull listener sends each request through one gateway. A connect failure there
  already fails over to the next (ADR-0028 decision 7), but a refusal does not: decision 7 reads a
  `4xx` as the environment's verdict, "since every gateway would answer the same". That is not
  true of every refusal: the authorizer of a gateway that cannot reach the broker answers
  `403 broker_unreachable`, a condition of that gateway alone.

`POST /v1/me/exit` carries `code`, `signal` and `restarts` and nothing that says the workload
never ran. Putting a made-up code there would overload a field the owner reads as the workload's.

## Decision

1. **The pull is attempted at most three times, within one budget.** The budget is the pull's
   deadline (`MEDIATORE_PULL_DEADLINE_SECS`, default 900 s, already cut to what is left of the
   claim): every attempt and every wait share it, and an attempt still running when it ends is
   cut there. The waits are 5 s after the first failure and 15 s after the second; a wait that
   would end past the budget is not waited, and that failure is the last. Before each attempt
   after the first, the rootfs and the staging directory are emptied (a link removed as a link,
   never followed). The connect and idle bounds of ADR-0063 decision 9 are unchanged and apply
   to each attempt (`crates/mediatore-guest/src/pull.rs`).

2. **Each failed attempt is one line on the claim's output stream, from a closed set.** When the
   claim asked for its output (`workload.logs`, ADR-0045), shipping starts before the pull, and
   each failed attempt queues one stderr record written entirely by the guest:
   `mediatore: image pull attempt N of M from <registry> failed (<kind>); retrying in S s`, or
   `...; giving up: the claim ends`. The kind is one of `unreachable`, `timeout`, `refused`,
   `not_found`, `unavailable`, `invalid`, `failed` (`PullError`,
   `crates/mediatore-proto/src/lib.rs`), read from the error's chain
   (`image::kind_of`). Never the error's text, which can name a URL path, a token realm or a
   gateway's answer; never a credential, a query or a token. The registry is the host the image
   reference names, which the owner wrote. The guest's lines take `seq` 1 onwards and the
   workload's capture continues after them (`logs::GuestLines`, `Capture::continuing_after`),
   since the broker keeps a `seq` once. The guest's journal keeps the whole error, as before.

3. **After the last attempt the guest ends the claim.** It flushes the output (bounded,
   `logs::FLUSH_TIMEOUT`), then sends `POST /v1/me/exit` with a `reason` (decision 4) and no
   code or signal. The broker records the exit and releases the claim as for any exit, and logs
   `the claim's image could not be pulled and the guest ends the claim (ADR-0076)` at `warn` with
   the attempts and the kind. When the broker took the exit, `mediatore guest` stops without a
   failure, so systemd does not start it again to pull for a claim being released. When it did
   not, the guest fails as before: systemd starts it again, and the claim's deadline is still the
   bound. A trip during the pull is a trip: no exit is sent (ADR-0069 decision 9).

4. **`POST /v1/me/exit` gains an optional `reason`.** `GuestExit.reason`:
   `{"kind": "pull_failed", "attempts": N, "error": "<kind>"}`, a closed set with no free text,
   so nothing the registry or a gateway said reaches the record. Absent, the exit is the
   workload's, as before; present, `code` and `signal` are absent and `restarts` is 0. It is kept
   on the record with the exit (`WorkloadExit` flattens `GuestExit`), on the `AgentSandbox`
   status where the exit already is, and shown by `mediatore sandbox get` after the exit line
   (`reason=pull_failed attempts=N error=<kind>`). A reason outside the set is refused by the
   extractor and nothing ends. Compatibility: an older broker ignores the field (`GuestExit` does
   not deny unknown fields) and records an exit with no code, so the claim still ends; an older
   guest sends none.

5. **The pull listener asks the next gateway when one does not carry a request.** For the pull
   alone, a request answered by one gateway with `gateway_refused`, `gateway_unreachable` or
   `upstream_unreachable` is sent to the next, once each, in one pass from a random start; when
   none carries it, the last answer is the answer (`Proxy::handle_pull`,
   `Dialer::one_by_one`, `crates/mediatore-guest/src/egress.rs`, `forward.rs`). The puller's
   requests are root's `GET`s with no body, so a request can be sent again; one with a body is
   refused `400`. Each gateway still runs its own authorizer: nothing is admitted that some
   gateway did not admit, and a gateway with a stale view could already admit a request on a
   random start. The workload's path is unchanged: its bodies are streamed and cannot be
   replayed, and decision 7's reading stands there.

6. **The workload's restarts are not touched.** ADR-0033's restart policy is the supervisor's
   and starts after the pull; nothing here retries a workload.

## Consequences

- A pull that cannot succeed ends its claim in at most the pull's deadline (900 s by default)
  instead of the claim's TTL, and the owner reads why, on the claim and, with `workload.logs`,
  in `mediatore sandbox logs`.
- A transient failure (one gateway restarting, a registry `503`) costs a retry instead of the
  claim.
- A claim without `workload.logs` gets no lines (ADR-0045 is opt-in); the reason on the claim is
  its only signal.
- A pull through the gateways can now ask every gateway once per request when all refuse: at
  most the gateway count in requests to the authorizers, per pull request.
- `GuestExit` gained a field: every Rust literal of it names `reason`.

## Alternatives rejected

- **A code on the exit for a pull failure** (`code: 125`, say): overloads the workload's field;
  the owner could not tell a pull from a workload that exited so.
- **A new route** (`POST /v1/me/failed`): a second way to end a claim, with the same release and
  the same record, for one more reason.
- **Retrying until the claim's deadline**: what the crash loop did; the owner waits for nothing.
- **Following a refusal at the next gateway on the workload's path too**: its bodies cannot be
  replayed, and that is ADR-0028's decision to reopen, not this one's.

## What must be proven

- Hermetic (`make check`): `pull.rs` (the attempts, the budget, the waits, the emptying),
  `image.rs` (`each_failed_pull_says_what_kind_of_failure_it_is`,
  `a_status_is_a_kind_and_the_proxys_code_decides_its_502`), `logs.rs`
  (`the_guests_lines_and_the_workloads_share_one_seq`), `egress.rs`
  (`the_pull_listener_asks_the_next_gateway_when_one_refuses_or_is_down`,
  `the_pull_listener_answers_the_last_refusal_when_every_gateway_refuses`), the broker
  (`a_pull_failure_exit_is_recorded_with_its_reason_and_releases_the_claim`), the e2e
  (`a_claim_whose_image_could_not_be_pulled_ends_with_the_reason_its_owner_reads`), the CLI line.
- Live, not yet: a pool VM whose registry is unreachable through every gateway, the owner's three
  lines in `mediatore sandbox logs`, the claim released within the pull's deadline with
  `reason=pull_failed`, the guest not restarted by systemd; and a pull with one gateway refusing
  that completes through another.
