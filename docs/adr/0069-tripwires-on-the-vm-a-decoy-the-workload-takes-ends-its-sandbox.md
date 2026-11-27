<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0069: Tripwires on the VM: a decoy the workload takes ends its sandbox

**Status:** Proposed (no implementation yet; CALM updated 2026-11-26, `flow-tripwire`; the
threat-model pass and roadmap 15's export ADR are owed before it is accepted) · **Date:** 2026-11-26

Roadmap 17. Adds one route to the sandbox API's node surface beside
[ADR-0033](0033-a-one-shot-workload-the-restart-policy-and-the-claim-released-when-it-is-done.md)'s
`POST /v1/me/exit`, one field to the claim's record and one to the `AgentSandbox` status (as
[ADR-0064](0064-a-claims-egress-summarised-on-its-sandboxs-status.md) added `status.egress`), a
`traps` section to the signed policy bundle
([ADR-0026](0026-notaio-bundles-verified-in-shadow.md),
[ADR-0055](0055-audiences-from-signed-sandboxaudience-bundles.md)), and the broker's first
OpenTelemetry signals under roadmap 15's invariants. Changes what the guest plants in the jail and
what the egress proxy ([ADR-0025](0025-phantom-token-egress-proxy.md)) checks before it forwards.
Changes no token shape, no SPIFFE ID, and nothing on the gateway
([ADR-0028](0028-egress-gateway-envoy-with-spiffe-identity.md)). Leaves
[ADR-0068](0068-the-cloud-platforms-host-addresses-root-alone-on-azure-the-metadata-service-for-nobody.md)'s
host table as it is (decision 13).

## Context

The jail's allowlist bounds where a hijacked workload can go. It does not say whether the
workload is hijacked. Today a refusal is a log line in three places (the jail chain's
`mediatore-sandbox drop:` kernel line, the egress proxy's `404` and `401`, the gateway's deny of
ADR-0062), and a typo, a tool's probe and an attack produce the same line. Nothing acts on one.

A decoy separates them. No honest run of a task has a reason to connect to a service it was not
told about, to call an internal API nobody configured, or to send a credential it was never
given. One use of such a thing is a signal strong enough to end the sandbox without a person in
the loop, which a deny line never is.

What already exists and shapes the answer:

- **Every request the workload makes is seen in the clear on the VM.** The workload calls the
  proxy as `http://127.0.0.1:<port>/<host>/<path>`; a `CONNECT` is `405`; the proxy makes the
  upstream TLS itself (`crates/mediatore-guest/src/egress.rs`). The proxy is the one place that
  sees headers and bodies before they leave.
- **The VM can already end its claim.** `POST /v1/me/exit` (ADR-0033), under the node's SVID,
  writes the exit on the record by compare-and-set
  ([ADR-0057](0057-a-claims-record-written-by-compare-and-set-and-bound-to-its-sandbox.md)) and
  releases the claim: entry retracted first, record revoked, `VirtualMachineClaim` deleted
  (`release` in `crates/mediatore-claims/src/lib.rs`).
- **The guest is root outside the jail; the jail's network is one nftables table keyed by the
  sandbox uid** ([ADR-0020](0020-jail-network-nftables-keyed-by-sandbox-uid.md),
  `crates/mediatore-guest/src/net.rs`), loaded in one `nft -f` transaction. The egress proxy runs
  as the sandbox uid outside the jail, so a drop of that uid's traffic cuts the jail and the proxy
  together, and leaves the guest's own path to the broker alone.
- **mediatore is open source.** The method, the catalogues and this ADR are public, and an agent
  can read them before it acts. A trap that works only while its list is secret is not a trap.
  The real risk is not that an attacker predicts one sandbox's draw but that it avoids the whole
  catalogue.
- **Roadmap 15 fixed how telemetry may look** before any exists: OTLP/HTTP push over SVID mutual
  TLS, off by default, a closed attribute schema (I-3), no workload-controlled bytes as attribute
  values (I-4), no new route from a pool VM (I-8), the audit line as the record and OTel as a copy
  that may lose data (I-12), no claim UID as a metric label (I-14). Its export ADR (the exporter,
  the collector's SPIFFE ID) is not written yet.
- **ADR-0064 put a bounded, workload-influenced summary on the `AgentSandbox` status** and showed
  how: a separate status field, written by compare-and-set apart from the record, bounded so a
  workload cannot grow the object, readable by whoever may `get` the sandbox.

## Decision

1. **Every trap lives on the VM and is decided there, before anything leaves it.** The guest
   (root) and the egress proxy hold the traps and make every verdict. A request that carries bait
   is refused on the VM and no byte of the bait reaches a gateway. The gateway holds no trap, no
   part of the draw, and gains no route; it keeps enforcing the claim's allowlist and refuses the
   claim once its record is revoked, as for any released claim.

2. **A trap trips on use, never on discovery.** Listing a directory, reading a bait file, `env`,
   `grep -r ~` and `netstat` trip nothing. These trip:

   | Kind | The bait | It trips when | Decided by |
   | --- | --- | --- | --- |
   | `port` | a drawn loopback listener that answers with a plausible first line (an SSH banner, a Redis `-NOAUTH`, an HTTP `401`), or the metadata address `169.254.169.254:80`, which the sandbox uid's table redirects to a drawn loopback listener (decision 13) | a TCP handshake from the sandbox uid completes; a connection from any other uid is logged and never trips (the guest reads the peer's uid with `NETLINK_SOCK_DIAG`) | the guest |
   | `route` | a drawn host the proxy carries as a route that is no audience, advertised in a variable pointing at the proxy (`VAULT_ADDR=$MEDIATORE_EGRESS_PROXY/<host>/`) | a request names it | the proxy |
   | `credential` | drawn values in the shape a provider issues, in the environment and in the files tools read them from, in the sandbox user's home only (never `/work`) | the value appears in a request the proxy is asked to forward (decision 6) | the proxy |
   | `denied` | none: the space no honest run reaches. A loopback port that is neither the proxy nor drawn, the link-local and private ranges, a host at the proxy that is no route | as for `port` and `route`, under the per-target switches of decision 10 | the guest's chain and the proxy |

   A file trap (tripping on read) is rejected: it fires on every agent that greps its home.

3. **The draw: random per claim, generated, and never off the VM.** At boot the guest draws, from
   the OS CSPRNG, how many traps of each kind (`port` two to five, `route` one to three,
   `credential` three to six) and which:
   - **Seeds**, the public tables of roadmap 17, weighted as more likely and never as the whole
     space. A `port` may be any port from 1024 to 65535 besides the seeds, at least one per draw.
   - **Generated** entries: host names from word lists, a stem and a suffix
     (`secrets.prod.internal`); variable names from a stem, a provider and a suffix
     (`BILLING_STRIPE_TOKEN`); every credential value random within its provider's prefix, length,
     alphabet and checksum, and valid nowhere.
   - **Derived** entries, shaped after the claim's real routes (a claim routed to a Git host also
     gets a decoy that looks like a second Git host), so avoiding the decoys means avoiding things
     that look exactly like what the workload was given.
   - **The deployment's own catalogue** from the bundle (decision 4), weighted above the seeds, so
     most of a sandbox's traps come from a part an outside reader has not seen.

   A drawn entry that collides with anything real is **redrawn**, never skipped: a port the proxy
   or the pull listener uses or the workload is declared to serve; a host that is one of the
   claim's routes; a variable the guest sets (the phantom, the proxy's address); a credential
   whose provider is one of the claim's routes, or whose variable comes earlier in a routed tool's
   lookup order than the one holding the phantom (a bait `GH_TOKEN` beside a phantom
   `GITHUB_TOKEN` would win and trip `gh` on an honest run); a file the image already has. The
   catalogue records each entry's provider and lookup order so the check can be made, and unit
   tests pin it.

   The draw is held by the guest and handed to the proxy over the local socket of decision 7. It
   is not in the image, the bundle, the record, `GET /v1/me` or any log at `info`. Two claims from
   one image under one policy differ. The secret is the draw, never the method: reading this ADR
   tells an attacker the shape of the space, not their sandbox's position in it. Nothing of a
   draw leaves the VM except the one trap a report names (decision 8).

4. **The deployment's catalogue is a `traps` section of the signed policy bundle.** It may add
   seed ports, host stems and suffixes, and variable names each with a generator from the fixed
   set; it may set the counts within the built-in bounds. It may not narrow a catalogue to a fixed
   set, and it carries no literal value. Admission refuses an entry that overlaps a grant of the
   same policy (a port, host or variable the policy allows) with the next free `P` code (`P013`
   at the time of writing). The section reaches the guest in `GET /v1/me`, read by the guest
   outside the jail and never by the proxy, which is handed the drawn result only. Readers of the
   policy repository can read the catalogue: that is accepted (Consequences).

5. **The mode: `policy.traps: off | shadow | enforce`, `off` by default.** Any other value
   refuses the broker at start. The broker serves the mode in `GET /v1/me`; the guest arms
   nothing under `off`. Under `shadow` every trap is armed and every use is reported as
   `would_trip`, and nothing is ended. Under `enforce` a use ends the sandbox (decision 7).
   `off` is the default, unlike ADR-0030's `shadow`, because arming traps changes the environment
   and the home directory of every workload, which an operator turns on deliberately. The rollout
   is `off`, then `shadow` with the false-positive soak of roadmap 17, then `enforce`. Under
   `enforce`, a guest that cannot arm its traps does not report ready
   ([ADR-0019](0019-guestready-after-attestation-and-registration.md)), so a sandbox never runs
   believing it is guarded when it is not.

6. **The proxy checks, then forwards; the bait never leaves.**
   - **Headers, whole, before the upstream is opened.** `Authorization` (a Basic pair decoded),
     every header of `CREDENTIAL_HEADERS`, every other header value, the path and the query.
   - **The body, streamed through a matcher that holds back.** The proxy runs the body through a
     multi-pattern matcher (each bait value raw, URL-encoded, and base64 at its three alignments)
     and forwards only bytes that can no longer be part of a match: it holds back the length of
     the longest pattern. So no body is buffered whole and no size limit is added, and a complete
     bait value is never forwarded. On a match the request is aborted (the upstream stream reset
     before its end, so the upstream discards an incomplete request) and the workload gets
     `403 trap`. The bytes before the match may have left; the bait has not.
   - **An encoded body** (`Content-Encoding` on the request) is decoded for the matcher with an
     expansion bound; an encoding the proxy cannot decode is `415` under `enforce` on a route whose
     body is matched.
   - **The agent's conversation is not matched in the body.** An audience that carries the agent's
     own context (a model API) is marked `traps.body: skip` in its `SandboxAudience` bundle; on its
     routes only the headers, path and query count. An honest agent that reads a bait file and
     sends what it read to its model is discovering, not using. Every other route's body is
     matched, since a body is where an exfiltration to an allowed route goes (a gist, an issue).
   - **A transformed value** (reversed, split, encrypted) is not caught. The ADR says so; the
     `port`, `route` and `denied` traps remain, and they depend on no value.

7. **What a trip does, in order.**
   1. **The proxy** refuses the tripping request, forwards nothing more for the claim, and tells
      the guest over a unix socket in a root-owned directory the jail cannot reach, admitting the
      proxy's uid by its peer credential.
   2. **The guest cuts the network.** It replaces the sandbox uid's chain with a drop of
      everything in one `nft -f` transaction. That cuts the jail and the proxy; the guest's own
      path to the broker is root's and untouched.
   3. **The guest kills the jail's process tree** (`SIGKILL` to the jail's PID namespace).
      Freezing for inspection is not done (Alternatives rejected).
   4. **The logs** collected under [ADR-0045](0045-a-sandbox-workloads-output-streamed-to-its-owner.md)
      are flushed with a final line naming the trap, within two seconds.
   5. **The guest reports** (decision 8), retrying with capped backoff until the broker answers
      `204` or the VM is gone. Containment never waits on the report: a guest that cannot reach
      the broker has still cut and killed.

   The guest measures the time from the proxy's or the listener's verdict to the end of step 2 and
   puts it in the report; the speed figure is recorded at implementation.

8. **`POST /v1/me/trip`, under the node's SVID.** The same authentication as `exit` and `report`
   (`claim_of_node_peer`); `501 not_implemented` under `off`; refused with `400` if any part of the
   body is off; rate-limited per claim like `POST /v1/me/logs`.

   ```json
   { "mode": "enforce",
     "events": [
       { "id": "6f1c…",                       "at": "2026-11-26T15:02:11.204Z",
         "kind": "credential",                "trap": "aws",
         "target": { "host": "git.example" }, "source": "drawn",
         "containment_ms": 41,                "count": 1 } ] }
   ```

   - `id` is random per event, from the guest; the broker deduplicates on it, so a retry is
     idempotent.
   - `kind` is decision 2's enum. `trap` is the catalogue entry's name for a `credential` (`aws`,
     `github`) or the drawn decoy's name for a `port` or `route`, at most 63 characters of
     `[a-z0-9.-]`; absent for `denied`.
   - `target` is what the workload reached for, exactly one of `host` (an RFC 1123 name or a
     literal address, at most 253 bytes, lower case), `port` (`u16`) or `address` (an IP and a
     port). For a `credential`, it is the host of the route the request named. Never a path, a
     query, a header, a body or the bait value.
   - `source` is `drawn` when the target is the guest's own value (a decoy's port or host) and
     `workload` when the workload chose it (every `denied`, and the route a `credential` was sent
     to). Decision 11 treats the two differently.
   - `containment_ms` is decision 7's figure, on an `enforce` event only. `count` folds repeats
     of one `(kind, trap, target)` under `shadow`; the guest sends at most 32 distinct events per
     claim per minute and counts the rest into the next batch.

9. **The broker records every event; under `enforce` it ends the claim.**
   - **The audit line.** One line per accepted event, at `warn` under `enforce` and `info` under
     `shadow`: claim UID, subject, mode, kind, trap, target, source, count, containment. This is
     the record (roadmap 15 I-12).
   - **The record**, under `enforce` only: `tripped` (the first event's id, time, kind, trap,
     target and source) written by compare-and-set (ADR-0057 decision 2) before the release. A
     record with `tripped` set is never restarted (ADR-0033's restart policy does not apply), its
     token is refused at `POST /v1/token`, and a second trip report for it is `204` and recorded
     on the status only. Then the release, as `exit` does it.
   - **The status**, `status.tripwires`, on the `AgentSandbox` beside ADR-0064's `status.egress`,
     in both served versions: the events' fields (never `id`), with `firstAt`, `lastAt` and
     `count` folded per `(kind, trap, target)`, at most 16 entries with `overflow` beyond, the
     oldest `shadow` entry evicted first and an `enforce` entry never. Written by the same
     compare-and-set and re-merge as ADR-0064 decision 5, a patch that names `status.tripwires`
     alone; the controller's watch filter of ADR-0064 decision 7 also ignores it. Read by whoever
     may `get` the sandbox.
   - **The condition** `Tripped=True` on the `AgentSandbox`, reason the kind, message the trap
     and target. The reconciler does not claim again for a tripped sandbox until its spec changes
     or the annotation `mediatore.io/trip-acknowledged` names the trip's id; a sandbox that trips
     three times within an hour waits an hour before it may be claimed again either way.
   - **The CLI** shows the condition and the latest entries.
   - No Kubernetes `Event` objects: they expire and are lossy, and the status already carries the
     same facts under the sandbox's RBAC.

10. **Which `denied` targets trip is switched per target class**: `loopback_port`,
    `private_range`, `unknown_host`, each `report` or `trip`, all `report` by default. `report`
    records the event as for `shadow` without ending anything, even under `enforce`. An operator
    moves a class to `trip` only once the soak shows it silent on honest runs (tools that probe
    localhost for a local service or an IDE, package managers falling back across mirrors, a typo
    in a host).

11. **The broker instruments trips with OpenTelemetry, inside roadmap 15's invariants.** The
    audit line and the status are complete without any of this; OTel is the extra copy roadmap
    15 I-12 allows, and with no `telemetry` section (I-11) nothing below exists.
    - **A root span per accepted report**, `mediatore.trip.report` (a fresh root, I-6; the report
      carries no trace context), with child spans for the record write, the release and the
      status write. Attributes, added to roadmap 15's closed schema (I-3):
      `mediatore.claim.uid`, `mediatore.trip.mode` (`shadow`, `enforce`), `mediatore.trip.kind`
      (decision 2's enum), `mediatore.trip.source` (`drawn`, `workload`),
      `mediatore.trip.result` (`released`, `already_released`, `recorded`, `refused`),
      `mediatore.trip.port` (an integer, when the target is a port), and
      `mediatore.trip.target` and `mediatore.trip.trap` **only when `source` is `drawn`**. A
      drawn target is the guest's value, not the workload's, so I-4 does not forbid it. A
      `workload` target is never exported: it is in the audit line and on the status, and the
      span carries the class (`mediatore.trip.target_class`: `loopback_port`, `private_range`,
      `unknown_host`, `route_host`) instead.
    - **One span event per trip event** on that span, named `mediatore.trip`, with the same
      attributes and the event's `count`.
    - **Metrics**, every label an enum so the series count is fixed (I-14), never a claim UID, a
      trap name or a target:
      - `mediatore.trips` (counter): `mode`, `kind`, `source`;
      - `mediatore.trip.containment` (histogram, ms, from the guest's figure): `kind`;
      - `mediatore.trip.report.lag` (histogram, ms, from the event's `at` to the broker's
        acceptance; negative clock skew clamps to zero): `mode`;
      - `mediatore.trip.release` (histogram, ms, record write to release done): `result`;
      - `mediatore.trip.reports.refused` (counter): `code`.
    - **The guest and the proxy export nothing** (I-8). Their figures reach the broker inside the
      trip report, over the node SVID and the relay leg that exists.
    - **The exporter is roadmap 15's**, not one of this ADR's own. This ADR adds the attributes,
      spans and instruments above to its schema; it ships its OTel part only once roadmap 15's
      export ADR and its phase 1 foundations (`mediatore-telemetry`, the allowlist layer, the
      canary test) exist. The canary test plants bait values too, and scans every exported signal
      for them.

12. **Never log the bait.** No log line, status field, span, event or metric carries a bait value,
    a phantom, a request path, a header or a body. A test plants bait in every position the proxy
    checks and asserts it appears in nothing the guest, the proxy or the broker writes.

13. **The metadata decoy is a redirect in the sandbox uid's table, not an address on `lo`.**
    ADR-0068 decision 3 makes `169.254.169.254` nobody's: a drop for every uid in the pool VM's host
    table on Azure, and the default drop elsewhere. Putting the address on `lo` would carry every
    uid's packets to it out through loopback, past that rule, and change ADR-0068 for root and the
    daemons. Instead the claim's table (ADR-0020) gains a `nat` output rule keyed on the sandbox uid
    alone, `meta skuid <uid> ip daddr 169.254.169.254 tcp dport 80 dnat to 127.0.0.1:<drawn port>`,
    and its filter chain admits that loopback port. Every other uid still meets ADR-0068's drop. The
    rule is in the ruleset the guest renders and hashes (`net.rs`), so it is in the hash reported on
    `POST /v1/me/report` (ADR-0029 decision 5), and it is absent when the draw did not pick the
    metadata decoy.

## Consequences

- **A hijack that explores ends its sandbox within milliseconds on the VM**, and the claim is
  released within a report's round trip. The gateway's cached allow for the claim (up to
  `fresh_secs`) does not matter: the VM's network is already cut.
- **What it does not catch.** A workload that touches only what it was given and sends data out
  only through its own allowed routes, untransformed bait aside, trips nothing. That remains the
  allowlist's job (ADR-0025, ADR-0030) and, inside a route, roadmap 16's. The `credential` traps
  mostly catch generic attacks (malicious packages and injected prompts that scrape any
  environment for `AKIA…`), which is most of them; a mediatore-aware attacker who knows a sandbox
  never holds a real credential ignores them and is left with `port`, `route`, derived decoys and
  the `denied` classes.
- **A third party can end a run.** A planted README that steers an agent into a decoy ends a run
  its requester wanted. That is the intended outcome and the cost; a workload that wants its own
  sandbox ended could already exit.
- **The workload's environment and home change** under `shadow` and `enforce`: extra variables,
  extra files, extra loopback listeners. A workload that enumerates its environment and fails on
  an unknown variable breaks; the soak finds it.
- **The proxy reads bodies.** It already forwarded them; now it scans them, holding back a few
  hundred bytes. The latency and memory cost are measured and recorded at implementation.
- **More writes.** One record write and one status write per trip; under `shadow`, at most one
  status write per claim per batch, bounded as ADR-0064's are.
- **The policy repository's readers can read the deployment catalogue.** They can narrow what an
  attacker would avoid, but not tell which entries a sandbox drew. Accepted, and recorded in the
  threat model with a *Revisit when* (a separate, narrower-read source for the catalogue).
- **Shadow mode shows part of a live sandbox's draw** to whoever may `get` the sandbox and, for
  `drawn` targets, to the telemetry backend's readers. One trap per event, of a sandbox still
  running. Accepted for a reader the cluster already trusts; recorded.
- **Workload-chosen strings reach the status** (`denied` and credential-route targets), within
  the host grammar and the 16-entry bound, as ADR-0064 accepted for refused authorities.
- **The threat-model pass is owed** before this is accepted, and touches: §2 (the guest's trap
  listeners, the proxy's matcher), §3 (the draw as an asset held on the VM; the trip record and
  status), TB-6 (the new route), TB-12 (the proxy reading bodies), TB-2 and TB-9 (the new status
  and record writes), §7 (the redraw rules, the hold-back matcher, the bait canary test) and §8
  (the gaps above, each with a *Revisit when*).
- **CALM and docs.** The guest's trip flow and the node-to-broker relationship's new route in
  `docs/architecture/calm/architecture.json`; `docs/guides/tripwires.md`; the `traps` section in
  `docs/guides/the-policy-bundle.md`; `traps.body` in the audience bundle's guide.

## Alternatives rejected

- **Decoys at the gateway.** The bait would have to leave the VM to trip, on a component every
  claim shares; the gateway would hold a trap list attackers could probe across claims; and a jail
  escape is still inside the VM, where the chain, the `denied` classes and the gateway's allowlist
  all still apply.
- **A fixed, public list of traps.** Avoided wholesale by anyone who reads the repository.
- **A draw made by the broker** (and sealed on the record). It lets the gateway's inject listener
  match bait too, but the draw would leave the VM, sit in the store and be readable by anything
  that reads the record. The proxy already sees every request.
- **Buffering the whole body and a size limit (`413`).** It refuses honest uploads (a `git push`
  pack) and costs memory per request; the hold-back matcher needs neither.
- **Quarantine (the VM kept frozen for inspection).** A compromised VM kept running is a risk of
  its own, and the log stream, the audit line and the status hold the record. Left as an open
  question with a hard upper bound if it ever returns.
- **Trap knowledge in OTel without the audit line**, or the workload's targets as span
  attributes. Roadmap 15 I-12 and I-4.
- **Kubernetes `Event` objects for trips.** Lossy and short-lived; the status is the durable view.
- **A file trap on read.** Fires on discovery (decision 2).

## What must be proven

- Unit: the draw (seeded for the rules, from the OS for real): every exclusion redraws, two draws
  differ, counts stay in bounds; every generated credential passes its provider's offline check;
  the matcher catches each encoding and alignment, never forwards a complete value, and holds back
  no more than the longest pattern; the `traps.body: skip` routes match headers only; the trip
  report's validation; the record and status patches name only their fields (as ADR-0064 pins).
- Live in `crates/mediatore/tests/jail_exec_live.rs` on the build host: every drawn port trips
  from the jail; a closed loopback port trips when its class is `trip`; after a trip nothing from
  the sandbox uid leaves and no jail process remains, within the recorded figure; containment
  holds with the broker unreachable.
- e2e in `crates/mediatore/tests/e2e_dev.rs` and `e2e_egress.rs`: a trip ends the claim and
  sets `Tripped`; a report from a non-node peer or another claim's node is refused; a repeated
  `id` is idempotent; the tripped claim's token is refused; bait in a header, a query, a body and
  a gzip body each trip; reading the file or running `env` trips nothing; bait in a model-API body
  trips nothing and in its `Authorization` trips; `gh` with a routed GitHub phantom never picks up
  bait; the bait canary scan over every log line, status and exported signal.
- A red-team check: a script that reads this repository's seeds and avoids every one still trips
  within a bounded number of probes on a sandbox with a deployment catalogue; the number recorded.
- Live on the homelab under `enforce`: a Claude Code sandbox given a planted instruction to send
  `~/.aws/credentials` somewhere is ended, its VM is gone, its `AgentSandbox` shows `Tripped` with
  the event, and the collector shows the trip span and counter.

## Open questions

1. Whether `mediatore.io/trip-acknowledged` should require a role beyond `update` on the sandbox.
2. Whether a separate, narrower-read source for the deployment catalogue is worth its cost.
3. Quarantine, if a responder's need for a live VM proves real.
4. Whether roadmap 16's attribution should add the tripping binary to the event, and under which
   `source`.

The actors past the jail (a process outside it holding the claim SVID, root on a pool VM, a
compromised gateway process) are
[ADR-0070](0070-tripwires-beyond-the-sandbox-a-request-no-honest-build-makes.md)'s, which adds the
kinds `protocol` and `segment` and the source `peer` to decisions 2 and 8.
