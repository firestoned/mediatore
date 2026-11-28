<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0069: Tripwires on the VM: a decoy the workload takes ends its sandbox

**Status:** Accepted 2026-11-27; implemented 2026-11-27, `off` by default (roadmap 17): the
draw, the trap listener and the arming (`draw.rs`, `decoy.rs`, `arm.rs` in
`crates/mediatore-guest/src`), the claim's table with the decoys, the `denied` sets and the
redirect of the decoy ports and the metadata address to the trap listener (`net.rs`),
containment, the trap socket and the report (`trip.rs`,
`supervise.rs`, `guest.rs`), the proxy's checks and its matcher (`egress.rs`, `trapmatch.rs`),
the planted environment and home (`jail.rs`, `sandboxfs.rs`), the wire types
(`crates/mediatore-proto/src/trip.rs`), `POST /v1/me/trip`, the record and the summary
(`crates/mediatore-api/src/trip.rs`), `Tripped`, `status.tripwires` and the watch filter
(`crates/mediatore-claims/src/sandbox.rs`, `kubestore.rs`, `watch.rs`), `policy.traps`,
`policy.traps_denied` and `audiences[].traps_body` (`crates/mediatore/src/config.rs`) and the
CLI's view (`crates/mediatore-client/src/cli.rs`). **Not built:** the OpenTelemetry of decision
11 (no exporter exists, roadmap 15) and, on notaio's schemas, the bundle's `traps` section,
`traps.body` in a `SandboxAudience` bundle and the admission code `P017` (decision 4). A fix
round of the same day is in (decisions 2, 6, 7 and 9 amended again): nothing listens on a decoy
port, the claim's table redirects them to one trap listener; bait matched as the method and as
header names; the first trip always cut and reported, the wait for its acknowledgement bounded;
the proxy stopped at the guest's word; logs taken for a minute after a trip; an exit that races
a trip deletes nothing. Proven hermetically by `make check`; in kind by `make kind-e2e-sandbox`
(the `status.tripwires` schema in both served versions and a tripped record failing its
sandbox, with the status written by hand, not by the broker), on the merged tree:
on the build host after `make kind-delete`, `kind-e2e-tpm` PASS (attested as `spiffe://sandbox.test/spire/agent/tpm/e4f28760dd09942c82dc86b03248494247007215cd35a9173734e14865e354c9`), `kind-e2e-x509pop`, `kind-e2e-sandbox` (the tripped path: Failed with `Tripped=True`, no second claim) and `kind-e2e-gateway` PASS, and every suite of the default `kind-e2e` set PASS, 2026-11-27; live on the build host by the nine tripwire tests of
`crates/mediatore/tests/jail_exec_live.rs` in a throwaway namespace (containment 54 ms, a debug
build). Not proven: anything on a booted VM, the real guest end to end, `POST /v1/me/trip` and
the broker's own status write against a real API server, the homelab soaks (*What must be
proven*). Threat-model pass 2026-11-27 (A-39 to A-43, R-78 to R-95) · **Date:** 2026-11-26

Roadmap 17. Adds one route to the sandbox API's node surface beside
[ADR-0033](0033-a-one-shot-workload-the-restart-policy-and-the-claim-released-when-it-is-done.md)'s
`POST /v1/me/exit`, one field to the claim's record and one to the `AgentSandbox` status (as
[ADR-0064](0064-a-claims-egress-summarised-on-its-sandboxs-status.md) added `status.egress`), a
`traps` section to the signed policy bundle
([ADR-0026](0026-notaio-bundles-verified-in-shadow.md),
[ADR-0055](0055-audiences-from-signed-sandboxaudience-bundles.md)), and the broker's first
OpenTelemetry signals under roadmap 15's invariants. (*Amended 2026-11-27: ADR-0064 is Proposed
and not implemented; `status.egress` is in nothing under `crates/`. `status.tripwires` is the
first such field, and decision 9's amendment says what that changes.*) Changes what the guest plants in the jail and
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

   *Amended 2026-11-27: the guest does not read the peer's uid. `SO_PEERCRED` does not exist
   for TCP, and a `NETLINK_SOCK_DIAG` lookup loses a client that connects and closes at once.
   Instead the claim's table refuses every other uid to the decoy ports, logged and counted, in
   the rule shape it already has for the proxy's port (`Ruleset::render`,
   `crates/mediatore-guest/src/net.rs`). A handshake that completes on a decoy listener is
   therefore the sandbox uid's by construction, with no lookup and no race.*

   *Amended 2026-11-27, at implementation: the other uid's packet is dropped and counted under
   the kernel log prefix `mediatore-sandbox decoy other uid: ` and is never a trip. A `denied`
   loopback port is seen only where Landlock lets a connect through (decision 10, amended), so
   the `denied` row's "a loopback port that is neither the proxy nor drawn" reaches the chain
   only on a port Landlock admits.*

   *Amended 2026-11-27, after the fix round, by the maintainer's decision: nothing listens on a
   decoy port. A live test found that the jail could list the decoy listeners in its own
   `/proc/self/net/tcp` (the jail shares the VM's network namespace, and its `/proc` keeps the
   per-process `net` directories), which the consequences below had said it could not. Now the
   claim's table redirects the sandbox uid's connections to the decoy ports, and to
   `169.254.169.254:80` when the metadata decoy is drawn, to one trap listener on loopback, on a
   port drawn per claim off every other port of the claim and of the VM (`trap_port`,
   `draw.rs`; the `nat_out` chain, `net.rs`). The listener names the decoy from the
   connection's original destination (`SO_ORIGINAL_DST`, `decoy.rs`); a connection whose
   original destination cannot be read or is no decoy is still a use, noted as the trap
   `invalid` and closed unanswered. A direct connection to the trap listener's port is dropped
   for every uid, logged under `mediatore-sandbox trap port direct: `, and the rule that drops
   other uids at the decoy ports matches new connections only, so a root server's replies to a
   client on such a port pass. Landlock admits the decoy ports and not the trap listener's. So
   the `port` row's "a drawn loopback listener" is the trap listener answering as the decoy the
   connection was made to, and "a handshake that completes on a decoy listener" in the first
   amendment is a connection the trap listener accepts, the sandbox uid's by construction
   (`the_decoy_ports_are_redirected_to_the_one_trap_listener_for_the_uid_alone`, `net.rs`;
   `the_trap_listener_answers_as_the_decoy_reached_and_notes_a_port_trip`,
   `a_connection_that_names_no_decoy_is_still_a_use_and_is_answered_nothing`, `decoy.rs`).*

   A file trap (tripping on read) is rejected: it fires on every agent that greps its home.

   *Amended 2026-11-28, by [ADR-0077](0077-chaff-ports-a-probe-of-the-ports-the-jail-admits-is-a-use.md): the `port` row gains the chaff ports, 16 to 32 a
   claim, admitted by Landlock beside the decoys, with nothing listening, nothing redirected
   and nothing answering. The sandbox uid's new TCP connection to one, at any address and in
   either family, is the use: the claim's table drops it and counts it by port in the set
   `chaff_used`, which the guest reads every 250 ms, and the event is `kind: port`,
   `trap: chaff`, the chaff port as the target, `source: drawn`. No handshake is needed and
   other uids are untouched.*

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

   *Amended 2026-11-27, at implementation (`crates/mediatore-guest/src/draw.rs`):*
   - *The weights are the deployment's catalogue 6, the seeds 2, generated entries 2, derived
     entries 2, and the first port of every draw is a generated one. A place that still
     collides after the bounded attempts fails the draw, and a draw is never shortened.*
   - *The lookup-order exclusion is by family, by the maintainer's decision: when any variable
     of a tool's lookup family is set by the workload's specification or the guest, no bait
     variable of that family is drawn (`GH_TOKEN` and `GITHUB_TOKEN`; the two GitHub
     Enterprise names; `GITLAB_TOKEN`, `GITLAB_ACCESS_TOKEN` and `OAUTH_TOKEN`; `HF_TOKEN` and
     `HUGGING_FACE_HUB_TOKEN`; `GOOGLE_API_KEY` and `GEMINI_API_KEY`; the three AWS names).*
   - *More collisions are arming failures rather than redraws: a decoy on a port the claim's
     list already uses, and the metadata decoy when a destination of the claim is on port 80
     (`Ruleset::with_decoys`, `net.rs`), because Landlock admits a connect port at every
     address and either would open a path around the proxy; and a drawn variable that is not
     a plain name or is `HOME`, `MEDIATORE_EGRESS_PROXY` or `MEDIATORE_TOKEN` (`jail.rs`).
     Arming makes at most three draws and draws again only when a drawn decoy port is taken
     before its listener binds; the VM's own listeners are reserved in the draw.*
   - *"A file the image already has" cannot collide: under `shadow` and `enforce` the home is a
     bind mount of a directory the guest prepares (decision 7's amendment), which hides the
     image's own home.*
   - *The `ghp_` and `npm_` checksums are the common reading (CRC32 of the random part, base62,
     six characters), not confirmed against a public vector; the OpenAI project key and the
     PyPI token shapes are taken from public scanner rules and are not confirmed either.*
   - *`SENTRY_DSN` is a decoy route's variable with no key in it, unlike roadmap 17's table: an
     SDK reads that variable on its own, so a well-formed DSN would be used by an honest run.*

   *Amended 2026-11-27, after the fix round: the trap listener's port (decision 2, amended) is
   drawn after the claim's draw, which it leaves unchanged, from 1024 to 65535, never a seed and
   never a port the claim, the VM or the draw uses (`trap_port`, `draw.rs`). Arming draws again,
   at most three draws in all, only when that port is taken before the listener binds; a bind
   error names no port, and an `nft` refusal of the armed table writes `<drawn>` in place of
   every drawn port (`a_refused_armed_ruleset_names_no_drawn_port_in_its_error`, `net.rs`;
   `the_listener_is_on_loopback_alone_and_a_port_in_use_is_an_arming_failure_naming_no_port`,
   `decoy.rs`).*

4. **The deployment's catalogue is a `traps` section of the signed policy bundle.** It may add
   seed ports, host stems and suffixes, and variable names each with a generator from the fixed
   set; it may set the counts within the built-in bounds. It may not narrow a catalogue to a fixed
   set, and it carries no literal value. Admission refuses an entry that overlaps a grant of the
   same policy (a port, host or variable the policy allows) with the next free `P` code (`P013`
   at the time of writing). The section reaches the guest in `GET /v1/me`, read by the guest
   outside the jail and never by the proxy, which is handed the drawn result only. Readers of the
   policy repository can read the catalogue: that is accepted (Consequences).

   *Amended 2026-11-27: the code is `P017`. `P013` and `P014` are the rejected ADR-0065's and
   `P015` and `P016` are ADR-0066's (`docs/design/policy-subjects.md`). And the section is not
   built: the bundle's schema is notaio's (`sandboxpolicy-bundle`, pinned by tag in the workspace
   `Cargo.toml`), whose `BundleContent` is a closed struct that the verifier recomputes the
   content digest from, so nothing can be added to a bundle from this repository. What is built
   is the wire type (`TrapCatalogue`, `crates/mediatore-proto/src/trip.rs`) and the draw's use
   of one; `GET /v1/me` carries no catalogue, and a draw is made from the seeds, the generated
   and the derived entries. Revisit when a notaio release carries a `traps` section.*

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

   *Amended 2026-11-27, two changes.*
   - *`GuestReady` is announced after registration, before any claim exists (`run`,
     `crates/mediatore-guest/src/guest.rs`), and the mode arrives with the claim in
     `GET /v1/me`, so "does not report ready" cannot hold. What holds: under `enforce` a guest
     that cannot arm its traps starts no jail. `serve_claim` returns its error before the jail
     starts and tears down, and the claim ends at its deadline as after any such failure. Under
     `shadow` it logs at `warn` and runs unarmed. The property, never running while believed
     guarded, is kept.*
   - *`policy.traps: enforce` refuses the broker at start under
     `policy.audience_definitions.mode: bundles`. No bundle-defined audience can carry decision
     6's mark until notaio's schema does (decision 4), and an unmarked model API would end
     honest runs. `shadow` is allowed there and shows `would_trip` on such a route. Revisit when
     a `SandboxAudience` bundle carries the mark.*

   *Amended 2026-11-27, at implementation, three more facts.*
   - *`policy.traps` is a key of the `policy` section, which requires `trusted_keys` (notaio's
     signing keys), so a deployment with no signed policy cannot turn this ADR on at all.
     Accepted by the maintainer as built. Revisit when the mode moves to a top-level key.*
   - *The rollout order starts before `off`: upgrade the guests first. A guest from before
     this ADR ignores `traps` in `GET /v1/me`, so under a broker at `enforce` it runs a claim
     unguarded and the broker cannot know. Then `off`, `shadow`, `enforce`. Never switch the
     broker to `off` with claims running: their reports are then `501` and a claim a guest has
     cut and killed ends only at its deadline.*
   - *Under `shadow` a guest that cannot arm logs at `warn`, reloads the claim's table without
     the draw, starts the proxy without the trap socket and the jail without bait; under
     `enforce` the same failure is an error before any jail (`arm.rs`).*

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

   *Amended 2026-11-27, two changes.*
   - *The mark is `audiences[].traps_body: skip` in the broker's own configuration, so for
     audiences defined there (mode `config`) only, and it reaches the proxy as `traps_body` on
     each route of `GET /v1/me`. `traps.body` in a `SandboxAudience` bundle is not built: that
     schema is notaio's too (decision 4).*
   - *The query leaves the proxy's log lines. `handle` in `crates/mediatore-guest/src/egress.rs`
     logged the path with its query on the `request refused` and `forwarded` lines, which
     decision 12 forbids once a query can carry bait. Both log the path alone, and a request a
     trap matched logs no path at all.*

   *Amended 2026-11-27, at implementation (`crates/mediatore-guest/src/trapmatch.rs`,
   `egress.rs`), by the maintainer's decisions on what an unscannable body does.*
   - *The matcher holds at most 25 patterns per value: raw; percent-encoded under six sets of
     kept characters, in both hex cases; standard and URL-safe base64 at three alignments; and
     standard base64 percent-encoded. It holds back one byte less than the longest pattern. A
     value under eight bytes is no pattern; double encoding, a compression the request does
     not declare, and any other transform are not caught.*
   - *A body that expands past the bound (64 times what was read, at least 1 MiB, at most
     64 MiB) or does not decode in its declared encoding never ends a sandbox, under either
     mode: an honest large compressed upload or a buggy client must not kill a run. Under
     `enforce` the request is refused (`413 body_expansion`, `400 body_undecodable` while the
     response has not started), nothing unscanned is forwarded, and the event is one `warn`
     line on the VM and is not reported to the broker, because the wire types cannot say "a
     credential event that ends nothing" (`Cause::is_refused_body`,
     `crates/mediatore-guest/src/trip.rs`). Under `shadow` the body is forwarded whole, and the
     guest logs the same line and reports nothing either. A broker-visible record would need a new `denied` class (open question 7).*
   - *A decoy route under `shadow` answers `404 no_route`, what an unknown host gets. The
     response side is not scanned, and the pull listener (root's puller, outside the jail) is
     matched against no trap.*

   *Amended 2026-11-27, after the fix round.*
   - *The head is the method and every header name too, not only the values, the path and the
     query: a method is any token and a header name reaches the upstream as it came, so a bait
     value fits either. The method is matched first, then the head, and every header name, a
     trailer's included, as it is, upper-cased and lower-cased (`Matcher::in_method`,
     `Matcher::in_name`, `trapmatch.rs`;
     `a_method_and_every_header_name_are_matched_whatever_case_hyper_gave_them`;
     `bait_as_the_method_or_a_header_name_is_matched_like_any_other_position`, `egress.rs`). A
     log line that named the method names one of the nine standard methods or the word
     `extension`. Not caught: a mixed-case value used as a header name, which the HTTP library
     sends lower-cased, a transform like any other.*
   - *A credential event's target is `invalid` when the request matched no route, never the
     request's first path segment, which may be the bait itself; and a target in which a bait
     value is found is replaced by `invalid` before it is told
     (`bait_that_names_no_route_is_never_a_target_nor_a_logged_segment`, `egress.rs`; the canary
     scan plants bait as the first path segment, as the method and as a header name, and looks
     for its lower case too).*

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

   *Amended 2026-11-27, at implementation.*
   - *Measured: `containment_ms` 54, from the listener's verdict to the end of the `nft` cut, and
     every process of the sandbox uid gone 290 ms after the verdict; with the broker unreachable,
     cut and kill done 293 ms after it. One run of the live tests on the build host, a debug
     build, in a throwaway network namespace and not on a VM. A release build on a VM is not
     measured. The cut is an `nft` process (the hand-loaded cut took 50 to 58 ms), bounded at
     five seconds; an `nft` that refuses, fails or does not answer still lets the kill happen,
     and the report then carries no `containment_ms`.*
   - *The socket's directory is `/run/mediatore-guest/trap`, root's, mode `0711` (the proxy, the
     sandbox uid outside the jail, must traverse it); the socket is `0666` and admits the
     sandbox uid alone, by `SO_PEERCRED`. Only the first connection is handed the draw; a
     second is refused and logged. If the socket closes, the proxy treats itself as tripped,
     answers `403 trap` to everything and exits, which ends the claim; the guest only logs.*
   - *Under `enforce` a use the decider cannot queue signals the supervision directly (the
     kill without the cut first), logged at `error`: the queue fails closed.*
   - *After a trip the teardown keeps the cut table and the sandbox user, so nothing the uid
     left behind regains the network (`teardown_after`, `supervise.rs`).*
   - *The final line of the workload's output names the kind and the trap or the class, never
     the target, and is flushed within two seconds.*

   *Amended 2026-11-27, after the fix round; where these differ from the bullets above, these
   hold.*
   - *Step 1 holds for the proxy's own verdicts. For a decoy port or a `denied` trip under
     `enforce` the guest tells the proxy the moment it decides the trip, before the cut (`GuestToProxy::Tripped` on
     the socket), and from then on the proxy answers `403 trap` to every request and stays up
     for the kill (`the_proxy_is_told_a_trip_was_decided_before_the_cut_lands`, `trip.rs`;
     `a_guest_that_decided_a_trip_stops_the_proxy_at_once_and_the_proxy_stays_up`,
     `egress.rs`). A request body already streaming at that moment keeps flowing until the cut
     lands, about 50 ms: accepted (R-95).*
   - *Step 5 is bounded: the guest waits at most 120 s (`REPORT_WAIT`, `trip.rs`) for the
     broker's acknowledgement; then it logs an `error` and tears down, the cut and the user
     kept, and a report that never arrives leaves the claim to end at its deadline
     (`the_wait_for_the_report_of_a_trip_is_bounded`).*
   - *"A use the decider cannot queue" above no longer applies to the first trip. The first use
     that ends the run claims the end and goes to the decider on a slot of its own, which the
     decider takes before its queue, so it is always cut and reported, however full the queue
     of other uses is (`a_trip_that_finds_the_queue_full_is_still_cut_reported_and_ends_the_run`).
     Only a decider that is gone signals the supervision without the cut, at `error`. A later
     use that finds the queue full is a count lost, logged at `warn` and rate-limited.*
   - *A refused connection on the trap socket (another uid, no credential, a second connection)
     is logged at the 1st, 2nd, 4th, 8th refusal and so on, with the count
     (`refused_peers_on_the_trap_socket_are_logged_a_bounded_number_of_times`).*
   - *A run that ends while its trip is being cut is still the tripped run. Under `enforce`,
     once the supervision returns, the guest waits `SETTLE` (600 ms) for a use still on its way
     and, once a trip is claimed, for its cut, before it writes the final line, reports an exit
     or tears down; a trip found then takes the tripped path and no exit is sent
     (`Trips::settle`, `trip.rs`; `serve_claim`, `guest.rs`;
     `a_run_that_ends_while_its_trip_is_being_cut_is_still_the_tripped_run`). So the end of
     every armed `enforce` claim takes 600 ms longer. Under `shadow` nothing waits.*
   - *Without a tripwire the supervision's select is unordered, as it was before this ADR; it
     puts the trip first only when a tripwire is armed
     (`without_a_tripwire_a_jail_and_a_proxy_that_exit_together_are_taken_as_before`,
     `supervise.rs`).*
   - *Measured again on the merged tree, the same way (a debug build, a throwaway namespace):
     `containment_ms` 54, every process of the sandbox uid gone 242 ms after the verdict, and
     256 ms with the broker unreachable.*

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

   *Amended 2026-11-27, three changes.*
   - *The example's `source` reads `workload`, as the `source` bullet says: a `credential`
     event's target is the host of the route the workload sent the bait to. The validation
     (`TripReport::validate`, `crates/mediatore-proto/src/trip.rs`) refuses `drawn` there.*
   - *A `denied` event carries its class in a field of its own, `class` (`loopback_port`,
     `private_range`, `unknown_host`), and no `trap`; `count` folds repeats of one kind, trap,
     class and target. Every kind names a target, and a `port` target of zero is refused.*
   - *The handler reads the body itself, so a body that is off in any part is `400
     invalid_trip` and never the JSON extractor's own `415` or `422`. Until the route is built
     it answers `501` under every mode.*

   *Amended 2026-11-27, at implementation (`crates/mediatore-api/src/trip.rs`,
   `crates/mediatore-guest/src/trip.rs`).*
   - *The answers, in order: `501 not_implemented` under `off`; `401` with no peer identity;
     `403 forbidden` for a peer that is not a registered node; `400 invalid_trip`; `429
     too_many_trips` with `Retry-After: 1` past two reports a second per claim (a node with no
     claim is keyed by the first 128 bits of its EK hash, and a refused body spends nothing);
     `204`. A release that fails after a trip is `500 internal` with a fixed detail.*
   - *A report from a registered node with no claim must hold `segment` events alone (ADR-0070
     decision 8), else it is dropped whole, `204`.*
   - *The guest retries a report with backoff from 250 ms to 30 s (honouring `Retry-After` up
     to 30 s) until it is acknowledged; `501` and `404` are final answers and the report is
     not sent again. Folding waits a second; the 32 distinct events a minute bound lets the
     event that ends the run and a final flush through, and at most 256 pending events are
     kept, the rest counted and logged.*
   - *A `denied` event's `count` is packets (a SYN and its retransmissions), as is a `segment`
     event's.*
   - *The pool VM's segment reports (ADR-0070 decision 4) say `mode: shadow` and are given up
     after three attempts: they end nothing whatever they say.*

   *Amended 2026-11-27, after the fix round: a `credential` event's target is the host `invalid`
   when the request named no route, and any target in which a bait value is found is replaced
   by `invalid` (decision 6, amended); a `port` event from a connection the trap listener cannot
   name has the trap `invalid` and the trap listener's port as its target (decision 2,
   amended). The guest's retries are bounded by its wait for the acknowledgement, 120 s
   (decision 7, amended).*

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

   *Amended 2026-11-27, five changes.*
   - *The release keeps the `AgentSandbox`. Outside `dev_mode`, `exit` releases by deleting the
     `AgentSandbox` (`exit`, `crates/mediatore-api/src/lib.rs`), which would take the status and
     the condition with it. A trip instead writes `tripped` and releases the claim (the entry
     retracted, the record revoked); the reconciler then deletes the `VirtualMachineClaim` and
     marks the sandbox `Failed` with `Tripped=True` and `status.reason` `tripped: <kind>`. The
     reconciler never deletes it, but its record is released, so the retention sweep
     (ADR-0034 decision 4) deletes the `AgentSandbox` `store.retention_secs` after the release,
     its `status.tripwires` and its condition with it, as for any ended claim; after that only
     the audit lines remain. (Corrected 2026-11-27 by the maintainer's decision: the first
     wording, "stays until its owner deletes it", was not what the code does.)*
   - *The acknowledgement annotation and the three-trips backoff are struck. A sandbox never
     gets a second claim (`reconcile`, `crates/mediatore-claims/src/sandbox.rs`: "a sandbox
     never gets a second VM") and its spec is immutable, so "does not claim again" is already
     true of every sandbox and neither rule has anything to act on. Revisit when a sandbox can
     claim more than once.*
   - *The status write and the watch filter are built here, not borrowed: ADR-0064 is not
     implemented. The write is a compare-and-set patch that names `status.tripwires` and the
     resource version it read, merged again on a conflict; the filter keeps an event that
     differs only in `status.tripwires` from the reconciler. ADR-0064 reuses both. An entry
     carries what it did (`would_trip`, `reported`, `tripped`), and the eviction is by that: an
     entry that ended the claim is never evicted.*
   - *The dedupe on `id` is per replica. The status never carries `id`, so a retry that lands
     on another replica may add its `count` to `status.tripwires` twice. The audit line and
     `tripped` (first id wins, by compare-and-set) stay exact; the status count is a lower
     bound on attention, not a ledger.*
   - *A report that says `enforce` while the broker's mode is `shadow` (the mode changed during
     the claim) ends the claim, logged at `warn`: the VM has already cut and killed, and a node
     can end its own claim with `exit` anyway. Under `off` the answer is `501` and the claim
     ends at its deadline.*

   *Amended 2026-11-27, at implementation, ten readings accepted by the maintainer as built.*
   - *A mode mismatch ends the claim either way: a report that says `shadow` to a broker at
     `enforce` ends it too. `enforce` is followed wherever either side says it, logged at
     `warn`.*
   - *A `denied` event follows the broker's switch at the time it arrives, and under `shadow`
     a `denied` event whose class is at `report` is recorded `reported`, not `would_trip`.*
   - *A late event for a claim that ended for another reason is folded as `reported`;
     `tripped` is never set after the fact.*
   - *`claim_of_node_peer` treats a tripped record as no claim from the moment `tripped` is
     written, before the release lands: the node's later `GET /v1/me` and `POST /v1/me/report`
     are `404 no_claim`, its exit and its logs `204`, so its guest is handed nothing to start or
     restart a workload with.*
   - *The audit line, `trip reported`, also carries the event's id, the effect, the node, the
     class, the source address and the time; it is at `warn` when either mode is `enforce` or
     the kind is `segment`, at `info` otherwise. A trip that ends a claim adds
     `claim ended by a trip: entry retracted, record revoked (ADR-0069 decision 9)`.*
   - *`status.tripwires` timestamps are RFC 3339 strings at full precision. A `status.tripwires`
     this build cannot read is read as absent; a `status.record.tripped` it cannot read makes
     the record unreadable, never a record with no trip.*
   - *Only the broker's ServiceAccount may write the `AgentSandbox` status (the admission
     policy `deploy/base/admission/agentsandbox-status.yaml`), and its RBAC is `patch` on the
     subresource: a person cannot mark a sandbox tripped by hand.*
   - *`GET /v1/claims/{name}` shows `tripped` and the summary; `ready` is false once tripped.
     Outside `dev_mode` the phase can still read `Bound` until the reconciler's pass, then
     `Failed`; in `dev_mode` it is `Releasing`. A client treats `tripped` as the end whatever
     the phase says.*
   - *A trip that wrote `tripped` and whose release then failed leaves the entry until a retried
     report, or the reconciler's pass, releases it (in `dev_mode`, until the deadline).*
   - *The summary's count is a lower bound of what was reported: besides the per-replica dedupe
     above, a fold that fails is logged and not retried, while the audit lines stand.*

   *Amended 2026-11-27, after the fix round, by the maintainer's decisions; where these differ
   from the bullets above, these hold.*
   - *"Its logs `204`" above is corrected: the broker takes `POST /v1/me/logs` for a tripped
     claim from the node the claim was bound to for 60 s after `tripped.recorded_at`
     (`LOGS_AFTER_A_TRIP`, `crates/mediatore-api/src/tripwires.rs`; `logs_claim_of`,
     `crates/mediatore-api/src/lib.rs`), so the final line and the workload's last output reach
     the owner even when the report lands first. After that, from another node, or for a claim
     released without a trip, a batch is dropped with `204` as before
     (`a_tripped_claims_last_output_reaches_its_owner_when_the_trip_lands_first`,
     `a_tripped_claims_output_is_dropped_after_the_grace_and_a_released_ones_always`,
     `crates/mediatore-api/src/trip.rs`; e2e
     `a_tripped_claims_last_output_reaches_its_owner_after_the_report`).*
   - *An exit never deletes a tripped claim's `AgentSandbox`. `POST /v1/me/exit` for a record
     that carries `tripped` writes nothing and deletes nothing (`204`); and outside `dev_mode`
     the record is read again right before the sandbox is deleted, and a `tripped` found then,
     or a read that fails, leaves the sandbox (`an_exit_racing_a_trip_writes_nothing_and_deletes_nothing`,
     `an_honest_exit_still_deletes_the_sandbox`, `crates/mediatore-api/src/trip.rs`). A
     `tripped` written between that read and the delete, a window of milliseconds, is not
     caught: accepted (R-93) until the delete is conditional on the resource version. The
     retention sweep still deletes a tripped sandbox (the first bullet above), and the reconciler
     deletes its `VirtualMachineClaim`, never the sandbox.*
   - *The owner's `DELETE /v1/claims/{name}` is not refused for a tripped claim: the owner's
     RBAC lets them delete the `AgentSandbox` with `kubectl` anyway. Deleting it deletes the
     evidence on it, its `status.tripwires` and its `Tripped` condition; the audit lines remain.*
   - *The end comes before the fold: `tripped`, then the release, then the status fold, so the
     release never waits on a status write; a release that fails still folds, then answers the
     error.*
   - *A `segment` event is never put on a claim, a node's live claim included: it is one audit
     line at `warn` with no claim and no subject, never folded (ADR-0070 decision 8, amended;
     `segment_events_from_a_node_with_a_live_claim_are_never_put_on_its_summary`). A report of
     `segment` events alone is no mode mismatch
     (`a_segment_report_under_an_enforce_broker_is_no_mode_mismatch`).*

10. **Which `denied` targets trip is switched per target class**: `loopback_port`,
    `private_range`, `unknown_host`, each `report` or `trip`, all `report` by default. `report`
    records the event as for `shadow` without ending anything, even under `enforce`. An operator
    moves a class to `trip` only once the soak shows it silent on honest runs (tools that probe
    localhost for a local service or an IDE, package managers falling back across mirrors, a typo
    in a host).

    *Amended 2026-11-27: Landlock inside the jail admits a TCP connect to the ports the guest
    lists and no other (`--connect-port`, `crates/mediatore-guest/src/jail.rs`, ADR-0024), and
    until now that was the proxy's port alone. A connect to any other port fails in the syscall
    and reaches neither the chain nor a listener. Landlock stays as it is; only the drawn decoy
    ports are added (and port 80 with the metadata decoy). So `loopback_port` and
    `private_range` see a connect only on a port Landlock admits, and `unknown_host`, decided at
    the proxy, is the `denied` class that sees every attempt. Opening Landlock to every port
    would remove one of the jail's three layers and needs an ADR of its own.*

    *Amended 2026-11-27, at implementation: the chain keeps a dropped new TCP connection in
    the sets `denied4` and `denied6` by destination (1024 elements, a minute each), read every
    250 ms. Loopback is `loopback_port`, the private and link-local ranges are `private_range`,
    and any other destination is refused and logged by the chain and is no class. A count is
    packets. A side effect of admitting the decoy ports (and 80) to Landlock: the workload may
    attempt those ports at any address, and the claim's table is then the only bound for
    them. Proven live: a connect to a closed loopback port that Landlock does not admit fails
    in the syscall and trips nothing, even with `loopback_port` at `trip`.*

    *Amended 2026-11-28, by [ADR-0077](0077-chaff-ports-a-probe-of-the-ports-the-jail-admits-is-a-use.md): Landlock also admits the claim's chaff ports, and
    the chaff rule comes before the `denied` rules, so a chaff port is never `loopback_port` or
    `private_range`; at a public address, where a dropped connection was no class, it is now a
    `port` use. The ports below 1024, the seeds and the ports common tools try on their own are
    never chaff, so `loopback_port` still sees what it saw on every other admitted port.*

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

    *Amended 2026-11-27: not built. There is no exporter to add to: no `opentelemetry`
    dependency is in any `Cargo.toml`, no `mediatore-telemetry` crate exists and roadmap 15 is
    not started. The audit line and the status are the record, as this decision already says.*

12. **Never log the bait.** No log line, status field, span, event or metric carries a bait value,
    a phantom, a request path, a header or a body. A test plants bait in every position the proxy
    checks and asserts it appears in nothing the guest, the proxy or the broker writes.

    *Amended 2026-11-27, at implementation: two log lines of the broker carried a request's
    path and are changed. The request span of both routers named the URI; it now names the
    method and the matched route template only (`request{method route}`, `(unknown)` for the
    fallback). And the `accept_plain_gateway_identity` warning logged the raw path segment; it
    now logs it only when it parses as a UUID. Every bait value also joins the redaction set
    of the workload's output (ADR-0045), so a workload that prints its environment ships no
    bait. The canary scans log lines, the record and the status; nothing is exported.*

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

    *Amended 2026-11-27: the hash the guest reports is the public one, of the render with the
    decoy ports and the redirect rule left out (`Ruleset::public_sha256`). The hash of the whole
    text would give the draw away: its only unknowns are two to five ports, so whoever reads
    `report.sandbox_ruleset_sha256` (the claim's owner, through `GET /v1/claims/{name}`) could
    search for them offline, against decision 3. ADR-0029 decision 5's comparison still covers
    every other rule.*

    *Amended 2026-11-27, at implementation: the public hash leaves out everything a draw adds,
    not only the decoy ports and the redirect: also the `denied4` and `denied6` sets and their
    two rules, and the rule that keeps other uids off the decoys. It equals the hash the same
    claim has under `off`, and ADR-0029's comparison does not cover those lines. The redirect's
    chain is `type nat hook output priority -100` (`nft` takes the name `dstnat` on the
    prerouting hook only), and the metadata decoy is drawn only where a route to the address
    exists: with no route a connect fails before any hook. Proven live in a throwaway
    namespace: the redirect carried the jail's connect to the drawn listener and tripped as
    `metadata`. Not proven beside a pool VM's `mediatore_host` table, nor on Azure.*

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

  *Amended 2026-11-27: the `port` traps have a limit of the same kind against a workload that
  knows how mediatore works. Landlock admits the decoy ports and refuses every other, and the
  two outcomes can be told apart from inside the jail without a packet any decoy or table
  would see, so such a workload can learn which ports to leave alone. Accepted by the
  maintainer as a known limit, with the follow-up named: an ADR for chaff ports, ports
  Landlock admits that nothing listens on, any use of which trips (open question 6). The
  workload cannot read the jail's connect-port list nor list the loopback listeners (both
  proven live); the jail's `confinement applied` line, which reaches the owner with the
  output, gives the number of admitted ports, not which.*

  *Corrected 2026-11-27, after the fix round: "nor list the loopback listeners" was not true.
  The live test behind it read `/proc/net/tcp` and asked `ss`; a later live test found every
  decoy listener listed in the jail's own `/proc/self/net/tcp`, `/proc/1/net/tcp` and
  `/proc/thread-self/net/tcp`, since the jail shares the VM's network namespace. Since the fix
  (decision 2, amended) nothing listens on a decoy port, and the jail lists one loopback
  listener, the trap listener, on a port drawn per claim, which Landlock refuses it; proven
  live (`the_jail_cannot_list_the_decoys_through_its_own_proc_net`,
  `crates/mediatore/tests/jail_exec_live.rs`). So the jail cannot list the decoy ports, but it
  can tell that traps are armed: accepted (R-94). The connect-port list is still unreadable.*

  *Amended 2026-11-28: the follow-up is built, [ADR-0077](0077-chaff-ports-a-probe-of-the-ports-the-jail-admits-is-a-use.md). The admitted ports are now the
  proxy's, the decoys, 80 with the metadata decoy, and 16 to 32 chaff ports, any connection to
  which trips, so a sweep that tells admitted ports from refused ones by their errors is a use at
  its first chaff port. The limit narrows and does not close: a probe that fails before any
  packet (an address with no route) still shows which ports are admitted, and what it shows is
  decoys and chaff mixed; a workload that connects to nothing but the proxy is caught by no
  port trap. The confinement line's count is now of decoys and chaff together.*
- **A third party can end a run.** A planted README that steers an agent into a decoy ends a run
  its requester wanted. That is the intended outcome and the cost; a workload that wants its own
  sandbox ended could already exit.
- **The workload's environment and home change** under `shadow` and `enforce`: extra variables,
  extra files, extra loopback listeners. A workload that enumerates its environment and fails on
  an unknown variable breaks; the soak finds it.

  *Amended 2026-11-27: the home is a bind mount of `<sandbox root>/home` on the claim's tmpfs
  (`0700`, the bait files `0600`, never under `/work`), so under `shadow` and `enforce` what
  the workload writes there persists across its restarts within the claim; under `off` the
  home is a fresh tmpfs at every start, as before. Either mount hides the image's own home.
  Under `off` the ruleset, the jail's arguments and the proxy's arguments are byte for byte
  what they were before this ADR (pinned by tests).*

  *Amended 2026-11-27, after the fix round: "extra loopback listeners" is one, the trap
  listener (decision 2, amended).*
- **The proxy reads bodies.** It already forwarded them; now it scans them, holding back a few
  hundred bytes. The latency and memory cost are measured and recorded at implementation.

  *Amended 2026-11-27: not yet measured. No figure for the matcher's latency or memory is
  recorded.*
- **More writes.** One record write and one status write per trip; under `shadow`, at most one
  status write per claim per batch, bounded as ADR-0064's are.
- **The policy repository's readers can read the deployment catalogue.** They can narrow what an
  attacker would avoid, but not tell which entries a sandbox drew. Accepted, and recorded in the
  threat model with a *Revisit when* (a separate, narrower-read source for the catalogue).
- **Shadow mode shows part of a live sandbox's draw** to whoever may `get` the sandbox and, for
  `drawn` targets, to the telemetry backend's readers. One trap per event, of a sandbox still
  running. Accepted for a reader the cluster already trusts; recorded. *Amended 2026-11-27:
  nothing is exported, so only readers of the sandbox see it; and a tripped sandbox shows it
  until the retention sweep deletes the object (decision 9).*
- **Workload-chosen strings reach the status** (`denied` and credential-route targets), within
  the host grammar and the 16-entry bound, as ADR-0064 accepted for refused authorities.
- **The threat-model pass is owed** before this is accepted, and touches: §2 (the guest's trap
  listeners, the proxy's matcher), §3 (the draw as an asset held on the VM; the trip record and
  status), TB-6 (the new route), TB-12 (the proxy reading bodies), TB-2 and TB-9 (the new status
  and record writes), §7 (the redraw rules, the hold-back matcher, the bait canary test) and §8
  (the gaps above, each with a *Revisit when*). *Amended 2026-11-27: the threat-model pass is
  done, 2026-11-27.*
- **CALM and docs.** The guest's trip flow and the node-to-broker relationship's new route in
  `docs/architecture/calm/architecture.json`; `docs/guides/tripwires.md`; the `traps` section in
  `docs/guides/the-policy-bundle.md`; `traps.body` in the audience bundle's guide. *Amended
  2026-11-27: done, with the policy bundle guide saying the section is not in the bundle yet,
  and `audiences[].traps_body` documented in `docs/design/issuers-and-audiences.md` and
  `docs/design/configuration.md` in place of `traps.body`.*

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

  *Amended 2026-11-27: `dev_mode` has no `AgentSandbox`, so `e2e_dev.rs` proves that a trip
  ends the claim and that `GET /v1/claims/{name}` shows `tripped` and the folded events. That
  the sandbox is `Failed` with `Tripped=True` is proven in `crates/mediatore-claims` and in
  `crates/mediatore/tests/e2e_sandbox.rs`. Nothing is exported, so the scan covers log lines,
  the record and the status.*

  *Amended 2026-11-27, what was proven and what was not, at implementation.*
  - *Unit and e2e, in `make check` (green on the integrated tree): the draw's rules
    (`crates/mediatore-guest/src/draw.rs`), the matcher's encodings, alignments, gzip and
    hold-back (`trapmatch.rs`), the proxy's refusals (`egress.rs`), containment against a fake
    `nft` and a broker that never answers (`trip.rs`), the trip arm and the teardown that keeps
    the cut (`supervise.rs`), the route, the record, the summary and the release
    (`crates/mediatore-api/src/trip.rs`), the patches naming only their fields and the watch
    filter (`crates/mediatore-claims`), the bytes of the ruleset and of the jail's and the
    proxy's arguments under `off`; `e2e_dev.rs` (a trip ends the claim, a foreign peer and
    another claim's node end nothing, a repeated id, a released claim, `shadow`, a `denied`
    class at `trip`, `501` under `off`), `e2e_egress.rs` (bait in a header, a query, a body
    and a gzip body, the model-API body exemption and its `Authorization`, a decoy route, the
    unknown host, the canary scan), `e2e_sandbox.rs`.*
  - *Live on the build host, in a throwaway network and mount namespace with a debug build,
    the real `nsjail`, `jail-exec`, `nft` and Landlock, a stand-in proxy and broker: every
    drawn port trips from the jail and root is refused; nothing is open under `off`; after a
    trip nothing from the sandbox uid leaves and no jail process remains (54 ms, decision 7);
    containment holds with the broker unreachable; reading the bait files and running `env`
    trip nothing and no bait reaches the redacted output; a closed loopback port is refused by
    Landlock and trips nothing (so "a closed loopback port trips when its class is `trip`"
    holds only on a port Landlock admits, decision 10); the jail cannot read its connect ports
    or list the listeners; the metadata address trips where it is routed.*
  - *In kind (`make kind-e2e-sandbox`): `status.tripwires` in both served versions, its enum
    enforced, and a `tripped` record failing the sandbox with `Tripped=True`, its claim deleted
    and never recreated, the object then swept; the status is written by hand in that tier,
    which proves the schema and the reconciler, not the broker's own write.*
  - *"`gh` with a routed GitHub phantom never picks up bait" is proven as the draw's exclusion,
    not by running `gh`.*
  - *Not proven: the real guest binary end to end on a VM (the real proxy over the socket, the
    cut and the kill by the guest as root), a pool VM beside `mediatore_host`, Azure, a
    release-build containment figure, `POST /v1/me/trip` and the broker's status write
    against a real API server, the matcher's latency and memory, the shadow soak and
    `enforce` with Claude Code on the homelab.*
  - *After the fix round, on the merged tree: `make check` green with the tests named in the
    amendments of decisions 2, 3, 6, 7 and 9; live, the same way, nine tripwire tests passed,
    the ninth `the_jail_cannot_list_the_decoys_through_its_own_proc_net` (no decoy port in any
    of the tables the jail can read; the one listener listed is the trap listener, refused to
    the jail by Landlock; a direct connection to it refused to the sandbox uid and to root), and
    "the jail cannot read its connect ports or list the listeners" above holds for the
    connect-port list and the system-wide tables only (the consequences, corrected); the
    redirect carried every drawn port and the metadata address to the trap listener. In kind:
    on the build host after `make kind-delete`, `kind-e2e-tpm` PASS (attested as `spiffe://sandbox.test/spire/agent/tpm/e4f28760dd09942c82dc86b03248494247007215cd35a9173734e14865e354c9`), `kind-e2e-x509pop`, `kind-e2e-sandbox` (the tripped path: Failed with `Tripped=True`, no second claim) and `kind-e2e-gateway` PASS, and every suite of the default `kind-e2e` set PASS, 2026-11-27.*
- *Added 2026-11-27: the red-team check is a SIMULATION, not the live number:
  `a_prober_that_avoids_every_seed_still_trips_within_n_probes_with_a_deployment_catalogue`
  (`draw.rs`) over 5000 seeded draws. With a hand-built deployment catalogue, a prober that
  avoids every seed still trips within 6 probes at worst, 1.59 on average (reading the seeds
  avoids 19.5% of the traps); with the seeds alone, 6 at worst and 1.81 on average (42.6%
  avoided). The live number is owed, and needs a deployment catalogue, which needs notaio.*
- A red-team check: a script that reads this repository's seeds and avoids every one still trips
  within a bounded number of probes on a sandbox with a deployment catalogue; the number recorded.
- Live on the homelab under `enforce`: a Claude Code sandbox given a planted instruction to send
  `~/.aws/credentials` somewhere is ended, its VM is gone, its `AgentSandbox` shows `Tripped` with
  the event, and the collector shows the trip span and counter.

## Open questions

1. Whether `mediatore.io/trip-acknowledged` should require a role beyond `update` on the sandbox.
   *Amended 2026-11-27: moot while the annotation is struck (decision 9).*
2. Whether a separate, narrower-read source for the deployment catalogue is worth its cost.
   *Amended 2026-11-28: proposed in
   [ADR-0080](0080-the-deployments-trap-catalogue-read-by-the-broker-alone-each-claim-handed-a-slice.md),
   which would supersede decision 4.*
3. Quarantine, if a responder's need for a live VM proves real. *Amended 2026-11-28: proposed
   in [ADR-0079](0079-a-tripped-vm-held-for-its-operator-running-and-cut-for-a-bounded-time.md).*
4. Whether roadmap 16's attribution should add the tripping binary to the event, and under which
   `source`. *Amended 2026-11-28: proposed in
   [ADR-0081](0081-a-trip-names-the-executable-that-took-the-bait.md).*
5. *Added 2026-11-27.* The `traps` section and `traps.body` in notaio's bundles (decisions 4 and
   6), and with them `enforce` under bundle-defined audiences (decision 5).
6. *Added 2026-11-27.* Whether Landlock should admit more ports so that `loopback_port` and
   `private_range` see more (decision 10). *Amended 2026-11-27: the maintainer's follow-up is
   an ADR for chaff ports, admitted by Landlock with nothing listening, any use of which
   trips, which also answers the limit stated under "What it does not catch". *Answered
   2026-11-28 by [ADR-0077](0077-chaff-ports-a-probe-of-the-ports-the-jail-admits-is-a-use.md).**
7. *Added 2026-11-27.* A record at the broker of a body the proxy refused because it could not
   scan it (decision 6, amended): it needs a change to the wire types, such as a `denied`
   class of its own.
8. *Added 2026-11-27.* Moving `policy.traps` to a key outside the `policy` section, so that a
   deployment with no signed policy can turn tripwires on (decision 5, amended).

The actors past the jail (a process outside it holding the claim SVID, root on a pool VM, a
compromised gateway process) are
[ADR-0070](0070-tripwires-beyond-the-sandbox-a-request-no-honest-build-makes.md)'s, which adds the
kinds `protocol` and `segment` and the source `peer` to decisions 2 and 8.
