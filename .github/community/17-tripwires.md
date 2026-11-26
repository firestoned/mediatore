<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 17: Tripwires: a decoy the workload takes ends its sandbox

**Status: not started** (opened 2026-11-26). A sandbox carries decoys that no honest run of its
task has a reason to use: a loopback port that looks like a service, a route on the egress proxy
that looks like an internal API, a credential that looks real, a host at the gateway that looks
like a place to send data. The first use of one is taken as proof that the workload is no longer
doing what it was asked (a prompt injection, a hijacked agent, a malicious dependency), and the
sandbox is ended: the jail's network is cut and its processes killed on the VM at once, the claim
is released at the broker, and the VM goes back to banlieue. Needs an ADR (provisionally
ADR-0067, not yet written; take the next free number when it is drafted): it adds a route to the
node surface and one to the authorizer's, a field to the claim's record and a condition to the
`AgentSandbox` status, and a section to the policy bundle.

Builds on roadmap 06 (the jail and its nftables table, ADR-0020), roadmap 07 (the egress proxy,
ADR-0025), roadmap 08 (the `AgentSandbox` status), roadmaps 09 and 11 (the signed bundle), and
roadmap 10 (the gateway and its decisions, ADR-0062). Uses ADR-0033's ending of a claim from the
guest and ADR-0045's log stream. Roadmap 16, when it lands, lets a trip name the binary that took
the bait.

## Why

An allowlist bounds where a hijacked workload can go; it does not say whether the workload is
hijacked. Today a refusal is a log line, and a typo, a probe and an attack produce the same line,
so nothing can act on one. A decoy separates them: no legitimate run touches it, so one touch is a
signal strong enough to justify ending the sandbox without a person in the loop.

## Where it is today

- The jail's chain admits a short list of destinations and then logs and drops
  (`crates/mediatore-guest/src/net.rs`, the `mediatore-sandbox drop:` prefix). The drop is a
  kernel log line; nothing reads it.
- The egress proxy (`crates/mediatore-guest/src/egress.rs`) sees every request in the clear:
  the workload calls `http://127.0.0.1:<port>/<host>/<path>`, a `CONNECT` is `405`, and the
  proxy makes the upstream TLS itself. It already refuses a host outside the routes (`404`) and a
  foreign `Authorization` or credential header (`401`), and logs; nothing reacts.
- The gateway refuses an authority outside the claim's allowlist and reports the decision to the
  broker (ADR-0062). That report is lossy by design (a bounded queue, one attempt, decision 4) and
  the broker logs it and keeps nothing (decision 5), so it cannot carry an action.
- A claim can already be ended from the guest: `POST /v1/me/exit` (ADR-0033), under the node's
  SVID, writes the exit to the record and releases the claim (entry retracted first, then the
  record revoked; `release` in `crates/mediatore-claims/src/lib.rs`). A revoked record is refused
  by the gateway on its next ask, up to `fresh_secs` (30 by default) after the release.
- Nothing in the jail's filesystem or environment is planted.

## Invariants (proposed)

1. **A trap trips on use, never on discovery.** Listing a directory, reading a file, `env`,
   `grep -r ~` and a `netstat` do not trip. Completing a connection to a decoy port, requesting a
   decoy route, or sending a decoy credential does. Agents read everything; they should not be
   killed for it.
2. **No trap shares anything with a route the claim may use.** A decoy's port, host and
   credential are never one the claim's policy grants; admission refuses the overlap.
3. **The verdict is the guest's, the proxy's or the gateway's, never the workload's.** The
   workload has no identity to report with. A trip reaches the broker under the node's SVID or the
   authorizer's.
4. **Containment is local and comes first.** The guest cuts the sandbox uid's network and stops
   the jail before it makes any network call of its own. The broker's release is the authoritative
   end, not the first line.
5. **A trip that cannot be reported still ends the jail.** The guest's containment does not wait
   on the broker; the report is retried until it is acknowledged or the VM is gone.
6. **The bait is per claim and useless anywhere else.** A canary value is generated for the claim,
   valid nowhere (not a phantom token, not a real credential), and its sighting is attributable to
   that claim alone. Which ports, routes and values are traps is held outside the jail.
7. **A tripped claim is never restarted.** ADR-0033's restart policy does not apply, and the
   `AgentSandbox` reconciler does not claim again on its own.
8. **Never log the bait.** A trip logs the claim UID, the trap's kind and id, the port or
   authority; never the canary value, the phantom, or a request body.
9. **Shadow first.** `policy.traps: off | shadow | enforce`, refused at start when it is anything
   else. In `shadow` a trap logs and reports `would_trip` and ends nothing, as ADR-0030 and
   ADR-0061 rolled out.

## The trap kinds

| Kind | The bait | It trips when | Seen by |
| --- | --- | --- | --- |
| Decoy port | Loopback listeners that look like services (`:22`, `:2375`, `:6443`, `:8200`), and the link-local metadata address (`169.254.169.254:80`) | a TCP handshake from the sandbox uid completes | the guest (root, outside the jail), which owns the listeners; the jail's chain admits the sandbox uid to them |
| Decoy route | A host on the proxy that is no audience, advertised to the workload (`VAULT_ADDR=http://127.0.0.1:<port>/vault.internal/`) | any request names it | the egress proxy |
| Canary credential | Per-claim values in the places tools look (`~/.aws/credentials`, `~/.git-credentials`, `~/.netrc`, a `*_TOKEN` variable) | the value appears in a request the proxy is asked to forward: a header, the query, or the body up to a bound, raw, URL-encoded or base64 | the egress proxy |
| Decoy host | An authority the bundle names as a trap at the gateway | a tunnel or inject request for it arrives under a claim SVID | the gateway authorizer |

The decoy host matters only for a workload that has left the jail and holds the claim's SVID: a
jailed workload reaches the gateway through the proxy alone, and the proxy refuses a host outside
its routes first. That is the case worth catching, so it stays, behind the other three.

A file trap (fanotify on a decoy file, tripping on read) is rejected by invariant 1: it would
fire on every agent that greps its home directory.

## What a trip does

1. **On the VM, at once.** The guest replaces the sandbox uid's chain with a drop of everything,
   in one `nft -f` transaction, and then kills the jail's process tree (or freezes its cgroup;
   question 1). Network first, then processes. The time from the trip to the cut is measured and
   recorded in the ADR. A trip seen by the proxy refuses the tripping request itself, and the
   proxy forwards nothing more for the claim before it tells the guest.
2. **Logs.** What ADR-0045 has collected is flushed with a final line naming the trap, within a
   bounded wait.
3. **Report.** `POST /v1/me/trip` under the node's SVID: the trap's kind and id, the time, the
   port or authority. Retried with backoff until acknowledged (unlike ADR-0062's decisions).
4. **At the broker.** `tripped` is written on the record by compare-and-set (ADR-0057), and the
   claim is released as any other: the entry retracted, the record revoked, the
   `VirtualMachineClaim` deleted, so banlieue destroys the VM. The `AgentSandbox` gets a
   `Tripped` condition with the trap's kind as its reason, and the CLI shows it.
5. **At the gateway.** A decoy host trips at the authorizer, which refuses the claim locally from
   then on (its cache marks the claim tripped, so `fresh_secs` is not a window) and reports at
   `POST /v1/gateway/trips`, a route of its own beside ADR-0062's, retried, under the
   authorizer's identity.

## The design questions for the ADR

1. **Kill or quarantine.** Ending the VM destroys what a responder would want to look at. The
   alternative keeps it frozen and cut off for a bounded time before the release. Proposed: kill
   by default, since a compromised VM kept running is a risk of its own and the log stream holds
   the record; quarantine as an option with a hard upper bound, if at all.
2. **Where traps are declared.** A default set built into the guest, enabled by the mode, with the
   signed bundle able to add decoy routes and hosts and to turn a default off per policy (a new
   `traps` section, a new `P` code at admission for an overlap with a grant). Or broker
   configuration only. Proposed: defaults in the guest, additions in the bundle.
3. **Who makes the canary values.** The guest at boot (simplest; the gateway never sees them, so
   canary detection is the proxy's alone), or the broker at claim time (sealed on the record, so
   the gateway's inject listener could match them too). Proposed: the guest.
4. **How far the proxy looks.** Headers and the query always; the body up to a bound (64 KiB
   proposed), in the three encodings. A value the workload transforms first (reversed, split,
   encrypted) is not caught; the ADR says so, and the decoy port and route remain.
5. **The channel from the proxy to the guest.** The proxy runs as the sandbox user outside the
   jail; it tells the guest over a unix socket the jail cannot reach (its own directory, root
   owned, the proxy's uid admitted by the peer credential). Both are already in the trust base.
6. **Readiness.** Under `enforce`, a guest that cannot arm its traps does not report ready
   (ADR-0019), so a sandbox never runs believing it is guarded when it is not.
7. **After a trip.** Whether the `AgentSandbox` may be claimed again: never on its own; on a spec
   change, or on an acknowledgement (an annotation the owner sets). Repeated trips on one
   `AgentSandbox` back off.
8. **A self-inflicted trip.** A workload that wants its sandbox ended can already exit. A third
   party that steers an agent into a decoy (a planted README) ends a run the requester wanted:
   that is the intended outcome, and the ADR states it as the cost.
9. **What the requester sees.** The kind and the port or authority, not the trap's full layout.

## Phases

### Phase 0: design

- [ ] The ADR written and accepted, the questions above decided.
- [ ] CALM: the guest's `trip` flow, `POST /v1/me/trip`, `POST /v1/gateway/trips`, the record's
      `tripped`; `make calm-validate` and `make calm-diagrams`.
- [ ] notaio: the bundle's `traps` section agreed with its schema, if question 2 puts it there.

### Phase 1: containment on the guest

- [ ] A `trip` module in `crates/mediatore-guest`: the drop-all ruleset for the sandbox uid,
      rendered as text and pinned by tests as `net.rs` is; the jail stopped after the cut.
- [ ] Live test in `crates/mediatore/tests/jail_exec_live.rs` on the build host: after a trip a
      connection from the sandbox uid fails, no jail process remains, and the cut takes under the
      bound the ADR sets.
- [ ] A trip the broker cannot hear about still contains the jail (the broker faked down).

### Phase 2: the broker and the status

- [ ] `POST /v1/me/trip` on the node surface: the node's SVID only, the claim bound to it, the
      body validated; `tripped` written by compare-and-set, then the release.
- [ ] A tripped claim is not restarted (ADR-0033) and its token is refused at `POST /v1/token`.
- [ ] The `Tripped` condition on `AgentSandbox`, the reconciler's no-reclaim rule, the CLI's view.
- [ ] e2e in `crates/mediatore/tests/e2e_dev.rs`: a trip ends the claim; a trip from a
      non-node peer, from another claim's node and for a revoked claim are refused or no-ops; a
      second trip is idempotent.

### Phase 3: decoy ports

- [ ] The guest's listeners and the jail chain's admission of them; the link-local address.
- [ ] `shadow` and `enforce` behind `policy.traps`, refused at start when anything else.
- [ ] Live test: `curl 127.0.0.1:2375` from the jail trips; the same port closed under `off`.

### Phase 4: decoy routes and canary credentials at the proxy

- [ ] Decoy routes in the proxy's table, refused and reported; the advertised variables.
- [ ] Canary values generated per claim, planted outside the image's read-only paths before the
      jail starts, held by the guest; the proxy's matcher, unit-tested on the three encodings and
      the bound.
- [ ] The proxy-to-guest socket, peer-credential checked.
- [ ] e2e in `crates/mediatore/tests/e2e_egress.rs`: the canary in a header, in a query and in a
      body each trip; a request that merely reads the file trips nothing; a legitimate route is
      unchanged.

### Phase 5: decoy hosts at the gateway

- [ ] The authorizer's trap check, its local refusal of the tripped claim, and
      `POST /v1/gateway/trips` with retry.
- [ ] e2e: a tunnel for a decoy host under a claim SVID ends the claim with the guest absent.

### Phase 6: docs, threat model, live proof

- [ ] `docs/guides/tripwires.md`: the kinds, the modes, what a requester sees, and how to read a
      trip.
- [ ] Threat-model pass: the new routes (TB-6 and the authorizer's), the proxy as a reader of
      request bodies for canaries, a trip as a denial of service a third party can cause, the
      transformed-canary gap in §8; stamp bumped.
- [ ] A false-positive soak in `shadow` on the homelab: a run of ordinary Claude Code tasks with no
      `would_trip`.
- [ ] Live on the homelab under `enforce`: a Claude Code sandbox given a planted instruction to
      send `~/.aws/credentials` somewhere is ended, its VM is gone, and its `AgentSandbox` shows
      `Tripped`.
