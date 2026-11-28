<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0077: Chaff ports: a probe of the ports the jail admits is a use

**Status:** Accepted and implemented 2026-11-28, under `policy.traps` `shadow` and `enforce`
(`chaff_ports` and `HONEST_PROBES` in `crates/mediatore-guest/src/draw.rs`, `Ruleset::with_chaff`
and `read_chaff` in `net.rs`, `chaff_cause` and the reader in `trip.rs`, `JailTraps::with_chaff`
in `jail.rs`, the arming in `arm.rs`). Proven hermetically by the guest's unit tests, by `nft -c`
on the build host, and live on the build host in a throwaway namespace by
`a_connect_to_a_chaff_port_is_a_use_at_any_address` and
`a_probe_of_a_chaff_port_ends_the_run_under_enforce` (`crates/mediatore/tests/jail_exec_live.rs`,
a debug build: `containment_ms` 43 and 61 in two runs, every process of the uid gone 263 and
272 ms after the reader's verdict); `make check` green. Not proven: anything on a booted VM (*What must be proven*). The threat-model pass
done 2026-11-28 (R-83 narrowed, R-99) · **Date:** 2026-11-28

Amends [ADR-0069](0069-tripwires-on-the-vm-a-decoy-the-workload-takes-ends-its-sandbox.md)
decisions 2, 3 and 10 (a third source of `port` events, drawn per claim beside the decoys, and
one more set and rule in the claim's table) and answers its open question 6 and the limit its
consequences name under "What it does not catch" (accepted risk R-83 in the threat model).
Changes no wire type, no token shape, no SPIFFE ID, nothing at the broker or the gateway, and
nothing under `policy.traps: off`.

## Context

Under ADR-0069 the jail's Landlock admits a TCP connect to the egress proxy's port, to each
drawn decoy port, and to 80 when the metadata decoy is drawn (`--connect-port`,
`crates/mediatore-guest/src/jail.rs`; `Draw::connect_ports`, `draw.rs`), at every address, and
refuses every other port in the syscall with `EACCES`. Nothing listens on a decoy port: the
claim's table redirects the sandbox uid's connection to a decoy port on loopback to one trap
listener, which notes the use when it accepts (`net.rs`, `decoy.rs`).

Live, 2026-11-27, a workload that knew this swept the port range and found every decoy, without
a trip. The redirect matches `127.0.0.1` alone, so a connect to a decoy port at any other
address reaches the claim's chain and is dropped (`EPERM`), and a public address is no `denied`
class; an address with no route fails before any hook (`ENETUNREACH`). Either answer differs
from Landlock's `EACCES`, so the set of admitted ports can be read off the errors with no packet
that a decoy or a class sees. Every admitted port but the proxy's is a decoy, so knowing the set
is knowing the decoys.

ADR-0069 named the follow-up: ports Landlock admits that nothing listens on, any use of which
trips, so that probing which ports are admitted is itself a use.

What shapes the answer:

- **A trip is decided on the VM by the guest** (ADR-0069 decision 1); the claim's table is one
  `nft -f` transaction keyed by the sandbox uid, and the guest already reads two counted sets
  of it every 250 ms for the `denied` classes (`read_denied`, `net.rs`; `watch_denied`,
  `trip.rs`).
- **The trap listener notes a use on accept**, which needs a completed handshake, on loopback,
  over IPv4 (`SO_ORIGINAL_DST`).
- **Landlock admits a port at every address**, so a port added to it is bounded only by the
  claim's table at any other address (R-82).
- **The draw is the secret, never the method** (ADR-0069 decision 3): this ADR is public, and
  only each claim's draw is not.

## Decision

1. **Chaff ports.** Under `shadow` and `enforce` the guest draws, per claim, a set of chaff
   ports. Landlock admits each beside the decoys. Nothing listens on one, nothing is redirected
   from one, and nothing answers: the SYN is dropped and the connect waits until it times out,
   as a connect to a decoy port at an address other than loopback does. Any new TCP connection
   of the sandbox uid to a chaff port, **at any address and in either family**, is a use.

2. **How many, and drawn how.** From 16 to 32, the count uniform, from the OS's random source,
   each port uniform in 1024 to 65535 (`chaff_ports`, `crates/mediatore-guest/src/draw.rs`).
   Its own draw after the claim's draw and the trap listener's port, so the claim's draw is what
   it was. A chaff port is never:
   - a seed port of roadmap 17 (a named service an honest tool may look for on loopback or a
     private host);
   - a port in `HONEST_PROBES`, the ports common tools connect to on their own without being
     told (an OpenTelemetry exporter's 4317 and 4318, a local model server's 11434, a
     debugger's 9229 and 5005, the development servers' 3000, 4200, 5173, 8000, 8888, a SOCKS
     or HTTP proxy's 1080 and 3128, `git://`'s 9418, ...);
   - a port the claim's list uses (every destination's and the proxy's, `Ruleset::ports`), the
     pull listener's (18129 by default), one the VM listens on, a port of any of the claim's
     routes (its endpoint's and its inject port), a decoy port, the metadata decoy's port
     number, or the trap listener's.

   A collision draws that port again, at most `ATTEMPTS` times; a port that cannot be placed
   fails the arming (ADR-0069 decision 5: under `enforce` no jail starts), and a draw is never
   shortened. The ruleset refuses chaff that breaks any of these rules (`Ruleset::with_chaff`,
   `net.rs`), and refuses chaff on a ruleset that carries no draw.

3. **The use is the SYN, counted in the claim's table.** In the sandbox uid's chain, after the
   allowlist and before the `denied` rules:

   ```text
   set chaff { type inet_service; elements = { <drawn> } }
   set chaff_used { type inet_service; size 64; flags dynamic; counter; }
   ...
   tcp dport @chaff ct state new update @chaff_used { tcp dport } counter drop
   ```

   The kernel puts the port in `chaff_used` before `connect` returns, so nothing the workload
   does afterwards undoes the use. `chaff_used` is keyed by the port and can hold every chaff
   port, so no other destination can fill it, unlike the `denied` sets. The guest's reader of
   the `denied` sets reads and zeroes `chaff_used` too (`read_chaff`, `net.rs`), every 250 ms
   (`DENIED_EVERY`), and notes each port with packets as a use. The rule logs nothing to the
   kernel: a log line would print the drawn port on the VM's console.

   Rejected for detection: redirecting chaff to the trap listener. It sees a use only once a
   handshake completes (a non-blocking connect closed at once may never be accepted), its
   redirect (`dnat ip to`) carries IPv4 alone, and an answer is exactly the plausibility chaff
   must not have. The cost of the set is latency: a chaff use is noted at the reader's next
   pass, at most 250 ms after the SYN plus one `nft` run, where a decoy's is noted on accept.

4. **The event: kind `port`, trap `chaff`.** A chaff use is reported as `kind: port`,
   `trap: chaff`, `target: {port: <the chaff port>}`, `source: drawn`. The address the
   workload chose is not reported: it is the workload's value, and the port is enough to name
   the trap. Not a new kind: a `port` event already means "a port the guest drew was used", and
   the wire's enum, the `status.tripwires` schema in both served versions, the broker's
   validation and the CLI take this event as they are. `chaff` tells the owner what it means: a
   port nobody would use but a scan. It ends the claim under `enforce` and is `would_trip` under
   `shadow`, as any `port` use; the `policy.traps_denied` switches do not apply to it, since its
   target is drawn and not the workload's.

   What each reader learns. The owner (whoever may `get` the sandbox) sees, under `shadow`, the
   chaff ports a scan touched, which is part of the draw of a sandbox still running, as
   ADR-0069 accepted for decoys; under `enforce` one port, of a sandbox that has ended. The
   workload reads nothing of the status. A sweep under `shadow` folds into one entry per port
   touched, within ADR-0069's bounds (32 distinct events a minute, 16 entries with `overflow`,
   the oldest `shadow` entry evicted first).

5. **Landlock and the confinement line.** The chaff ports join the jail's `--connect-port`
   list, sorted with the decoy ports so that the order says nothing (`JailTraps::with_chaff`,
   `jail.rs`). The `confinement applied` line still reads `connect_ports=<n> ports`, where `n`
   is now the proxy's port, the decoys, 80 with the metadata decoy, and the chaff: the count no
   longer tells how many decoys there are, and never which.

6. **Interaction with the `denied` classes.** The chaff rule precedes the `denied` rules, so a
   chaff port is never `loopback_port` or `private_range`; at a public address, where a dropped
   connection was no class, it is now a use. `loopback_port` and `private_range` see what they
   saw before for every other admitted port.

7. **Other uids are untouched.** The rule is in the chain the sandbox uid alone jumps to (`meta
   skuid <uid> jump sandbox`). Another uid's connection to a chaff port is neither refused nor a
   use. Unlike a decoy port, where every other uid is refused so that an accepted connection is
   the sandbox uid's, nothing listens on a chaff port and the use is keyed on the uid itself;
   refusing root's outbound connections on 16 to 32 random ports at every address could break
   the guest's and the VM's own traffic for nothing.

8. **Under `off` nothing changes, byte for byte.** No chaff is drawn, the ruleset, the jail's
   arguments and the proxy's are what they were before ADR-0069 (pinned by the existing tests,
   which now also look for `chaff`).

9. **Nothing of the chaff leaves the VM** but the one port a report names. The public hash of
   the ruleset (ADR-0069 decision 13, amended) leaves the two sets and the rule out, so it is
   still the hash of the claim under `off`; an `nft` refusal of the armed table writes `<drawn>`
   in place of every chaff port too; no log line names one.

## Consequences

- **Enumerating the admitted ports costs the run.** A sweep that reaches the claim's table on
  an admitted port meets 16 to 32 chaff ports beside 2 to 5 decoys (and 80 with the metadata
  decoy): the first admitted port it touches is chaff at least 16 times in 22 for any draw, and
  in a simulation of 20,000 seeded draws in a random order it was chaff in 17,402 (87 %) and
  every decoy came before any chaff in 9 (`a_sweep_of_the_admitted_ports_meets_chaff_before_it_learns_the_decoys`,
  `draw.rs`; a simulation, not a measurement). Under `enforce` the first chaff use ends the
  sandbox. A port scan of the VM's own address or of a LAN host, which tripped
  nothing before (a decoy redirect matches loopback alone), now trips at its first chaff port.
- **What chaff does not catch.**
  - *A workload that connects to nothing but the proxy.* Every port Landlock admits but the
    proxy's is a trap, and this ADR says so; an attacker that reads it never needs to probe.
    Chaff takes away the probe, not that choice, and the `route`, `credential` and `denied`
    traps and the allowlist are what stand against such a workload.
  - *A probe that fails before any hook.* A connect to an address with no route (an IPv6
    address on a VM with no IPv6 route; any off-link address on a VM with no default route)
    fails with `ENETUNREACH` on an admitted port and `EACCES` on a refused one, with no packet.
    So the admitted set can still be read without a use. What it shows is now decoys and chaff
    mixed, 2 to 5 among 18 to 37 ports (with the metadata decoy's 80), and telling them apart
    takes a use. Closing this needs the sandbox uid to have a route to everything (a policy
    route by uid), which is not done here.
  - *Ports never drawn as chaff.* Below 1024, the seed ports and `HONEST_PROBES` hold no chaff,
    by this public rule, so an admitted port there is a decoy (or 80 for the metadata decoy).
    A workload that probes only those with the no-route oracle can find a decoy among them.
  - *A workload that only tries ports a real tool would use*, which are the seeds and the honest
    probes, meets the decoys alone, as before.
- **Honest runs can meet chaff.** A tool that connects to a chaff port by itself trips: its own
  test server on a port the kernel chose, a service on a private host on a high port, a program
  that ignores the proxy and dials a public address on an unusual port. Each such connection
  already failed (Landlock or the chain refused it), and each distinct port has about a 1 in
  2000 to 1 in 4000 chance of being chaff. `HONEST_PROBES` takes the common ones out, and the
  `shadow` soak shows the rest as `trap=chaff`.
- **A chaff use is noted up to 250 ms later than a decoy's.** In that window the workload's
  connect is still waiting on a SYN that was dropped, and its use is already in the kernel's
  set; under `enforce` the
  proxy is told of the trip only when the reader notes it, so it keeps forwarding the claim's
  allowed traffic for that long, which it does for any honest request anyway (compare R-95).
- **The claim's table grows** by two sets and one rule, and the jail's Landlock ruleset by 16 to
  32 port rules; neither is measurable against a claim's start.

## Alternatives rejected

- **Redirect chaff to the trap listener** (decision 3): needs a handshake, IPv4 alone, and
  answers.
- **A new kind `chaff`.** It would change the wire's enum, the CRD's enum in both served
  versions, the broker's validation, the status fold and the CLI, for a fact the trap name
  already carries.
- **Fold chaff into the `denied` sets.** Those sets hold any dropped destination, so a workload
  could fill them (1024 elements) with connections that are no use and then probe unseen; and
  their classes are switched per deployment, while a chaff use is always a use.
- **Admit every port in Landlock.** Removes one of the jail's three layers (ADR-0024), and would
  make every honest localhost probe reach the table; ADR-0069 decision 10 already rejects it.
- **Refuse other uids at chaff ports**, as at decoy ports (decision 7).
- **A switch to set chaff to `report`.** A chaff port is the guest's own value, chosen off every
  port an honest tool is known to use; if a soak shows otherwise, the fix is in
  `HONEST_PROBES`, not a switch an operator leaves on.

## What must be proven

- Unit, in `crates/mediatore-guest`: the chaff draw within its bounds and off every reserved
  port, and a draw that cannot place a port failing, never shortened (`draw.rs`); the ruleset
  rendering the sets and the rule in the sandbox uid's chain alone, refusing chaff on any port
  the claim or the draw uses and beside no draw, keeping the public hash and redacting the
  chaff from an `nft` error, and reading `chaff_used` (`net.rs`); a chaff use being a `port`
  event named `chaff` that trips under `enforce` whatever the `denied` switches say, from the
  reader (`trip.rs`); the jail admitting the chaff, sorted, and printing no port (`jail.rs`);
  arming drawing chaff into the ruleset and the jail, and under `off` none (`arm.rs`).
- `nft -c` on the build host accepting the armed ruleset with chaff
  (`nft_accepts_the_ruleset_with_decoys_and_the_metadata_redirect`, `net.rs`).
- Live in `crates/mediatore/tests/jail_exec_live.rs`, in a throwaway namespace on the build
  host: a connect from the jail to a chaff port on loopback and at another address is reported
  as `port`/`chaff` under `shadow`; under `enforce` a sweep is ended at its first chaff port.
- On a booted VM: the same, with the real proxy, the real guest and the broker's record.

*Proven 2026-11-28, on the build host (Debian 13, Rust 1.99.0, nftables 1.1.3):*

- *Unit: `chaff_is_drawn_within_its_bounds_and_off_every_reserved_port`,
  `the_honest_probes_are_ports_tools_use_and_none_is_a_seed`,
  `a_chaff_draw_that_cannot_place_a_port_fails_and_is_never_shortened`,
  `a_sweep_of_the_admitted_ports_meets_chaff_before_it_learns_the_decoys` (`draw.rs`);
  `the_chaff_ports_are_dropped_and_counted_for_the_sandbox_uid_at_every_address`,
  `chaff_is_refused_beside_no_draw_and_on_any_port_the_claim_or_the_draw_uses`,
  `the_public_hash_and_a_refusal_leave_the_chaff_out`,
  `the_chaff_set_is_read_and_zeroed_and_idle_ports_are_skipped` (against a listing captured on
  the build host) and `with_no_decoys_the_ruleset_is_byte_identical_to_before`, which now also
  looks for `chaff` (`net.rs`);
  `a_chaff_use_is_a_drawn_port_named_chaff_that_trips_whatever_the_denied_switches_say`,
  `the_reader_of_the_chain_notes_a_chaff_use_as_a_port_trip_with_its_count` (`trip.rs`);
  `chaff_ports_are_connect_ports_beside_the_decoys_in_an_order_that_says_nothing` (`jail.rs`);
  `arming_draws_chaff_into_the_ruleset_and_the_jail_off_every_port_the_claim_uses` (`arm.rs`).*
- *`nft -c` took both shapes of the armed ruleset with chaff
  (`nft_accepts_the_ruleset_with_decoys_and_the_metadata_redirect`).*
- *Live, eleven tripwire tests in a throwaway namespace, a debug build, all passing: under
  `shadow` a connect from the jail to a chaff port on loopback, at `192.0.2.10` (routed through
  loopback in the namespace) and at `::1` was each reported as `port`/`chaff` with source
  `drawn`, none as a `denied` class, and root reached a listener of its own on a chaff port with
  nothing reported; under `enforce` a probe of a chaff port at `192.0.2.10` ended the run
  (`containment_ms` 43 and 61 in two runs, every process of the uid gone 263 and 272 ms after
  the reader's verdict, the run ended 529 and 537 ms after it started, the 250 ms read interval included); the confinement line
  counted the proxy, the decoys and the chaff, and no chaff port appeared in anything the jail
  could read; `nothing_is_open_under_off` found no chaff in the table.*
