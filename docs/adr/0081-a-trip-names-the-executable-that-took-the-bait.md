<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0081: A trip names the executable that took the bait

**Status:** Proposed · **Date:** 2026-11-28

Answers [ADR-0069](0069-tripwires-on-the-vm-a-decoy-the-workload-takes-ends-its-sandbox.md)'s
open question 4 ("Whether roadmap 16's attribution should add the tripping binary to the event,
and under which `source`") and the line of roadmap 17 that "Roadmap 16, when it lands, lets a
trip name the binary that took the bait". Extends ADR-0069 decisions 7, 8 and 9 (the event, the
record and `status.tripwires` gain an optional `process`). Builds the attribution that roadmap
16 (per-binary policy, `.github/community/16-per-binary-egress-policy.md`) proposes for its
phase 2, and uses it first where nothing is refused on its account: a trip that has already
happened. Changes no token shape, no SPIFFE ID and no decision a trap makes. It changes the trip
report's wire type and the status schema, so the full ADD cycle and a threat-model pass apply
when it is accepted.

## Context

A trip event today names `kind`, `trap` or `class`, `target`, `source` (`drawn` or `workload`)
and, under `enforce`, `containment_ms` (`TripEvent`, `crates/mediatore-proto/src/trip.rs`). It
does not say which process took the bait. A responder reading `credential github` on a sandbox
running Claude Code cannot tell `node` from a package's `postinstall` script, nor a process in
the jail from one of the sandbox uid that is outside it (ADR-0070's escape, R-16).

What each decider knows at its verdict, from the code:

- **A decoy port** (`serve`, `crates/mediatore-guest/src/decoy.rs`). The claim's table
  redirects the sandbox uid's connections to the decoy ports to one trap listener (root's, on
  loopback). `accept()` returns the client's address and port (the code discards it today), and
  `SO_ORIGINAL_DST` gives the decoy reached. The listener notes the trip **before a byte is read
  or written**; a connection that names no decoy is closed at once, a named one is answered for
  at most `ANSWER_WITHIN`. `SO_PEERCRED` does not exist for TCP; ADR-0069 decision 2's first
  amendment records that a `NETLINK_SOCK_DIAG` lookup "loses a client that connects and closes
  at once", which is why the uid is now guaranteed by the table instead.
- **A route or credential trap** (`Traps::tell`, `crates/mediatore-guest/src/egress.rs`). The
  proxy runs as the sandbox uid outside the jail; its client is a loopback TCP peer. It tells
  the guest a `ProxyTrip { at, kind, trap, class, host }` over the trap socket and has the
  connection in hand: the client is waiting for the answer, or still sending its body.
- **A `denied` class** (`watch_denied`, `crates/mediatore-guest/src/trip.rs`). The chain keeps
  a dropped new TCP connection in `denied4` and `denied6` **by destination**, read every 250 ms.
  No source port, no socket. A blocking `connect` that the chain drops stays in `SYN_SENT` and
  retransmits after about a second; a non-blocking one the workload closes is gone.
- **Containment** (`decide`, `trip.rs`). The first use that ends the run is cut first (the `nft`
  transaction, 54 ms on the build host), then `shared.signal` wakes the supervision, which kills
  the jail and every process of the sandbox user (`kill_sandbox_processes`,
  `crates/mediatore-guest/src/supervise.rs`). Once killed, `/proc/<pid>` is gone.

The kernel gives a route from a TCP 4-tuple to a process: an `INET_DIAG` request
(`NETLINK_SOCK_DIAG`) returns the client socket's inode and uid; the processes holding that
inode are those whose `/proc/<pid>/fd` has a link to `socket:[<inode>]` (what `ss -p` does);
`/proc/<pid>/exe` is the executable. Opening `/proc/<pid>/exe` yields a descriptor of the file
that was executed, which stays readable after the process dies and after the file is unlinked
or replaced. The guest is root with every capability (`image/systemd/mediatore-guest.service`),
so a workload's `prctl(PR_SET_DUMPABLE, 0)`, which hides `/proc/<pid>/fd` and `exe` from its own
uid, does not hide them from the guest.

Roadmap 16 wants the same chain (peer address, socket inode, holders, identity) in an `attrib`
module, the identity being "`/proc/<pid>/exe` and the SHA-256 of its content, compared with
digests the guest computes when it unpacks the verified image", an interpreter being "the
identity of every script it runs", and "the script path from argv is logged, never matched".
It is not started, and its ADR is not written (its text still names ADR-0066, a number since
taken by "eligibility by group from the signed bundle").

## Decision

1. **Attribution never delays containment, and races the kill on purpose, not by accident.**
   It starts at the verdict, in parallel with the cut, in a task of its own; neither the cut
   nor the kill waits for it. The race-critical step is opening `/proc/<pid>/exe` (and reading
   `/proc/<pid>/ns/pid`), microseconds once the pid is known; everything slow (hashing) runs on
   the open descriptor afterwards. Since the kill follows the cut, the attribution normally has
   the cut's tens of milliseconds; when it loses, the event says so (decision 4). The report of
   the event that ends the run waits at most `ATTRIBUTE_WITHIN` (500 ms from the verdict) for
   the attribution, then leaves with what is ready. Under `shadow` nothing is killed and the
   same bound applies to the report.

2. **One module, `attrib`, the guest's** (`crates/mediatore-guest/src/attrib.rs`, new): from a
   TCP 4-tuple (or, for `denied`, a destination) to the socket's inode by `INET_DIAG`, filtered
   to the sandbox uid; to its holders by a scan of `/proc/<pid>/fd` over the sandbox uid's
   processes only, bounded (at most 4096 processes and 50 ms, then `unreadable`); to an
   identity per holder (decision 3). The pure parts are tested against a fake `/proc` and a fake
   diag that are never more permissive than the kernel (`rules/testing.md` rule 2). It is the
   module roadmap 16 phase 2 asks for; the proxy may call it later for enforcement, the guest
   calls it now for trips, as root.
   - **Decoy port**: the listener keeps the accepted stream open until the lookup has run
     (bounded by `ATTRIBUTE_WITHIN`), so a client that does not close is found. The client's
     socket is `(peer address, peer port) -> (original destination)`: the client never saw the
     redirect.
   - **Route and credential**: `ProxyTrip` gains `peer_port: u16` (the proxy's accepted
     connection's remote port), sent before the proxy writes its `403 trap`, while the client
     is still waiting. The proxy reads no `/proc`; the guest looks the socket up.
   - **`denied`**: best effort. At each read of the sets, a new destination is looked up among
     the sandbox uid's `SYN_SENT` sockets to it; one identity found is recorded, none or several
     is `gone` or `ambiguous`.
   - **`protocol` and `segment`** (ADR-0070): no process on a VM is named; the field is absent.

3. **What is recorded: the executable's identity, small and kernel-sourced.** A new optional
   `process` on `TripEvent` (`TripProcess`, `crates/mediatore-proto/src/trip.rs`), exactly one
   of:
   - **attributed**: `{ "exe": <basename>, "origin": <origin>, "sha256": <hex>, "jail": <bool> }`
     - `exe`: the basename of `/proc/<pid>/exe`'s target, 1 to 63 of `[A-Za-z0-9._+-]`, else
       `invalid`; and `invalid` when the guest's matcher finds a bait value in it (ADR-0069
       decision 12). Never the directory, never argv, `comm`, the environment, the working
       directory or the pid.
     - `origin`: where the executable lies, a closed set: `image` (in the unpacked rootfs,
       outside the writable directories), `writable` (under `/work`, `/tmp` or the sandbox
       home), `deleted` (the kernel reports it unlinked), `anonymous` (a `memfd`), `outside`
       (not under the sandbox root at all: a sandbox-uid process running the VM's own
       binaries, which only an escape does).
     - `sha256`: of the executed file, read through the descriptor opened in decision 1, at
       most 512 MiB; absent when larger or not done within `ATTRIBUTE_WITHIN`.
     - `jail`: whether the holder's PID namespace is the jail's (`/proc/<pid>/ns/pid` against
       the jail's init, which the supervision knows). `false` is ADR-0070's escape, seen.
   - **unattributed**: `{ "unattributed": <reason> }`, a closed set: `gone` (no holder: the
     client closed, or the socket was not found), `late` (the kill came first), `ambiguous`
     (holders of more than one SHA-256, as roadmap 16 treats them), `unreadable` (the scan's
     bounds, or a `/proc` read that failed).

   Several holders with one SHA-256 (a socket inherited across `fork`) are one identity. The
   holder is the process that holds the socket, never its ancestors (roadmap 16 question 4).

4. **Where it goes, and where it does not.** In the audit line `trip reported` (as
   `process_exe`, `process_origin`, `process_sha256`, `process_jail` or `process_unattributed`),
   in the record's `tripped` (the first event's, a new optional field of `Tripped`), on
   `status.tripwires[].process` (the first attribution of the entry; later uses that fold into
   the entry change its count, not its process), and in `mediatore sandbox get`'s trip lines.
   The fold key stays `(kind, trap, class, target)`: an attribution never splits an entry, so a
   workload cannot grow the status by running many binaries. Never in OpenTelemetry: `exe` is a
   name the workload chooses (roadmap 15 I-4), and the hash is an identity the owner's
   workload controls; the span's attributes are ADR-0069 decision 11's. It answers the second
   half of ADR-0069's question: **`source` is unchanged** (it says whose value the *target*
   is); the process is a field of its own, on `port`, `route`, `credential` and `denied` events.

5. **Sent only to a broker that takes it.** `TripEvent` denies unknown fields, so an older
   broker would refuse a report carrying `process` with `400 invalid_trip`, and the guest treats
   `400` as final (`report_with`, `trip.rs`): the claim would then end only at its deadline. So
   the broker announces `traps.attribution: true` in `GET /v1/me` (a new field of `TrapsPolicy`,
   which an older guest ignores), and the guest attributes and sends `process` only then.
   `Tripped` and the status are read leniently (an older build ignores the field; an older CRD
   prunes it), so the upgrade order is the CRDs, the broker, then the guests.

## Security analysis

| Boundary | Threat | STRIDE | Control |
| --- | --- | --- | --- |
| TB-12 | The workload names its binary `git` or sets `argv[0]` to look innocent | S/R | Decision 3: the basename is reported as the kernel has it, beside `origin` and `sha256`; argv is never read. A copy of a binary under `/work` says `writable`; once roadmap 16 phase 1 stores the image's digests, the hash can be matched (open question 2) |
| TB-12 | The workload replaces or deletes the binary after `exec` | T | The descriptor of `/proc/<pid>/exe` is the executed inode: `deleted` and the hash of what ran |
| TB-12 | The workload makes attribution fail (connect and close; many processes; `PR_SET_DUMPABLE`) | R/D | Decision 3's `unattributed` reasons, never a guess; the scan is bounded (decision 2); the guest is root, so the dumpable flag does not hide anything; the trip itself is unaffected |
| TB-12 | Attribution slows containment | D | Decision 1: neither the cut nor the kill waits; the report waits at most 500 ms |
| TB-6 / TB-2 | The owner's process names reach the broker's audit, the record and the status | I | A basename of a fixed grammar, the origin, a hash, a bool: no path, argv, environment or pid. The audit is the operator's; the status is readable by whoever may `get` the sandbox, who already reads its targets. Bait-scrubbed |
| TB-6 | A workload grows the status or the report with attributions | D | Decision 4: the fold key is unchanged, one process per entry; at most ~150 bytes per event |
| TB-7 | The guest, as root, reads a workload-made file to hash it | E/D | Read through the descriptor of an executed file, which is a regular file or a `memfd`; bounded to 512 MiB and the deadline; nothing is parsed |
| TB-6 | An older broker refuses reports that carry the field | D | Decision 5: sent only when the broker says it takes it |

## Consequences

- A trip says which executable took the bait, from where, and whether it was in the jail; the
  last turns an escape that reaches a trap from an inference into a fact.
- The first part of roadmap 16 phase 2 is built and proven on a path that refuses nothing;
  roadmap 16's ADR can take the module as is and decide only enforcement and the schema.
- An interpreter is the identity of everything it runs: a trip from `python3` says `python3`.
  The script is not recorded (open question 1).
- `denied` events are attributed only sometimes; port, route and credential events nearly
  always, except a client that connects and closes before the lookup.
- The wire type, the record and the CRD schema change; the CLI shows one more line per trip.
- The threat-model pass touches the guest's component row (a reader of the sandbox uid's
  `/proc`), TB-12 and TB-6 rows above, and §8 for the residue (an interpreter's script is not
  named; a connect-and-close is unattributed).

## Alternatives rejected

- **`SO_PEERCRED`**: unix sockets only; the decoys and the proxy are TCP.
- **An nft `log` rule with `meta`**: a log line carries the uid, the cgroup and the tuple, never
  a pid or an executable; the uid is already known.
- **seccomp user notification on `connect`** (OpenShell's way, roadmap 16's fallback): the pid
  at the call, exactly, but a supervisor in every connect's path and a new mechanism in the
  jail, for a record. Revisit if roadmap 16 needs it for enforcement.
- **eBPF on `connect`**: a new privileged mechanism and a loader in the guest, for a field.
- **argv, or `argv[0]`**: chosen by the workload, often long, and where tokens are passed on
  command lines; ADR-0069 decision 12 forbids what may carry bait in a log.
- **The full path**: under `/work` it is the owner's directory names, workload-chosen and
  unbounded; the basename and `origin` say what a responder needs.
- **Freezing the uid (`SIGSTOP`, the cgroup freezer) until attribution is done**: delays the
  kill, and ADR-0069 decision 7 rejected freezing.
- **The proxy attributing its own clients**: it runs as the sandbox uid, which a non-dumpable
  workload hides from; and it must stay the least privileged component on the VM.

## What must be proven

- Hermetic (`make check`), in `attrib.rs` against the fake `/proc` and diag: one holder
  (`a_socket_held_by_one_process_names_its_executable`), two holders of one identity
  (`a_forked_socket_with_one_identity_is_one_process`), two identities
  (`holders_of_two_identities_are_ambiguous`), a holder gone (`a_holder_that_exited_is_late_or_gone`),
  the bounds (`a_scan_past_its_bounds_is_unreadable_never_a_guess`), the grammar and the bait
  scrub (`an_executable_name_outside_the_grammar_or_holding_bait_is_invalid`), each `origin`.
  In `trip.rs`: the cut and the kill never wait (`containment_does_not_wait_for_attribution`),
  the report waits at most `ATTRIBUTE_WITHIN`. In the proto: the wire type's validation, and a
  report without `traps.attribution` byte for byte unchanged. In the broker and the claims
  crate: the audit fields, the record and the status entry, the fold key unchanged
  (`attributions_never_split_a_status_entry`).
- Live on the build host (`crates/mediatore/tests/jail_exec_live.rs`): a drawn port taken by
  `nc` in the jail names `nc`, `image`, `jail: true` and the hash of the image's `nc`; a copy
  under `/work` names `writable`; a deleted binary names `deleted`; a `curl` to a decoy route
  names `curl`; a connect-and-close is `gone`; a non-dumpable process is still named; and
  `containment_ms` against the same tests without attribution (the figure must not move).
- e2e (`e2e_dev.rs`): the broker records and shows `process`; an older-shaped broker (no
  `traps.attribution`) is never sent the field.
- Live on the homelab under `shadow`: Claude Code's trips (if any) name `node`, and a planted
  `postinstall` that reads `~/.aws/credentials` and posts it names its interpreter.

## Open questions

1. **The interpreter's script.** Roadmap 16 logs the script path from argv and never matches
   it. Recommendation: not in the event; once roadmap 16 lands, the guest's journal (the
   operator's) may carry the script's basename for an interpreter in a fixed list, never the
   broker's records.
2. **`in_image` from roadmap 16's digests.** Recommendation: add `in_image: bool` to the
   attributed shape when roadmap 16 phase 1 stores the image's digests; until then `origin`
   and `sha256` are what a responder compares by hand.
3. **`ATTRIBUTE_WITHIN`.** Recommendation: 500 ms, measured again on a VM with a release build;
   the report may leave later, the containment never does.
4. **Attribution for `denied` at all.** Recommendation: yes, best effort as decision 2 says,
   since a blocked blocking `connect` is usually still there 250 ms later; drop it if the soak
   shows it mostly `gone`.
