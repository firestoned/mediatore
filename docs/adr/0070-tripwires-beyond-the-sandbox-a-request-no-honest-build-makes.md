<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0070: Tripwires beyond the sandbox: a request no honest build makes

**Status:** Accepted 2026-11-27; implemented 2026-11-27, every class at `report` by default
(roadmap 18): the eight `protocol` classes, their fold and their audit lines
(`crates/mediatore-api/src/classify.rs`, the hook points and the route table in `lib.rs`), a
claim-scoped class at `trip` ending its claim through ADR-0069's `end_claim`
(`crates/mediatore-api/src/trip.rs`), the `tripwires` section and its start-up refusals
(`crates/mediatore/src/config.rs`), the gateway's counters, its probes reader and the `probes`
list on ADR-0062's batch (`image/gateway/nftables.conf.in`,
`image/gateway/systemd/mediatore-gateway-probes.service` and `.timer`,
`crates/mediatore-gateway/src/probes.rs`, `report.rs`), the pool VM's counters and the guest's
segment reader (`image/host-table`, `crates/mediatore-guest/src/segment.rs`), the wire types
(`crates/mediatore-proto/src/trip.rs`). **Not built:** the OpenTelemetry of decision 8 (no
exporter, roadmap 15) and the mapping of a probe's source address to a node (deferred,
decision 8). Proven hermetically by `make check` (`e2e_dev.rs` for each claim-scoped class at
both values, `e2e_gateway.rs` for the probes over the real listener); the tables' renders by
`make host-table-test` and `make gateway-render-check`, and on the build host's kernel in fresh
network namespaces (the counters move per class and not for honest traffic, the reader's unit
holds `CAP_NET_ADMIN` alone); both images built and checked. A fix round of the same day is in
(decisions 3, 4, 6 and 8 amended again): `deny_outside_rendered` records only, a `segment`
event is never put on a claim, the decisions route is limited per gateway identity and in the
batches it judges at once, and the probes summary is opened without following a link or
waiting on a FIFO. In kind, on the merged tree: on slate after `make kind-delete`, `kind-e2e-tpm` PASS (attested as `spiffe://sandbox.test/spire/agent/tpm/e4f28760dd09942c82dc86b03248494247007215cd35a9173734e14865e354c9`), `kind-e2e-x509pop`, `kind-e2e-sandbox` (the tripped path: Failed with `Tripped=True`, no second claim) and `kind-e2e-gateway` PASS, and every suite of the default `kind-e2e` set PASS, 2026-11-27. Not proven: a booted gateway
or pool VM, the classifier and the broker's status write against a real API server, the soak
across an upgrade (*What must be proven*). Threat-model pass 2026-11-27 (A-39 to A-43, R-78 to
R-95) · **Date:** 2026-11-26

Roadmap 18. The companion of
[ADR-0069](0069-tripwires-on-the-vm-a-decoy-the-workload-takes-ends-its-sandbox.md), which traps
the jailed workload on its VM. This ADR covers the actors that have already got past that: a
process outside the jail on a pool VM, a compromised gateway, an identity that should not exist.
It adds two values to ADR-0069's `kind` enum (`protocol`, `segment`) and one to its `source`
(`peer`), a `tripwires` section to the broker's configuration, a `probes` list to the batch of
[ADR-0062](0062-the-gateway-reports-its-decisions-to-the-broker.md), and lets a node with no claim
send a `segment` event on ADR-0069's `POST /v1/me/trip`. It adds no listener, no bait, no
identity and no route between components, and it changes no authorization decision: every request
it classifies is one that is refused today, and stays refused in the same words.

## Context

ADR-0069's traps live on the VM and are decided by the guest and the egress proxy. That is right
for the workload and wrong for anything stronger, because the stronger actors are exactly those
for whom the guest and the proxy are no longer in the way:

| Actor | Holds | ADR-0069 sees it |
| --- | --- | --- |
| A process of the sandbox uid outside the jail (an escape, R-16) | the claim SVID through the agent's socket, the phantom, the routes file | only if it goes back through the proxy |
| Root on a pool VM | the node SVID, the claim SVID, the draw, the guest's own reporting | no: it can skip or silence both deciders |
| A compromised gateway process (R-20, R-27) | the listeners' SVID (A-21) or the authorizer's (A-28) | no: the gateway holds no trap, by ADR-0069 decision 1 |
| Whoever can have SPIRE issue an identity the broker did not declare (A-7, TB-3) | an SVID of the trust domain | no |
| Whoever holds the broker's reach at the API server (A-11, R-46) | the store | no, and not here either (Alternatives rejected) |

What already exists and shapes the answer:

- **Past the jail, both ends of every boundary are mediatore's own code.** TB-6, TB-13 and TB-17
  are mutual TLS between two roles of one binary. An honest guest calls `POST /v1/nodes`,
  `GET /v1/me`, `POST /v1/me/report`, `POST /v1/me/exit` and `POST /v1/me/logs`; an honest proxy
  calls `POST /v1/token` for the audiences it was handed and dials a gateway for the hosts of its
  routes; an honest authorizer asks about the claim whose certificate it just verified. Each set
  is closed and known at compile time. A workload's behaviour had to be baited because it is
  open-ended; a peer's does not.
- **The refusals are already made and already logged, and nothing tells them apart.** The
  listener refuses an identity of the wrong shape at the handshake (`sandbox_authorizer`,
  `crates/mediatore-api/src/lib.rs`). The handlers answer `403 forbidden` to a peer of the wrong
  kind (`claim_of_node_peer`, `require_gateway_authorizer`), `unknown_audience` to an audience
  the claim does not have, `404` to a claim the store does not hold (`claim_egress`). The gateway
  reports each deny with its authority (ADR-0062). Each is one log line that reads the same
  whether the cause is a release racing a request or a stolen SVID.
- **The broker records what each guest was handed.** `status.record.rendered` (ADR-0061, A-32)
  holds the routes and destinations `GET /v1/me` answered. An honest proxy refuses a host outside
  its routes with `404` on the VM and never dials a gateway for it. So the broker can tell a
  gateway deny an honest proxy could have caused (a route the claim rendered, narrowed since by a
  newer bundle) from one it could not (an authority the claim was never handed).
- **The host tables already drop and count what no honest machine sends.** The gateway's input
  chain drops everything from the sandbox interface but the data plane, the relay ports and the
  inject port (`mediatore-gateway drop:`), its output chain drops a new connection towards the
  segment and each user's traffic outside its own allowlist (`mediatore-gateway out …:`,
  `image/gateway/nftables.conf.in`), and the pool VM's table drops every inbound connection
  (`mediatore-host input:`, `image/host-table`). Each is a kernel log line nothing reads.
- **The Kubernetes API has no hook on a read.** A `get` or a `list` is visible only in the API
  server's audit log, which is the operator's (A-11). The broker can watch writes; it cannot see
  who read a Secret.
- **All gateways share one authorizer identity** (A-28), so the broker cannot tell which gateway
  asked, and a class that acted on that identity would act on every gateway at once.
- **mediatore is open source**, as ADR-0069 says. Nothing below depends on a list being secret:
  there is no list. The trap is the whole space outside what the code does.

## Decision

1. **Past the jail the trap is the request no honest build makes.** No bait is planted in the
   control plane and no decoy listens anywhere. The broker, and the host tables of the gateway
   and the pool VM, classify refusals they already make. ADR-0069 property 5 (the denied space
   trips) is the whole design here, because here the honest space is closed and small.

2. **A trip changes no answer.** The tripping request gets the status, code and body the route
   returns today, byte for byte, so the caller learns nothing from being classified, and a fault
   in the classifier can refuse nothing extra and admit nothing at all. A test per class compares
   the response with the class on and off.

3. **The `protocol` classes, decided by the broker.**

   | Class | It trips when | Scope |
   | --- | --- | --- |
   | `identity_shape` | a handshake on the sandbox listener presents a valid SVID of the trust domain that is none of the admitted shapes (the listeners' `spiffe://<td>/gateway` included, while `accept_plain_gateway_identity` is off) | none |
   | `foreign_route` | an admitted identity calls a route of another kind: a claim on a node or gateway route, a node on `POST /v1/token` or a gateway route, the authorizer on anything but its own | claim, node or authorizer |
   | `unknown_route` | a request on the sandbox listener names a path the router does not serve | claim, node or authorizer |
   | `no_record` | a claim identity whose uid has no record at all, or a node identity whose EK hash is not registered on any route but `POST /v1/nodes` | none |
   | `audience_outside_rendered` | `POST /v1/token` names an audience that is in no route of the claim's `rendered` | claim |
   | `claim_never_issued` | the authorizer asks about a uid the store holds no record of, live or ended | authorizer |
   | `credential_outside_inject` | the authorizer asks for a credential for an audience that is not gateway-placed for that claim | authorizer |
   | `deny_outside_rendered` | a gateway reports (ADR-0062) a tunnel or inject deny for a claim whose authority is in no route or destination of that claim's `rendered` | claim |

   What is deliberately not a class, because an honest run produces it: a request for a claim
   released moments ago; an audience or a route that was rendered and that a newer bundle no
   longer allows (ADR-0061's follow, which already refuses and records); `no_claim` for a node
   that is not bound yet; a malformed body. `no_record` needs an ended claim's record to outlive
   its SVID, so the broker refuses to start when `store.retention_secs` is not above the claim
   SVID's lifetime (`MAX_CLAIM_SVID_TTL`, fifteen minutes; the default retention is an hour).

   *Amended 2026-11-27, three changes.*
   - *A claim with no `rendered` is not judged. `rendered` is written only for a claim under a
     policy whose bundle the broker holds (`record_rendered`,
     `crates/mediatore-api/src/follow.rs`), so `audience_outside_rendered` and
     `deny_outside_rendered` look only at a record that has one and record nothing otherwise. A
     deployment with no `policy` section gets neither class.*
   - *`no_record` has two honest sources: a node removed from the register after
     `store.node_grace_secs` (ADR-0039) while its guest still polls `GET /v1/me`, and a restore
     of the datastore. The class is `report` only (decision 6), and the runbook names both.*
   - *There is no retention refusal (this bullet replaces the one written earlier the same day,
     which said it applied outside `dev_mode`), by the maintainer's decision: any
     `store.retention_secs` is still valid, the kind tier's broker keeps `retention_secs: 0`
     (`dev/kind/broker/mediatore.yaml`), and at a retention not above `MAX_CLAIM_SVID_TTL`
     (900 s, the constant, not the configured `claim_svid_ttl`) the `no_record` class is not
     judged at all, the node case included, since an honest claim released a moment ago still
     holds a valid SVID and would read as `no_record`. The broker logs one `warn` line at start
     saying so (`Config::no_record_judged`, `crates/mediatore/src/config.rs`).*
   - *Not classified, because another refusal comes first and the answer is the same either
     way: a foreign peer on `POST /v1/me/trip` under `policy.traps: off` (`501`), on
     `POST /v1/me/logs` with logs off (`501`), and any peer whose JSON body the extractor
     refuses. An identity of no admitted shape that reaches a handler (possible only through
     the `dev_mode` header) is classified nowhere.*
   - *`deny_outside_rendered` is judged for at most 16 claims a batch. A deny for a claim that
     has ended, tripped or is unknown is not judged; an authority that does not parse counts
     as outside; an inject deny's authority is the `Host` header as it came, so the peer
     chooses it within the grammar the route checks. The "since narrowed" case is a deny for an
     authority that is in `rendered`: the judgement reads `rendered` alone.*

   *Amended 2026-11-27, after the fix round, by the maintainer's decision:
   `deny_outside_rendered` records only. Its scope is still the claim the deny names, so its
   entry lands on that claim's summary, but the claim uid comes from the authorizer's batch,
   and every gateway shares that identity: at `trip` any holder of it could end any live claim
   with a `rendered`, which decision 6 forbids for the authorizer's own classes. So
   `TripClass::may_trip` is false for it (`crates/mediatore-proto/src/trip.rs`), `trip` on it
   refuses the start like the other classes held to `report`, and nothing ends a claim for it
   whatever the configuration says
   (`a_reported_deny_outside_rendered_only_records_whatever_the_configuration_says`,
   `classify.rs`; e2e `a_reported_deny_outside_rendered_only_records_and_trip_is_refused`). Three
   classes may trip: `foreign_route`, `unknown_route` and `audience_outside_rendered`. The table's
   Scope column is unchanged; decision 6's first bullet loses this class.*

   *Amended 2026-11-27, after the fix round: the batches whose denies are judged are bounded.
   `POST /v1/gateway/decisions` takes at most 20 batches a second per gateway identity, a burst
   of 20, one bucket for the authorizer's identity and one for the listeners' (where ADR-0053's
   switch admits it), past which it answers `429 too_many_batches` with `Retry-After: 1` and
   logs and judges nothing of the batch (`GATEWAY_BATCHES_PER_SECOND`,
   `crates/mediatore-api/src/tripwires.rs`); a body refused as malformed spends nothing. An
   honest gateway sends one batch every two seconds, so the limit is forty gateways at their
   cadence. At most 4 batches are judged at once (`MAX_JUDGING_BATCHES`); the denies of a batch
   that finds every permit held are not judged, its answer is unchanged, and the count is one
   `warn` line at the next flush
   (`the_decisions_route_takes_so_many_batches_a_second_per_gateway_identity`,
   `a_batch_that_finds_every_judging_permit_held_is_answered_and_not_judged`,
   `an_honest_fleet_at_its_cadence_never_meets_the_decisions_limit`, `classify.rs`).*

4. **The `segment` classes, decided by the host tables.**

   | Class | It trips when | Decided on |
   | --- | --- | --- |
   | `gateway_port` | a new connection from the sandbox interface to a port the gateway does not serve | the gateway |
   | `gateway_output` | a gateway user's new connection outside its allowlist: towards the segment, the metadata address, or anything a per-user chain drops | the gateway |
   | `pool_inbound` | a new inbound connection to a pool VM | the pool VM |
   | `pool_output` | a new connection from a pool VM's root or daemons that its host table drops | the pool VM |

   Each dropping rule gains a named counter and, for the inbound classes, a dynamic set of source
   addresses with a timeout (as `relay_sources` already is). Nothing else in the tables changes
   and no rule accepts anything new. On the pool VM the guest, which is root and already drives
   `nft`, reads its own table. On the gateway nothing runs as root, so a oneshot unit under a
   timer, with `CAP_NET_ADMIN` alone and no network, reads the counters and writes a summary to a
   directory the authorizer reads; the authorizer never gains a capability.

   *Amended 2026-11-27, at implementation, accepted by the maintainer as built.*
   - *The reader, `mediatore gateway-probes` (`crates/mediatore-gateway/src/probes.rs`), is not
     root: it runs as its own user `mediatore-probes`, in no group but its own, with
     `CAP_NET_ADMIN` as its whole bounding and ambient set, no address family but netlink and
     every address denied (`image/gateway/systemd/mediatore-gateway-probes.service`), started
     every 30 s by `mediatore-gateway-probes.timer`.*
   - *The summary is remembered, not removed. The directory `/run/mediatore-gateway/probes` is
     the reader's, `2750`, group `mediatore-gateway`; `summary.json` is `0640` and read up to
     64 KiB. The authorizer can read it and can neither write nor delete it, so "reported once"
     is the authorizer's memory of the last file it read, and a summary already there when it
     starts is taken as read (lost, never duplicated). The authorizer looks every two seconds
     (`mediatore gateway --probes-dir`, default that directory; off the image the directory is
     absent and no probe is reported, silently).*
   - *`gateway_port`, `pool_inbound` and `pool_output` are new TCP connections only: each is one
     added dropping rule in front of its chain's last drop, whose text is unchanged and would
     have dropped the same packet, so DHCP and ICMP noise is counted in none of them (and
     `pool_inbound` is IPv4 alone). `gateway_output` is a named counter on each dropping rule
     the gateway's output chains already had, so it counts what those rules drop, as they drop
     it. The gateway has the set `probe_sources` (4096 elements, five minutes each) and eleven
     named counters, `gateway_port` and `gateway_output_{sandbox,imds,wireserver,broker,
     authorizer,relay,agent,loopback,ipv6,refused}`; the pool VM has the sets `inbound_sources`
     (4096) and `output_ports` (1024) and the counters `pool_inbound` and `pool_output`. A
     counter moves before its set is updated, so a full set still counts; what it could not
     name is a count with no port. No verdict of either table changes, pinned as text
     (`image/gateway/table-test.sh` and `image/host-table-test.sh` strip what was added and
     require the table from before this ADR byte for byte).*
   - *A `gateway_output` probe names a user only for the three chains that are one user's
     (`mediatore-gateway`, `envoy-relay`, `spire`); the per-rule detail stays in the reader's
     log, and the frozen `GatewayProbe` gains no `rule` member.*
   - *`pool_output` counts every uid, the sandbox uid included: the host table knows no uid,
     and a workload's own dropped connection is counted where the host table's chain runs
     first. So "root or daemons" above does not hold, and a `pool_output` during a claim proves
     nothing about anything outside the jail. On Azure the drop of the metadata address keeps
     its own rule (ADR-0068) and is not in `pool_output`.*
   - *Each read is `nft -j -n reset`, one command per process (two `reset set` in one process
     fail on nftables 1.1.3), so no state is kept and nothing is read twice; the two resets are
     separate dumps, so a remainder may be off by a packet. Measured on the build host: one
     `reset counters` 3.6 to 4.1 ms; `reset set` 3.9 ms with two elements, 122 ms and 430 kB of
     JSON with 4096; the whole reader about 14 ms; as a transient unit 135 to 262 ms. The pool
     VM's guest reads its table every 60 s.*

   *Amended 2026-11-27, after the fix round.*
   - *"Not root" above holds for the reader. The unit has one setup step that runs as root:
     `ExecStartPre=+/usr/bin/install -d -m 2750 -o mediatore-probes -g mediatore-gateway
     /run/mediatore-gateway/probes`, a fixed command that makes the one directory, with its
     setgid bit, which `RestrictSUIDSGID=yes` forbids the reader itself. A runtime directory
     owned by the unit would take the reader's own group, or put the reader in the authorizer's
     group, which "in no group but its own" refuses.*
   - *Amended 2026-11-27, after the first boot of a gateway: the step above is gone. systemd
     sets a unit's mount namespace up before its first `ExecStartPre`, even a `+` one, and the
     unit's `ReadWritePaths=` named the directory that step was to make, so the reader failed
     every run with `226/NAMESPACE`. The directory is made at boot by the image's `tmpfiles.d`
     entry (`image/gateway/tmpfiles.d/mediatore-gateway.conf`, `d /run/mediatore-gateway/probes
     2750 mediatore-probes mediatore-gateway`), and the reader's unit has no root step.*
   - *The authorizer opens the summary with `O_NONBLOCK | O_NOFOLLOW` and checks what it opened
     (a regular file of at most 64 KiB, by `fstat` on the descriptor), so a link or a FIFO put
     in its place is refused at once and never stalls the authorizer
     (`a_fifo_or_a_symlink_where_the_summary_is_opened_is_refused_without_waiting`,
     `crates/mediatore-gateway/src/probes.rs`).*

5. **A `segment` event never ends anything.** A dropped SYN proves nothing about its sender: on a
   shared segment the source address of `gateway_port` and `pool_inbound` can be forged, and a
   class that acted on it would let one VM end its neighbours' claims. The two output classes are
   not forgeable (they are keyed on a local uid) but their reporter runs on the machine they
   accuse. So every `segment` class is `report`, and configuring one as `trip` refuses the broker
   at start. Their worth is the pattern: one source reported by several pool VMs, or a gateway
   user that has never before dialled outside its chain.

6. **What a trip does depends on what the identity can be scoped to.**
   - **A claim** (`foreign_route` and `unknown_route` under a claim identity,
     `audience_outside_rendered`, `deny_outside_rendered`). The claim SVID is in hands other than
     the proxy's code. Under `trip`: `tripped` is written on the record and the claim is released
     exactly as ADR-0069 decision 9 does, the `Tripped` condition set with reason `protocol`.
     There is no containment on the VM to wait for, since the guest may be what was bypassed; the
     entry is retracted, the broker refuses the revoked claim at once, the gateways within
     `fresh_secs`, and banlieue destroys the VM when the `VirtualMachineClaim` goes.
   - **A node.** The claim bound to it, if any, is treated as above. The node itself is recorded
     and nothing more: mediatore cannot retire a pool member (open question 1).
   - **The authorizer, or no scope at all.** `report` only, always, and `trip` refuses the broker
     at start. All gateways share one identity, and a class that revoked it would be an outage
     any holder of that identity could cause on purpose.

   *Amended 2026-11-27, after the fix round: `deny_outside_rendered` leaves the first bullet. It
   is scoped to a claim, but on the authorizer's word, so it is held to `report` for the reason
   the third bullet gives (decision 3, amended). The start-up refusal now reads `tripwires.<class>:
   trip is refused, this class records only: a segment class proves nothing about its sender, a
   class of the authorizer's or on its word (a reported deny names a claim any holder of the
   shared authorizer identity could name) must not end one, and a class with no scope has no
   claim to end (ADR-0070 decisions 5 and 6); set it to report or leave it out`.*

7. **`tripwires` in the broker's configuration: each class `report` or `trip`, `report` by
   default.** There is no `off` and no `shadow`: recording arms nothing and changes no workload's
   environment (the reason ADR-0069 decision 5 defaults to `off` does not apply), and `report` is
   what `shadow` would be. An unknown class, an unknown value, or `trip` on a class that decision
   5 or 6 holds to `report` refuses the broker at start. A claim-scoped class moves to `trip`
   only after its soak (roadmap 18) shows it silent across a version-skewed rollout, which is the
   known source of an honest request no current build makes.

   *Amended 2026-11-27, at implementation, accepted by the maintainer as built: `unknown_route`
   is not held to `report`. Its scope is a claim, a node or the authorizer, so an operator may
   set it to `trip`, and then a version-skewed guest that calls a route an older broker lacks
   ends its own claim. That is the soak's reason to exist; nothing in the code stops it. What
   would change it: a scope of its own for the class in the wire types, or a start-up
   refusal. The start logs the mode of ADR-0069 and one `warn` line for each class at `trip`
   (`a class at trip: an event of this class ends the claim it is scoped to (policy.traps_denied,
   tripwires)`). The section needs no `policy` section: unlike `policy.traps`, it is a
   top-level key.*

8. **How an event is recorded.**
   - **The audit line**, one per event at `warn`: the class, the scope, the peer's SPIFFE ID,
     the route's template, the claim uid, and for `audience_outside_rendered` and
     `deny_outside_rendered` the audience or authority, admitted only within the grammar the
     route already enforces (an audience name, an RFC 1123 host and a port). Never a path, a
     query, a header, a body or a token, and for `unknown_route` nothing the peer chose at all.
     Repeats of one `(class, peer)` fold into a count per minute, in a table of at most 1024
     peers with an overflow counter, so a peer cannot grow the log.
   - **The status**, for a claim-scoped event: an entry in ADR-0069's `status.tripwires` with
     `kind: protocol`, `trap` the class, `source: peer`, and the target where the audit line has
     one. Same bound, same compare-and-set, same eviction.
   - **A `segment` event** reaches the broker in a `probes` list on ADR-0062's batch from a
     gateway, and on `POST /v1/me/trip` from a pool VM, which for `kind: segment` alone is
     accepted from a registered node with no claim. Each carries the class, the time, a count,
     the port, and for the inbound classes the source address, which the broker maps to a node
     where the `VirtualMachine` reports that address and records unattributed where it does not.
     Both channels keep their bounds; ADR-0062's stays lossy.
   - **OpenTelemetry**, under roadmap 15's invariants and its exporter as in ADR-0069 decision
     11: `mediatore.trips` gains the two kinds and a `class` label (an enum, so the series count
     stays fixed). A peer-chosen audience or authority is never exported (I-4).

   *Amended 2026-11-27, three changes.*
   - *The class is a field of its own, `class`, in the event, the record and the status, and
     `trap` is absent on a `protocol` or `segment` entry. `trap` keeps one grammar
     (`[a-z0-9.-]`, a catalogue or decoy name) and the class names have underscores
     (`TripClass`, `crates/mediatore-proto/src/trip.rs`).*
   - *The mapping of a source address to a node is deferred, and every probe is recorded
     unattributed. The API replicas hold no cache of machines (the watcher does), so the
     mapping would be a list at the Kubernetes API on a route that any holder of the
     authorizer's identity can drive. Revisit when the broker's API side has a machine cache.*
   - *The OpenTelemetry part is not built, as ADR-0069 decision 11's amendment says: no
     exporter exists.*

   *Amended 2026-11-27, at implementation (`crates/mediatore-api/src/classify.rs`), accepted
   by the maintainer as built.*
   - *The audit line is `a refusal no honest build earns (ADR-0070 decision 8)`, at `warn`,
     with `class`, `scope`, `action`, `peer`, `route` (`METHOD /template`, `(unknown)` or
     `(handshake)`), `claim_uid`, `audience`, `authority`, `count`, `first_at`, `last_at`. The
     fold keys on the peer and the claim the event names, and the class, so a deny reported
     under the shared authorizer identity is one line per accused claim. It keeps the first
     event's route, claim and audience or authority; 1024 keys, a peer cut at 255 bytes,
     flushed every 60 s; past the bound one line counts what was not kept.*
   - *At `report`, a status entry is written at the flush, at most one per class and peer a
     minute, not one per event, so a stolen SVID cannot use the Kubernetes API as a write
     amplifier. At `trip` the entry is written when the claim ends. Its effect is `reported` or
     `tripped`, its kind `protocol`, its source `peer`, its class set and its trap absent.*
   - *The audience has no place on a status entry (`TripTarget` has no variant for one), so an
     `audience_outside_rendered` entry has no target; the audit line carries it. For
     `deny_outside_rendered` the status target is the host, or the address and port of an IP;
     a name's port is in the audit line only.*
   - *A peer is recorded in the broker's own spelling: a node ID whose last segment is not an
     EK hash becomes `.../node/(not-an-ek-hash)`.*
   - *A probe is one `warn` line each, `gateway probe`, with the class, the gateway's name, the
     count, the port and the source address or the user, and nothing else; it is never folded
     and never put on a claim, whatever the configuration says. A `gateway_port` probe may have
     no port and no source (what a full set could not name), and a `gateway_output` probe no
     user. A `segment` event on `POST /v1/me/trip` from a node with no claim is one audit line
     at `warn` and nothing else.*

   *Amended 2026-11-27, after the fix round, by the maintainer's decision: a `segment` event is
   never put on a claim, whether or not its node has one. The pool VM's events were folded onto
   the node's live claim, where forged sources could evict that claim's own entries. Now every
   `segment` event on `POST /v1/me/trip` is one audit line at `warn` with an empty claim uid and
   subject, deduplicated by its id and never folded, as "recorded unattributed" above says
   (`trip::record`, `crates/mediatore-api/src/trip.rs`;
   `segment_events_from_a_node_with_a_live_claim_are_never_put_on_its_summary`). So the status
   bullet above is for `protocol` events alone, and a report of `segment` events alone logs no
   mode mismatch.*

   *Amended 2026-11-27, after the live run: a report of `segment` events alone is taken under
   `policy.traps: off` too. The pool VM's host table is loaded wherever the pool has gateways,
   whatever `policy.traps` says, and the guest's segment reader runs for the guest's life in any
   mode (`segment::spawn`, `crates/mediatore-guest/src/guest.rs`); but the broker answered the
   route `501` under `off` before it read the body, and the reader drops a refused report. So
   with tripwires on the VM off, the default, `pool_inbound` and `pool_output` were never
   recorded, while `shadow` recorded them live. Now, under `off`, the body is read first: a
   report whose every event is `segment` goes on exactly as under `shadow` (the peer must be a
   registered node, the per-claim or per-node limit of two reports a second holds, one audit
   line at `warn` per event, never put on a claim, nothing ended), and any other body, a report
   with an ADR-0069 event in it or no report at all, is the `501` it was, whoever sent it
   (`trip::trip`, `crates/mediatore-api/src/trip.rs`;
   `a_segment_only_report_under_off_is_accepted_as_an_audit_line_and_nothing_more`,
   `a_report_with_any_adr_0069_event_under_off_is_still_501_and_nothing_is_recorded`,
   `segment_reports_under_off_keep_the_per_node_rate_limit`, and in `e2e_dev.rs`
   `the_pools_segment_events_are_taken_under_off_and_any_trap_event_is_still_501`). Decision 1's
   amendment still holds for those: a foreign peer's report that is not `segment` alone is the
   `501` under `off`, unclassified; one that is `segment` alone is refused as under `shadow`.*

9. **Never log what the peer sent.** ADR-0069 decision 12 holds here: the canary test plants a
   token, a path and a header on every classified route and asserts none appears in a log line,
   a status or an exported signal.

   *Amended 2026-11-27, at implementation: built as
   `a_token_a_path_and_a_header_planted_on_every_classified_route_appear_in_no_line`
   (`classify.rs`) and `the_canary_scan_finds_nothing_the_peer_sent` (`e2e_dev.rs`); nothing is
   exported. It found two lines that carried a request's path, both changed: tower-http's
   request span, which named the URI on both listeners and now names the method and the
   matched route template only (`request{method route}`), and the
   `accept_plain_gateway_identity` warning, which now logs the path's claim segment only when
   it parses as a UUID.*

## Consequences

- **A stolen claim SVID used directly is seen on its first off-script request**, at the broker or
  at a gateway, without any trap list to avoid. An attacker who keeps to exactly what the proxy
  would have done trips nothing: that is bounded by the allowlist and the rules, as before.
- **A forged or undeclared identity is seen when it is first used at the broker**
  (`identity_shape`, `no_record`), which today is one `warn` among many.
- **A compromised gateway process that tries to leave its lane is counted on the gateway**
  (`gateway_output`), and one that asks the broker for what no certificate justified is seen at
  the broker. Neither is stopped by this ADR: R-27 stands, and a root compromise of the gateway
  can silence the first.
- **Version skew is the false positive.** A newer guest calling a route an older broker lacks is
  `unknown_route`; an image pull redirected to a host outside the rendered routes may be
  `deny_outside_rendered`. This is why every class starts at `report` and why the soak includes a
  rollout. *Amended 2026-11-27, after the fix round: `deny_outside_rendered` stays at `report`
  whatever the soak shows (decision 3, amended); its false positives are summary entries.*
- **A restore of the datastore (R-47) can produce `no_record` and `claim_never_issued`** for
  claims created after the backup. Both classes are `report` only; the runbook says so.
- **The gateway gains a root oneshot with one capability.** Small, with no network and no
  listener, but it is new privileged code on the gateway and the threat-model pass must weigh it
  against what `gateway_port` and `gateway_output` are worth. *Amended 2026-11-27: not root.
  The reader is its own user, `mediatore-probes`, with `CAP_NET_ADMIN` alone, no socket family
  but netlink, and one writable directory (decision 4, amended); root on the gateway can still
  silence it, as R-27 says. The user is not named in the gateway's output chain: having no
  socket family but netlink is what bounds it.* *Amended again 2026-11-27, after the fix round:
  one setup step of the unit, a fixed `install -d` of its directory, runs as root (decision 4,
  amended).*
- **ADR-0069 and ADR-0062 are amended** (the enums, a node without a claim on the trip route for
  `segment` alone, the `probes` list). ADR-0069 is still Proposed (*amended 2026-11-27: accepted
  that day, with this ADR*); ADR-0062 is accepted, and its
  R-68 (a report is the word of whoever holds the authorizer's identity) is why
  `deny_outside_rendered` starts at `report` (*amended 2026-11-27, after the fix round: and
  stays there, decision 3, amended*). This ADR's claim-scoped
  `trip` needs ADR-0069's record, status and condition; its audit lines and metrics need neither.
- **The threat-model pass is owed** and touches TB-6 (the classes as detection rows beside the
  refusals they classify), TB-13, TB-14 and TB-17 (the gateway's counters and the reader), TB-15
  (the pool VM's), §7, and §8: R-16, R-20 and R-27 gain a detection that narrows none of them,
  and the gaps below are recorded with a *Revisit when*. *Amended 2026-11-27: the threat-model
  pass is done, 2026-11-27.*
- *Added 2026-11-27, at implementation.* `gateway_output_refused` and `gateway_output_ipv6` can
  be moved by an honest claim whose allowed name resolves to a refused or an IPv6 address;
  `pool_output` by the workload's own dropped connections. A classified refusal costs a mutex
  and perhaps a spawn more than an unclassified one. The fold is per replica, and up to a
  minute of counts is lost at shutdown. Probes and `deny_outside_rendered` are the word of
  whoever holds the authorizer identity (R-68).

## Alternatives rejected

- **Decoy records and Secrets in the store.** The broker cannot see a read (Context), so a decoy
  Secret detects nothing unless the operator's audit pipeline watches for it, and that is a
  control this repository cannot cite as existing. A decoy the broker could watch for writes
  would have to be skipped by every reader of the store, in the component that is the system of
  record. The exposure a decoy would address is R-46, and its answer is the authenticated record
  ADR-0057 decision 8 deferred, not a trap. *Revisit when* that MAC is built, or a deployment
  wants a documented audit-policy fragment for named decoys.
- **A honey audience.** Any audience outside what the claim rendered already trips
  (`audience_outside_rendered`); a named decoy adds a list to avoid and nothing else.
- **A canary SPIFFE identity** (an entry on every node for a user no honest process runs as,
  which trips when presented). It changes the SPIFFE ID scheme (ADR-0004) and the entries a node
  gets, for an actor who already holds the node and claim SVIDs and has no reason to prefer a
  third. Kept as open question 3.
- **A replayed phantom at the gateway.** The phantom is swapped only on the VM's loopback and is
  worthless anywhere else (A-18); matching it at the gateway would put a per-claim secret on the
  shared component, which ADR-0069 rejected for bait and which holds here.
- **Decoy listeners on the segment** (a honeypot VM in the pool, or decoy ports on a gateway's
  sandbox address). A listener that completes a handshake cannot be framed by a forged source,
  which the drop counters can. But it is a new parser on the most hostile segment, on the
  components with the least surface, and roadmap 15 I-2 already refuses new listeners for less.
- **Tripping on TB-1** (a person asking for a claim that is not theirs). People mistype. The
  rate limit and the `404` are the control.
- **Acting on the authorizer's identity.** One identity for every gateway makes any action an
  outage. *Revisit when* each gateway's authorizer has its own identity (open question 2).

## What must be proven

- Unit, in `crates/mediatore-api`: each `protocol` class fires on its case and on nothing in the
  "deliberately not a class" list; the response is identical with the class at `report` and at
  `trip`; the fold bounds the audit lines; the configuration refuses every forbidden `trip`, and
  a retention at or below the SVID lifetime.
- e2e in `crates/mediatore/tests/e2e_dev.rs`: a claim identity on a node route, an audience
  outside `rendered`, and a reported deny outside `rendered` each end the claim under `trip` and
  only record under `report`; the same deny for a route that was rendered and since narrowed
  ends nothing; the authorizer's classes never end anything; the canary scan of decision 9.
- Live on the build host: the gateway's and the pool VM's counters move for each `segment` class
  and for no honest boot, pull and run; the gateway's reader holds `CAP_NET_ADMIN` alone
  (`image/gateway/check.sh`); `make gateway-render-check` shows no new accept.
- A soak at `report` on the homelab across one guest-and-broker upgrade, with the count of each
  class recorded here before any class moves to `trip`.

*Amended 2026-11-27, what was proven and what was not, at implementation.*
- *Unit, in `crates/mediatore-api/src/classify.rs`: each class on its case and on nothing of
  the "deliberately not a class" list, the response byte for byte the same at `report` and at
  `trip`, the fold's bounds, the honest request set
  (`every_route_of_the_sandbox_router_is_in_the_honest_set_of_exactly_one_role`); in
  `crates/mediatore/src/config.rs`, every forbidden `trip` refused, and in place of the
  retention refusal (decision 3, amended)
  `a_retention_at_or_below_the_claim_svid_lifetime_leaves_no_record_unjudged_and_says_so`.*
- *e2e, in `make check`: `e2e_dev.rs`, for a claim identity on a node route, an unserved path,
  an audience outside `rendered` and a reported deny outside `rendered`, each ending the claim
  under `trip` and only recording under `report`, and the canary scan; `e2e_gateway.rs`, a
  gateway's probes reaching the broker in its batch over the real listener, one line each.*
- *On the build host's kernel (6.12, nftables 1.1.3, systemd 257), in fresh network namespaces
  only: both tables load; each class's counter moves for its case and not for honest traffic;
  a full set fails closed; the reader under its unit's exact `[Service]` lines has
  `CAP_NET_ADMIN` as its effective, bounding and ambient set, opens netlink alone and cannot
  write outside its directory; inside the built gateway image the authorizer's user reads the
  summary and cannot write or delete it, and the Envoys cannot read it. `make
  gateway-render-check` and `make host-table-test` show no new accept. Both images were built
  and passed their checks (`image/gateway/check.sh`, `image/check.sh`).*
- *Not proven: a booted gateway or pool VM (the timer firing, the IPv6 output rule, no counter
  moving on an honest boot, pull and run); the classifier and the broker's own status write
  against a real API server (no kind tier runs with traps on); the request span outside the
  process; the soak.*
- *After the fix round: the e2e for a reported deny outside `rendered` is
  `a_reported_deny_outside_rendered_only_records_and_trip_is_refused` (it records with every
  class that may trip at `trip`, and `trip` on it is refused where the broker's state is
  filled; the start-up refusal is tested in `crates/mediatore/src/config.rs`), in place of the one that ended the claim under
  `trip`; the segment, decisions-route and summary-open tests are named in the amendments of
  decisions 3, 4 and 8; `make check` green on the merged tree.*

## Open questions

1. A way to retire a pool member that tripped as a node. It needs banlieue (a cordon on a member),
   since mediatore can release a claim but cannot stop the next one binding to the same VM.
2. An identity per gateway authorizer, which would give `claim_never_issued`,
   `credential_outside_inject` and `gateway_output` a scope something could act on.
3. Bait outside the jail on the pool VM (a decoy route in the proxy's file that the jail is never
   told about, a canary identity), for the escaped process that reads before it acts. It belongs
   to ADR-0069's draw if it is built.
4. Whether `pool_inbound` reports from several VMs naming one source should raise a condition on
   that source's `AgentSandbox`, and at what count. *Amended 2026-11-27: it needs the mapping of
   a source address to a node first, deferred (decision 8).*
5. *Added 2026-11-27.* A scope of its own for `unknown_route`, or a start-up refusal, so that it
   cannot be set to `trip` while version skew is its known honest source (decision 7, amended).
