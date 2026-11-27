<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0070: Tripwires beyond the sandbox: a request no honest build makes

**Status:** Proposed (no implementation yet; CALM and the threat-model pass are owed before it is
accepted) · **Date:** 2026-11-26

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

7. **`tripwires` in the broker's configuration: each class `report` or `trip`, `report` by
   default.** There is no `off` and no `shadow`: recording arms nothing and changes no workload's
   environment (the reason ADR-0069 decision 5 defaults to `off` does not apply), and `report` is
   what `shadow` would be. An unknown class, an unknown value, or `trip` on a class that decision
   5 or 6 holds to `report` refuses the broker at start. A claim-scoped class moves to `trip`
   only after its soak (roadmap 18) shows it silent across a version-skewed rollout, which is the
   known source of an honest request no current build makes.

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

9. **Never log what the peer sent.** ADR-0069 decision 12 holds here: the canary test plants a
   token, a path and a header on every classified route and asserts none appears in a log line,
   a status or an exported signal.

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
  rollout.
- **A restore of the datastore (R-47) can produce `no_record` and `claim_never_issued`** for
  claims created after the backup. Both classes are `report` only; the runbook says so.
- **The gateway gains a root oneshot with one capability.** Small, with no network and no
  listener, but it is new privileged code on the gateway and the threat-model pass must weigh it
  against what `gateway_port` and `gateway_output` are worth.
- **ADR-0069 and ADR-0062 are amended** (the enums, a node without a claim on the trip route for
  `segment` alone, the `probes` list). ADR-0069 is still Proposed; ADR-0062 is accepted, and its
  R-68 (a report is the word of whoever holds the authorizer's identity) is why
  `deny_outside_rendered` starts at `report`. This ADR's claim-scoped
  `trip` needs ADR-0069's record, status and condition; its audit lines and metrics need neither.
- **The threat-model pass is owed** and touches TB-6 (the classes as detection rows beside the
  refusals they classify), TB-13, TB-14 and TB-17 (the gateway's counters and the reader), TB-15
  (the pool VM's), §7, and §8: R-16, R-20 and R-27 gain a detection that narrows none of them,
  and the gaps below are recorded with a *Revisit when*.

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

## Open questions

1. A way to retire a pool member that tripped as a node. It needs banlieue (a cordon on a member),
   since mediatore can release a claim but cannot stop the next one binding to the same VM.
2. An identity per gateway authorizer, which would give `claim_never_issued`,
   `credential_outside_inject` and `gateway_output` a scope something could act on.
3. Bait outside the jail on the pool VM (a decoy route in the proxy's file that the jail is never
   told about, a canary identity), for the escaped process that reads before it acts. It belongs
   to ADR-0069's draw if it is built.
4. Whether `pool_inbound` reports from several VMs naming one source should raise a condition on
   that source's `AgentSandbox`, and at what count.
