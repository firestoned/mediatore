<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 18: Tripwires beyond the sandbox: a request no honest build makes

**Status: not started** (opened 2026-11-26). Roadmap 17 traps the jailed workload on its VM. This
one covers what has already got past the jail: a process outside it holding the claim SVID, root
on a pool VM, a compromised gateway process, an identity SPIRE issued that the broker never
declared. Past the jail both ends of every boundary are mediatore's own code, so the set of honest
requests is closed, and the trap is everything outside it: no bait, no decoy listener, no list to
avoid. The broker and the host tables classify refusals they already make, record each one, and
for a class that can be scoped to one claim, end that claim. Decided in
[ADR-0070](../../docs/adr/0070-tripwires-beyond-the-sandbox-a-request-no-honest-build-makes.md)
(Proposed).

Builds on roadmap 17 (ADR-0069's `tripped` record, `status.tripwires`, the `Tripped` condition and
`POST /v1/me/trip`), roadmap 10 (the gateway's host table and ADR-0062's decision reports),
roadmap 11 (ADR-0061's `rendered`) and roadmap 06 (the pool VM's host table). The OpenTelemetry
part waits on roadmap 15, as roadmap 17's does. Phase 1 needs none of them.

## Why

A refusal at the broker is one log line, and a release racing a request, a version-skewed guest
and a stolen SVID produce the same line. The stronger the attacker, the less roadmap 17 sees: its
deciders are the guest and the proxy, which are what an escape or a root compromise has bypassed.

## Where it is today

- The sandbox listener refuses a wrong-shaped identity at the handshake and a wrong-kind peer in
  the handler (`sandbox_authorizer`, `claim_of_node_peer`, `require_gateway_authorizer` in
  `crates/mediatore-api/src/lib.rs`), each a log line.
- The broker keeps what each guest was handed (`status.record.rendered`) and uses it for
  ADR-0061's follow rule only.
- The gateway reports its denies (ADR-0062, Proposed, drafted); the broker logs them and keeps
  nothing.
- The host tables drop and count (`image/gateway/nftables.conf.in`, `image/host-table`); the
  counters are read by nobody.

## Phases

### Phase 0: design

- [ ] ADR-0070 accepted (drafted 2026-11-26, Proposed).
- [ ] CALM: the classes on the node, claim and authorizer relationships to the broker, the
      gateway's counter reader, a `flow-protocol-trip`; `make calm-validate` and
      `make calm-diagrams` pass.
- [ ] The honest request set written down per role and pinned by a test that fails when a role
      gains a call, so a new route cannot ship without its class being considered.

### Phase 1: the broker classifies and records (no dependency on roadmap 17)

- [ ] A `tripwires` configuration section: each class `report` or `trip`; the start-up refusals
      (an unknown class or value, a forbidden `trip`, a retention at or below the SVID lifetime).
- [ ] The eight `protocol` classes of ADR-0070 decision 3 as audit lines, folded per
      `(class, peer)` with the bounded table; the response unchanged, proven per class.
- [ ] The "deliberately not a class" cases each pinned by a test that records nothing.
- [ ] The canary test: a token, a path and a header on every classified route, found in no line.

### Phase 2: a claim-scoped class ends its claim (needs roadmap 17 phase 2)

- [ ] `kind: protocol` and `source: peer` in the record, `status.tripwires` and both CRD versions.
- [ ] Under `trip`: `tripped` by compare-and-set, the release, `Tripped` with reason `protocol`.
- [ ] `deny_outside_rendered` from ADR-0062's batch, against `rendered`; a deny for a rendered
      route narrowed since ends nothing.
- [ ] e2e in `crates/mediatore/tests/e2e_dev.rs` for each claim-scoped class, both values.

### Phase 3: the segment

- [ ] A spike on the build host: named counters and dynamic sets on the dropping rules, read by
      the guest on a pool VM and by a `CAP_NET_ADMIN` oneshot on a gateway; the cost per read.
- [ ] The gateway's `probes` on ADR-0062's batch; the pool VM's `kind: segment` on
      `POST /v1/me/trip`, accepted from a registered node with no claim.
- [ ] The source address mapped to a node where the `VirtualMachine` reports it.
- [ ] `image/gateway/check.sh` and `image/check.sh`: the reader's one capability, no new accept.
- [ ] Live: each class's counter moves for its case and for no honest boot, pull and run.

### Phase 4: docs, threat model, soak

- [ ] `docs/guides/tripwires.md` (roadmap 17's guide) gains the control-plane classes and a
      runbook: what each class means, what to look at, what a datastore restore produces.
- [ ] Threat-model pass (TB-6, TB-13 to TB-15, TB-17, §7, §8); stamp bumped.
- [ ] A soak at `report` on the homelab across one guest-and-broker upgrade; the counts recorded
      in ADR-0070 before any class moves to `trip`.
- [ ] Roadmap 15: `mediatore.trips` with the two kinds and the `class` label, once its exporter
      exists.
