<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 18: Tripwires beyond the sandbox: a request no honest build makes

**Status: in progress: built 2026-11-27, every class at `report` by default; the live proof on booted VMs and the soak remain** (opened 2026-11-26). Roadmap 17 traps the jailed workload on its VM. This
one covers what has already got past the jail: a process outside it holding the claim SVID, root
on a pool VM, a compromised gateway process, an identity SPIRE issued that the broker never
declared. Past the jail both ends of every boundary are mediatore's own code, so the set of honest
requests is closed, and the trap is everything outside it: no bait, no decoy listener, no list to
avoid. The broker and the host tables classify refusals they already make, record each one, and
for a class that can be scoped to one claim, end that claim. Decided in
[ADR-0070](../../docs/adr/0070-tripwires-beyond-the-sandbox-a-request-no-honest-build-makes.md)
(accepted 2026-11-27).

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
- The gateway reports its denies (ADR-0062); the broker logs them and keeps nothing.
- The host tables drop and count (`image/gateway/nftables.conf.in`, `image/host-table`); the
  counters are read by nobody.

## Phases

### Phase 0: design

- [x] ADR-0070 accepted (drafted 2026-11-26, accepted 2026-11-27 with the amendments of that day).
- [x] CALM: the classes on the node, claim and authorizer relationships to the broker, the
      gateway's counter reader, a `flow-protocol-trip`; `make calm-validate` and
      `make calm-diagrams` pass. (2026-11-27; the elements marked implemented the same day.)
- [x] The honest request set written down per role and pinned by a test that fails when a role
      gains a call, so a new route cannot ship without its class being considered.
      (2026-11-27: `sandbox_routes` in `crates/mediatore-api/src/lib.rs`,
      `every_route_of_the_sandbox_router_is_in_the_honest_set_of_exactly_one_role` in `classify.rs`.)

### Phase 1: the broker classifies and records (no dependency on roadmap 17)

- [x] A `tripwires` configuration section: each class `report` or `trip`; the start-up refusals
      (an unknown class or value, a forbidden `trip`, a retention at or below the SVID lifetime).
      (2026-11-27: `an_unknown_class_or_value_in_tripwires_refuses_the_start`,
      `trip_on_a_segment_class_or_an_authorizer_class_or_an_unscoped_class_refuses_the_start` in
      `crates/mediatore/src/config.rs`. *Amended 2026-11-27 by the maintainer: a low retention is not refused; `no_record`
      is then not judged and the start says so,
      `a_retention_at_or_below_the_claim_svid_lifetime_leaves_no_record_unjudged_and_says_so`.*)
- [x] The eight `protocol` classes of ADR-0070 decision 3 as audit lines, folded per
      `(class, peer)` with the bounded table; the response unchanged, proven per class.
      (2026-11-27: one test per class in `classify.rs`, from `a_claim_identity_on_a_node_route_is_foreign_route` to
      `a_reported_deny_for_an_authority_never_rendered_is_deny_outside_rendered`;
      `the_response_is_byte_identical_with_the_class_at_report_and_at_trip`,
      `repeats_of_one_class_and_peer_are_one_line_a_minute_with_a_count`, `the_table_holds_1024_peers_and_counts_the_rest`.
      The fold also keys on the claim an event names.)
- [x] The "deliberately not a class" cases each pinned by a test that records nothing.
      (2026-11-27: `a_request_for_a_claim_released_a_moment_ago_records_nothing`,
      `an_audience_rendered_and_since_narrowed_records_nothing`, `a_deny_for_a_route_rendered_and_since_narrowed_records_nothing`,
      `no_claim_for_a_node_not_bound_yet_records_nothing`, `a_malformed_body_records_nothing` in `classify.rs`.)
- [x] The canary test: a token, a path and a header on every classified route, found in no line.
      (2026-11-27: `a_token_a_path_and_a_header_planted_on_every_classified_route_appear_in_no_line` in `classify.rs`,
      `the_canary_scan_finds_nothing_the_peer_sent` in `e2e_dev.rs`; it found the request span naming the URI, fixed.)

### Phase 2: a claim-scoped class ends its claim (needs roadmap 17 phase 2)

- [x] `kind: protocol` and `source: peer` in the record, `status.tripwires` and both CRD versions.
      (2026-11-27: `tripped_round_trips_through_status_record` in `kubestore.rs`,
      `both_served_versions_carry_tripwires_with_its_bounds` in `sandbox.rs`; the schema in kind.)
- [x] Under `trip`: `tripped` by compare-and-set, the release, `Tripped` with reason `protocol`.
      (2026-11-27: `a_claim_scoped_class_at_trip_ends_the_claim_after_the_answer_and_once` in `classify.rs`, through
      ADR-0069's `end_claim`; `a_tripped_record_sets_the_tripped_condition_with_the_kind_as_its_reason` in `sandbox.rs`.)
- [x] `deny_outside_rendered` from ADR-0062's batch, against `rendered`; a deny for a rendered
      route narrowed since ends nothing.
      (2026-11-27: `a_reported_deny_for_an_authority_never_rendered_is_deny_outside_rendered`,
      `a_deny_for_a_route_rendered_and_since_narrowed_records_nothing`, `one_batch_is_judged_for_sixteen_claims_and_no_more`.
      After the fix round the class records only, by the maintainer's decision: the claim it names is the authorizer's
      word, so `trip` on it refuses the start (ADR-0070 decision 3, amended),
      `a_reported_deny_outside_rendered_only_records_whatever_the_configuration_says`. The decisions route takes at most
      20 batches a second per gateway identity and judges at most 4 at once,
      `the_decisions_route_takes_so_many_batches_a_second_per_gateway_identity`,
      `a_batch_that_finds_every_judging_permit_held_is_answered_and_not_judged`.)
- [x] e2e in `crates/mediatore/tests/e2e_dev.rs` for each claim-scoped class, both values.
      (2026-11-27: `a_claim_identity_on_a_node_route_ends_the_claim_under_trip_and_only_records_under_report`,
      `a_path_the_broker_does_not_serve_ends_the_claim_under_trip_and_only_records_under_report`,
      `an_audience_outside_rendered_ends_the_claim_under_trip_and_only_records_under_report`, and for
      `deny_outside_rendered`, which records only since the fix round,
      `a_reported_deny_outside_rendered_only_records_and_trip_is_refused`. A node identity's `foreign_route` is a unit
      test.)

### Phase 3: the segment

- [ ] A spike on the build host: named counters and dynamic sets on the dropping rules, read by
      the guest on a pool VM and by a `CAP_NET_ADMIN` oneshot on a gateway; the cost per read.
      *2026-11-27: done by hand on the build host (kernel 6.12, nftables 1.1.3) in fresh network namespaces: both
      tables load, the parsers' fixtures are its real captures, and a read costs 3.6 to 4.1 ms for the counters, 3.9 ms
      for a set of two and 122 ms for a full set of 4096 (recorded in ADR-0070 decision 4). Left open as a by-hand step
      outside the PR.*
- [x] The gateway's `probes` on ADR-0062's batch; the pool VM's `kind: segment` on
      `POST /v1/me/trip`, accepted from a registered node with no claim.
      (2026-11-27: `a_gateways_probes_reach_the_broker_in_its_batch` in `e2e_gateway.rs`,
      `the_reader_resets_the_set_then_the_counters_and_the_summary_reaches_the_inbox` in `probes.rs`,
      `a_segment_event_from_a_node_with_no_claim_is_accepted_and_any_other_kind_is_dropped` in
      `crates/mediatore-api/src/trip.rs`, `a_counter_that_moved_becomes_one_event_with_the_delta` in `segment.rs`. That
      real counters feed them on a booted VM is not proven. After the fix round a `segment` event is never put on a
      claim, a node's live claim included, `segment_events_from_a_node_with_a_live_claim_are_never_put_on_its_summary`;
      and the authorizer opens the summary without following a link or waiting on a FIFO,
      `a_fifo_or_a_symlink_where_the_summary_is_opened_is_refused_without_waiting`.)
- [ ] The source address mapped to a node where the `VirtualMachine` reports it.
      *2026-11-27: deferred (ADR-0070 decision 8, amended): the API replicas hold no machine cache, and a list per probe
      would be a Kubernetes API call any holder of the authorizer identity could drive. Every probe is unattributed.
      Revisit when the API side has a machine cache.*
- [x] `image/gateway/check.sh` and `image/check.sh`: the reader's one capability, no new accept.
      (2026-11-27: both images built with podman on the build host and both checks passed; `make gateway-render-check`
      (`image/gateway/table-test.sh`) and `make host-table-test` require every verdict unchanged on every platform.
      The reader is its own user, not root; one setup step of its unit, a fixed `install -d` of its directory, runs
      as root.)
- [ ] Live: each class's counter moves for its case and for no honest boot, pull and run.
      *2026-11-27, partly: in fresh network namespaces each counter moved for its case and not for honest traffic.
      Not run: a booted gateway or pool VM (the timer firing, the IPv6 output rule, an honest boot, pull and run).*

### Phase 4: docs, threat model, soak

- [x] `docs/guides/tripwires.md` (roadmap 17's guide) gains the control-plane classes and a
      runbook: what each class means, what to look at, what a datastore restore produces. (2026-11-27.)
- [x] Threat-model pass (TB-6, TB-13 to TB-15, TB-17, §7, §8); stamp bumped. (2026-11-27.)
- [ ] A soak at `report` on the homelab across one guest-and-broker upgrade; the counts recorded
      in ADR-0070 before any class moves to `trip`. *2026-11-27: owed.*
- [ ] Roadmap 15: `mediatore.trips` with the two kinds and the `class` label, once its exporter
      exists. *2026-11-27: not buildable; waits on roadmap 15.*
