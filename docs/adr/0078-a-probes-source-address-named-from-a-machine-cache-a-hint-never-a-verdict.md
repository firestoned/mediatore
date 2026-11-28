<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0078: A probe's source address named from a machine cache, a hint never a verdict

**Status:** Accepted and implemented 2026-11-28 (hermetic proof only; what a live run must still
show is under *What must be proven*): the cache and its watches
(`crates/mediatore-claims/src/machines.rs`), held on `Tripwires::machines`
(`crates/mediatore-api/src/tripwires.rs`, `Who`), the fields on both lines (`trip::segment_line`,
`crates/mediatore-api/src/trip.rs`; `gateway_decisions`, `crates/mediatore-api/src/lib.rs`),
`tripwires.segment_hosts` (`crates/mediatore/src/config.rs`), the watches started on every
replica (`machine_cache`, `crates/mediatore/src/main.rs`). No RBAC change. · **Date:** 2026-11-28

Amends [ADR-0070](0070-tripwires-beyond-the-sandbox-a-request-no-honest-build-makes.md)
decision 8 (the mapping of a source address to a node, deferred there "until the API side has a
machine cache") and closes the precondition of its open question 4. Keeps ADR-0070 decision 5 (a
`segment` event never ends anything) and decision 8's amendment of 2026-11-27 (a `segment` event
is never put on a claim) exactly as they are.

## Context

Two host tables report probes of the sandbox segment (ADR-0070 decision 4):

- a gateway's input drop counts a new TCP connection from the sandbox interface to a port it does
  not serve (`gateway_port`), keeping the source address in the set `probe_sources`; the
  authorizer sends it in the `probes` list of its decisions batch, and the broker writes one
  `gateway probe` line at `warn` (`gateway_decisions`, `crates/mediatore-api/src/lib.rs`);
- a pool VM's input drop counts an inbound connection (`pool_inbound`, the set `inbound_sources`);
  the guest reports it as a `segment` event on `POST /v1/me/trip`, and the broker writes one
  `trip reported` line at `warn` with an empty claim uid (`trip::record`,
  `crates/mediatore-api/src/trip.rs`).

Each line carries `source_address` and nothing that says whose it is. Live on 2026-11-28 the
gateway's line read `gateway_port ... source_address=<segment host>`: the operator had to know,
from outside mediatore, that the address was the host's own bridge. With many pool members the
address alone tells nobody which member, node or claim the connection came from.

ADR-0070 deferred the mapping because the API replicas held no machines: the claim watcher does,
on the Lease holder only (`crates/mediatore-claims/src/watch.rs`), and a list at the Kubernetes
API on the decisions route would let any holder of the authorizer's identity drive API reads.

What the cluster already says: banlieue's `VirtualMachine.status.addresses` carries the member's
`InternalIP`, and `status.heldAddresses` the static addresses its infrastructure was applied with
(banlieue ADR-0083); `status.tpmEndorsementCertificates` gives a TPM member's EK hash, which is its
node key; a `VirtualMachineClaim` mediatore created (`app.kubernetes.io/managed-by=mediatore`)
names its machine in `status.virtualMachineRef`, and its `metadata.uid` is the claim UID. The
broker's ServiceAccount already holds `get`, `list` and `watch` on both, cluster-wide
(`deploy/base/rbac.yaml`).

A source address on a shared segment can be forged (ADR-0070 decision 5). Whatever this ADR names
is the word of the packet's sender, read through a table that may lag.

## Decision

1. **A machine cache on every replica, outside the Lease.** `MachineCache`
   (`crates/mediatore-claims/src/machines.rs`) is filled by two watches, run on every replica the
   way the bundle reflector is: `VirtualMachine` labelled `banlieue.io/pool` in every namespace,
   and `VirtualMachineClaim` labelled `app.kubernetes.io/managed-by=mediatore` in every namespace
   (`machines::run`). It is held on the broker's state (`Tripwires::machines`,
   `crates/mediatore-api/src/tripwires.rs`), so the trip route and the decisions route read memory
   and never call the Kubernetes API or the store. No new verb: the watches use the `list` and
   `watch` the claim watcher already has. Without a cluster client (`dev_mode`) the cache is
   listed empty at start, so only declared hosts (decision 5) can be named.

2. **What it keeps of a member.** Its namespace and name; whether it is live (no
   `deletionTimestamp`, and an observed power state that is absent or `PoweredOn`); its addresses
   (each `status.addresses` entry of type `InternalIP`, and each `status.heldAddresses` address,
   parsed as an IP, an IPv4-mapped IPv6 address read as IPv4, anything that does not parse
   dropped); its node key, the EK hash of its endorsement certificates for a TPM member, and none
   for a member of a pool in `watcher.x509pop_pools`, whose key needs its Provider's CA, which the
   cache does not hold (its EK is never consulted, as ADR-0049 decision 9 says); and its bound
   claim, the UID of the one managed claim in phase `Bound`, not being deleted, whose
   `status.virtualMachineRef` names it in its own namespace (two such claims name none). Nothing
   else of either object is kept.

3. **The answer for an address is one of four, and only exactly one match names anything.** The
   candidates are the live members that report the address and the declared hosts that list it.
   One candidate: `member` (with its name, namespace, node and bound claim UID, where known) or
   `host` (with its declared name). None: `unattributed`. Several: `ambiguous`, naming none of
   them. A member that is not live is no candidate, so an address reused by a newer member while
   the old one is stopped or being deleted goes to the newer, live member; two live members
   reporting one address are `ambiguous`, never the newer by guess, since the cache cannot tell
   which status is stale. An event with no source address (`pool_output`, `gateway_output`, a
   `gateway_port` probe a full set could not name) is `unattributed`.

4. **Freshness is the watch's, and an incomplete list names nothing.** Until both watches have
   completed their first listing, every address is `unattributed`. A relist (the watch's
   reconnect) builds a new view and replaces the old one only when it is complete; in between, the
   last complete view answers. A watch error is logged and retried with the watcher's backoff,
   and the last view stays. There is no expiry: a member whose status lags its guest by the
   watch's latency is named from the lagging status. That is acceptable for a hint and is stated
   on the line (decision 7), never acted on.

5. **Declared hosts.** `tripwires.segment_hosts`, a map from a name (`[a-z0-9.-]`, 1 to 63
   bytes) to the addresses that name holds on the sandbox segment: the hosts' bridge addresses,
   the gateways', anything else on the segment that is not a pool member. Default empty. An
   address that does not parse, a name outside the grammar, an address under two names, more
   than 64 names or more than 16 addresses under one refuse the start. A probe from the host
   itself, the live test's case, then reads `attribution=host source_host=<name>`.

6. **Attribution never changes an answer, ends nothing and is on no claim.** The route answers
   are computed before and without it, byte for byte. It is not a class, has no action and is
   not configurable to `trip`; a `segment` event stays `report` and is never put on a claim
   (ADR-0070 decisions 5 and 8), so the matched claim's `status.tripwires`, its record and its
   summary are not touched, and the fold of `protocol` events is not touched. The matched claim
   UID is a field of the audit line, `source_claim_uid`, distinct from the line's `claim_uid`
   (which stays empty for a `segment` event).

7. **The fields.** Both the `trip reported` line and the `gateway probe` line gain
   `attribution` (`member`, `host`, `unattributed` or `ambiguous`; empty on a `trip reported` line
   whose event is not `segment`), `source_vm`, `source_namespace`, `source_node`,
   `source_claim_uid` and `source_host`, each empty when it does not apply. `source_node` is spelled
   as the line's own `node` field is, the SPIRE agent ID the broker records a node under
   (`spiffe://<td>/spire/agent/tpm/<EK hash>` for a TPM member). Nothing of a
   `VirtualMachine` but its name and namespace is logged, and nothing of a claim but its UID.

8. **STRIDE, at the boundary this crosses.**
   - *Spoofing*: a forged source address names whichever member or host holds it. Mitigated by
     decision 6 (nothing acts on it) and decision 3 (several holders name none). Accepted:
     attribution is a hint.
   - *Tampering*: whoever can write a `VirtualMachine`'s status (banlieue's controller, a cluster
     admin) can choose what an address names. Same mitigation; no new writer is trusted.
   - *Repudiation*: none new; the line still carries the raw source address beside the name.
   - *Information disclosure*: the lines name a member, a namespace, a node ID and a claim UID,
     all already in the broker's logs elsewhere (the claim watcher's lines). No token, no secret.
   - *Denial of service*: the cache is bounded by the pool members and managed claims in the
     cluster, which mediatore already watches; a lookup is a scan of memory per probe (at most 64
     a batch, 20 batches a second per gateway identity; 32 events a report, two reports a second
     per node). No Kubernetes API or store read on a request.
   - *Elevation of privilege*: none; no new verb, no new identity, no new route.

## Consequences

- An operator reads which member, node and claim a probe's source address belonged to, or that
  it was a declared host, or that nothing or several held it, on the line itself.
- Every replica runs two more watches (pool members and managed claims), the Lease holder's
  controllers keeping theirs: two more watch connections per replica at the API server.
- A member of an `x509pop` pool is named without a node ID (decision 2); its bound claim still
  names it.
- ADR-0070 open question 4 (a condition on the source's `AgentSandbox` after several reports) has
  its precondition, but is not decided here: nothing is written anywhere on an attribution.

## Alternatives rejected

- **A list at the Kubernetes API per probe**: ADR-0070's reason for deferring; any holder of the
  authorizer's identity would drive API reads.
- **The cache in the claim watcher**: it runs on the Lease holder alone, and the routes are served
  by every replica.
- **The newest live member wins a shared address**: a guess. Two live members reporting one
  address is exactly the case the cache cannot settle.
- **Reading the store for the node or the claim**: one store read per probe on a route a forged
  segment drives, for what the watched objects already say.
- **Putting an attributed event on the matched claim**: reverses ADR-0070's amendment of
  2026-11-27 for the same reason it was made: a forger would write onto someone else's claim.

## What must be proven

- Hermetic (`make check`): the cache from fake machines and claims (one match, none, several, a
  reused address going to the newer live member, a member not live, an incomplete listing, a
  relist, a claim bound and released, an x509pop member with no node ID), in
  `crates/mediatore-claims/src/machines.rs`; the route lines carry the fields and the claim's
  record and summary are untouched, and each answer is byte for byte the one without
  attribution, in `crates/mediatore-api/src/trip.rs` and `lib.rs`; the configuration's refusals in
  `crates/mediatore/src/config.rs`; and end to end over the real listeners, in
  `crates/mediatore/tests/e2e_dev.rs` (`POST /v1/me/trip`) and `e2e_gateway.rs` (the decisions
  batch).
- Live, not yet: a probe of a gateway and of a pool member from the host on the homelab, the
  host's bridge address declared, reading `attribution=host`; a probe from one member to another
  reading `attribution=member` with that member's claim.

*Amended 2026-11-28, at implementation: what was proven.* Hermetic, `make check` on the build
host: in `machines.rs` (`one_live_member_holding_the_address_is_named_with_its_node_and_bound_claim`,
`an_address_nobody_holds_or_no_address_is_unattributed`,
`several_live_members_holding_one_address_name_none`,
`a_reused_address_goes_to_the_newer_live_member`,
`nothing_is_named_before_both_listings_complete`, `a_relist_replaces_the_view_whole`,
`the_bound_claim_is_the_one_managed_claim_bound_to_the_member`,
`a_member_of_an_x509pop_pool_has_no_node_key_whatever_it_publishes`,
`held_addresses_count_and_other_address_types_do_not`, `an_ipv4_mapped_address_is_the_ipv4_one`,
`a_declared_host_is_named_and_a_member_on_its_address_makes_it_ambiguous`,
`declared_hosts_out_of_bounds_are_refused`,
`the_fake_api_servers_machines_fill_the_cache_as_a_listing`); in `trip.rs`
(`a_segment_events_source_is_named_from_the_cache_on_the_line_and_never_on_a_claim` under `off`,
`shadow` and `enforce`, with the named claim live in the store and nothing written;
`a_source_held_by_none_or_by_several_names_nothing_and_a_declared_host_reads_so`;
`attribution_changes_no_answer_byte_for_byte`); in `classify.rs`
(`a_probes_source_is_named_from_the_cache_and_the_answer_is_unchanged`); in `config.rs`
(`declared_segment_hosts_are_named_and_a_host_out_of_bounds_refuses_the_start`); end to end in
`e2e_dev.rs` (`a_segment_events_source_is_named_on_its_line_and_the_named_claim_is_untouched`) and
`e2e_gateway.rs` (`a_probes_source_is_named_from_the_machine_cache_and_its_claim_is_untouched`,
and the probe line's exact field set). Departures from the brief that framed this ADR: the cache is
fed by its own watches rather than by `ClaimsApi::list_machines` (a list per relist, not per
request; the fake's listing is shown to fill it the same way), and a member of an `x509pop` pool is
named without a node. Not proven: the watches against a real API server (no kind tier runs with
traps on) and a live probe.
