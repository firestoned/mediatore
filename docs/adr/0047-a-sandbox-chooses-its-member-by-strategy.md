<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0047: A sandbox chooses its member by strategy

**Status:** Accepted and implemented 2026-11-18, released in v0.4.0 (proposed the same day; `Selection`, `SelectionStrategy`, `--strategy`, `spec.selection`, banlieue-api v0.5.10) · **Date:** 2026-11-18

Roadmap 08 (the `AgentSandbox` CRD). Amends
[ADR-0008](0008-agentsandbox-crd-owned-by-mediatore.md) decision 7 (the spec's fields) and
the `POST /v1/claims` body, and extends [ADR-0044](0044-a-sandbox-selects-its-pool-by-label.md),
which said that the selection itself and the ranking across pools were banlieue's. They still
are: banlieue ADR-0135 (a claim chooses its member by strategy, 2026-11-17) adds the knob, and
this ADR carries the requester's choice through unchanged, as ADR-0044 carries the pool
selector.

## Context

With ADR-0044 a sandbox claims across every pool its selector matches, and banlieue picks the
member: Ready and unclaimed, current image revision first, then the one Ready longest. That
order has no notion of where a member runs. In a namespace whose pools sit on several hosts
(one per host, as in the homelab), claims drain whichever host holds the longest-Ready
members, and a person who holds several sandboxes may find them all on one host, so one host's
failure takes all of their work.

banlieue ADR-0135 (released in banlieue v0.5.10) gives the claim a choice:

- `spec.selection` is an optional struct on `VirtualMachineClaimSpec` with one field,
  `strategy`, an enum: `LongestReady` (the default, and the order every claim used before),
  `MostAvailable` (take from the failure domain with the most Ready members, so warm capacity
  drains evenly), `Spread` (take from the failure domain where this claim's subject holds the
  fewest members, then as `MostAvailable`, so one subject's sandboxes do not share a host);
- a strategy only reorders, never filters: Ready and unclaimed, then current image revision,
  then a healthy host, then the strategy's key, then Ready longest, then name. No strategy
  leaves a claim `Pending` while a Ready member exists;
- a failure domain is the pair `(providerName, failureDomain)` of the member's
  `status.scheduled`;
- the bound claim's `Bound` condition says which strategy chose the member and from which
  domain; there is no new status field;
- `spec.selection` is immutable, by banlieue's claim admission policy.

In Rust, `VirtualMachineClaimSpec` gains `selection: Option<ClaimSelection>`, so mediatore
must say what a sandbox carries before it compiles against banlieue-api v0.5.10. `Pack`, the
opposite of `Spread`, is named in banlieue's ADR as a later candidate and does not exist.

## Decision

1. **The `AgentSandbox` spec mirrors the claim: `spec.selection`, optional, banlieue's own
   type.** `AgentSandboxSpec.selection` is `Option<banlieue_api::banlieue::ClaimSelection>`
   (`strategy: LongestReady | MostAvailable | Spread`), copied to the claim verbatim by
   `claim_for`. The CRD's schema therefore lists exactly the strategies banlieue's does, and a
   sandbox naming any other value is refused by the API server at admission, before the
   reconciler runs. The existing admission policy
   (`deploy/base/admission/agentsandbox-subject.yaml`) freezes the whole spec, so the field is
   immutable without a change to it, as banlieue's is on the claim.

2. **An absent `selection` stays absent.** mediatore writes no default: a sandbox or a request
   without one produces a claim without one, which banlieue reads as `LongestReady`, the
   order every claim had before. This differs from ADR-0044 decision 2 on purpose: an omitted
   pool was refused because "neither" and "any" are different requests, but an omitted
   strategy has one meaning, written down in banlieue ADR-0135 decision 1, and is what every
   existing sandbox already means. No sandbox or request written so far changes behaviour.

3. **`ClaimRequest` carries `selection: Option<Selection>`, `Selection.strategy` a
   `SelectionStrategy`.** Both are `mediatore-proto`'s own copies of banlieue's shape, since
   the proto crate is shared with the client and the guest and depends on nothing of kube's;
   the broker converts them when it creates the sandbox (`claim_selection_of`,
   `crates/mediatore-claims/src/sandbox.rs`). The values are spelled as banlieue spells them
   (`LongestReady`, `MostAvailable`, `Spread`), as ADR-0044 spells the selector's operators,
   so a body, a sandbox and a claim read the same. A body naming a strategy the broker does
   not know fails to parse and is refused with `422` before anything is created; the broker
   never maps an unknown value to a default.

4. **The CLI takes `--strategy longest-ready | most-available | spread`.** Without the flag
   nothing is sent (decision 2). The flag is one of the request's fields, like `--restart`,
   not a default the CLI invents.

5. **The outcome is on the claim, not duplicated.** Which strategy chose the member and from
   which domain is the message of the claim's `Bound` condition (banlieue ADR-0135 decision 6),
   readable with `kubectl` by whoever can read the claim. `AgentSandboxStatus` and
   `ClaimResponse` gain nothing: banlieue added no status field, and parsing a condition's
   message to mirror it would be a contract on prose. If banlieue later records the choice in
   a field, mirroring it is an amendment to this ADR, as `status.poolRef` was to ADR-0008.
   The reconciler's and the API's "claim created" log lines name the strategy, or `default`.

6. **The namespace boundary and the pool boundary do not move.** A strategy orders the
   members a pool selector or a `poolRef` already reaches, inside the sandbox's namespace
   (ADR-0044 decision 6, as amended by ADR-0046). It cannot reach a member, a pool or a host
   the request could not already be bound to; it only says which of them first. `Spread`
   reads the subject's own members (the annotations a bind writes), never another subject's,
   so no strategy lets one requester learn where another's sandboxes run.

7. **`dev_mode` is unchanged.** The dev binder has no pools and no hosts: it binds the first
   registered free node whatever the request says, as before. It accepts the field and logs
   it.

## Consequences

- **Wire compatible.** Every request and every `AgentSandbox` written so far has no
  `selection`, is valid under the new schema and produces the same claim as before. The CRD in
  `deploy/base/crds/` is re-rendered (`make crds`) and must be applied before a broker that
  writes `selection`; an old CRD would prune the field and the claim would silently be
  `LongestReady`, so the CRD goes first in a release.
- **Not source compatible.** `VirtualMachineClaimSpec` gains a field, so `claim_for` and the
  e2e suites move with it; `AgentSandboxSpec` and `ClaimRequest` literals in the tests gain
  `selection: None`.
- **The banlieue pin moves.** `banlieue-api` goes from tag v0.5.9 to v0.5.10, the release that
  carries ADR-0135; the kube and k8s-openapi pins are unchanged (kube `~5.0`, k8s-openapi
  0.29). v0.5.10 also changes `provider_ref` on banlieue's machine types to a
  `ProviderReference`, which mediatore does not read.
- **The core cluster's banlieue admission policy moves with it.** banlieue's claim-subject
  `ValidatingAdmissionPolicy` of v0.5.10 is what makes `spec.selection` immutable on the claim
  and lets a claim carrying it be updated at all; an older policy denies the update. Upgrading
  the core cluster to banlieue v0.5.10 re-applies that policy with the CRDs, as ADR-0044
  already requires for v0.5.9.
- **A requester chooses placement among what they could already have.** `Spread` and
  `MostAvailable` let a requester influence which host their member comes from, inside the
  pools they may claim. That is a preference over a set they already had full access to; the
  threat model records it and finds no new reach (TB-1, TB-2).
- **Not done here.** `Pack` and a hard spread are banlieue's to decide first. The outcome is
  not mirrored into the sandbox's status (decision 5). The kind sandbox tier gains the
  strategy sandbox and the refused unknown value (`make kind-e2e-sandbox`, PASS on the build
  host, 2026-11-18); a live run on the core cluster waits for the upgrade to banlieue v0.5.10
  and a release of mediatore carrying this change.
