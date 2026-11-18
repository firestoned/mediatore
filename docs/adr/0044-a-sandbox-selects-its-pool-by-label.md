<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0044: A sandbox selects its pool by label, or names it

**Status:** Accepted 2026-11-16; implemented, released in v0.2.10 (#127, whose title names ADR-0043 by mistake; `PoolSelector`, `--pool-selector`, `invalid_pool`, banlieue-api v0.5.9) · **Date:** 2026-11-16 · **Amended:** 2026-11-17 (decision 6, the namespace boundary, [ADR-0046](0046-who-may-claim-a-list-of-groups-and-a-namespace-to-groups-mapping.md))

Roadmap 08 (the `AgentSandbox` CRD). Amends
[ADR-0008](0008-agentsandbox-crd-owned-by-mediatore.md) decision 7 (the spec's fields) and
the `POST /v1/claims` body. Mirrors banlieue's ADR-0132 (a `VirtualMachineClaim` selects its
pool by label), which this ADR consumes and adds nothing to: the selection itself, the ranking
across pools and the record of the pool bound from are banlieue's; mediatore carries the
caller's choice through unchanged and shows the answer.

## Context

A sandbox request names exactly one pool. `ClaimRequest.pool_ref` is a required string,
`AgentSandboxSpec.poolRef` a required `LocalObjectReference`, and the reconciler copies the
name onto the one `VirtualMachineClaim` it owns. The requester therefore chooses a pool
before claiming, with no view of capacity: in a namespace with several interchangeable pools
(one per host, one per backend, all serving the same image) the claim sits `Pending` on an
empty pool while its neighbour holds Ready members. Erick's requirement, 2026-11-16: a claim
is made across all the namespace's pools unless the requester narrows it.

banlieue ADR-0132 (2026-11-16) gives the claim what this needs:

- `spec.poolRef` becomes optional beside a new `spec.poolSelector`, a `LabelSelector`
  matched against `VirtualMachinePool` labels in the claim's namespace; exactly one of the
  two, enforced by CEL on the claim (`has(self.poolRef) != has(self.poolSelector)`);
- `poolSelector: {}` is the explicit spelling of "any pool in this namespace"; a claim with
  neither field is refused, never read as "any" (the "never all by default" rule of banlieue
  ADR-0130 and ADR-0131);
- the controller ranks the members of every matched pool as one set and records the pool
  the bound member came from in `status.poolRef`;
- `Pending` gains the reason `NoPoolMatches` beside `PoolNotFound` and `NoMemberAvailable`.

In Rust, `VirtualMachineClaimSpec.pool_ref` is now `Option<LocalObjectReference>` and
`pool_selector` is `Option<LabelSelector>`, so mediatore stops compiling against the new
`banlieue-api` until it decides what a sandbox carries.

## Decision

1. **The `AgentSandbox` spec mirrors the claim: `poolRef` optional, `poolSelector` beside
   it, exactly one.** `spec.poolSelector` is banlieue's `LabelSelector` (`matchLabels`,
   `matchExpressions`), copied to the claim verbatim with `poolRef`. The same CEL rule
   guards the sandbox, with the same message, so a sandbox the claim would refuse is refused
   at the sandbox's own admission, before the reconciler runs and before a claim exists.
   The existing admission policy (`deploy/base/admission/agentsandbox-subject.yaml`) already
   freezes the whole spec, so both fields are immutable without a change to it.

2. **"Any pool" is written down on the resource and on the wire.** `poolSelector: {}` means
   every pool in the sandbox's namespace, exactly as on the claim. A sandbox or a request
   with neither field is refused, by CEL on the resource and with `400 invalid_pool` on
   `POST /v1/claims`. mediatore does not widen an omitted field to "any" on the user's
   behalf: the broker is a second writer of the claim's spec and follows the claim's rule.

3. **The CLI is where the default lives.** `mediatore sandbox create` takes `--pool <name>`
   or `--pool-selector <key>=<value>` (repeatable, `matchLabels` only; `matchExpressions`
   is for the API body and the declarative resource). With neither, the CLI sends
   `pool_selector: {}` and says so on stderr, one line. This is the "across all pools unless
   a selector is given" behaviour, placed in the one component whose job is to turn a
   person's intent into an explicit request. Both flags together is a usage error.

4. **`ClaimRequest` carries `pool_ref: Option<String>` and `pool_selector:
   Option<PoolSelector>`.** `PoolSelector` is `mediatore-proto`'s own copy of the
   `LabelSelector` shape (`match_labels`, `match_expressions` with `In`, `NotIn`, `Exists`,
   `DoesNotExist`), because the proto crate is shared with the client and the guest and
   depends on nothing of kube's. The broker converts it to banlieue's type when it creates
   the sandbox. `pool_ref` keeps its name and type for a named pool, so every existing
   request body stays valid.

5. **The pool bound from is shown, not the pool asked for.** `AgentSandboxStatus.poolRef`
   mirrors the claim's `status.poolRef`, and the `Pool` print column reads
   `.status.poolRef.name` (empty while `Pending`, as on the claim). `ClaimResponse` gains
   `pool`, the same name, once bound. The reconciler's "claim created" log line names the
   pool or prints the selector.

6. **The namespace boundary does not move.** A selector is matched in the sandbox's
   namespace, which is the claim's (ADR-0008: `sandboxes.namespace` in `mediatore.yaml`),
   because banlieue matches it there. Who may claim from a pool is still the namespace RBAC
   question of ADR-0008 decision 5 and banlieue ADR-0047 decision 10; a selector can reach
   no pool a `poolRef` in the same namespace could not already name.

   *Amended by [ADR-0046](0046-who-may-claim-a-list-of-groups-and-a-namespace-to-groups-mapping.md) (2026-11-17):* the claim's namespace is no longer always
   `sandboxes.namespace`; with `sandboxes.namespaces` set it is the one the caller names and is
   in the groups of. For a request through the broker, "who may claim" is that per-namespace group
   check; the Kubernetes RBAC answer stands for the declarative path. A selector and a `poolRef`
   are still matched only in the sandbox's own namespace.

7. **`dev_mode` is unchanged.** The dev binder has no pools: it binds the first registered
   free node whatever the request says, as before. It accepts both forms and logs them.

## Consequences

- **Wire compatible.** Every request and every `AgentSandbox` written so far has `poolRef`
  and no `poolSelector`, valid under the new schema and reconciled exactly as before. The
  CRD in `deploy/base/crds/` is re-rendered (`make crds`) and must be applied before the
  broker that writes `poolSelector`; an old CRD prunes the unknown field and the claim then
  fails CEL with neither, which is the loud failure wanted.
- **Not source compatible.** `pool_ref` on the request and the spec changes type; the e2e
  suites and the testkit's `MemorySandboxes` validation (which restates the CRD's refusals)
  move with it.
- **The banlieue pin moves.** `banlieue-api` goes from tag v0.5.0 to v0.5.9, the release that
  carries ADR-0132; the kube and k8s-openapi pins are unchanged, since that release keeps
  kube 5 and k8s-openapi 0.29. The change was developed against a local `[patch]` of the
  banlieue tree before the tag existed.
- **A pool's labels now steer sandboxes.** Whoever may edit a pool's labels can move it into
  or out of a selector. That principal can already edit the pool's template and image, so
  this adds no power (banlieue ADR-0132); the threat model records it.
- **Not done here.** The CLI does not offer `matchExpressions`; selection across namespaces,
  weighting and locality are banlieue's to decide first, and none is decided. *2026-11-18:*
  banlieue ADR-0135 decided the ranking among the matched pools' members, and
  [ADR-0047](0047-a-sandbox-chooses-its-member-by-strategy.md) carries that choice,
  `spec.selection.strategy`, the same way this ADR carries the selector.
