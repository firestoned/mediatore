<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 16: A sandbox under several policies, the first named wins

**Status: not started** (opened 2026-11-23). An `AgentSandbox` names an ordered list of
`SandboxPolicy` objects (`spec.policyRefs`) and is served under their composition: the union of
their audiences, direct egress and tools, the first policy's entry taken whole on a collision,
and the first policy's sandbox-wide parts (knobs, lease, budgets), refused when they are looser
than a later policy's. Decided by [ADR-0065](../../docs/adr/0065-a-sandbox-under-several-policies-the-first-named-wins.md).

Builds on roadmap 09 (bundles), roadmap 11 (ADR-0054's sources, ADR-0061's follow) and roadmap 08
(the CRD). The first user is Claude Code cloning a private repository: `claude-agent` and
`git-agent` in one sandbox, with neither policy copied into a third.

## Where it is today

- One `spec.policyRef`; `bundle_of` and `refuse_unresolved_policy` in
  `crates/mediatore-claims/src/sandbox.rs` resolve one name.
- The record holds one `policy_uid`, one `bundle_version` and one `rendered`.
- `claims_bundle`, `egress_of`, `served_direct_egress` and the mint in
  `crates/mediatore-api/src/lib.rs` read one bundle; `serve_under` in
  `crates/mediatore-claims/src/follow.rs` compares one `current` with one `rendered`.
- `shadow::compare_with` takes one bundle.
- The workaround is a third policy that copies the grants of two.

## Phases

### Phase 0: design (this document)

- [ ] ADR-0065 accepted, its open questions decided.
- [ ] CALM: the `AgentSandbox` → policy relationship becomes one-to-many;
      `make calm-validate` and `make calm-diagrams`.

### Phase 1: the composition, pure

- [ ] `Composite` and `compose` in `crates/mediatore-claims/src/policy.rs`, with the origin index
      of every part. Tests first: union without collisions; a colliding audience, egress entry
      and tool each taken whole from the first; sandbox-wide parts from the first; a list of one
      equal to the bundle itself.
- [ ] Decision 4's check (`P013`): one test per knob, lease and budget looser in the first; a
      tighter first accepted; equal accepted.
- [ ] The composite's digest over canonical bytes, stable under the same inputs, different under
      a reordering.

### Phase 2: the API surface

- [ ] `spec.policyRefs` in both served versions; the CEL rules (exactly one of `policyRef` and
      `policyRefs`, unique names, at most four); the CRD schema tests beside the `poolRef` rule's.
- [ ] `policy_refs` on `POST /v1/claims`, exclusive with `policy_ref`; `--policy` repeatable in
      the CLI, order kept.
- [ ] `policy.max_policies` and the per-namespace key on a `policy.sources` entry, refused at
      start when not a positive integer; `P014`.

### Phase 3: admission and the verdict

- [ ] Each name resolved under ADR-0054, the failing entry named in the refusal.
- [ ] The record's `policies` list (compare-and-set, ADR-0057), `policy_uid` and
      `bundle_version` kept as the first entry for older replicas.
- [ ] `compare_with` over the `Composite`; findings name the supplying policy.
- [ ] Eligibility: the requester eligible for every policy of the list.

### Phase 4: serving and follow

- [ ] `claims_bundle` returns the `Composite`; `egress_of`, `served_direct_egress`, the mint,
      `/v1/me` and the gateway's answer read it.
- [ ] `rendered` keeps the list and the composite's routes; `serve_under` over the composite;
      a new version of any one entry judged as a new composite.
- [ ] e2e in `crates/mediatore/tests/e2e_dev.rs`: two policies, an audience from each minted;
      a third audience in neither refused; a reordered list that loosens refused with `P013`;
      a list longer than `max_policies` refused with `P014`; a newer version of the second
      policy that drops its audience refusing the claim under `policy.follow: enforce`.

### Phase 5: docs, threat model, live proof

- [ ] `docs/guides/deploying.md` and the policy guide: `policyRefs`, the order, `max_policies`.
- [ ] Threat-model pass: the combination risk of ADR-0065's consequences, with `max_policies`
      as its control; stamp bumped.
- [ ] Live on the homelab: one sandbox under `claude-agent` then `git-agent` clones a private
      repository through the gateway's inject listener and has Claude Code summarise it.
