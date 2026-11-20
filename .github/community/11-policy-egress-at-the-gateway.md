<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 11: A policy's direct egress at the gateway

**Status: in progress** (ADR-0030 accepted and implemented 2026-11-05; the live proof and the rollout are open; ADR-0054 accepted and implemented 2026-11-19, its live migration and its check by subject open). The first enforcing step of
[ADR-0026](../../docs/adr/0026-notaio-bundles-verified-in-shadow.md): the verified bundle's
direct `egress[]` joins the audience endpoints in the claim's gateway allowlist, behind a
`policy.egress: shadow | enforce` switch that defaults to shadow.

Depends on roadmap 09 (the verified bundle cache) and roadmap 10 (the gateway and its route).

- [x] ADR-0030 accepted
- [x] CALM updated; `make calm-validate` and `make calm-diagrams` pass
- [x] `BundleCache`: lookup by policy `uid` (an unlisted cache is empty, so nothing is served from it)
- [x] `policy.egress` config (`shadow` default); a malformed value refuses the start
- [x] `egress_of`: the union, entries filtered per decision 3; tests: enforce adds, shadow
      does not, stale/missing/tampered bundle adds nothing, `rules` and IP literals refused,
      the gateway's 404 behaviour unchanged
- [x] `P006` follows the switch; `P007` for entries not served
- [x] e2e in `e2e_gateway.rs`: negative cases included
- [x] README and rollout documented; threat-model full pass, stamp bumped (2026-11-05)
- [x] Live proof: `make kind-e2e-gateway-policy` (2026-11-08), the gateway tier under a notaio
      bundle in the cluster, through the real Envoy: the bundle's direct entry for the
      destination's second port is refused at the gateway under `shadow` (the broker logging
      `would_add`, the sandbox reporting P006) and opens under `enforce` (a tunnel, the
      destination answering through it, the authorizer's allow from the broker), an entry
      with rules is never served (P007), the audience endpoints stand in both modes
- [ ] Rollout: shadow, then enforce in dev, then each tier. Step one done 2026-11-08: the
      homelab broker runs `policy.egress: enforce` after a week of shadow with no
      `would_add` line (neither of its bundles names direct egress, so the gateway's answer
      is unchanged and the first entry a policy adds will be served); the broker restarted
      on the value, both bundles admitted, the API healthy. The kind overlay stays on the
      default. Open: the other tiers, as they exist. The broker names the mode in its
      start-up log since the same day (`policy.egress … mode=enforce`), the kind tier
      waits on that line; the homelab check had to infer it from the start succeeding

## Which policies a namespace may name (ADR-0054)

Under `enforce` the policy a sandbox names decides part of what it reaches, so where the name
is looked up became a boundary.
[ADR-0054](../../docs/adr/0054-which-policies-a-namespace-may-name.md) resolves a `policyRef`
in the namespaces the sandbox's own namespace draws from: itself alone by default, or its
`policy.sources` entry.

- [x] ADR-0054 accepted (2026-11-19), its seven questions answered by their recommendations
- [x] CALM updated and the diagrams rendered; `make calm-validate` passes
- [x] `PolicySources` and `BundleCache::resolve` returning `Found`, `NotFound`, `Ambiguous` or
      `NotRead`; the lookup across `policy.namespaces` removed
- [x] `policy.sources` in the configuration, validated at start (`check_policy_sources`), the
      sources of each namespace logged at start with a `warn` for one that has no watched source
- [x] `P012` for a name two sources hold; `P011` for a name outside the sources
- [x] Under `enforce`: `Failed` with `policy_not_resolved` before any claim exists, a hold
      while the sources are unread, `400 policy_not_resolved` at the front door, one answer
      wherever the name is or is not held; `shadow` reports and refuses nothing
- [x] The serving check (`claims_bundle`): a bundle signed for a namespace outside the
      record's sources serves nothing, so a removed source withdraws reach on the next ask
- [x] Unit tests and e2e in `e2e_gateway.rs`, negative cases included; `make check`
- [x] Guides, README, ADR-0026, ADR-0030 and ADR-0046 amended; threat-model full pass, stamp
      bumped (2026-11-19: A-29, R-54, R-55)
- [x] The kind tiers: both green on the build host (2026-11-19), each with its ADR-0054
      scenario (`dev/kind/policy-e2e.sh`, `dev/kind/gateway-e2e.sh`); what they showed is in
      ADR-0054, *What was proven, and what was not*
- [ ] Rollout checklist, before `enforce` on a build that carries ADR-0054: where policies
      are kept apart from sandboxes, the `policy.sources` entry lands with the image in one
      rollout; then one week of `shadow` with no `P011`, no `P012` and no "outside this
      sandbox's sources" line that was not expected
      ([the policy bundle](../../docs/guides/the-policy-bundle.md#which-policies-a-namespace-may-name))
- [ ] The migration walked on a live cluster that keeps policies apart from sandboxes
- [ ] Eligibility by subject (ADR-0054 decision 7): not built. It waits on notaio's bundle
      carrying `subjects.groups`, and gets an ADR of its own
