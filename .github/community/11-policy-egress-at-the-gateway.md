<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 11: A policy's direct egress at the gateway

**Status: in progress** (ADR-0030 accepted and implemented 2026-11-05; the live proof and the rollout are open). The first enforcing step of
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
- [ ] Live proof: `make kind-e2e-gateway` with a bundle in the cluster, through the real Envoy
- [ ] Rollout: shadow, then enforce in dev, then each tier
