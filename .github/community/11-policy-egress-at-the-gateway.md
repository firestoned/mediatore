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
      default. Open: the other tiers, as they exist; a startup log line naming the mode
      would have made the check direct, instead of inferred from the start succeeding
