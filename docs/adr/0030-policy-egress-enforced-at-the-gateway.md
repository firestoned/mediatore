<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0030: A policy's direct egress, enforced at the gateway behind a switch

**Status:** Implemented · **Date:** 2026-11-05 (accepted and implemented the same day; the live proof against the real Envoy is open, roadmap 11)

Roadmap 11. The first enforcing step of [ADR-0026](0026-notaio-bundles-verified-in-shadow.md),
limited to one thing: the verified bundle's direct `egress[]`. Amends
[ADR-0028](0028-egress-gateway-envoy-with-spiffe-identity.md) decision 4 (what the broker
answers the gateway: "today `audiences[].egress` ... and the notaio bundle when roadmap 04
and notaio M3 land"). Changes no token shape, no SPIFFE ID and no storage contract. It
does change what a gateway lets through, so the threat-model pass is part of done.

## Context

The gateway decides each `CONNECT` from one allowlist per claim, which the broker computes in
`egress_of` (`crates/mediatore-api/src/lib.rs`): the union of the `egress` endpoints of the
claim's audiences, from the broker's configuration (ADR-0020 decision 2). A `SandboxPolicy`
also declares direct `egress[]`: hosts the sandbox may reach that are not the API of any
audience (an artifact repository, a source host, a model API). notaio compiles them into the
signed bundle as `host:port` entries, and the policy repository's lint holds them inside the
Security-approved ceiling. ADR-0026 verifies that bundle and compares it with the broker's
configuration in shadow. Check `P006` reports the entries the broker "has no way to provide".

So today a reviewed, signed, ceiling-checked policy cannot make the gateway admit its own
direct egress. Operators stand in for it with a static allowlist baked into each gateway at
build time, outside this repository, which is what this ADR retires on the broker's side.

## Decision

1. **The allowlist of a claim is the union of two sources, and the second is conditional.**
   - The audience endpoints, exactly as today.
   - The direct `egress[]` of the claim's policy bundle, only when that bundle is **usable**:
     it is in the reflector's cache (so it passed the signature check, the version floor and
     the Misplaced check of ADR-0026 decision 4) and is unexpired now.

   A claim whose bundle is missing, stale (past `notAfter`), dropped or never verified gets the
   audience endpoints only, never the direct egress. Nothing about a bundle can reduce the
   audience endpoints: the bundle adds, it does not subtract. A claim that names no policy
   (`P010`) gets the audience endpoints only. The union is sorted and deduplicated, as the
   audience endpoints are.

2. **Which bundle is a claim's.** The claim record holds the policy's `uid` (ADR-0026 decision
   6), not its name. The broker finds the bundle by that `uid` among the cached bundles and
   uses the **current** bundle, not the version the claim was created under: a policy that
   tightens narrows the egress of the sandboxes running under it on the gateway's next ask
   (at most the gateway's fresh-plus-stale bound, ADR-0028 decision 4), and the version floor
   guarantees the current bundle is never older than one the broker already accepted. A `uid`
   held by no cached bundle is "missing", per decision 1. No migration: the record already
   has what is needed.

3. **Only entries the gateway can enforce exactly are served.** An entry is served when it is
   `host:port` with a DNS host name: no IP literal, no wildcard, a port, matched by the
   gateway on exact equality as every other entry is (ADR-0028 decision 4). An entry that
   fails this is not served, and is logged with the policy and the reason, never
   reinterpreted. An entry with non-empty `rules` (a policy that allows only some calls
   there) is **not served**: the gateway sees an authority, not a path (no interception,
   ADR-0028 decision 9), so serving it would allow more than the policy says. It is logged
   and stays a finding until an ADR on interception exists. This keeps the rule that
   an unimplemented path fails closed.

4. **A switch, per environment, defaulting to shadow.** The `policy` section gains
   `egress: shadow | enforce`, default `shadow`. It is the broker's own configuration,
   reviewed with the deployment, like the trusted keys (ADR-0026 decision 2); never cluster
   state. In `shadow` the broker serves today's answer and logs, per ask whose answer would
   differ, the policy, the bundle version and the entries it would have added (hosts and
   ports only, no tokens). In `enforce` it serves the union. Without a `policy` section
   there is nothing to enforce and the switch does not exist. The switch is global to a
   broker process; rollout is per environment (one broker deployment each), so the order is
   deployment configuration, not code.

5. **`/v1/me` and the gateway answer stay one list.** `egress_of` feeds both the guest's
   ruleset and the gateway's answer, and its comment says they must agree. They keep
   agreeing: the same function, the same switch. On a gateway-era pool the ruleset names the
   gateways, not the endpoints (ADR-0028 decision 6), so the extra entries change what the
   gateway admits and nothing the guest's firewall admits.

6. **`P006` follows the switch.** While the switch is `shadow` it is reported as ADR-0026
   says. In `enforce` the broker can provide the entries, so `P006` is not reported for
   entries it serves; an entry it refuses under decision 3 is reported by a new code,
   `P007` ("the bundle holds a direct egress entry the broker does not serve", with the
   reason), so the finding is never lost.

7. **Nothing else loosens.** Default-deny, exact match, the claim-only SVID check at the
   gateway, the broker's gateway-only route and the `404` that drops the gateway's cache
   are untouched, and have a test that says so.

## Rollout

`shadow` everywhere first (the code ships dormant). Then `enforce` in the dev environment,
checking the shadow log of the previous week for entries nobody expected. Then each other
tier in turn, a configuration change per environment with the previous value as rollback:
setting `egress: shadow` restores today's answer on the gateway's next ask. The static
allowlist on the gateways is retired by the gateway repository after `enforce` is on, in its
own change; this ADR does not touch it.

## Implementation notes

- `EgressMode`, `direct_egress` and `BundleCache::by_uid` are in `crates/mediatore-claims/src/policy.rs`;
  `by_uid` takes the highest version among the unexpired cached bundles of that uid. Hosts are
  lowercased before serving, as the gateway lowercases the authority it matches.
- `egress_of` (`crates/mediatore-api/src/lib.rs`) reads `AppState::policy_egress`
  (`PolicyEgress { bundles, mode }`), `None` without a `policy` section and under `dev_mode`.
  In shadow it logs what it would have added (the claim UID, the policy uid, the bundle
  version, host and port); an unservable entry is logged at debug and is `P007` in the
  sandbox's `PolicyConformant` condition.
- `shadow::compare_with` takes the switch; `compare` is `compare_with(.., Shadow)`. The
  watcher gets the mode through `WatcherConfig::egress_mode`.
- A cache that has not completed its first list is empty, so a replica that is not ready
  serves the audience endpoints only, with no separate check.
- Tests: units in `policy.rs`, `shadow.rs` and `config.rs`; end to end in
  `crates/mediatore/tests/e2e_gateway.rs` (enforce adds, shadow does not, no policy or an
  unknown policy adds nothing, rules, IP literals and wildcards are never served). The
  gateway's 404 behaviour keeps its existing tests, unchanged.

## Consequences

- A reviewed, signed policy can drive the gateway. Review of an egress change moves to the
  policy repository, where the ceiling lint already runs.
- The bundle becomes load-bearing at the gateway before it is at admission. ADR-0026's
  warning applies: the trusted keys and the reflector's RBAC are now part of the trust
  boundary for egress. The threat model gets a full pass.
- Every cached-bundle expiry or drop now shrinks a live claim's reach (to the audience
  endpoints) within the gateway's bound. That is the intended fail-closed direction, and an
  operational dependency on notaio republishing before `notAfter`.
- `GET /v1/gateway/claims/{uid}` reads the reflector's cache, so a replica that has not
  completed its first bundle list serves audience endpoints only: fail closed, and
  `synced` is the check.
- Entries with `rules` stay unserved until interception is decided.

## Alternatives considered

- **Enforce with no switch.** Rejected for the reason of ADR-0026: the first evidence of a
  surprise would be a blocked sandbox.
- **Use the bundle version recorded on the claim.** Rejected: a tightened policy would not
  narrow running sandboxes.
- **Serve the bundle's audiences too (replace the broker's config).** Out of scope: it is
  the enforcing ADR for `P001` to `P005`, a different decision.
- **Let the gateway read bundles itself.** Rejected: it would give the gateway a second
  trust anchor and a Kubernetes client, on the most exposed host.
- **Serve entries with `rules` as the bare authority.** Rejected (decision 3): more than the
  policy says.
