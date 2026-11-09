<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 07: Credential-injecting egress proxy

**Status: in progress.** Phase 2 of the delegation model: instead of handing the workload
a 15-minute token it could exfiltrate, the sandbox's egress goes through a proxy that
injects the credential on the way out, and the workload never sees a token at all.
Threat model R-3 was accepted until the ADR for this was written; it is rewritten now.

- [x] The ADR. Done 2026-10-30 as
      [ADR-0025](../../docs/adr/0025-phantom-token-egress-proxy.md), answering the
      questions this roadmap carried: the proxy runs in the guest, as the sandbox user,
      outside the jail, and holds the claim SVID (the identity the workload used to
      hold); the audience is chosen per request by the host the request names, since
      every `egress` endpoint is one audience's; nothing replaces `mediatore token` in
      the jail (it stays a role, with no socket and no route inside); no TLS is
      intercepted (a reverse proxy on loopback, nono's shape for credential injection);
      R-3 becomes "the workload drives requests through the proxy within the rules
      while the claim lives"
- [x] The proxy. Done 2026-10-30: `mediatore egress-proxy`
      (`crates/mediatore-guest/src/egress.rs`), started per claim by the guest as the
      `sb-` user before the jail, on `127.0.0.1:3128`; `http://127.0.0.1:3128/<host>[:<port>]/<path>`
      forwards to `https://<host>:<port>/<path>` over TLS 1.3 to the Mozilla roots,
      HTTP/1.1 both legs, bodies streamed; the phantom in `MEDIATORE_TOKEN` swapped for
      a token for the host's audience, fetched at `POST /v1/token` over the claim SVID and
      cached until 30 s before its expiry; a bare request forwarded bare, a foreign bearer
      `401`, a host outside the routes `404`; a proxy that exits ends the claim
- [x] The policy format: nono's `endpoint_rules`. Done 2026-10-30: `audiences[].rules`
      (`{ method, path }`, `*` one segment, `**` any) in the broker's config, carried to
      the guest as `routes` on `GET /v1/me` (one per audience and endpoint); a request
      outside the rules is `403` before anything is forwarded; the broker refuses an
      endpoint declared by two audiences
- [x] The jail's reach. Done 2026-10-30: no Workload API socket in the jail, no
      `MEDIATORE_URL`; Landlock admits the proxy's port alone (ADR-0024 decision 2
      amended), the uid-keyed table admits loopback to the proxy and drops packets to that
      port from any other uid (ADR-0020 decision 3 amended); the phantom reaches the jail
      through `nsjail`'s environment, never its argument list
- [x] Proven in `make check`: `crates/mediatore/tests/e2e_egress.rs` against a TLS
      upstream from the test kit (`TlsUpstream`), the dev-mode broker and the fake issuer
- [x] A private certificate authority per audience, for an upstream on a private PKI.
      Done 2026-10-30 as ADR-0025 decision 7 (amendment): `audiences[].ca_file`, the
      `issuers[].ca_file` shape, read at start and refused if empty, carried on the route
      as `Route::ca_pem`, the proxy trusting exactly that CA for that audience and the
      Mozilla roots for the rest; a PEM that does not parse refuses the proxy and the
      claim. Proven in `e2e_egress.rs` through the production constructor against the
      test kit's CA, and refused with the CA stripped
- [x] A route without a credential, for what a policy admits without a token: a bundle's
      direct `egress[]` (ADR-0030) and an audience whose upstream rejects the minted bearer
      (GitHub, the 2026-11-05 run). The gateway admits the direct entry under `enforce`
      (proven 2026-11-08), but `/v1/me` rendered routes from the claim's audiences only, so
      a jail behind the gateways could not ask the proxy for it. Done 2026-11-08, ADR-0025
      decision 8: `Route::credential` (`token` or `none`), the audience optional; under
      `enforce` `/v1/me` renders a route per served direct entry (no audience, no rules,
      the Mozilla roots), an audience `via: none` keeps its routes with `credential: none`
      and gets no token from `POST /v1/token`; the proxy drops the phantom on such a route
      and forwards bare, a foreign bearer stays `401`. Proven in `e2e_egress.rs`,
      `e2e_gateway.rs` and `make kind-e2e-gateway-policy` (the direct route in the broker's
      shape, the forward logged `credential=false`). Live the same day on the homelab
      (v0.2.0-rc.7 on the broker and the pool image, the GitHub audience `via: none`): a
      claim under the research-agent policy fetched one route, the proxy forwarded the
      workload's request with the phantom and the one without it bare through a gateway
      (`credential=false`), Envoy's tunnel to GitHub's API answered 200 with the repository,
      no token was asked of the broker, a path outside the rules was 403 and a host off the
      claim 404, PolicyConformant true, the sandbox released clean. Open beside it: a direct
      entry on a private PKI has no CA on its route, so it is reachable on the public roots
      alone; and a policy repository's comment that the proxy "injects the token" on such an
      audience reads wrong now that the audience may carry none
- [x] A gateway's own failure moving the forwarder on. ADR-0028 decision 7 took any
      answer other than `200` from a gateway as final (`502 gateway_refused`), right for
      the authorizer's refusal and wrong for the gateway's own trouble: on 2026-11-09 a
      gateway's Envoy answered `503 DNS resolution failure` for a name every gateway
      resolved a minute later, and the request died with two healthy gateways beside it.
      Done 2026-11-09, decision 7 amended: a `5xx` is the gateway's own condition and the
      next gateway is tried within the one pass, a `4xx` stays the verdict (`verdict` in
      `forward.rs`; the stand-in gateway's unwell mode in `e2e_forward.rs`)
- [ ] An audience served directly, without the proxy, declared per audience for a
      protocol that is not HTTP; never a default. Until then such an audience is
      unreachable from the jail
- [ ] Per-request approval: the proxy asks before forwarding a request a rule marks
      as needing one (nono's approval backends; mediatore's would ask the broker, which
      asks the requester). The instrument that narrows R-3 further
- [x] ~~The proxy answers names for the jail, or the image pins a filtering resolver,
      so the sandbox uid needs no DNS of its own (R-12)~~ Settled another way by
      roadmap 10 (2026-11-04): with egress gateways the sandbox uid's ruleset carries no
      DNS rule at all and the gateway resolves the tunnel's authority on its egress side
      ([ADR-0028](../../docs/adr/0028-egress-gateway-envoy-with-spiffe-identity.md)
      decisions 5 and 6, `net::Shape::Gateways`); R-12 is closed there and stands only
      for an environment without gateways
- [ ] Upstream connection reuse (one connection per request today) and HTTP/2 to the
      upstream, if a workload needs them
- [ ] notaio M3: the bundle renders the routes and the rules, so the jail's two layers
      and the proxy come from one signed policy
- [x] Gateway: [ADR-0028](../../docs/adr/0028-egress-gateway-envoy-with-spiffe-identity.md) (roadmap 10,
      done 2026-11-04) adds the egress gateway behind this proxy: Envoy on banlieue's proxy VMs, with its own SPIFFE
      identity, authorizing each tunnel by claim SVID; the proxy's dialer is the forwarder
      ([ADR-0027](../../docs/adr/0027-control-plane-relay-on-the-egress-gateway.md) decision 8,
      `crates/mediatore-guest/src/forward.rs`).

**Reference design (2026-10-30).** nono's supervisor and `nono-proxy`
([always-further/nono](https://github.com/always-further/nono)) are this roadmap built for
a laptop: the child reaches only a loopback proxy, holds a phantom token, and the proxy swaps
it for the real credential per route with method and path rules; its NEP-0007 moves the
decisions and the credentials to the host over vsock, which is mediatore's shape already.
[ADR-0024](../../docs/adr/0024-landlock-inside-the-jail.md) put the nono library inside the
jail for Landlock; the proxy of this roadmap is written on this workspace's TLS stack
(`nono-proxy` pulls `ring`), with nono's route and endpoint-rule shape as the policy format
so a claim, or a notaio bundle under M3, renders both layers once.
