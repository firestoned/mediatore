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
- [ ] An audience served directly, without the proxy, declared per audience for a
      protocol that is not HTTP; never a default. Until then such an audience is
      unreachable from the jail
- [ ] Per-request approval: the proxy asks before forwarding a request a rule marks
      as needing one (nono's approval backends; mediatore's would ask the broker, which
      asks the requester). The instrument that narrows R-3 further
- [ ] The proxy answers names for the jail, or the image pins a filtering resolver,
      so the sandbox uid needs no DNS of its own (R-12)
- [ ] Upstream connection reuse (one connection per request today) and HTTP/2 to the
      upstream, if a workload needs them
- [ ] notaio M3: the bundle renders the routes and the rules, so the jail's two layers
      and the proxy come from one signed policy

**Reference design (2026-10-30).** nono's supervisor and `nono-proxy`
([always-further/nono](https://github.com/always-further/nono)) are this roadmap built for
a laptop: the child reaches only a loopback proxy, holds a phantom token, and the proxy swaps
it for the real credential per route with method and path rules; its NEP-0007 moves the
decisions and the credentials to the host over vsock, which is mediatore's shape already.
[ADR-0024](../../docs/adr/0024-landlock-inside-the-jail.md) put the nono library inside the
jail for Landlock; the proxy of this roadmap is written on this workspace's TLS stack
(`nono-proxy` pulls `ring`), with nono's route and endpoint-rule shape as the policy format
so a claim, or a notaio bundle under M3, renders both layers once.
