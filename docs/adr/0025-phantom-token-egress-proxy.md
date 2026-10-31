<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0025: The egress proxy, a phantom token in the jail and the real one in a process the workload cannot read

**Status:** Accepted · **Date:** 2026-10-30 · **Amended:** 2026-10-30 (decision 7, the
audience's own CA)

Roadmap 07, the credential-injecting egress proxy: phase 2 of the delegation model that
[ADR-0003](0003-token-backends.md) recorded as a trade-off and that threat model R-3
accepted until this ADR was written. Amends [ADR-0014](0014-one-binary-roles-as-subcommands.md)
decision 4 (what the binary mounted into the jail is for), [ADR-0020](0020-jail-network-nftables-keyed-by-sandbox-uid.md)
decisions 2 and 3 (what the sandbox uid reaches and who else reaches the proxy) and
[ADR-0024](0024-landlock-inside-the-jail.md) decision 2 (the workload's connect ports).
Changes nothing about the identities of [ADR-0004](0004-spiffe-identity-scheme.md), the
token shapes of ADR-0003 or the broker's `POST /v1/token`: the proxy is one more client
of it, with the claim SVID, like the workload was.

## Context

Since ADR-0014 the workload inside the jail runs `mediatore token --audience <a>`, which
fetches the claim SVID from the Workload API socket mounted into the jail, opens a
mutual-TLS session to the broker and prints a bearer token for that audience. The
workload then calls the downstream API with it. The design is honest about what that
means: a prompt-injected workload holds a token it can send anywhere its egress reaches
for as long as the token lives, 15 minutes for the STS's, the tenant's lifetime for an
Entra-minted one (R-3). ADR-0020 bounded where the packets go and ADR-0024 bounded what
the process may touch, and neither changes the fact that the credential is in the
hostile process.

Roadmap 07 listed the questions. Where the proxy runs and what identity it holds. How
the audience is chosen per request. What replaces `mediatore token`. Whether the proxy
intercepts TLS. What R-3 becomes.

nono ([always-further/nono](https://github.com/always-further/nono), whose library crate
ADR-0024 put inside the jail) answers them for a laptop, and its answers transfer. Its
proxy does not intercept TLS for credentials: credential injection is a reverse proxy
on loopback, the sandboxed process is given `http://127.0.0.1:<port>/<route>` as the base
URL of each API and a phantom token in the environment variable the tool reads, and the
proxy swaps the phantom for the real credential on the way out, checking the request
against per-route `endpoint_rules` of method and path glob first. A request without the
phantom gets `401`, one outside the rules `403`. Its NEP-0007 moves the decisions and the
credentials to the host and keeps enforcement in the guest, which is where mediatore's
broker already is. `nono-proxy` itself pulls `ring` and cannot enter this workspace
(`deny.toml`, ADR-0007); the shape is what is borrowed, on this workspace's TLS stack.

What makes the shape fit here is that the claim already knows its routes: `audiences[]`
in the broker's config names, per audience, the `egress` endpoints the workload reaches
it at (ADR-0020). Every endpoint is an audience's, so the host of a request chooses the
audience, and the audience chooses the token.

## Decision

1. **A second process of the one binary, as the sandbox user, outside the jail.** The
   guest starts `mediatore egress-proxy` for every claim before it starts the jail, as
   the `sb-` uid and gid, in the VM's network namespace and filesystem, not in the
   chroot. It fetches the claim SVID from the Workload API as the workload used to (the
   claim entry's selector is `unix:user:<sb-user>`, ADR-0006, unchanged) and it is now
   the only process that ever holds a downstream token: it calls `POST /v1/token` over
   the claim SVID when a request needs one and keeps the answer in memory until shortly
   before its `expires_at`. It listens on `127.0.0.1:3128` (`--egress-proxy-port` on the
   guest). The guest supervises it with the jail: a proxy that exits ends the claim, since
   nothing may run with no way out (fail closed, like a ruleset that does not load,
   ADR-0020 decision 5). A role of the one binary, as ADR-0014 says every piece of the
   guest is; nothing new enters the image.

2. **A reverse proxy on loopback; the destination host is the first path segment.** The
   workload calls `http://127.0.0.1:3128/<host>[:<port>]/<path>` and the proxy forwards
   to `https://<host>:<port>/<path>` over TLS 1.3 to the Mozilla roots, the same client
   configuration the broker uses for an identity provider. `<host>` must be an `egress`
   endpoint of one of the claim's audiences; the port may be omitted when that host
   appears with one port only. Any other first segment is `404`. No TLS is intercepted,
   no certificate authority is minted or installed in the jail, and the proxy speaks
   HTTPS to every upstream: an endpoint that serves plain HTTP gets no credential and no
   route. HTTP/1.1 on both legs, bodies streamed, hop-by-hop headers dropped, one
   upstream connection per request.

3. **A phantom token in the jail, the real one swapped in by the proxy.** The guest
   generates 256 random bits per claim and hands them to the jail as `MEDIATORE_TOKEN`,
   through `nsjail`'s environment rather than its argument list, so no other user on the
   VM reads it from `/proc`. The workload sends `Authorization: Bearer $MEDIATORE_TOKEN`
   to the proxy and the proxy replaces it with `Bearer <token for the host's audience>`.
   A request with no `Authorization` header is forwarded without a credential (a public
   endpoint behind the same host). A request with any other `Authorization` value is
   refused with `401`: the workload has no credential of its own that this layer
   carries, and a credential baked into an image is exactly what the policy must not
   let through. The phantom is not a secret in the usual sense: it is useless anywhere
   but at this proxy, from this uid, during this claim.

4. **nono's endpoint rules, per audience, in the broker's config, enforced by the
   proxy.** `audiences[].rules` is a list of `{ method, path }`: `method` an HTTP method or
   `*`, `path` a glob where `*` matches one segment and `**` zero or more, matched against
   the path after the host segment, without the query. No rules means every method and
   path at that audience's endpoints is admitted. Once an audience has rules, a request
   outside them is `403` and nothing is forwarded, credentialed or not. The rules travel to
   the guest with the subject: `GET /v1/me` gains `routes`, one entry per audience and
   endpoint with that audience's rules, over the same mutual-TLS session as `egress` and
   the pull credential; the guest writes them to a file the proxy reads, owned by the
   sandbox user, outside the jail. The broker refuses a configuration in which one
   endpoint belongs to two audiences, since the host must choose the token.

5. **The jail reaches the proxy and nothing else; the socket leaves the jail.** The
   workload's Landlock plan (ADR-0024) grants TCP connect to the proxy's port only, and
   the guest refuses a claim whose broker or egress uses that port, so the one allowed
   port names one destination. The uid-keyed table of ADR-0020 admits `127.0.0.1:3128`
   for the sandbox uid, keeps the broker, the egress addresses and DNS for the same uid
   (the proxy's sockets carry it), and gains one rule in its base chain: a packet to the
   proxy's loopback port from any other uid is dropped, so no system daemon and no other
   sandbox on the VM can present the phantom. The Workload API socket is no longer mounted
   into the jail, and `MEDIATORE_URL` and `SPIFFE_ENDPOINT_SOCKET` are not in its
   environment; `MEDIATORE_EGRESS_PROXY=http://127.0.0.1:3128` and `MEDIATORE_TOKEN` are.
   `mediatore token` stays a role of the binary (the proxy's own client is the same code,
   and an operator or a test runs it outside a jail); inside the jail it has no socket and
   no route, and nothing replaces it. The binary stays mounted for `jail-exec`.

6. **Not decided here.** An audience served directly, without the proxy, for a protocol
   that is not HTTP; a `direct` bypass per claim; approval of individual requests; the
   proxy answering DNS for the jail (R-12 is unchanged, the uid still needs the resolvers
   for the proxy's own lookups). Each is a roadmap 07 item with its own trigger, not a
   default. *The private certificate authority per audience, listed here when this ADR
   was accepted, became decision 7 the same day: the homelab's endpoints are on a private
   PKI, so without it the proxy reached nothing there.*

7. **The audience's own CA, on the route.** (Amendment, 2026-10-30.) `audiences[].ca_file`
   names a PEM of CA certificates, the shape `issuers[].ca_file` already has for an
   identity provider on a private PKI. The broker reads it at start and refuses to start on
   a file that holds no certificate; `GET /v1/me` carries the PEM on every route of that
   audience (`Route::ca_pem`, public material, over the same mutual-TLS session as the
   rest); the proxy builds, for that audience, a client configuration that trusts exactly
   that CA and nothing else, and uses the Mozilla roots for routes that carry none. A route
   whose PEM does not parse refuses the proxy, and so the claim, at start: never the
   default roots in its place. The CA is per audience, not per endpoint, since an audience
   is one API behind one authority.

## Consequences

- `crates/mediatore-guest/src/egress.rs` (the `egress-proxy` role: the routes, the
  rules, the phantom, the token cache, the two HTTP legs), `jail.rs` (the socket mount
  and the broker variables gone, the proxy's variables and port in), `net.rs` (the
  loopback entry and the other-uid rule), `supervise.rs` (the proxy supervised with the
  jail), `guest.rs` (the phantom, the routes file, the spawn as the sandbox user, the
  readiness wait), `sandboxfs.rs` (an `egress/` directory of the sandbox user's beside
  `work/`), `crates/mediatore/src/main.rs` (the subcommand), `config.rs`
  (`audiences[].rules`, the one-audience-per-endpoint check), `crates/mediatore-api`
  (`routes` on `GET /v1/me`), `crates/mediatore-proto` (`Route`, `EndpointRule`,
  `Me::routes`; `Me::egress` stays, so an older guest keeps its ruleset).
- The proxy is proven end to end in `crates/mediatore/tests/e2e_egress.rs`: the fake
  issuer, the dev-mode broker, a TLS upstream from `mediatore-testkit` on its own CA that
  records what reached it, and the proxy in between through its production constructor;
  the audience's CA travels on the route and the phantom is swapped for an STS token the
  upstream verifies against the broker's JWKS, a request with no header forwarded bare, a
  foreign bearer refused, a request outside the rules refused, an unknown host refused,
  the token fetched once for two requests, and the same upstream refused (`502`, nothing
  reaching it) when the route carries no CA. The image is unchanged; the kind tiers start
  no jail and no proxy.
- What the workload sees: no socket, no `mediatore token`, a base URL and a phantom.
  Tools that take a base URL and a bearer from the environment work unchanged; `git`
  takes the URL and `http.extraheader`. The research agent walkthrough shows both.
- R-3 is rewritten. The workload holds no token and cannot obtain one: the exfiltration
  window is gone. What remains is that a prompt-injected workload drives requests
  through the proxy, within the rules, while the claim lives; the rules and the claim's
  TTL bound it, and per-request approval is the next instrument. R-12 is unchanged.
- The proxy shares the sandbox uid with the workload. What keeps the workload out of
  the proxy's memory is not the uid: the jail is a PID namespace of its own with no
  `/proc` (`nsjail`, ADR-0020), so the proxy's process has no pid the workload can name
  for `ptrace` or `process_vm_readv`, and Landlock scopes its signals and abstract Unix
  sockets to the jail (ADR-0024). Yama's `ptrace_scope` is 0 on Debian 13 and is not
  relied on; setting it to 1 on the image is a cheap second line and a roadmap 06 item.
  A dedicated uid for the proxy would need a second SPIRE entry per claim or a
  node-issued token; recorded as an accepted risk, revisited if either becomes cheap.
- Rejected: terminating TLS in the proxy with a per-claim CA installed in the jail
  (every tool trusts the CA differently and Go binaries ignore `SSL_CERT_FILE`; nono does
  not do it for credentials either); running the proxy as root inside `mediatore guest`
  (root could request tokens for the claim only by a change to ADR-0003's issuance rule,
  and a compromise of the guest process would then hold every claim's tokens as well);
  `nono-proxy` itself (`ring`); keeping the direct path beside the proxy (the token would
  still be in the workload, and this ADR would have changed nothing against R-3).
