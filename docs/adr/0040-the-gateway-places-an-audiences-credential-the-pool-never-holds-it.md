<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0040: The gateway places an audience's credential, so the pool VM never holds it

**Status:** Accepted, implemented in the repository 2026-11-15 (config and validation, the broker's credential route, the authorizer's inject check and two sockets, the guest's route and ruleset, the host table's inject port, three Envoy templates; the live proof is pending the gateways' egress allowance, the OpenBao transit key and a release, and the per-claim limit and the real-Envoy integration test are open) · **Date:** 2026-11-15

Roadmap 07 (the egress proxy) and roadmap 10 (the gateway). Takes the "own ADR" that
[ADR-0028](0028-egress-gateway-envoy-with-spiffe-identity.md) decision 9 reserved for credential
injection at the gateway. Amends [ADR-0025](0025-phantom-token-egress-proxy.md) decisions 1 to 3
for an audience that opts in (the swap moves from the guest's proxy to the gateway) and
[ADR-0035](0035-a-requesters-own-session-delegated-at-claim-time.md) decision 4 (where the opened
envelope goes). Changes no token shape, no SPIFFE ID, no storage contract; adds one broker route,
one gateway process and one listener. Nothing changes for an audience that does not opt in.

## Context

A credential for an audience (the operator's key, ADR-0032; the requester's own session,
ADR-0035; an STS token) is fetched today by the guest's `mediatore egress-proxy` at
`POST /v1/token` over the claim SVID and held in that process's memory, outside the jail
(ADR-0025 decisions 1 and 3). The jail sees a phantom. So the credential does reach the pool VM:
root on the VM, or a flaw in the proxy, can read it, which ADR-0025 accepts. The operator wants
the credential for the Anthropic API never to reach a pool VM: held by OpenBao, short lived (five
minutes), and placed for that subject at the gateway.

The gateway cannot do that today. The sandbox leg is mutual TLS carrying `CONNECT`
(ADR-0028 decision 3); the upstream TLS runs end to end inside the tunnel, so Envoy sees an
authority and bytes, never a request, and a header cannot be added to a request Envoy cannot
read. ADR-0028 decision 9 said so and named the way out: "a per-API opt-in for known hosts", with
its own ADR. For an opted-in audience the gateway itself originates the TLS to the audience, so
it sees the request and can add the header. No certificate authority is minted or installed
anywhere (a MITM of the workload's TLS stays rejected, ADR-0028 decision 9).

What OpenBao's transit engine is, and is not (ADR-0015): encryption as a service. The broker
seals refresh material with a key OpenBao keeps; the key is `derived` and the claim's binding UID
is the derivation context. Transit has no lifetime on a ciphertext and mints no Anthropic
credential. So "a session key from transit with a five minute TTL" is, in this design: the
credential is sealed at rest under a transit key; its plaintext exists only when the broker opens
it; and its life downstream is bounded by `max_ttl` (300), the delegation's own expiry and the
claim's deadline, all enforced by the broker exactly as `delegated_token` does today.

Facts established for this environment. OpenBao is set up for the cluster and its
Kubernetes-auth role exists (the operator). The broker pod already mounts a projected
ServiceAccount token with audience `openbao` at `/var/run/secrets/openbao/token`
(`deploy/base/deployment.yaml`), which is the transit sealer's `token_file`; enabling
`store.sealing.transit` needs only `url`, `mount`, `key`, `role` and that path. Not yet known, for
the operator to confirm: whether the transit mount and a `derived` key exist, and whether the
role's policy covers them. And the gateways cannot reach the audience today: from a gateway,
`api.anthropic.com` resolves but the TCP connect times out and no proxy is configured. So the whole
Anthropic flow, under any placement, needs an egress allowance first (open question 4).

## Decision

1. **A per-audience setting, `inject: proxy | gateway`, default `proxy`, and a rule that binds
   the credential to its authority.** `proxy` is today's behaviour, byte for byte. `gateway` is
   accepted for `via: secret`, `via: delegated` and `via: sts` (a `none` audience has no
   credential to place), only when the broker's `gateways` and a new `gateway_inject_port` are set,
   and only with `max_ttl` at most 300 (a hard cap, a constant, not a setting). A credential is
   bound to the authority that needs it, so the broker also refuses at start a gateway-placed
   audience whose `egress` has a wildcard, a hostless entry or an IP address (the gateway verifies the
   upstream by name), whose entries are not all exact `host:port` of one upstream (one host name,
   one entry per port), or that has no `rules` (under `proxy` no rules means every method
   and path; a placed credential does not get that default). At request time the header is added
   only when the request's authority equals an entry of that audience's own `egress` and a rule
   matches (decision 4). Each of these is a configuration test.

2. **The broker gives the credential to the gateway and to nobody else, and audits each issue.** A
   new route, `POST /v1/gateway/claims/{uid}/credential` with `GatewayCredentialRequest { audience }`,
   accepts only the peer `spiffe://<td>/gateway`, through the guard `GET /v1/gateway/claims/{uid}`
   uses: any other peer is `403 forbidden`, no identity `401`. The checks, in order: the uid is a UUID
   (`400 invalid_claim_uid`); the claim is live (`404` for one that is unknown, unbound, released or
   expired); the claim names the audience (`400 unknown_audience`); the audience is gateway-placed
   (`403 not_placed_at_gateway` otherwise); the policy admits the audience; the per-claim rate limit.
   It then calls the per-backend code `POST /v1/token` calls (one shared function: `secret`, the
   `delegated` envelope opened, Entra On-Behalf-Of, STS with the claim as actor) and returns a
   `GatewayCredential` (`mediatore-proto`; a new type, because `TokenResponse` keeps its token in a
   plain `String` that a `Debug` would print, and this one holds it as a `Secret`) with `expires_at`
   at most 300 seconds ahead. Nothing is stored. Policy admission is new on this route: `token_claim`
   has no policy check, so this route adds one and does not repeat one. Under `policy.egress: enforce`
   it fails closed: the claim must name a policy whose verified, unexpired bundle lists the audience,
   and no policy, no cached bundle or an omitted audience is `403`; under `shadow` it logs the gap and
   allows; with no `policy` section it does nothing. `/v1/token` for a proxy-placed audience is
   unchanged, policy included. The limiter is the same per-claim bucket `/v1/token` uses, which is
   enough because the gateway asks at most about once a minute per claim (decision 5), and a refused
   ask does not spend it. `POST /v1/token` for a gateway-placed audience is `403 placed_at_gateway`
   (the shape of `no_credential`), refused before the limiter, so the claim SVID on the pool VM cannot
   obtain the credential either. Every issue is one log line, `gateway credential issued`: claim UID,
   audience, subject, backend, `expires_at`, never the credential. `GET /v1/gateway/claims/{uid}` gains
   `inject`: per gateway-placed audience, its endpoint, rules, header names and the non-secret extra
   headers (`anthropic-version`), with the claim's deadline, and `GET /v1/me` carries
   `credential: gateway` and the inject port on the audience's routes.

3. **The inject listener is its own Envoy, `envoy-inject`: a process and a user of its own.** Three
   processes divide the gateway, so that the one that carries every tunnel never holds a credential:

   | Process | Identity | Credential | TLS |
   | --- | --- | --- | --- |
   | `envoy-relay` (ADR-0027) | none | never | none: ciphertext in, ciphertext out |
   | `envoy` (data plane, ADR-0028) | gateway SVID | never | mutual TLS to claims, `CONNECT`, `ext_authz` yes or no |
   | `envoy-inject` (new) | gateway SVID, for the claim mutual TLS | transient, in a request's headers | terminates claim mutual TLS, originates TLS to the fixed hosts |

   `envoy-inject` runs a unit and a static user of its own, has no admin interface, and takes its
   SVID from the agent socket by its own SPIRE entry (`unix:user:envoy-inject`, a third entry for
   the `gateway` SPIFFE ID beside `unix:user:envoy` and `unix:user:mediatore-gateway`: an entry's
   selectors are a conjunction, so one entry per user, ADR-0028 implementation notes). Its listener is on the sandbox address and its
   own port (`INJECT_PORT`): the same mutual TLS 1.3 with the claim SAN prefix (ADR-0028
   decision 4), HTTP/1.1, no `CONNECT` route, no dynamic forward proxy. A route matches the request's
   `:authority` exactly against the operator's fixed list (`INJECT_ENDPOINTS=api.anthropic.com:443`
   in the gateway's env, a reviewed change like a relay leg, ADR-0027) and goes to a static cluster per
   upstream with TLS origination (`sni` the host; the system roots, or a PEM for an audience on a
   private PKI, `ca_file`). A host not in the list has no route (`404`). The deployment's gateway repository renders one virtual
   host and one cluster per entry of `INJECT_ENDPOINTS`; this repository's own image template
   (`image/gateway/envoy/inject.yaml.in`) renders the one upstream its env file names (`INJECT_HOST`,
   `INJECT_UPSTREAM_PORT`, `INJECT_DOMAIN`), and says a second is a reviewed change to the template, as
   a relay leg is. `ext_authz` on the listener carries `context_extensions: { mode: inject }` (per
   virtual host, `failure_mode_allow: false`, `status_on_error: Forbidden`, a 3 second timeout). Envoy
   runs at `info` (its `debug` and `trace` log headers), `suppress_envoy_headers` is on, and the route
   has no overall timeout but an idle limit (`INJECT_STREAM_IDLE_SECS`, 300) and a stream ceiling
   (`INJECT_MAX_STREAM_SECS`, 3600) so a streamed response lives as long as a claim may.

4. **The authorizer answers an inject check, and alone writes the credential header.** The check
   carries what Envoy fills from the connection and request: `source.principal`,
   `request.http.method`, `.host`, `.path` (never read from the client). The authorizer requires a
   claim identity, refuses `CONNECT` (`not_inject`), finds the gateway-placed route for `host:port` in
   the claim's cached `inject` answer (`InjectRoute::matches_authority`, an absent port meaning 443),
   applies the route's `rules` to the method and the path without its query (`InjectRoute::admits`;
   enforced here as well as in the guest proxy), obtains the credential (decision 5), and answers `OK`
   with the credential header and the extra headers by `OVERWRITE_IF_EXISTS_OR_ADD`, which replaces a
   client's copy of the same name and never appends to it. It also sends `headers_to_remove` for the
   OTHER credential-bearing headers a client could have sent (`authorization` and `x-api-key`, minus the
   route's own header and its extra headers): Envoy's `OkHttpResponse` does not say whether
   `headers_to_remove` runs before or after `headers`, so naming the route's own header in the removal
   list could strip the credential it just set, and the overwrite already does that header's job. A
   credential whose value or header name is empty is refused (`credential_refused`), because Envoy's
   header add drops an empty value without an error and the request would reach the upstream with no
   credential at all. A refusal is the same `403` and code as today, marked as decision 12 says. The
   design rule, shown on the pinned Envoy 1.40.2 (the spike, TESTING.md T-61, with an HTTP-service
   `ext_authz`): route-level and virtual-host-level `request_headers_to_remove` run after `ext_authz`
   has mutated the request and removed the very header the authorizer had added, so the credential
   header must never be added or removed at route, virtual-host or listener level; only the
   authorizer's response touches it, and no static strip names it (a render test pins that none
   appears). The rules match the path as Envoy hands it over, so the listener normalises it first:
   `normalize_path`, `merge_slashes` and `path_with_escaped_slashes_action: REJECT_REQUEST`, which stop
   a `../` or a doubled slash walking out of a rule and refuse an escaped slash instead of decoding it
   into a different path. Authority matching follows from the spike: the virtual hosts' `domains` are
   bare hosts, the guest proxy sends `Host` without a port (an absent port means 443, which is right
   for an HTTPS upstream on its default port; any other port is a rule's explicit `host:port`), and
   `strip_any_host_port` stays off, because on default Envoy a `Host` carrying an explicit port
   against a bare domain is a `404` (fail closed) while with the option on, a request for the same
   host on another port would select the same route. The access log's `%REQ_WITHOUT_QUERY(:PATH)%` is an
   extension formatter: Envoy 1.40.2 rejects it unless `envoy.formatter.req_without_query` is
   registered under the log format, which both templates do (`envoy --mode validate` caught it).

5. **The credential lives in the authorizer, for a short time, never in a log, and spending is
   bounded per claim.** It is held as a `Secret` in memory only, keyed by claim UID and audience, for
   the least of 60 seconds, its `expires_at` minus 30 seconds and the claim's deadline (an expiry
   inside the margin is served once and kept nowhere), dropped when the broker answers `404` for the
   claim, and bounded in size by least recent use. Concurrent asks for one key make one broker call. A
   cached credential is served through a broker outage until its bound and then denied; with none
   cached the answer is a deny. The decision line is claim UID, audience, host, verdict, reason
   (ADR-0028: never a token, never a body, never the query); the listener's access log names peer,
   method, authority, the path without its query, status and flags, and no header. A compromised
   workload must not be able to spend without bound through a valid claim: the intended mechanism, a
   limit by request rate and concurrent streams keyed by the claim identity on the connection (a local
   rate limit with descriptors from the peer SAN is the candidate), is NOT built or proven here. The
   template carries a marked placeholder, and until the mechanism is proven the bound is the host
   table's per-source connection cap on the inject port, as for every other port, plus the upstream
   account's own limit (decision 9, layer 10). That is an accepted risk in the threat model, not a
   control.

6. **The authorizer serves two unix sockets, one per kind of Envoy, so the tunnel Envoy cannot ask
   an inject question.** A check response now carries a credential and the check's
   `source.principal` is supplied by the caller, so the question asked must follow from the channel,
   not from a header. `mediatore gateway` listens on `check/check.sock` for the data plane, which gets
   `OK` or `403` and never a credential (an inject-shaped question there is refused as `not_connect`
   before any lookup), and on `inject/inject.sock` for `envoy-inject`, the only caller served an inject
   answer (a `CONNECT` there is `not_inject`). Each socket has a directory of its own, because the
   directory carries each Envoy's access: `check_layout` refuses two sockets in one directory. The
   directories are `2750`, setgid, owned by `mediatore-gateway` and by each Envoy's group (`envoy`,
   `envoy-inject`), made by the authorizer unit's `ExecStartPre=+`; each socket is `0660`; each
   Envoy's `authorizer` cluster is a pipe. The authorizer is in neither group, so it cannot `chgrp` a
   socket to either, and it is not put in them (that would let it read their configuration): the unit
   passes `--check-socket`, `--inject-socket` and `--socket-dir-mode 2750` and no owner or group flag,
   and the setgid directory gives each socket its Envoy's group. The directory mode accepts the setgid
   bit and no other special bit, on a directory only, and is applied after any `chown`, because some
   systems clear the bit on a `chown`. A compromised data-plane Envoy, even holding the gateway SVID,
   cannot obtain a credential through the authorizer. Without a gateway-placed audience the loopback
   TCP of ADR-0028 stays (`--listen`) and `envoy-inject` is not started.

7. **The guest proxy sends the request to the gateway instead of tunnelling; the direct path stays
   rejected.** A route gains `credential: gateway` beside `token` and `none` (ADR-0025 decision 8) and
   carries the gateway's inject port. For such a route the proxy never calls `POST /v1/token`, still
   refuses a non-phantom `Authorization` with `401` (decision 3 of ADR-0025), still checks the rules
   (a request outside them never leaves the guest), strips the phantom and any `x-api-key` the client
   sent, and sends the request in origin form with `Host: <audience host>` (bare at 443, `host:port`
   otherwise) and no credential over the claim-SVID mutual TLS dialler the forwarder already has
   (`crate::forward`, the gateway verified as `spiffe://<td>/gateway`) to a gateway's inject port,
   streaming the body and relaying the response unchanged, server-sent events included. It tries the
   gateways in the order the CONNECT path does and fails over on a connection failure only: the body
   is streamed and cannot be replayed, so a gateway's `5xx` is not retried. Nothing unreachable is
   `502 gateway_unreachable`; a refusal by the gateway itself is `502 gateway_refused` (decision 12).
   The proxy refuses to start for a gateway-placed route with no inject port, with port 0 or with a
   direct dialler (no gateways), and never falls back to a tunnel or to fetching the credential. The
   workload is untouched (its base URL is still the loopback proxy, its header still the phantom), and
   the jail still reaches the proxy and nothing else (ADR-0025 decision 5). A direct path from the
   jail to the gateway is smaller on the wire and larger in the trust model: the jail has no SVID, so
   it could not authenticate. The sandbox uid's table gains `gateway . INJECT_PORT` for each gateway
   when, and only when, the claim has a gateway-placed route (`Ruleset::with_inject_ports`; a claim
   without one renders exactly today's table; the proxy's sockets carry that uid and the jail's
   Landlock plan does not change), the pool VM's host table admits the same destinations (decision
   13), and the gateway's sandbox filter admits `INJECT_PORT` to the sandbox range under the same
   per-source cap as the other ports.

8. **The credential source is unchanged, and transit is configured for sealing.** The first source
   is `via: delegated` (ADR-0035): the requester's session, delegated with `--delegate`, sealed under
   `store.sealing.transit` (ADR-0015: `url`, `mount`, `key` created `derived`, a Kubernetes-auth
   `role`, `token_file`), opened by the broker at the gateway's ask. The audience reads
   `{ via: delegated, inject: gateway, max_ttl: 300, egress: ["api.anthropic.com:443"], rules: ... }`.
   Switching the sealer from the local key file to transit invalidates the sealed sessions that
   exist (their holders log in again) and makes the `key_id` `transit:<mount>/<key>`. What transit
   protects, plainly: the `derived` key's context stops an envelope sealed for one claim opening for
   another; it does not stop a compromised broker, which supplies the context. The protections that
   hold against a stolen broker token are the key's non-exportability, a policy limited to encrypt
   and decrypt on that one key, a short token TTL on the role, the audit device, and rotation by
   rewrap. The federation end state (ADR-0032 decision 7, named the end state by ADR-0035) is a later
   source behind the same placement: a broker-signed JWT with a 300 second `exp`, its signing key in
   transit (`sign`, non-exportable), exchanged at the upstream's token endpoint for a short lived
   token. It is described here so the placement does not have to change; it is not built.

9. **The layers, in order from the workload to the upstream, and what each stops.** (1) The jail's
   Landlock and mount plan: the workload reaches the loopback proxy and nothing else. (2) The
   sandbox uid's nftables table (ADR-0020): no address but the proxy's. (3) The guest proxy: a
   non-phantom credential is refused, the rules are checked, nothing is fetched. (4) The firewall of
   the gateway: `INJECT_PORT` only for the sandbox range, under the per-source cap. (5) The claim
   SVID's mutual TLS at `envoy-inject`: no SVID, no connection; the peer is a claim, by its SAN.
   (6) `envoy-inject`: an exact authority list (no route, no request), normalised paths, headers
   it does not log (the per-claim limit is a placeholder, decision 5: not a layer yet). (7) The authorizer: the claim is live, the policy admits the audience, the rules
   match, the credential header is overwritten and any the client sent is removed. (8) The broker: the
   same checks again, the 300 second cap, the audit line. (9) The network: the datacenter's firewall
   lets only the gateways' routable addresses reach the audience's host and port (an external
   control, open question 4). (10) The upstream account: its own spend limit, the outer bound.
   Revocation is by retracting the claim SVID (the listener refuses the claim at once) and, at the
   latest, by the cache bound.

10. **The ADD cycle, in order, and where each piece lives.** (a) The spike on the pinned Envoy
    (open question 2), before any template. (b) CALM: the gateway node gains the `envoy-inject` process
    and listener, the broker the credential route (`mediatore`). (c) Tests first in `mediatore`:
    config validation (decision 1), the broker route and the `placed_at_gateway` refusal, the
    authorizer's inject check, cache and two sockets (a fake broker), the guest route and proxy
    dispatch (a fake gateway), the sandbox ruleset. (d) Broker route and config (`mediatore-api`,
    `mediatore`). (e) Authorizer (`mediatore-gateway`: inject mode, two sockets, cache,
    `OkHttpResponse` headers). (f) Guest (`mediatore-guest`: route, proxy dispatch, ruleset). (g) The
    Envoy templates, now three (relay, data plane, inject), in both places that render them:
    `image/gateway/envoy/` (`mediatore`) and `gateway/envoy/` with `scripts/deploy.sh` (the
    deployment's gateway repository): the `envoy-inject` unit and user, the listener, the clusters
    from `INJECT_ENDPOINTS`, the firewall port, the sockets and their groups, the SPIRE selector, the
    env keys, their tests. (h) The deployment's broker config and the OpenBao transit setup (key,
    policy, role attachment). (i) Docs. (j) The threat-model pass, which is what makes this ADR
    implemented.
    Stages (a) to (g), (i) and (j) exist in the repository; (h) and the live proof are the
    operator's (the egress allowance, the transit key and a release).

The next three decisions are what building it found; the numbering above is unchanged because the
code, the templates and the tests cite it.

11. **The only path to a gateway-placed host is the injecting one.** A placed audience's endpoint is
    removed from the claim's tunnel lists: from `Me.egress` and from the gateway's
    `ClaimEgress.egress`, and a policy's direct egress under `enforce` cannot bring it back (the
    broker removes placed endpoints after merging the direct entries). Without this the data plane's
    authorizer would still approve a `CONNECT` to the host for that claim: no credential is added on a
    tunnel, so nothing would leak, but the host would be reachable around the rules the inject
    listener enforces, and "bound to the one path that checks the rules" would be decoration. The
    inject routes travel in their own `inject` list (decision 2).

12. **A refusal by the gateway is marked, so the guest can tell it from the upstream's own 403.** Every
    denial the authorizer builds, on either socket, carries `x-mediatore-refusal: <code>` (the code is
    the refusal's stable name). The guest turns a response carrying it into `502 gateway_refused` and
    passes any other response, an upstream's own `403` or `503` included, through unchanged; an
    upstream that sets the header costs only its own response a different status. Envoy relays an
    authorizer's denied-response headers to the client: shown on 1.40.2 for `allowed_client_headers`
    with the HTTP-service `ext_authz` (the spike); the gRPC `DeniedHttpResponse` headers are still to
    confirm with the real authorizer (the integration proof, below).

13. **The pool VM's host table admits the inject port, for every uid.** The proxy dials the gateways'
    inject port as the sandbox uid, so a table that drops it (default-drop output, ADR-0029) would
    drop the request before the sandbox uid's own table mattered. `MEDIATORE_INJECT_PORT` in the
    guest's env (`/etc/mediatore-guest/env`) makes `image/host-table` admit each gateway at that port
    in the every-uid set, as the data port is; the port must be a number from 1 to 65535 or the table
    refuses to load, and unset admits nothing. It is not root-only like the registry leg, because the
    proxy is not root; the sandbox uid's per-claim table is the second layer and lists the port only
    for a claim that has a gateway-placed route. The deployment's layer carries its own copy of the
    host table (the image has no network at build time) and must be kept in step with this one.

## Consequences

- **Where the credential is now.** Held by the broker (as before), and by the authorizer and
  `envoy-inject` on a gateway VM for at most 300 seconds. No pool VM holds it, whatever the VM's
  state: root on a pool VM yields no credential for a gateway-placed audience, which closes
  ADR-0025's accepted residual for those audiences. The tunnel Envoy and the relay never hold it, and
  the authorizer's data-plane socket cannot return one. A compromised gateway VM yields the
  credentials of the live claims with a gateway-placed audience, each for at most 300 seconds, and
  it can ask the broker for any live claim's (it holds the gateway SVID): the blast radius moves from
  one pool VM's claims to every live gateway-placed claim, on three hardened VMs (ADR-0028
  decision 8) that run no sandbox code. The threat model records this as a new accepted risk with a
  revisit condition (the federation source).
- **The relay is untouched.** ADR-0027's control relay stays a separate process and user with no
  SVID, no credential and no TLS termination. `envoy-inject` originates TLS to a fixed list of hosts
  for its own listener only; the `CONNECT` path, and every tunnel on it, stays end to end, and no CA
  exists in any sandbox or on any gateway for the workload's traffic.
- **Failure modes, all closed.** Authorizer down: Envoy's `failure_mode_allow: false` gives `403` with no
  marker, which the guest passes through as a plain `403` (decision 12 marks only the authorizer's
  own refusals); the authorizer refusing gives `502 gateway_refused`. Broker unreachable and nothing cached: deny, no new
  credential; a cached one is used until its bound. An expired delegation: the broker answers
  `403` and the request is `403`; a claim cannot outlive its delegation (ADR-0035 decision 5,
  `delegation_expires_first`). An upstream `401` is returned to the workload; the next request
  re-asks once the cache entry has aged out. `envoy-inject` down: gateway-placed audiences fail,
  tunnels and the relay are unaffected.
- **Release lag.** A released claim loses its gateway credential within the cache bound (60
  seconds) of the authorizer's next broker ask, and sooner in practice because its claim SVID is
  retracted; the workload cannot reach the listener without it.
- **Rules are enforced at two places** for a gateway-placed audience, the proxy and the gateway;
  the gateway's decision is the one that counts.
- **Residuals named.** An upstream that echoes a credential in an error body would return it to the
  workload (Anthropic's API does not; an audience with such an upstream should not opt in).
  `ptrace_scope` and separate users keep the gateway's ops user from reading the authorizer's and
  `envoy-inject`'s memory; root on the gateway can. The `inject` listener is a new reachable port per
  gateway and a third Envoy process on it.

## Alternatives rejected

- **Keep the swap in the guest, as today.** The credential reaches every pool VM that runs a claim for
  the audience; the operator rejects that for the Anthropic credential.
- **The inject listener in the data-plane Envoy.** One fewer process, but the process that carries
  every tunnel would hold a credential in memory, and one `ext_authz` channel would serve both
  questions. The relay is already separate for the same reason.
- **A MITM CA in the guest** (or on the gateway for `CONNECT`). A certificate authority trusted by
  every workload, and a gateway that reads every tunnel: ADR-0028 decision 9's rejected shape.
  Origination to a fixed list, for an opt-in audience, reads only what it was asked to place.
- **A credential in the guest's memory for five minutes anyway.** Shorter exposure, same place; it
  does not answer "never reaches the pool VM".
- **A separate credential-injecting service in the cluster.** One more hop and one more identity
  that holds credentials, and the gateway already has the claim's mutual TLS, the policy decision
  and the allowlist in one process.
- **OpenBao as the injecting proxy.** OpenBao's transit engine encrypts and signs; it is not an HTTP
  proxy, and the claim's identity and policy are the broker's and the gateway's.
- **The jail dialling the gateway directly.** No SVID in the jail, so no way to authenticate, and
  the jail's reach grows from one loopback port to a network port.
- **Leaving a placed audience's host in the claim's tunnel lists.** The data plane would still approve
  a `CONNECT` to it, around the inject listener's rules (decision 11).
- **The authorizer in both Envoys' groups, or running as root, to `chgrp` its sockets.** It could then
  read their configuration, or everything; a setgid directory per Envoy gives each socket its group
  with no extra privilege (decision 6).
- **One socket directory for both sockets.** The directory is where each Envoy's access is decided, so
  a shared one lets the tunnel Envoy's group reach the inject socket; `check_layout` refuses it.
- **`inject` per endpoint of an audience.** More configuration for no gain once a placed
  audience is limited to one upstream's exact authorities (decision 1).

## What was proven, and what was not

Proven by tests in this repository (each a pinned unit, integration or shell test):

- The configuration and its refusals: `crates/mediatore/src/config.rs` (`inject_defaults_to_proxy_and_a_proxy_audience_is_unchanged`,
  `gateway_placement_needs_gateways_and_the_inject_port`, `max_ttl_is_capped_at_300_for_a_placed_credential`,
  `a_placed_credential_needs_a_host_name_to_verify_not_an_ip_literal`, and the exact-entry, one-upstream and rules cases).
- The broker route, the `placed_at_gateway` refusal, the policy admission, the audit line, the routes
  and the tunnel exclusion: `crates/mediatore-api/src/lib.rs` (the new tests, among them
  `only_the_gateway_identity_may_ask_and_a_refusal_never_carries_the_credential`,
  `under_enforce_the_claims_bundle_must_admit_the_audience`,
  `each_issue_is_one_audit_line_with_claim_audience_subject_backend_and_expiry_and_never_the_credential`,
  `a_placed_audiences_host_is_not_in_the_tunnel_lists_only_the_injecting_path_reaches_it`).
- The authorizer: `crates/mediatore-gateway/src/{lib,serve}.rs` (the inject check, the cache bounds and
  coalescing, the empty-credential refusal, the two sockets, the layout, the modes, the marker, the
  credential absent from every log line, and a real gRPC client over a unix socket).
- The guest: `crates/mediatore-guest/src/{egress,net}.rs` (origin form, no credential, SSE, failover,
  the refusal marker, the start-time refusals, the ruleset with and without the inject port).
- The host table: `image/host-table-test.sh` (the inject port admitted and refused when malformed).
- The templates: `make gateway-render-check` in this repository, and, in the deployment's gateway
  repository, its render tests (off by default byte for byte, no header handling at route level, the
  normalisation settings, the unit, the sockets, the SPIRE entry).
- On the pinned Envoy 1.40.2: the spike (TESTING.md T-61: overwrite of a client's header, the route
  and virtual-host removal stripping the authorizer's header, the deny relayed, exact authority
  matching) and `envoy --mode validate` accepting all four rendered bootstraps (the inject and the
  data-plane one, in each repository).

Not proven, said plainly:

- The gRPC `OkHttpResponse` and `DeniedHttpResponse` header behaviour on a non-`CONNECT` route with a
  real Envoy and the real authorizer: overwrite, removal, the order of the two, and the marker
  reaching the client. The spike used an HTTP-service `ext_authz`. This is the integration proof.
- The per-claim limit (decision 5): a placeholder, not a mechanism.
- Server-sent events through the listener with its idle and stream timeouts, against a real upstream.
- The live path: the egress allowance to the upstream, the OpenBao transit key, a release carrying
  this change on the gateways, the guest image and the broker, and a claim end to end.

## Open questions

1. **Source.** Delegated session now, federation later (decision 8). Two things only the operator
   can answer: whether the upstream accepts a subscription session placed from a gateway's address
   (ADR-0035 notes sessions are bound to Claude's own harnesses; a placement the harness does not
   make may be refused or against terms), and whether refresh-token rotation by the broker could
   invalidate the user's own CLI session. Also whether a workload-identity-federation path exists for
   the organisation.
2. **Envoy behaviours still to prove.** The spike and `envoy --mode validate` settled the HTTP-level
   behaviours (decision 4, and the section above). Still to prove, with the real authorizer and a
   real Envoy in an integration test before the path is switched on: that a gRPC `ext_authz`
   `OkHttpResponse.headers` with `OVERWRITE_IF_EXISTS_OR_ADD`, and `headers_to_remove`, behave the same
   on a non-`CONNECT` route; that a `DeniedHttpResponse`'s headers (decision 12's marker) reach the
   client; the mechanism for the per-claim limit (decision 5); and streaming through the listener
   with its idle and stream timeouts.

3. **Transit specifics.** Whether the transit mount and a `derived`, non-exportable key exist, and
   whether the existing Kubernetes-auth role's policy covers encrypt and decrypt on that key alone,
   with a short token TTL (the operator, with the OpenBao owners).
4. **Egress from the gateway.** The gateways cannot reach the audience today (Context). Either a
   datacenter firewall allowance for the gateways' routable addresses to the audience's host on 443,
   by name or the vendor's published ranges, or a corporate proxy that `envoy-inject` tunnels
   through (a `CONNECT` upstream in its cluster, a change to the template). The operator says which
   exists.
