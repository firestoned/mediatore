<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# The egress proxy

The jail's only way out. The code is `crates/mediatore-guest/src/egress.rs` (the proxy) and `forward.rs` (how it
reaches an upstream through a gateway). It is the `egress-proxy` role of the one binary: **one process per claim, started
by the guest as the sandbox user, outside the jail**, listening on the VM's loopback.

The design problem it solves: the workload is hostile by assumption (a prompt-injected agent runs here), yet it must be
able to call authenticated APIs. So the workload never holds a credential. It holds a **phantom token**, useless anywhere
but at this proxy during this claim, and the proxy, which the workload cannot read or signal (it is outside the jail's
PID namespace and file view), places the real credential.

## What the workload sees

A base URL in `MEDIATORE_EGRESS_PROXY` (for example `http://127.0.0.1:18128`) and the phantom in `MEDIATORE_TOKEN`. To
call an audience it requests:

```
http://127.0.0.1:<port>/<host>[:<port>]/<path>      Authorization: Bearer <phantom>
```

The first path segment names the route: the host, with the port only when it is not 443. The proxy answers:

| Status | Code | Meaning |
| --- | --- | --- |
| `404` | `no_route` | the host is not one of the claim's routes |
| `403` | | the request is outside the route's rules (method and path) |
| `401` | | an `Authorization` that is not the phantom: the workload has no credential of its own for this layer to carry |
| `502` | `token_unavailable`, `upstream_unreachable`, `gateway_unreachable`, `gateway_refused` | the credential or the upstream could not be had; the last two are the gateway's |

A request with **no** `Authorization` is forwarded bare, which is how a route with no credential works. The proxy also
strips every header it owns on every route (the header a route places a credential in), so a workload cannot smuggle its
own copy past the swap.

## The routes

Each route is one host and port of an audience (or one entry of a policy's direct egress), with the audience's `rules`,
an optional CA, and how its credential is handled. `GET /v1/me` returns them and the guest writes them to a file of the
sandbox user's; the proxy reads that file at start. A request is judged by `judge_headers`: the route exists, the method
and path (without the query) are admitted by the rules, and any credential header is the phantom. Only then does anything
leave.

| `credential` on the route | The proxy |
| --- | --- |
| `token` | swaps the phantom for a token it fetched from the broker over the claim's identity (`POST /v1/token`), cached until shortly before expiry, then forwards to the upstream over TLS 1.3 |
| `none` | drops the phantom and forwards bare: a direct-egress entry of a policy, or an audience that mints nothing |
| `gateway` | **never asks for a token and holds none.** Strips the phantom and sends the request in origin form to a gateway's inject listener, which places the credential (below) |

## Reaching the upstream

How a request leaves depends on the environment (`Dialer`):

- **With gateways** (the case that matters): the proxy opens a tunnel through a gateway as the claim, `CONNECT host:port`
  over mutual TLS 1.3 with the claim's SVID, verifies the gateway presents exactly `spiffe://<td>/gateway`, and runs the
  upstream's own TLS inside the tunnel. A gateway's own `5xx` or a connection failure moves the forwarder to the next
  gateway; a `4xx` is the verdict and is not retried. A tunnel the gateway's authorizer refuses is `502` with the
  authorizer's code.
- **Without gateways**: the upstream is dialled directly, and the guest's firewall rules admit the audiences' endpoints.
- The proxy's own TLS to an upstream trusts the public roots, plus the route's CA when it has one, or the CA the guest
  hands it for hosts a policy lists (`--upstream-ca`), at a minimum TLS version of 1.3 unless the operator allows 1.2
  (`--upstream-min-tls`) for an upstream that has no 1.3.

### A gateway-placed route

For `credential: gateway` (ADR-0040) the proxy keeps the checks (the rules, the foreign-credential refusal) and then:

- strips the phantom and every credential header, so nothing a workload sent goes on;
- sends the request in **origin form**, `Host` the audience's authority (without the port when it is 443), over the claim's
  mutual TLS to a gateway's inject port (carried on the route), and streams the body and the response;
- fails over to the next gateway on a connection failure only;
- treats a response carrying `x-mediatore-refusal` as the gateway's own refusal and answers `502 gateway_refused`, while an
  upstream's answer is passed on unchanged.

The workload and the jail are untouched by any of it, and the sandbox uid's firewall table lists a gateway's inject port
only for a claim that has such a route. See [The gateway](gateway.md).

## The pull listener

When the claim's image is on a registry that is a gateway-placed audience (ADR-0043), the proxy binds a **second**
loopback listener, the pull port, beside the workload's, **before** it prints its ready line:

- it serves the **one registry host** the guest names, and nothing else (`not_the_pull_host` `404` for any other);
- it serves gateway-placed routes only (`not_placed` `403` if the route is not), so it never dials an upstream itself
  and never asks for a token;
- the guest's puller, as root, uses it with no credential; the request goes to a gateway as above.

The workload cannot reach this port: no jail rule lists it (see [The guest](guest.md)). The command-line options that add
it (`--pull-listen`, `--pull-host`) are appended by the guest only for such a claim (`pull_args`).

## Tripwires (ADR-0069)

Under `policy.traps` `shadow` or `enforce` the guest starts the proxy with `--trap-socket`. The proxy connects to the
guest's socket, is handed the claim's decoy routes and bait values once (`GuestToProxy::Arm`), builds its matcher, answers
`armed`, and only then prints its ready line; a proxy that cannot do all of that is not ready, and the claim does not
start under `enforce`. With no `--trap-socket` its arguments and behaviour are what they were.

Armed, it checks every request before anything leaves (`check_traps`, `trapmatch.rs`):

- **The head**, before any route is consulted or name resolved: a host that is a decoy route; bait in the method, the
  path, the query, any header's value (a Basic pair decoded) or any header's name, a trailer's included, as it is,
  upper-cased and lower-cased.
- **The body**, on a route whose audience is not `traps_body: skip`, streamed through a matcher that holds back one byte
  less than the longest pattern, so a complete bait value is never forwarded. A gzip or deflate body is decoded for the
  matcher within an expansion bound and forwarded as it came.

| Status | Code | When |
| --- | --- | --- |
| `403` | `trap` | under `enforce`: a decoy route, bait in the head, bait in a body whose response has not started (otherwise the upstream stream is reset), and every request after a trip, after the guest said it decided one, or after the trap socket closed |
| `404` | `no_route` | a decoy route under `shadow`, the same bytes an unknown host gets |
| `415` | `unsupported_encoding` | under `enforce`, a body in an encoding other than identity, gzip and deflate on a matched route; forwarded unscanned under `shadow` |
| `413` | `body_expansion` | under `enforce`, a compressed body past the expansion bound; forwarded under `shadow`; ends nothing |
| `400` | `body_undecodable` | under `enforce`, a body that does not decode in its declared encoding; forwarded under `shadow`; ends nothing |

Each use is told to the guest over the socket (kind, trap or class, host; never a value or a path), which decides what
it does by the mode. A request for a host that is no route is still `404 no_route` and is also told, as the `denied` class
`unknown_host`. A credential hit on a request that names no route is told and logged with the host `invalid`, never the
request's first path segment, and any host in which a bait value is found is told as `invalid`. When the guest decides a
trip of its own (a decoy port, a `denied` class) it writes `{"type":"tripped"}` on the socket before the cut, and the
proxy answers `403 trap` to everything from then on and stays up for the kill; a body already streaming flows until the
cut lands. If the socket closes the proxy answers `403 trap` to everything and exits, which ends the claim. The query
is in no log line, a request a trap matched logs no path, and a line that names a method names one of the nine
standard methods or `extension`. The response is not scanned, and the pull listener is
matched against no trap. See [Tripwires](../guides/tripwires.md).

## Running it

Before it reads or binds anything, `egress::run` closes every socket family but unix and inet to itself
(`seccomp::restrict_families`, `crates/mediatore-guest/src/seccomp.rs`; ADR-0049 decision 12): the family half of the
jail's seccomp policy ([ADR-0051](../adr/0051-socket-families-and-io-uring-denied-to-the-workload-by-seccomp.md)),
installed on every thread, irreversible, and proven on the spot by asking for a netlink and a vsock socket, which must
both fail with `EAFNOSUPPORT`. The proxy runs beside the jail as the sandbox user and parses what the workload sends, and
on a guest without a vTPM the host's signer answers whatever asks on the guest's vsock, so vsock is not a family this
process may hold. Only the family rule is taken, not the jail's type and protocol rules: on a pool without gateways the
proxy resolves names over UDP. It logs `address families restricted to unix and inet (seccomp, all threads)`; a filter
that does not load, or does not refuse, means no proxy and so no claim.

`egress::run` then reads the routes, the gateways and the phantom, refuses a listen address that is not loopback, obtains the
claim SVID from the Workload API (one source for the broker client and the gateway tunnels), builds the dialer, binds, and
prints one line, `ready <addr>`, on standard output. The guest starts the jail when it reads it. A failure at any step
exits before that line, which ends the claim before the workload runs.

The default listen port is 3128 (`DEFAULT_PORT`); `MEDIATORE_EGRESS_PROXY_PORT` moves it. The guest refuses a claim whose
broker or egress destination uses the proxy's port, whatever that port is (the workload's one allowed port would name
two destinations), so a deployment moves the port when the broker or an audience is served on 3128.

## Rules this part keeps

- A credential, when there is one, exists only in this process's memory, never in the jail, and for a gateway-placed route
  not here either.
- A request leaves only after the route, the rules and the credential check pass.
- A route the gateway places is never tunnelled, and never given a token instead.
- The proxy listens on loopback only.
- The proxy opens unix and inet sockets and no other kind, and does not start otherwise.

## Read next

ADR-0025 (the phantom token), ADR-0027 and ADR-0028 (the gateway and the tunnel), ADR-0030, ADR-0040, ADR-0043 and ADR-0069. Threat model
TB-7 (the proxy to a downstream), TB-12 (the jail to the proxy), TB-13 (the forwarder to the gateway), TB-17. Roadmap 07.
