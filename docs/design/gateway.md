<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# The gateway

What stands between the sandbox segment and the world. The sandbox VMs have no route and no resolver, so everything
they reach goes through an **egress gateway VM**. The authorizer is `crates/mediatore-gateway` (the `gateway` role of
the one binary); the Envoys, units and firewall are under `image/gateway/`. The guide
[Deploying](../guides/deploying.md) covers rolling gateways.

A gateway VM has two network interfaces: one on the sandbox segment (an address on that zone's layer-2 network, no
default route and no forwarding), and a routable one. Nothing is routed between them: a connection is accepted by one
process on the sandbox side and re-originated by another on the routable side.

## Four processes, each its own Linux user

The work is divided so the process that carries every tunnel never holds a credential, and the one that holds a
credential for one request never carries a tunnel. Each has its own user, its own SPIRE entry (where it needs an
identity) and a hardened systemd unit.

| Process | Unit | Port (on the sandbox address) | Identity | Does |
| --- | --- | --- | --- | --- |
| **Data plane** (Envoy) | `envoy-gateway.service` | 8443 (`DATA_PORT`) | the gateway SVID | accepts a claim's `CONNECT` over mutual TLS, asks the authorizer, relays the tunnel untouched |
| **Authorizer** (`mediatore gateway`) | `mediatore-gateway.service` | unix sockets (below) | the gateway SVID | answers each Envoy check; fetches per-claim answers and credentials from the broker |
| **Control relay** (Envoy) | `envoy-relay.service` | 3129 SPIRE, 3130 broker, 3131 bundle | none | three `tcp_proxy` legs to fixed upstreams (the registry leg removed by ADR-0063): the only path from the segment to the identity plane; credential-less and sees ciphertext only |
| **Inject** (Envoy) | `envoy-inject.service` | 3133 (`INJECT_PORT`) | the gateway SVID | terminates a claim's mutual TLS, originates TLS to a fixed host, and adds the credential the authorizer returned; shipped, and enabled only where an audience is `inject: gateway` |

## The tunnel path

A claim's egress proxy dials the data plane, presents its claim SVID, and sends `CONNECT host:port`. Envoy has already
required the client certificate and validated it against the trust bundle. It then asks the authorizer over gRPC. The
check carries what **Envoy fills from the verified connection**, never anything the client sent: the peer's URI SAN, the
method and the authority. The authorizer (`Authorizer::authorize`) answers allow only when:

- the peer is a claim identity of this trust domain, `spiffe://<td>/banlieue/claim/<uid>`;
- the method is `CONNECT` and the authority is `host:port` (one shape);
- the authority is in that claim's allowlist.

The allowlist comes from the broker's gateway-only route, `GET /v1/gateway/claims/{uid}`, asked over SPIFFE mutual TLS
with the gateway's own SVID, and is kept in a **bounded cache** of one list per claim UID. A refusal carries a stable
code, which the guest passes on. The broker's answer is the claim's audiences' endpoints, plus, under
`policy.egress: enforce`, its policy bundle's servable direct egress. A claim that is revoked or expired is refused
because the broker says so. Anything the authorizer cannot decide is a refusal.

## The inject path

For an audience with `inject: gateway`, the egress proxy sends the request in origin form to the **inject** listener
(port 3133) instead of tunnelling. The inject Envoy ends the claim's mutual TLS, asks the authorizer, **originates TLS to
the audience's host** (verifying its certificate by name, against the system store or a CA the operator names) and the
request leaves with the credential header the authorizer wrote.

The authorizer answers an inject check from its second socket:

1. it checks the peer is a claim identity and the host is one of the claim's placed routes, and applies the route's
   `rules` (method and path, without the query), in the authorizer as well as in the proxy;
2. it gets the credential from the broker, `POST /v1/gateway/claims/{uid}/credential` over mutual TLS (the broker answers
   the gateway identity alone, and runs the checks of `POST /v1/token` plus the policy admission);
3. it answers with the header and its value, which the inject Envoy writes into the request, overwriting anything the
   client put there.

The credential is held in a bounded cache keyed by claim. It stays for the **least** of 60 seconds, its own expiry less a
margin, and the claim's deadline, and a sweep every 10 seconds evicts the credentials of claims that have been released,
so it leaves memory within seconds of the claim's end. It is never logged: the type prints `[redacted]`, and the broker's
audit line names the claim, audience, subject, backend and expiry, never the value.

An empty credential, one for another audience, and one already expired are refused and kept nowhere. Every refusal on
this path carries `x-mediatore-refusal: <code>`, so the guest can tell the gateway's own refusal from the upstream's.

## What the broker hears of each decision

Each tunnel and inject decision about a claim is also reported to the broker (ADR-0062):
`POST /v1/gateway/decisions`, over the same mutual TLS as the ask, in batches every two seconds or of 256. A decision
carries the claim, `tunnel` or `inject`, the authority, the audience of a matched inject route, the verdict, the refusal
code and where the allowlist came from, and the batch carries the gateway's name (`--name`, `MEDIATORE_GATEWAY_NAME`, by
default the host name). The broker writes one `gateway decision` line for each and stores nothing, so its log alone says
which gateway carried a claim to which host.

The name is attribution, not authentication: every gateway's authorizer has the one identity. Reporting is never on the
decision's path: a decision is queued without waiting, a full queue (1024) drops and counts it, and a failed batch is
dropped, logged once per run of failures. The gateway's own decision line stays the complete record.

## The two sockets

The authorizer serves the data plane and the inject Envoy on **two unix sockets in two directories**, never one:

| Socket | Directory group | Served to |
| --- | --- | --- |
| `check.sock` | `envoy` | the data-plane Envoy; it refuses an inject-shaped question outright |
| `inject.sock` | `envoy-inject` | the inject Envoy; the only channel on which a credential is answered |

Each directory is `2750` (setgid), owned by the authorizer's user and one Envoy's group, so a socket created in it
inherits that group and no other local process can open it. A mode that gives access to others is refused, a stale socket
is replaced, and anything else at the path is refused. The flags are `--check-socket`, `--inject-socket` and
`--socket-dir-mode 2750`.

**The unit's hardening and the directory modes meet here.** The authorizer's unit sets `RestrictSUIDSGID=yes`, which
makes any `chmod` that sets a setgid bit fail with `EPERM`. The deployment's root step makes each directory at `2750`
before the authorizer starts, and `UnixSocket::bind` changes a directory's mode **only when it differs** (`dir_mode_differs`),
so the hardening stays on. (Found on the first live roll of the inject path, fixed in v0.2.9: an authorizer that always
`chmod`-ed crash-looped.)

## What is in `image/gateway/`

| Path | What |
| --- | --- |
| `envoy/gateway.yaml.in`, `relay.yaml.in`, `inject.yaml.in` | the three Envoy bootstrap templates |
| `systemd/` | the units, each its own user, no capability and a read-only root |
| `nftables.conf.in`, `network.in` | the gateway's own firewall: the sandbox filter, with a per-source connection cap, and the two interfaces |
| `render` | fills a template's placeholders from the env file; it refuses one left unfilled or a value that holds its delimiter |
| `env.example`, `env.inject.example`, `vm.env.example` | the settings, including `INJECT_HOST`, `INJECT_UPSTREAM_PORT` and `INJECT_DOMAIN` (the one upstream the inject Envoy may originate to; a second is a reviewed change to the template, never a parameter) and `INJECT_PORT` |
| `check.sh` | validates the rendered output; each unit also runs `envoy --mode validate` before every start |

Settings that must agree across the repository and the deployment: the broker's `gateways` and `gateway_inject_port`
(see [Configuration](configuration.md)), the gateway's `INJECT_HOST` and `INJECT_PORT`, the pool's
`MEDIATORE_INJECT_PORT` (so a pool VM's host table admits the port), and the SPIRE entries for each gateway user.

## What the gateway cannot do

- A **compromised gateway VM yields the credentials of every live gateway-placed claim** for the cache's bound, and,
  holding the gateway SVID, can ask the broker for any live claim's. The blast radius moves from one pool VM to a
  gateway; it is an accepted risk (threat model R-27), reduced by the division of processes above.
- The datacenter firewall's allowance for a gateway to reach an audience's host is an external control: where it is
  absent the path fails closed with a connect timeout.
- The per-claim request limit at the inject listener is a marked placeholder, not a mechanism (R-28).

## Rules this part keeps

- A tunnel or a credential is answered only to a verified claim identity of this trust domain.
- The tunnel Envoy and the relay never hold a credential; the inject Envoy holds one for one request.
- A credential leaves the gateway's memory with its claim, within seconds.
- Anything the authorizer cannot decide is a refusal.

## Read next

ADR-0027 (the control relay), ADR-0028 (the gateway), ADR-0030, ADR-0037 (the bundle leg), ADR-0038 (the registry leg, removed by ADR-0063),
ADR-0040 (placing a credential). Threat model TB-13 to TB-15 and TB-17, risks R-27 to R-29. Roadmaps 10 and 11.
