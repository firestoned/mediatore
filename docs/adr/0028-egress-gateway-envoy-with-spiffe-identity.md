<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0028: The egress gateway is Envoy, and it knows which claim is calling

**Status:** Accepted, implemented 2026-11-04 · **Date:** 2026-10-28 · **Amended:** 2026-10-30 by
[ADR-0027](0027-control-plane-relay-on-the-egress-gateway.md) (decisions 4 and 6: the
sandbox reaches the broker and the SPIRE server only through a control relay on the
gateway, not directly; the data plane stands)

Roadmap 10. Gives the egress gateway of [ADR-0010](0010-no-inbound-to-sandboxes.md)
decision 4 its software, its identity and its authorization. Amends banlieue
[ADR-0109](https://github.com/firestoned/banlieue/blob/main/docs/adr/0109-isolated-sandbox-network-with-proxy-egress.md)
decision 4 (the proxies run Envoy, not haproxy; amended there on 2026-10-28) and
[ADR-0020](0020-jail-network-nftables-keyed-by-sandbox-uid.md) decisions 2 to 4 (the
ruleset names the gateways, not the audiences' endpoints). Builds on
[ADR-0004](0004-spiffe-identity-scheme.md) (identities),
[ADR-0007](0007-broker-identity-and-spiffe-mtls.md) (SPIFFE mTLS),
[ADR-0014](0014-one-binary-roles-as-subcommands.md) (one binary, roles as subcommands) and
[ADR-0018](0018-tpm-attestation-with-the-spiffe-plugin.md) (TPM node attestation). Answers
the placement question left open by notaio
[ADR-0003](https://github.com/firestoned/notaio/blob/main/docs/adr/0003-bundle-distribution.md)
(the gateway's placement) only in part; see *Still to decide*. Does not decide credential
injection, which stays roadmap 07 and its own ADR.

## Context

ADR-0010 puts egress enforcement outside the guest, at a gateway, because guest root can
flush the in-guest nftables table. banlieue ADR-0109 then fixed the shape of that
gateway: three proxy VMs per environment, each with a routable `egress` interface and a
`sandbox` interface on a layer 2 segment, IP forwarding off, the proxy terminating the
sandbox's connection and opening a new one from its own address. It chose haproxy as a
TCP passthrough on SNI plus an HTTP forward proxy, with a default-deny allowlist held in
the image.

That design has no notion of who is calling. Every sandbox on the segment is the same to
the proxy, so the allowlist is one list for all of them, a change to it is an image
rebuild, and the proxy's log says an address drew a connection, not which claim. Three
facts make that too little for AgentSandbox:

- A claim's permissions differ per subject and per policy (notaio's profiles, grants and
  ceilings). One list per environment cannot express them.
- The workload already has an identity that names its claim:
  `spiffe://<td>/banlieue/claim/<claim-uid>` (ADR-0004), issued by the SPIRE agent on the
  VM to the `sb-` user. Nothing at the network edge uses it.
- ADR-0020 left DNS open for the sandbox uid, recorded as threat-model R-12 and accepted
  "until the egress proxy answers names itself". Only a gateway that resolves names for
  the workload can close it.

The software has to terminate mutual TLS with SPIFFE peer validation, take its own SVID
and the trust bundle from a local SPIRE agent with rotation, authorize each tunnel on the
caller's SPIFFE ID and the requested authority, resolve names itself, and leave room for
credential injection later. banlieue ADR-0100 already assumes the shape on the VM side: a
forwarder in the sandbox carries the subject's outbound connections to the gateway under
that identity.

## Decision

1. **The gateway is Envoy, on each of ADR-0109's three proxy VMs.** One `envoy` process
   per VM, as a dedicated non-root user. It replaces haproxy; nothing else about
   ADR-0109's VM shape changes (two interfaces, forwarding off, no sshd, the `sandbox`
   address fixed by the image, one environment per segment and proxy set).

2. **The gateway has its own SPIFFE identity.** Each gateway VM runs a SPIRE agent that
   attests through the VM's vTPM (ADR-0018), like every sandbox. Envoy takes its SVID and
   the trust bundle over SDS from that agent's Workload API socket (a local unix socket,
   no files on disk) and rotates without a restart. All three gateways hold
   `spiffe://<td>/gateway`, so a client verifies "a gateway of this environment" and not a
   particular VM. The registration entries are `ClusterStaticEntry` objects
   (ADR-0006), applied by the platform team with the agent's SPIFFE ID as the parent;
   the broker does not mint them, because a gateway is not a claim.

3. **The sandbox leg is mutual TLS carrying CONNECT.** A new role in the one binary,
   `mediatore forward` (ADR-0014), runs in the VM as the claim's `sb-` user, listens on a
   loopback port, and is the workload's only proxy (`HTTPS_PROXY`, `HTTP_PROXY` and
   `ALL_PROXY` point at it, set by the guest like the rest of the jail's environment). For
   each connection it fetches the claim SVID from the SPIRE agent, opens TLS 1.3 to a
   gateway presenting it, verifies the gateway's SVID is `spiffe://<td>/gateway`, and
   sends `CONNECT host:port`. Plain HTTP proxy requests are carried as `CONNECT host:80`
   by the forwarder, so the gateway sees one request shape. The TLS the workload speaks to
   its destination runs inside the tunnel, end to end. No certificate authority is
   installed in any sandbox and nothing is intercepted (decision 9).

4. **The gateway authorizes each tunnel on the caller's SPIFFE ID and the authority.**
   Envoy requires a client certificate, validates it against the trust bundle with the
   SPIFFE certificate validator, and refuses any peer that is not under
   `spiffe://<td>/banlieue/claim/`. The CONNECT is then checked through `ext_authz`
   against a local authorizer, `mediatore gateway` (the same binary, a second new role),
   which holds a short-lived, bounded cache of one answer per claim UID: the set of
   `host:port` pairs the claim may reach. A miss asks the broker over SPIFFE mTLS on a
   gateway-only route that accepts the peer `spiffe://<td>/gateway` and nobody else
   (ADR-0007). The broker answers from the same evaluation that decides which audiences
   the claim may mint tokens for: today `audiences[].egress` (ADR-0020 decision 2), and
   the notaio bundle when roadmap 04 and notaio M3 land. A released, expired or unknown
   claim gets `404`, and the cache entry is dropped on the answer. Broker unreachable and
   no cached answer is a deny. The cache never outlives the claim's deadline.

5. **The gateway resolves names, not the sandbox.** Envoy resolves the CONNECT authority
   on its own `egress` interface and connects from its own address. The sandbox has no
   resolver to ask and no use for one.

6. **The sandbox's ruleset names the gateways.** ADR-0020's table keeps its shape and
   changes its set: for the `sb-` uid, output is accepted to the forwarder's loopback
   port, to the broker, and to the three gateways' `sandbox` addresses and listener port;
   established and related traffic as before; everything else is logged and dropped. The
   per-audience destinations and the DNS rule are removed. `GET /v1/me` gains
   `gateways`, an ordered list of `host:port` (addresses, in the broker's config per
   environment), beside `egress`, which stays as the claim's allowed destinations for
   the audit log and for the broker's own answer in decision 4. The guest renders the
   ruleset from `gateways` plus the broker, and the forwarder dials them.

7. **A sandbox picks among the three by list.** The forwarder takes the list in `/v1/me`
   order, starts at a random position per connection, and tries the next on a connect or
   handshake failure. No DNS name, no floating address, no VRRP: the segment stays
   resolver-free as ADR-0109 decision 7 requires. This settles the first open item of
   ADR-0109.

8. **The gateway VMs are hardened as ADR-0109 decision 4 and this ADR require.**
   - `net.ipv4.ip_forward` and `net.ipv6.conf.all.forwarding` are 0.
   - Envoy's only listener is on the `sandbox` address and one port; nothing listens on
     `egress` and an input chain drops everything arriving there that is not
     established.
   - Envoy's admin interface is off, or on a unix socket in a directory only its
     user reads, never on a network interface.
   - The only services are Envoy, the SPIRE agent and `mediatore gateway`. No sshd.
     Break-glass is the hypervisor console under RBAC (ADR-0010 decision 2).
   - Envoy runs with `NoNewPrivileges`, no capabilities (the listener uses an
     unprivileged port), a private `/tmp` and a read-only root.
   - An access log line per tunnel: time, claim SPIFFE ID, claim UID, authority, verdict
     and reason, bytes each way, duration. Logged to the journal and shipped by the image's
     log forwarder. Never the payload, never a token.

9. **Phase one is identity, allowlist and audit. No interception.** Credential
   injection (roadmap 07) needs the gateway to read or rewrite requests, which means a
   certificate authority trusted by the workload or a per-API opt-in for known hosts. That
   is a different trust decision with its own ADR, and Envoy's filters (`ext_proc`, Lua,
   a credential-injection listener) leave room for it without a change to this one.

10. **The gateway is image content, owned by whoever runs the environment (banlieue
    ADR-0100, ADR-0097 decision 5).** A `VMImage` carries Envoy (version and checksum
    pinned), the SPIRE agent and TPM plugin (ADR-0018), the `mediatore` binary, and
    cloud-config layers that write the Envoy bootstrap, the units and the `sandbox`
    address. The three VMs are ordinary banlieue `VirtualMachine` objects with a
    two-interface `VMClass` (`egress` first, so it carries the static address and the
    default route; `sandbox` second, written by the image, ADR-0109 decisions 4 and 6),
    placed one per failure domain (banlieue ADR-0098), on a `tpmEnabled` class like every
    VM from now on. banlieue gains no kind, no field and no controller.

## Implementation notes

What roadmap 10 fixed within the decisions above, as it is built:

- **The gateway-only route is `GET /v1/gateway/claims/{uid}` on the sandbox listener**
  (decision 4), `claim_egress` in `crates/mediatore-api/src/lib.rs`. The listener's
  authorizer admits `spiffe://<td>/gateway` beside node and claim identities, exactly that
  id and nothing under it (`Naming::is_gateway`); which routes each identity may use stays
  the handlers' business, so a gateway on `/v1/me` or `/v1/token` is `403` like a node on
  this route. The answer (`ClaimEgress`, `crates/mediatore-proto/src/lib.rs`) is the claim
  uid, the claim's deadline and `egress`: the union of its audiences' `egress`, sorted and
  deduplicated, the one list `GET /v1/me` hands the guest, so the gateway and the ruleset
  never disagree. A claim the store does not know, one not yet bound (no deadline, so no
  identity for a tunnel to carry), one released or past its deadline is `404` alike: the
  authorizer needs one signal for "deny, and drop what was cached", and telling the cases
  apart would tell a caller which uids exist. This settles the answer format left to the
  test plan in *Still to decide*; the cache bound stays with the authorizer.
- **`gateways` is a top-level list in the broker's config** (decision 6), `host:port` pairs
  parsed like `audiences[].egress`, one listed twice refused at start, empty by default;
  `Me::gateways` carries it in that order and an old broker reads as an empty list. The
  environment is the broker's: one broker, one segment, one gateway set (ADR-0109).
- **The authorizer is `mediatore gateway`, in `crates/mediatore-gateway`** (decision 4),
  Envoy's external authorization service, on loopback. It speaks Envoy's own `Check` call
  over gRPC (`ext_authz` with `grpc_service`), the one place mediatore speaks gRPC, for a
  reason verified on Envoy 1.40.2 and not a preference: Envoy's HTTP mode copies the
  downstream request's method and target into the check, so for a tunnel the check is
  itself a `CONNECT`, and Envoy's own client then resets any `2xx` to it and strips a
  refusal's body. The gRPC check carries what Envoy verified and nothing the client sent:
  the peer's identity from its certificate's URI SAN (`source.principal`), the method and
  the authority (`request.http.method`, `request.http.host`). The decision: the peer must
  be a claim identity of the trust domain, the method `CONNECT` (decision 3: one shape),
  the authority `host:port`, and that pair in the claim's allowlist exactly, host names
  compared case-insensitively. An allow is `OK`; a refusal is `PERMISSION_DENIED` with a
  stable code (`not_a_claim`, `not_connect`, `bad_authority`, `not_allowed`, `claim_gone`,
  `broker_unreachable`, `broker_refused`), the same code as the `403` body the client gets;
  an unreachable authorizer is a refusal by `failure_mode_allow: false`. The cache,
  settling the bound left to the test plan: one answer per claim UID, used without asking
  for `--fresh-secs` (30), then refreshed; while the broker is unreachable the last answer
  stands in for a further `--stale-secs` (300) and then an outage is a deny; no answer is
  used past the claim's deadline; the broker's `404` drops the entry and denies; the broker
  refusing the gateway's own identity denies whatever is cached; at most `--max-claims`
  (4096) entries, the least recently used evicted; checks arriving together for one claim
  share one ask. The broker is asked over mTLS with the gateway SVID from the local
  Workload API, a client built per ask so a rotated SVID is used next, each ask bounded at
  five seconds. One log line per decision: claim UID, peer, authority, what served it and
  the verdict with its code; never a body, never a token.
- **Envoy's bootstrap is `dev/kind/gateway/envoy.yaml`** (decisions 1, 2, 4, 5 and 8), the
  one the gateway image will carry: no admin block; one listener on the sandbox side,
  TLS 1.3 only, X25519MLKEM768 offered first, the gateway's SVID and the trust bundle over
  SDS from the SPIRE agent's socket (the secret names are the gateway's SPIFFE ID and the
  trust domain, as the agent serves them), a client certificate required and its URI SAN
  matched against the claim prefix before any filter runs; `CONNECT` the only route, through
  `ext_authz` to the authorizer, then the dynamic forward proxy resolving the authority on
  Envoy's own resolver; one access-log line per tunnel keyed by the peer's SPIFFE ID with
  the authority, the status, the flags and the bytes each way. Envoy is the official image
  pinned by digest. The ML-KEM question is answered: the pinned build negotiates
  X25519MLKEM768 with a client that offers nothing else, which is what `mediatore-tls`'s
  client config does.
- **The forwarder is the egress proxy's dialer** (decisions 3 and 7, as ADR-0027 decision 8
  placed it): `crates/mediatore-guest/src/forward.rs`, no `forward` subcommand. The proxy
  of ADR-0025 already runs as the sandbox user outside the jail and is the one process
  holding the claim SVID, so the jail keeps its one loopback port and the proxy's upstream
  dial changes shape: when `GET /v1/me` lists gateways (the guest writes them beside the
  routes, `--gateways`), each upstream connection is TCP to a gateway, TLS 1.3 on the
  sandbox leg's configuration (`mediatore-tls`, X25519MLKEM768 only) presenting the claim
  SVID from the shared Workload API source and verifying the gateway as exactly
  `spiffe://<td>/gateway`, `CONNECT host:port`, and the upstream's own TLS inside the
  tunnel, end to end as decision 3 says. The list is walked in the broker's order from a
  random position per connection; a connect, handshake or transport failure, or no answer
  within ten seconds, moves to the next; a gateway's answer other than `200` is the
  environment's verdict and ends the attempt. The workload sees `502` with
  `gateway_refused` (the authorizer's code in the proxy's log) or `gateway_unreachable`.
  An empty list, an old broker or an environment with no gateway yet, dials the upstream
  directly as before, said once at start. The guest's ruleset admits the gateways beside
  what it admitted already; its reshaping (decision 6: the gateways in place of the
  audiences' endpoints, no DNS) is the roadmap's guest item. Proven with no Envoy in
  `crates/mediatore/tests/e2e_forward.rs` against a stand-in gateway on the production
  mTLS configuration, and in kind against the real one (`make kind-e2e-gateway`, the real
  proxy as a sidecar beside a workload with no socket).
- **The sandbox's ruleset has two shapes** (decision 6, amending ADR-0020 decisions 2 to
  4; `crates/mediatore-guest/src/net.rs`, `Shape`). With gateways, the sandbox uid reaches
  the broker, which is the control relay at a gateway's `sandbox` address (ADR-0027
  decisions 3 and 6), the gateways' data-plane port and the egress proxy on loopback, all
  by address, and nothing else: no audience endpoint and no DNS rule at all, since the
  proxy tunnels every upstream and the gateway resolves the name (decision 5). A broker or
  a gateway given by name in that shape refuses the claim before it starts: the segment
  has no resolver, so the proxy could never have dialled it. Without a gateway (an older
  environment, the dev loop, the kind tiers) the list is ADR-0020's: the broker, the
  audiences' endpoints resolved at load, the proxy and DNS to the VM's resolvers, and the
  proxy dials directly. The guest takes the gateways from `GET /v1/me`, or from the pool's
  bootstrap file `/etc/mediatore/gateways` when the broker lists none (ADR-0027 decision
  4, `--gateways-file`), and logs which. Decision 3's `HTTPS_PROXY`, `HTTP_PROXY` and
  `ALL_PROXY` are not set in the jail: the workload's proxy is ADR-0025's reverse proxy on
  `MEDIATORE_EGRESS_PROXY`, not a `CONNECT` proxy, and a `CONNECT` handler beside it would
  carry requests the audience's rules cannot see; that is a trust decision for roadmap 07
  if a workload ever needs a tool that speaks only `HTTPS_PROXY`.
- **The gateway image is `image/gateway/`** (decisions 1, 2, 8 and 10; ADR-0027 decisions
  1, 2, 5 and 9): the same Kairos base as the sandbox image (ADR-0023), Envoy's binary
  copied from the official image at the digest the kind tier runs, the one `mediatore`
  binary, the SPIRE agent and the TPM plugin, `nftables`, three service users (`envoy`,
  `envoy-relay`, `mediatore-gateway`), no sshd, forwarding off in `sysctl`
  (`image/gateway/sysctl/`). The bootstraps are templates in the image rendered at every
  unit start by `image/gateway/render` from two env files, the deployment's
  (`/etc/mediatore-gateway/env`: trust domain, ports, the relay's upstream addresses) and
  the VM's (`vm.env`: its sandbox address, delivered as the `VirtualMachine`'s `userData`,
  since the three VMs share the image and its layers, banlieue ADR-0109 decision 6);
  `dev/kind/gateway/envoy.yaml` is the data-plane template rendered with the tier's values
  and `make gateway-render-check` fails on drift, so the bootstrap proven in kind is the
  one the image carries. Units: `mediatore-gateway-network` (the sandbox interface, a
  networkd file in `/run`), `mediatore-gateway-nft` (the host table: default-drop input,
  the data port and the two relay ports on the sandbox interface only, a per-source
  connection cap on the relay ports with a dynamic set, nothing new on egress, forward
  dropped), `envoy-gateway` (the data plane, user `envoy`, `NoNewPrivileges`, no
  capability, `ProtectSystem=strict`, private `/tmp`, `--mode validate` before start),
  `envoy-relay` (the control relay, user `envoy-relay`, the same hardening,
  `InaccessiblePaths=/run/spire`), `mediatore-gateway` (the authorizer on loopback); both
  Envoys `Require` the table and the interface, so no listener exists without them.
  `image/gateway/check.sh` proves all of it inside the built image on every pull request
  (`make gateway-image-check`), as `image/check.sh` does for the sandbox image; the Build
  workflow publishes it as `ghcr.io/firestoned/mediatore-gateway`, signed and attested,
  and the release carries its `VMImage` and layers.
- **The VMs and the entries are `deploy/gateway/`** (decisions 2 and 10): the `VMImage`
  and a two-interface `VMClass` (`egress` first, on a routable class with the subnet's
  gateway and resolver; `sandbox` second, on the segment, no address from banlieue), three
  `VirtualMachine`s with the egress address in `networkOverrides`, the sandbox address in
  `userData` and a required anti-affinity across the `host` key, and two
  `ClusterStaticEntry` objects per VM, both `spiffe://<td>/gateway` under that VM's agent:
  `unix:user:envoy` for the data plane and `unix:user:mediatore-gateway` for the
  authorizer, since one entry's selectors are a conjunction. This settles the selectors
  item of *Still to decide*; the bootstrap of the first entry is the platform team reading
  the agent ID the SPIRE server logs when the gateway first attests. The relay has no
  entry. The network (the segment's VLAN on every host, the firewall on the three
  `egress` addresses and on the SPIRE server and the broker admitting them) is the
  deployment's, stated in the deploying guide; nothing in this repository can apply it.
- **Booted live on 2026-11-05** (roadmap 06's libvirt proof extended with the gateways,
  v0.2.0-rc.4 on a homelab cluster): three gateway VMs from the published image on an
  isolated libvirt network, a pool member behind them, one claim through the whole path.
  Observed, as the decisions say: the agents attested over their vTPMs and the two entries
  per VM gave Envoy and the authorizer the gateway SVID over SDS; the member registered
  through the relay; the proxy tunnelled every allowed request through a gateway as the
  claim, Envoy's access log named the claim's SPIFFE ID, the authority and the upstream,
  the authorizer answered `allow` from the broker and then from its cache at the fresh
  bound, a path outside the rules was refused at the proxy, and the release retracted the
  entry while the pool destroyed the member. Three defects of the never-booted image
  surfaced and are fixed in the change after the run: the agent's unit was the sandbox
  image's and required the pool's host-table unit, which a gateway does not have, so
  systemd never scheduled the agent, the authorizer or the data plane (the gateway now
  carries its own unit requiring the gateway's table); the sandbox interface's networkd
  file sorted after the base's DHCP catch-all and lost (rendered as `10-sandbox.network`
  now); and a Kairos guest reads no `network-config` from banlieue's seed, so the egress
  static address needs a stage in the VM's `userData` with banlieue's placeholders
  (`deploy/gateway/virtualmachines.yaml` carries it). `image/gateway/check.sh` pins the
  first two. Also learned: the host table drops ICMP, so `ping` is no liveness probe for a
  gateway; and the segment's host must serve what the segment reaches (the mirror)
  directly, since libvirt's isolated network rejects anything forwarded off the bridge,
  a container port mapping included. Threat model R-15 is revised accordingly.

## Consequences

- **Identity reaches the network edge.** Each tunnel is attributable to a claim, and
  revoking a claim (release, expiry, a failed group gate) stops new tunnels within the
  authorizer's cache bound and ends the SVID's usefulness at its own expiry, which the
  broker already bounds (ADR-0004).
- **R-12 closes in the design.** The sandbox uid can no longer query a resolver, so DNS
  is not a covert channel from the workload. What remains is the gateway's own
  resolution of an allowed authority, bounded by the allowlist, and the claim's name in
  the tunnel's authority, which is data the destination sees. Recorded in the threat
  model when this is implemented.
- **The gateway is a new trust boundary and the first component on both sides of the
  sandbox segment.** It holds a routable address and an SVID. Compromising it yields
  every in-flight tunnel and the ability to dial any destination its egress firewall
  allows. The mitigation that does not depend on Envoy is the network team's firewall on
  the three `egress` addresses, a second allowlist, listed as a deployment requirement
  and not as something this ADR builds.
- **The broker gains a route and a dependency.** A gateway-only listener or route, and
  the claim-egress answer. An outage degrades to cached answers, then to deny. New claims
  cannot egress while the broker is down, which is consistent with `/v1/token` already
  being a `503` that revokes nothing (ADR-0015).
- **New code:** the forwarder and `mediatore gateway` in `crates/mediatore` (the forwarder
  a module of `mediatore-guest` inside the egress proxy, per ADR-0027 decision 8, and a
  new crate for the authorizer), `Me::gateways`
  in `mediatore-proto`, the gateway route in `mediatore-api`, the ruleset change in
  `crates/mediatore-guest/src/net.rs`. A kustomize or image fragment for the gateway VM
  lives under `image/`. banlieue ADR-0109 gets an amendment; nothing else in banlieue
  changes.
- **Envoy's TLS stack decides what the sandbox leg can offer.** The broker's sandbox leg
  is X25519MLKEM768 only (threat model R-8's reference). The gateway offers it first if
  the pinned Envoy build supports it and says so in the access log; otherwise the leg is
  classical until it does, recorded as an accepted risk with that revisit.
- **Rejected:**
  - haproxy and `spiffe-helper` (SVID files on disk, no per-peer SPIFFE ID check in the
    stream, authorization by a second system);
  - haproxy as in ADR-0109 (no identity: one list for every claim);
  - identity by source address (addresses are drawn from a pool and recycled; an address
    names a VM, never a claim, and a malicious guest chooses its own);
  - a gateway in the cluster (ADR-0009 decision 2 and 4: the segment never routes to a
    cluster);
  - a gateway per claim or per VM (the point is one place outside the guest; a sandbox
    that could run its own gateway could skip it);
  - letting Envoy read the notaio bundle itself in phase one (it would need the claim's
    group binding, which only the broker has; see below).

### Still to decide

- **Does the gateway verify the notaio bundle itself?** notaio's model has every
  enforcing component verify the signed bundle and refuse downgrades. Here the gateway
  enforces the broker's evaluation of it, which keeps the claim-to-profile binding in
  one place but means the gateway trusts the broker. If notaio wants the gateway to be a
  verifier too, the authorizer links `sandboxpolicy-bundle` and the broker sends the
  claim's resolved binding with the answer. Decide with notaio ADR-0003's gateway item.
- **How the log leaves the gateway** (the platform's collector, a syslog target) and who
  reads it.
- ~~**The allowlist's cache bound** and the answer format between the authorizer and the
  broker, settled in the implementation's test plan.~~ Settled, see *Implementation notes*.
- ~~**The registration entries' selectors for the gateway workload** (the Envoy user on a
  gateway VM) and how the first entry is bootstrapped after the agent first attests.~~
  Settled, see *Implementation notes*: `unix:user:envoy` and `unix:user:mediatore-gateway`,
  two entries per VM, applied by the platform team against the agent ID the server logs.
- ~~**The ML-KEM question above,** on the Envoy build chosen.~~ Answered, see
  *Implementation notes*: Envoy 1.40.2 negotiates X25519MLKEM768.
