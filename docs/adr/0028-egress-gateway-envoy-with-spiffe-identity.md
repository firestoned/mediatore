<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0028: The egress gateway is Envoy, and it knows which claim is calling

**Status:** Accepted · **Date:** 2026-10-28 · **Amended:** 2026-10-30 by
[ADR-0027](0027-control-plane-relay-on-the-egress-gateway.md) (decisions 4 and 6: the
sandbox reaches the broker and the SPIRE server only through a control relay on the
gateway, not directly; the data plane stands)

Roadmap 10. Gives the egress gateway of [ADR-0010](0010-no-inbound-to-sandboxes.md)
decision 4 its software, its identity and its authorization. Amends banlieue
[ADR-0103](https://github.com/firestoned/banlieue/blob/main/docs/adr/0103-isolated-sandbox-network-with-proxy-egress.md)
decision 4 (the proxies run Envoy, not haproxy) and
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
flush the in-guest nftables table. banlieue ADR-0103 then fixed the shape of that
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

1. **The gateway is Envoy, on each of ADR-0103's three proxy VMs.** One `envoy` process
   per VM, as a dedicated non-root user. It replaces haproxy; nothing else about
   ADR-0103's VM shape changes (two interfaces, forwarding off, no sshd, the `sandbox`
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
   resolver-free as ADR-0103 decision 7 requires. This settles the first open item of
   ADR-0103.

8. **The gateway VMs are hardened as ADR-0103 decision 4 and this ADR require.**
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
    default route; `sandbox` second, written by the image, ADR-0103 decisions 4 and 6),
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
  environment is the broker's: one broker, one segment, one gateway set (ADR-0103).
- **Not yet:** `mediatore gateway`, `mediatore forward`, the ruleset change, the gateway
  image and VMs, the threat-model pass, which comes with the rest of the roadmap.

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
- **New code:** `mediatore forward` and `mediatore gateway` in `crates/mediatore`
  (libraries in `mediatore-guest` and a new crate for the authorizer), `Me::gateways`
  in `mediatore-proto`, the gateway route in `mediatore-api`, the ruleset change in
  `crates/mediatore-guest/src/net.rs`. A kustomize or image fragment for the gateway VM
  lives under `image/`. banlieue ADR-0103 gets an amendment; nothing else in banlieue
  changes.
- **Envoy's TLS stack decides what the sandbox leg can offer.** The broker's sandbox leg
  is X25519MLKEM768 only (threat model R-8's reference). The gateway offers it first if
  the pinned Envoy build supports it and says so in the access log; otherwise the leg is
  classical until it does, recorded as an accepted risk with that revisit.
- **Rejected:**
  - haproxy and `spiffe-helper` (SVID files on disk, no per-peer SPIFFE ID check in the
    stream, authorization by a second system);
  - haproxy as in ADR-0103 (no identity: one list for every claim);
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
- **The allowlist's cache bound** and the answer format between the authorizer and the
  broker, settled in the implementation's test plan.
- **The registration entries' selectors for the gateway workload** (the Envoy user on a
  gateway VM) and how the first entry is bootstrapped after the agent first attests.
- **The ML-KEM question above,** on the Envoy build chosen.
