<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0027: A sandbox reaches the identity plane only through a control relay on the egress gateway

**Status:** Accepted, implemented 2026-11-04 (decisions 4, 6, 7 and 8 in code; 1, 2, 5 and
9 in the gateway image) · **Date:** 2026-10-30 · **Amended:** 2026-11-07 by
[ADR-0031](0031-a-trust-anchor-that-outlives-the-servers-ca.md) (decision 3: the bundle the
agent starts with is the PKI root the server's CA chains to, good for years, not the
server's CA of the day)

Roadmap 10. Amends [ADR-0028](0028-egress-gateway-envoy-with-spiffe-identity.md) decisions 4
and 6 (what the gateway carries, and whether the sandbox reaches the broker directly),
[ADR-0009](0009-kubernetes-orchestrates-vms-run-agents.md) decision 4 ("sandboxes reach only
mediatore and the egress gateway") and [ADR-0020](0020-jail-network-nftables-keyed-by-sandbox-uid.md)
decision 3 (the ruleset's scope). Composes with
[ADR-0025](0025-phantom-token-egress-proxy.md) (the loopback proxy and where the claim SVID
is held). Changes nothing about the identities of [ADR-0004](0004-spiffe-identity-scheme.md),
the TPM attestation of [ADR-0018](0018-tpm-attestation-with-the-spiffe-plugin.md) or the
segment of banlieue
[ADR-0109](https://github.com/firestoned/banlieue/blob/main/docs/adr/0109-isolated-sandbox-network-with-proxy-egress.md).

## Context

A sandbox gets its claim identity in three steps that already exist: the SPIRE agent on the
VM attests with the vTPM to a SPIRE server (ADR-0018), `mediatore guest` registers the node
with the broker over the node SVID (ADR-0007, ADR-0019), and the broker creates the claim's
registration entry on `Bound` so the agent issues `spiffe://<td>/banlieue/claim/<claim-uid>`
(ADR-0004, ADR-0006). Every one of them is a connection from the VM to something that is not
the gateway: the SPIRE server (TCP 8081) and the broker.

The network says the opposite. banlieue ADR-0109 decision 1 makes the sandbox segment layer 2
only, with no route anywhere, so that "a sandbox can reach exactly two things: other members
of its own segment, and the proxy VMs". The gateway does not forward (ADR-0028 decision 8),
and the segment has no resolver. ADR-0028 decision 6 nevertheless lists "the broker" as a
destination the sandbox's ruleset admits directly, which no route can provide, and decision 4
makes the gateway refuse every peer that is not under `/banlieue/claim/`, so the node SVID
could never pass it either. There is also a circle: the forwarder learns the gateways'
addresses from `GET /v1/me` at the broker (decision 6), and cannot reach the broker without a
gateway.

This was measured on 2026-10-30, on the first gateways and a sandbox pool built to the
ADRs above. A pool VM has one NIC and a default route to a gateway that does not forward, so
its SPIRE agent has nowhere to attest. The outbound path was proven end to end only with a
hand-minted claim certificate. The identity steps, the gateway and the segment each hold on
their own; nothing joins them.

Two designs were considered first and are not the answer. Delivering a certificate and key
through `guestinfo` puts a private key in the VM's configuration in the hypervisor, readable
by anyone with that access and by guest root (ADR-0009's follow-on: guest configuration
carries no secrets). Routing the segment to the SPIRE servers and the broker contradicts
ADR-0109 and turns "no inbound, no route" from a topological fact into a firewall rule.

## Decision

Defense in depth: the path is narrow at the network, split at the process, authenticated by
the thing at the far end and not by the relay, bounded in rate, and short-lived in the
credential it produces. No layer is relied on alone.

1. **The gateway carries two planes, on separate listeners and separate processes.**
   - The **data plane** is ADR-0028's: one listener, mutual TLS, claim SVIDs only, CONNECT to
     an allowlist. It is unchanged. In particular the claim-only peer check stays exactly as
     strict as ADR-0028 decision 4 made it, and a node SVID still cannot use it.
   - The **control plane** is new: a relay that carries the three bootstrap connections and
     nothing else. It runs as its own systemd unit under its own user, **with no SPIRE
     socket, no SVID and no credential of any kind**, so a compromise of it, or of the data
     plane's Envoy through the attacker-controlled requests it parses, yields neither the
     other's position nor an identity to use.

2. **The relay has fixed destinations and the client chooses none.** One listener per
   upstream on the `sandbox` address, each an L4 pass-through (`tcp_proxy`) to one static
   cluster: the SPIRE server's attestation port, and the broker. No CONNECT, no authority
   from the client, no name resolution on behalf of the sandbox. A new upstream is a new
   listener and a reviewed change to the gateway's cloud-config, never a parameter. The
   listener ports are configuration (defaults 3129 and 3130), the upstream addresses are
   per environment, and neither is a secret.

3. **Authentication stays end to end, at the far side.** The relay adds no trust and sees
   only ciphertext.
   - The SPIRE leg: the agent verifies the server's SVID against the trust bundle and the
     server verifies the vTPM's endorsement key against its EK CAs (ADR-0018). The agent's
     `server_address` is the gateway's `sandbox` address and the relay's SPIRE port, so the
     VM needs no resolver. The bundle the agent starts with is the image's
     (ADR-0018 decision 3); later rotations arrive over the attested channel. An image
     whose bundle shares no root with the server's fails closed and needs a rebuild; since
     ADR-0031 that bundle is OpenBao's PKI root and the server's CA an intermediate under
     it, so a layer stays good for the root's life and not for one `ca_ttl`.
   - The broker leg: mutual TLS with the node SVID, end to end through the relay, exactly as
     ADR-0007 specifies. The broker's gateway-only route of ADR-0028 decision 4 is a
     different route (the gateway's own SVID); this one is the node's.
   - A compromised or malicious relay can drop, delay or observe the metadata of
     connections. It cannot attest as a node, mint a claim identity or read a token.

4. **The gateways' addresses reach the guest from the pool, not from the broker.** The
   circle in the Context is broken by a bootstrap list: the three gateways' `sandbox`
   addresses and ports are written into the guest by the pool's cloud-config
   (`/etc/mediatore/gateways`; addresses are not secrets). `GET /v1/me` keeps its
   `gateways` field as the authoritative list for the data plane (ADR-0028 decision 7) and
   may disagree with the bootstrap list; the guest follows `/v1/me` once it has it.

5. **The gateway host admits the control and data ports and nothing else on the sandbox
   NIC, with a per-source cap.** An `nftables` input chain on the gateway, default drop for
   the sandbox interface, accepting only established traffic and the listeners' ports. A
   per-source connection count (`ct count over <n>`) bounds one sandbox's use of the relay,
   since the control plane cannot rate-limit by identity: it has none to see. This replaces
   the cgroup filter and service masking added on 2026-10-30, which stay until the table is
   proven, as the stopgap they are.

6. **The sandbox's own ruleset narrows by every uid, not only the sandbox uid.** ADR-0020
   decision 3 filters the `sb-` uid and leaves root-level rules to the image. For the
   segment interface the image adds: output to the gateways' `sandbox` addresses on the
   data and control ports and to the segment's neighbours' none, for every uid. Guest root
   can flush this table (ADR-0010 decision 4), so it is a second layer; the first is that
   the segment has no other route and the gateway carries only what decisions 1 and 2 name.
   The broker leaves ADR-0020's list of direct destinations: it is reached through the
   control relay at the gateway's address.

7. **The claim's identity is short-lived and tied to the claim's life.** The registration
   entry the broker writes on `Bound` carries an explicit `x509_svid_ttl` of no more than 15
   minutes (the value is configuration, and never exceeds the time left to the claim's
   deadline), and is deleted on release, expiry or a failed group gate (ADR-0006). Renewal
   rides the same control path, so a gateway outage ends a sandbox's identity within one
   TTL (fail closed). The data plane's `ext_authz` check against live claim state
   (ADR-0028 decision 4) refuses a released claim even while its certificate is still valid.

8. **The claim SVID's key is held where ADR-0025 put it.** The loopback proxy of ADR-0025
   fetches the claim SVID from the Workload API as the `sb-` uid, outside the jail, and is
   the only process that holds it. This ADR makes that process the data plane's client as
   well: `mediatore forward` (ADR-0028 decision 3) is a role of the same process, not a
   second listener, so the workload gets one loopback port (3128 by ADR-0025) and neither
   an identity nor a socket to one. The forwarder's upstream dial is a CONNECT to the
   gateway, where ADR-0025 dials the upstream directly. The vTPM binds the **node**, through
   attestation; SPIRE's agent holds SVID keys in memory or on disk, never in the TPM, and
   this ADR does not change that.

9. **Every layer is visible.**
   - Control relay: one line per connection (time, sandbox source address, upstream,
     bytes each way, duration). No identity exists to log, and nothing is read.
   - SPIRE server: its own log of attestations and refusals, which is where a rogue agent
     shows up.
   - Data plane: ADR-0028 decision 8's per-tunnel line, keyed by claim.
   - Alert on: control connections from a source with no attested node, a source over its
     connection cap, an attestation refused, and a 403 burst from one claim.

## Implementation notes

What roadmap 10 fixed within the decisions above, as it is built:

- **The relay is a second Envoy** (decisions 1, 2 and 9), `envoy-relay.service` in the
  gateway image (`image/gateway/`), as user `envoy-relay`, on the bootstrap
  `image/gateway/envoy/relay.yaml.in`: two `tcp_proxy` listeners on the sandbox address,
  3129 to the SPIRE server and 3130 to the broker, each a static cluster by address from
  the deployment's env file, no TLS context, no SDS, no admin block, one access-log line per
  connection (source, upstream, bytes each way, duration, flags). Its unit keeps `/run/spire`
  inaccessible, so the mount namespace enforces "no socket" beside the file modes, and it
  needs no agent to start: it runs before any identity on the VM exists.
- **The host table is `image/gateway/nftables.conf.in`** (decision 5), rendered and loaded
  by `mediatore-gateway-nft.service` before either Envoy may start: input policy drop,
  loopback and established traffic accepted, on the sandbox interface the data port and the
  two relay ports for new connections only, a new relay connection counted per source in a
  dynamic set and dropped past `RELAY_CAP` (16 by default) with a `cap:` log line, nothing
  new on egress, the forward hook dropped. It replaces the cgroup filter and the masking of
  2026-10-30 on the next image.
- **The bootstrap list is `/etc/mediatore/gateways`** (decision 4), one `host:port` per line
  with `#` comments, written by the pool's cloud-config layer
  (`image/cloud-config-deployment.example.yaml`); `mediatore guest` reads it
  (`--gateways-file`, `net::bootstrap_gateways`) and uses it when `GET /v1/me` lists no
  gateway, the broker's list otherwise, logging which (`net::choose_gateways`). A line that
  is not an endpoint refuses the claim: a list the pool wrote wrong is better refused than
  silently shortened.
- **The broker leg and the SPIRE leg are addresses** (decision 3): the pool's
  `MEDIATORE_URL` is `https://<a gateway's sandbox address>:3130` and the agent's
  `server_address` the same address with port 3129. With gateways the sandbox ruleset
  admits the broker's address and port as the one the relay has, resolves nothing and
  carries no DNS rule (decision 6, ADR-0028's implementation notes); a broker given by name
  in that shape is refused at the guest before the claim starts. The agent's failover
  between gateways stays as *Still to decide* says.
- **`x509_svid_ttl` is at most 15 minutes and never more than the claim has left**
  (decision 7): `spire.entries.claim_svid_ttl` defaults to `15m` and the broker refuses a
  larger value or one that is not a duration at start (`EntriesSection::claim_svid_ttl`,
  `mediatore_spire::MAX_CLAIM_SVID_TTL`); on `Bound` the entry carries the smaller of that
  bound and the claim's own TTL, in seconds (`KubeEntryManager::claim_svid_ttl`,
  `Reconciler::bind`). The admission policy's `4h` ceiling stands as the outer bound for
  any entry.

## Consequences

- **A sandbox can finally get a real claim identity.** The path from a pool VM to the SPIRE
  server and the broker exists, narrow, and carries no credential of its own. The
  hand-minted certificate of the 2026-10-30 proof is no longer needed to test the data
  plane, and the control path becomes testable from a pool VM.
- **The gateway grows a second surface on the most hostile segment in the system.** It is
  smaller than the first (no TLS termination, no parsing, fixed upstreams, no credentials)
  and is deliberately a separate process. It is still a new thing an unauthenticated sandbox
  can connect to, bounded by the per-source cap and by what the SPIRE server and the broker
  do with an unauthenticated connection, which both already must handle.
- **The SPIRE servers and the broker are now reachable from every sandbox's relay.** The
  network team's firewall on them should admit the three gateways' `egress` addresses on
  these ports and nothing from the sandbox range. A deployment requirement, like the one in
  ADR-0028, and not something this ADR builds.
- **The gateways are now an identity-plane dependency.** All three down means no new sandbox
  attests, and a running one loses its identity within one TTL. That is the cost of decision
  7, accepted for the same reason ADR-0028 accepted the broker's dependency: closed beats
  open. The agent holds one `server_address`, so unlike the forwarder (ADR-0028 decision 7)
  it fails over only when it restarts.
- **New code and configuration:** the control relay's unit, listeners and `nftables` table
  in the gateway cloud-config; `/etc/mediatore/gateways` and the agent's `server_address`
  in the pool's cloud-config; `x509_svid_ttl` on the entries in `mediatore-spire`; the
  forwarder as a dialer inside `egress-proxy` (`crates/mediatore-guest/src/egress.rs`); the
  per-interface rule in `crates/mediatore-guest/src/net.rs`.
- **Threat model and CALM:** a new boundary (the control relay), a new relation (sandbox to
  SPIRE and broker through it) and a changed assumption (ADR-0009 decision 4). The pass is
  owed when this is implemented.
- **Rejected:**
  - a certificate and key delivered through `guestinfo` (the key in the VM's configuration);
  - a route or SVI from the segment to the SPIRE servers and the broker (breaks ADR-0109
    decision 1);
  - the node SVID on the data listener (widens the claim-only check that gives ADR-0028
    decision 4 its meaning, and attestation happens before any SVID exists);
  - a SPIRE agent on the gateway that issues for sandboxes (the gateway would hold signing
    authority for every claim);
  - a SPIRE server or proxy on the segment (a second identity plane to attest and defend);
  - one listener and one process for both planes (a flaw in the HTTP/2 path would also hold
    the bootstrap path);
  - separate relay VMs for the control plane (a stronger isolation, not needed while the
    relay holds no credential; revisit if it ever must).

### Still to decide

- **How the agent fails over** between the three gateways when one is down: a restart by
  the guest's unit after N failures, or a local balancer on loopback. Measured 2026-11-05
  on the live run: with one gateway's relay stopped for ninety seconds the member's agent
  logged its synchronisation failing within forty seconds and recovered on the relay's
  restart, while the workload's requests kept flowing through another gateway's data
  plane the whole time (decision 1 holds: the planes are independent). The failover
  itself is still open.
- **The per-source cap** and the rate it implies, which depends on how many sandboxes
  start at once, and whether `ct count` is enough or a rate limit is also needed.
  Measured 2026-11-05: a member holds one connection to the relay's SPIRE port (the
  agent's stream) and none open to the broker port between calls, so the example's
  `RELAY_CAP=16` is an order of magnitude above need; a rate limit was not needed.
- **Whether the broker's node leg needs a second, separate listener** from the one the
  gateway's own SVID uses, or one listener that accepts both SVID shapes.
- **The bundle's age limit:** how often the image's bundle is rebuilt so a long-lived image
  still shares a root with the servers.
- **The `x509_svid_ttl` value,** against the SPIRE server's capacity at the renewal rate it
  implies for the pool's size.
