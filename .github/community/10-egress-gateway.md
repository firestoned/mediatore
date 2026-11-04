<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 10: Egress gateway (Envoy, SPIFFE identity)

**Status: done** (2026-11-03 to 2026-11-04; the live run on gateway VMs is roadmap 06's
proof, below). [ADR-0028](../../docs/adr/0028-egress-gateway-envoy-with-spiffe-identity.md)
(Accepted 2026-11-02, implemented 2026-11-04) and
[ADR-0027](../../docs/adr/0027-control-plane-relay-on-the-egress-gateway.md) (the control
relay, implemented the same day). Built: the `gateways` list on `GET /v1/me`, the
gateway-only route, the authorizer Envoy asks, Envoy's bootstrap, the forwarder inside the
egress proxy, the sandbox ruleset's reshaping, the gateway VM image with the data plane, the
control relay and the host table, the VMs' and entries' manifests, and the threat-model pass.
The gateway is what makes ADR-0010's "enforcement outside the guest" true, and what closes
threat-model R-12 (DNS from the jail).

Depends on roadmap 02 (SPIRE the VMs can attest to, with the TPM plugin, ADR-0018) and on
roadmap 06's image work (the VM image carries the SPIRE agent and the `mediatore` binary).
Runs on banlieue's proxy VMs and sandbox segment
([banlieue ADR-0109](https://github.com/firestoned/banlieue/blob/main/docs/adr/0109-isolated-sandbox-network-with-proxy-egress.md));
the segment and its VLAN must exist before the three VMs do. Roadmap 07 (credential
injection) builds on this and stays design-only.

- [x] ADR-0028 accepted (2026-11-02)
- [x] banlieue ADR-0109 decision 4 amended (haproxy to Envoy, 2026-10-28; this roadmap
      named it ADR-0103 until 2026-11-04, banlieue's number for a different ADR)
- [x] `mediatore-proto`: `Me::gateways`; broker config for the per-environment gateway list
      (`gateways`, 2026-11-03)
- [x] Broker: the gateway-only route answering a claim's allowed `host:port` pairs, peer
      `spiffe://<td>/gateway` only; `404` for a released, expired or unknown claim
      (`GET /v1/gateway/claims/{uid}`, 2026-11-03; a pending claim is `404` too)
- [x] `mediatore gateway` (ext_authz authorizer with a bounded per-claim cache; deny on no
      answer) (`crates/mediatore-gateway`, 2026-11-04; over gRPC, Envoy's HTTP mode cannot
      carry a CONNECT check) and Envoy's bootstrap (`image/gateway/envoy/gateway.yaml.in`,
      rendered for kind as `dev/kind/gateway/envoy.yaml` and proven there the same day)
- [x] `mediatore forward` (loopback proxy, claim SVID, mutual TLS, CONNECT, gateway list
      with random start and failover) (2026-11-04: a dialer inside `egress-proxy` as
      ADR-0027 decision 8 placed it, `crates/mediatore-guest/src/forward.rs`; the jail
      keeps its one loopback port and no subcommand was added)
- [x] Guest: the ruleset naming the gateways and the broker through the relay by address,
      the DNS rule and the audiences' endpoints removed in that shape, ADR-0020's shape
      kept without a gateway (amends ADR-0020 decisions 2 to 4; `net::Shape`, 2026-11-04);
      the pool's bootstrap list `/etc/mediatore/gateways` read when the broker lists none
      (ADR-0027 decision 4, `--gateways-file`). The jail's proxy environment stays
      ADR-0025's `MEDIATORE_EGRESS_PROXY`: `HTTPS_PROXY` to a `CONNECT` proxy would carry
      requests the audience's rules cannot see (ADR-0028's implementation notes)
- [x] ADR-0027 decision 7: the claim SVID's TTL at most 15 minutes and never past the
      claim's deadline (`spire.entries.claim_svid_ttl`, default `15m`, refused above;
      `KubeEntryManager::claim_svid_ttl`, 2026-11-04)
- [x] Gateway VM image: Envoy (pinned by digest, checked to run), SPIRE agent and TPM
      plugin, the `mediatore` binary, the bootstraps as templates rendered at every start,
      the units, forwarding off, no sshd, the `sandbox` address from the VM's `userData`
      (`image/gateway/`, `make gateway-image`, `make gateway-image-check` on every pull
      request, published as `ghcr.io/firestoned/mediatore-gateway`; 2026-11-04). With it
      ADR-0027's control relay (a second Envoy, its own user, no socket) and the host
      table with the per-source cap (decisions 1, 2, 5 and 9)
- [x] `ClusterStaticEntry` for `spiffe://<td>/gateway` per gateway VM: two per VM,
      `unix:user:envoy` and `unix:user:mediatore-gateway`, under that VM's agent
      (`deploy/gateway/clusterstaticentries.yaml`, placeholders; 2026-11-04)
- [x] Three gateway `VirtualMachine`s, one per failure domain, on a TPM class: the
      two-interface `VMClass`, the `VMImage` and the three VMs with the egress address in
      `networkOverrides`, the sandbox address in `userData` and a required anti-affinity
      on `host` (`deploy/gateway/`, rendered by `make manifests`; 2026-11-04)
- [x] Network: sandbox segment, VLAN trunked on every host of the zone (banlieue ADR-0109
      decision 3), firewall on the three `egress` addresses and on the SPIRE server and
      the broker admitting them: a deployment requirement, stated in the deploying guide
      with the ports; nothing in this repository applies it (2026-11-04)
- [x] Tests: unit (ruleset in both shapes and the bootstrap list, forwarder framing,
      authorizer cache and fail-closed, the TTL bound), kind e2e with Envoy and SPIRE
      through the real proxy (`make kind-e2e-gateway`), the forwarder's e2e against a
      stand-in gateway (`crates/mediatore/tests/e2e_forward.rs`), both rulesets accepted
      by a real `nft -c` on the build host, the gateway image built and checked
      (2026-11-04)
- [x] Threat model: full pass; R-12 revised, new boundaries for the sandbox leg to the
      gateway, the gateway to the world and the control relay (2026-11-04)
- [x] CALM `architecture.json` and the stack model carry the forwarder, the authorizer,
      the gateway route, the relay and the gateway as built (2026-11-04)

Left to a live environment, tracked by roadmap 06's libvirt proof: three gateway VMs
booted from the published image, a pool VM behind them reaching the SPIRE server and the
broker through the relay and its destinations through the data plane, and ADR-0027's open
items (the agent's failover between gateways, the cap's value, the bundle's age limit)
measured there.
