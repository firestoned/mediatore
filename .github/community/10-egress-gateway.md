<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 10: Egress gateway (Envoy, SPIFFE identity)

**Status: in progress** (since 2026-11-03). [ADR-0028](../../docs/adr/0028-egress-gateway-envoy-with-spiffe-identity.md)
is Accepted (2026-10-28 proposed, accepted 2026-11-02) and the CALM stack model carries the gateway and the forwarder
as proposed nodes. Built: the `gateways` list on `GET /v1/me`, the gateway-only route, and
the authorizer Envoy asks. The gateway is what makes ADR-0010's "enforcement
outside the guest" true, and what closes threat-model R-12 (DNS from the jail).

Depends on roadmap 02 (SPIRE the VMs can attest to, with the TPM plugin, ADR-0018) and on
roadmap 06's image work (the VM image carries the SPIRE agent and the `mediatore` binary).
Runs on banlieue's proxy VMs and sandbox segment
([banlieue ADR-0103](https://github.com/firestoned/banlieue/blob/main/docs/adr/0103-isolated-sandbox-network-with-proxy-egress.md));
the segment and its VLAN must exist before the three VMs do. Roadmap 07 (credential
injection) builds on this and stays design-only.

- [x] ADR-0028 accepted (2026-11-02)
- [ ] banlieue ADR-0103 decision 4 amended (haproxy to Envoy)
- [x] `mediatore-proto`: `Me::gateways`; broker config for the per-environment gateway list
      (`gateways`, 2026-11-03)
- [x] Broker: the gateway-only route answering a claim's allowed `host:port` pairs, peer
      `spiffe://<td>/gateway` only; `404` for a released, expired or unknown claim
      (`GET /v1/gateway/claims/{uid}`, 2026-11-03; a pending claim is `404` too)
- [x] `mediatore gateway` (ext_authz authorizer with a bounded per-claim cache; deny on no
      answer) (`crates/mediatore-gateway`, 2026-11-04; over gRPC, Envoy's HTTP mode cannot
      carry a CONNECT check) and Envoy's bootstrap (`dev/kind/gateway/envoy.yaml`, proven
      in kind the same day)
- [ ] `mediatore forward` (loopback proxy, claim SVID, mutual TLS, CONNECT, gateway list
      with random start and failover)
- [ ] Guest: proxy environment for the jail, the ruleset naming the gateways and the
      forwarder, DNS rule removed (amends ADR-0020 decisions 2 to 4)
- [ ] Gateway VM image: Envoy (pinned version and checksum), SPIRE agent and TPM plugin,
      the `mediatore` binary, bootstrap and units, forwarding off, no sshd, the `sandbox`
      address in a cloud-config layer
- [ ] `ClusterStaticEntry` for `spiffe://<td>/gateway` per gateway VM
- [ ] Network: sandbox segment, VLAN trunked on every host of the zone (banlieue ADR-0103
      decision 3), firewall on the three `egress` addresses
- [ ] Three gateway `VirtualMachine`s, one per failure domain, on a TPM class
- [ ] Tests: unit (ruleset, forwarder framing, authorizer cache and fail-closed), kind e2e
      with Envoy and SPIRE (a claim reaches only its own allowlist, a released claim is cut
      off, a peer outside the claim path is refused, broker down is a deny after the cache).
      The authorizer's units and the kind tier (`make kind-e2e-gateway`, 2026-11-04, a
      stand-in for the forwarder) are done; the ruleset's and the forwarder's remain
- [ ] Threat model: full pass; R-12 revised, new boundary for the sandbox leg to the
      gateway and the gateway to the world
- [ ] CALM `architecture.json` gains the forwarder, the authorizer and the gateway route
      when they are built
