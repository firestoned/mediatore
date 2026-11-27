<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 10: Egress gateway (Envoy, SPIFFE identity)

**Status: done** (2026-11-03 to 2026-11-04; the live run on gateway VMs is roadmap 06's
proof, below); **reopened 2026-11-19** for ADR-0053 (the authorizer's own identity and the host
table's output chain: built, its items and its live proof at the end). [ADR-0028](../../docs/adr/0028-egress-gateway-envoy-with-spiffe-identity.md)
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
injection) builds on this: its proxy, built 2026-10-30, tunnels through these gateways.

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
      (`deploy/gateway/clusterstaticentries.yaml`, placeholders; 2026-11-04). Since
      2026-11-19 (ADR-0053, below) three per VM and two IDs: `gateway-NN-envoy` and
      `gateway-NN-envoy-inject` for `spiffe://<td>/gateway`, `gateway-NN-authorizer` for
      `spiffe://<td>/gateway/authorizer`
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

Added 2026-11-14 ([ADR-0037](../../docs/adr/0037-the-pool-fetches-its-spire-bundle-at-boot-through-the-relay.md)):

- [x] The relay's third leg (the SPIRE bundle endpoint on `RELAY_BUNDLE_PORT`, 3131) and the
      host table's port; the pool's boot-time fetch (`image/spire-bundle-fetch`,
      `spire-bundle-fetch.service`) and the host table's element for it, pinned by
      `make bundle-fetch-test`, `make host-table-test`, `make gateway-render-check`
      (2026-11-14)

Left to a live environment, with roadmap 06's libvirt proof: a gateway and a pool member
booted from images that carry the leg and the fetch, the relay's `upstream=bundle` line and
the member's `journalctl -u spire-bundle-fetch` recorded.

Added 2026-11-15 ([ADR-0038](../../docs/adr/0038-the-pull-reaches-the-operators-registry-through-a-fourth-relay-leg.md)):

- [x] The relay's fourth leg (the operator's registry on `RELAY_REGISTRY_PORT`, 3132, to
      `REGISTRY_ADDRESS:REGISTRY_PORT`) and the host table's port; `registries[].reach: relay`;
      the guest's mapping of a declared registry name to the gateway (`MEDIATORE_RELAY_REGISTRIES`),
      with manual redirects refused off the declared hosts; the host table's `registry4` set
      admitted to uid 0 alone; the jail's ruleset pinned not to list a leg, pinned by
      `make host-table-test`, `make gateway-render-check` and the guest's unit tests (2026-11-15)

Superseded 2026-11-22 by [ADR-0063](../../docs/adr/0063-the-image-pull-goes-through-the-claims-proxy-and-the-gateway-like-any-egress.md):
the leg was a path from a pool VM to a registry that no authorizer saw, and is removed; it was never
proven live.

Added 2026-11-15 ([ADR-0040](../../docs/adr/0040-the-gateway-places-an-audiences-credential-the-pool-never-holds-it.md)):

- [x] A third Envoy on the gateway (`envoy-inject`: the claim's mutual TLS in, TLS originated to a fixed host, its own user and SPIRE entry), the authorizer's second socket and the broker's credential route, so an audience's credential is placed at the gateway and never held by a pool VM; the guest's route to the inject port, the host table's `MEDIATORE_INJECT_PORT`, and a placed host removed from the tunnel lists (unit, e2e and render tests; `make gateway-render-check`, `make host-table-test`)

Left to a live environment: the integration proof on a real Envoy with the real authorizer, the per-claim limit, the gateways' egress allowance, the OpenBao transit key and a release (threat model R-28, R-29).

Added 2026-11-19 ([ADR-0053](../../docs/adr/0053-the-gateways-authorizer-has-an-identity-of-its-own.md)):

- [x] The authorizer's own identity, `spiffe://<td>/gateway/authorizer`: `Naming`, the SVID selected by path and required at start, the broker's two gateway routes answering it alone and the listeners' ID no longer a peer of the broker, the transition switch `accept_plain_gateway_identity` (off by default), the audit line naming the peer (2026-11-19)
- [x] The admission policy for gateway entries (`deploy/base/admission/clusterstaticentry-gateway.yaml`) and the entries' new shape, three per VM (2026-11-19)
- [x] The gateway host table's output chain keyed on the socket's owner, with `EGRESS_DENY_ELEMENTS`, `CHECK_TCP_ELEMENTS` and `RESOLVER_ELEMENTS`, and the `MEDIATORE_URL` guard on the authorizer's unit; asserted by `make gateway-render-check` and `make gateway-image-check` (2026-11-19)
- [x] A connection on the sandbox listener ends at its peer certificate's `notAfter` (2026-11-19)
- [x] Tests: unit and end to end in `make check`; the kind gateway tiers with two identities on the pod, the listeners' identity refused by the broker and the admission dry runs (2026-11-19)
- [x] Threat model: full pass; A-28 new, R-20 and R-27 narrowed, R-48 to R-51 new (2026-11-19)
- [x] The tunnel check on the unix socket by default, which removes the loopback exception (ADR-0053 open question 7; built 2026-11-26, the image check green; seen on one booted gateway 2026-11-27: the check directory `2750` with the group `envoy`, the socket `0660`, a claim's tunnels decided by the authorizer listening on it)
- [ ] The output chain's default policy moved to `drop`, once a booted gateway has given the list of users that open a connection (open question 4)
- [ ] The transition switch removed, the release after the one that ships it
- [ ] Per-gateway identities and binding a credential ask to the gateway serving the claim: an ADR of its own (decision 8)

- [x] One gateway VM booted from the image under the new entries, behind a broker with the transition switch off, and one claim through a tunnel: the authorizer on its own ID, the output chain loaded with every user resolved, the agent, the relay and the resolver working under it, nothing legitimate dropped (2026-11-27; ADR-0053, *Shown on a booted gateway, 2026-11-27*)
- [x] The two boot faults that run found, fixed in the image's files and not yet booted: the agent's socket directory optional in `ReadOnlyPaths=` on the authorizer's and the tunnel Envoy's units and no start limit on the authorizer's, asserted by `image/gateway/check.sh`; the inject drop-in written in the example cloud-config's `initramfs` stage (2026-11-27)

Left to a live environment: the rest of ADR-0053's condition. A refused destination attempted as each Envoy's user and the drop seen counted, a name made to resolve into the refused set (`503`), the migration walked in each direction, a claim through the inject listener, three gateways, and which certificate validator Envoy runs (ADR-0053, *What was proven, and what was not*; threat model R-48, R-51). Until then the output chain is shown to load and to pass what a gateway needs on one VM, and its refusals are built and not verified.

Added 2026-11-22 ([ADR-0063](../../docs/adr/0063-the-image-pull-goes-through-the-claims-proxy-and-the-gateway-like-any-egress.md)):
no workload path goes around the gateway, the image pull included, and each namespace pulls only from the
registries it was granted.

- [x] ADR-0063 accepted, its open questions answered (the cost measured on kind: under 3% against a direct fetch,
      the proxy streams a 4 GiB layer in 3.4 MiB); CALM updated
- [x] The pull bounded: a 10 s connect, `MEDIATORE_PULL_IDLE_SECS` and `MEDIATORE_PULL_DEADLINE_SECS` (decision 9)
- [x] `audiences[].role: registry` with read-only rules; `registry_not_granted` at the front door and the
      reconciler; `registries[]` refused with `gateways` (decisions 2 and 4)
- [x] Pull-only routes: left out of the jail's egress, `404 pull_only` to the workload, served by the pull listener
      over a tunnel or the inject port; every gateway-era pull through the claim's proxy (decisions 1, 3 and 5)
- [x] The relay's registry leg removed (three legs), the gateway's table without a registry address, the pool's host
      table refusing a registries file and `MEDIATORE_RELAY_REGISTRIES`, the guest refusing the old variables at boot
- [x] The pool image's own exits (decision 8): the host table before `network-pre.target`, `image/host-quiet` masking
      the base's dialling units for the boot and removing the DHCP catch-all, the datasource limited to local devices
- [x] Unit, e2e and image tests; `make check`, `make host-table-test`, `make gateway-render-check` (2026-11-22)
- [ ] notaio: `role` on `SandboxAudience` and its read-only lint, then the pin; until then bundles mode grants no
      registry
- [ ] A kind tier: a claim pulls through a gateway, a claim in another namespace is refused the same registry, the
      relay has no registry leg
- [ ] Live: a pool member's boot with no flow but to a gateway (the journal's `mediatore-host drop:` lines, the
      conntrack table), and a pull through a gateway keyed by the claim SVID; the cost on a real link and several
      pulls at once
