<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0063: The image pull goes through the claim's proxy and the gateway, like any egress

**Status:** Accepted and implemented 2026-11-22, released in v0.4.0 (every open question answered, 3 by a spike on the build host;
the threat-model pass the same day; not yet run live, and bundles mode grants no registry until notaio carries
`role`: see the implementation notes) ·
**Date:** 2026-11-22

Roadmap 10 (the gateways) and roadmap 06 (the guest). Generalizes
[ADR-0043](0043-a-persons-registry-credential-is-placed-at-the-gateway-the-vm-never-sees-it.md)
decision 3 (the pull through the claim's egress proxy) from a gateway-placed registry to every
registry. Supersedes, for a gateway-era environment,
[ADR-0029](0029-the-pull-on-a-routeless-segment-and-the-pool-vms-root-rules.md) decision 1's
segment reach and [ADR-0038](0038-the-pull-reaches-the-operators-registry-through-a-fourth-relay-leg.md)
(the relay's registry leg). Moves the list of registries a claim may pull from out of the broker's
`registries[]` and into the namespace's own signed bundles
([ADR-0053](0053-an-audience-scoped-to-namespaces-each-with-its-own-rules.md),
[ADR-0055](0055-audiences-from-signed-sandboxaudience-bundles.md)).

## Context

The operator's rule, 2026-11-22: **a workload has no path out that bypasses the gateway, and the
image pull is part of the workload.** The first thing a claim fetches, its OCI image, must go
through the same proxy and the same policy match as every request the workload makes after it,
and which registries a claim may pull from is decided per namespace (per team), not once for the
whole broker.

What the code does today (`serve_claim`, `crates/mediatore-guest/src/guest.rs`):

- **Three ways to reach a registry, two of which skip the policy.** A registry that is a
  gateway-placed audience (ADR-0043) is pulled through the claim's egress proxy (its pull
  listener, `--pull-listen`/`--pull-host`) and the gateway's inject port. The authorizer checks it
  against the claim's allowlist, and the route's rules apply. Every other registry is pulled **by
  root, before the proxy exists**:
  - `reach: segment` (ADR-0029): a registry on the sandbox segment, reached at layer 2. No gateway
    sees the connection.
  - `reach: relay` (ADR-0038): the relay's fourth leg, a `tcp_proxy` on `RELAY_REGISTRY_PORT` to
    one fixed address. The connection goes through a gateway VM, but not through the authorizer.
    The leg has no identity, no claim and no policy, and any claim on any pool member reaches the
    same upstream.
- **The list of registries is broker-global.** `registries[]` in the broker's configuration
  names the registries and their reach. Every namespace sees the same set, and a claim whose image
  is on one is admitted whatever its namespace's policy says (ADR-0029 decision 1's refusal is
  "not a declared registry", not "not your registry").
- **The rest of the egress is already per namespace.** The claim's allowlist at the gateway is the
  union of its audiences' endpoints and its policy bundle's direct `egress[]` (ADR-0030). Team
  audiences are signed per namespace and resolve only for a claim in that namespace (ADR-0055
  decision 3), and a running claim follows a newer bundle only while it is still inside it
  (ADR-0061).

So the only egress a namespace's policy does not govern is the pull, the one fetch that decides
what code runs in the sandbox.

## Decision

1. **In a gateway-era environment, every image pull goes through the claim's egress proxy and a
   gateway.** The guest starts the claim's proxy before the pull for every claim, not only for a
   placed registry (ADR-0043's reorder becomes the only order). Root's puller reaches the registry
   through the proxy's pull listener alone. The proxy sends the request to a gateway as it sends
   the workload's: a placed route to the inject port, any other route as a `CONNECT` tunnel on the
   data port under the claim's SVID. The authorizer decides it against the claim's allowlist like
   any other request. A pull the allowlist does not admit is refused at the gateway, the claim
   fails before the jail (ADR-0021 decision 6), and the log names the host and the refusal.

2. **The registries a claim may pull from are its namespace's, from signed bundles.** A registry
   is an audience marked `role: registry` (open question 1), declared in a `SandboxAudience` bundle
   (ADR-0055): a platform audience that a namespace's policy grants, or a team audience locked to
   that namespace (ADR-0055 decision 3). A claim may pull an image only from a registry its
   allowlist reaches. The broker refuses a claim whose image is on any other registry at the
   front door (`400 registry_not_granted`), and on the declarative path a `Failed` sandbox with
   that reason. The refusal reads the same whether the registry exists in another namespace or
   not at all (ADR-0055 decision 3's rule, so a refusal tells a tenant nothing about another
   tenant).

3. **The pull listener serves every route kind.** Today `handle_pull` refuses a host whose route
   is not gateway-placed (`crates/mediatore-guest/src/egress.rs`). It now serves the claim's
   image registry under whatever route the claim has for it. For a tunnelled route the proxy
   originates the TLS to the registry inside the tunnel, as it does for the workload's requests,
   so the registry's certificate is checked by the proxy against the route's CA. The listener
   still serves the one registry host the guest names (`not_the_pull_host` for any other), still
   binds on loopback at a port no jail rule lists, and still runs under the claim's `sb-` user and
   SVID (ADR-0043 decision 3).

4. **The bypasses are removed, not left as options.** With `gateways` set:
   - the broker refuses to start with any `registries[]` entry (the list moves to bundles,
     decision 2), and `reach` is no longer read;
   - the relay's registry leg (`RELAY_REGISTRY_PORT`, `REGISTRY_ADDRESS`, `REGISTRY_PORT`) is
     removed from the gateway image's templates, the source filter and the host table's
     `registry4` set;
   - the host table admits no registry address for root. Root's only exits are the relay's
     identity-plane legs (decision 6) and the claim's proxy on loopback;
   - `MEDIATORE_RELAY_REGISTRIES` and `MEDIATORE_PLAIN_HTTP_REGISTRIES` are refused by the guest
     when the pool names gateways, so an old env file fails the boot loudly, not silently.

   A direct environment (no `gateways`) keeps today's behaviour. It already has no gateway to
   route through, and threat model R-12 and R-13 read "open without gateways".

5. **The pull is held to the same rules as the workload, with one difference.** The route's
   `rules` apply to the pull's requests (method and path; a placed registry audience already
   admits only the read paths of the registry API, ADR-0043 decision 1). A tunnelled route cannot
   be matched by path at the gateway, which sees only `host:port`. The proxy applies the rules
   before it dials, as it does for the workload. The difference: a `role: registry` audience is
   **pull-only**. The proxy's pull listener serves it and the workload's listener refuses it
   (`404 pull_only`), the sandbox uid's table does not list its endpoints, and the broker leaves it
   out of the routes `GET /v1/me` hands the workload. The workload cannot fetch further images
   (open question 2). A bundle that wants the workload to reach the same host for other requests
   grants a second, ordinary audience for it, with its own rules.

6. **The identity plane is not workload egress, and stays on the relay.** The relay's SPIRE
   attestation, broker and bundle legs (ADR-0027, ADR-0037) carry the node's own traffic before it
   has an identity to present. No workload byte uses them, and the jail's table does not list them
   beyond the broker's leg it already names. They are unchanged here, and the threat model says
   so. The pool VM's own image (the ISO or disk banlieue boots) is not pulled by the guest, and is
   not in scope either.

7. **The follow rule applies to the pull's route as to any other.** A newer bundle that removes
   the registry from a running claim's allowlist refuses that claim's next pull under
   `policy.follow: enforce` (ADR-0061). A claim pulls once, at start, so this matters only for a
   claim that restarts its workload (ADR-0033).

8. **Nothing else on the pool VM dials out, and the host table is up before anything could.**
   Open question 4 found exits in the image that the host table either does not see or is not
   yet loaded for (below). The image closes them:
   - the host table loads before the network: `mediatore-host-nft.service` gains
     `DefaultDependencies=no`, `Before=network-pre.target` and `Wants=network-pre.target`, so no
     unit that waits for the network runs without it. Today it is ordered only before the agent
     and the guest;
   - masked in the image, as `ssh` and `nftables` already are: `systemd-timesyncd` (NTP to the
     Debian pool), `systemd-resolved` (the segment has no resolver), `apt-daily.timer`,
     `apt-daily-upgrade.timer` (HTTP to the Debian mirrors), `iscsid.socket` and `open-iscsi`
     (unused), `open-vm-tools` and `vgauth` (not on our hypervisors);
   - the Kairos datasource is limited to the provider banlieue delivers the cloud-config by
     (`cdrom` or `config-drive`), so the boot does not probe the cloud metadata addresses of the
     other ten providers. That stage runs in the initramfs, before any table can be loaded, so
     the limit has to be in the image's own `/system/oem` override, not in a rule;
   - the base's DHCP catch-all (`20-dhcp.network`, written by Kairos' `05_network`) is replaced by
     a static network file sorting before it, as the gateway image already does
     (`image/gateway/network.in`). DHCP uses a packet socket that nftables does not see, so it is a
     broadcast on the segment the host table cannot bound;
   - `kairos-agent start` stays (upgrades come from banlieue, not from the VM), and the image check
     asserts it is configured with no remote upgrade source;
   - `image/check.sh` asserts each of these, and the pool's live proof reads the boot's journal for
     any `mediatore-host drop:` line and the conntrack table for any flow that is not to a gateway.

9. **The pull has bounds of its own, and they are in the code.** ADR-0038 decision 7(f) says the
   pull "runs before the jail, bounded at fifteen seconds". The puller has no such bound
   (`crates/mediatore-guest/src/image.rs`, `Puller::new`, `with_placed_registry` and
   `build_client` set no timeout), so a registry that stalls holds the claim until its TTL. And
   fifteen seconds for the whole pull would refuse any multi-gigabyte image on any path (open
   question 3). So:
   - **a connect timeout** of 10 seconds and **an idle timeout** of 60 seconds per read
     (`MEDIATORE_PULL_IDLE_SECS`), so a stalled registry, proxy or gateway fails the claim quickly
     with the host named;
   - **a deadline for the whole pull,** `MEDIATORE_PULL_DEADLINE_SECS`, default 900, refused at
     start above the claim's longest TTL; past it the claim fails before the jail, as any failed
     pull does (ADR-0021 decision 6);
   - the gateway's limits stay as they are: a tunnel is cut only past `TUNNEL_MAX_SECS` (86400),
     and the inject listener's `INJECT_STREAM_IDLE_SECS` (300) and `INJECT_MAX_STREAM_SECS` (3600)
     are wider than the guest's own. The guest's bound is the one that decides, and it fails
     first and says why;
   - ADR-0038 decision 7(f) is amended to point here.

## Consequences

- **No path from a pool member to a registry skips the authorizer.** The pull, like every other
  request, is decided per claim, against the namespace's signed policy, at a gateway that logs it
  (and reports it to the broker once ADR-0062 lands).
- **A team chooses its registries in its own bundles.** A platform registry is granted per
  namespace by policy, and a team registry is the team's own audience. The broker's operator no
  longer edits a global list for a team to pull from a new mirror.
- **Every image's layers go through a gateway.** Today only a placed registry's do. This is the
  cost ADR-0043 open question 4 named, now for every claim: start time, gateway bandwidth and
  memory, and the stream limits (`INJECT_STREAM_IDLE_SECS`, `INJECT_MAX_STREAM_SECS`, and the data
  plane's own for a tunnel). It is measured before the ADR is accepted (open question 3).
- **The guest's order is one order.** Proxy, then pull, for every claim. A proxy that fails to
  start fails the claim before any byte is pulled. The early pull, its client options for the
  segment and relay reaches, and the tests that pin them are removed.
- **A registry that redirects blobs to another host** (a cloud store) needs that host in the
  registry audience's endpoints, under the same policy, or the pull fails with the host named
  (ADR-0038 decision 2's refusal, kept).
- **Breaking for a gateway-era deployment that uses `reach: segment` or `reach: relay`.** The
  migration moves each `registries[]` entry into a `SandboxAudience` bundle and grants it in the
  policies of the namespaces that pull from it. The broker's start refusal and the guest's boot
  refusal make an unmigrated environment fail loudly.
- **The relay loses a leg and the host table a set**, which narrows root's exits on the pool VM to
  the identity plane and loopback.

## Alternatives rejected

- **Keep the relay leg, and have the broker check the image's registry against the namespace's
  policy at admission.** The admission check would be per namespace, but the bytes would still
  leave by a path no authorizer sees, and a compromised guest (root) could use the leg for any
  claim. That is the bypass the operator's rule forbids.
- **An authorizer on the relay leg.** It would duplicate the data plane's identity, allowlist and
  logging on a second listener. The data plane already does all of that for the claim's SVID.
- **Pull as the node identity, at the gateway.** Rejected by ADR-0043 open question 2 for the
  same reasons: it widens TB-17 and lets a node identity act for a claim.

## Open questions

1. **How a bundle marks a registry. Answered 2026-11-22: a marker,** `role: registry` on the
   audience, so a team cannot pull from a host it was granted for API calls, and notaio's lint can
   check that a registry audience's rules are the read paths only (decision 2).
2. **Does the jail get the registry route too? Answered 2026-11-22: no.** The workload cannot
   fetch further images; a registry audience is pull-only (decision 5).
3. **The cost of every layer through a gateway. Answered 2026-11-22 by a spike on the build host:
   no meaningful cost, and the pull needs bounds of its own (decision 9).** A random blob, served
   over TLS on the fixture CA, fetched from a pod on a one-node kind cluster; peak anonymous memory
   from each container's cgroup, sampled every half second; every transfer `200`, the full length
   and the digest matching:

   | Path | Size | Time | MB/s | Peak memory |
   | --- | --- | --- | --- | --- |
   | Direct, no gateway | 1 GiB | 5.84 s | 184 | (Envoy idle 25.6 MiB) |
   | Egress proxy, `CONNECT` tunnel, the data-plane Envoy | 1 GiB | 6.04 s | 178 | Envoy 27.7, authorizer 4.1, proxy 3.4 MiB |
   | An inject-shaped Envoy (TLS on both sides) | 1 GiB | 5.87 s | 183 | Envoy 24.3 MiB |
   | Direct, no gateway | 4 GiB | 23.49 s | 183 | |
   | Egress proxy, `CONNECT` tunnel | 4 GiB | 23.58 s | 182 | Envoy 29.9, authorizer 4.1, proxy 3.4 MiB |
   | An inject-shaped Envoy | 4 GiB | 24.06 s | 178 | Envoy 26.4 MiB |

   The gateway costs under 3% in throughput here, and memory does not grow with the size: the
   proxy holds 3.4 MiB at either size (it streams the body, `crates/mediatore-guest/src/egress.rs`,
   it never buffers it) and Envoy 2 to 4 MiB over idle, bounded by its 1 MiB per-connection buffer.
   Envoy's access log keyed the tunnel by the claim SVID, and the authorizer decided it once, at
   the `CONNECT`. Not shown: a real link (on loopback the link's bandwidth, not the gateway, will
   set a live pull's time), several pulls at once on one gateway, and the real inject path (the
   kind tier has no inject Envoy; the spike used `inject.yaml.in`'s listener, route and timeouts
   without `ext_authz` or the claim's certificate, and `ext_authz` runs once per request, not per
   byte). The kind tier of the checklist and the live proof cover the last; the first two are
   measured on a live pool before the rollout.
4. **What else a pool member fetches before a claim. Answered 2026-11-22: more than the host
   table claimed; decision 8 closes it.** In mediatore's own code the guest's outbound connections
   are the broker and the bundle leg through the relay, the SPIRE agent's server leg, the puller
   and the egress proxy to the gateways (`crates/mediatore-guest/src/client.rs`, `forward.rs`,
   `image.rs`, `image/spire-bundle-fetch`). The pool image (`ghcr.io/firestoned/mediatore-guest:dev`
   on the Kairos base `debian:13-core-amd64-generic-v3.7.2`, read offline on the build host) also
   enables, from its base:
   - `systemd-timesyncd` (sysinit, the Debian NTP pool) and `systemd-resolved` (sysinit);
   - `apt-daily.timer` and `apt-daily-upgrade.timer`, against `deb.debian.org`;
   - `iscsid.socket`, `open-iscsi`, `open-vm-tools`, `vgauth`, `multipathd` (idle without
     configuration, but enabled);
   - Kairos' datasource stage, which probes twelve providers (`gcp`, `aws`, `azure`, `openstack` and
     others, several of them by HTTP to a link-local metadata address) in the initramfs and again
     at the `network` stage;
   - Kairos' `20-dhcp.network` on every `en*` and `eth*` interface;
   - `kairos-agent.service`, written and started at the `boot` stage.

   The host table is TCP-only and drops UDP once it is loaded, so NTP, DNS and the apt timers fail
   closed against it. But the table loads late: `mediatore-host-nft.service` is ordered only
   `Before=spire-agent.service mediatore-guest.service`. The initramfs stages, DHCP's packet
   socket, and anything that starts before the unit are not bounded by it. Not yet shown on a
   running pool member; the live check in decision 8 is how it is shown.
5. **The direct environment. Answered 2026-11-22: kept** as it is (decision 4), with the start-up
   warning it already logs.

## Implementation notes (2026-11-22)

Built, tests first:

- **Decision 9.** `PullBounds` in `crates/mediatore-guest/src/image.rs`: the connect and idle bounds on every client
  the puller builds (the direct one and the one to the claim's proxy), the deadline over the whole pull, cut to what is
  left of the claim (`pull_bounds`, `crates/mediatore-guest/src/guest.rs`). `MEDIATORE_PULL_IDLE_SECS` and
  `MEDIATORE_PULL_DEADLINE_SECS` refuse zero at start. The test registry gained `stall_blobs_after` and
  `trickle_blobs`.
- **Decision 2, in the broker's file configuration.** `audiences[].role: api | registry`
  (`crates/mediatore/src/config.rs`), a registry audience's rules held to `GET` and `HEAD` under `/v2/`, and
  `granted_registries` (per audience, the registries it serves, only with `gateways`). `POST /v1/claims` answers
  `400 registry_not_granted` and the reconciler fails the sandbox with the same sentence
  (`mediatore_proto::image::ungranted_registry`), which names no registry the broker serves.
- **Decision 4, the broker, the gateway image and the pool's host table.** `registries[]` with `gateways` refuses the
  start. The relay renders three legs (`image/gateway/envoy/relay.yaml.in`), the gateway's table no longer admits or
  refuses a registry address, and the pool's host table refuses a registries file that names one and
  `MEDIATORE_RELAY_REGISTRIES` (`image/host-table`). The guest refuses `MEDIATORE_RELAY_REGISTRIES` on any pool and
  `MEDIATORE_PLAIN_HTTP_REGISTRIES` on a pool with gateways, at boot, before it registers.
- **Decisions 1, 3 and 5.** `Route.pull_only` on a registry audience's routes; `GET /v1/me` leaves their endpoints
  out of the jail's `egress`, the gateway's answer keeps them. The proxy's workload listener answers `404 pull_only`;
  its pull listener serves a pull-only route over a tunnel (the route's own credential placed, the puller sending
  none) or a placed one. With gateways the guest pulls every image through the proxy, and refuses a claim whose image
  has no route (`through_the_proxy`). Proven over the real routers and a stand-in gateway in
  `crates/mediatore/tests/e2e_forward.rs`.

Not yet, and why:

- **Bundles mode grants no registry yet.** `role` lives on notaio's `AudienceDefinition`, which has no such field
  (`sandboxpolicy-types` v0.7.0). Until notaio carries it and the pin moves, a broker under
  `policy.audience_definitions.mode: bundles` with `gateways` refuses every image (fail closed). An older broker would
  ignore the field and serve a registry audience to the workload, so the broker moves first.
- **The puller answers no challenge through the proxy.** It sends no credential and follows no redirect (ADR-0043
  decision 2), so a registry whose anonymous pull needs a token from a realm is not served by a tunnelled route; a
  pull-through mirror that answers anonymously, or a placed credential, is. The kind tier will show which the
  operator's mirror is.
- **Decision 8, two findings when it was started.** the pool image is shared by direct
  pools, which need `systemd-resolved` for their DNS rule (ADR-0020), so the masks must apply only where the host table
  loads; and `/etc/mediatore/gateways` and the guest's env are written by the deployment layer's cloud-config stage,
  so a host table ordered before `network-pre.target` may run before its inputs exist and skip itself
  (`ConditionPathExists`). Both need the stage the deployment layer writes in, checked on a pool member's boot.
- **Decision 8, built 2026-11-22 after those were settled.** Nothing is masked in the image, which direct pools
  share: `image/host-quiet`, run by `mediatore-host-nft.service` after the table loads (so only on a pool with
  gateways), masks for that boot `systemd-timesyncd`, `systemd-resolved`, the apt timers, iSCSI and the VMware tools,
  stops them, and removes the base's DHCP catch-all. The unit loads before `network-pre.target`
  (`DefaultDependencies=no`), safe because the deployment layer writes its inputs in the `initramfs` stage
  (`image/cloud-config-deployment.example.yaml`). The datasource stage is the base's with three local providers
  (`image/oem/00_datasource.yaml`) for every pool. Not settled by code: Kairos may run `systemd-networkd` in the
  initramfs with the DHCP file (its `05_network` comment says so), before any table; the pool member's boot shows
  whether it does.
- **The puller's relay internals** are removed (`image.rs`), with the tests that only exercised them.

## The ADD checklist

- [x] ADR accepted (2026-11-22); every open question answered, 3 by the spike
- [x] CALM updated (the relay's registry leg retired, `rel-gateway-registry`,
      `flow-registry-pull-gateway`, the pool image's exits); `make calm-validate` (no error; the one
      warning, `data-asset-sealing-key` unreferenced, is on `main` too) and `make calm-diagrams`
- [x] Tests first (2026-11-22, `make check` green on the build host): the pull's connect, idle and whole-pull
      bounds (decision 9), each failing the claim with the host named; the broker's refusal (`registry_not_granted`, by namespace), the start refusal
      for `registries[]` with `gateways`, the pull listener over a tunnelled route, the workload's
      listener refusing a pull-only route, `/v1/me` leaving it out, the guest's boot refusal of the
      old variables, the host table without `registry4`
- [x] The image (decision 8, 2026-11-22): the host table before `network-pre.target`, `host-quiet`'s masks and
      the DHCP catch-all removed, the datasource limit; `image/check.sh` and `make host-table-test` asserting each
- [ ] A pool member's boot with no flow but to a gateway
- [x] e2e over the real routers (`e2e_forward`: an ungranted registry refused with no other named, a pull through a
      stand-in gateway's tunnel as the claim, the same route refused to the jail)
- [ ] A kind tier: a claim pulls through a gateway, a claim in another namespace is refused the
      same registry, the relay has no registry leg
- [x] Guides, README, roadmaps 06 and 10, ADR-0029, ADR-0038 (superseded, decision 7(f) too) and ADR-0043
      amended (2026-11-22)
- [x] Threat model full pass (2026-11-22): TB-15 narrowed, TB-11 rewritten, TB-13 one row, R-13 revised, R-25
      withdrawn, R-63 to R-65 new, the stamp bumped
- [ ] notaio: `role` on `SandboxAudience`, its read-only lint, the pin (R-63)
