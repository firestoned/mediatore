<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0029: The image pull on a routeless segment, and the pool VM's root rules

**Status:** Accepted · **Date:** 2026-11-04 (proposed and accepted the same day: the segment
reach is what the homelab runs; the relay reach is recorded, not built)

Roadmap 06, the last network item. Amends [ADR-0021](0021-sandbox-filesystem-tmpfs-and-rootfs-from-the-registry.md)
(its consequence that "the segment's firewall must let the members reach the registry")
and finishes [ADR-0020](0020-jail-network-nftables-keyed-by-sandbox-uid.md) decision 3
(the root-level rules it left to the image) as [ADR-0027](0027-control-plane-relay-on-the-egress-gateway.md)
decision 6 restated them. Builds on [ADR-0028](0028-egress-gateway-envoy-with-spiffe-identity.md)
(the gateways are the segment's only exits) and banlieue
[ADR-0109](https://github.com/firestoned/banlieue/blob/main/docs/adr/0109-isolated-sandbox-network-with-proxy-egress.md)
decision 1 (the segment routes nowhere). Changes nothing about identities, token shapes
or who pulls (the guest, as root, before the jail: ADR-0021 decision 5).

## Context

Roadmap 10 built the exits of the sandbox segment and, in doing so, showed one path that
has none. Since banlieue ADR-0109 the segment is layer 2 only: a pool VM reaches its
neighbours and the three gateways' `sandbox` addresses, nothing else. ADR-0027 gave the
identity plane a way through (the control relay, two fixed upstreams), ADR-0028 gave the
claim's traffic a way through (the data plane, claim SVIDs only, `CONNECT` to the claim's
allowlist). The workload image pull has neither. ADR-0021 decision 5 has the guest, as
root, fetch `workload.image` over HTTPS with the Mozilla roots before the claim's proxy
exists, and its consequences assumed "the segment's firewall" would admit the registry,
which was true of the segment ADR-0010 sketched and is not true of the one ADR-0109
built. On a gateway-era pool the pull hangs on a SYN that goes nowhere, and no claim
starts.

Two facts bound the answer. The data plane admits claim identities only, and the claim
SVID is issued to the `sb-` user (ADR-0006), which the guest is not; ADR-0027 rejected
admitting the node SVID there, since the claim-only check is what gives the gateway its
meaning. And a public registry does not serve its blobs itself: `ghcr.io` and `docker.io`
answer a blob request with a redirect to a content host that changes, so a tunnel or a
relay fixed to the registry's own address carries the manifest and loses the layers.

The same roadmap item carries the other half of ADR-0010's outline: the rules for every
uid on the VM, root's included, which ADR-0020 decision 3 deferred "with the image, once
its system users are known" and ADR-0027 decision 6 shaped for the segment interface
(output to the gateways' data and control ports and to the segment's neighbours' none,
for every uid). The sandbox uid's table (ADR-0020, in its two shapes since ADR-0028
decision 6) bounds the workload; nothing in the guest bounds root or the agent yet, and
the input hook is open (threat model R-13). Those rules cannot be written without knowing
where root is allowed to go, which is the pull.

## Decision

1. **A gateway-era pool pulls only from a registry it can reach without a route: the
   operator's.** Two ways to reach one, both declared by the operator and neither a
   default:
   - **On the segment.** A registry or pull-through mirror with an address on the sandbox
     segment, reached at layer 2 like a neighbour. Plain HTTP as `MEDIATORE_PLAIN_HTTP_REGISTRIES`
     already allows (pin by digest, no credential crosses it: ADR-0022), or HTTPS under a
     certificate authority the pool is told about (`MEDIATORE_REGISTRY_CA`, a PEM beside
     the Mozilla roots for the registries the operator names, the same shape as
     `audiences[].ca_file` and `issuers[].ca_file`).
   - **Through the control relay** (recorded, not built). A third kind of listener on the
     gateway, one per operator registry, a fixed upstream by address like the SPIRE
     server's and the broker's (ADR-0027 decision 2), the guest's HTTP client pinning the
     registry's host name to the gateway's `sandbox` address and that port so the TLS
     inside is the registry's, end to end. Only a registry that serves its blobs itself
     fits it. The homelab runs a mirror on the segment instead; this reach is built when
     an environment cannot host one, with its own `reach` value then.

   A public registry (`ghcr.io`, `docker.io`) is unreachable from a gateway-era pool by
   construction. The operator who wants its images mirrors them: a pull-through cache on
   the segment or behind a relay listener, which is also where image review belongs
   (threat model R-14: a tag is the registry's word; a mirror makes it the operator's).
   The broker refuses a claim whose image names a registry the environment cannot reach
   (`400` at `POST /v1/claims`, a `Failed` sandbox with the reason on the declarative
   path), with the reachable registries named, as soon as the broker's config has
   `gateways`: a gateway-era environment pulls from its declared registries and no other.
   An environment without `gateways` keeps today's behaviour.

2. **The broker's `registries[]` gains `reach`,** `segment` for now, so that one
   configuration says both who may pull (ADR-0022) and from where; the credential becomes
   optional on an entry, so an anonymous mirror is declared by its host and its reach
   alone (`username` and `password_file` still come together). With `gateways` set, every
   registry entry needs a `reach` and the broker refuses to start otherwise: a pull nobody
   has said how to route is a claim that cannot start. The guest needs no second check:
   the host table of decision 3 admits the declared mirrors' addresses and nothing else,
   so a pull the broker should have refused is dropped and logged on the VM.

3. **The pool VM's root rules are image content, rendered from the pool's env, loaded
   before anything listens or connects.** A second table beside ADR-0020's, `inet
   mediatore_host`, owned by the image like the gateway's (`image/gateway/nftables.conf.in`),
   rendered by the same `render` script from the pool's env files and loaded by a oneshot
   unit that the agent and the guest `Require`:
   - input: policy drop; loopback and established accepted; nothing else. A pool VM
     listens for nobody (ADR-0010 decision 1; the guest's `GuestReady` leaves on the
     hypervisor's channel, not the network).
   - output on the segment interface, for every uid: the three gateways' `sandbox`
     addresses on the data port and the two relay ports (and the registry relay ports of
     decision 1), the segment registries' addresses and ports, the proxy on loopback as
     today; established accepted; the rest logged `mediatore-host drop:` and dropped. No
     neighbour, no broadcast but what DHCP needs if the pool uses it (banlieue ADR-0109
     does not), no DNS, no NTP on the segment (the gateway is the clock's path if one is
     wanted, a later listener).
   - forward: policy drop.
   The sandbox uid's per-claim table stays as it is (ADR-0020): the workload's bound is
   the uid's, root's is the host's, and a flush of either is visible in the other's log.

4. **Direct environments load no host table.** Without gateways the exits are the
   broker, the SPIRE server, the registries, the resolvers and whatever the operator's
   firewall allows, none of them known to the image; the host table exists only when the
   pool's env names gateways, as the sandbox ruleset's gateway shape does. Threat model
   R-13 then reads: closed with gateways, open without, the same bound as R-12.

5. **The ruleset hashes and the image digest reach the broker.** The guest reports, with
   the claim, the SHA-256 of the host table it found loaded and of the sandbox table it
   loaded, and the manifest digest it pulled (ADR-0020 decision 5's follow-up; roadmap
   06). A broker-side comparison is a later roadmap; the record saying which rules and
   which bytes ran is this one.

## Consequences

- **The pool's images are the operator's.** A requester names an image; the operator
  decides which registries a gateway-era pool reaches and mirrors the rest. That is a
  policy change for the walkthroughs, which pull from `ghcr.io` today, and it is the
  right one: the gateway was built so that nothing leaves the segment unexamined, and a
  pull is a download.
- **New code:** `MEDIATORE_REGISTRY_CA` in `crates/mediatore-guest/src/image.rs`;
  `registries[].reach` and the optional credential in `crates/mediatore/src/config.rs`,
  the refusal in `crates/mediatore-api` and the sandbox reconciler; the host table script
  and unit in `image/` (`image/host-table`, `mediatore-host-nft.service`), proven by
  `image/check.sh` and by `nft -c` on the build host; the pool's `/etc/mediatore/registries`
  in the deployment layer. CALM: the segment and the VM; the threat model: R-13 revised,
  TB-11 rewritten for the segment reach.
- **Rejected:**
  - the node SVID on the data plane for the pull (ADR-0027 rejected it; the claim-only
    check is the gateway's meaning);
  - the pull as the `sb-` user through the claim's own tunnel (the rootfs must be root's
    and read-only to the workload, ADR-0021; and the proxy does not exist until the pull
    is done, by ADR-0025's order);
  - the pull through the data plane with a `CONNECT` allowlist of the registry's content
    hosts (unknowable for a public registry, changing without notice, and a tunnel the
    gateway could not attribute to a claim);
  - a registry on the gateway VMs (a fourth service on the most exposed VM);
  - a route from the segment to the registry (banlieue ADR-0109 decision 1).

## Implementation notes

What roadmap 06 fixed within the decisions above, as it is built (2026-11-04):

- **The report is `POST /v1/me/report` on the sandbox listener** (decision 5), over the
  node SVID, for the claim bound to that node as `GET /v1/me` finds it: `GuestReport`
  (`crates/mediatore-proto`) carries the manifest digest, the sandbox table's SHA-256 as
  loaded (`net::Ruleset::sha256`) and the host table as `nft -s list table inet
  mediatore_host` prints it, hashed, or `missing` where the environment has gateways and
  no table is loaded, or `not_loaded` where none is expected (`crates/mediatore-guest/src/report.rs`).
  The broker validates the shapes, logs one line (a missing table at `warn`), stamps
  `reported_at` and keeps it on the record (`claims.report`, migration `0005`, swept into
  the audit row with the claim); `GET /v1/claims/{name}` shows it to the subject and
  `mediatore sandbox get` prints it. The guest sends it once, after the tables are loaded
  and before the jail starts, bounded at fifteen seconds; a broker unreachable then is
  said at `warn` and the claim goes on: the report is the record's, not the jail's gate,
  and a record with no report is itself visible. The `AgentSandbox` status does not carry
  it yet; the resource says the claim's phase, the record says what ran.
- **Proven live on 2026-11-05** (the gateway run of roadmap 06, v0.2.0-rc.4): a pool
  member on the routeless segment with a static address from the pool's range (through a
  `userData` stage with banlieue's placeholders, since a Kairos guest reads no seed
  `network-config`), the host table loaded before the agent, the agent and the guest
  through a gateway's relay, the pull from a pull-through mirror on the segment's host
  (an anonymous `registries[]` entry with `reach: segment`, plain HTTP, the image named
  by digest and the manifest index resolved to the platform's manifest), the report at
  the broker with the host table `loaded` and shown by `mediatore sandbox get`. Two
  things the run settled for the deploying guide: the mirror must listen on the host's
  segment address itself (libvirt's isolated network rejects forwarded traffic, a
  container port mapping included), and the host table drops ICMP, so `ping` proves
  nothing about a member.

### Still to decide

- Whether `reach: relay` is ever worth its listener: the homelab runs a mirror on the
  segment (decided 2026-11-04); an environment that cannot host one reopens it.
- Whether the report belongs on the `AgentSandbox` status too, for a requester who reads
  the resource and not the API; and whether the guest re-reports on a change (today once).
- A broker-side comparison: the host table's expected hash per pool image, so a flushed
  or altered table is refused rather than recorded.
- The clock: whether pool VMs need NTP through the gateway, or the hypervisor's clock
  suffices (libvirt's and Cloud Hypervisor's guests take it from the host).
- ~~The report of decision 5: on `POST /v1/nodes`, on a new route, or in the proxy's
  readiness.~~ Settled, see *Implementation notes*: `POST /v1/me/report`.
