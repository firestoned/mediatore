<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0020: The jail's network is the guest's, bounded by nftables keyed by the sandbox uid

**Status:** Accepted · **Date:** 2026-10-24

Roadmap 06, the network item. Implements mediatore's share of
[ADR-0010](0010-no-inbound-to-sandboxes.md) (no inbound to sandboxes; in-guest nftables
as the second layer) and amends its decision 5 for what
[ADR-0014](0014-one-binary-roles-as-subcommands.md) made of the workload's client. Changes
nothing about the identities of [ADR-0004](0004-spiffe-identity-scheme.md) or the token
shapes of [ADR-0003](0003-token-backends.md).

## Context

The jail is an `nsjail` started by `mediatore guest` as the per-subject user. `nsjail`
puts its child in a fresh network namespace unless told otherwise, and the spec in
`crates/mediatore-guest/src/jail.rs` never told it otherwise: the jail had loopback and
nothing else. ADR-0010 decision 5 described that state as intended, "an empty network
namespace", with the workload reaching the world "only through a socket to
mediatore-guest". That socket was never built. ADR-0014 instead mounted the one binary
into the jail so the workload runs `mediatore token`, which opens its own mutual-TLS
session to the broker with the claim SVID, and the workload then calls the downstream API
with the token it got. Both calls need a route out of the jail. The guide promised "no
network beyond the broker and the claim's audiences"; nothing enforced the bound, and the
namespace enforced a different one, under which `mediatore token` could not have worked.

ADR-0010's ruleset outline already names the mechanism: output for the jailed uid, matched
by `skuid`, to the allowed destinations only. What was missing is where the destinations
come from, when the ruleset is loaded, and what happens when it cannot be.

## Decision

1. **The jail keeps the guest's network namespace.** `nsjail` runs with
   `--disable_clone_newnet`; the workload's sockets are ordinary sockets of the `sb-` uid
   on the VM's interfaces, which is what lets the kernel attribute them. ADR-0010 decision
   5 is amended: the jailed process reaches the broker and its audiences' endpoints through
   nftables keyed by its uid, not through a relay socket. The relay that injects
   credentials so the workload never holds a token is roadmap 07, a different design with
   its own ADR.

   *Amended 2026-10-31, from the live proof.* No user namespace either
   (`--disable_clone_newuser`). nsjail's default is one, and inside it the jail's uid is
   mapped to the invoker's, root: `uid_map` `101 0 1`, so every socket the workload opens
   carries global uid 0, outside the chain this decision keys on, and the loopback rule
   that admits the sandbox uid alone to the proxy cuts the workload off from its one route.
   The unix workload attestor's `unix:user` selector and the proxy's uid gate key on the
   same global uid. Without the namespace nsjail sets the uid directly, `uid_map`
   `0 0 4294967295` and `id` the sandbox user's. The namespace also fails on a systemd
   host, where the read-only remount of nsjail's mount tree under `/run/user`
   (`nosuid,nodev` locked by the parent mount) is refused inside it. The kind tier ran the
   guest in a pod and saw neither.

2. **The destinations are the claim's audiences' endpoints, declared in the broker's
   config.** `audiences[].egress` lists `host:port` pairs per audience;
   `GET /v1/me` returns the union over the claim's audiences as `egress`, so the guest
   learns the destinations with the subject and the workload, over the same node SVID.
   The broker itself (the host and port of `MEDIATORE_URL`) is always a destination. An
   audience with no `egress` yields tokens with nowhere to spend them: that is the
   fail-closed default, and the deploying guide says so.

3. **One ruleset per claim, loaded in one transaction before the jail starts.** The
   guest renders table `inet mediatore_sandbox`: an output hook whose only rule sends
   packets of the sandbox uid (`meta skuid`) to a chain that accepts established and
   related traffic, TCP to the resolved address and port pairs, DNS (53, UDP and TCP) to
   the resolvers in the VM's `/etc/resolv.conf`, and then logs and drops. Packets of any
   other uid, and packets with no socket, never enter that chain: the root-level rules and
   the input chain of ADR-0010's outline belong with the image, once its system users
   (DHCP, NTP, the SPIRE agent) are known; roadmap 06 keeps that item. `nft -f` applies
   the ruleset atomically; a stale table from an earlier claim is replaced in the same
   transaction.

4. **Names are resolved by the guest at load time.** The set holds addresses, so the log
   and the ruleset's hash say exactly what was admitted. A destination that does not
   resolve is omitted with a warning (closed for that destination, the rest unaffected); a
   broker that does not resolve is an error, since nothing would work. A destination whose
   address changes during the claim becomes unreachable, not open.

5. **No ruleset, no jail.** A failure to load (no `nft` on the image, a syntax the
   installed `nft` refuses, no uid) is an error before `nsjail` is spawned, and the guest
   tears down what it created. The SHA-256 of the loaded ruleset is logged with the claim
   UID; reporting it to the broker, so a flush or change is detected (ADR-0010's outline),
   is a follow-up item of roadmap 06.

6. **Teardown deletes the table**, after the jail is stopped, best effort like the rest of
   the teardown: the next claim replaces it anyway.

7. **Second layer, restated.** Guest root can flush the table (ADR-0010 decision 4). The
   enforcement that holds against guest root is outside the guest: the segment and the
   hypervisor's rules, which banlieue's providers own. This ruleset bounds the workload,
   which is not root.

## Consequences

- `crates/mediatore-guest/src/net.rs` renders, loads and unloads the ruleset; `jail.rs`
  drops the namespace; `guest.rs` loads before `supervise::run` and unloads in the
  teardown. `mediatore_proto::Endpoint` and `Me::egress` carry the destinations;
  `AudienceConfig::egress` declares them; the API computes the union per claim.
- The VM image carries `nftables` (the `nft` binary); roadmap 06's image item lists it.
  The kind tiers run the guest with `--dev-skip-setup` and need nothing new; the rendered
  ruleset is pinned by unit tests, and an ignored test hands it to a real `nft -c` where
  one is reachable (`MEDIATORE_NFT`, the build host), since `nft` checks syntax through
  netlink and wants `CAP_NET_ADMIN` even to check.
- The workload shares the VM's interfaces. It can open a listening socket; nothing reaches
  it, because ADR-0010 decision 1 is enforced by the segment, and the input chain is the
  image item above. Recorded in the threat model.
- DNS to the VM's resolvers is open for the sandbox uid, by name of any zone: a covert
  channel bounded by the resolver's logging and the claim's deadline, recorded as an
  accepted risk until the egress proxy of roadmap 07 answers names itself.
- Rejected: a namespace per jail with a `veth` pair and NAT (the uid is lost behind the
  translation, and the guest would carry a router); the relay socket of ADR-0010 decision
  5 as written (it rebuilds the mTLS client as a proxy, which is roadmap 07's design, with
  credential injection, not a second copy of it); letting `nft` resolve names at load
  (equivalent, but the admitted addresses would appear nowhere the operator can read).
