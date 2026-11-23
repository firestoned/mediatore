<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0038: The pull reaches the operator's registry through a fourth leg of the control relay, for root only

**Status:** Superseded 2026-11-22 by [ADR-0063](0063-the-image-pull-goes-through-the-claims-proxy-and-the-gateway-like-any-egress.md) (the leg was a path from a pool VM to a registry that no authorizer saw; it, `reach: relay`, `MEDIATORE_RELAY_REGISTRIES` and the host table's `registry4` set are removed, never having run live; decision 7(f)'s "bounded at fifteen seconds" was not in the code, and the pull's bounds are ADR-0063 decision 9). Was: Accepted, implemented in the repository 2026-11-15 · **Date:** 2026-11-15

Roadmap 10 (the gateway) and roadmap 06 (the guest). Builds what
[ADR-0029](0029-the-pull-on-a-routeless-segment-and-the-pool-vms-root-rules.md) decision 1 recorded
as "through the control relay (recorded, not built)", gives `registries[].reach` its second value
(ADR-0029 decision 2), and amends [ADR-0027](0027-control-plane-relay-on-the-egress-gateway.md)
decision 2 (the relay's legs are fixed upstreams, one per reviewed change; this is one more).
Changes no token shape, no SPIFFE ID, no entry shape and no storage contract.

## Context

The guest pulls each claim's `workload.image` itself, as root, before the jail's ruleset is loaded
(ADR-0021 decision 5), and a pool member's segment has no route and no resolver. ADR-0029 left
two ways to give it a registry: one on the segment, reached at layer 2 (built, `reach: segment`),
and one through the control relay (recorded, not built, "when an environment cannot host one").
A deployment that has a corporate registry or a pull-through cache of a public one, but cannot put
a host on the sandbox segment, has no way to run a claim at all: the broker accepts the claim, the
guest cannot reach the registry, and the claim fails before the jail starts. The two example
images (`research-agent`, `claude-code`) are exactly such a case when they are served by the
operator's mirror of a public registry.

The relay already carries three fixed legs (ADR-0027, ADR-0037): the SPIRE server's attestation
port, the broker's sandbox listener and the SPIRE bundle endpoint. Each is an L4 pass-through to
one fixed upstream by address, with no identity, no TLS context and no authority from the client.
A registry is a fourth place a member needs to reach, and the same shape fits it, provided the TLS
inside stays the registry's own, end to end.

Opening a path from the segment to a registry raises one question the other legs did not: the
jail must not get it. The jail shares the VM's network namespace and is bounded by nftables keyed
by its uid (ADR-0020 decision 1), so "the jail cannot reach the registry" is a statement about
rules, and the design below states which rules, in how many independent places.

## Decision

1. **The relay gains a fourth fixed leg per registry upstream.** A `tcp_proxy` listener on the
   gateway's sandbox address, `RELAY_REGISTRY_PORT` (3132), to one fixed upstream by address,
   `REGISTRY_ADDRESS:REGISTRY_PORT` (the registry, 443), the same shape as the bundle leg's
   `SPIRE_BUNDLE_ADDRESS:SPIRE_BUNDLE_PORT`. The same shape as the
   other legs (ADR-0027 decision 2): L4 pass-through, no CONNECT, no authority from the client, no
   name resolution on behalf of the sandbox, no SDS, no TLS context, one access-log line per
   connection with `upstream=registry`. The leg does not know a host name: it carries bytes to one
   address, so several registry names that resolve to that address (a registry that names each
   repository by subdomain) share it. A second, different registry is a second leg and a reviewed
   change in the template, never a parameter. The sandbox source filter admits the port beside
   3128 and the other relay ports, under the same per-source connection cap (ADR-0027 decision 5).

2. **The guest maps a declared registry name to the gateway, and the TLS inside is the
   registry's.** `/etc/mediatore-guest/env` names the registries reached this way,
   `MEDIATORE_RELAY_REGISTRIES=host=port[,host=port]`, and the gateway is the one the guest
   already uses for the control relay (the host of `MEDIATORE_URL`, an IPv4 address). For a
   declared host, every request the puller sends, the manifest, the blobs and the token realm on
   the same host, is dialled at that gateway address and port instead of the host's own; the TLS
   server name, the certificate check against the image's CA set (or `MEDIATORE_REGISTRY_CA`) and
   the `Host` header stay the registry's real name. The match is on the registry's name without
   its port, the name the certificate carries; a port the reference or a redirect gave is kept
   in the `Host` header and replaced by the leg's in the dial. The client never uses an ambient
   proxy once a registry is declared (a proxy in the environment would carry the request
   somewhere the pin did not intend). The relay never holds a credential and never sees
   plaintext. A response that redirects to a host that is not declared is not followed: the
   pull fails, the claim fails before the jail (ADR-0021 decision 6), and the log names the host.
   This is the "only a registry that serves its blobs itself fits it" limit of ADR-0029, made a
   refusal and not a hang.

3. **The pull is root's, and the host table says so.** The pool VM's host table
   (ADR-0029 decision 3) gets a second set, `registry4`, holding the gateway address and the
   registry port, admitted by one rule that matches the owner:
   `meta skuid 0 ip daddr . tcp dport @registry4 accept`. The guest's pull is root's; every
   other uid, the sandbox users included, is dropped at the output hook with the rest, and the
   existing log line names the drop. The set is read from `MEDIATORE_RELAY_REGISTRIES` and
   `MEDIATORE_URL` by the same script and with the same refusal of names (ADR-0029); with the
   variable unset the set is empty and the rule is not emitted.

4. **The jail's table is unchanged, and a test says so.** The sandbox uid's ruleset
   (ADR-0020, ADR-0028 decision 6) admits the broker's relay port, the gateways' data port and
   the loopback proxy; it does not and will not list the registry port. A test renders the
   ruleset with `MEDIATORE_RELAY_REGISTRIES` set and asserts the registry address and port appear
   nowhere in it, and the guest's live proof (a pool member, a claim) includes a connection from
   the sandbox uid to the leg that is refused. A workload that needs the registry's content the
   claim's policy allows reaches it the other way, through the egress proxy under the notaio
   policy (ADR-0028), which is a different path with a different gate.

5. **The broker declares and enforces the reach.** `registries[].reach` accepts `relay`
   beside `segment`. A host declared `relay` is a reachable registry for the refusal of
   ADR-0029 decision 2: a claim whose image names a registry that is neither `segment` nor
   `relay` is refused with `400` and the reachable registries named, as soon as the broker has
   `gateways`. A credential on a `relay` entry is allowed (the TLS is the registry's, end to
   end, unlike a plain-HTTP mirror, ADR-0022), read-only and scoped to the pool's images.

6. **The registry side is least privilege, and it is the operator's.** The leg is L4: it cannot
   restrict paths, so the server must. The deployment points the leg at a repository dedicated
   to the pool's images, read-only to the identity the pool uses (anonymous, or the
   broker-supplied credential of ADR-0022), and claims name images by digest (a tag is the
   registry's word, a digest is the bytes the guest verified; threat model R-14). The deploying
   guide says this and lists what a general-purpose remote repository would expose instead.

7. **Defence in depth, listed so each layer can be checked on its own.** (a) The leg's upstream
   is fixed by address in a reviewed template. (b) The gateway filter admits the port only to the
   sandbox range, with a per-source cap. (c) The host table admits the destination to uid 0 only.
   (d) The jail's table does not list it. (e) The broker refuses an image from an undeclared
   registry. (f) The pull runs before the jail, bounded at fifteen seconds, into a tmpfs mounted
   `nosuid,nodev` (ADR-0021). (g) The registry serves one read-only repository, by digest. Losing
   any one of (b) to (d) leaves the other two standing between the jail and the leg.

8. **What is not decided here.** Whether the registry serves its own blobs (Artifactory and
   several others can be configured to redirect downloads to cloud storage, which this leg
   refuses by decision 2); the live proof settles it for the operator's registry, and the guide
   records the setting. A pull window that opens the host table's rule only for the duration of a
   pull is possible and deferred: it adds a moving part in a root process for a bound the uid
   match already gives. The egress proxy's own allowlist, the static one of a gateway without the
   authorizer, is a separate surface (ADR-0028); this ADR neither widens nor narrows it, and the
   deploying guide states that a deployment on the static list lets every claim through the proxy
   to the hosts on it.

## Consequences

- A deployment with a registry it cannot place on the segment can run claims. The example images,
  served by the operator's pull-through mirror, are runnable on a gateway-era pool.
- The relay's surface grows by one fixed upstream and one port. It still has no identity, no
  socket and no credential; the per-source cap bounds each source on 3132 as on the others.
- The pool VM's root gains one destination, to the gateway, and only root. A compromise of the
  guest process (root) can reach the registry, as it could already reach the broker and the
  SPIRE server; the jail cannot, by two independent rules. The threat model extends TB-15 with
  the registry leg (rows for spoofing the registry, tampering with an image in transit, a jail
  reaching the leg, a redirect to an unlisted host, an over-broad repository) and records the
  repository scoping as the control that is not in this repository's `deploy/`, with its owner.
- `MEDIATORE_RELAY_REGISTRIES` (guest), `RELAY_REGISTRY_PORT`, `REGISTRY_ADDRESS` and
  `REGISTRY_PORT` (gateway) are new names; a deployment that sets none behaves as before,
  and the host table emits no new rule.
- A registry that redirects blobs to a host the pool cannot reach still fails the claim, with the
  reason in the log and the claim `Failed`, not a hang.

## Alternatives rejected

- **A registry on the segment.** Still the better answer where a host can be placed there
  (ADR-0029 decision 1, built, `reach: segment`); this ADR is for the environment that cannot.
- **Baking the image into the pool image.** Proves a claim once; it is not a pull, it
  freezes the workload at image-build time and moves image review to the image's build.
- **The pull through the egress proxy.** It would put root's pull behind the notaio policy of a
  claim that does not exist yet (the pull precedes the jail and the claim's ruleset), and make
  the proxy's allowlist carry the registry for every claim. The pull is a destination of the
  guest, not of the workload (ADR-0021 decision 5).
- **Admitting the registry to every uid in the host table, as the other relay ports are.** The
  other legs are used by the guest and the agent, which are not the workload's uid; the registry
  is used by root alone, so the rule says so, and a jail table that later loses its own bound
  does not become a path to the registry.
- **A host name in the host table.** Refused by ADR-0029: the segment has no resolver and a name
  would be a rule that admits nothing while looking like one. The guest's mapping carries the
  name; the table carries the address.
- **Listening on 443 so the image reference needs no mapping.** A listener below 1024 needs a
  capability or a host-wide change to the unprivileged port range on a gateway whose relay has
  none by design (ADR-0028 decision 8); the mapping in the guest costs nothing on the gateway.
- **A pull window.** Deferred, decision 8.
