<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0037: The pool fetches its SPIRE bundle at boot, through a third leg of the control relay

**Status:** Accepted, implemented in the repository 2026-11-14 (the relay's third leg, the host table's element, the fetch script and unit, their pinned tests; the live proof is a gateway and a pool member booted from the images that carry them) · **Date:** 2026-11-14

Roadmap 10 (the gateway) and roadmap 06 (the guest). Amends
[ADR-0027](0027-control-plane-relay-on-the-egress-gateway.md) decisions 2 and 3 (the relay has
three fixed legs, not two) and [ADR-0031](0031-a-trust-anchor-that-outlives-the-servers-ca.md)
decision 4 (`trust_bundle_url` is rejected there; for a bundle endpoint with a web PKI
certificate, the first-boot bundle is fetched, through the relay, and not baked). Changes no
token shape, no SPIFFE ID, no entry shape and no storage contract.

## Context

A pool member authenticates the SPIRE server on its first boot with a bundle the deployment's
layer carries (ADR-0023 decision 3, ADR-0027 decision 3). The server signs with a CA that
rotates every `ca_ttl`, 24 hours by default, so a bundle written into a layer at some instant
admits a first boot for under a day; past that a new member trusts nothing the server can
present, never registers, and the pool recycles it into the same failure (ADR-0031 context).
ADR-0031 fixes the cause: the server's CA becomes an intermediate under a root that lives for
years, and the layer carries the root. That needs OpenBao's PKI engine in front of the SPIRE
servers, a change to servers that are not the pool's to make, and until it lands every layer
built from `bundle show` has a life of hours.

Egress gateways already solve the same problem for themselves. A gateway's agent does not carry
a bundle: it uses `trust_bundle_url` against the SPIRE servers' bundle endpoint (the
`bundle_endpoint` block, `https_web` profile), whose certificate comes from a web PKI that the
gateway's image already trusts, and the agent verifies it by hostname. Nothing is baked, so
nothing expires. A pool member cannot do the same directly: its segment has no route and no
resolver (ADR-0010, ADR-0027 context), and it reaches the identity plane only through the
gateway's control relay. The relay has two legs, the SPIRE server's attestation port and the
broker's sandbox listener; the bundle endpoint is a third place a member needs to reach and
nothing carries it there.

## Decision

1. **The relay gains a third fixed leg, the bundle leg.** A third `tcp_proxy` listener on the
   gateway's sandbox address, `RELAY_BUNDLE_PORT` (3131), to one fixed upstream by address,
   `SPIRE_BUNDLE_ADDRESS:SPIRE_BUNDLE_PORT` (the bundle endpoint, 8443), the same shape as the
   other two (ADR-0027 decision 2): L4 pass-through, no CONNECT, no authority from the client,
   no name resolution on behalf of the sandbox, no SDS and no TLS context in the relay (the
   image check still refuses both), one access-log line per connection with `upstream=bundle`.
   The host table's `relay_ports` set admits 3131 beside 3129 and 3130 under the same
   per-source connection cap (ADR-0027 decision 5). A new upstream remained a reviewed change in
   the template, never a parameter; this is that change.

2. **The pool fetches its bundle with curl at every boot.** `image/spire-bundle-fetch`, run by
   `spire-bundle-fetch.service` (a oneshot, `After` the host table, `Before`
   `spire-agent.service`, which `Requires` it), runs one request:
   `curl --proto =https --tlsv1.2 --retry 10 --retry-all-errors --resolve
   <host>:<port>:<gateway> [--cacert <ca>] https://<host>:<port>/`. The hostname is the bundle
   endpoint's own, as its certificate names it, and it is the pin: curl verifies the
   certificate against that name and the CA set, and `--resolve` only says where to dial it,
   the segment having no resolver. The reply is the SPIFFE-format bundle the endpoint serves;
   it is checked for an `x509-svid` key (a proxy's error page or an empty body is refused and
   the previous file stays), written next to its destination and renamed, `0644`, to
   `/run/spire/bundle.json`. The agent reads it with `trust_bundle_path` and
   `trust_bundle_format = "spiffe"`. Run at every boot, from `/run`, the file is never older
   than the boot; a bundle that cannot be fetched keeps the agent down (fail closed), and the
   unit retries.

3. **The configuration is four names in the guest's env.** `/etc/mediatore-guest/env` carries
   `SPIRE_BUNDLE_HOST` (the endpoint's hostname), `SPIRE_BUNDLE_PORT` (the relay's bundle
   port), `SPIRE_BUNDLE_GATEWAY` (a gateway's sandbox address, IPv4) and optionally
   `SPIRE_BUNDLE_CA` (a PEM of the CAs the certificate chains to; the image's system store when
   unset). With `SPIRE_BUNDLE_HOST` unset the script does nothing and the unit succeeds: a
   deployment with no bundle endpoint still carries a PEM file, as before. The host table
   reads `SPIRE_BUNDLE_GATEWAY` and `SPIRE_BUNDLE_PORT` from the same file and admits that one
   address and port for the fetch, by address, with the same refusal of names (ADR-0029). The
   image carries `curl` and `ca-certificates` for it.

4. **First contact anchors on the web PKI, and this ADR says so.** Before: a bundle written by
   the operator into the layer, the SPIRE root (or the server's CA of the day) the agent
   checks the server's SVID against. After: the bundle is whatever the endpoint named by
   `SPIRE_BUNDLE_HOST` serves over a TLS connection whose certificate chains to a CA the image
   (or `SPIRE_BUNDLE_CA`) trusts. Anyone able to obtain a certificate for that hostname from
   such a CA, and to answer at the gateway's bundle port, could hand a member a bundle of their
   own at its first boot, and the member would then attest to a server of their choosing. The
   exposures that stay shut: the relay holds no key and sees ciphertext, so a compromised
   relay can drop or delay the fetch but cannot forge the reply (it has no certificate for the
   name); a host on the segment that stands in for a gateway cannot present a certificate for
   the name either, because the hostname and the CA set are the member's, not the network's;
   and after the first attestation every later bundle arrives over the attested channel
   (ADR-0027 decision 3), unchanged. This is a weaker anchor than a root only the operator
   holds. It is a stronger one than `insecure_bootstrap`, and a stronger operating posture
   than a baked bundle that expires and is refreshed by hand, which in practice means an
   image nobody can scale.

5. **It coexists with ADR-0031; neither replaces the other.** ADR-0031 rejected
   `trust_bundle_url` because the endpoint's certificate needs an anchor the agent already
   holds, "the problem moved". That holds when the endpoint's certificate is the SPIRE
   server's own. It does not hold when the endpoint presents a web PKI certificate: the anchor
   is then the CA set already in the image, a different and longer-lived trust than the
   server's CA, and it is the same one the gateways already rely on. The OpenBao upstream
   authority stays the stronger design (a root only the operator holds, in an audited engine,
   good for years, no network fetch at all) and a deployment that has it keeps
   `trust_bundle_path` with a PEM and needs no bundle leg. A deployment that has not, and
   whose endpoint has a web PKI certificate, uses this ADR in the meantime, and may use both:
   the PEM of ADR-0031 as the file and the fetch dropped.

6. **What is not decided here.** The endpoint's certificate lifecycle (its issuer, renewal and
   the CA set in the image) is the SPIRE operators'; this ADR depends on the endpoint serving
   a certificate that names `SPIRE_BUNDLE_HOST` and says so in the deploying guide. The bundle
   endpoint has several servers behind a name; the relay's upstream is one address, as the
   SPIRE leg's is.

## Consequences

- A pool layer carries no bundle and none expires: the failure ADR-0031 describes (a pool that
  churns until the layer is rebuilt) is gone for any deployment whose bundle endpoint has a
  web PKI certificate, without a change on the SPIRE servers.
- The relay's surface grows by one fixed upstream and one port. It still has no identity, no
  socket and no credential; the table's cap bounds each source on 3131 as on the other two.
- The member's first-boot trust moves from "the operator's bundle" to "the web PKI plus a
  hostname". The threat model extends TB-15 (five rows) and records the accepted risk R-24
  with its revisit condition: the OpenBao upstream root of ADR-0031 landing on the servers.
- One more boot-time dependency, `curl` against the gateway; a gateway that is down at a
  member's first boot keeps the member down until it is back (the same dependency the agent
  already has on the SPIRE leg).
- The image grows by `curl` and `ca-certificates` (the Kairos base may already carry both).

## Alternatives rejected

- **`trust_bundle_url` in the agent.** The agent's own fetch dials a name; the segment has no
  resolver and the agent has no `--resolve`. The unit that curls with the hostname and the
  address does what the agent cannot, and leaves the agent on `trust_bundle_path`.
- **`insecure_bootstrap`.** The server unauthenticated on first contact; rejected by ADR-0031
  and still.
- **Baking the bundle and refreshing the layer daily.** A chore standing in for a control; the
  pool churns the moment it is late (ADR-0031).
- **Serving the bundle from the relay itself.** The relay would then hold a copy and be the
  anchor, and an Envoy with a file to serve is an Envoy with a credential to protect; the leg
  carries the endpoint's own reply and nothing else.
- **A longer `ca_ttl` on the servers.** Moves the cliff and widens the plaintext key's life
  (ADR-0031).
