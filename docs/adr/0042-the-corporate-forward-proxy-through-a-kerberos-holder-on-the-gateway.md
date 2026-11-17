<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0042: The corporate forward proxy, reached through a Kerberos holder on the gateway

**Status:** Accepted 2026-11-15, implementation deferred (use of the proxy will be very rare, so it is built only when a concrete destination with no Artifactory mirror is named; decision 0 holds now) · **Date:** 2026-11-15

Roadmap 10 (the gateway). Adds a second kind of upstream path beside the direct one of
[ADR-0028](0028-egress-gateway-envoy-with-spiffe-identity.md): for a destination the gateway cannot
reach directly, the tunnel continues through the organisation's forward proxy
(`proxy.home.example:8080`), which authenticates its clients with Kerberos. Keeps ADR-0028
decision 9 whole (no TLS interception, no certificate authority minted) and ADR-0040's division
of processes (the process that carries every tunnel never holds a credential). Related to
[ADR-0040](0040-the-gateway-places-an-audiences-credential-the-pool-never-holds-it.md) by shape
(a credential the pool VM never holds, held at the gateway) and different from it in kind: a
Kerberos ticket is negotiated per connection, so it is not a header the gateway can add to a
request. Changes no SPIFFE ID of a claim, no route shape on the broker, no claim API. Adds one
process and user on the gateway, one SPIRE entry, one gateway environment setting and one
policy-side label.

## Context

The sandbox's egress today is `claim → gateway → host`, where the gateway dials the host itself
(ADR-0028). That reaches Artifactory (the registries and the PyPI mirror), `git.home.example`
and `ghe.example.com`, which are on the internal network. It does not reach the internet: the
organisation's route to the internet is a forward proxy, `proxy.home.example:8080`, and the proxy
requires Kerberos (SPNEGO, `Proxy-Authenticate: Negotiate`).

Facts established 2026-11-15, and facts still to be confirmed:

- Envoy (the pinned 1.40.x) can tunnel to an upstream proxy with `CONNECT` (`tunneling_config` on a
  TCP proxy) and can add static headers to that `CONNECT`. It has no SPNEGO client. A Negotiate token is
  produced per connection from a service ticket, is not reusable across connections in general
  (servers keep a replay cache), and so cannot be a static header or one fetched once a minute as in
  ADR-0040 decision 5.
- Mediatore has no Kerberos code. A search of the repository finds Kerberos mentioned only in
  ADR-0007, ADR-0028, the threat model and the testing guide, as a thing it is not. (As of
  2026-11-17 those mentions are gone too: Kerberos appears in ADR-0041 and this ADR alone.)
- The operator has said the credential could be injected as for the Anthropic audience, with
  OpenBao holding it, or the gateway could proxy to the proxy through Envoy. This ADR takes the second
  with the first's rule (OpenBao holds the secret) and says why neither alone is enough.
- **Not yet confirmed (open questions 1 to 5):** which destinations need the proxy; whether a service
  account with a keytab exists for the gateways; the proxy's accepted schemes (Negotiate only, or NTLM
  too); which destinations and ports the proxy lets `CONNECT` reach; whether the gateway VMs can open
  `proxy.home.example:8080` at all (the gateways' own firewall, ADR-0028, and the network between).

## Decision

0. **Package registries never use the proxy: every Docker, OCI, Rust and PyPI source is an Artifactory
   mirror.** The operator's rule, 2026-11-15: all container and OCI registries, crates (Rust) and
   Python indexes MUST be reached through Artifactory (for example `pypi.mirror.example.com`,
   `docker.mirror.example.com`), so a policy lists the mirror's host and never `pypi.org`,
   `crates.io`, `docker.io`, `ghcr.io` or their file hosts, and `PROXY_VIA_ENDPOINTS` never contains one.
   The forward proxy is the exception path for a destination that has no mirror and is expected to be
   rare. Because of that this ADR is deferred: nothing is built until a concrete destination is named
   (open question 1), and the gateway runs without the holder, as decision 1's empty setting says.

1. **A destination is reached through the proxy only when the gateway's configuration says so, per
   host.** `INJECT_*`-style, reviewed like a relay leg (ADR-0027): a gateway setting
   `PROXY_VIA_ENDPOINTS` lists the exact `host:port` entries that go through `oproxy`; every other
   authority is dialled directly as today. The policy still decides whether a claim may reach the host
   (an audience's `egress` and the exposure ceiling, unchanged). The sandbox never names the proxy and
   a policy never lists `proxy.home.example:8080`: the proxy is the gateway's means of reaching a host,
   not a host a claim may talk to. A claim that tried `proxy.home.example:8080` as an authority is
   refused by the authorizer like any host not in its policy.

2. **A Kerberos holder: `mediatore-oproxy`, a process and a user of its own.** The data plane `envoy`
   (ADR-0028) keeps no credential and does no Kerberos. For an authority in `PROXY_VIA_ENDPOINTS` its
   route points at a static cluster whose only endpoint is the holder on loopback
   (`127.0.0.1:OPROXY_PORT`), with `tunneling_config` so Envoy sends the claim's `CONNECT host:443` to the
   holder as an HTTP `CONNECT`. The holder:

   - accepts `CONNECT` only from loopback and only for an authority in `PROXY_VIA_ENDPOINTS`
     (a second, local check beside the authorizer's);
   - holds the Kerberos credential for a **service account** (decision 4), obtains and renews its
     ticket-granting ticket from the keytab, and gets the service ticket for
     `HTTP/proxy.home.example` itself;
   - dials `proxy.home.example:8080`, sends `CONNECT host:443` with `Proxy-Authorization: Negotiate <token>`
     (a fresh token per connection), and on `200` splices the two sockets: ciphertext in, ciphertext out,
     as `envoy-relay` does (ADR-0027). It never sees plaintext: the claim's TLS to the upstream runs
     end to end inside the tunnel (ADR-0028 decision 9);
   - logs one line per tunnel: the claim UID Envoy passes in a header, the authority, the proxy's status,
     bytes each way, never a ticket or token.

   | Process | Identity | Credential | Role |
   | --- | --- | --- | --- |
   | `envoy-relay` (ADR-0027) | none | never | control-plane legs, ciphertext |
   | `envoy` (ADR-0028) | gateway SVID | never | mutual TLS to claims, `CONNECT`, `ext_authz`, chains to the holder |
   | `envoy-inject` (ADR-0040) | gateway SVID | transient, in a header | HTTP-level credential placement |
   | `mediatore-oproxy` (new) | its own SVID | the service account's keytab | Kerberos to the forward proxy, ciphertext splice |

3. **OpenBao holds the keytab; the gateway holds the ticket, in memory.** The keytab is stored in
   OpenBao and fetched by the holder at start and on renewal over a JWT-SVID (the holder's SPIFFE ID,
   by the same Kerberos-free SPIFFE-to-OpenBao path ADR-0015 uses for the broker; a correction,
   2026-11-17: ADR-0015's broker path is OpenBao's Kubernetes auth with a projected ServiceAccount
   token, so the holder, a VM process with no ServiceAccount, needs a JWT auth role for its JWT-SVID,
   a new role beside that one). It is written to no
   disk (a `memfd`, or held in the process), the unit has no `ProtectHome` exception, no
   `PrivateTmp` leak and no core dump (`LimitCORE=0`), and the ticket cache is in memory. A keytab on
   the gateway's disk is rejected (Alternatives). The holder asks for the keytab again when the
   ticket-granting ticket is within a quarter of its life of expiry; if OpenBao is unreachable it
   keeps working until the ticket expires and then refuses new tunnels (fail closed, `502`), and the
   gateway's `/ready` reports it.

4. **The identity at the proxy is a service account, not the person.** Every claim reaches `oproxy`
   as the same Kerberos principal. A person's own Kerberos credential would need their ticket-granting
   ticket on the broker or constrained delegation (S4U2proxy) set up for the gateway's account, and
   neither is justified for reaching a package mirror on the internet. Attribution therefore stays where
   it is today: the gateway's per-tunnel log carries the claim SPIFFE ID and the broker's log carries the
   subject, and the holder's line carries the same claim UID, so a request in `oproxy`'s own log by the
   service account is matched to a claim by time and authority. The service account is named in the
   deployment's configuration (`OPROXY_PRINCIPAL`), not in the repository's. Per-person Kerberos is
   open question 6.

5. **The policy is unchanged; the ceiling needs one reviewed fact.** An audience's `egress` lists the
   destination (`pypi.org:443`), exactly as for a directly reached host, and the exposure ceiling lists
   it with a Security approval. That the gateway reaches it through `oproxy` is a gateway setting
   (decision 1), reviewed in the gateway repository, because it widens what the gateway can reach: the
   proxy permits whatever its own policy allows the service account, which may be more than the
   sandbox's. The holder therefore refuses any authority not in `PROXY_VIA_ENDPOINTS` even if the
   proxy would allow it (decision 2), so the sandbox's reach is bounded by the gateway's list and the
   claim's policy, not by what the proxy permits.

6. **A request to a host the gateway reaches directly never touches the holder.** Routing is by
   authority, per decision 1, and a destination not in `PROXY_VIA_ENDPOINTS` is dialled as before.
   Nothing about the registry leg, the control relay, Artifactory, `gitserver` or `ghe.example.com`
   changes, so a fault in the holder cannot take down a claim's access to internal hosts.

7. **One SPIRE entry, one firewall rule.** `mediatore-oproxy` runs as a static user and takes its SVID
   from the agent socket by `unix:user:mediatore-oproxy`, a fourth entry for a gateway SPIFFE ID (or
   its own SPIFFE ID, `spiffe://<td>/gateway-oproxy`, preferred so the OpenBao role binds to it alone;
   decided at the ADD cycle). The gateway's firewall (ADR-0028) allows the holder's user, and only it,
   to open `proxy.home.example:8080`; `envoy` and `envoy-inject` cannot. A claim's tunnel can reach the
   forward proxy only by passing the authorizer and the holder.

8. **A claim sees no difference.** The workload's `$MEDIATORE_EGRESS_PROXY/<host>/...` (ADR-0025,
   ADR-0035) is unchanged, and so is the claim's mutual TLS to the gateway; the proxy chain is entirely
   on the gateway side. A failure of the chain is `502` (the holder could not authenticate or the proxy
   refused) or `403` (the authorizer or holder refused), with a header (`x-mediatore-refusal:
   oproxy_refused`) a workload can tell apart from an unreachable host.

## Consequences

- The sandbox reaches the internet through the organisation's forward proxy without the pool VM,
  the jail, the broker or Envoy holding a Kerberos credential. The credential is at the gateway, in one
  process of its own, in memory.
- The gateway gains a process that is a second place an attacker would aim at on a compromised
  gateway VM: the service account's keytab (in memory) and a ticket. Root on a gateway is as
  powerful as it already is (it holds the gateway SVID and the relay), but this adds a credential that
  is not claim-scoped, so its exposure is for the operator to accept, with a service account scoped
  to the proxy and nothing else.
- The proxy's own log shows one principal for every claim; attribution depends on the gateway's logs
  (decision 4).
- The mediatore binary gains a role (`mediatore oproxy`), a SPNEGO client (a library, not a fork of
  `curl` or `px`), and a dependency on a Kerberos implementation (the system's `libgssapi` or a Rust
  one), each reviewed. The gateway image gains `libgssapi-krb5` and a `krb5.conf`, which the
  deployment owns.
- A destination not in `PROXY_VIA_ENDPOINTS` is unaffected, so the feature can be absent and the
  gateway behaves as today (the setting empty means no holder is started).

## Alternatives rejected

- **Envoy alone, with a static `Proxy-Authorization` header.** Envoy cannot produce a Negotiate token,
  and a token fetched elsewhere and placed as a static header is per-connection and rejected on
  reuse by a server with a replay cache. It would work only for Basic, which the proxy does not
  accept.
- **Credential injection as in ADR-0040.** That ADR's placement adds a header to a request Envoy can read,
  at the HTTP layer after originating TLS. Here the tunnel is `CONNECT` to a proxy and the client's TLS
  is end to end (ADR-0028 decision 9); there is no request to place a header on, and a per-connection
  token is not a value the authorizer can hand over once.
- **A keytab on the gateway's disk.** Simple and survives an OpenBao outage; it is a long-lived,
  copyable credential at rest on every gateway, in backups and in the image's build context. Decision 3
  keeps it in OpenBao and in memory.
- **A Kerberos ticket per person (S4U or delegated TGT).** Attribution at the proxy for a mirror of
  public packages does not justify a delegated credential. Open question 6 for a destination that does.
- **Run the holder as a sidecar of each pool VM.** The ticket would be on the VM the sandbox runs on,
  against the premise of ADR-0040; and the VM has no route to the proxy (ADR-0028).
- **A second `oproxy` with a different authentication scheme.** Out of scope until open question 3 is
  answered.

## What was proven, and what was not

Nothing in this ADR is implemented or tested. What was observed 2026-11-15, relevant to it:

- The gateways, on mediatore 0.2.6, carry a claim's tunnel to an internal host (Artifactory and its
  PyPI mirror, `git.home.example`) and refuse a host not in its policy.
- Envoy's `tunneling_config` and the three-process division of ADR-0040 are as described there; the
  chaining to a loopback holder is a design, not a spike. The ADD cycle (ADR-0040 decision 10)
  starts with the spike that fixes it: Envoy 1.40.x tunnelling `CONNECT` to a holder on loopback, and the
  holder to a stand-in proxy that demands Negotiate (an MIT Kerberos KDC in the test).

## Open questions

1. **Which destinations need the proxy?** The list for `PROXY_VIA_ENDPOINTS`. Answered in part by
   decision 0: no package registry; what remains is a destination with no Artifactory mirror, to be
   named when one appears. Internal hosts do not need it.
2. **Is there a service account with a keytab for the gateways?** Its name, its realm, the SPN of the
   proxy (`HTTP/proxy.home.example`), and who rotates the keytab. Without it there is nothing to hold.
3. **What does `oproxy` accept?** Negotiate only, or NTLM as well; whether it lets `CONNECT` reach
   any port or only 443; whether it filters by destination or by category, and so which destinations
   would be refused by the proxy though the claim's policy allows them.
4. **Can the gateways reach it?** Whether the gateway VMs' network path and the firewall (ADR-0028)
   admit `proxy.home.example:8080` from the gateway addresses, and whether DNS and time (Kerberos allows
   five minutes of skew) are right on the gateways.
5. **OpenBao.** Whether the keytab fits a KV path with a role the holder's SPIFFE ID can read, and
   whether the operator will accept a keytab in OpenBao at all (the alternative is a short-lived
   password the holder uses to obtain the ticket, with the same exposure).
6. **Per-person Kerberos.** Needed only if the proxy's log must name the person. Constrained
   delegation for the gateway's account (S4U2proxy) is the shape; costly and not proposed.
7. **Is the proxy needed at all for the sandbox?** Answered 2026-11-15: rarely (decision 0). The ADR
   stays as the recorded design for that case; if no destination is ever named, mark it Rejected.
