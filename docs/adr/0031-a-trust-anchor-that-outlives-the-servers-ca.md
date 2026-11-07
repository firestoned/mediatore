<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0031: The agent's trust anchor outlives the server's CA: OpenBao's PKI as the upstream authority

**Status:** Proposed · **Date:** 2026-11-07

Roadmap 02 (the server) and roadmap 06 (the layer that carries the bundle). Amends
[ADR-0027](0027-control-plane-relay-on-the-egress-gateway.md) decision 3 (what the bundle the
agent starts with is good for) and fills in the `UpstreamAuthority` that
[ADR-0005](0005-spire-topology.md) names for the root server, in the homelab collapse where
one server plays every role. Changes no token shape, no SPIFFE ID, no entry shape and no
storage contract: what changes is which certificate the deployment's layer hands a member
as its anchor, and where the key behind it lives.

## Context

A pool member or a gateway VM authenticates the SPIRE server on its first boot with the
bundle the deployment's cloud-config layer writes to `/etc/spire/bundle.pem`
([ADR-0023](0023-sandbox-vm-image-kairos-derivative.md) decision 3: the image carries no
bundle, the layer does). After attestation the agent receives every later bundle over the
attested channel; the layer's copy matters for first boots alone.

The server, as deployed (the ADR-0005 collapse: one server, no root above it, no upstream
authority), signs with a **self-signed CA that rotates every `ca_ttl`**, 24 hours, the
chart's default (`dev/kind/spire/spire.yaml` carries the same value). SPIRE prepares the
next CA halfway through the current one's life and publishes both in the bundle, so a layer
built at some instant verifies the server until the CA current at that instant retires:
under 24 hours, and in the one measurement taken (the live run of 2026-11-05, roadmap 06)
about 22. Past that, **a member that boots for the first time trusts no certificate the
server can present**, the agent logs a verification failure, the node never registers, the
pool recycles it, and the next member fails the same way: a pool that churns until the
operator rebuilds the layer. Two release candidates hit this in a row (rc.3, then rc.4), the
relay of ADR-0027 removes nothing of it (its decision 3 says so), and the deploying guide
asks the operator to rebuild daily, which is not a control.

The threat model carries this topology as accepted risk R-7: no root, no upstream
authority, the signing key in plaintext on a node-local volume where sandboxes are
administered.

What SPIRE offers (1.15.3):

- **An `UpstreamAuthority` plugin.** The server's CA becomes an intermediate signed by the
  upstream, rotating every `ca_ttl` under a root the upstream holds. Since SPIRE 0.11.0 the
  server *always* uses the upstream bundle as the trust bundle (the `upstream_bundle`
  switch was removed, #1702): agents anchor on the upstream root and never see the
  intermediates rotate. Plugins: `disk`, `vault`, `cert-manager`, `spire`, the cloud CAs.
  The `vault` plugin calls the PKI engine's `root/sign-intermediate` and supports
  Kubernetes auth; it does not publish JWT keys, which matters only to nested topologies
  using JWT-SVIDs (mediatore issues none).
- **Agent bootstrap options**, mutually exclusive: `trust_bundle_path` (what the layer
  does today), `trust_bundle_url` (over `https://` with a certificate the agent can verify,
  or `http://` over a unix socket), `insecure_bootstrap` (the server unauthenticated on
  first contact; SPIRE's own documentation warns that an attacker in the path then
  controls the infrastructure).

OpenBao is already in the architecture: [ADR-0015](0015-transit-sealer.md) places it
beside the broker for the refresh envelopes' sealing key, the kind tier runs it
(`make kind-openbao`, over TLS, Kubernetes auth), and notaio signs its bundles with it
([ADR-0026](0026-notaio-bundles-verified-in-shadow.md)). Its PKI engine keeps Vault's API
and the `root/sign-intermediate` path, which the SPIRE plugin uses.

## Decision

1. **The anchor the layer carries is a root that lives for years, not the server's
   signing CA.** The SPIRE server (the one server in the collapse; the root server where
   the ADR-0005 topology is deployed, which already names an `UpstreamAuthority` for it)
   runs the `vault` `UpstreamAuthority` against an OpenBao PKI mount. The server's CA is an
   intermediate signed by that mount, `ca_ttl` stays 24 hours (at or under the mount's
   maximum lease), and the bundle the server publishes, hence `bundle.pem` in every layer,
   holds the OpenBao root. A layer stays good for as long as the root does.

2. **OpenBao is the authority, not the `disk` plugin.** With `disk` the root's private key
   sits on the server's volume, the place today's key sits, and R-7 stands unchanged. With
   OpenBao the root key never leaves the PKI engine; the server holds a Kubernetes-auth
   role whose policy grants `update` on `<mount>/root/sign-intermediate` and nothing else,
   and every signing is in OpenBao's audit log. The same OpenBao that ADR-0015 deploys, a
   second mount; where ADR-0015 is not yet deployed (the homelab cluster today), it comes
   first.

3. **The root.** An EC P-384 key, ten years (`87600h`), common name the trust domain's
   name, the mount's maximum lease long enough for the intermediates; its certificate is
   what `bundle.pem` holds, and what `spire-server bundle show` prints once the switch
   has settled. The root's renewal is a documented operation years out, not a daily one.

4. **The agent does not change.** `trust_bundle_path` in `image/spire/agent.conf` stays,
   PEM format, written by the layer at every boot (ADR-0023 decision 3). Rejected:
   `trust_bundle_url`, because an endpoint the agent could verify needs a certificate from
   an anchor the agent already holds, which is the problem moved, and a unix-socket helper
   would need the same anchor to fetch from anywhere; `insecure_bootstrap`, because a host
   on the segment could stand in for the server at a member's first boot, which is
   exactly what the anchor exists to refuse (the fail-closed rule).

5. **The switch has no cliff.** After the server starts under the upstream authority its
   bundle holds the OpenBao root and, until the old CA retires one `ca_ttl` later, the
   self-signed CA; running agents receive that bundle over the attested channel and are
   unaffected; a layer built with the old CA alone still verifies the server for the
   remainder of that CA's life; a layer built from the new bundle carries the root and
   needs no rebuild again for this reason. One rebuild of the layer, the last one.

6. **Proven in kind, on the TPM path.** `make kind-openbao` enables a PKI mount with a
   root and the policy and role of decision 2; `make kind-spire` renders the server with
   the `vault` `UpstreamAuthority` (Kubernetes auth, the OpenBao CA from its ConfigMap).
   `make kind-e2e-tpm` then starts the agent with a bundle holding the OpenBao root alone,
   the server's own CA deliberately absent from it, and the node attests; a check reads
   `bundle show` and asserts its roots are the OpenBao root and nothing self-signed.
   `dev/kind/spire/` and the server configuration are the TPM attestation path, so the
   tier runs on the build host before the change is handed back (`rules/testing.md`).

7. **Deployed as a component.** `deploy/spire-upstream/`: the `server.conf` fragment with
   the `UpstreamAuthority "vault"` block (address, mount, CA reference and role as
   placeholders), the projected ServiceAccount token it authenticates with; the deploying
   guide gains the OpenBao side (mount, root, policy, role) and the migration of
   decision 5 as a runbook part, replacing "rebuild the layer daily".

## Consequences

- The first-boot window closes: a layer verifies the server for the root's life, a pool
  recycling after a day stops churning, and the ADR-0027 decision 3 sentence "an image
  whose bundle shares no root with the server's fails closed and needs a rebuild" keeps
  its truth but stops describing a daily event.
- **R-7 narrows.** The signing key that was the root is in OpenBao's PKI engine; what stays
  online on the server's volume is a 24-hour intermediate's key, revocable from above by
  refusing to sign the next one. The row's "no upstream authority" clause goes; its "one
  flat trust domain on the management cluster" stays until the ADR-0005 split.
- **OpenBao joins the identity plane's dependencies.** If OpenBao is unreachable when the
  server prepares its next intermediate (halfway through `ca_ttl`, so twelve hours of
  slack), the server logs the failure and keeps signing with the current CA until it
  expires; SVIDs already issued run to their own TTL. An OpenBao outage longer than half a
  `ca_ttl` stops new identities. The deploying guide says so, and the OpenBao deployment
  of ADR-0015 is sized for it (two replicas, the same storage class as the server's).
- The kind tier grows one setup step and one assertion; CI time by a few seconds.
- The ADR-0005 topology gets its upstream authority for real; the enterprise split later
  moves the plugin to the root server and leaves this cluster's server as a nested one,
  with no change to any member.

## Alternatives rejected

- **A longer self-signed `ca_ttl`** (a year): a values change and nothing else. It moves
  the cliff, it does not remove it, and it leaves a long-lived signing key in plaintext on
  a node volume, widening R-7 instead of narrowing it.
- **The `disk` upstream authority** with a long-lived root in a Secret: closes the window,
  leaves the root key where today's key is (decision 2).
- **Rebuilding the layer daily**, as the guide says now: an operator chore standing in for
  a control; it is what this ADR replaces.
- **The full ADR-0005 tier** (a root SPIRE server on its own cluster): the right end state
  and out of scope for the homelab collapse; this ADR is its first step and does not
  preclude it.

## Implementation notes

To be filled when implemented: the component's files, the kind targets, the tier's
assertion, the migration as performed, the threat-model pass (R-7 revised, TB-6 and TB-12
rows for the server's new upstream call, the CALM relationship from `service-spire-server`
to `service-openbao`).
