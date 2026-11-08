<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0031: The agent's trust anchor outlives the server's CA: OpenBao's PKI as the upstream authority

**Status:** Implemented · **Date:** 2026-11-07 (the homelab cluster's switch is roadmap 02's open item)

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

Implemented 2026-11-07, in the repository and in kind; the homelab cluster's switch (OpenBao
on it first, ADR-0015, then the component and the last layer rebuild of decision 5) is
roadmap 02's open item and an operator's run.

- **The component**, `deploy/spire-upstream/`: `server.conf.fragment.hcl` with the
  `UpstreamAuthority "vault"` block (`vault_addr`, `pki_mount_point`, `ca_cert_path`,
  `k8s_auth` with the mount, the role and the projected token's path, all placeholders);
  `statefulset-patch.yaml` mounting the OpenBao CA from the ConfigMap `spire-upstream-ca`
  at `/upstream/ca` and a projected ServiceAccount token (audience `openbao`, one hour) at
  `/upstream/token`; `kustomization.yaml` as a kustomize Component beside
  `deploy/spire-tpm`.
- **The kind side**: `dev/kind/openbao-setup.sh` enables the `spire` PKI mount, generates
  the P-384 ten-year root `internal` (the key never leaves OpenBao), writes its certificate
  to `.kind/openbao/upstream-root.pem`, brings the mount's maximum lease down to a week,
  writes the policy (`spire/root/sign-intermediate`, `update` only) and the Kubernetes-auth
  role bound to `spire-server/spire-server` with audience `openbao`; it is idempotent, and
  `make kind-openbao` no longer restarts the in-memory OpenBao, so the root survives a
  second `make kind-spire`. `make kind-spire` creates `spire-upstream-ca` from OpenBao's
  serving CA and applies the component; `dev/kind/spire/render-server-conf-patch.sh` reads
  the fragment and writes the `UpstreamAuthority` into the generated
  `server-conf-patch.yaml` with the in-cluster OpenBao address. Every kind tier runs its
  server under the upstream authority.
- **The tier's assertion**, `dev/kind/tpm-e2e.sh`: `UPSTREAM_ROOT` is required; the script
  reads `spire-server bundle show`, asserts its SHA-256 fingerprints equal the root file's
  (one certificate, nothing self-signed), and starts the agent with the OpenBao root alone
  as `/etc/spire/bundle.pem`. Run on the build host on 2026-11-07 against a tree with this
  change: `make kind-e2e-ci KIND_E2E_SUITES="kind-e2e-tpm kind-e2e"`, every tier PASS, the
  TPM tier's agent attested as
  `spiffe://sandbox.test/spire/agent/tpm/dbabf5bcaeb5f108598e46db585db9ed48b0bdcbcc3f57f37095fa3c52289be4`
  from a bundle holding the OpenBao root only, re-attested after a member replacement.
  Rerun of the TPM tier alone against the final tree (the mount's week-long lease cap added
  after the first launch): PASS, the agent
  `spiffe://sandbox.test/spire/agent/tpm/2586185606d62837f41cfd53250cc58270251a547337d580152c89a13da7e644`.
- **CALM**: `rel-spire-server-openbao-pki` (the server to OpenBao over HTTPS), the node
  descriptions and the ADR list in `docs/architecture/calm/architecture.json`;
  `make calm-validate` passes, the diagrams re-rendered.
- **Docs**: the deploying guide's OpenBao side (`bao` commands for the mount, the root, the
  policy, the role) and the migration of decision 5 replacing "rebuild the layer daily";
  the testing guide's tier row; README's status table; ADR-0005 and ADR-0027 marked
  Amended; roadmap 02's item ticked with the homelab switch as its next open item.
- **Threat model**, full pass stamped 2026-11-07 against ADR-0001 to ADR-0031: new boundary
  TB-16 (the server to OpenBao's PKI, eight rows), new asset A-22 (the root key), one TB-4
  row for the first-boot window the rc.3 and rc.4 live runs hit, **R-7 revised** (the key
  on the server's volume is now a 24-hour intermediate's), **R-21 new** (OpenBao as a
  dependency of CA rotation).
- **On the homelab cluster, 2026-11-08** (roadmap 02). The OpenBao of ADR-0004 was already
  there, so the PKI mount, root, policy and role went beside notaio's transit key; the
  server is a Helm release there, so decision 7's component became the chart's
  `upstreamAuthority.vault` values with the same CA ConfigMap and projected token. Two
  things the kind tier, which starts its server fresh, could not show: a server that
  already has a CA (and the next one prepared) keeps signing with it after the upgrade
  until it prepares a new authority, so the root entered the bundle only once
  `localauthority x509 prepare` and `activate` ran on each server; and after that, the
  servers' own serving certificates, issued by the old CA with a four-hour life, stayed
  until their half-life, so a member booting from the root alone logged "Trust Bundle and
  Server don't agree" until the servers were restarted and re-minted them under the new
  authority, chain included (the guide carries both steps). The first-boot window was
  live at the time, a member replaced every provisioning timeout. The last layer rebuild
  was both installer ISOs with the root alone; the pool's image moved to the new one and
  its members recycled onto it. The proof: the endpoint presents the serving certificate
  and the OpenBao-signed intermediate, and `openssl verify` against the root alone passes;
  the first recycled member's `/etc/spire/bundle.pem` holds one certificate, the root, and
  its agent attested as `tpm/cbe86780…` within three minutes of the servers' restart, the
  node entry declared and `GuestReady` announced. The pool's churn stopped there.
