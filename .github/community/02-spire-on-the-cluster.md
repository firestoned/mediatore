<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 02: SPIRE on the homelab cluster

**Status: in progress.** Runbook Parts 1 to 3 on the banlieue management cluster (the
ADR-0005 homelab collapse: one server playing the downstream role). The enterprise
split is documented in `docs/guides/enterprise-spire-topology.md` and is not this
roadmap.

Measured on the cluster on 2026-10-21, before any item below was checked off: the
`spiffe/spire` chart runs the server (1.15.3, PostgreSQL datastore over `verify-full`,
RSA-2048 CA, 24 h CA TTL, audit log off: threat model R-7), the controller manager
(0.7.0, class `spire-server-spire`, `watchClassless: false`), agents and the CSI driver
on every node; the only node attestor is `k8s_psat`, and the only ClusterSPIFFEIDs are
the chart's. banlieue's claim subject policy already names the issuers (Dex with GitHub
behind it, Google, Auth0) with their username prefixes. Dex runs on the cluster behind
the Tailscale operator with a `kubernetes` client only; nothing of mediatore is
installed beyond a `ServiceAccount` a live test left behind.

## First half: the broker on the cluster (no VM attests yet)

- [x] A deployable overlay for the single-cluster shape, with placeholders only
      (`deploy/overlays/homelab-example`, 2026-10-21): one replica on a SQLite PVC, the
      local sealer, the user API behind the Tailscale ingress class instead of Traefik,
      the sandbox listener as a MetalLB LoadBalancer, the image pinned by the operator;
      the real copy lives outside the repository (`docs/guides/deploying.md`)
- [x] `NetworkPolicy` for the broker pods (ADR-0007 decision 7, from roadmap 01):
      ingress 8443 from the sandbox segment's CIDR only, 8080 from the ingress
      controller's namespace only; egress to DNS, the API server and the issuer
      (`deploy/overlays/homelab-example/networkpolicy.yaml`; the deploying guide has
      the table)
- [x] A `mediatore` public client in the cluster's Dex (its Helm values, not this repo),
      the overlay's copy filled in, the three Secrets created, `kubectl apply -k`. In place
      since the 2026-10-31 run; every live claim since logged in through it
- [ ] `make live-admission-test` against the cluster as the broker's ServiceAccount
      (needs `deploy/base`'s ServiceAccount, RBAC and admission policy applied first)
- [x] `mediatore login` at the cluster's Dex and `sandbox create` through the Tailscale
      ingress: the `AgentSandbox` created, the claim owned, `Pending` until a pool
      member attests (the second half). Done 2026-10-31 (rc.3) and again 2026-11-05
      (rc.4, through the egress gateways): login at the cluster's Dex, the claim bound
      to an attested member, the tokens minted. One limit found: Dex's GitHub connector
      refreshes an identity with the GitHub token it stored at login, so a session older
      than that token's life cannot mint tokens any more (the broker says
      `upstream_unavailable`, the proxy fails closed); log in shortly before claiming

## Second half: VMs attest ([ADR-0018](../../docs/adr/0018-tpm-attestation-with-the-spiffe-plugin.md))

- [x] ~~Build the SPIRE server image with the bloomberg/spire-tpm-plugin server attestor~~
      Withdrawn (2026-10-22): the Bloomberg repository is archived; its continuation
      `spiffe/spire-tpm-plugin` ships static binaries as images, and SPIRE verifies an
      external plugin's checksum at load, so an init container from the pinned image
      replaces the image build. `deploy/spire-tpm` is the kustomize component (the
      StatefulSet patch, the EK CA ConfigMap, the `server.conf` fragment), v1.11.3 by
      digest and checksum; `make dist-tpm-plugin` extracts the binaries
- [x] ~~swtpm fleet EK CA generated; root into the `ek-ca` ConfigMap~~ Replaced
      (2026-10-22): libvirt already signs every vTPM's EK certificate with the host's
      `swtpm-localca`; the EK trust bundle is one root per hypervisor host in ConfigMap
      `spire-tpm-ek-cas` (ADR-0018 decision 2). The hash allowlist stays empty
- [x] The agent's side as image fragments (2026-10-22): `image/spire/agent.conf` with
      the `tpm` attestor (the same release, its checksum), the `unix` workload attestor
      and the trust bundle path; `image/systemd/spire-agent.service` allowing the TPM
      devices and nothing else
- [ ] The cluster's SPIRE manifests rendered once from its distribution into a tracked
      kustomization (the Helm release it was installed with retired), the component
      included with the three hosts' CAs and the `server.conf` block, `kubectl apply -k`;
      `tpm` listed among the server's node attestors
- [x] `make kind-spire` moved from a Helm release to rendered manifests (2026-10-22):
      `dev/kind/spire` is SPIRE's distribution rendered once by `make kind-spire-render`
      (`helm template`, no hooks, the only target that runs Helm), the `deploy/spire-tpm`
      component included, the `server.conf` patch generated from the component's
      fragment; `make kind-spire` applies it with kustomize, sets the webhook to fail
      closed as the chart's hook did, and asserts that the server loaded the `tpm`
      attestor. CI no longer needs Helm
- [x] ~~Trust bundle exported for the VM image (Part 1.5): `spire-server bundle show`
      into `/opt/spire/conf/bundle.pem`~~ Superseded by ADR-0031 (next item): the layer
      carries the OpenBao root alone, not the server's bundle, and never goes stale
      with the server's CA
- [x] ADR-0031 (accepted and built 2026-11-07): the anchor the layer carries outlives the
      server's CA. OpenBao's PKI as the `vault` upstream authority (`deploy/spire-upstream`,
      the fragment, the CA mount, the projected token), the server's CA a 24-hour
      intermediate under a ten-year P-384 root (the mount capping intermediates at a
      week), the layer holding the root; every kind tier runs under it and
      `make kind-e2e-tpm` attests from a bundle with the root alone, asserting the
      server's bundle is that root; the OpenBao side and the no-cliff migration in the
      deploying guide. Closes the first-boot window the live runs of rc.3 and rc.4 hit
      (a layer good for one `ca_ttl`, the pool churning past it); R-7 narrows
- [x] ADR-0031 on the homelab cluster: the `spire` PKI mount, root, policy and role on the
      OpenBao already there (notaio's, ADR-0004), the server (a Helm release there) given
      the chart's `upstreamAuthority.vault` values, a new authority prepared and activated
      on each server so the root entered the bundle at once, one last layer rebuild (both
      ISOs) with the root alone; the pool's image moved and its members recycled onto it.
      Done 2026-11-08: the first recycled member booted with the root as its whole bundle,
      attested as `tpm` and announced `GuestReady`. Found on the way: a server that already
      has a CA keeps it across the upgrade until it prepares its next one, and its serving
      certificate stays until its half-life (the guide now carries the rotation and the
      restart)
- [ ] The VM image with the agent, the plugin from `dist/` and the fragments baked by
      banlieue-imagebuilder (roadmap 06's image item; the mediatore side is `image/`)
- [x] Part 3 acceptance on libvirt: a fresh member appears in `agent list` as type
      `tpm` within 60 s, EK hash matches the local computation, reboot does not create
      a second agent. Done 2026-10-31 and 2026-11-05: every member and every gateway
      attested as `tpm` with the ID the broker had declared from the EK banlieue read,
      the reboot kept the agent ID (roadmap 06's live item)
- [x] The broker Deployment on the agent's Workload API socket proven as
      `make kind-e2e-mtls` does in kind, against this cluster: a sandbox turning `Ready`,
      the guest fetching its subject, a token issued to the workload. Done 2026-11-08
      (rc.6): the broker's own SVID from the Workload API, the sandbox `Bound` and ready,
      `subject fetched` on the member, `token issued` for the audience and the 200 at the
      upstream with it (roadmap 06's live item has the run)
- [x] A kind tier for the attestation path (2026-10-23): the kind node carries a vTPM
      (`make kind-vtpm`: swtpm behind the kernel's vtpm proxy on the host, a throwaway
      swtpm local CA for its EK, the device mounted into the node at creation);
      `make kind-e2e-tpm` runs a pod on `image/spire/agent.conf` with the pinned agent
      plugin, refused under a CA that never signed its EK, attested as
      `spiffe://<td>/spire/agent/tpm/<hash>` under the right one with the hash mediatore
      computes, the member's certificate becoming the node entry under that agent and the
      guest registering over the SVID it issues, a fresh pod re-attesting as the same
      agent; by hand on a host whose kernel has `tpm_vtpm_proxy` (GitHub's Azure runners
      do not ship it). What it found: the EK is signed by the local CA's issuing
      certificate (`issuercert.pem`), not its root, and the plugin takes no intermediates,
      so the bundle must carry the issuing certificate; the docs and `ek-cas.yaml` fixed
