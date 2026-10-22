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
- [ ] A `mediatore` public client in the cluster's Dex (its Helm values, not this repo),
      the overlay's copy filled in, the three Secrets created, `kubectl apply -k`
- [ ] `make live-admission-test` against the cluster as the broker's ServiceAccount
      (needs `deploy/base`'s ServiceAccount, RBAC and admission policy applied first)
- [ ] `mediatore login` at the cluster's Dex and `sandbox create` through the Tailscale
      ingress: the `AgentSandbox` created, the claim owned, `Pending` until a pool
      member attests (the second half)

## Second half: VMs attest (needs slate for the images)

- [ ] Build the SPIRE server image with the bloomberg/spire-tpm-plugin server attestor;
      record the plugin checksum; the chart values that add the `tpm` node attestor
      beside `k8s_psat`
- [ ] swtpm fleet EK CA generated; root into the `ek-ca` ConfigMap (`ek-ca.pem`)
- [ ] Trust bundle exported for the VM image (Part 1.5)
- [ ] Part 3 acceptance on libvirt: a fresh member appears in `agent list` as type
      `tpm` within 60 s, EK hash matches the local computation, reboot does not create
      a second agent
- [ ] The broker Deployment on the CSI socket proven as `make kind-e2e-mtls` does in
      kind, against this cluster: a sandbox turning `Ready`, the guest fetching its
      subject, a token issued to the workload
