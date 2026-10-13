<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 02: SPIRE on the homelab cluster

**Status: not started.** Runbook Parts 1–3 on the banlieue management cluster (the
ADR-0005 homelab collapse: one server playing the downstream role). Enterprise split
is documented in `docs/guides/enterprise-spire-topology.md` and is not this roadmap.

- [ ] Build the SPIRE server image with the bloomberg/spire-tpm-plugin server attestor;
      record the plugin checksum
- [ ] swtpm fleet EK CA generated; root into the `ek-ca` ConfigMap (`ek-ca.pem`)
- [ ] Helm install (`spiffe/spire` hardened chart): trust domain, datastore,
      `admin_ids` for `spiffe://<td>/mediatore`, k8s PSAT for in-cluster workloads
- [ ] mediatore Deployment gets its SVID via ClusterSPIFFEID (`deploy/base/` already
      carries the manifest); `spire.endpoint` config pointed at the server
- [ ] Trust bundle exported for the VM image (Part 1.5)
- [ ] Part 3 acceptance on libvirt: a fresh member appears in `agent list` as type
      `tpm` within 60 s, EK hash matches the local computation, reboot does not create
      a second agent
- [ ] `NetworkPolicy` for the broker pods (ADR-0007 decision 7, from roadmap 01):
      ingress 8443 from the sandbox segment's CIDR only, 8080 from the ingress controller
      only; egress to the API server and the IdP's discovery and token endpoints
- [ ] Run roadmap 01's live tiers against this cluster (`make live-admission-test`; the
      broker Deployment from `deploy/base` on the CSI socket as `make kind-e2e-mtls` does
      in kind)
