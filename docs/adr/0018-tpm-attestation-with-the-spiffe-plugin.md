<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0018: TPM node attestation with the SPIFFE community plugin, the hypervisors' swtpm CAs as the EK trust bundle

**Status:** Accepted · **Date:** 2026-10-22

Roadmap 02, second half. Amends [ADR-0005](0005-spire-topology.md) and
[ADR-0006](0006-registration-entries-as-clusterstaticentry.md) on which attestor plugin
is run and what signs the endorsement keys; changes nothing about the identities those
ADRs and [ADR-0004](0004-spiffe-identity-scheme.md) define.

## Context

ADR-0004 and ADR-0006 built the identity scheme on the SPIRE TPM attestor: a pool VM's
agent is `spiffe://<td>/spire/agent/tpm/<sha256 of the EK's PKIX DER>`, the watcher
computes the same hash from the certificate banlieue publishes, and the node and claim
entries name that agent as their parent. Roadmap 02 then planned to build a SPIRE server
image around `bloomberg/spire-tpm-plugin` and to generate a fleet EK CA for swtpm.

Measured on 2026-10-22, three things changed that plan:

- The Bloomberg repository was archived in May 2025. Its maintained continuation is
  `spiffe/spire-tpm-plugin` (v1.11.3 at the time of writing): same code, same hash
  (`GetPubHash` is SHA-256 over `x509.MarshalPKIXPublicKey` of the EK, which is what
  ADR-0006 says and `mediatore_proto::ek` computes), same agent ID, static binaries
  published as images under `ghcr.io/spiffe/`.
- SPIRE loads an external plugin from a path and refuses it unless the binary's SHA-256
  matches `plugin_checksum`. The plugin therefore needs no custom server image: a pinned
  image, an init container that copies the binary into a shared volume, and the
  checksum in `server.conf` give the same guarantee with nothing of ours to build.
- libvirt gives every VM an EK certificate already: `swtpm_setup --create-ek-cert` on
  each hypervisor signs it with that host's `swtpm-localca` (`/var/lib/swtpm-localca/`,
  a root and an issuer per host). The CA that must be trusted exists; it is per host,
  not per fleet.

The agent plugin opens the TPM through go-attestation's defaults (`/dev/tpmrm0`, then
`/dev/tpm0`), takes no device path, and sends the EK certificate when the TPM has one.
A vTPM made by swtpm has one.

## Decision

**1. The attestor is `spiffe/spire-tpm-plugin`, pinned, as manifests.** The server side
is a kustomize component, `deploy/spire-tpm`: an init container on the `spire-server`
StatefulSet copies `tpm_attestor_server` out of the plugin image (pinned by digest) into
an `emptyDir`, the server mounts it read-only, and `server.conf` gains the
`NodeAttestor "tpm"` block with the binary's checksum (`server.conf.fragment.hcl`).
The operator's SPIRE kustomization includes the component; how those SPIRE manifests
were produced is not this ADR's concern (SPIRE's distribution rendered once with
`helm template` and checked in with placeholders, or hand-written), as long as the
StatefulSet and its config path are the standard ones. No Helm release is involved,
and the roadmap's "build the SPIRE server image" item is withdrawn.

**2. The EK trust bundle is the set of hypervisor swtpm CAs.** ConfigMap
`spire-tpm-ek-cas`, mounted at the plugin's `ca_path`, holds one PEM per hypervisor
host: the root of its `swtpm-localca` (`swtpm-localca-rootca-cert.pem`; the EK
certificate chains through the host's issuer to it). Collecting them is the operator's
step, documented; a new hypervisor is a new key in the ConfigMap. The hash allowlist
(`hash_path`) is not configured: a VM's EK is born with the VM (banlieue ADR-0045), so
there is no hash to know in advance, and the CA route is what makes the fleet open to
new members without touching the server. A fleet-wide swtpm CA shared by every host
would reduce the bundle to one certificate and is a change on the hosts, not here;
revisit when hosts are provisioned by configuration rather than by hand.

**3. The agent plugin is the same release, in the VM image.** `image/spire/agent.conf`
carries `NodeAttestor "tpm"` with `plugin_cmd` under `/opt/spire/bin` and the checksum of
the agent binary from the same release, the `unix` workload attestor the node and claim
entries' selectors need, and the trust bundle at `/opt/spire/conf/bundle.pem`.
`make dist-tpm-plugin` extracts the two static binaries from the pinned images and
verifies their checksums, so the image builder (banlieue's, roadmap 06) takes them from
`dist/` like the `mediatore` binary. The agent's systemd unit grants the `tss` group and
the TPM character devices and nothing else.

**4. PVE mode stays off.** The plugin's Proxmox extension binds an agent to a Proxmox VM
id through a host hook; banlieue's providers run libvirt and Cloud Hypervisor, whose VMs
are identified by the EK alone (ADR-0004), so `pve { enabled = false }` and the server
takes no `pve` block.

**5. What the identities rest on is unchanged.** The agent ID, the hash, the entry
shapes and the admission policy of ADR-0006 stand; this ADR changes which plugin runs
and what signs the EK, not what mediatore writes or checks. The watcher still binds only
by the EK banlieue mirrored (ADR-0011), and a VM whose EK certificate chains to no
configured host CA never becomes an agent, let alone a node.

## Alternatives considered

- **Building the server image with the plugin** (the original roadmap item): the
  checksum SPIRE verifies at load is the control, and an init container from a pinned
  image provides the binary without one more image of ours to sign, scan and bump.
- **The hardened chart's `tpmDirect` values**: the same plugin and the same checksum,
  behind a Helm release and a values file. Rejected: this repository ships manifests,
  reviewed and applied with `kubectl apply -k` like everything in `deploy/`; a chart
  value cannot be read in a diff of what runs.
- **The hash allowlist**: a static set of EK hashes the server knows beforehand. Right
  for bare metal, wrong for VMs created on demand.
- **SPIRE's built-in `tpm_devid`**: attests a DevID certificate provisioned onto the TPM
  by a CA the operator runs, which needs a provisioning step per VM that nothing in the
  pool lifecycle has.
- **Keylime**: full measured-boot attestation and a registrar; more than ADR-0006's
  "this vTPM" needs today, and R-6 records the gap as accepted.

## Consequences

- `deploy/spire-tpm/`: the component (the StatefulSet patch, the EK CA ConfigMap, the
  `server.conf` fragment), pinned to v1.11.3 by digest and checksum.
- `image/spire/agent.conf`, `image/systemd/spire-agent.service`: the agent's side.
- `Makefile`: `dist-tpm-plugin` and the pinned versions, digests and checksums.
- Docs: the deploying guide's "VMs attest" section; the walkthrough; roadmap 02's second
  half rewritten.
- Threat model: TB-4 rows cite the component, the checksum and the per-host CAs;
  **A-15 new** (the hypervisors' swtpm CA keys); R-6 reworded; the stamp.
- Still outside this repository: the VM image build (banlieue-imagebuilder, roadmap 06),
  the SPIRE manifests the component patches (the operator's, rendered once), and the
  acceptance on libvirt (roadmap 02). The kind tier still installs SPIRE with a Helm
  release (`make kind-spire`); moving it to a rendered manifest set is roadmap 02's
  follow-up, so that the component is exercised in kind the way it is on the cluster.
