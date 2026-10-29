<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0023: The sandbox VM image is a Kairos derivative built from this repository

**Status:** Accepted · **Date:** 2026-10-27

Roadmap 06, the image item. Implements mediatore's share of banlieue
[ADR-0108](https://github.com/firestoned/banlieue/blob/main/docs/adr/0108-sandbox-guest-software-is-consumer-image-content.md)
(the sandbox guest software is consumer image content; a template carries no per-VM
identity) and of [ADR-0008](0008-agentsandbox-crd-owned-by-mediatore.md) decision 8 (the
agent runtime comes from the VM image). Amends
[ADR-0014](0014-one-binary-roles-as-subcommands.md) decision 5: the pinned path of the one
binary. Changes nothing about attestation ([ADR-0018](0018-tpm-attestation-with-the-spiffe-plugin.md)),
`GuestReady` ([ADR-0019](0019-guestready-after-attestation-and-registration.md)) or what
the guest does once it runs.

## Context

Every pool member boots one VM image, and nothing in this repository said how that image
is made. The pieces existed: `make dist` builds the static binary "that the VM image
bakes in", `make dist-tpm-plugin` extracts the attestor plugin "for banlieue-imagebuilder
to bake beside it", `image/` holds two units, an agent configuration and a cloud-config
fragment, and the deploying guide pointed at a runbook that is not in the tree. An
operator had to assemble a Kairos image by hand from those parts, and the roadmap's
remaining items (root's egress chain, seccomp, the live libvirt proof) all wait on an
image that exists.

banlieue's side is settled: it ships none of the guest software, and the consumer brings
it either as `VMImage.spec.cloudConfigs` layers or as a pre-built source
(ADR-0108 decision 1); a `Url` source is an OCI reference that `banlieue-imagebuilder`
turns into a disk; a `tpmEnabled` pool's image carries no private key and generates
per-VM identity on first boot onto a sealed partition (decisions 2 and 3).

Kairos's layout decides where the software can live. The root filesystem is immutable.
`/usr/local` is the mount point of the persistent partition (`COS_PERSISTENT`), `/opt`,
`/etc/systemd` and a list of `/var/lib/*` paths are bind mounts from it, and the rest of
`/etc` and `/var` are ephemeral overlays. A binary copied into `/usr/local/bin` at build
time is therefore hidden on every installed member, under the partition mounted over it.
`AGENT_BINARY_PATH` has been `/usr/local/bin/mediatore` since ADR-0014, and the node
entry selects it (`unix:path`), the jail mounts it, the server image runs from it.

The newest Kairos base for Debian 13 on quay is v3.7.2 (checked 2026-10-27). banlieue's
first-boot sealing shape (its ADR-0088, `Immediate` plus `firstBootSealing`) needs Kairos
4.4; until a Debian base at that version is published, a `tpmEnabled` pool on libvirt
runs `Deferred` installs, which banlieue's libvirt guide calls the simpler path there.

## Decision

1. **The image is a Kairos derivative built from `image/Dockerfile`.** `FROM` the Kairos
   Debian 13 `core` base, pinned by digest; the packages the guest needs installed with
   `apt-get` (`tpm2-tools` for the EK export, `qemu-guest-agent` for the libvirt
   channels, `nftables`, which the base already has); `nsjail`, the jail itself
   ([ADR-0020](0020-jail-network-nftables-keyed-by-sandbox-uid.md)), which no Debian archive
   carries, built from source at a pinned commit in a build stage and installed at
   `/usr/bin/nsjail` with the two libraries it links (*amended 2026-10-28: the first build
   omitted it, and `image/check.sh` now proves it*); every listening service the base
   ships removed or masked (`openssh-server`, `snmpd`, `lldpd`, `fail2ban`, `rpcbind`:
   no inbound, [ADR-0010](0010-no-inbound-to-sandboxes.md) decision 2); the `spire` system
   user created, in group `tss`; the two units installed and enabled. The build takes the
   `mediatore` binary from the same two-stage choice as the server image (`BINARY_FROM`:
   compiled in the build, or `dist/mediatore` from the host), the SPIRE agent from the
   `spiffe/spire-agent` image and the attestor plugin from the `spire-tpm-plugin` image,
   both pinned by digest, the plugin's checksum verified in the build against the one
   `image/spire/agent.conf` pins. No `banlieue-imagebuilder` layer installs software.

2. **Binaries in the immutable rootfs; the pinned path is `/usr/bin/mediatore`.**
   `mediatore` at `/usr/bin/mediatore`, `spire-agent` at `/usr/bin/spire-agent`, the
   plugin at `/usr/lib/spire/tpm_attestor_agent`. `AGENT_BINARY_PATH` becomes
   `/usr/bin/mediatore` everywhere it is used (the node entry's `unix:path` selector, the
   jail mount, the guest's default, the server image, the kind tiers): one path, in a
   directory no partition is mounted over. This amends ADR-0014 decision 5.

3. **Configuration is the deployment's layer; the agent's state is on the sealed
   partition.** The image carries no trust bundle, no trust domain and no server address:
   the deployment's cloud-config layer writes `/etc/spire/agent.conf` (from
   `image/spire/agent.conf` with the two placeholders replaced) and `/etc/spire/bundle.pem`
   at every boot, into the ephemeral `/etc`. `image/cloud-config.yaml`, the base layer,
   binds `/var/lib/spire` from the persistent partition (`install.bind_mounts`), so the
   agent's key is generated on the member's first boot onto storage sealed to its own
   vTPM and never exists in the image (ADR-0108 decisions 2 and 3), and it re-asserts the
   directories and the enabled units at every boot.

4. **Published by this repository's Build workflow as `ghcr.io/firestoned/mediatore-guest`**,
   on push and release, keyless-signed by digest, with an SBOM and build provenance, like
   the server image; built but not pushed on a pull request, where `make guest-image-check`
   runs what decision 1 promised against the built image (the binaries, the plugin's
   checksum, the packages, the units, no `sshd`, the `spire` user).

5. **The `VMImage` is the operator's, from an example in the overlay.**
   `deploy/overlays/homelab-example/vmimage.yaml` names the published image by digest as a
   libvirt `Url` source with three cloud-config layers in order: the base layer of
   decision 3, banlieue's EK-certificate layer (its `examples/21`, unchanged) and the
   deployment layer; `installMode: deferred` while the base is Kairos 3; beside it a
   `VMClass` with a vTPM and EFI. Its phase layer (banlieue's `examples/17`) is not
   included (ADR-0019).

## Consequences

- `image/Dockerfile`, `image/check.sh`, `image/cloud-config.yaml` (rewritten as the base
  layer), `image/cloud-config-deployment.example.yaml`, `make guest-image` and `make
  guest-image-check`, the `guest-image` job of `.github/workflows/build.yaml`, the
  overlay's `vmimage.yaml`. `AGENT_BINARY_PATH` and every file that spelled it; the units
  and `image/spire/agent.conf` point at the new paths, and the kind TPM tier mounts the
  agent's configuration and the plugin where that file says.
- The image is built and checked with podman on the build host before it is pushed
  anywhere, and the kind TPM tier proves the attestation path on the paths the image now
  uses; booting the image on a libvirt member, the install, the sealed partition, the EK
  export and a claim end to end are roadmap 06's live item, which this ADR makes possible
  rather than done.
- `Immediate` plus `firstBootSealing` replaces `deferred` in the example the day a Kairos
  4.4 Debian base exists; nothing else in the image changes.
- Rejected: installing the software from cloud-config stages at template build or first
  boot (every member downloads at boot, nothing is testable without an imagebuilder run,
  and the install depends on the network and a release URL); keeping the pinned path and
  copying the binary onto the persistent partition at every boot (a pinned path on a
  writable partition, and a copy to keep in step with the image); a binary under
  `/usr/local` with the path left as it was (hidden on every installed member, which is
  the finding that forced decision 2); baking the trust bundle and the agent configuration
  (one image per deployment, and a public bundle is exactly what a layer is for).
