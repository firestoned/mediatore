<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0067: The VM images are overlays on a replaceable base

**Status:** Accepted, implemented 2026-11-26 (`image/base/Dockerfile`, the two overlays
`image/Dockerfile` and `image/gateway/Dockerfile`, `make base-image`, the `vm-base-image`
job of the Build workflow; built and checked with podman on the build host, the old and the
new images compared package by package and file by file) · **Date:** 2026-11-26

Amends [ADR-0023](0023-sandbox-vm-image-kairos-derivative.md) decisions 1 and 4 (how the
sandbox image is built and what the workflow publishes) and
[ADR-0028](0028-egress-gateway-envoy-with-spiffe-identity.md) decision 10 (the gateway
image, the same way). Changes nothing about what either image carries, where its binaries
live, its units, its users, or how banlieue turns it into a disk.

## Context

Both VM images were one Dockerfile each: `FROM` the Kairos Debian 13 core base, then, in
the same file, the OS layer (the packages, every listener the base ships purged, ssh masked)
and mediatore's layer (the binary, Envoy, the SPIRE agent and plugin, nsjail, the users,
units, sysctl and templates). The OS layer was written twice, nearly identically, and it
could not be swapped.

A site that runs mediatore often has its own VM base already: Kairos and Debian 13 like
ours, but kept in its own registry (an Artifactory, a Harbor), carrying its own CA bundle,
apt mirror, agents and hardening, and the one its security review has signed off. What it
needs from this repository is mediatore, not another OS. With one file per image, the only
way to get there was to fork the Dockerfiles and keep them in step.

The binary had the same problem in a smaller way: `BINARY_FROM` could compile the tree in
the build (`container`) or copy `dist/mediatore` (`host`), both of which need this
repository's source and a Rust toolchain, while the same static binary is already published
in the server image, signed, at `/usr/bin/mediatore`.

## Decision

1. **A VM base image, `image/base/Dockerfile`, holds the OS layer and nothing of
   mediatore's.** `FROM` the Kairos Debian 13 core base, pinned by digest (`KAIROS_BASE`,
   the pin that used to sit in both images); `tpm2-tools`, `qemu-guest-agent` and
   `nftables` installed; `openssh-server`, `openssh-sftp-server`, `snmpd`, `lldpd`,
   `fail2ban`, `rpcbind` and `nfs-common` purged, the build failing if `sshd` is left, and
   the ssh units masked. `make base-image` builds it as `BASE_IMAGE`
   (`ghcr.io/firestoned/mediatore-vm-base:dev` locally); the Build workflow publishes it as
   `ghcr.io/firestoned/mediatore-vm-base`, keyless-signed by digest with an SBOM and build
   provenance, attested, like the other images.

2. **The sandbox and gateway images are overlays: `ARG VM_BASE`, `FROM ${VM_BASE}`.** They
   add mediatore's pieces only, with `RUN` and `COPY`, the binaries pulled with
   `COPY --from=` their images (the mediatore image, `spiffe/spire-agent`, the TPM
   attestor plugin, Envoy for the gateway) and nsjail from its pinned-commit build stage, as
   before. What the sandbox overlay still installs with apt is its own: `curl` and
   `ca-certificates` for the bundle fetch (ADR-0037) and the two libraries nsjail links. The
   users, units, sysctl files, `qemu-ga.conf`, templates, datasource stage and the
   `systemctl enable`/`mask` lines stay in the overlays, unchanged.

3. **An overlay checks its base before it builds on it.** The first `RUN` of each overlay
   fails the build unless the base has `systemctl`, `useradd`, `nft`, `tpm2_nvread`,
   `qemu-ga` and the `tss` group, and no `sshd` (the sandbox overlay also `apt-get`). That
   is the contract a site's own base must meet; everything else the overlay needs it adds
   itself. `image/check.sh` and `image/gateway/check.sh` run against the built overlay, so a
   site base that reintroduces a listener or a binary under `/usr/local` still fails them.

4. **`BINARY_FROM=image` takes the binary from the mediatore container image.** A third
   choice beside `container` and `host`: `COPY --from=${MEDIATORE_IMG} /usr/bin/mediatore`,
   `MEDIATORE_IMG` pinned by digest in each overlay. It is the overlays' default, so a site
   builds with no toolchain and no source but the `image/` files. `make guest-image` and
   `make gateway-image` keep `BINARY_FROM=container` as their default (a developer builds
   the tree in front of them), and CI keeps `host` (the dist job's binary, one compile per
   run).

5. **CI builds the overlay on the base of the same run.** A pull request's check jobs run
   `make guest-image` / `make gateway-image` on the runner's own Docker, which builds the
   base first as a local tag; nothing is pushed. On push and release, `vm-base-image`
   publishes the base and the two publish jobs build `FROM` it by the digest it output, so a
   published overlay always names the base it was built on.

## Consequences

- The published images are the same as before, file for file and package for package
  (checked on the build host: `dpkg -l`, and the file lists of `/usr`, `/etc`, `/system`,
  `/mnt` with modes and owners, old against new). What changes is the layer history: the OS
  layer is one shared, separately signed image, and an overlay's own layers are only
  mediatore's.
- A site replaces the base with `--build-arg VM_BASE=<its image>` (or
  `make guest-image VM_BASE=...`), and nothing else: the overlays are this repository's,
  the base is theirs. What the base carries is then the site's to review: it is in A-17's
  supply chain (threat model R-66), and only the overlay's prerequisite check and the
  image checks stand between it and a member.
- The overlays' default `VM_BASE` is a tag until the first published base exists; it is
  pinned by digest then, like every other pin. CI never uses the default (decision 5).
- Bumping Kairos is a change to `image/base/Dockerfile` alone; bumping mediatore in a
  site-built overlay is `MEDIATORE_IMG`.
- A pull request's image check no longer reads the GitHub Actions cache: the plain Docker
  builder has none. The nsjail build stage runs on every PR (about two minutes).
- Cloud-specific OS work belongs in a base, not an overlay. Neither image carries banlieue
  ADR-0163 decision 3's Azure requirements today (customData from the provisioning disk,
  the report to WireServer, the accelerated-networking VF left unconfigured, no QEMU guest
  agent on Hyper-V, logging to `/dev/kmsg`); the guide says so, and an Azure base, or
  additions to this one, are their own change.
- Rejected: one Dockerfile with a `target` per image (a site still forks the file to change
  the OS); the base as a build stage in each overlay (two copies again, and nothing to
  replace); installing the shared packages in the overlays as well (a site base would get
  them from Debian behind its back, and the base's purges could be undone by a dependency).
