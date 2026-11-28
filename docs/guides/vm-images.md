<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# The VM images: a base and two overlays

mediatore ships two VM images, both Kairos OCI images that banlieue turns into disks:

| Image | Dockerfile | Published as | What boots it |
| --- | --- | --- | --- |
| VM base | `image/base/Dockerfile` | `ghcr.io/firestoned/mediatore-vm-base` | nothing directly: the two below are built `FROM` it |
| Sandbox (guest) | `image/Dockerfile` | `ghcr.io/firestoned/mediatore-guest` | every pool member ([ADR-0023](../adr/0023-sandbox-vm-image-kairos-derivative.md)) |
| Egress gateway | `image/gateway/Dockerfile` | `ghcr.io/firestoned/mediatore-gateway` | the three gateway VMs ([ADR-0028](../adr/0028-egress-gateway-envoy-with-spiffe-identity.md) decision 10) |

The split is [ADR-0067](../adr/0067-the-vm-images-are-overlays-on-a-replaceable-base.md).

## The layering

```
quay.io/kairos/debian:13-core-...@sha256:...      Kairos + Debian 13 (pinned by digest)
  └── mediatore-vm-base                            image/base/Dockerfile
        tpm2-tools, qemu-guest-agent, nftables;
        openssh, snmpd, lldpd, fail2ban, rpcbind, nfs-common purged; ssh masked;
        resolved: the link's resolver alone (no global, fallback, LLMNR or mDNS),
        /etc/resolv.conf naming its stub until Kairos links it at boot
        ├── mediatore-guest                         image/Dockerfile (overlay)
        │     /usr/bin/mediatore   <- COPY --from the mediatore image
        │     spire-agent, TPM plugin <- COPY --from their images
        │     nsjail (pinned commit), curl, the spire user, units, sysctl, datasource
        └── mediatore-gateway                       image/gateway/Dockerfile (overlay)
              /usr/bin/mediatore   <- COPY --from the mediatore image
              envoy, spire-agent, TPM plugin <- COPY --from their images
              the four service users, units, templates, sysctl
```

The base is the operating system and nothing of mediatore's. The overlays start
`ARG VM_BASE` / `FROM ${VM_BASE}` and only add mediatore's pieces. Their first step checks
the base has what they rely on (`systemctl`, `useradd`, `nft`, `tpm2_nvread`, `qemu-ga`, the
`tss` group, the resolver drop-in, no `sshd`, and `apt-get` for the sandbox overlay) and fails
the build if not.

**The resolver.** The Kairos base ships `/etc/resolv.conf` as a plain file naming two public
resolvers, and systemd-resolved imports a file like that as global servers, used for every name
beside the link's. A gateway sent private names to them after its host rebooted (2026-11-28).
The VM base fixes it in two files: `image/base/resolved/60-mediatore.conf`, installed as
`/usr/lib/systemd/resolved.conf.d/60-mediatore.conf` (`DNS=` and `FallbackDNS=` empty,
`LLMNR=no`, `MulticastDNS=no`, the stub on `127.0.0.53`), and `image/base/resolv.conf` as
`/etc/resolv.conf`, naming the stub alone until Kairos replaces it at boot with a link to
resolved's own file. Both overlays refuse a base without the drop-in, and both image checks read
the two files. On the pool this matters to the `Direct` shape (a pool without gateways): the
guest puts the `nameserver` lines of `/etc/resolv.conf` in the sandbox user's DNS set and the
egress proxy resolves through them, so they are now the link's resolver, or the stub, and never
a public one. A pool with gateways resolves nothing (its segment has no resolver). Your own base
must carry the same drop-in.

## What the images carry for tripwires

[ADR-0070](../adr/0070-tripwires-beyond-the-sandbox-a-request-no-honest-build-makes.md) counts what the host tables drop
and no honest machine sends; nothing new is accepted in either image.

- **The gateway** gains a fifth service user, `mediatore-probes`, in no group but its own, and two units:
  `mediatore-gateway-probes.timer` (`OnBootSec=30s`, `OnUnitActiveSec=30s`, enabled) starts
  `mediatore-gateway-probes.service`, a oneshot running `mediatore gateway-probes --dir /run/mediatore-gateway/probes`
  with `CAP_NET_ADMIN` as its whole bounding and ambient set, no address family but `AF_NETLINK`, every address denied,
  and one writable directory. The image's tmpfiles.d entry (`/usr/lib/tmpfiles.d/mediatore-gateway.conf`) makes that
  directory at boot, before any unit starts, `2750`, owned by `mediatore-probes` and group `mediatore-gateway`, so the
  authorizer reads the summary and cannot change it. (In v0.5.0-rc.1 the unit's own `ExecStartPre=+` made it, too late:
  systemd sets a unit's mount namespace up first, and every run failed with `226/NAMESPACE`.) The same entry makes
  `/run/mediatore-gateway` and `/run/spire/sockets`, which other units name in their mount options. The table
  (`image/gateway/nftables.conf.in`) gains the set `probe_sources` and eleven named counters (`gateway_port`,
  `gateway_output_*`). `make gateway-image-check` pins the unit's lines and the user, runs the tmpfiles.d entry in the
  built image, and checks that every path a unit names bare in its mount options exists before it starts;
  `make gateway-render-check` runs `image/gateway/table-test.sh`, which requires every verdict of the table unchanged.
- **The sandbox image** gains no unit: the guest, already root and already driving `nft`, reads the pool's host table
  every 60 s. The table (`image/host-table`, on a pool with gateways) gains the counters `pool_inbound` and `pool_output`
  and the sets `inbound_sources` and `output_ports`, pinned by `make host-table-test`.

Both report what moved to the broker, which logs it; whatever its `tripwires` section says, a `segment` class records only
and ends nothing. See [Tripwires](tripwires.md#the-gateways-and-the-pools-probes).

## Building

```sh
make base-image                         # ghcr.io/firestoned/mediatore-vm-base:dev
make guest-image   BINARY_FROM=host     # builds the base first, then the overlay on it
make gateway-image BINARY_FROM=host
make guest-image-check gateway-image-check
```

`BINARY_FROM` chooses where `/usr/bin/mediatore` comes from:

| Value | Source | Used by |
| --- | --- | --- |
| `image` | `COPY --from=${MEDIATORE_IMG} /usr/bin/mediatore`: the published server image, which carries the same static musl binary | the Dockerfiles' default, a site's build |
| `container` | compiled from this tree inside the build | the Makefile's default |
| `host` | `dist/mediatore` (`make dist`) | CI, the kind tiers |

`MEDIATORE_IMG` is pinned by digest in each overlay; set it to the release you deploy
(`make guest-image BINARY_FROM=image MEDIATORE_IMG=ghcr.io/firestoned/mediatore:<version>@sha256:<digest>`).

## Your own base

A site with its own VM base (Kairos and Debian 13, kept in its own registry with its CA
bundle, apt mirror and hardening) builds the overlays on it and nothing else:

```sh
docker build -f image/Dockerfile \
  --build-arg VM_BASE=registry.internal:5000/platform/kairos-debian13@sha256:<digest> \
  --build-arg MEDIATORE_IMG=ghcr.io/firestoned/mediatore:<version>@sha256:<digest> \
  -t registry.internal:5000/platform/mediatore-guest:<version> .
make guest-image-check GUEST_IMAGE=registry.internal:5000/platform/mediatore-guest:<version>
```

What your base must provide is the overlay's prerequisite list above. The sandbox overlay
installs four packages of its own with `apt-get` (`curl`, `ca-certificates`,
`libprotobuf32t64`, `libnl-route-3-200`), so your base's apt sources must reach a Debian 13
archive or a mirror of it. Always run the check targets against the result: they are what
proves your base did not bring back a listener, a binary under `/usr/local` or a key.

## Consuming the images from banlieue

banlieue takes a Kairos OCI image as a `kind: Url` source: its image builder (the
kairos-operator's `OSArtifact`) builds a disk from `importFrom`, a raw disk for
`cloud-hypervisor` and `libvirt`, and for `azure` it also publishes that disk to an Azure
Compute Gallery (banlieue ADR-0162). Pin the image by digest; `ref` is required by the
schema and ignored for `Url` sources. One `VMImage` can carry a source per provider class:

```yaml
apiVersion: banlieue.io/v1alpha1
kind: VMImage
metadata:
  name: mediatore-guest
spec:
  osFamily: linux
  osDistribution: debian
  osVersion: "13"
  architecture: amd64
  guestAgent: cloud-init
  sources:
    - providerClass: cloud-hypervisor
      kind: Url
      ref: unused
      importFrom: ghcr.io/firestoned/mediatore-guest@sha256:<digest>
    - providerClass: libvirt
      kind: Url
      ref: unused
      importFrom: ghcr.io/firestoned/mediatore-guest@sha256:<digest>
    - providerClass: azure   # see "On Azure" below before using this source
      kind: Url
      ref: unused
      importFrom: ghcr.io/firestoned/mediatore-guest@sha256:<digest>
  cloudConfigs:
    - secretRef: { name: mediatore-guest-base, key: cloud-config.yaml }
    - secretRef: { name: banlieue-guest-ek-certificate, key: cloud-config.yaml }
    - secretRef: { name: mediatore-guest-deployment, key: cloud-config.yaml }
  template:
    installMode: deferred
```

The cloud-config layers, the class and the gateway's equivalent are
`deploy/overlays/homelab-example/vmimage.yaml` and `deploy/gateway/vmimage.yaml`; the
[deploying guide](deploying.md) walks through them. For an image built on your own base,
`importFrom` names your overlay's digest in your registry.

## On Azure

An image banlieue boots on Azure must meet banlieue ADR-0163 decision 3. **Neither
mediatore image does today**, and the base is where that work belongs:

- **customData from the provisioning disk.** The image must read `ovf-env.xml` from the
  provisioning disk (UDF) and decode `<CustomData>` early enough that its stages run in this
  boot. The sandbox image's datasource stage reads `cdrom`, `config-drive` and `vmware`
  only (`image/oem/00_datasource.yaml`, ADR-0063 decision 8). The gateway image keeps the
  Kairos default list, which names an `azure` provider, but that one is the metadata-service
  path, read too late in the boot (banlieue ADR-0163 finding 4), not the provisioning disk.
- **Report ready to WireServer**, retrying until a 2xx once a route exists, and only after
  user data is applied (for the sandbox image, after the agent has attested). Nothing in
  either image does this.
- **Never configure the accelerated-networking VF** (`mana`, `mlx4_core`, `mlx5_core`) in
  the initramfs network config. Not done.
- **No QEMU guest agent on Hyper-V.** Both images enable `qemu-guest-agent.service`
  unconditionally; on Azure it must be masked or conditioned off.
- **Log to `/dev/kmsg`**, not the serial device. Not done.

Until those land, use the `azure` source only for experiments, not for a pool.
