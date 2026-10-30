<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Deploying on a homelab cluster

The single-cluster shape of [ADR-0005](../adr/0005-spire-topology.md): one SPIRE server
on the management cluster plays the downstream role, banlieue runs beside it, the
broker runs as a Deployment from `deploy/base` with an overlay for what is yours. This
page is that overlay, in order, for a k0s cluster that already has SPIRE,
banlieue and an issuer; [the walkthrough](homelab-walkthrough.md) is the whole stack
from the empty cluster, with every command. The enterprise split (a root on its own identity cluster) is
[a separate guide](enterprise-spire-topology.md); roadmap 02 tracks what is still
missing for VMs to attest ([`ROADMAPS.md`](https://github.com/firestoned/mediatore/blob/main/ROADMAPS.md)).

Every release attaches what the install needs beside the two images: the binary for Linux
(`mediatore-<version>-linux-amd64`, static, every role) and for a Mac
(`mediatore-<version>-darwin-arm64`, the CLI: `login`, `sandbox`, `session`), `mediatore-<version>.yaml`
(this `deploy/base` with the server image pinned by digest), the `VMImage` of step 6 pinned to
the guest image's digest with the two cloud-config layers it names, the SBOMs and
`checksums.sha256`, each file attested by the Build workflow. Every binary and both images
report the release's version (`mediatore --version` prints `mediatore <version>`): the
workspace version is set from the tag before each build, and the release job refuses a
binary that says otherwise. An overlay can name the manifest instead of a checkout, and
every asset verifies offline:

```sh
gh release download v0.1.0 --repo firestoned/mediatore --pattern 'mediatore-0.1.0*' --pattern checksums.sha256
shasum -a 256 -c checksums.sha256
gh attestation verify mediatore-0.1.0.yaml --repo firestoned/mediatore
# kustomization.yaml of your overlay:
#   resources:
#     - https://github.com/firestoned/mediatore/releases/download/v0.1.0/mediatore-0.1.0.yaml
```

## What the cluster must already have

| Piece | Where it comes from | How mediatore uses it |
| --- | --- | --- |
| SPIRE server, agents and the SPIFFE CSI driver | SPIRE's distribution rendered once into manifests ([the walkthrough](homelab-walkthrough.md), step 2), `watchClassless: false`, class name `<namespace>-<release name>` | the broker's SVID over the CSI socket (ADR-0007); entries as `ClusterStaticEntry` (ADR-0006) |
| SPIRE Controller Manager | the same manifests | renders the entries the broker declares |
| banlieue with `VirtualMachinePool` and `VirtualMachineClaim` | banlieue's release | the claims mediatore creates (ADR-0008, ADR-0011) |
| banlieue's claim subject policy listing mediatore as a broker | ConfigMap `banlieue-claim-subject-policy`, `brokers:` line `system:serviceaccount:banlieue-system:mediatore`, `issuers:` listing yours | every claim mediatore creates names someone else's subject ([requesting a sandbox](requesting-a-sandbox.md)) |
| An issuer with a public client for mediatore | Dex, Google, Auth0 or Entra ([issuers](issuers.md)) | `mediatore login` and the refresh before every issue |
| An ingress for the user API, a LoadBalancer for the sandbox listener | the Tailscale operator's ingress class and MetalLB in the example | `:8080` to people, `:8443` to pool VMs |
| A ReadWriteOnce storage class | `local-path` on k0s | the SQLite file of a one-replica broker, or nothing with PostgreSQL |

None of those are this repository's to install. What follows is.

## 1. Copy the example overlay and put your values in

```sh
cp -r deploy/overlays/homelab-example ~/.config/mediatore/core
```

Keep the copy outside the repository: it will carry your trust domain, your issuer's
URL, your CIDRs. Edit:

- `mediatore.yaml`: `trust_domain`, `issuers` (from the [issuers guide](issuers.md)),
  `audiences`, each with the `egress` the jail may reach for it (`host:port` pairs; an
  audience without one yields tokens the workload can spend nowhere, [ADR-0020](../adr/0020-jail-network-nftables-keyed-by-sandbox-uid.md)),
  `sts.issuer` (what downstream services will see as `iss`), and
  `spire.entries.class_name` if SPIRE was rendered with another namespace or release
  name (the class is `<namespace>-<release name>`, `spire-server-spire` in the example);
- `networkpolicy.yaml`: the sandbox segment's CIDR for `:8443`, the control-plane
  addresses for the API server, the node CIDR for the kubelet's probe, and the
  issuer's namespace or addresses;
- `ingress.yaml`: the ingress class and hostname, if not Tailscale's;
- `kustomization.yaml`: the image tag, pinned to a digest or a `sha-<commit>` tag of
  [the published image](https://github.com/firestoned/mediatore/pkgs/container/mediatore).

`kubectl kustomize ~/.config/mediatore/core` renders the whole thing; read it once.

## 2. Create the Secrets the overlay expects

The overlay generates no secret. Three Secrets in `banlieue-system`, each a file the
broker reads at startup:

```sh
# The STS signing key (ES256), whose public half becomes the broker's JWKS.
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out sts.pem
kubectl -n banlieue-system create secret generic mediatore-sts --from-file=sts.pem

# The sealing key for refresh material (ADR-0012 decision 3), the local sealer.
openssl rand -hex 32 > sealing.key
kubectl -n banlieue-system create secret generic mediatore-sealing --from-file=key=sealing.key

# The store URL (ADR-0012). SQLite on the PVC for one replica, as the example
# config says; or PostgreSQL over verify-full, in which case this overrides it.
kubectl -n banlieue-system create secret generic mediatore-store \
  --from-literal=url='sqlite:///var/lib/mediatore/store.db?mode=rwc'
```

Delete the local files afterwards. With the transit sealer ([the store](the-store.md))
the sealing Secret is not needed; with Entra ([the Entra path](the-entra-path.md)) a
fourth Secret holds the client credential.

## 3. Apply, and read the start-up log

```sh
kubectl apply -k ~/.config/mediatore/core
kubectl -n banlieue-system rollout status deploy/mediatore
kubectl -n banlieue-system logs deploy/mediatore | head -40
```

The broker fails the start on anything it cannot use, and says which: a key file that
does not parse, a store it cannot migrate, an issuer whose discovery document it cannot
fetch, a class name the controller manager does not serve. What a healthy start logs,
in order: the store migrated, the sealing key loaded, each issuer (and `issuer pinned
to a private CA` when `ca_file` is set), `broker SVID` from the Workload API, the
listeners, `claim watcher running` on the replica that holds the Lease.

`/healthz` on the user API answers true only once the store is reachable; the Ingress
routes to it.

## 4. Prove the cluster side as the broker's ServiceAccount

Before a single sandbox, run the live admission round trip from your machine, as the
ServiceAccount the broker runs as (impersonated through your admin kubeconfig):

```sh
MEDIATORE_LIVE_KUBECONFIG=~/.kube/core.yaml \
MEDIATORE_LIVE_TRUST_DOMAIN=sandbox.home.example \
MEDIATORE_LIVE_CLASS_NAME=spire-server-spire \
make live-admission-test
```

It declares the two entry shapes, waits for the controller manager to set them, proves
that admission refuses what [ADR-0006](../adr/0006-registration-entries-as-clusterstaticentry.md)
forbids and that RBAC refuses edits, and retracts everything. Give the API server a
moment after step 3: a policy is stored before it is enforced, and
`dev/kind/admission-settled.sh <sa kubeconfig> <trust domain>` is the dry-run probe
the kind tier waits on (it needs a kubeconfig for the broker's ServiceAccount, which
`dev/kind/sa-kubeconfig.sh` writes from an admin one). It fails rather than
skips when a variable is missing. [Testing tiers](testing.md) has the rest of the
suites.

## 5. Log in and request a sandbox

```sh
mediatore login --issuer https://dex.home.example
mediatore sandbox create --server https://mediatore.<tailnet> --pool pool-a \
  --audience grafana.home.example --image registry.internal:5000/sandbox:latest
```

The sandbox turns `Bound` when banlieue hands it a member and `Ready` once the member
has registered its node and the entry is set ([requesting a sandbox](requesting-a-sandbox.md)).
Until pool VMs attest with a TPM (roadmap 02's second half: the server's TPM attestor
and the guest image), a claim binds and nothing registers, so `ready` stays false and
the claim fails after `watcher.resolve_timeout_secs`; the API, the issuer, the store,
the entries and the policies are nonetheless live at that point, which is what this
page gets you. Once the image carries the guest, the pool's `GuestReady` is the guest's
own announcement after it registered ([ADR-0019](../adr/0019-guestready-after-attestation-and-registration.md)),
so a `GuestReady` pool binds only members that can take the claim.

## 6. Let the VMs attest

This step is about the VM image: the pool member's disk, which every member boots from.
It carries the SPIRE agent, the TPM plugin, the one `mediatore` binary, `nsjail`,
`nftables`, `tpm2-tools` and `qemu-guest-agent`, and nothing of any workload. What a sandbox runs is
the *workload image*, an ordinary OCI container image the requester names on each claim
and the guest pulls at bind ([what "the workload" is](running-workloads.md#what-the-workload-is)).
One VM image serves every workload image.

The VM image is built from this repository ([ADR-0023](../adr/0023-sandbox-vm-image-kairos-derivative.md)): `image/Dockerfile` is a
Kairos Debian 13 derivative with the guest software in the immutable rootfs (`/usr/bin`,
never `/usr/local`, which Kairos mounts the persistent partition over), every listener the
base shipped removed, the `spire` user created and both units enabled. The Build workflow
publishes it as `ghcr.io/firestoned/mediatore-guest`, signed and attested like the server
image, on every push and release; `make guest-image` builds it locally and
`make guest-image-check` proves what it carries. The image holds no trust bundle, no trust
domain and no key: the deployment's cloud-config layer writes the agent's configuration at
every boot, and the agent's key is generated on each member's first boot onto the sealed
persistent partition (banlieue ADR-0108). `deploy/overlays/homelab-example/vmimage.yaml`
is the `VMImage` (a libvirt `Url` source pinned by digest, three cloud-config layers:
`image/cloud-config.yaml`, banlieue's EK-certificate layer, your copy of
`image/cloud-config-deployment.example.yaml`) and the `VMClass` with a vTPM; it runs
`installMode: deferred` until a Kairos 4.4 Debian base exists for first-boot sealing.

```sh
make dist && make guest-image BINARY_FROM=host && make guest-image-check   # or pull a release by digest
gh attestation verify oci://ghcr.io/firestoned/mediatore-guest@sha256:<digest> --repo firestoned/mediatore
```

Pool VMs become SPIRE agents with their vTPM ([ADR-0018](../adr/0018-tpm-attestation-with-the-spiffe-plugin.md)).
On the server side it is a kustomize component, `deploy/spire-tpm`, that your SPIRE
kustomization includes: an init container puts the attestor plugin (pinned by digest)
into the server pod together with the EK trust anchors it copies out of a ConfigMap,
and `server.conf` gains the attestor block with the binary's checksum.

```sh
# One PEM per hypervisor host: the issuing certificate of its swtpm local CA, the one
# that signs every vTPM's EK certificate libvirt creates (CN=swtpm-localca). Not the
# root beside it: the attestor verifies an EK against these files with no intermediates,
# so the root alone refuses every VM. Repeat for each host that runs pool VMs.
cp -r deploy/spire-tpm ~/.config/mediatore/spire-tpm
for h in hv-01 hv-02; do
  ssh $h sudo cat /var/lib/swtpm-localca/issuercert.pem > $h.pem
done
# Put them under data: of ~/.config/mediatore/spire-tpm/ek-cas.yaml (one key per host),
# add the component to your SPIRE kustomization and the block of
# server.conf.fragment.hcl to your rendered server.conf, then:
kubectl apply -k ~/.config/mediatore/spire
kubectl -n spire-server rollout restart statefulset/spire-server   # the init container copies the certificates at start
kubectl -n spire-server rollout status statefulset/spire-server
kubectl -n spire-server exec spire-server-0 -c spire-server -- \
  spire-server bundle show > bundle.pem        # the trust bundle for the VM image
```

A new hypervisor is a new key in the ConfigMap and the same restart. The whole path,
from this component to an agent attesting with a vTPM, a refusal under a CA that did not
sign the EK, and the node entry under the attested agent, runs in kind before it runs
here: `make kind-e2e-tpm` ([testing tiers](testing.md)).

If your SPIRE manifests are a Helm release today, render them once
(`helm template spire spire --repo ... -f your-values.yaml > spire.yaml`), check them
in with placeholders, and apply them with kustomize from then on; the component patches
the standard `spire-server` StatefulSet whichever way the manifests were produced.

The hash allowlist is not configured, because a VM's EK is created with the VM and the
CA route is what admits new members. On the VM side, the image carries the agent and the
plugin (the same release the server runs, pinned by digest in `image/Dockerfile`, the
plugin's checksum verified in the build against `image/spire/agent.conf`), and your
deployment layer writes `/etc/spire/agent.conf` and the bundle at every boot
([ADR-0023](../adr/0023-sandbox-vm-image-kairos-derivative.md)). `make dist-tpm-plugin` still extracts both plugin binaries into
`dist/`, for the record. A VM whose EK certificate chains to no configured host CA never
becomes an agent, and so never a node.

Both units (`image/systemd/spire-agent.service`, `mediatore-guest.service`) start only
when Kairos's installed-disk sentinel exists (`/run/cos/active_mode` or
`passive_mode`), so the live installer, which boots the same image with the same
enabled units, never attests with the member's vTPM, registers or announces
`GuestReady` mid-install ([ADR-0019](../adr/0019-guestready-after-attestation-and-registration.md)).
The image carries no phase stage of banlieue's: the guest announces after it registered.
On a non-Kairos image, drop the two `ConditionPathExists` lines or provide the sentinel,
and take the installer case on yourself.

When a claim binds, the guest loads a ruleset keyed
by the sandbox user's uid before it starts the jail, and refuses to start the jail
without it ([ADR-0020](../adr/0020-jail-network-nftables-keyed-by-sandbox-uid.md)): TCP to the broker and to the audiences' `egress`, DNS to the VM's
resolvers, the rest logged under `mediatore-sandbox drop:` and dropped. The guest's log
carries the ruleset's SHA-256 per claim, and `nft list table inet mediatore_sandbox` on
the VM shows what is loaded. Root's own egress and the input chain are not in that
table: those rules come once the image's system users are settled (roadmap 06).

The guest pulls each claim's `workload.image` itself ([ADR-0021](../adr/0021-sandbox-filesystem-tmpfs-and-rootfs-from-the-registry.md)): over HTTPS with the
Mozilla roots, anonymously, into a tmpfs it mounts at `/mnt/sandbox` for that claim
(`nosuid,nodev`, mode 0700). Two things follow for the deployment. The segment's
firewall must let members reach the registries the images live on, beside the broker
and the audiences' endpoints; and the members need memory for the unpacked image, its
largest layer and `/work` on top of the workload: `MEDIATORE_SANDBOX_SIZE` in
`/etc/mediatore-guest/env` bounds the tmpfs (`--sandbox-size`; `50%` of RAM, the kernel's
default, when unset). A registry on the segment without TLS is named in
`MEDIATORE_PLAIN_HTTP_REGISTRIES` (`--plain-http-registry`, `host:port`, comma-separated);
pin images from it by digest, since nothing else vouches for the bytes.

A private registry gets its credential from the broker, not from the image
([ADR-0022](../adr/0022-registry-pull-credentials-from-the-broker.md)): list it under `registries` in `mediatore.yaml`, with
the login and a file holding the token, mounted from a Secret like the STS key, and the
broker hands the guest that credential with the claim whose image names the registry.
The token should be read-only and scoped to the pool's images; it is one credential for
every member, which is what a pull secret is anywhere. A registry listed as plain HTTP
never receives a credential.

```yaml
registries:
  - { host: ghcr.io, username: octocat, password_file: /etc/mediatore-registry/ghcr }
```

```sh
kubectl -n banlieue-system create secret generic mediatore-registry --from-file=ghcr=./ghcr-pull-token
```

and in the overlay's Deployment patch, beside the STS volume:

```yaml
volumeMounts:
  - { name: registry, mountPath: /etc/mediatore-registry, readOnly: true }
volumes:
  - name: registry
    secret: { secretName: mediatore-registry, defaultMode: 0440 }
```

## What the NetworkPolicy allows

| Direction | Peer | Port | Why |
| --- | --- | --- | --- |
| ingress | the sandbox segment | 8443 | the guest and the jailed workload, over SPIFFE mTLS (TB-6) |
| ingress | the ingress controller's namespace | 8080 | people and their tools, bearer over the ingress's TLS (TB-1) |
| ingress | the node CIDR | 8080 | the kubelet's readiness probe, where the CNI does not exempt it |
| egress | kube-dns | 53 | names |
| egress | the control-plane addresses | 6443 | the API server: sandboxes, claims, entries, the Lease (TB-2, TB-3) |
| egress | the issuer | 5556 or 443 | discovery, JWKS, the refresh before every issue (TB-5) |

The Workload API is a socket on the node and needs no rule. Nothing else is open: the
broker never reaches the internet unless the issuer or OpenBao is there, in which case
their addresses go in. [ADR-0007](../adr/0007-broker-identity-and-spiffe-mtls.md)
decision 7 is where this was decided.
