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
| An ingress for the user API, a LoadBalancer for the sandbox listener | the Tailscale operator's ingress class and MetalLB in the example | `:8080` to people; `:443` on the LoadBalancer (the pod's 8443) to pool VMs, so `MEDIATORE_URL` in the members' env file names the address alone |

None of those are this repository's to install. What follows is.

## 1. Copy the example overlay and put your values in

```sh
cp -r deploy/overlays/homelab-example ~/.config/mediatore/core
```

Keep the copy outside the repository: it will carry your trust domain, your issuer's
URL, your CIDRs. Edit:

- `mediatore.yaml`: `trust_domain`, `issuers` (from the [issuers guide](issuers.md)),
  `audiences`, each with the `egress` the jail may reach for it (`host:port` pairs; an
  audience without one yields tokens the workload can spend nowhere, [ADR-0020](../adr/0020-jail-network-nftables-keyed-by-sandbox-uid.md);
  an endpoint belongs to one audience only), optionally the `rules` the egress proxy
  enforces for it (`{ method, path }` globs, [ADR-0025](../adr/0025-phantom-token-egress-proxy.md);
  none means every method and path) and, for an audience on a private PKI, the `ca_file`
  the proxy trusts for its endpoints instead of the Mozilla roots (a PEM from a Secret
  volume, read at start; the homelab overlay mounts one),
  `sts.issuer` (what downstream services will see as `iss`), and
  `spire.entries.class_name` if SPIRE was rendered with another namespace or release
  name (the class is `<namespace>-<release name>`, `spire-server-spire` in the example),
  and, with notaio installed, the `policy` section: notaio's signing public keys and the
  namespaces whose bundles to read and compare with each sandbox, which refuses nothing
  yet ([ADR-0026](../adr/0026-notaio-bundles-verified-in-shadow.md)). A key that is not a
  32-byte Ed25519 key, or an id listed twice, stops the start. The broker reads bundles
  with a Role per listed namespace, `get`, `list` and `watch` on ConfigMaps and nothing
  else: `kubectl apply -k deploy/policy-bundles` grants it in `sandboxes`, and another
  namespace is a two-line overlay of that directory setting `namespace:`
  ([the policy bundle, in shadow](the-policy-bundle.md)), and, once the environment has
  its egress gateways, `gateways`: their `sandbox` addresses and data-plane port as
  `host:port` pairs, addresses not names, in the order every guest receives them on
  `GET /v1/me` ([ADR-0028](../adr/0028-egress-gateway-envoy-with-spiffe-identity.md)
  decision 6; one listed twice stops the start). With it set, every guest's egress proxy
  tunnels its upstreams through one of them as the claim (the forwarder, decisions 3 and
  7) and the sandbox ruleset takes its gateway shape: the relay, the gateways and the
  proxy by address, no DNS, no audience endpoint ([step 7](#7-the-egress-gateways)).
  Leave it out until then: the proxy then dials the audiences' `egress` directly, as
  before, and says so once at start. `spire.entries.claim_svid_ttl` is at most `15m`
  (the default; [ADR-0027](../adr/0027-control-plane-relay-on-the-egress-gateway.md)
  decision 7: a claim's identity ends within that of its release or of losing the
  gateways, and never outlives the claim);
- `networkpolicy.yaml`: the sandbox segment's CIDR for `:8443`, the control-plane
  addresses for the API server, the node CIDR for the kubelet's probe, and the
  issuer's namespace or addresses;
- `ingress.yaml`: the ingress class and hostname, if not Tailscale's;
- `kustomization.yaml`: the image tag, pinned to a digest or a `sha-<commit>` tag of
  [the published image](https://github.com/firestoned/mediatore/pkgs/container/mediatore).

`kubectl kustomize ~/.config/mediatore/core` renders the whole thing; read it once.

## 2. Create the Secrets the overlay expects

The overlay generates no secret. Two Secrets in `banlieue-system`, each a file the
broker reads at startup (the store needs none: it is the cluster's API, [the store](the-store.md)):

```sh
# The STS signing key (ES256), whose public half becomes the broker's JWKS.
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out sts.pem
kubectl -n banlieue-system create secret generic mediatore-sts --from-file=sts.pem

# The sealing key for refresh material (ADR-0012 decision 3), the local sealer.
openssl rand -hex 32 > sealing.key
kubectl -n banlieue-system create secret generic mediatore-sealing --from-file=key=sealing.key
```

Delete the local files afterwards. With the transit sealer ([the store](the-store.md))
the sealing Secret is not needed; with Entra ([the Entra path](the-entra-path.md)) a
fourth Secret holds the client credential.

An audience served from a credential you hold (`via: secret`, [ADR-0032](../adr/0032-operator-held-credentials-as-an-audience-backend.md):
an API key the upstream issued you, Anthropic's for Claude from inside the sandbox) is one
more Secret, one key per file, mounted read-only where `audiences[].secret_file` points,
`defaultMode: 0440` with the `fsGroup` the overlay already sets:

```sh
# Paste the key when prompted, so it is in neither your shell history nor a file.
read -rs ANTHROPIC_KEY && kubectl -n banlieue-system create secret generic mediatore-audience-secrets \
  --from-literal=anthropic="$ANTHROPIC_KEY" && unset ANTHROPIC_KEY
```

The broker reads each file once at start and refuses to start on an empty one; it never
writes the value anywhere. Rotate by editing the Secret and restarting the broker: every
proxy holds the old value for at most that audience's `max_ttl`.

## 3. Apply, and read the start-up log

```sh
kubectl apply -k ~/.config/mediatore/core
kubectl -n banlieue-system rollout status deploy/mediatore
kubectl -n banlieue-system logs deploy/mediatore | head -40
```

The broker fails the start on anything it cannot use, and says which: a key file that
does not parse, an issuer whose discovery document it cannot fetch, a class name the
controller manager does not serve. What a healthy start logs, in order: the store (the
Kubernetes API, ADR-0034), the sealing key loaded, each issuer (and `issuer pinned
to a private CA` when `ca_file` is set), `broker SVID` from the Workload API, the
listeners, `claim watcher running` on the replica that holds the Lease.

`/healthz` on the user API answers true only while the API server answers the store;
the Ingress routes to it.

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
mediatore sandbox create --mediatore https://mediatore.<tailnet> --pool pool-a \
  --audience grafana.home.example --image registry.internal:5000/sandbox:latest
```

Each claim spends the delegated refresh token, so log in again before the next one.
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
base shipped removed, the `spire` user created, both units enabled and Yama's `ptrace_scope` raised to 1 (`image/sysctl/`). The Build workflow
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

A `Url` source needs banlieue-imagebuilder and the kairos-operator on the cluster; without
them the `VMImage` stays `BuildPending` on every provider. The other route, the one the
live proof took: merge the three layers yourself (maps deep-merged, lists concatenated, in
that order, with the `#cloud-config` header), build the installer ISO on a host with
AuroraBoot (`build-iso --cloud-config merged.yaml --override-name <name> docker://ghcr.io/firestoned/mediatore-guest@sha256:<digest>`),
put it in the libvirt pool the `VMClass`'s storage class maps to (`virsh pool-refresh`),
and declare `sources: [{providerClass: libvirt, kind: BackingFile, ref: <name>.iso}]` with
`installMode: deferred`: the member installs from the CD-ROM, which is ejected when the
guest reports its phase. Two things to know for either route. The bundle in the deployment
layer is what a member trusts on its first boot: with the server under the OpenBao upstream
authority ([ADR-0031](../adr/0031-a-trust-anchor-that-outlives-the-servers-ca.md), the
`deploy/spire-upstream` block below) it is the PKI root and a layer stays good for the
root's ten years; on a server signing with its own CA it is that CA and the layer admits a
first boot only for its `ca_ttl` (24 h in a default Helm render: the pool churns a day
after the layer was built, which both rc.3 and rc.4 ran into). And
`/etc/mediatore-guest/env` takes whole-line comments only, since systemd's
`EnvironmentFile` keeps an inline comment as part of the value.

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

The trust domain's root lives in OpenBao's PKI engine, not on the server
([ADR-0031](../adr/0031-a-trust-anchor-that-outlives-the-servers-ca.md)): the second
component, `deploy/spire-upstream`, makes the server's CA an intermediate OpenBao signs
every `ca_ttl`, and the bundle every layer carries becomes the root. The OpenBao side is
a PKI mount, a root, a policy that allows signing intermediates and nothing else, and a
Kubernetes auth role for the server's ServiceAccount (the same OpenBao as the transit
sealer, [ADR-0015](../adr/0015-transit-sealer.md); `dev/kind/openbao-setup.sh` is the
reference, with the kind names):

```sh
# At OpenBao, as an administrator. The root is ten years; the mount's maximum lease then
# comes down to a week, which caps any intermediate the server's token could ask for.
bao secrets enable -path=spire pki
bao secrets tune -max-lease-ttl=87600h spire
bao write spire/root/generate/internal common_name=sandbox.home.example key_type=ec key_bits=384 ttl=87600h issuer_name=root
bao secrets tune -max-lease-ttl=168h spire
bao policy write spire-upstream - <<'HCL'
path "spire/root/sign-intermediate" { capabilities = ["update"] }
HCL
bao write auth/kubernetes/role/spire-server bound_service_account_names=spire-server \
  bound_service_account_namespaces=spire-server audience=openbao token_policies=spire-upstream token_ttl=1h
bao read -field=certificate spire/cert/ca > upstream-root.pem   # what every layer's bundle.pem becomes

# On the cluster: the CA that signed OpenBao's TLS certificate, before the server starts,
# then the component and the fragment's block (vault_addr and the role are yours).
kubectl -n spire-server create configmap spire-upstream-ca --from-file=ca.pem=openbao-ca.pem
cp -r deploy/spire-upstream ~/.config/mediatore/spire-upstream
kubectl apply -k ~/.config/mediatore/spire
kubectl -n spire-server rollout status statefulset/spire-server
kubectl -n spire-server exec spire-server-0 -c spire-server -- spire-server bundle show
```

A server that already has a CA keeps it across the restart, and the next one it had
prepared too: the upstream signs only when a new authority is prepared, which the server
does on its own halfway through `ca_ttl`. To have the root in the bundle now rather than
within a day, prepare and activate a new authority on each server:

```sh
for p in spire-server-0 spire-server-1; do
  kubectl -n spire-server exec $p -c spire-server -- spire-server localauthority x509 prepare
  kubectl -n spire-server exec $p -c spire-server -- spire-server localauthority x509 show   # the prepared authority's ID, upstream-signed
  kubectl -n spire-server exec $p -c spire-server -- spire-server localauthority x509 activate -authorityID <prepared>
done
# The servers' own serving certificates were issued by the old CA and rotate at their
# half-life; until then a member holding the root alone logs "Trust Bundle and Server
# don't agree". A restart re-mints them under the new authority, chain included.
kubectl -n spire-server rollout restart statefulset/spire-server
kubectl -n spire-server rollout status statefulset/spire-server
echo | openssl s_client -connect <server address>:8081 -showcerts 2>/dev/null \
  | openssl verify -CAfile upstream-root.pem   # from the root alone, with the chain presented
```

The switch has no cliff. The server's bundle after the rotation holds the OpenBao root
and, until the old CA retires one `ca_ttl` later, the self-signed CA; running agents
receive it over the attested channel; a layer built before the switch still verifies the
server for the rest of that CA's life; the next layer you build carries the root alone
(`upstream-root.pem` above, or `bundle show` once the old CA is gone) and is the last one
you rebuild for this reason. If OpenBao is away when the server prepares its next
intermediate (halfway through `ca_ttl`, so twelve hours of slack) the server keeps
signing with the current one until it expires and issues nothing after; size OpenBao for
that. A chart-managed server reaches the same state through the hardened chart's
`upstreamAuthority.vault` values instead of the component (`caCert` as a ConfigMap with
the key `ca.crt`, `k8sAuth.token.audience` the role's audience); the chart mounts the CA
and the projected token itself, and the rotation above is the same.

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
without it ([ADR-0020](../adr/0020-jail-network-nftables-keyed-by-sandbox-uid.md)). Its
shape follows the environment. With egress gateways (the broker's `gateways`, or the
pool's `/etc/mediatore/gateways` when the broker lists none): TCP to the broker, which is
the control relay at a gateway's `sandbox` address, to the three gateways' data port and
to the egress proxy on loopback, every one an address, and nothing else, no DNS rule at
all ([ADR-0028](../adr/0028-egress-gateway-envoy-with-spiffe-identity.md) decision 6); a
broker or a gateway given by name refuses the claim, since the segment has no resolver.
Without a gateway: TCP to the broker, to the audiences' `egress` resolved at load and to
the proxy, DNS to the VM's resolvers. In both, the rest is logged under
`mediatore-sandbox drop:` and dropped, and a packet to the proxy's port from any other uid
is dropped too. The guest's log carries the shape and the ruleset's SHA-256 per claim, and
`nft list table inet mediatore_sandbox` on the VM shows what is loaded. Root's own egress
and the input chain are not in that table: those rules come once the image's system users
are settled (roadmap 06).

The guest then starts `mediatore egress-proxy` as the sandbox user, outside the jail, on
`127.0.0.1:3128` (`--egress-proxy-port`, or `MEDIATORE_EGRESS_PROXY_PORT`, on the guest's
unit; a claim whose broker or `egress` uses that port is refused), and only then the jail
([ADR-0025](../adr/0025-phantom-token-egress-proxy.md)). The jail has no Workload API
socket and no route to the broker: it reaches the proxy, the proxy reaches the broker (for
tokens, over the claim's SVID) and the audiences' endpoints over TLS 1.3 to the Mozilla
roots, or to the CA named by the audience's `ca_file`, which travels to the guest on the
route. In an environment with `gateways`, that upstream connection is a tunnel through one
of them, opened as the claim with its SVID and `CONNECT host:port`, the upstream's TLS
inside it ([ADR-0028](../adr/0028-egress-gateway-envoy-with-spiffe-identity.md) decision
3); the list is walked from a random start, a gateway that is down or answering with its
own `5xx` is skipped, and a gateway's refusal (`4xx`, the authorizer's `403`) is `502` with
`gateway_refused` at the workload and the authorizer's code in the proxy's log. The proxy's log names the audience, the host, the method, the path, the
gateway and the status of every request it forwards or refuses, never a token.

The guest pulls each claim's `workload.image` itself ([ADR-0021](../adr/0021-sandbox-filesystem-tmpfs-and-rootfs-from-the-registry.md)): over HTTPS with the
Mozilla roots, anonymously, into a tmpfs it mounts at `/mnt/sandbox` for that claim
(`nosuid,nodev`, mode 0711). Two things follow for the deployment. The segment's
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

## 7. The egress gateways

With the pool attesting, the environment's egress goes through the three gateway VMs of
banlieue ADR-0109 and [ADR-0028](../adr/0028-egress-gateway-envoy-with-spiffe-identity.md):
Envoy with the identity `spiffe://<td>/gateway`, authorizing every tunnel on the caller's
claim against the broker, and beside it the control relay of
[ADR-0027](../adr/0027-control-plane-relay-on-the-egress-gateway.md), through which a pool
VM reaches the SPIRE server and the broker at all (the segment has no route and no
resolver). Everything is image content and ordinary banlieue objects; banlieue gains no
kind.

**The image.** `image/gateway/Dockerfile` is the same Kairos derivative as the sandbox
image with Envoy copied from its official image at the digest the kind tier runs
(`dev/kind/gateway/kustomization.yaml`), the authorizer (`mediatore gateway`, the one
binary), the agent and the plugin, `nftables`, and three service users. The Build workflow
publishes it as `ghcr.io/firestoned/mediatore-gateway`, signed and attested; `make
gateway-image` builds it locally and `make gateway-image-check` proves what it carries
(both Envoys unprivileged with no capability and a read-only root, the relay kept out of
`/run/spire`, the host table, no sshd, forwarding off, the examples filling every
template). Nothing in it is yours: at every unit start `image/gateway/render` fills the two
Envoy bootstraps, the host table and the sandbox interface's networkd file from two env
files, the deployment's `/etc/mediatore-gateway/env` (`image/gateway/env.example`: the
trust domain, the sandbox NIC's name and prefix, the ports, the SPIRE server's and the
broker's addresses on the egress side, the broker's URL for the authorizer) and the VM's
`vm.env` (`image/gateway/vm.env.example`: its sandbox address). Addresses, not names,
throughout: the gateway is what resolves names for everyone else.

**The layers and the objects** are `deploy/gateway/`, with placeholders: the `VMImage`
(three cloud-config Secrets like the sandbox image's: `image/gateway/cloud-config.yaml`,
banlieue's EK-certificate layer, your copy of
`image/gateway/cloud-config-deployment.example.yaml` with the agent's configuration, the
bundle and the env file), the two-interface `VMClass` (`egress` first, on a routable class
with the subnet's gateway and resolver, so it carries the static address and the default
route; `sandbox` second, on the segment, with no address from banlieue), and the three
`VirtualMachine`s: the egress address of each in `networkOverrides`, its sandbox address in
a ConfigMap as `userData`, a required anti-affinity across the `host` key so no two share
a failure domain (banlieue ADR-0098). The same `userData` carries a networkd file for the
egress NIC written from banlieue's placeholders (`${IP}`, `${PREFIX}`, `${GATEWAY}`,
`${DNS}`): a Kairos guest reads no `network-config` from the seed (banlieue ADR-0114
decision 4), so `networkOverrides` reaches it through that stage and nothing else. Its
`Name=` is the first NIC's name on your machine type (`ens2` on libvirt's pc-i440fx,
`enp1s0` on q35); the sandbox NIC is `SANDBOX_IF` in the deployment layer's env. On one
host, drop the anti-affinity or set it `preferred`.

```sh
cp -r deploy/gateway ~/.config/mediatore/gateway     # then put your addresses, hashes and names in
kubectl kustomize ~/.config/mediatore/gateway | less  # read it once
kubectl apply -k ~/.config/mediatore/gateway
```

**The identity.** Each gateway attests with its vTPM like a pool member (the same
`deploy/spire-tpm` component, its host's CA in the ConfigMap), and the SPIRE server logs
its agent ID, `spiffe://<td>/spire/agent/tpm/<ek-hash>` (`spire-server agent list` shows
it). That hash goes into two `ClusterStaticEntry` objects per VM
(`deploy/gateway/clusterstaticentries.yaml`): `spiffe://<td>/gateway` for `unix:user:envoy`
(the data plane, over SDS) and for `unix:user:mediatore-gateway` (the authorizer), since one
entry's selectors are a conjunction. You apply them, not the broker: its admission policy
constrains only its own ServiceAccount. The relay gets no entry. The data plane refuses
every peer that is not a claim of the trust domain before any check runs, so a sandbox
cannot reach the relay's upstreams through it, and the authorizer asks the broker over
`GET /v1/gateway/claims/{uid}` with the gateway SVID, on the egress side.

A gateway drops ICMP, so `ping` proves nothing about one; a TCP connect to its relay
ports from the segment, or `nft list table inet mediatore_gateway` on its console, does.

**The pool behind them.** The pool's deployment layer changes in four places
(`image/cloud-config-deployment.example.yaml` shows them): the agent's `server_address`
is a gateway's sandbox address with port `3129`, `MEDIATORE_URL` is
`https://<the same address>:3130`, `/etc/mediatore/gateways` lists the three sandbox
addresses with the data port, the list the guest uses until the broker's `gateways` arrives
(ADR-0027 decision 4), and `/etc/mediatore/registries` lists the mirror below. The broker's
`gateways` lists the same three. The agent holds one server address, so it fails over
between gateways only when it restarts; the forwarder fails over per connection. The
pool's members take their addresses from the pool's `addressing` (banlieue ADR-0056: the
class's one interface on the segment's network class with `ipam: {}`, a range of the
segment, no gateway and no nameserver), and, the image being Kairos, from a `userData`
stage on the pool's template writing `/etc/systemd/network/10-static.network` with
`Address=${IP}/${PREFIX}`, which banlieue renders per member; without that stage a member
boots with no address at all, since the segment has no DHCP.

**The mirror, and the host table.** A pool VM on the segment reaches the gateways and its
neighbours and nothing else, so it cannot pull a workload image from `ghcr.io` or
`docker.io`: a gateway-era pool pulls from the operator's registry on the segment, a
registry or pull-through mirror with an address there
([ADR-0029](../adr/0029-the-pull-on-a-routeless-segment-and-the-pool-vms-root-rules.md)
decision 1), and the images your requesters name are the ones you mirrored, which is also
where image review belongs. When the mirror runs on the host that owns the segment's
bridge, it must listen on that host's segment address itself: libvirt's isolated network
rejects anything forwarded off the bridge, a container's port mapping included, and a
member sees `connection refused`. Declare it twice, once on each side. On the broker,
`registries[]` gains `reach: segment` on every entry once `gateways` is set (the broker
refuses to start otherwise), and an entry may carry no credential at all for an anonymous
mirror (`- { host: "198.51.100.10:5000", reach: segment }`); a claim whose image names any
other registry is refused at `POST /v1/claims` with `unreachable_registry`, and an
`AgentSandbox` naming one fails before any claim exists, both naming the registries the
pool reaches. On the pool, `/etc/mediatore/registries` lists the mirror's address and port
(addresses, like everything on the segment), and either `MEDIATORE_PLAIN_HTTP_REGISTRIES`
names it for a plain-HTTP mirror (pin by digest; no credential crosses plain HTTP,
ADR-0022) or `MEDIATORE_REGISTRY_CA` points at the PEM of the CA your mirror's certificate
chains to, trusted beside the Mozilla roots for the pull.

With `/etc/mediatore/gateways` present the image loads a second table at boot,
`inet mediatore_host`, before the agent and the guest may start (ADR-0029 decision 3;
`image/host-table`, `mediatore-host-nft.service`): input default drop but loopback and
established traffic, output default drop but loopback, established traffic and TCP to the
three gateways' data port, the relay's two ports (read from `MEDIATORE_URL` and the agent's
`server_address`) and the registries file, forward dropped, every entry an IPv4 address
and a port or the table refuses to load and the VM stays down. That is the bound on root
and every other uid; the sandbox uid's per-claim table sits beside it. Without the
gateways file the unit is skipped and the pool runs as before. `nft list table inet
mediatore_host` on a member shows it; `make host-table-test` pins the text.

**What the network must do**, outside this repository: the segment's VLAN trunked on every
host of the zone (banlieue ADR-0109 decision 3), the three gateways' `egress` addresses
allowed to reach the SPIRE server's attestation port, the broker's sandbox listener and the
audiences' endpoints, and the SPIRE server and the broker admitting those three addresses
and nothing from the sandbox range (ADR-0027's consequences). The broker's
`networkpolicy.yaml` already carries the row for the gateways' addresses on `8443`; with
the relay in place the sandbox segment's own row on `8443` is no longer needed, since no
sandbox reaches the listener directly any more.

**What proves it before a VM does.** `make kind-e2e-gateway` runs the data plane end to end
against a real Envoy on the bootstrap the image renders (`make gateway-render-check` keeps
the two identical), `make gateway-image-check` the image, and `nft -c` on the build host
both rulesets ([testing tiers](testing.md)). The live run on three VMs and a pool VM behind
them, roadmap 06's libvirt proof extended with the gateways, happened on 2026-11-05
against v0.2.0-rc.4: the whole path held, and what it found (the three image defects,
the mirror behind a port mapping, the Kairos stages above) is fixed or written here.

## What the NetworkPolicy allows

| Direction | Peer | Port | Why |
| --- | --- | --- | --- |
| ingress | the sandbox segment | 8443 | the guest and the egress proxy, over SPIFFE mTLS (TB-6); with the control relay in place ([step 7](#7-the-egress-gateways)) this row narrows to the gateways' `egress` addresses below, since no sandbox reaches the listener directly any more |
| ingress | the gateways' `egress` addresses | 8443 | the gateway's authorizer asking what a claim may reach, over SPIFFE mTLS with the gateway SVID ([ADR-0028](../adr/0028-egress-gateway-envoy-with-spiffe-identity.md) decision 4), and the control relay carrying the pool VMs' own node and claim sessions to the listener ([ADR-0027](../adr/0027-control-plane-relay-on-the-egress-gateway.md) decision 3) |
| ingress | the ingress controller's namespace | 8080 | people and their tools, bearer over the ingress's TLS (TB-1) |
| ingress | the node CIDR | 8080 | the kubelet's readiness probe, where the CNI does not exempt it |
| egress | kube-dns | 53 | names |
| egress | the control-plane addresses | 6443 | the API server: sandboxes, claims, entries, the Lease (TB-2, TB-3) |
| egress | the issuer | 5556 or 443 | discovery, JWKS, the refresh before every issue (TB-5) |

The Workload API is a socket on the node and needs no rule. Nothing else is open: the
broker never reaches the internet unless the issuer or OpenBao is there, in which case
their addresses go in. [ADR-0007](../adr/0007-broker-identity-and-spiffe-mtls.md)
decision 7 is where this was decided.

The two `8443` rows only hold if the client's source address reaches the pod intact, which
is why `deploy/base/service-sandbox.yaml` sets `externalTrafficPolicy: Local` on the
sandbox Service: with the default `Cluster`, a node that forwards to a broker pod on
another node masquerades the connection as itself and the policy refuses it. Under
`Local` the load balancer (MetalLB in the homelab) announces the address from the pod's
node, and the source stays what the segment sent. Since ADR-0034 nothing pins the pod to a
node, so this matters on the first reschedule.
