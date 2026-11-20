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

Every release attaches what the install needs beside the three images (the server, the
guest and the gateway): the binary for Linux
(`mediatore-<version>-linux-amd64`, static, every role) and for a Mac
(`mediatore-<version>-darwin-arm64`, the CLI: `login`, `logout`, `sandbox`, `session`), `mediatore-<version>.yaml`
(this `deploy/base` with the server image pinned by digest), the `VMImage`s of step 6 and
step 7 pinned to the guest and gateway images' digests with the two cloud-config layers
each names, the SBOMs and
`checksums.sha256`, each file attested by the Build workflow. Every binary and all three images
report the release's version (`mediatore --version` prints `mediatore <version>`): the
workspace version is set from the tag before each build, and the release job refuses a
binary that says otherwise. An overlay can name the manifest instead of a checkout, and
every asset verifies offline:

```sh
# <version> is the release, v0.3.0 at the time of writing.
gh release download v<version> --repo firestoned/mediatore --pattern 'mediatore-<version>*' --pattern checksums.sha256 | tee
shasum -a 256 -c checksums.sha256
# The attestation must come from the Build workflow, run for this release's tag: the
# repository alone would also accept a file attested by any other workflow or ref in it.
gh attestation verify mediatore-<version>.yaml --repo firestoned/mediatore \
  --signer-workflow firestoned/mediatore/.github/workflows/build.yaml \
  --source-ref refs/tags/v<version> | tee
# kustomization.yaml of your overlay:
#   resources:
#     - https://github.com/firestoned/mediatore/releases/download/v<version>/mediatore-<version>.yaml
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
  volume mounted like the STS key, read at start; the example overlay leaves the key
  commented out),
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
- `kustomization.yaml`: the server image's digest, the one the release's
  `mediatore-<version>.yaml` carries for
  [the published image](https://github.com/firestoned/mediatore/pkgs/container/mediatore).
  The example carries a placeholder digest of zeros, so an unedited copy pulls nothing.

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
third Secret holds the client credential.

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
to a private CA` when `ca_file` is set), the listeners (`listening`), `broker identity
from the Workload API`, `claim watcher running` on the replica that holds the Lease.

`/healthz` on the user API answers true only while the API server answers the store;
the Ingress routes to it.

An upgrade across the change of ADR-0057 has an order (the detail is in
[the store](the-store.md)): apply the CRDs first (`kubectl apply -f deploy/base/crds`), since
the record gains two fields the API server would otherwise prune, then replace the broker in
one step, old replicas at zero before the new ones start. A broker from before the change
cannot open an envelope the new one sealed, and if it rewrites the Secret it leaves it
unopenable, so the two never run side by side.

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
`ready` turns true once the attested member's guest has registered (step 6). On a pool
whose members do not attest (no TPM attestor on the server, or an image without the
guest), a claim binds and nothing registers, so `ready` stays false and the claim
fails after `watcher.resolve_timeout_secs`; the API, the issuer, the store, the
entries and the policies are nonetheless live at that point. With the image of step 6
the pool's `GuestReady` is the guest's own announcement after it registered ([ADR-0019](../adr/0019-guestready-after-attestation-and-registration.md)),
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
base shipped removed, the `spire` user created, the four units (the agent, the guest, the host table, the bundle fetch) enabled and Yama's `ptrace_scope` raised to 1 (`image/sysctl/`). The Build workflow
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
# A release's image: attested by the Build workflow, run for that release's tag.
gh attestation verify oci://ghcr.io/firestoned/mediatore-guest@sha256:<digest> --repo firestoned/mediatore \
  --signer-workflow firestoned/mediatore/.github/workflows/build.yaml \
  --source-ref refs/tags/v<version> | tee
# The keyless Cosign signature, pinned to the same workflow and tag (escape the dots of
# <version> in the expression).
cosign verify ghcr.io/firestoned/mediatore-guest@sha256:<digest> \
  --certificate-identity-regexp '^https://github\.com/firestoned/mediatore/\.github/workflows/build\.yaml@refs/tags/v<version>$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The same two commands verify the server image (`ghcr.io/firestoned/mediatore`) and the
gateway image of step 7 (`ghcr.io/firestoned/mediatore-gateway`). An image built from a
merge to `main` rather than a release verifies with `--source-ref refs/heads/main` and
`@refs/heads/main$`.

Pool VMs become SPIRE agents with their vTPM ([ADR-0018](../adr/0018-tpm-attestation-with-the-spiffe-plugin.md)).
On the server side it is a kustomize component, `deploy/spire-tpm`, that your SPIRE
kustomization includes: an init container puts the attestor plugin (pinned by digest)
into the server pod together with the EK trust anchors it copies out of a ConfigMap,
and `server.conf` gains the attestor block with the binary's checksum.

```sh
# One PEM per swtpm local CA: the issuing certificate (CN=swtpm-localca) that signs every
# vTPM's EK certificate the hypervisor creates. libvirt's lives at
# /var/lib/swtpm-localca/issuercert.pem; banlieue's Cloud Hypervisor provider runs its own
# swtpm with its own CA, /var/lib/banlieue/swtpm-localca/issuercert.pem (the statedir in
# /etc/banlieue/swtpm/swtpm-localca.conf), same CN, a different key. A host that runs both
# providers contributes both. Not the root beside either: the attestor verifies an EK
# against these files with no intermediates, so the root alone refuses every VM.
cp -r deploy/spire-tpm ~/.config/mediatore/spire-tpm
for h in hv-01 hv-02; do
  ssh $h sudo cat /var/lib/swtpm-localca/issuercert.pem > $h.pem               # libvirt
  ssh $h sudo cat /var/lib/banlieue/swtpm-localca/issuercert.pem > $h-ch.pem   # Cloud Hypervisor, where it runs
done
# Put them under data: of ~/.config/mediatore/spire-tpm/ek-cas.yaml (one key per CA),
# add the component to your SPIRE kustomization and the block of
# server.conf.fragment.hcl to your rendered server.conf, then:
kubectl apply -k ~/.config/mediatore/spire
kubectl -n spire-server rollout restart statefulset/spire-server   # the init container copies the certificates at start
kubectl -n spire-server rollout status statefulset/spire-server
kubectl -n spire-server exec spire-server-0 -c spire-server -- \
  spire-server bundle show > bundle.pem        # the trust bundle for the VM image
```

A VM whose EK was signed by a CA the ConfigMap lacks is refused at every attempt, and the
server says so: `Nodeattestor(tpm): could not verify cert: x509: certificate signed by
unknown authority (... candidate authority certificate "swtpm-localca")`. Its agent exits
and restarts every few seconds, and so does every unit that `Requires=` it. On a gateway
that is the data plane: `8443` open for half a minute and refused for a quarter, over and
over, while the relay ports hold. Add the CA, restart the servers, and check that the
certificate you added is the one that issued the VM's EK (`VirtualMachine`
`.status.tpmEndorsementCertificates`, `openssl verify -CAfile`).

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

All four units (`image/systemd/spire-agent.service`, `mediatore-guest.service`,
`mediatore-host-nft.service`, `spire-bundle-fetch.service`) start only
when Kairos's installed-disk sentinel exists (`/run/cos/active_mode` or
`passive_mode`), so the live installer, which boots the same image with the same
enabled units, never attests with the member's vTPM, registers or announces
`GuestReady` mid-install ([ADR-0019](../adr/0019-guestready-after-attestation-and-registration.md)).
The image carries no phase stage of banlieue's: the guest announces after it registered.
On a non-Kairos image, drop the two `ConditionPathExists` lines from each unit or provide
the sentinel, and take the installer case on yourself.

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
and the input chain are not in that table: they are the host table's (`inet
mediatore_host`, below), loaded when `/etc/mediatore/gateways` is present.

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

### Nodes of VMs that are gone

Every VM that registers leaves a `SandboxNode`, and a pool that recycles its members (one-shot
claims end their VM) would add one per VM for ever. The broker removes the node of a VM that no
longer exists ([ADR-0039](../adr/0039-a-node-leaves-the-register-when-its-vm-is-gone.md)): at
each resync, on the replica holding the watcher's Lease, when no pool member `VirtualMachine`
publishes its EK hash. Two settings matter. `watcher.resync_secs` (five minutes) is how often it
looks; `store.node_grace_secs` (ten minutes, zero refused) is how old a registration must be
before it can go, so a registration that precedes its VM's published certificate is never
collected. The ClusterRole in `deploy/base/rbac.yaml` already grants `delete` on `sandboxnodes`
and `list` on `virtualmachines`; check a role you maintain yourself has both. A banned node stays
until you delete it. `kubectl get sandboxnodes` should settle at
about the size of the pool plus the grace's worth of churn.

## 7. The egress gateways

With the pool attesting, the environment's egress goes through the three gateway VMs of
banlieue ADR-0109 and [ADR-0028](../adr/0028-egress-gateway-envoy-with-spiffe-identity.md):
Envoy with the identity `spiffe://<td>/gateway`, authorizing every tunnel on the caller's
claim against the broker through the authorizer beside it, which holds an identity of its
own, `spiffe://<td>/gateway/authorizer`
([ADR-0053](../adr/0053-the-gateways-authorizer-has-an-identity-of-its-own.md)), and beside
those the control relay of
[ADR-0027](../adr/0027-control-plane-relay-on-the-egress-gateway.md), through which a pool
VM reaches the SPIRE server and the broker at all (the segment has no route and no
resolver). Everything is image content and ordinary banlieue objects; banlieue gains no
kind.

**The image.** `image/gateway/Dockerfile` is the same Kairos derivative as the sandbox
image with Envoy copied from its official image at the digest the kind tier runs
(`dev/kind/gateway/kustomization.yaml`), the authorizer (`mediatore gateway`, the one
binary), the agent and the plugin, `nftables`, and four service users. The Build workflow
publishes it as `ghcr.io/firestoned/mediatore-gateway`, signed and attested; `make
gateway-image` builds it locally and `make gateway-image-check` proves what it carries
(all three Envoys unprivileged with no capability and a read-only root, the inject one
installed but off until a deployment turns it on, the relay kept out of
`/run/spire`, the host table, no sshd, forwarding off, the examples filling every
template). Nothing in it is yours: at every unit start `image/gateway/render` fills the three
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
it). That hash goes into the `ClusterStaticEntry` objects of that VM
(`deploy/gateway/clusterstaticentries.yaml`), one per user since one entry's selectors are
a conjunction, and two identities between them (ADR-0053):

| Entry | `spiffeID` | selector | held by |
| --- | --- | --- | --- |
| `gateway-NN-envoy` | `spiffe://<td>/gateway` | `unix:user:envoy` | the data plane, over SDS |
| `gateway-NN-envoy-inject` | `spiffe://<td>/gateway` | `unix:user:envoy-inject` | the inject listener, where an audience is gateway-placed |
| `gateway-NN-authorizer` | `spiffe://<td>/gateway/authorizer` | `unix:user:mediatore-gateway` | the authorizer, as a client of the broker |

`spiffe://<td>/gateway` is the name every sandbox's forwarder verifies and no peer of the
broker: the broker's sandbox listener refuses it at the handshake and its two gateway
routes answer the authorizer's ID alone. The authorizer asks the agent for its own SVID by
ID and does not start without it (Envoy then refuses every tunnel), so never give its user
the listeners' ID, nor a listener's user the authorizer's. You apply the entries, not the
broker, and `deploy/base/admission/clusterstaticentry-gateway.yaml` pins their shape for
whoever does: these two IDs, each with its own users' selector, one selector per entry, and
nothing else under `/gateway`. The relay gets no entry. The data plane refuses
every peer that is not a claim of the trust domain before any check runs, so a sandbox
cannot reach the relay's upstreams through it, and the authorizer asks the broker over
`GET /v1/gateway/claims/{uid}` with its own SVID, on the egress side. The agent ID is
the vTPM's, not the VM's name: a gateway recreated (a provider change, a host move, a
deleted VM) comes back with a new vTPM, a new EK and a new agent ID, and its entries
name a parent that no longer attests until you regenerate them from the new hash
(`openssl x509 -pubkey -noout < ek.pem | openssl pkey -pubin -outform der | sha256sum` on
the first RSA certificate in `.status.tpmEndorsementCertificates` gives it without the
server). Its Envoy then has no SVID to serve and `8443` stays closed, or flaps if the
attestation itself fails (above).

**What a gateway's own processes may dial.** The host table has an output chain keyed on the
socket's owner (ADR-0053 decisions 5 and 6), rendered from the same env file as the rest and
loaded in the same transaction: no table, no listener. Established traffic is accepted
first, so each rule is about a new connection.

| User | New connections admitted |
| --- | --- |
| `mediatore-gateway` (the authorizer) | `BROKER_ADDRESS` at `BROKER_PORT`, nothing else |
| `envoy-relay` | its four upstreams (`SPIRE_SERVER_*`, `BROKER_*`, `SPIRE_BUNDLE_*`, `REGISTRY_*`), each by address and port, nothing else |
| `spire` (the agent) | `SPIRE_SERVER_ADDRESS` at `SPIRE_SERVER_PORT`, nothing else |
| `envoy`, `envoy-inject` | any IPv4 destination that is not loopback or one of the VM's own addresses, link-local (`169.254.0.0/16`), one of the four control-plane addresses of the env file, or an entry of `EGRESS_DENY_ELEMENTS`; no IPv6. The tunnel Envoy keeps one loopback exception, the authorizer's check port, while that is loopback TCP |
| every other user, root included | as before, except `BROKER_ADDRESS`, on any port |

No user opens a new connection by the sandbox interface. Three consequences for your env
file. `MEDIATORE_URL` must be `https://BROKER_ADDRESS` (with `:BROKER_PORT` unless that is
`443`): an address, never a name, and the authorizer's unit refuses to start when the two
differ. The agent's `server_address` and `server_port` in `/etc/spire/agent.conf` must be
`SPIRE_SERVER_ADDRESS` and `SPIRE_SERVER_PORT`. And the refused destinations hold whatever
a name resolved to, at connect time: a claim's allowed name that resolves to the gateway's
loopback, to the segment or to the broker is a `503` for that tunnel and a counted,
logged drop on the gateway (`nft list table inet mediatore_gateway`; the log prefixes begin
`mediatore-gateway out`). Three keys are optional, each rendering a safe default when your
env file predates them:

- `EGRESS_DENY_ELEMENTS` (default empty): more addresses and ranges neither Envoy may dial,
  as `, 10.0.0.0/8, 198.51.100.40`. Put your Kubernetes API, secrets store and identity
  provider here at least; a blanket refusal of private space is yours to choose, since an
  audience may be an on-premises host. Until you fill it those addresses are your datacenter
  firewall's to refuse on the three egress addresses.
- `CHECK_TCP_ELEMENTS` (default `elements = { 9001 }`): the tunnel Envoy's one loopback
  port. Empty once the data plane asks the check socket (`env.inject.example` empties it).
- `RESOLVER_ELEMENTS` (default empty): the Envoys' resolver, only where the rules would
  refuse it, as `elements = { 127.0.0.53 }` for a stub on loopback or an address inside a
  range you denied. Read `/etc/resolv.conf` on a booted gateway before you rely on the
  default: with a loopback stub and this key empty, no tunnel resolves a name.

What the chain does not bound: root on the gateway, which can rewrite the table; an
internal address you did not list; a name that resolves to a public address you did not
intend (the TLS inside the tunnel is the control there); and unix sockets, so the agent's
socket stays reachable to both Envoys, whose SVID now opens no route at the broker. A
deployment that renders its own copy of the table has none of this until its copy follows.

**Moving gateways that predate ADR-0053.** Before it, the authorizer held the listeners'
ID. The broker, the entries and the image cannot change at one instant, so the order is:

1. *The broker.* The release that carries ADR-0053 answers the authorizer's ID alone. Where
   the entries are changed in the same window as the broker, go to step 2 and accept that
   tunnels are refused for the minutes in between. Where they are another team's change on
   another day, set `accept_plain_gateway_identity: true` in the broker's config first: the
   handshake and the two gateway routes then accept either ID, the broker says so at start,
   and every ask under the old one is a `warn` line naming the peer, the route and the claim
   UID. With the key on, the separation between a gateway's listeners and its authorizer is
   not in force.
2. *The entries and the image, one gateway VM at a time.* Replace that VM's
   `gateway-NN-mediatore-gateway` entry with `gateway-NN-authorizer` (delete the old object:
   the old image takes whichever SVID the agent hands it first, so never leave a user with
   both), and boot the new image. A new image whose entry is missing does not start its
   authorizer and serves nothing; an old image whose entry was replaced is refused by a
   broker without the switch. Both are closed and both are loud. A gateway that is refused
   keeps serving the allowlists it had already cached for at most its stale bound (300 s by
   default), as in a broker outage, and nothing after.
3. *The admission policy* for gateway entries
   (`deploy/base/admission/clusterstaticentry-gateway.yaml`) belongs after the last entry of
   the old shape is gone. It is part of `deploy/base`, so applying the base with the broker's
   release installs it at step 1 unless your overlay leaves it out until then. It does not
   judge the entries that exist, but from the moment it is installed an entry of the old
   shape can no longer be created or updated (a recreated gateway's new agent ID, say): that
   gateway then moves to the new shape instead.
4. *The switch back to `false`*, once no such `warn` line has appeared for a full claim
   lifetime. The key is removed in the following release, and a config still carrying it
   then refuses to start.

Rolling an image back means rolling its entry back, or the switch.

A gateway drops ICMP, so `ping` proves nothing about one; a TCP connect to its relay
ports from the segment, or `nft list table inet mediatore_gateway` on its console, does.

**The pool behind them.** The pool's deployment layer changes in four places
(`image/cloud-config-deployment.example.yaml` shows them): the agent's `server_address`
is a gateway's sandbox address with port `3129`, `MEDIATORE_URL` is
`https://<the same address>:3130`, `/etc/mediatore/gateways` lists the three sandbox
addresses with the data port, the list the guest uses until the broker's `gateways` arrives
(ADR-0027 decision 4), and `/etc/mediatore/registries` lists the mirror below. Where the
SPIRE servers publish a bundle endpoint with a certificate from a CA the image trusts, a fifth
place replaces the baked bundle ([ADR-0037](../adr/0037-the-pool-fetches-its-spire-bundle-at-boot-through-the-relay.md)):
the gateways' env names the endpoint (`RELAY_BUNDLE_PORT=3131`, `SPIRE_BUNDLE_ADDRESS`,
`SPIRE_BUNDLE_PORT=8443`), the pool's `/etc/mediatore-guest/env` names `SPIRE_BUNDLE_HOST` (the
endpoint's hostname, as its certificate names it), `SPIRE_BUNDLE_PORT=3131`,
`SPIRE_BUNDLE_GATEWAY` (a gateway's sandbox address) and optionally `SPIRE_BUNDLE_CA`, and the
agent reads `/run/spire/bundle.json` in the `spiffe` format. The bundle is fetched at every boot
by `spire-bundle-fetch.service`, which the agent requires, so it cannot go stale. The broker's
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

**The registry through the relay** ([ADR-0038](../adr/0038-the-pull-reaches-the-operators-registry-through-a-fourth-relay-leg.md)).
Where a host cannot be placed on the segment, the pool pulls through a fourth leg of the
gateway's control relay: `RELAY_REGISTRY_PORT` (3132) to `REGISTRY_ADDRESS:REGISTRY_PORT`
(the registry, 443), a fixed upstream by address like the other three. Declare it twice. On
the broker, `- { host: registry.example.com, reach: relay }` (a credential is allowed: the
TLS is the registry's, end to end). On the pool, in `/etc/mediatore-guest/env`,
`MEDIATORE_RELAY_REGISTRIES=registry.example.com=3132`, the registry's own name and the leg's
port; the gateway is the one `MEDIATORE_URL` names, by address. The image reference carries
no port: the guest dials the gateway at 3132 for that name and keeps the name for the TLS
server name, the certificate check and the `Host` header, so the image reference is the one
the registry knows. Three things to know. The pull is root's: the host table admits the leg
to uid 0 alone (`meta skuid 0`) and the jail's ruleset never lists it, so the sandbox
reaches the registry's content only through the egress proxy, under its claim's policy.
The leg is L4 and cannot restrict paths, so the registry must: point the leg at a repository
dedicated to the pool's images, read-only (anonymous, or the broker-supplied credential),
and have claims name images by digest. And only a registry that serves its blobs itself
fits: one that redirects layers to a cloud-storage host fails the claim before the jail
(the log names the host), because the puller refuses a redirect off the declared names; set
the registry to proxy the download, or declare the content host as a second leg. A gateway
running the static allowlist (no authorizer yet) lets every claim reach the hosts on it
through the egress proxy; this leg does not change that.

With `/etc/mediatore/gateways` present the image loads a second table at boot,
`inet mediatore_host`, before the agent and the guest may start (ADR-0029 decision 3;
`image/host-table`, `mediatore-host-nft.service`): input default drop but loopback and
established traffic, output default drop but loopback, established traffic and TCP to the
three gateways' data port, the relay's two ports (read from `MEDIATORE_URL` and the agent's
`server_address`), the bundle leg and, for root alone, the registry legs
(`MEDIATORE_RELAY_REGISTRIES`), and the registries file, forward dropped, every entry an IPv4 address
and a port or the table refuses to load and the VM stays down. That is the bound on root
and every other uid; the sandbox uid's per-claim table sits beside it. Without the
gateways file the unit is skipped and the pool runs as before. `nft list table inet
mediatore_host` on a member shows it; `make host-table-test` pins the text.

**What the network must do**, outside this repository: the segment's VLAN trunked on every
host of the zone (banlieue ADR-0109 decision 3), the three gateways' `egress` addresses
allowed to reach the SPIRE server's attestation port, the broker's sandbox listener and the
audiences' endpoints, and the SPIRE server and the broker admitting those three addresses
and nothing from the sandbox range (ADR-0027's consequences). Add an ingress row to the
broker's `networkpolicy.yaml` for the gateways' `egress` addresses on `8443` (the example
overlay carries only the sandbox segment's row); with the relay in place the sandbox
segment's own row on `8443` is no longer needed, since no sandbox reaches the listener
directly any more.

**What proves it before a VM does.** `make kind-e2e-gateway` runs the data plane end to end
against a real Envoy on the bootstrap the image renders (`make gateway-render-check` keeps
the two identical), `make gateway-image-check` the image, and `nft -c` on the build host
both rulesets ([testing tiers](testing.md)). The live run on three VMs and a pool VM behind
them, roadmap 06's libvirt proof extended with the gateways, happened on 2026-11-05
against v0.2.0-rc.4: the whole path held, and what it found (the three image defects,
the mirror behind a port mapping, the Kairos stages above) is fixed or written here.

### Placing an audience's credential at the gateway (ADR-0040)

By default the pool VM's proxy fetches an audience's credential and swaps it in as the request leaves (`inject: proxy`, the default). For an audience that must never put its credential on a pool VM, set `inject: gateway`: the proxy then sends the request, with no credential, to a gateway's inject listener over the claim's mutual TLS, and the gateway's third Envoy originates TLS to the audience's host with the credential the authorizer obtained from the broker.

```yaml
gateways: ["192.0.2.10", "192.0.2.11", "192.0.2.12"]   # the gateways' sandbox addresses
gateway_inject_port: 3133                              # the inject listener's own port, never a data-plane port
audiences:
  - name: anthropic
    via: delegated                  # or secret, or sts: something to place
    inject: gateway
    max_ttl: 300                    # the cap for a placed credential is 300 seconds
    egress: ["api.example.com:443"] # exactly one host name and port, never an IP literal
    rules:                          # required: a placed credential is never granted to every path
      - { method: POST, path: "/v1/messages" }
```

The broker refuses at start an audience with `inject: gateway` that has no `gateways`, no `gateway_inject_port`, no `egress`, no `rules`, an IP-literal host, a `max_ttl` above 300 or no credential to place. A placed audience's host is removed from the claim's tunnel lists, so the only path to it is the injecting one. `POST /v1/token` for it answers `403 placed_at_gateway`.

**On each gateway**, nothing changes until a deployment turns the third process on: write the two lines of `image/gateway/env.inject.example` into `/etc/mediatore-gateway/env` above the rest (the authorizer endpoint moves to the check socket, and the host table admits the inject port), start the authorizer with `--check-socket`, `--inject-socket` and `--socket-dir-mode 2750` (two setgid directories, one Envoy's group each, named with `--check-socket-group` and `--inject-socket-group`; `--socket-owner` defaults to the authorizer's own user and `--socket-mode` to `0660`), register the third SPIRE entry for `unix:user:envoy-inject` under the gateway's SPIFFE ID, then `systemctl enable --now envoy-inject.service`. The unit validates its bootstrap before every start. This repository's template renders one upstream; a deployment that places several audiences renders its own from the same shape.

**On each pool VM**, `MEDIATORE_INJECT_PORT` in the guest's env admits the inject port in the host table; the sandbox uid's per-claim table lists it only for a claim with a placed route.

**Operator prerequisites, none of them in this repository** (threat model R-29): the datacenter firewall's allowance for the gateways to reach the audience's host, an OpenBao transit key for `store.sealing.transit` with a policy limited to encrypt and decrypt on it, and the upstream's answer on terms and refresh-token rotation for a delegated session placed from a gateway address. Without the allowance the path fails closed.

**Rollout order and rollback.** Release the broker and authorizer first and confirm the running broker is the new one before editing the config: a broker that predates ADR-0040 (before v0.2.7) did not reject unknown fields, so it ignores `inject: gateway` without a word and keeps the audience in the proxy, which would put the credential on the pool VM; a current broker refuses an unknown key at start. Then roll the gateways, then the pool image, then set `inject: gateway`. To roll back, set the audience back to `inject: proxy` (or remove the line) and restart the broker; the proxy then fetches the credential as before. Stopping `envoy-inject.service` alone fails the placed path closed.

### A person's user name and secret, and a placed registry (ADR-0041, ADR-0043)

An audience for an upstream that wants a person's own user name and secret is `via: delegated` with `credential: basic` and `inject: gateway`; the broker refuses `basic` on anything else, on a header other than `authorization`, or with a `refresh`. The gateway places `Authorization: Basic`, and the audience's `rules` are matched segment by segment (`*` is one segment, `**` zero or more, anything else literal).

```yaml
audiences:
  - name: gitserver
    via: delegated
    credential: basic
    inject: gateway
    max_ttl: 300
    egress: ["git.example.com:443"]
    rules:
      - { method: GET, path: "/*/*/info/refs" }
      - { method: POST, path: "/*/*/git-upload-pack" }
```

**A registry as a placed audience.** To pull a person's image with their credential, make the registry's host an audience of this shape (rules `GET` and `HEAD` on `/v2/**`) and list the host under `registries` with `reach: relay`. With `gateways` set, every registry needs a `reach`, and a clean start does not show that: a missing one refuses every claim whose image is on a registry, so **run one claim after any change to the file**. Beyond the broker:

- the registry's host is each gateway's inject upstream (`INJECT_HOST` and `INJECT_DOMAIN` in `/etc/mediatore-gateway/env`, or your own inject template when you place several audiences) and the datacenter firewall lets the gateways reach it (without the allowance the pull fails closed with a connect timeout);
- the pool image carries a guest that has the pull listener (a second loopback port on the claim's egress proxy, `MEDIATORE_EGRESS_PULL_PORT`, default 18129; it must not equal the proxy's own port, and no jail rule lists it, so the workload cannot reach it);
- the pull is made as root with no credential of its own, and a claim's image on a placed registry must name the registry's audience.

**Sealing.** A delegated credential is kept only as ciphertext in a Secret of the broker's namespace while the claim lives, sealed under the OpenBao transit key (`store.sealing.transit`, a derived key per claim), so the broker survives a restart. It is deleted when the claim ends and at the credential's expiry, and never outlives the claim's TTL: the watcher sweeps expired envelopes every 15 seconds. Do not set a longer TTL on the CLI's side expecting a longer life; the broker caps it.

**Rollout.** As for ADR-0040: broker and authorizer first, then the gateways (the authorizer needs `--socket-dir-mode 2750` and, from v0.2.9, a unit with `RestrictSUIDSGID=yes` is fine because the directory mode is changed only when it differs), then the pool image, then the audience. On a first boot, make sure the `envoy-inject` group exists before the step that installs files with that group.

## What the NetworkPolicy allows

The object itself is in `deploy/base` (`networkpolicy.yaml`), so the release's install
manifest carries it: ingress to the broker's pods is denied by default, with `8443` and
`8080` opened to placeholder peers (a documentation CIDR and a namespace name no cluster
has) that admit nothing. Until your overlay patches them with the sandbox segment's CIDR
and the ingress controller's namespace, as the example overlay's `networkpolicy.yaml`
does (listed under `patches`, not `resources`; it also adds the egress rules), an
enforcing CNI lets nobody reach the broker.

| Direction | Peer | Port | Why |
| --- | --- | --- | --- |
| ingress | the sandbox segment | 8443 | the guest and the egress proxy, over SPIFFE mTLS (TB-6); with the control relay in place ([step 7](#7-the-egress-gateways)) this row narrows to the gateways' `egress` addresses below, since no sandbox reaches the listener directly any more |
| ingress | the gateways' `egress` addresses | 8443 | a row to add (the example overlay does not carry it): the gateway's authorizer asking what a claim may reach, over SPIFFE mTLS with the gateway SVID ([ADR-0028](../adr/0028-egress-gateway-envoy-with-spiffe-identity.md) decision 4), and the control relay carrying the pool VMs' own node and claim sessions to the listener ([ADR-0027](../adr/0027-control-plane-relay-on-the-egress-gateway.md) decision 3) |
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
