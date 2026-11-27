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
| banlieue's claim subject policy listing mediatore as a broker | ConfigMap `banlieue-claim-subject-policy`, `brokers:` line `system:serviceaccount:mediatore-system:mediatore`, `issuers:` listing yours | every claim mediatore creates names someone else's subject ([requesting a sandbox](requesting-a-sandbox.md)) |
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
  gateways, and never outlives the claim). `sandboxes.max_ttl_seconds` is the longest
  lifetime a claim may ask for, `86400` (one day) unless you write another: a request above
  it is refused (`400 ttl_exceeds_maximum`, or a declarative `AgentSandbox` marked `Failed`
  with the reason), with or without a policy, and a policy's lease only narrows it. It
  must be positive, the start log names it (`longest lifetime a claim may ask for`), and
  its default is the gateways' `TUNNEL_MAX_SECS` default (`image/gateway/env.example`):
  no tunnel outlives that cap, so raise the two together. Lowering it does not release a
  claim that is already bound; that claim runs to the TTL it was admitted with
  ([ADR-0008](../adr/0008-agentsandbox-crd-owned-by-mediatore.md) decision 9, amended
  2026-11-26). **Upgrading:** before this key existed a claim without a policy could ask
  for any lifetime, so a caller that asks for more than a day is now refused until the
  key is raised;
- `networkpolicy.yaml`: the sandbox segment's CIDR for `:8443`, the control-plane
  addresses for the API server, the node CIDR for the kubelet's probe, and the
  issuer's namespace or addresses;
- `ingress.yaml`: the ingress class and hostname, if not Tailscale's;
- `kustomization.yaml`: the server image's digest, the one the release's
  `mediatore-<version>.yaml` carries for
  [the published image](https://github.com/firestoned/mediatore/pkgs/container/mediatore).
  The example carries a placeholder digest of zeros, so an unedited copy pulls nothing.

`kubectl kustomize ~/.config/mediatore/core` renders the whole thing; read it once.

### The broker's own namespace

The base deploys into `mediatore-system` and ships that `Namespace`, labelled
`pod-security.kubernetes.io/enforce: restricted`
([ADR-0056](../adr/0056-the-broker-in-a-namespace-of-its-own.md)). It holds the broker and
what is the broker's and nothing else: its `ServiceAccount`, its keys, the session, delegation
and log Secrets the store writes, the `SandboxNode` and `PolicyFloor` resources, the watcher's
Lease, and the ConfigMap that names the broker to the admission policies. The broker's `Role`
on Secrets cannot be narrowed by name (the store makes one Secret per sandbox), so the
namespace is its bound: keep it to the broker.

- **Pools, claims and sandboxes live somewhere else**: banlieue's namespace, `sandboxes`, a
  team's. The broker reaches them through its `ClusterRole`, which holds no verb on Secrets
  or ConfigMaps anywhere. A claimable namespace (`sandboxes.namespace`, or a key of
  `sandboxes.namespaces`) that is the broker's own is warned about at start, one line, and
  still works.
- **The home namespace is not configuration.** It is the namespace of the pod's
  `ServiceAccount`; the start-up line `store: the Kubernetes API (ADR-0034)
  namespace=<home>` states it. The broker refuses to start when it is `default`, which is
  what a client outside a pod falls back to: a broker run outside the cluster names its
  namespace in the context of the kubeconfig `spire.entries.kubeconfig` points at.
- **An operator whose namespaces are created elsewhere** deletes the `Namespace` object in
  the overlay (`$patch: delete`) and carries the Pod Security label where the namespace is
  made.
- **An overlay that renames the namespace or the `ServiceAccount`** sets `namespace:` and
  then patches what kustomize does not rewrite, because none of it is object metadata:

  | What | Where | Unpatched |
  | --- | --- | --- |
  | the value of `broker`, `system:serviceaccount:<namespace>:<name>` | ConfigMap `mediatore-agentsandbox-subject-policy` (`deploy/base/admission/agentsandbox-subject.yaml`) | the broker's entries and status writes are refused; it stops at start saying the policy does not name it |
  | `paramRef.namespace` | the three bindings `mediatore-agentsandbox-subject`, `mediatore-agentsandbox-status`, `mediatore-clusterstaticentry` | no parameter is found: every `AgentSandbox`, status write and `ClusterStaticEntry` is refused, and the broker stops at start saying the policy cannot be evaluated |
  | `subjects[0].namespace` | the `ClusterRoleBinding` `mediatore` and the three `RoleBinding`s in `deploy/base/rbac.yaml` (a subject that names its namespace is left as it is) | the broker has no verb: it stops at start on RBAC |
  | `namespaceSelector` | the `ClusterSPIFFEID` `mediatore` (`deploy/base/clusterspiffeid.yaml`) | the broker is issued no SVID and does not start |
  | the subject's namespace | the `RoleBinding`s of `deploy/policy-bundles` and `deploy/audience-credentials` in each namespace that has one | bundles and credentials there are not read |

  Every row fails closed. `dev/kind/migration/kustomization.yaml` is a worked overlay with
  the first four patches (it is what the migration rehearsal runs the broker under).

One parameter names the broker to three admission policies: the key `broker` of that
ConfigMap, read by the subject policy (the broker's exemption), the status policy (the one
writer) and the entries policy (the one sender of the broker's SPIRE entries). Whoever may
edit the ConfigMap can name another account as the broker, so keep `update` on ConfigMaps in
`mediatore-system` to whoever deploys the broker, and audit changes to it. Without the
ConfigMap, or without the key, all three policies refuse everything they govern, the
gateways' `ClusterStaticEntry` resources included: restore it before declaring anything.

## 2. Create the Secrets the overlay expects

The overlay generates no secret. Two Secrets in `mediatore-system`, each a file the
broker reads at startup (the store needs none: it is the cluster's API, [the store](the-store.md)):

```sh
# The STS signing key (ES256), whose public half becomes the broker's JWKS.
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out sts.pem
kubectl -n mediatore-system create secret generic mediatore-sts --from-file=sts.pem

# The sealing key for refresh material (ADR-0012 decision 3), the local sealer.
openssl rand -hex 32 > sealing.key
kubectl -n mediatore-system create secret generic mediatore-sealing --from-file=key=sealing.key
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
read -rs ANTHROPIC_KEY && kubectl -n mediatore-system create secret generic mediatore-audience-secrets \
  --from-literal=anthropic="$ANTHROPIC_KEY" && unset ANTHROPIC_KEY
```

The broker reads each file once at start and refuses to start on an empty one; it never
writes the value anywhere. Rotate by editing the Secret and restarting the broker: every
proxy holds the old value for at most that audience's `max_ttl`.

## 3. Apply, and read the start-up log

```sh
kubectl apply -k ~/.config/mediatore/core
kubectl -n mediatore-system rollout status deploy/mediatore
kubectl -n mediatore-system logs deploy/mediatore | head -40
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

The start also says what the tripwires are ([ADR-0069](../adr/0069-tripwires-on-the-vm-a-decoy-the-workload-takes-ends-its-sandbox.md),
[ADR-0070](../adr/0070-tripwires-beyond-the-sandbox-a-request-no-honest-build-makes.md)): `tripwires on the VM are off`
by default, one line per class set to `trip`, and, at a `store.retention_secs` of 900 or less, that `no_record` is not
judged. The example overlay lists every key, commented out at its default. An upgrade to a build with tripwires applies
the CRDs first (the record gains `tripped` and the status `tripwires`), then the broker, and the guest images before
`policy.traps` leaves `off`: the order and the modes are in [the tripwires guide](tripwires.md#the-modes-and-the-order-to-roll-them-out).

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

The broker makes the same proof for itself at every start, and the replica that holds the
Lease repeats it at every resync
([ADR-0056](../adr/0056-the-broker-in-a-namespace-of-its-own.md) decision 5): a dry-run create
of an entry the policy must refuse, and it does not serve unless the refusal is the policy's.
What it says when it is not:

| The start error says | What it found | What to do |
| --- | --- | --- |
| `is not in force for this identity` | the forbidden entry was admitted: the policy or its binding is absent, or was edited to `Warn` | apply `deploy/base/admission/clusterstaticentry-mediatore.yaml` |
| `does not name this identity as the broker` | the policy refused the broker by its sender validation | set `broker` in `mediatore-agentsandbox-subject-policy` to the username the broker runs as |
| `cannot be evaluated` | the bindings found no parameter, or the parameter has no `broker` key | restore the ConfigMap in the namespace the bindings' `paramRef` names |
| `may not create clusterstaticentries` | RBAC refused before admission was asked | the `ClusterRoleBinding`'s subject |
| `not by the entries admission policy`, `did not answer` | another refusal, or no answer | the message carries the API server's own |

A failure at a resync does not stop the broker. It logs an error (`the entries admission
self-check failed at resync`) and declares no new entry until the check passes again: a claim
that would bind waits, a new pool member gets no node entry, and nothing that is bound is
released on its account. The check is asked again before each declaration, so binding
resumes as soon as the policy answers. A replica that does not hold the Lease runs the
check at its start only.

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

Since [ADR-0067](../adr/0067-the-vm-images-are-overlays-on-a-replaceable-base.md) the image
is an overlay on a VM base (`image/base/Dockerfile`, `make base-image`): the base is Kairos,
Debian 13 and the OS layer, the overlay only mediatore's pieces, so a site can build it on
its own base with `VM_BASE=<image>`. [The VM images](vm-images.md) has the layering, the
`BINARY_FROM` choices, a multi-provider `VMImage` and what Azure still needs.

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
kubectl -n mediatore-system create secret generic mediatore-registry --from-file=ghcr=./ghcr-pull-token
```

and in the overlay's Deployment patch, beside the STS volume:

```yaml
volumeMounts:
  - { name: registry, mountPath: /etc/mediatore-registry, readOnly: true }
volumes:
  - name: registry
    secret: { secretName: mediatore-registry, defaultMode: 0440 }
```

### Pools whose guests have no vTPM (x509pop, ADR-0049)

A guest with no vTPM (banlieue's `firecracker` class, or a Cloud Hypervisor host that opted
in to its attestation CA) has no EK to attest with. Its agent attests with SPIRE's built-in
`x509pop` attestor instead ([ADR-0049](../adr/0049-a-guest-without-a-vtpm-attests-with-x509pop-and-a-certificate-its-host-signs.md)):
the guest makes a key at each boot, its host signs a short-lived certificate for that key
over vsock, and the agent proves possession of it to the server. The agent ID is
`spiffe://<td>/spire/agent/x509pop/<host CA common name>/<machine UID>`, two things the
control plane knows before the guest boots, so the node entry is declared in advance as it
is for an EK. Nothing changes for a pool with a vTPM, and one cluster runs both.

Such a member cannot seal its disk, so its agent keeps nothing of its identity on one: the
shipped configuration (`image/spire/agent-x509pop.conf`, and the pool's example layer)
uses SPIRE's `memory` key manager and a data directory on `tmpfs`, `/run/spire/agent`,
which the agent unit's drop-in makes before the agent starts. An agent that restarts
attests again under the same ID. Keep both settings if you write your own layer:
`make guest-image-check` fails on a `disk` key manager or a path under `/var/lib` there.

What you trust, per host, is that host's attestation CA: a host that holds its key can
mint an identity for any guest *under its own name*, and for no other host's. Three rules
make that true, and the SPIRE server checks none of them. `mediatore x509pop-bundle check`
(below) checks the first two on the files you are about to apply; nothing runs it against
the bundle a server already holds, so run it every time the ConfigMap changes:

- **one CA per host, with a common name of its own**, unique among the CAs the server
  trusts (letters, digits, dots, dashes and underscores, at most 64). Two CAs sharing a
  name could each attest as the other's guests;
- **`basicConstraints` CA:TRUE with a path length of zero**, so a host cannot sign a
  further CA carrying another host's name. The broker declares no node entry under a CA
  without it;
- **the same certificate in two places**: the server's bundle, and inline on the host's
  `Provider`, where the broker reads the name.

**Upgrading a broker that predates this.** In this order: apply the release's
`deploy/base/admission/clusterstaticentry-mediatore.yaml` and `deploy/base/rbac.yaml`
on their own first (`kubectl apply -f`), then the rest, which rolls the broker. The policy
gains the second parent shape (`spire/agent/x509pop/<segment>/<segment>`), and under the
older policy an entry with such a parent is refused at admission; the ClusterRole gains
`list` on `providers`, and nothing else on them (the broker lists them in every namespace
once per pass and never reads one by name). A role you maintain yourself
needs the same rule.

Nothing enforces that order: the broker's check at start passes under the older policy
too. A broker of this release under the older policy starts and serves TPM pools as
before, but every `x509pop` node entry is refused at admission (the broker's log has the
refusal), so those machines' guests never register and their claims are failed at
`watcher.resolve_timeout_secs`, until the policy is applied. Under an older ClusterRole
the read of a Provider is an error in the log, and nothing is declared or bound for a
listed pool, nor is any gone node collected, until the rule is there. With
`watcher.x509pop_pools` empty neither matters: no Provider is read and no such entry is
declared.

**The server.** `deploy/spire-x509pop` is a kustomize component beside `deploy/spire-tpm`:
a ConfigMap with one PEM per host, an init container that joins them into the one file
the attestor reads, and the block of `server.conf.fragment.hcl` for your `server.conf`.
Its `agent_path_template` is the decision, not a preference: copy it as it is. There is no
plugin binary and no checksum.

```sh
cp -r deploy/spire-x509pop ~/.config/mediatore/spire-x509pop
# One certificate per host: the attestation CA banlieue's host install created
# (`banlieue host cloud-hypervisor install --attestation-ca-name hv-01`), public.
ssh hv-01 sudo cat /var/lib/banlieue/attestation-ca/ca.crt > hv-01.pem
openssl x509 -in hv-01.pem -noout -subject -ext basicConstraints   # CN=hv-01; CA:TRUE, pathlen:0
# The whole bundle, every host's file at once, before anything is applied. It exits non-zero
# and names the certificate when two CAs share a common name, a name cannot be a segment of
# an agent ID, or a certificate is not a CA with a path length of zero; otherwise it prints
# `ok: <n> host CA(s), ...` and the names. Stop here on a refusal:
mediatore x509pop-bundle check *.pem
# Put it under data: of ~/.config/mediatore/spire-x509pop/host-cas.yaml in place of the
# placeholder (one key per host), add the component to your SPIRE kustomization and the
# fragment's block to your rendered server.conf, then:
kubectl apply -k ~/.config/mediatore/spire
kubectl -n spire-server rollout restart statefulset/spire-server   # the bundle is read at start
kubectl -n spire-server rollout status statefulset/spire-server
kubectl -n spire-server logs spire-server-0 -c spire-server | grep 'plugin_name=x509pop'
```

Replace the placeholder before you apply: the attestor loads its bundle when the server
starts, and with no certificate in it the server does not start at all (`unable to load
trust bundle "/x509pop/ca-bundle.pem": no certificates found in file`, then `Server
crashed`; seen in kind with the placeholder alone). The rollout stops at that replica,
and with a single server nothing attests until it is fixed, the TPM pools included. A key that is no
certificate beside one that is gets skipped without a word, so a host whose PEM was
pasted badly is simply not trusted: its guests are refused with `certificate signed by
unknown authority`, as are those of a host you never added.

**The host, on its Provider.** The same file, inline, on the `Provider` banlieue schedules
that host's machines on. The broker reads `spec.attestation.hostCa.inline` and nothing
else: a `configMapRef` or `secretRef` there is refused with a message naming the
Provider, since following one would need read access to ConfigMaps or Secrets wherever a
Provider lives.

```yaml
apiVersion: banlieue.io/v1alpha1
kind: Provider
metadata: { name: hv-01, namespace: sandboxes }
spec:
  # ...the provider's class, connection and capabilities, as before...
  attestation:
    hostCa:
      inline: |
        -----BEGIN CERTIFICATE-----
        ...hv-01.pem, the one certificate, no key...
        -----END CERTIFICATE-----
```

The broker looks for a machine's Provider (`status.scheduled.providerName`) in the
machine's own namespace, and, when that namespace has none, in `watcher.provider_namespace`
if you set it (banlieue's fallback for Providers kept in one platform namespace). To apply
that rule it lists the Providers of every namespace, once per pass (the ClusterRole's
`list` on `providers`), and the list is also how it sees a rival: when two Providers,
in any namespaces, assert *different* certificates under one common name, no machine of
either gets a node entry and their claims are failed, naming both, until one of them is
corrected. The same certificate on two Providers is one CA and is fine. The check sees
Providers only, not the server's bundle, which is what `x509pop-bundle check` is for.

**The broker.** Which pools attest this way is your statement, in `mediatore.yaml`, never
a label a pool's owner could set and never guessed from what a machine publishes:

```yaml
watcher:
  x509pop_pools: ["sandboxes/microvm"]   # <namespace>/<the machines' banlieue.io/pool label>
  # provider_namespace: banlieue-system  # only when the Providers are not in the pools' namespaces
```

A machine of a listed pool gets an `x509pop` node entry and never a TPM one, even when it
also publishes an EK certificate; every other machine is `tpm`, as before. The node's key,
which names its entry (`mediatore-node-<key>`), its SPIFFE ID and its `SandboxNode`, is the
SHA-256 of the agent ID, so it does not show the host or the machine; `kubectl get
clusterstaticentries -l app.kubernetes.io/managed-by=mediatore -o
custom-columns=NAME:.metadata.name,PARENT:.spec.parentID` shows which is whose.

**The pool's image layer.** The VM image is the same; the deployment layer is
`image/cloud-config-deployment-x509pop.example.yaml` in place of the other example. It
differs in three things: `/etc/spire/agent.conf` is `image/spire/agent-x509pop.conf` (the
`x509pop` attestor over `/run/spire/x509pop/key.pem` and `cert.pem`, no
`intermediates_path`); a drop-in, `/etc/systemd/system/spire-agent.service.d/x509pop.conf`,
makes the agent require `mediatore-node-cert.service`, which fetches the certificate from
the host before the agent starts and keeps it renewed (no certificate, no agent); and
`MEDIATORE_NODE_ATTESTATION=x509pop` in `/etc/mediatore-guest/env` tells the guest to read
its names from that certificate and leave the TPM alone. The three go together with the
pool's line in `watcher.x509pop_pools`: a guest that attests one way while the broker
expects the other gets no SVID and never registers. banlieue's EK-certificate layer has no
use on such a pool. The agent's unit keeps its two TPM device lines; systemd starts a unit
whose allowed device does not exist (checked with `systemd-run` on Debian 13's systemd
257). No member has booted from this layer yet: the server's side, the agent's
configuration and the registration run in kind (`make kind-e2e-x509pop`, [testing
tiers](testing.md)), and the certificate fetch was proven against banlieue's signer on its
own.

**When nothing is declared.** A listed machine gets no node entry at all while something
its entry is made from is missing or refused, and the broker's log names the machine and
the reason. It never falls back to the machine's EK. The reasons, as the log gives them:

- missing, which may pass, so the watcher looks again: `machine <ns>/<name> is of an
  x509pop pool and publishes no attestationSubject`; `... is not placed on a Provider
  yet`; `... its Provider <name> was not found`;
- refused, which waiting does not cure: `Provider <ns>/<name> asserts no
  spec.attestation.hostCa, so its guests have no x509pop identity`; `...
  spec.attestation.hostCa must be inline; a configMapRef or secretRef is not read`; `...
  spec.attestation.hostCa.inline is not set`; `... the host CA or machine <ns>/<name>'s
  attestationSubject is unusable: <the rule>` (for a CA that may sign further CAs, `its
  path length constraint must be 0`); `two Providers assert host CAs named "<cn>" with
  different certificates (<ns/a> and <ns/b>); a host CA's common name must be unique`.

With `watcher.x509pop_pools` set, every `Bound` claim, of a TPM pool too, is resolved
through the machine its `status.virtualMachineRef` names, since the machine's pool label
says which attestor applies (banlieue v0.6.0 writes the reference with the `Bound` phase).
With the list empty nothing is read that was not read before.

A claim bound to such a machine is **failed**, not left unbound: the broker revokes its
record and deletes the `VirtualMachineClaim`, which makes banlieue destroy the member,
and logs `claim failed: record revoked, claim deleted` with the reason. For a refused
cause that happens at the first pass. For a missing one it happens after
`watcher.resolve_timeout_secs` (60 by default), as it does when the claim names no
machine yet, when its machine does not exist, and when everything was declared but the
guest has not registered (`no node registered for the machine's x509pop identity`). A
banned node, and a node registered under another agent ID than its machine attests as,
fail the claim at once. A Provider the broker cannot read at all is an error in the log
and not a verdict: nothing is declared, bound or collected until it can be read.

**A node key registered under another agent ID.** The first registration under a node
key stands. A guest that registers the same key under another agent ID (a machine first
registered under one attestor and now, honestly, under the other) is answered
`409 node_identity_conflict`, stops, and the broker logs `node registration refused: the
key is registered under another agent ID` with the key and both IDs; nothing is changed.
To let it register again, delete the record, after checking that no live sandbox is bound
to it. The record is a `SandboxNode` in the broker's own namespace (`mediatore-system`
here), named by the node key; a sandbox bound to a node carries the label
`mediatore.io/node`, the first 32 hex characters of the SHA-256 of that node's agent ID,
and the agent ID itself in `status.record.nodeId`:

```sh
KEY=<the node key from the log line, its node_key field>
# The agent ID the key is registered under (stored_agent_id in the log line):
NODE_ID=$(kubectl -n mediatore-system get sandboxnode "$KEY" -o jsonpath='{.spec.nodeId}')
echo "$NODE_ID"
# No live sandbox may name that agent ID as its node (live: not revoked, not past its deadline):
LABEL=$(printf '%s' "$NODE_ID" | openssl dgst -sha256 -r | cut -c1-32)
kubectl get agentsandboxes -A -l "mediatore.io/node=$LABEL" -o json \
  | jq -r --arg id "$NODE_ID" --arg now "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      '.items[] | select(.status.record.nodeId == $id and .status.record.revokedAt == null
         and (.status.record.expiresAt == null or .status.record.expiresAt > $now))
       | "\(.metadata.namespace)/\(.metadata.name)"'
kubectl -n mediatore-system delete sandboxnode "$KEY"   # only when the command above printed nothing
```

Then restart the guest (its unit exited on the `409`); it registers under the agent ID it
attests as now.

On the guest the agent may well attest, since the server only needs the CA in its
bundle, but no entry is parented to it: the guest waits for an SVID, never registers,
and never announces `GuestReady`. `spire-server
agent list` showing an `x509pop` agent with no `mediatore-node-` entry under it is this
case: compare the agent's ID with the Provider's certificate (`openssl x509 -noout
-subject`) and the machine's `status.attestationSubject`.

**Retiring a host, or rotating its CA.** Remove the host's key from the bundle ConfigMap
and restart the servers: every identity that CA signed is refused at its agents' next
re-attestation, about half an SVID lifetime away, so drain the host's machines first.
Then remove `hostCa` from the Provider, which makes the broker retract that host's node
entries at the next resync. Remove the field and keep the Provider while any of its
machines exists: a Provider that is gone reads as "not found", which is one of the
missing causes and the one with no time limit, so nothing of that host is retracted and
the x509pop collection of every listed pool is held
(see [Nodes of VMs that are gone](#nodes-of-vms-that-are-gone)) until its machines are
deleted too. A rotation is a new CA under a
*new* name (banlieue refuses to reuse one for another key): add the new certificate to the
bundle, restart the servers, put it on the Provider, and keep the old certificate in the
bundle until the certificates it signed have expired (the host's
`--attestation-certificate-ttl`, an hour by default). The node keys of that host's
machines change with the name, so their entries are declared afresh under new names, and
a machine running across the change loses the identity it registered with: ADR-0049
leaves open how a host changes its CA without orphaning live guests, so drain the host
before a rotation as before a retirement.

### Nodes of VMs that are gone

Every VM that registers leaves a `SandboxNode`, and a pool that recycles its members (one-shot
claims end their VM) would add one per VM for ever. The broker removes the node of a VM that no
longer exists ([ADR-0039](../adr/0039-a-node-leaves-the-register-when-its-vm-is-gone.md)): at
each resync, on the replica holding the watcher's Lease, when no pool member `VirtualMachine`
gives its node key (its EK hash, or for a pool listed as `x509pop` the key of its agent ID). Two settings matter. `watcher.resync_secs` (five minutes) is how often it
looks; `store.node_grace_secs` (ten minutes, zero refused) is how old a registration must be
before it can go, so a registration that precedes its VM's published certificate is never
collected. The ClusterRole in `deploy/base/rbac.yaml` already grants `delete` on `sandboxnodes`
and `list` on `virtualmachines`; check a role you maintain yourself has both. A banned node stays
until you delete it. For the pools listed as `x509pop` there is one more hold: a pass that holds
removes no x509pop node and no x509pop node entry, in any listed pool, and logs `an x509pop
machine gives no key yet; no x509pop node or entry is collected in this pass` for the machine that
holds it. Two things hold a pass:

- a listed machine whose Provider is not found, whatever the machine's age, so a Provider deleted
  and applied again costs its idle guests nothing. This hold has no bound: a machine placed on a
  Provider that does not exist holds the collection until the Provider is applied or the machine
  is deleted, so if the line repeats at every resync with `its Provider <name> was not found`,
  find the machine it names and do one or the other;
- a listed machine that still has no `attestationSubject` or is not placed, while it is young:
  its `metadata.creationTimestamp` is less than `store.node_grace_secs` ago, the same grace a
  young node gets. Past that it holds nothing, and the log says so at each pass (`an x509pop
  machine older than the node grace still gives no key; it does not hold the collection`): a
  machine that never gets its subject delays the collection by the grace at most, and is worth
  fixing or deleting for its own sake.

A host CA you withdraw, rename or loosen is not "missing",
and its entries are still retracted. `kubectl get sandboxnodes` should settle at
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

**The image.** `image/gateway/Dockerfile` is an overlay on the same VM base as the sandbox
image ([ADR-0067](../adr/0067-the-vm-images-are-overlays-on-a-replaceable-base.md)) with Envoy copied from its official image at the digest the kind tier runs
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
| `envoy`, `envoy-inject` | any IPv4 destination that is not loopback or one of the VM's own addresses, link-local (`169.254.0.0/16`), one of the four control-plane addresses of the env file, or an entry of `EGRESS_DENY_ELEMENTS`; no IPv6. No loopback exception by default: the tunnel Envoy asks the authorizer on a unix socket. It has one, the authorizer's check port, only where you keep the check on loopback TCP on purpose (below) |
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
- `CHECK_TCP_ELEMENTS` (default empty): the tunnel Envoy's one loopback port, only for a
  gateway that keeps the authorizer's check on loopback TCP (next paragraph). Empty, there
  is no loopback exception at all.
- `RESOLVER_ELEMENTS` (default empty): the Envoys' resolver, only where the rules would
  refuse it, as `elements = { 127.0.0.53 }` for a stub on loopback or an address inside a
  range you denied. Read `/etc/resolv.conf` on a booted gateway before you rely on the
  default: with a loopback stub and this key empty, no tunnel resolves a name.

**Where the tunnel Envoy asks the authorizer.** On a unix socket, by default and with or
without the inject Envoy (ADR-0053 open question 7, built 2026-11-26):
`AUTHORIZER_ENDPOINT=pipe: { path: /run/mediatore-gateway/check/check.sock }` and
`CHECK_TCP_ELEMENTS=` in `image/gateway/env.example`, and the same when your env file names
neither key. The authorizer's unit makes the socket's directory (`2750`, setgid, owner
`mediatore-gateway`, group `envoy`), so the tunnel Envoy's group reaches the check and no
other local user does, and it listens where `AUTHORIZER_ENDPOINT` says: you do not set a
listen flag. To keep loopback TCP (any local user can then ask the check, a yes or no on a
claim's allowlist and a way to make the authorizer ask the broker; this is what the kind
tier's pod does, and it is not recommended on a gateway VM), set both keys, with one port:

```sh
AUTHORIZER_ENDPOINT=socket_address: { address: 127.0.0.1, port_value: 9001 }
CHECK_TCP_ELEMENTS=elements = { 9001 }
```

A gateway whose env file already carries those two lines keeps running as it did, on a new
image too. One whose env file carries the TCP endpoint and no `CHECK_TCP_ELEMENTS` line (a
file from before the output chain) must gain the line or lose the endpoint line: the
authorizer's unit refuses to start, with the reason in its journal, when one key says
loopback TCP and the other does not, since Envoy would dial where nobody listens or the
table would drop every check. To move a gateway to the socket, remove both lines (or set
them as the example does) and restart `mediatore-gateway`, `mediatore-gateway-nft` and
`envoy-gateway`, or reboot it.

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

**The pool behind them.** The pool's deployment layer changes in three places
(`image/cloud-config-deployment.example.yaml` shows them): the agent's `server_address`
is a gateway's sandbox address with port `3129`, `MEDIATORE_URL` is
`https://<the same address>:3130`, `/etc/mediatore/gateways` lists the three sandbox
addresses with the data port, the list the guest uses until the broker's `gateways` arrives
(ADR-0027 decision 4). It names no registry: the image is pulled through the claim's egress
proxy and a gateway (below). Where the
SPIRE servers publish a bundle endpoint with a certificate from a CA the image trusts, a fourth
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

**The image pull, through the gateway** ([ADR-0063](../adr/0063-the-image-pull-goes-through-the-claims-proxy-and-the-gateway-like-any-egress.md)).
A pool VM on the segment reaches the gateways and nothing else, and no workload path goes
around them, the pull included: the guest starts the claim's egress proxy first and pulls
through its pull listener, and the proxy sends each request to a gateway, in a tunnel on the
data port or, for a registry the gateway places a credential for (ADR-0043), to the inject
port. The gateway decides the pull like any other request of the claim, against its
allowlist. So a registry is an audience, marked `role: registry`, and a namespace pulls only
from the registries it was granted:

```yaml
audiences:
  - name: mirror
    via: none                      # an anonymous pull-through mirror; delegated + inject: gateway for a person's credential
    role: registry
    egress: ["registry.example.com:443"]
    ca_file: /etc/mediatore-ca/registry-ca.pem   # when the registry is on your PKI
    namespaces:                    # ADR-0053: the teams that may pull from it, each with its rules
      team-a: { rules: [{ method: GET, path: "/v2/**" }, { method: HEAD, path: "/v2/**" }] }
      team-b: { rules: [{ method: GET, path: "/v2/team-b/**" }, { method: HEAD, path: "/v2/team-b/**" }] }
```

A claim names the audience beside its others (`--audience mirror`, or `audiences` in the
body); one whose image is on a registry none of its audiences serves is refused at
`POST /v1/claims` with `registry_not_granted`, and an `AgentSandbox` naming one fails before
any claim exists, with a sentence that names no other registry. A registry audience's
routes are the puller's: the workload's proxy listener answers `404 pull_only` for them, and
the jail's ruleset does not list them, so a workload cannot fetch further images. Its rules
may only read (`GET` and `HEAD` under `/v2/`), or the broker refuses to start. With
`gateways` set the broker also refuses `registries[]` and its `reach` (the mirror on the
segment and the relay's registry leg of ADR-0029 and ADR-0038 are gone), and the guest
refuses `MEDIATORE_PLAIN_HTTP_REGISTRIES` and `MEDIATORE_RELAY_REGISTRIES` at boot, so an
environment that was not migrated fails loudly. The datacenter firewall must let the
gateways' egress addresses reach the registry. Two limits: the puller answers no auth
challenge through the proxy, so a registry whose anonymous pull needs a token from a realm
is served only with a placed credential, and one that redirects its layers to another host
needs that host in the audience's `egress`. Name images by digest: a tag is the registry's
word. A pull is bounded (`MEDIATORE_PULL_IDLE_SECS`, 60, and `MEDIATORE_PULL_DEADLINE_SECS`,
900, in the guest's env): a registry that stalls fails the claim before the jail, the
registry named.

Under `policy.audience_definitions.mode: bundles` no registry is granted yet: notaio's
`SandboxAudience` carries no `role` (ADR-0063, implementation notes), so with gateways every
image is refused there until it does.

With `/etc/mediatore/gateways` present the image loads a second table at boot,
`inet mediatore_host`, before the agent and the guest may start (ADR-0029 decision 3;
`image/host-table`, `mediatore-host-nft.service`): input default drop but loopback and
established traffic, output default drop but loopback, established traffic and TCP to the
three gateways' data port, the relay's two ports (read from `MEDIATORE_URL` and the agent's
`server_address`), the bundle leg and, for a pool with a placed audience, the inject port,
forward dropped, every entry an IPv4 address and a port or the table refuses to load and the
VM stays down. No registry address, for any uid: a registries file that names one, or
`MEDIATORE_RELAY_REGISTRIES`, refuses the table (ADR-0063 decision 4). It loads before
`network-pre.target`, and `host-quiet` then masks, for that boot, the units the Kairos base
enables that would dial out on their own (`systemd-timesyncd`, `systemd-resolved`, the apt
timers) or that the image never uses (iSCSI, VMware tools), and removes the base's DHCP
catch-all before `systemd-networkd` reads it (ADR-0063 decision 8). A direct pool runs
neither, and keeps its resolver and DHCP. That is the bound on root
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

#### How the gateway knows which credential goes into which connection

Identity decides it, not an address or a header the sandbox sends. The pool VM's workload has no credential for a placed audience and no way to name one; what it has is a claim SVID, and everything below keys on that.

1. **One identity per claim.** SPIRE gives each sandbox claim its own SPIFFE identity, through the registration entries the `spire.entries` class reconciles (ADR-0028). The gateway's three processes have identities too: `envoy-inject` takes the gateway SVID from its own SPIRE entry (`unix:user:envoy-inject`, ADR-0040 decision 3), and the authorizer has its own, `spiffe://<trust_domain>/gateway/authorizer` (ADR-0053).
2. **Mutual TLS carries the claim to the gateway.** The proxy on the pool VM sends the request, with no credential, to the gateway's inject port over mutual TLS 1.3 using the claim SVID. `envoy-inject` accepts only a peer whose SAN has the claim prefix (ADR-0028 decision 4). No SVID, no connection. Retracting a claim's SVID makes the listener refuse that claim at once.
3. **The identity is read from the connection.** Envoy hands the authorizer `source.principal` (the verified peer), the method, the host and the path of the request. The authorizer never reads the claim from anything the client sent. It looks up the claim's gateway-placed routes (`GET /v1/gateway/claims/{uid}`, answered only to the gateway), requires the request's authority to equal an entry of that audience's own `egress` and a rule to match the method and the path without its query, and refuses `CONNECT`.
4. **The broker issues the credential to the authorizer only.** The authorizer calls `POST /v1/gateway/claims/{uid}/credential` with the audience. The broker accepts that call only from the peer `spiffe://<trust_domain>/gateway/authorizer` (any other peer is `403`), and checks in order that the claim is live, that the claim names the audience, that the audience is gateway-placed, that the claim's policy bundle admits it (under `policy.egress: enforce`, no verified bundle is `403`) and that the per-claim rate limit allows it. It opens the credential sealed for that claim (the delegated envelope, which only that claim's uid can open) and answers with a credential that expires within 300 seconds. Nothing is stored, and every issue is one log line (`gateway credential issued`) with the claim, audience and subject, never the credential.
5. **The authorizer alone writes the header.** The response sets the credential header and removes any other credential-bearing header the client sent, so a sandbox cannot smuggle its own. `envoy-inject` then originates TLS to the audience's fixed host. The pool VM's own SVID cannot fetch the credential: `POST /v1/token` for a placed audience is `403 placed_at_gateway`.

An example, with placeholders. A person creates a sandbox with `--delegate gitserver=prompt` for the `gitserver` audience above, and the claim has the UID `<claim-uid>`:

```text
workload on the pool VM              gateway                                   broker
  GET /org/repo/info/refs
  (no credential)
  -- mutual TLS, claim SVID -->
                                     envoy-inject: peer SAN has the claim prefix
                                     ext_authz (mode: inject): principal = claim,
                                       host git.example.com:443, path matches a rule
                                     authorizer -- POST /v1/gateway/claims/<claim-uid>/credential -->
                                                                               peer is .../gateway/authorizer
                                                                               claim live, names gitserver,
                                                                               policy admits it, rate ok
                                                                               opens the sealed envelope
                                     <-- Basic credential, expires_at <= 300 s ahead --
                                     header set, other credential headers removed
                                     originates TLS to git.example.com:443
  <-- response ------------------------
```

A second claim on the same pool VM gets its own SVID, so it can neither obtain nor use the first claim's credential, and a sandbox whose policy does not list `gitserver` is refused at step 4 even though its mutual TLS is valid.

**On each gateway**, nothing changes until a deployment turns the third process on: write the line of `image/gateway/env.inject.example` into `/etc/mediatore-gateway/env` above the rest (the host table admits the inject port; the data plane is on the check socket already, the image's default, and inject is not for a gateway that keeps the check on loopback TCP), start the authorizer with `--check-socket`, `--inject-socket` and `--socket-dir-mode 2750` (two setgid directories, one Envoy's group each, named with `--check-socket-group` and `--inject-socket-group`; `--socket-owner` defaults to the authorizer's own user and `--socket-mode` to `0660`; on the image that is a drop-in for the authorizer's unit, which the example cloud-config writes in its `initramfs` stage so that it is in place before systemd starts the unit, a `boot` stage being too late and costing the authorizer a restart), register the third SPIRE entry for `unix:user:envoy-inject` under the gateway's SPIFFE ID, then `systemctl enable --now envoy-inject.service` (from a Kairos cloud-config, a `boot` stage that enables the unit and starts it with `systemctl start --no-block`: enabling alone starts nothing there). The unit validates its bootstrap before every start. This repository's template renders one upstream; a deployment that places several audiences renders its own from the same shape.

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

**A registry as a placed audience.** To pull a person's image with their credential, make the registry's host an audience of this shape (rules `GET` and `HEAD` on `/v2/**`) and mark it `role: registry` (ADR-0063). With `gateways` set, every registry needs a `reach`, and a clean start does not show that: a missing one refuses every claim whose image is on a registry, so **run one claim after any change to the file**. Beyond the broker:

- the registry's host is each gateway's inject upstream (`INJECT_HOST` and `INJECT_DOMAIN` in `/etc/mediatore-gateway/env`, or your own inject template when you place several audiences) and the datacenter firewall lets the gateways reach it (without the allowance the pull fails closed with a connect timeout);
- the pool image carries a guest that has the pull listener (a second loopback port on the claim's egress proxy, `MEDIATORE_EGRESS_PULL_PORT`, default 18129; it must not equal the proxy's own port, and no jail rule lists it, so the workload cannot reach it);
- the pull is made as root with no credential of its own, and a claim's image on a placed registry must name the registry's audience.

**Sealing.** A delegated credential is kept only as ciphertext in a Secret of the broker's namespace while the claim lives, sealed under the OpenBao transit key (`store.sealing.transit`, a derived key per claim), so the broker survives a restart. It is deleted when the claim ends and at the credential's expiry, and never outlives the claim's TTL: the watcher sweeps expired envelopes every 15 seconds. Do not set a longer TTL on the CLI's side expecting a longer life; the broker caps it.

**Rollout.** As for ADR-0040: broker and authorizer first, then the gateways (the authorizer needs `--socket-dir-mode 2750` and, from v0.2.9, a unit with `RestrictSUIDSGID=yes` is fine because the directory mode is changed only when it differs), then the pool image, then the audience. On a first boot, make sure the `envoy-inject` group exists before the step that installs files with that group.

## Moving a running broker from `banlieue-system` to `mediatore-system`

Until v0.4.0 the base put the broker in banlieue's namespace. The base now deploys into
`mediatore-system` ([ADR-0056](../adr/0056-the-broker-in-a-namespace-of-its-own.md)), and
**applying it over a running environment without this procedure gets you a second, empty
broker beside the first**: its own Lease, none of the keys, and the admission parameter
pointing at it, so the first one is refused its entries. Read the whole section first. The
move has one outage, between steps 4 and 7: no token is issued and no claim binds; running
sandboxes keep their SVIDs and the tokens their proxies hold.

Two brokers must never run at once. The Lease is per namespace, so two namespaces would mean
two leaders.

**Drain or copy.** The recommended path is the drain: let the claims end (they are hours
long at most), then move with nothing in the store but what step 5 copies. Step 6 is for an
environment that cannot drain, and is the path the rehearsal in
[the testing guide](testing.md#the-move-to-mediatore-system-rehearsed) proves: a claim
bound before the move, its token issued after.

The commands use `OLD=banlieue-system` and `NEW=mediatore-system`, and this filter, which
re-creates an object in another namespace with the same name, labels and data and none of
what belonged to the object it was:

```sh
OLD=banlieue-system NEW=mediatore-system
copied() {   # a kubectl JSON list on stdin, the copies for $1 on stdout
  jq --arg ns "$1" '.items[] |= (del(.metadata.ownerReferences, .metadata.uid,
      .metadata.resourceVersion, .metadata.creationTimestamp, .metadata.managedFields,
      .metadata.annotations["kubectl.kubernetes.io/last-applied-configuration"], .status)
    | .metadata.namespace = $ns)' | jq '.items[]'
}
```

1. **Upgrade in place first**, in the old namespace, to the release whose policies fail
   closed and whose broker checks itself at start (v0.4.0 or later), with the old username
   still the one the policies name. On v0.4.0 that username is a literal in the three files
   under `deploy/base/admission/`; on a later base it is the parameter, and your overlay
   keeps the broker in `banlieue-system` with the patches of
   [the table above](#the-brokers-own-namespace) until step 7. From here no rename can leave
   the broker's entries unjudged.

2. **Create the namespace and copy what you created** in the old one: the STS key (the same
   key, so the `kid` and the JWKS do not change and no verifier notices), the sealing key
   with the local sealer (nothing with transit), the audience and registry Secrets, any CA
   bundle, and the config if your overlay does not generate it.

   ```sh
   kubectl apply -f deploy/base/namespace.yaml
   for s in mediatore-sts mediatore-sealing mediatore-audience-secrets mediatore-registry; do
     kubectl -n $OLD get secret $s --ignore-not-found -o json | jq '{items: [.]}' | copied $NEW | kubectl apply -f -
   done
   ```

3. **Where something outside this repository names the broker's username, add the new one
   beside the old.** There are three, and the move finds them by failing if you do not:
   - banlieue's claim subject policy: a second line under `brokers:` in the ConfigMap
     `banlieue-claim-subject-policy`, `system:serviceaccount:mediatore-system:mediatore`;
   - with the transit sealer, the OpenBao Kubernetes auth role
     ([the store](the-store.md)): `bound_service_account_namespaces=banlieue-system,mediatore-system`;
   - with Entra's keyless form ([the Entra path](the-entra-path.md)), a second federated
     credential whose subject is the new username.

   In each policy namespace and each namespace with audience credentials, add the new
   subject to the `RoleBinding` (`mediatore-policy-bundles`, `mediatore-audience-credentials`):

   ```sh
   kubectl -n <namespace> patch rolebinding mediatore-policy-bundles --type=json \
     -p '[{"op":"add","path":"/subjects/-","value":{"kind":"ServiceAccount","name":"mediatore","namespace":"mediatore-system"}}]'
   ```

4. **Let the claims end, or accept step 6. Scale the old broker to zero**, and wait for its
   pods to be gone. The outage starts here.

   ```sh
   kubectl -n $OLD scale deploy/mediatore --replicas=0
   kubectl -n $OLD wait --for=delete pod -l app.kubernetes.io/name=mediatore --timeout=120s
   ```

5. **Copy what must survive**: every `PolicyFloor` (the replay floor; without it an older
   signed bundle would be admitted again) and every banned `SandboxNode` (a ban is a security
   record). Unbanned nodes need no copy after a drain: an idle guest is refused once,
   restarts and registers again.

   ```sh
   kubectl -n $OLD get policyfloors -o json | copied $NEW | kubectl apply -f -
   kubectl -n $OLD get sandboxnodes -o json | jq '.items |= map(select(.spec.banned == true))' | copied $NEW | kubectl apply -f -
   ```

6. **Only if claims were not drained**: copy their session and delegation Secrets, their
   stored output, and the `SandboxNode`s they are bound to (copying every node is simplest).

   ```sh
   kubectl -n $OLD get secrets -l mediatore.io/sandbox-uid -o json | copied $NEW | kubectl apply -f -
   kubectl -n $OLD get secrets -l mediatore.io/logs -o json | copied $NEW | kubectl apply -f -
   kubectl -n $OLD get sandboxnodes -o json | copied $NEW | kubectl apply -f -
   ```

   **The copies carry no `ownerReferences`, no `uid` and no `resourceVersion`**, which is
   what the filter removes. An owner reference cannot cross a namespace, and the garbage
   collector deletes an object whose owner it cannot find in the object's own namespace: a
   session copied with its owner reference is collected in the middle of a claim. The
   broker writes none for a sandbox outside its home, and release and the sweep remove the
   copies as they remove any other. A copied envelope opens because it is sealed to the
   sandbox's UID and its purpose and to nothing else: neither the namespace nor the
   Secret's name is in the binding, and the sandbox did not move.

7. **Apply the base in `mediatore-system`**, your overlay now with `namespace:
   mediatore-system` and none of step 1's patches: the `ServiceAccount`, the `Role`s and
   bindings, the `ClusterRoleBinding`'s subject, the `ClusterSPIFFEID`'s selector, the
   parameter's `broker` and the bindings' `paramRef.namespace` all move with it. Give the
   new `mediatore-sandbox` Service the address the old one had (release it from the old
   Service first), since the pool's members and the gateways' relay dial it; the user API
   keeps its host.

   ```sh
   kubectl -n $OLD delete service mediatore-sandbox     # frees the LoadBalancer address
   kubectl apply -k ~/.config/mediatore/core
   kubectl -n $NEW rollout status deploy/mediatore
   kubectl -n $NEW logs deploy/mediatore | grep -E 'store:|claim watcher running'
   # store: the Kubernetes API (ADR-0034) namespace="mediatore-system"
   ```

   The new broker starts only if its self-check passes, rebuilds its records from the
   `AgentSandbox` resources where they are, and opens the copied envelopes.

8. **Verify, then clean the old namespace.** A login, a claim, a token; for a copied claim,
   a token from its running workload. Then remove what the broker left in `banlieue-system`,
   the key Secrets last, and the old subject from the bindings of step 3.

   ```sh
   kubectl -n $OLD delete deployment/mediatore service/mediatore configmap/mediatore-config \
     rolebinding/mediatore-sessions rolebinding/mediatore-store rolebinding/mediatore-watcher-lease \
     role/mediatore-sessions role/mediatore-store role/mediatore-watcher-lease serviceaccount/mediatore \
     lease/mediatore-watcher configmap/mediatore-agentsandbox-subject-policy \
     networkpolicy/mediatore --ignore-not-found
   kubectl -n $OLD delete secrets -l mediatore.io/sandbox-uid
   kubectl -n $OLD delete secrets -l mediatore.io/logs
   kubectl -n $OLD delete sandboxnodes,policyfloors --all
   kubectl -n $OLD delete secret mediatore-sts mediatore-sealing mediatore-audience-secrets mediatore-registry --ignore-not-found
   ```

   Leave banlieue's own objects alone: its controller, its Secrets and ConfigMaps (the claim
   subject policy among them), the pools and the gateways' objects stay where they are.

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
