<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Homelab walkthrough: from an empty cluster to the first sandbox

The record of how the reference homelab was put together and what mediatore adds to it,
in the order it happened, with every command. [Deploying](deploying.md) is the short
operator's path for the mediatore part; this page is the whole stack, so a second
cluster can be built the same way and a reader can tell which piece is whose. Every
name is a placeholder (`home.example`, `<tailnet>`, RFC 5737 addresses); the real values
live in files outside the repository.

What the stack is, and who owns each part:

| Layer | Owner | Reference |
| --- | --- | --- |
| k0s, storage, MetalLB, the Tailscale operator | the cluster | this page, step 1 |
| SPIRE (server, controller manager, agents, CSI driver) | SPIRE's distribution, rendered once into manifests | step 2, [ADR-0005](../adr/0005-spire-topology.md), [ADR-0007](../adr/0007-broker-identity-and-spiffe-mtls.md) |
| The issuer (Dex over GitHub) | the `dex` chart | step 3, [issuers](issuers.md) |
| banlieue (pools, claims, the subject policy) | banlieue's release | step 4, [requesting a sandbox](requesting-a-sandbox.md) |
| mediatore (the broker, its entries and policies) | this repository | steps 5 to 7, [deploying](deploying.md) |
| VMs attesting with a TPM | `deploy/spire-tpm`, the VM image | step 8, [ADR-0018](../adr/0018-tpm-attestation-with-the-spiffe-plugin.md) |

## 1. The cluster

Three control-plane nodes on k0s (Kubernetes 1.36), kine on an external PostgreSQL, the
`local-path` storage class as default, MetalLB with one address pool for LoadBalancer
Services, and the Tailscale Kubernetes operator for anything people reach from their
laptops. Nothing mediatore needs is specific to k0s except one chart value (the kubelet
path, step 2).

```sh
kubectl get nodes -o wide
kubectl get storageclass                      # local-path (default)
kubectl get ipaddresspools -n metallb-system  # the pool LoadBalancers draw from
kubectl get ingressclass                      # tailscale
```

## 2. SPIRE from its distribution, rendered once

One trust domain for the whole homelab, the single-server collapse of ADR-0005: one
server plays the downstream role, its controller manager renders the
`ClusterStaticEntry` resources mediatore declares, its agents and CSI driver give the
broker pod its SVID over a socket. The datastore is the same PostgreSQL the cluster
already runs, over TLS the server verifies (`verify-full`, the CA in a ConfigMap).

SPIRE's distribution for Kubernetes is the hardened chart, so it is rendered once into
manifests that are checked in with placeholders and applied with kustomize from then on;
no Helm release lives in the cluster. (The reference cluster was first installed as a
release with the same values; retiring it for the rendered set is roadmap 02's open
item.)

```sh
kubectl create ns spire-server; kubectl create ns spire-system
kubectl -n spire-server create configmap pg-root-ca --from-file=ca.crt=pg-ca.pem
kubectl -n spire-server create secret generic spire-datastore --from-literal=password='...'
helm template spire-crds spire-crds --repo https://spiffe.github.io/helm-charts-hardened \
  --version 0.6.1 -n spire-server --kube-version 1.36.4 > spire/crds.yaml
helm template spire spire --repo https://spiffe.github.io/helm-charts-hardened \
  --version 0.30.2 -n spire-server --kube-version 1.36.4 --no-hooks --skip-tests \
  -f spire-template-values.yaml > spire/spire.yaml
cat > spire/kustomization.yaml <<'EOF'
resources: [crds.yaml, spire.yaml]
patches: [{ path: ../mediatore/dev/kind/spire/hardening-patch.yaml }]   # the CSI registrar's context
components: [../mediatore/deploy/spire-tpm]     # step 8; leave out until then
EOF
kubectl apply -f spire/crds.yaml && kubectl wait --for=condition=established -f spire/crds.yaml
kubectl apply -k spire
kubectl -n spire-server rollout status statefulset/spire-server
kubectl patch validatingwebhookconfiguration spire-server-spire-controller-manager-webhook \
  --type=strategic -p '{"webhooks":[{"name":"vclusterfederatedtrustdomain.kb.io","failurePolicy":"Fail"},{"name":"vclusterspiffeid.kb.io","failurePolicy":"Fail"}]}'
```

The hardening patch is the one gap the chart's recommended security contexts leave and
no value reaches, the CSI node driver registrar's container; the CSI driver itself is
privileged by necessity (bidirectional mount propagation), which the API server will
not combine with `allowPrivilegeEscalation: false`.
`--no-hooks --skip-tests` leaves out the chart's test pod and its hook Jobs. The one
hook that mattered flipped the controller manager's webhook from `Ignore` to `Fail`
after the first rollout (the webhook has to be lenient while the chart's own
`ClusterSPIFFEID` objects go in, before the controller manager answers), which is the
last command. The CRDs go first and are waited on, because `kubectl apply` discovers
kinds once per run. `dev/kind/spire` in the mediatore repository is this same procedure
for the kind tiers (`make kind-spire-render` renders, `make kind-spire` applies), so a
SPIRE version bump is a re-render and a diff, there and here.

`spire-template-values.yaml`, the render's input (the TPM attestor of step 8 is a kustomize
component, not a value):

```yaml
global:
  spire:
    clusterName: core
    trustDomain: sandbox.home.example
    caSubject: { commonName: sandbox.home.example, country: CA, organization: home.example }
    namespaces:
      create: false
      server: { name: spire-server }
      system: { name: spire-system }
    recommendations: { enabled: true }
spire-server:
  controllerManager: { enabled: true }      # className spire-server-spire
  replicaCount: 2
  topologySpreadConstraints:
    - maxSkew: 1
      topologyKey: kubernetes.io/hostname
      whenUnsatisfiable: DoNotSchedule
      labelSelector:
        matchLabels: { app.kubernetes.io/instance: spire, app.kubernetes.io/name: server }
  persistence: { type: pvc, size: 1Gi, storageClass: local-path }
  dataStore:
    sql:
      databaseType: postgres
      databaseName: spire
      username: spire
      host: 192.0.2.10
      port: 5432
      options: [{ sslmode: verify-full }]
      rootCAPath: /run/spire/pg-ca/ca.crt
      externalSecret: { enabled: true, name: spire-datastore, key: password }
  extraVolumes:
    - { name: pg-root-ca, configMap: { name: pg-root-ca } }
  extraVolumeMounts:
    - { name: pg-root-ca, mountPath: /run/spire/pg-ca, readOnly: true }
spire-agent:
  securityContext: { allowPrivilegeEscalation: false }   # root with hostPID; nothing to gain
  kubeletAddress: { mode: hostip }
  workloadAttestors:
    k8s:
      verification: { type: apiServerCA }    # the agent verifies the kubelet's serving cert
spiffe-csi-driver:
  kubeletPath: /var/lib/k0s/kubelet          # k0s, not /var/lib/kubelet
spiffe-oidc-discovery-provider: { enabled: false }
tornjak-frontend: { enabled: false }
```

What that leaves, measured: server 1.15.3 and controller manager 0.7.0, class
`spire-server-spire`, `watchClassless: false`, node attestor `k8s_psat` only, an
RSA-2048 CA with a 24 h TTL, the audit log off. Threat model R-7 records that posture.

```sh
kubectl -n spire-server rollout status statefulset/spire-server
kubectl -n spire-system rollout status daemonset/spire-agent
kubectl -n spire-server exec spire-server-0 -c spire-server -- spire-server agent list
```

## 3. The issuer: Dex over GitHub

GitHub is OAuth2 only, so Dex authenticates against it and mints the ID tokens the API
server, banlieue and mediatore validate ([issuers](issuers.md)). Dex's distribution is
a chart as well, rendered once the way SPIRE's was and applied with kustomize: Dex runs
in namespace `dex`, storage in its own CRDs, exposed to the tailnet by a Tailscale
Ingress (TLS terminated by the operator, hostname `dex.<tailnet>`). The GitHub OAuth
App's callback is `https://dex.<tailnet>/callback`.

```sh
kubectl create ns dex
kubectl -n dex create secret generic dex-github \
  --from-literal=GITHUB_CLIENT_ID=... --from-literal=GITHUB_CLIENT_SECRET=...
helm template dex dex --repo https://charts.dexidp.io --version 0.25.2 -n dex \
  --kube-version 1.36.4 --skip-tests -f dex-values.yaml > dex/dex.yaml
printf 'resources: [dex.yaml]\n' > dex/kustomization.yaml
kubectl apply -k dex
kubectl apply -f - <<'EOF'
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: { name: dex, namespace: dex }
spec:
  ingressClassName: tailscale
  defaultBackend: { service: { name: dex, port: { number: 5556 } } }
  tls: [{ hosts: [dex] }]
EOF
```

`dex-values.yaml`, the render's input, the parts that matter (the `mediatore` client is
the one addition this stack needs; the `kubernetes` client is `kubelogin`'s):

```yaml
replicaCount: 2
envVars:
  - { name: GITHUB_CLIENT_ID, valueFrom: { secretKeyRef: { name: dex-github, key: GITHUB_CLIENT_ID } } }
  - { name: GITHUB_CLIENT_SECRET, valueFrom: { secretKeyRef: { name: dex-github, key: GITHUB_CLIENT_SECRET } } }
config:
  issuer: https://dex.<tailnet>
  storage: { type: kubernetes, config: { inCluster: true } }
  oauth2: { responseTypes: [code], skipApprovalScreen: true }
  connectors:
    - type: github
      id: github
      name: GitHub
      config:
        clientID: $GITHUB_CLIENT_ID
        clientSecret: $GITHUB_CLIENT_SECRET
        redirectURI: https://dex.<tailnet>/callback
        useLoginAsID: true          # preferred_username is the GitHub login
  staticClients:
    - id: kubernetes
      name: Kubernetes
      public: true
      redirectURIs: [http://localhost:8000, http://localhost:18000]
    - id: mediatore                 # ADR-0013 decision 3: the CLI's public client
      name: mediatore
      public: true                  # Dex accepts any 127.0.0.1 port for a public client
```

```sh
curl -s https://dex.<tailnet>/.well-known/openid-configuration | jq .issuer
```

## 4. banlieue

banlieue's release installs its CRDs, the controller, the operator and one provider per
hypervisor (`libvirt` on each of the three hosts; Cloud Hypervisor beside it). Two of its
objects are mediatore's concern:

- the claim subject policy's ConfigMap, which must list mediatore's ServiceAccount as a
  broker and every issuer users come from, with the username prefix each gets at the
  API server;
- a `VirtualMachinePool` with `readiness: GuestReady`, which is what a sandbox is
  claimed from ([requesting a sandbox](requesting-a-sandbox.md)); on the sandbox image
  the guest announces it after attesting and registering (ADR-0019), so the image
  carries no phase stage of its own.

```sh
kubectl -n banlieue-system get configmap banlieue-claim-subject-policy -o yaml
```

```yaml
data:
  brokers: |
    system:serviceaccount:banlieue-system:mediatore
  issuers: |
    https://dex.<tailnet>
    https://accounts.google.com
    https://tenant.us.auth0.com/
  issuerPrefixes: |
    https://dex.<tailnet> github:
    https://accounts.google.com google:
    https://tenant.us.auth0.com/ auth0:
  usernamePrefix: |
    github:
```

## 5. mediatore's cluster-side objects

From this repository, with nothing yours in them: the `AgentSandbox` CRD, the broker's
ServiceAccount and RBAC, its `ClusterSPIFFEID`, and the two admission policies (what
the ServiceAccount may declare as an entry; who may name which subject on a sandbox).
These are what `make kind-deploy` applies in kind, and what the live admission test
needs on a real cluster.

```sh
kubectl apply -n banlieue-system -f deploy/base/crds -f deploy/base/serviceaccount.yaml \
  -f deploy/base/rbac.yaml -f deploy/base/clusterspiffeid.yaml \
  -f deploy/base/admission/clusterstaticentry-mediatore.yaml \
  -f deploy/base/admission/agentsandbox-subject.yaml
MEDIATORE_LIVE_KUBECONFIG=~/.kube/core.yaml \
MEDIATORE_LIVE_TRUST_DOMAIN=sandbox.home.example \
MEDIATORE_LIVE_CLASS_NAME=spire-server-spire \
make live-admission-test
```

The test runs as the ServiceAccount (impersonated), declares the two entry shapes,
sees the controller manager set them, proves admission refuses the shapes ADR-0006
forbids, and retracts everything.

## 6. The broker

[Deploying](deploying.md) in full; the summary:

```sh
cp -r deploy/overlays/homelab-example ~/.config/mediatore/core   # then edit every placeholder
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out sts.pem
kubectl -n banlieue-system create secret generic mediatore-sts --from-file=sts.pem
openssl rand -hex 32 > sealing.key
kubectl -n banlieue-system create secret generic mediatore-sealing --from-file=key=sealing.key
kubectl -n banlieue-system create secret generic mediatore-store \
  --from-literal=url='sqlite:///var/lib/mediatore/store.db?mode=rwc'
kubectl apply -k ~/.config/mediatore/core
kubectl -n banlieue-system rollout status deploy/mediatore
kubectl -n banlieue-system logs deploy/mediatore | head -40
```

The overlay's `mediatore.yaml` names the Dex of step 3 as the one issuer (`backend:
sts`, `subject_claim: preferred_username`, a `session` block, `required_group` the
GitHub team Dex reports), the audiences the STS mints for, the SQLite store on the PVC
and the local sealer. The `NetworkPolicy` opens 8443 to the sandbox segment, 8080 to
the Tailscale operator's namespace, and egress to DNS, the API server and `dex`.

## 7. The first login and request

```sh
mediatore login --issuer https://dex.<tailnet>
mediatore sandbox create --server https://mediatore.<tailnet> --pool pool-a \
  --audience grafana.home.example --image registry.internal:5000/sandbox:latest
mediatore sandbox get --server https://mediatore.<tailnet> <name>
```

The CLI logs in as the `mediatore` public client (PKCE, a loopback redirect), delegates
the refresh token with the request, and the broker parks it sealed under the sandbox's
UID; the reconciler creates the claim and the record ([ADR-0013](../adr/0013-dex-session-delegation.md)).
Until step 8 is done, the claim binds to a pool member and nothing registers a node, so
`ready` stays false and the watcher fails the claim after `resolve_timeout_secs`. That
is the expected state of a cluster at this step.

## 8. VMs attest with their vTPM

[ADR-0018](../adr/0018-tpm-attestation-with-the-spiffe-plugin.md). The server side is the
kustomize component `deploy/spire-tpm`, included by the SPIRE kustomization of step 2:
an init container copies the `spiffe/spire-tpm-plugin` server binary (pinned by digest)
into the server pod with the EK trust anchors it copies out of a ConfigMap (one PEM per
hypervisor host: the issuing certificate of its swtpm local CA, which signs every EK
certificate on that host; the root alone verifies nothing, the attestor takes no
intermediates), and `server.conf` gains the attestor block with the binary's checksum:

```sh
cp -r deploy/spire-tpm spire/tpm
for h in hv-01 hv-02 hv-03; do
  ssh $h sudo cat /var/lib/swtpm-localca/issuercert.pem > $h.pem
done
# one key per host under data: of spire/tpm/ek-cas.yaml; the block of
# spire/tpm/server.conf.fragment.hcl into server.conf as a patch, generated the way
# the kind tier does it (spire/spire.yaml stays as rendered):
mediatore/dev/kind/spire/render-server-conf-patch.sh spire/spire.yaml \
  spire/tpm/server.conf.fragment.hcl > spire/server-conf-patch.yaml
# components: [tpm] and server-conf-patch.yaml under patches: in
# spire/kustomization.yaml, then:
kubectl apply -k spire
kubectl -n spire-server rollout restart statefulset/spire-server   # the certificates are copied at start
kubectl -n spire-server rollout status statefulset/spire-server
kubectl -n spire-server exec spire-server-0 -c spire-server -- spire-server bundle show > bundle.pem
```

The VM side is the image: the SPIRE agent, the agent plugin binary from the same
release, the fragments in `image/` and the bundle just exported.

```sh
make dist-tpm-plugin CONTAINER_CLI=podman    # dist/tpm_attestor_agent, checksum verified
ls image/spire/agent.conf image/systemd/spire-agent.service image/systemd/mediatore-guest.service
```

banlieue-imagebuilder bakes them (roadmap 06). Acceptance, once a pool member boots from
that image: it appears in `spire-server agent list` as type `tpm` within a minute, its
hash equals `sha256` of the DER `SubjectPublicKeyInfo` of the certificate banlieue
published on the `VirtualMachine`, a reboot keeps the same agent, and a sandbox claimed
from the pool turns `ready` with the guest fetching its subject and the workload
getting a token.

## Where the real values live

| What | Where (outside the repository) |
| --- | --- |
| the admin kubeconfig | `~/.kube/core.yaml` |
| the SPIRE manifests with the real trust domain and datastore, the component copy with the hypervisor CAs | a kustomization beside the kubeconfig, applied with `kubectl apply -k` |
| Dex's manifests with the real issuer and GitHub app | the same |
| mediatore's overlay with the real names and CIDRs | `~/.config/mediatore/core` |
| the three Secrets' files | created once, deleted after `kubectl create secret` |
| the trust bundle for the VM image | the image builder's inputs |

Nothing on this page is tracked with a real value in it ([the rule](https://github.com/firestoned/mediatore/blob/main/.claude/rules/no-real-infrastructure.md)).
