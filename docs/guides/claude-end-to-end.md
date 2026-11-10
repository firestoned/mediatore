<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Claude from the sandbox, end to end: every configuration the path depends on

A person logs in, asks for a sandbox, and an agent inside the jail gets an answer from
Claude without ever holding the key that paid for it. That path crosses six things an
operator configures: Dex, SPIRE, notaio, a policy repository, the broker with its
gateways and pool, and the Anthropic side. Each has its own guide; this one reads them
together, with the exact values that have to agree across them. Every name and address
is a placeholder (RFC 2606 and RFC 5737); put yours in.

The hello shape of the path is proven live ([testing](testing.md), runs 5 and 7); the
repository shape, GitHub and Claude under one policy, is tracked as roadmap 12.

## The path

```text
person ── mediatore login (PKCE) ──> Dex ── GitHub OAuth App ──> GitHub
   │                                  │
   │  ID token + refresh token        │ groups claim: org:team
   ▼                                  ▼
mediatore sandbox create ──> broker (/v1/claims): validates the login, seals the refresh token,
   │                          creates the AgentSandbox, compares it with the policy's bundle
   ▼
AgentSandbox ──> VirtualMachineClaim ──> banlieue binds a pool member that attested its vTPM
   │                                      (SPIRE agent, tpm attestor) and registered as a SandboxNode
   ▼
guest on the member: GET /v1/me over mTLS (node SVID) through a gateway's relay
   pulls the image from the mirror on the segment, loads the ruleset, starts the proxy
   and the jail with a phantom token
   ▼
agent in the jail ── x-api-key: <phantom> ──> proxy (127.0.0.1:3128)
   proxy ── claim SVID ──> broker POST /v1/token: the operator's key for audience `anthropic`
   proxy ── CONNECT api.anthropic.com:443 through a gateway's Envoy (authorized on the claim)
   ──> api.anthropic.com, x-api-key: <the key>, anthropic-version beside it
```

## A. Dex: the issuer over GitHub

GitHub mints no ID tokens, so Dex authenticates against it and mints them
([issuers](issuers.md), [homelab walkthrough](homelab-walkthrough.md)
step 3). What the flow needs from it:

| Piece | Value | Why |
| --- | --- | --- |
| GitHub OAuth App | callback `https://dex.<tailnet>/callback` | Dex's connector |
| Dex issuer | `https://dex.<tailnet>` (Tailscale Ingress, TLS by the operator) | the `iss` the broker and banlieue validate |
| Connector `github` | `useLoginAsID: true`, `orgs: [{ name: <org>, teams: [sandbox-users] }]` | `preferred_username` is the GitHub login; the `groups` claim carries `<org>:sandbox-users`, which the policies' `subjects.groups` and the broker's `required_group` name. Without `orgs` (or `loadAllGroups`) Dex emits no groups at all |
| Static client `mediatore` | `public: true`, no secret, any loopback redirect | the CLI's PKCE login (ADR-0013 decision 3) |
| Storage | `kubernetes`, in-cluster CRDs | refresh tokens survive a Dex restart |
| Refresh tokens | Dex's defaults (`expiry.refreshTokens` unset) | one refresh token per claim is delegated to the broker and spent per issue |

```yaml
# dex values, the parts that matter
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
        useLoginAsID: true
        orgs:
          - name: <org>
            teams: [sandbox-users]
  staticClients:
    - { id: mediatore, name: mediatore, public: true }
```

On the broker:

```yaml
issuers:
  - url: https://dex.<tailnet>
    backend: sts
    client_id: mediatore
    subject_claim: preferred_username
    required_group: <org>:sandbox-users     # one gate for the broker; the policy's subjects is per policy
    session: { client_id: mediatore }
```

Known shape of the session: the refresh token Dex hands the CLI is delegated to the broker
on `POST /v1/claims` and sealed into the sandbox's Secret; every `POST /v1/token` refreshes
it. The GitHub token behind Dex's session expires after about eight hours, after which a
refresh fails and token minting with it: log in right before a claim. A claim under
`via: none` or `via: secret` audiences alone never refreshes anything.

## B. SPIRE: one trust domain, three kinds of node

[Homelab walkthrough](homelab-walkthrough.md) steps 2 and 8,
[deploying](deploying.md) steps 6 and 7, ADR-0005, ADR-0006, ADR-0018,
ADR-0028, ADR-0031.

| Piece | Value |
| --- | --- |
| Trust domain | `sandbox.home.example` |
| Server | the hardened chart rendered once (`spire` 0.30.2, server 1.15.3), two replicas, the controller manager with `className: spire-server-spire`, `watchClassless: false`; datastore PostgreSQL over `verify-full` |
| In-cluster attestation | `k8s_psat` for the agents on the nodes; the CSI driver gives the broker pod its socket |
| The broker's identity | `ClusterSPIFFEID` `mediatore` from `deploy/base`: `spiffe://sandbox.home.example/mediatore` for the Deployment's pods |
| VM attestation | the `deploy/spire-tpm` component: the `spiffe/spire-tpm-plugin` server binary (v1.11.3, pinned by digest, `plugin_checksum` in `server.conf`), `ca_path: /tpm/cas` with one PEM per hypervisor host (the issuing certificate of its swtpm local CA); no hash allowlist (decision 2 of ADR-0018) |
| Upstream authority | the `deploy/spire-upstream` component (ADR-0031): OpenBao's PKI mount `spire`, Kubernetes auth role `spire-server`, the CA the server chains to in ConfigMap `spire-upstream-ca`; the guests' bundle is the root alone |
| CA TTL | 24 h: a bundle baked into an image admits a first boot for a day; refresh the bundle layer before a pool scale-up, or ship the root (ADR-0031) |
| Server reach for VMs | a LoadBalancer address on the LAN for port 8081, reached by pool members only through a gateway's relay (`3129`) |

Agent configuration in the pool image's deployment layer (and the gateways', with their own
addresses):

```hcl
agent {
  trust_domain      = "sandbox.home.example"
  server_address    = "198.51.100.1"      # a gateway's sandbox address: the relay (ADR-0027)
  server_port       = "3129"
  trust_bundle_path = "/etc/spire/bundle.pem"
  socket_path       = "/run/spire/sockets/agent.sock"
  data_dir          = "/var/lib/spire/agent"
}
plugins {
  NodeAttestor "tpm" { plugin_cmd = "/usr/lib/spire/tpm_attestor_agent" plugin_checksum = "<checksum>" plugin_data { pve { enabled = false } } }
  KeyManager "disk" { plugin_data { directory = "/var/lib/spire/agent" } }
  WorkloadAttestor "unix" { plugin_data { discover_workload_path = true } }
}
```

The identities the flow uses, and who declares them:

| SPIFFE ID | Declared by | Selector |
| --- | --- | --- |
| `spiffe://<td>/spire/agent/tpm/<ek-hash>` | the attestor, at the VM's first boot | the EK certificate chaining to a host's CA |
| `spiffe://<td>/banlieue/node/<ek-hash>` | the broker, as a `ClusterStaticEntry` when banlieue publishes the member's certificates | the agent above as parent, `unix:uid:0` and `unix:path:/usr/bin/mediatore` on the member |
| `spiffe://<td>/banlieue/claim/<claim uid>` | the broker, when the claim binds | the member's agent as parent, the sandbox user `sb-<hash>` |
| `spiffe://<td>/gateway` | the operator, two `ClusterStaticEntry` per gateway VM (`deploy/gateway/clusterstaticentries.yaml`) | `unix:user:envoy` and `unix:user:mediatore-gateway` under the gateway's agent |
| `spiffe://<td>/mediatore` | `deploy/base/clusterspiffeid.yaml` | the broker's pods |

The admission policy `mediatore-clusterstaticentry` constrains what the broker's
ServiceAccount may declare to the two `banlieue/` shapes; the gateway entries are applied by
hand because of it. The TPM path is proven by `make kind-e2e-tpm` on the build host before
any change to it merges (`rules/testing.md`).

## C. notaio: the policy certified

[The policy bundle](the-policy-bundle.md), ADR-0026, ADR-0030, notaio's
own install guide and `dev/kind/notaio-install.sh` as the reference.

| Piece | Value |
| --- | --- |
| Install | notaio's release manifests (CRDs, then the controller and the built-in profiles), image by digest, in `notaio-system` with `pod-security.kubernetes.io/enforce: restricted` |
| Signing key | OpenBao transit key `notaio`, `ed25519`, `exportable=false`; policy `notaio-sign` allowing `transit/sign/notaio` and nothing else; Kubernetes auth role `notaio` bound to the `notaio` ServiceAccount, audience `openbao`, 15 min tokens |
| What consumers trust | the key's public half, read from OpenBao once (`notaio:v1 <base64>`), never from the cluster: `policy.trusted_keys` on the broker |
| Per policy namespace | Role `notaio-bundles` (ConfigMaps `get`, `create`, `patch`) for notaio; Role `mediatore-policy-bundles` (`deploy/policy-bundles`, `get`, `list`, `watch`) for the broker |
| The bundle | ConfigMap `<policy>-bundle` beside the policy, key `bundle.dsse.json`, annotations `sandbox.firestoned.io/bundle-version` and `bundle-digest`; payload type `application/vnd.firestoned.sandboxpolicy.bundle.v2+json` |
| Profiles that matter | `standard`: K5.3 at R1, one audience, write allowed, tokens of at most 900 s. `lab`: K5.3 at R2, several audiences, but `LabOnly` data scope, so every audience it names must carry `dataScope: LabOnly` on its ceiling (notaio ADR-0017) |
| Lints that bite here | `L005` the audience set does not fit K5.3; `L006` write without K5.2 or TTL over K5.1; `L014` the policy's exposure exceeds its approved ceiling |

On the broker:

```yaml
policy:
  trusted_keys:
    - { id: "notaio:v1", public_key: "<base64 Ed25519 public key>" }
  namespaces: [sandboxes]      # where the bundle ConfigMaps are read
  egress: enforce              # ADR-0030: a bundle's direct egress joins the gateway allowlist
```

What the broker does with it: verifies every bundle under those keys, keeps the version
floor as a `PolicyFloor` (ADR-0034), records on each claim the policy incarnation and the
bundle version it was created under, compares each sandbox with the bundle and reports
`PolicyConformant` with the `P00n` gaps; under `enforce` a bundle's direct `egress[]` is
served to the gateway. A sandbox names its policy with `spec.policyRef` (the CLI's
`--policy`).

## D. The `sandbox-policies` repository

Private, GitOps-only, Flux-applied. Its shape, and the three policies that exist:

| Path | Holds |
| --- | --- |
| `clusters/core/` | the `FluxInstance` (Flux 2.10), two `OCIRepository` sources (`policies`, `ceilings`) with cosign verification: `policies` by the lint workflow's keyless identity, `ceilings` by Security's key, and one `Kustomization` per source |
| `platform/admission/gitops-only.yaml` | the `ValidatingAdmissionPolicy` admitting only `flux-system:kustomize-controller` to `sandboxprofiles`, `sandboxpolicies`, `knobgrants`, `exposureceilings` |
| `namespaces/sandboxes/` | the namespace, notaio's bundle Role, `policies/`, `ceilings/` |
| `keys/security.pub` | the public half of Security's cosign key; the private half stays with Security, off every shared machine |
| `scripts/sign-ceilings.sh` | Security signs a published `ceilings` digest by hand, no transparency log |

The policies as they stand (profile `standard`, subjects `<org>:sandbox-users`):

| Policy | Audience | Access | TTL | Rules | Ceiling (Security-signed) |
| --- | --- | --- | --- | --- | --- |
| `claude-agent` | `anthropic` | Write, `messages:write` | 900 s | `POST /v1/messages`, `POST /v1/messages/count_tokens` | `anthropic` Write 900 s, endpoint `api.anthropic.com:443` |
| `research-agent` | `github` | Write, `repo:read`, `repo:write` | 480 s | `GET /repos/<org>/**`, `PUT /repos/<org>/*/contents/**` | `github` Write 720 s, `api.github.com:443` |
| `proof-agent` | `proof.<lab>` | Read | 480 s | `GET /v1/**` | Read 900 s |

All three: `egress: []`, `tools: []`, lease 1800 s, one concurrent. The audience `endpoints`
on a `v1alpha2` policy are brokered endpoints, reached through the proxy only.

```yaml
# namespaces/sandboxes/policies/claude-agent.yaml, as deployed
apiVersion: sandbox.firestoned.io/v1alpha2
kind: SandboxPolicy
metadata: { name: claude-agent, namespace: sandboxes }
spec:
  profileRef: standard
  subjects: { groups: ["<org>:sandbox-users"] }
  audiences:
    - name: anthropic
      access: Write
      scopes: ["messages:write"]
      ttlSeconds: 900
      endpoints: ["api.anthropic.com:443"]
      rules:
        - { method: POST, path: "/v1/messages" }
        - { method: POST, path: "/v1/messages/count_tokens" }
  egress: []
  tools: []
  lease: { maxDurationSeconds: 1800, maxConcurrent: 1 }
```

How a change gets in: a pull request runs `notaio lint`; anything under `ceilings/` needs
Security's review (CODEOWNERS); on merge the workflow publishes the two OCI artifacts;
Security signs the new `ceilings` digest with `scripts/sign-ceilings.sh`; Flux applies;
notaio lints again, signs, publishes `<policy>-bundle`; the broker admits it
(`policy bundle admitted … version=N`) and the floor moves.

## E. The broker

[Deploying](deploying.md); the overlay copied from
`deploy/overlays/homelab-example`. The parts of `mediatore.yaml` the flow uses:

```yaml
trust_domain: sandbox.home.example
spire:
  workload_api_socket: unix:///run/spire/sockets/spire-agent.sock
  entries: { class_name: spire-server-spire }
issuers:                      # section A
  - { url: https://dex.<tailnet>, backend: sts, client_id: mediatore, subject_claim: preferred_username, session: { client_id: mediatore } }
audiences:
  - name: github              # ADR-0025 decision 8: reached bare, the phantom dropped
    via: none
    max_ttl: 480
    egress: ["api.github.com:443"]
    rules:
      - { method: GET, path: "/repos/<org>/**" }
  - name: anthropic           # ADR-0032: the operator's key, placed by the proxy
    via: secret
    secret_file: /etc/mediatore-audience-secrets/anthropic
    secret_header: x-api-key
    secret_extra_headers:
      - { name: anthropic-version, value: "2023-06-01" }
    max_ttl: 900
    egress: ["api.anthropic.com:443"]
    rules:
      - { method: POST, path: "/v1/messages" }
      - { method: POST, path: "/v1/messages/count_tokens" }
sts: { issuer: https://mediatore.<tailnet>, kid: homelab-1, signing_key_file: /etc/mediatore-sts/sts.pem }
sandboxes: { namespace: banlieue-system }    # where POST /v1/claims creates them; the pool lives there
store: { sealing: { key_file: /etc/mediatore-sealing/key } }
policy: { trusted_keys: [...], namespaces: [sandboxes], egress: enforce }    # section C
gateways: ["198.51.100.1:8443", "198.51.100.2:8443", "198.51.100.3:8443"]  # section F
registries:
  - { host: "198.51.100.10:5000", reach: segment }                         # the mirror
```

The audience's `max_ttl`, `egress`, `rules` and `endpoints` must agree with the policy's,
or the shadow comparison reports the gap (`P002` for TTL, and so on) and
`PolicyConformant` goes `False`.

Secrets in `banlieue-system`, each a file read once at start:

| Secret | Key | Made by |
| --- | --- | --- |
| `mediatore-sts` | `sts.pem` | `openssl ecparam -name prime256v1 -genkey` to PKCS#8 |
| `mediatore-sealing` | `key` | `openssl rand -hex 32` |
| `mediatore-audience-secrets` | `anthropic` | `read -rs ANTHROPIC_KEY && kubectl create secret generic … --from-literal=anthropic="$ANTHROPIC_KEY"` |
| `mediatore-audience-ca` | `ca.pem` | the private PKI behind a private audience (`ca_file`); not needed for Anthropic |

Mounted `0440` with `fsGroup: 65532`. The deployment facts that bit on 2026-11-09: the
sandbox Service carries `externalTrafficPolicy: Local` (in `deploy/base` since PR #99), the
`NetworkPolicy` admits `8443` from the gateways' masqueraded addresses alone, `8080` from
the ingress namespace, egress to DNS, the control plane and Dex's address; nothing pins the
pod to a node since ADR-0034.

## F. The gateways, the pool, the mirror

[Deploying](deploying.md) step 7, ADR-0027, ADR-0028, ADR-0029.

| Piece | Value |
| --- | --- |
| Gateway VMs | three, from `ghcr.io/firestoned/mediatore-gateway` at the release's digest, two NICs (`egress` routable with the default route, `sandbox` on the routeless segment), anti-affinity across hosts |
| Gateway env | `TRUST_DOMAIN`, `SANDBOX_IF`, `DATA_PORT=8443`, `RELAY_SPIRE_PORT=3129`, `RELAY_BROKER_PORT=3130`, `SPIRE_SERVER_ADDRESS:PORT` (the LoadBalancer, 8081), `BROKER_ADDRESS:PORT` (the sandbox listener, 443), `MEDIATORE_URL` for the authorizer |
| What a gateway allows | a tunnel only for a claim SVID of the trust domain, to an endpoint the broker lists for that claim (`GET /v1/gateway/claims/{uid}`): the audiences' `egress` plus, under `enforce`, the bundle's direct egress |
| Pool | `VirtualMachinePool` `sandbox-pool`: `readiness: GuestReady`, `recycleOnImageChange: true`, one warm member, `VMClass` with one NIC on the segment, addresses from the pool's `addressing` and a `userData` stage writing the static network file |
| Pool image | `VMImage` `mediatore-guest` on the ISO built from `ghcr.io/firestoned/mediatore-guest` at the release's digest (`auroraboot`), three cloud-config layers: the image's base, banlieue's EK layer, the deployment layer (section B's `agent.conf`, the bundle, `/etc/mediatore-guest/env` with `MEDIATORE_URL=https://<gateway sandbox address>:3130`, `/etc/mediatore/gateways`, `/etc/mediatore/registries`, the mirror's CA or `MEDIATORE_PLAIN_HTTP_REGISTRIES`) |
| Mirror | `registry:2` in proxy mode to `ghcr.io`, listening on the host's own segment address (a forwarded port is refused by the isolated network); declared on the broker with `reach: segment` and on the pool in `/etc/mediatore/registries` |
| Host table | `inet mediatore_host` on every member: output to the gateways' data port, the relay ports and the mirror alone |

The example image, mirrored by digest: `198.51.100.10:5000/firestoned/research-agent@sha256:<digest>`
(`examples/research-agent`, `make example-image`).

## G. The Anthropic side

| Piece | Value |
| --- | --- |
| The key | an API key from a dedicated workspace with a spend limit: the upstream sees one key for every subject, attribution is the broker's log (ADR-0032 decision 5); the workspace's cap is the bound, and when it bites the agent sees `400 invalid_request_error: Your credit balance is too low` (run 5 saw it) |
| Where it goes | `x-api-key` on every request, `anthropic-version: 2023-06-01` beside it; the proxy recognises the phantom in `x-api-key` too, so a tool reading `ANTHROPIC_API_KEY` works unchanged |
| What the jail sees | `MEDIATORE_TOKEN` (the phantom) and nothing else from the broker; the example agent sets `ANTHROPIC_BASE_URL=http://127.0.0.1:3128/api.anthropic.com` and `ANTHROPIC_API_KEY=<phantom>` for the SDK itself, so its requests leave through the proxy, which swaps the phantom for the key and tunnels through a gateway |
| Rotation | edit the Secret, restart the broker; every proxy holds the old value for at most `max_ttl` (900 s) |
| OAuth instead of a key | not this flow: an OAuth bearer needs `anthropic-beta: oauth-2025-04-20` and is a per-person credential; `via: secret` is the operator's |

The two claims:

```sh
mediatore login --issuer https://dex.<tailnet>

# hello: one Messages call, policy claude-agent, the one audience
mediatore sandbox create --mediatore https://mediatore.<tailnet> --pool sandbox-pool \
  --audience anthropic --policy claude-agent --ttl 900 --restart never \
  --image 198.51.100.10:5000/firestoned/research-agent@sha256:<digest> \
  --arg /usr/local/bin/python3 --arg /usr/local/bin/research-agent --arg=--hello

# repository: GitHub through the proxy, then Claude; needs a policy naming both audiences
mediatore sandbox create --mediatore https://mediatore.<tailnet> --pool sandbox-pool \
  --audience github --audience anthropic --policy <two-audience policy> --ttl 900 --restart never \
  --image 198.51.100.10:5000/firestoned/research-agent@sha256:<digest> \
  --arg /usr/local/bin/python3 --arg /usr/local/bin/research-agent \
  --arg <org>/mediatore --arg "What does this project do and what would you read first?"
```

What the broker logs for a good run (run 7): `claim created`, the guest's `report` (image
digest, host table loaded), `token issued audience=anthropic backend="secret"
header=x-api-key`, then for a one-shot workload `workload exited and its restart policy
ends the claim code=Some(0)`, `entry retracted`, `claim released`. Argv is absolute: the
jail sets no `PATH` and applies nothing of the image's `ENTRYPOINT` or `ENV`.

