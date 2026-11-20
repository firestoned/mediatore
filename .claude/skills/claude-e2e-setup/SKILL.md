---
name: claude-e2e-setup
description: Set up or verify the end-to-end path from a person's login to a Claude answer inside a mediatore sandbox (Dex, SPIRE, notaio, the policy repository, the broker, the gateways and pool, the Anthropic key), step by step with a check at each step. Use when standing up the Anthropic flow on a new cluster, when a claim under the anthropic audience fails, or when any of the six configurations changes.
---

# Claude from the sandbox, end to end

The reference is `docs/guides/claude-end-to-end.md`: every value that must agree across
the six pieces. This skill is the order to do it in and what proves each step. Never put
a real hostname, address, tenant or key into the repository; the operator's values live in
their configuration directory outside it (`.claude/rules/no-real-infrastructure.md`).

## Before anything

- Read `docs/guides/claude-end-to-end.md` once, then the guide of the piece you touch
  (`issuers.md`, `homelab-walkthrough.md`, `deploying.md`, `the-policy-bundle.md`).
- Changes to a trust boundary, a token shape, an identity scheme or an external dependency
  start with an ADR (`.claude/rules/architecture-driven-development.md`), not here.

## 1. Dex

Check: the issuer answers discovery, the `mediatore` client is public, the ID token
carries `preferred_username` and a `groups` claim naming `<org>:sandbox-users`.

```sh
curl -s https://dex.<tailnet>/.well-known/openid-configuration | jq .issuer
mediatore login --issuer https://dex.<tailnet>      # the CLI prints the login it got
```

If `groups` is missing, the GitHub connector lacks `orgs: [{ name: <org>, teams: [...] }]`.

## 2. SPIRE

Check: the server runs, the broker's pod holds `spiffe://<td>/mediatore`, VMs attest as
`tpm`, and the entries the broker declares are rendered.

```sh
kubectl -n spire-server exec spire-server-0 -c spire-server -- spire-server agent list
kubectl -n banlieue-system logs deploy/mediatore | grep 'broker identity from the Workload API'
kubectl get clusterstaticentries | grep -E 'banlieue/(node|claim)|gateway'
kubectl -n spire-server logs -l app.kubernetes.io/name=server -c spire-server --since=10m | grep 'could not verify cert'
# nothing: every VM's EK chains to a CA in ConfigMap spire-tpm-ek-cas (one PEM per swtpm local CA:
# libvirt's per host, the Cloud Hypervisor provider's own beside it); a line here names the VM that does not
MEDIATORE_LIVE_KUBECONFIG=<kubeconfig> MEDIATORE_LIVE_TRUST_DOMAIN=<td> MEDIATORE_LIVE_CLASS_NAME=spire-server-spire make live-admission-test
```

The ConfigMap is copied into the server pod at start, so a CA added to it needs
`kubectl -n spire-server rollout restart statefulset/spire-server`. A change to the TPM
path is proven with `make kind-e2e-tpm` on the build host before it merges
(`.claude/rules/testing.md`).

## 3. notaio and the policies

Check: notaio runs, the policy namespace has both Roles, each policy has its bundle, the
broker admitted it and holds the floor.

```sh
kubectl -n notaio-system rollout status deploy/notaio
kubectl -n sandboxes get role notaio-bundles mediatore-policy-bundles
kubectl -n sandboxes get sbpolicy,exposureceilings
kubectl -n sandboxes get configmap claude-agent-bundle -o jsonpath='{.metadata.annotations.sandbox\.firestoned\.io/bundle-version}'
kubectl -n banlieue-system logs deploy/mediatore | grep 'policy bundle admitted'
kubectl -n banlieue-system get policyfloors
kubectl -n banlieue-system logs deploy/mediatore | grep -E 'policy sources:|no policy source'
# namespace=banlieue-system sources=sandboxes, and no "no policy source" warning
```

The sandboxes are created in `banlieue-system` and their policies are in `sandboxes`, so the
broker's configuration needs `policy.sources.banlieue-system.namespaces: [sandboxes]`
(ADR-0054). Without it a claim naming a policy is `400 policy_not_resolved` under
`policy.egress: enforce`, and reports `P011` under `shadow`; the broker's log then has
`policy held by a watched namespace outside this sandbox's sources`.

A policy that must name two audiences does not fit `standard` (K5.3 R1, lint `L005`):
decide `lab` with `dataScope: LabOnly` ceilings or a custom profile, under review in the
policy repository, with Security signing the ceiling.

## 4. The broker

Check: the audiences agree with the policies (`max_ttl` at or below `ttlSeconds`, the
same rules and endpoints), the Secrets exist, the start-up log names each backend, the
listener is reachable from the segment with the client's source intact.

```sh
kubectl -n banlieue-system get secret mediatore-sts mediatore-sealing mediatore-audience-secrets
kubectl diff -k <overlay>; kubectl apply -k <overlay>
kubectl -n banlieue-system logs deploy/mediatore | grep -E 'store:|audience served|policy.egress|listening'
kubectl -n banlieue-system get svc mediatore-sandbox -o jsonpath='{.spec.externalTrafficPolicy}'   # Local
```

A `503`/refused listener from the segment with the pod on another node than the one
announcing the address is the traffic policy, not the broker.

## 5. Gateways, pool, mirror

Check: three gateways attested with their entries applied, the pool warm, the member
registered, the mirror reachable from the segment.

```sh
kubectl -n banlieue-system get virtualmachines
kubectl -n banlieue-system get sandboxnodes            # PROVIDER filled, BANNED false
kubectl -n banlieue-system logs deploy/mediatore | grep 'node registered'
kubectl -n banlieue-system get configmap banlieue-claim-subject-policy -o jsonpath='{.data.brokers}{.data.issuers}'
# system:serviceaccount:banlieue-system:mediatore and the issuer URL: without them every claim is forbidden
```

A sandbox that stays `Pending` while the broker logs `virtualmachineclaims ... is forbidden:
ValidatingAdmissionPolicy 'banlieue-virtualmachineclaim-subject-authorization'` is that
ConfigMap, not the pool. A member that binds and whose workload exits within a second with
`Can't access working directory` is a guest older than ADR-0036 (no `/proc` in the jail).

A member logging `mediatore unreachable` is the relay or the listener (step 4), not the
member.

A workload whose requests time out while the proxy logs `upstream unreachable` or `the
gateway refused the tunnel`, with the relay ports steady and a gateway's `8443` open for
about half a minute then refused for a quarter, is the gateway's SPIRE agent failing
attestation and Envoy restarting with it (`Requires=spire-agent.service`): the server log
check of step 2 names it. Either the CA that issued the gateway's EK is missing from
`spire-tpm-ek-cas` (a gateway moved to another hypervisor has another swtpm CA), or the
gateway VM was recreated and its `ClusterStaticEntry` objects name the old agent ID:
regenerate them from the first RSA certificate in `.status.tpmEndorsementCertificates`.
A gateway VM needs one entry per user (ADR-0053): `gateway-NN-envoy` and, with a
gateway-placed audience, `gateway-NN-envoy-inject`, both `spiffe://<td>/gateway`, and
`gateway-NN-authorizer`, `spiffe://<td>/gateway/authorizer`, for `unix:user:mediatore-gateway`.
The admission policy `mediatore-clusterstaticentry-gateway` (in the base, applied with the
overlay in step 4) refuses any other shape, the pre-ADR-0053 authorizer entry included.

Envoy up and every tunnel `403` with the authorizer's unit restarting is the authorizer
without its own SVID (its entry missing, or still the old shape): it refuses to start on any
identity but `spiffe://<td>/gateway/authorizer`. The authorizer up and every tunnel refused
with `broker_unreachable` while the relay ports are steady is the broker refusing its identity
in the handshake (a broker from before ADR-0053, or an old authorizer entry against a broker
without `accept_plain_gateway_identity`), or `MEDIATORE_URL` not naming `BROKER_ADDRESS`, which
the authorizer's unit refuses to start on.

## 6. The Anthropic key

Check: the Secret has the `anthropic` key, the broker started on it, a hello claim gets
an answer. Never read the key's value; its length is enough to know it is there.

```sh
kubectl -n banlieue-system get secret mediatore-audience-secrets -o jsonpath='{.data.anthropic}' | base64 -d | wc -c
mediatore sandbox create --mediatore https://mediatore.<tailnet> --pool sandbox-pool \
  --audience anthropic --policy claude-agent --ttl 900 --restart never \
  --image <mirror>/firestoned/research-agent@sha256:<digest> \
  --arg /usr/local/bin/python3 --arg /usr/local/bin/research-agent --arg=--hello
kubectl -n banlieue-system logs deploy/mediatore | grep -E 'token issued|workload exited|claim released'
```

`400 … credit balance is too low` is the workspace's cap, not the path.

## Recording a run

A live run is written into `docs/guides/testing.md` under "Live proofs on the homelab"
with the lines each component printed, every real value replaced by a placeholder, and the
roadmap item ticked in the same commit.
