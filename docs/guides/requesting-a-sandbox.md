<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Requesting a sandbox

A sandbox request is an `AgentSandbox` resource (`mediatore.io/v1beta1`,
[ADR-0048](../adr/0048-agentsandbox-served-as-v1beta1.md); `mediatore.io/v1alpha1` is still
served as the same object, deprecated, [ADR-0049](../adr/0049-agentsandbox-served-as-v1alpha1-and-v1beta1.md);
[ADR-0008](../adr/0008-agentsandbox-crd-owned-by-mediatore.md)). There are two ways to
create one, and everything after creation is the same: mediatore creates and owns one
`VirtualMachineClaim` for it, banlieue binds a warm pool member, mediatore declares the
claim's SPIFFE identity, and the sandbox is `Ready`.

## Through mediatore's API

`POST /v1/claims` with a bearer token whose audience is mediatore creates the resource
with `spec.subject` taken from the validated token, in the namespace `sandboxes.namespace`
names in `mediatore.yaml` (or, since v0.3.0, the one the request names with
`namespace`, `--namespace` on the CLI, among `sandboxes.namespaces`,
[ADR-0046](../adr/0046-who-may-claim-a-list-of-groups-and-a-namespace-to-groups-mapping.md);
the answer then carries it). The caller never touches the cluster and needs no Kubernetes
RBAC. [Running workloads on a claimed VM](running-workloads.md) has the three ways to get
that token.

```bash
curl -sS https://mediatore.sandbox.example/v1/claims \
  -H "Authorization: Bearer $TOKEN" \
  -d '{ "pool_ref": "agents", "ttl_seconds": 3600,
        "audiences": ["api://trading-data"],
        "workload": { "image": "registry.internal:5000/sandbox/claude:latest",
                      "args": ["/usr/bin/claude", "-p", "reconcile the ledgers"] },
        "policy_ref": "agents" }'
# {"name":"sandbox-3f9a1c2e","namespace":"sandboxes","phase":"Pending","ready":false,"addresses":[]}
```

`ttl_seconds` is the sandbox's lifetime, counted from bind. It must be positive and at most
the broker's `sandboxes.max_ttl_seconds`, one day (`86400`) unless the operator set another:
above it the answer is `400 ttl_exceeds_maximum`, whose detail names the maximum, and a
declarative `AgentSandbox` with such a `ttlSeconds` is `Failed` with the same sentence in
`status.reason` and gets no claim. A policy's lease can only make the bound smaller
(`400 ttl_exceeds_policy`).

`pool_ref` names one `VirtualMachinePool` in that namespace. To let banlieue pick among
several, send `pool_selector` instead, a Kubernetes label selector over the namespace's pools
([ADR-0044](../adr/0044-a-sandbox-selects-its-pool-by-label.md), banlieue ADR-0132): `{}`
means every pool in the namespace, and `"pool_selector": { "match_labels": { "sandbox.example.com/image": "agent" } }`
the pools so labelled. Exactly one of the two: a body with neither or both is refused with
`400 invalid_pool`, never read as "any pool". The response's `pool` is the pool the member
came from, once the claim is bound. The CLI (`mediatore sandbox create`) takes `--pool <name>`
or `--pool-selector key=value`; with neither it sends `pool_selector: {}` and says so, so a
plain `sandbox create` claims across all the namespace's pools.

Among the Ready members of the matched pools, banlieue picks one: current image revision
first, then a healthy host, then the one Ready longest. `selection` says how to rank inside
that order ([ADR-0047](../adr/0047-a-sandbox-chooses-its-member-by-strategy.md), banlieue ADR-0135):
`"selection": { "strategy": "Spread" }` takes the member from the failure domain where you
hold the fewest sandboxes, so yours do not share a host; `MostAvailable` takes from the domain
with the most Ready members, so warm capacity drains evenly; `LongestReady` is the default and
what an absent `selection` means. A strategy only reorders, never filters: a claim never waits
while a Ready member exists. Any other value is refused (`422`), never read as a default. The
CLI takes `--strategy longest-ready|most-available|spread`, and sends nothing without it. Which
strategy chose the member, and from which domain, is on the claim's `Bound` condition
(`kubectl get vmclaim <name> -o jsonpath='{.status.conditions[?(@.type=="Bound")].message}'`).

An audience served from your own credential (`via: delegated`,
[ADR-0035](../adr/0035-a-requesters-own-session-delegated-at-claim-time.md)) takes it in
the same request, `"delegations": [{ "audience": "anthropic", "token": "...", "expires_at":
"..." }]`, sealed by the broker and never returned; the CLI fills it from a source you name
(`--delegate anthropic=claude-code`, `env:CLAUDE_CODE_OAUTH_TOKEN`, `file:<path>`) and
prints one line saying so. A claim naming such an audience without it is refused.

An audience can also want **your user name and a secret**, not an OAuth bearer
([ADR-0041](../adr/0041-a-requesters-own-username-and-password-or-token-from-the-os-credential-store.md),
`credential: basic`): the delegation's `token` is then `user:secret` (no colon in the user
name), and the gateway places it as `Authorization: Basic`, so the pool VM and the sandbox
never see it. `--delegate <audience>=prompt` asks at the terminal for the user name and then the
secret with echo off; `env:<NAME>` and `file:<path>` take the same `user:secret` shape for a
script. If the terminal's echo cannot be switched off (`stty -echo` fails), the CLI does not ask
for the secret and reads nothing: it stops with an error naming `env:` and `file:`, never a
prompt that says "not shown" over a secret the terminal would show. There is no flag that
carries the secret. A host that refuses passwords for a protocol
(an on-premises git host answers `403 Password authentication is not available for Git
operations`) needs a personal access token as the secret.

On macOS, `prompt` offers to keep the credential in the Keychain **for the claim's TTL** (never
longer than six hours; the offer names the duration, default no), and `--delegate
<audience>=store` reads it back. A saved item older than that limit is deleted and refused.
`mediatore logout --audience <name>` deletes it at once. Nothing is stored in the cluster beyond
the sealed envelope below, and the broker deletes that envelope when the claim ends or at the
credential's expiry, whichever comes first, never later than the claim's TTL
([ADR-0043](../adr/0043-a-persons-registry-credential-is-placed-at-the-gateway-the-vm-never-sees-it.md)).

The image's registry can be such an audience too: when it is, name it with `--audience
<registry-host>` and `--delegate <registry-host>=prompt`, and the pull is made with your
credential through the gateway; a claim whose image is on such a registry without naming its
audience is refused at admission.

`workload.image` is your agent as an ordinary OCI container image, the runtime and your
code, not the VM: the guest on the pool member pulls it at bind and runs `workload.args`
inside it under `nsjail` as your sandbox user ([what "the workload"
is](running-workloads.md#what-the-workload-is)). Pin it by digest when the record has to
say exactly which bytes ran.

For an issuer configured with a `session` (Dex in the homelab,
[ADR-0013](../adr/0013-dex-session-delegation.md)) the body also carries the caller's
`refresh_token`, which mediatore seals and keeps in its store, never on the resource, and
refreshes before every token it mints for the sandbox; `mediatore sandbox create` does this
for you (see [Running workloads](running-workloads.md)). A claim without it is refused with
`400 session_required`; one for an issuer that takes none, with `400 session_unexpected`.
The refresh token is spent by the claim that delegates it: the CLI drops it from the session
file once the broker holds it, so the next `mediatore sandbox create` needs a `mediatore login`
first, or it is the one refused with `session_required`.

`GET /v1/claims/sandbox-3f9a1c2e` answers from the resource's status: `phase` mirrors the
claim, `uid` is the claim's UID once the claim exists, `ready` is true once the claim is
`Bound` and its registration entry is set. `DELETE` deletes the resource; the finalizer
does the rest (below). Only the subject the token names can read or delete it.

## Declaratively

Anything with `create` on `agentsandboxes` in a namespace can request a sandbox there: a
GitOps repository, a CI job, an app-only service. The pool must live in the same
namespace, named with `poolRef` or selected with `poolSelector` (a `LabelSelector` over the
namespace's pools, `{}` for all of them; exactly one of the two, enforced by CEL on the
resource). `selection: { strategy: Spread }` says how banlieue ranks the members it may take
([ADR-0047](../adr/0047-a-sandbox-chooses-its-member-by-strategy.md)); it is optional, and a value outside
`LongestReady`, `MostAvailable` and `Spread` is refused by the schema.

```yaml
apiVersion: mediatore.io/v1beta1
kind: AgentSandbox
metadata:
  name: ledgers-2026-10-14
  namespace: agents
spec:
  subject:
    issuer: https://dex.home.example
    id: octocat
  poolRef: { name: agents }
  ttlSeconds: 3600
  audiences: ["api://trading-data"]
  workload:
    image: registry.internal:5000/sandbox/claude:latest
    args: ["/usr/bin/claude", "-p", "reconcile the ledgers"]
  policyRef: { name: agents }
```

```
$ kubectl -n agents get agentsandboxes
NAME                  SUBJECT   POOL     PHASE   READY   AGE
ledgers-2026-10-14    octocat   agents   Bound   true    41s
```

The `POOL` column is `status.poolRef.name`, the pool the bound member came from, so it reads
the same for a named pool and a selected one, and is empty while the sandbox is `Pending`.

### Naming a policy

`spec.policyRef` (`policy_ref` on `POST /v1/claims`, `--policy` on `mediatore sandbox
create`) names the notaio `SandboxPolicy` the sandbox is under, in the sandbox's own
namespace, or in the policy namespaces the operator mapped that namespace to
([ADR-0026](../adr/0026-notaio-bundles-verified-in-shadow.md) decision 6,
[ADR-0054](../adr/0054-which-policies-a-namespace-may-name.md)). It is
optional. Under `policy.egress: enforce`
([ADR-0030](../adr/0030-policy-egress-enforced-at-the-gateway.md)) the bundle's direct
egress entries are opened at the gateway; under `shadow`, the default, it grants nothing
beyond the broker's configuration, and the bundle notaio signs for the named policy is
read in shadow. What
naming one does is put on the claim record the policy's uid and the version of the verified
bundle current when the claim was created, and give the comparison below something to
compare with. Under `shadow`, a sandbox naming a policy with no verified bundle (no such
policy, none the broker trusts, or one in a namespace yours does not draw from) is admitted
exactly like one naming none, with nothing recorded. Under `enforce` it is refused:
`POST /v1/claims` answers `400 policy_not_resolved`, and a declarative `AgentSandbox` goes
`Failed` with a reason that starts with `policy_not_resolved`; no claim is created. The
answer is the same whether the policy exists nowhere or somewhere your namespace may not
use, so ask the operator which policies your namespace draws from. Like
the rest of the spec, the field is immutable.

`spec.workload.restart` (`restart` in `workload` on `POST /v1/claims`, `--restart` on
`mediatore sandbox create`; [ADR-0033](../adr/0033-a-one-shot-workload-the-restart-policy-and-the-claim-released-when-it-is-done.md))
says what the guest does when the workload exits before the deadline: `always` (the
default) restarts it whatever the status, `on-failure` restarts a non-zero exit and ends the
claim on `0`, `never` ends the claim on any exit. When the policy ends the claim, the guest
tells the broker, the exit (code or signal, restarts) goes on the record and `sandbox get`
shows it, and the claim is released as a delete releases it: the member recycled, the
tokens cut off. A one-shot agent is `--restart on-failure`.

`spec.workload.logs` (`logs: true` in `workload` on `POST /v1/claims`, `--logs` on
`mediatore sandbox create`; [ADR-0045](../adr/0045-a-sandbox-workloads-output-streamed-to-its-owner.md))
is the opt-in to output capture: the guest tees what the workload prints to stdout and
stderr, redacts it in the VM and ships it to the broker, and `mediatore sandbox logs <name>`
(`-f` to follow, `--tail`, `--since`, `--timestamps`, `--raw` to print control characters as the
workload wrote them instead of spelled out) reads it back, stdout lines to stdout and
stderr lines to stderr, for the claim's life and for `logs.retention_secs` after it ends. Only
the claim's subject can read it; a declarative requester has no token with that subject and
cannot. Without the opt-in nothing is captured and the output lands on the VM console alone,
as before. The broker must have `logs.enabled: true`
([the store](the-store.md#workload-output)): a claim that opts in on one that does not is
refused with `501 not_implemented` (declaratively, `Failed` with the reason). Redaction is best
effort, not a guarantee: the guest removes the secrets it placed in the jail and whatever looks
like a credential (a JWT, an `Authorization` value, a private key), and cannot catch a secret the
workload transforms or one it fetched itself; the output is kept for a bounded time and only
the newest `logs.max_bytes` (default 1 MiB) of it.

### What the comparison reports

With a `policy` section configured, every sandbox carries a `PolicyConformant` condition:
`True` when the broker's configuration allows the sandbox nothing the bundle does not,
`False` with a code per gap in its message, `Unknown` until the broker has read the
bundles of the namespaces yours draws from. [The policy bundle, in shadow](the-policy-bundle.md) has the codes
and how to read them. None of it changes what the sandbox gets; only `policy.egress:
enforce` does, above.

### Who may name which subject

`spec.subject` records who the sandbox is for, and every token mediatore mints for it
says so. The admission policy `mediatore-agentsandbox-subject`
(`deploy/base/admission/agentsandbox-subject.yaml`) therefore requires `spec.subject.id`,
with the cluster's username prefix applied, to equal the authenticated username of
whoever creates the resource. A GitHub login `octocat` through Dex with
`--oidc-username-prefix=github:` is the Kubernetes user `github:octocat`; the resource
stores `octocat`, which is what a token carries, and the policy adds the prefix from the
`usernamePrefix` (or per-issuer `issuerPrefixes`) key of ConfigMap
`mediatore-agentsandbox-subject-policy` in `banlieue-system`.

Two principals may name somebody else:

- mediatore's own ServiceAccount, always: it creates sandboxes for the subjects it has
  validated bearer tokens for, and that validation is the control;
- the usernames listed under `brokers` in that ConfigMap, which ships empty. A listed
  broker can attribute a sandbox, and the tokens it mints, to anyone, so list one only
  when something really does hand sandboxes to other people, and audit changes to the
  ConfigMap.

The whole `spec` is immutable after creation. The subject because the attribution was
authorized then; the rest because mediatore reads it once, when it creates the claim.
Change of mind means a new resource.

`spec.subject.issuer` is not checked at admission (the API server cannot tell which
issuer minted the caller's token). mediatore refuses a sandbox whose issuer is not one of
its configured `issuers`, or whose `audiences` are not all among its configured
`audiences`, before any claim exists: the status is `Failed` with the reason, and nothing
was created on the banlieue side.

### banlieue's side of the same rule

banlieue has the same policy on `VirtualMachineClaim`
(`banlieue-virtualmachineclaim-subject-authorization`). mediatore's ServiceAccount is the
only principal that creates claims under this design, and it creates them for other
people's subjects, so it has to be listed under `brokers` in ConfigMap
`banlieue-claim-subject-policy` in `banlieue-system`, and the issuers your users come
from must be in that ConfigMap's `issuers`. This is a one-time change on the cluster
that runs banlieue:

```yaml
brokers: |
  system:serviceaccount:banlieue-system:mediatore
issuers: |
  https://dex.home.example
```

Without it every claim mediatore creates is denied at admission, the sandbox stays
`Pending`, and the broker log shows the denial.

## What the status says

| Field | Meaning |
| --- | --- |
| `phase` | the claim's phase, mirrored: `Pending`, `Bound`, `Releasing`, `Failed` |
| `claimRef`, `claimUid` | the owned claim, once created; never cleared |
| `virtualMachineRef`, `addresses`, `boundAt`, `expiresAt` | from the claim's status |
| `entrySet` | the claim's `ClusterStaticEntry` is set on the SPIRE server |
| `ready` | `phase == Bound` and `entrySet`: the guest can fetch its SVID |
| `reason` | why the sandbox is `Failed` |
| `conditions` | `PolicyConformant`, with a `policy` section configured ([the policy bundle](the-policy-bundle.md#reading-the-findings)) |

A sandbox gets one claim, ever. When the claim's TTL fires, banlieue destroys the member
and the claim leaves `Bound`; the sandbox goes `Releasing`, then `Failed` with reason
`claim gone` once the claim is deleted. It is never rebound: a new VM is a new request.

## Deleting

Deleting the resource, by `kubectl delete` or `DELETE /v1/claims/{name}`, runs the
finalizer `mediatore.io/sandbox`: the claim's registration entry is retracted first,
then the store record is revoked (tokens stop at once), then the claim is deleted,
which makes banlieue destroy the VM. The object disappears only once the claim is gone.
A caller watching for deletion never sees success while the VM, or an identity that can
still mint tokens for it, exists.

## The pool must use `GuestReady`

A sandbox is only as ready as the pool's readiness signal. `spec.readiness` on a
`VirtualMachinePool` is required and has two values: `InfrastructureReady`, which fires
when the hypervisor reports the VM up, and `GuestReady` (banlieue ADR-0043), which fires
when the installed guest has booted and said so. Pools that serve sandboxes must use
`GuestReady`: `mediatore guest` needs the vTPM attested and the Workload API up before it
can register the node, and with `InfrastructureReady` a deferred-install image is handed
out while the install is still running. The claim then binds, the sandbox turns `Bound`,
and `ready` waits on a node registration that comes late or never, until the watcher's
`resolve_timeout_secs` fails the claim.

On a sandbox member the announcement is the guest's, not a boot stage's
([ADR-0019](../adr/0019-guestready-after-attestation-and-registration.md)): `mediatore
guest` writes it right after `POST /v1/nodes` is accepted, on the channel the hypervisor
reads (the `/run/banlieue/phase` marker for libvirt, `guestinfo.banlieue.phase` for
vSphere, a line over vsock for Cloud Hypervisor). So `GuestReady` on such a pool means
booted from the installed disk, attested as a SPIRE agent and registered with mediatore,
and the pool's `Warm` count is the number of members a claim can bind to now. A member
refused as a clone, or one that cannot reach the broker, announces nothing and stays out
of the pool. The signal is still liveness, not integrity (banlieue ADR-0043 decision 9):
mediatore reads it nowhere, and a bind resolves through the published EK and the node the
guest registered over its SVID.
