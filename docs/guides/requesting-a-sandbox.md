<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Requesting a sandbox

A sandbox request is an `AgentSandbox` resource (`mediatore.io/v1alpha1`,
[ADR-0008](../adr/0008-agentsandbox-crd-owned-by-mediatore.md)). There are two ways to
create one, and everything after creation is the same: mediatore creates and owns one
`VirtualMachineClaim` for it, banlieue binds a warm pool member, mediatore declares the
claim's SPIFFE identity, and the sandbox is `Ready`.

## Through mediatore's API

`POST /v1/claims` with a bearer token whose audience is mediatore creates the resource
with `spec.subject` taken from the validated token, in the namespace `sandboxes.namespace`
names in `mediatore.yaml`. The caller never touches the cluster and needs no Kubernetes
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
# {"name":"sandbox-3f9a1c2e","phase":"Pending","ready":false,"addresses":[]}
```

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

`GET /v1/claims/sandbox-3f9a1c2e` answers from the resource's status: `phase` mirrors the
claim, `uid` is the claim's UID once the claim exists, `ready` is true once the claim is
`Bound` and its registration entry is set. `DELETE` deletes the resource; the finalizer
does the rest (below). Only the subject the token names can read or delete it.

## Declaratively

Anything with `create` on `agentsandboxes` in a namespace can request a sandbox there: a
GitOps repository, a CI job, an app-only service. The pool must live in the same
namespace.

```yaml
apiVersion: mediatore.io/v1alpha1
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

### Naming a policy

`spec.policyRef` (`policy_ref` on `POST /v1/claims`, `--policy` on `mediatore sandbox
create`) names the notaio `SandboxPolicy` the sandbox is under, in the sandbox's own
namespace ([ADR-0026](../adr/0026-notaio-bundles-verified-in-shadow.md) decision 6). It is
optional, and in this release it grants and refuses nothing: the broker's configuration is
still the policy, and the bundle notaio signs for the named policy is read in shadow. What
naming one does is put on the claim record the policy's uid and the version of the verified
bundle current when the claim was created, and give the comparison below something to
compare with. A sandbox naming a policy with no verified bundle (no such policy, or none
the broker trusts) is admitted exactly like one naming none, with nothing recorded. Like
the rest of the spec, the field is immutable.

### What the comparison reports

With a `policy` section configured, every sandbox carries a `PolicyConformant` condition
(decision 7), recomputed on each reconcile and whenever its policy's bundle changes:

| Status | Reason | Meaning |
| --- | --- | --- |
| `True` | `Conformant` | the broker's configuration allows this sandbox nothing the bundle does not |
| `False` | `Gaps` | the message lists each gap as `<code> <detail>`, separated by `;` |
| `Unknown` | `BundlesNotRead` | the broker has not finished reading the bundles of this namespace yet |

The codes, each also a `policy gap` warning in the broker's log when it appears or
changes:

| Code | The broker would allow |
| --- | --- |
| `P001` | an audience on the sandbox that the bundle does not list |
| `P002` | a `max_ttl` for an audience above the bundle audience's `ttlSeconds` |
| `P003` | an `egress` endpoint for an audience that the bundle audience does not list |
| `P004` | a rule for an audience that no bundle rule covers, or no rules where the bundle has some |
| `P005` | a sandbox `ttlSeconds` above the bundle's `lease.maxDurationSeconds` |
| `P006` | nothing: the bundle holds direct `egress[]`, which the broker has no way to provide |
| `P010` | no `policyRef` on the sandbox |
| `P011` | a `policyRef` to no verified, unexpired bundle |

A bundle rule covers a broker rule when it admits every request the broker rule does: the
same method or `*`, and a path glob matching every path the broker's glob matches (`**`
covers `*`, `*` does not cover `**`). A covering the broker cannot prove is reported. An
audience grant without `ttlSeconds` (the ceiling then lives in notaio's knob registry) is
not compared on `P002`. None of this changes what the sandbox gets: a sandbox with every
code is admitted, bound and minted for exactly as before.

```
$ kubectl -n agents get agentsandbox ledgers-2026-10-14 \
    -o jsonpath='{.status.conditions[?(@.type=="PolicyConformant")]}'
{"lastTransitionTime":"2026-11-02T09:14:07Z","message":"P002 max_ttl 900 for api://trading-data is above the bundle's ttlSeconds 300","observedGeneration":1,"reason":"Gaps","status":"False","type":"PolicyConformant"}
```

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
| `conditions` | `PolicyConformant`, with a `policy` section configured ([above](#what-the-comparison-reports)) |

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
