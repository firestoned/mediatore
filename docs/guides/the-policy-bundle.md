<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# The policy bundle, in shadow

notaio certifies a `SandboxPolicy`: it lints it against its profile and its approved
ceiling, compiles it, signs the result and publishes it beside the policy as a ConfigMap.
Since [ADR-0026](../adr/0026-notaio-bundles-verified-in-shadow.md) the broker reads that
bundle, verifies it, keeps a version floor that survives restarts, and compares every
sandbox with it. It refuses nothing on the bundle's account: this is shadow mode, where the
broker's configuration is still the policy and the bundle says where the two disagree.
Enforcing the bundle is the next step (notaio's roadmap 00, phase 2).

This page is the operator's and the requester's side of it: installing notaio beside the
broker, which keys the broker trusts, naming a policy on a sandbox, and reading what the
comparison says.

## What shadow mode does, and does not

Does:

- verify each bundle notaio writes, under the keys you configured and nothing read from
  the cluster;
- keep, per policy, the highest bundle version it accepted, in the store with the claims,
  so an older bundle is refused after a restart too;
- record on each claim the policy a sandbox named and the bundle version current when the
  claim was created;
- compare each sandbox, on every reconcile and whenever its policy's bundle changes, with
  what the broker's configuration would allow it, and report the gaps as a condition on
  the `AgentSandbox` and a log line per gap.

Does not:

- refuse a sandbox, a claim or a token because of a bundle, a missing bundle or a gap;
- grant anything because a sandbox names a policy;
- change what the guest renders: the jail, the ruleset and the proxy's routes still come
  from `audiences[]` in `mediatore.yaml`.

The one new way to fail is at start: a `policy` section with a malformed key refuses the
start, as a malformed STS key does.

## notaio beside the broker

Install notaio from its release manifests as its install guide says (the CRDs, then the
controller and the built-in profiles, the image pinned by digest), signing with an OpenBao
transit key. `make kind-notaio` (`dev/kind/notaio-install.sh`) does exactly that in kind
and is the reference for the OpenBao side: a non-exportable Ed25519 key, a policy that
allows signing with it and nothing else, a Kubernetes auth role for notaio's
ServiceAccount.

notaio writes one ConfigMap per policy, `<policy>-bundle`, in the policy's own namespace,
labelled `app.kubernetes.io/managed-by=notaio`, with the signed envelope under
`bundle.dsse.json`. It needs its bundle Role in every namespace that holds policies
(`deploy/policy-namespace/notaio-bundles.yaml` in notaio's repository, applied per
namespace); the broker needs its read Role there too:

```sh
kubectl apply -k deploy/policy-bundles      # the Role and RoleBinding, in `sandboxes`
```

For another namespace, a two-line overlay of that directory setting `namespace:`. The
Role is `get`, `list` and `watch` on ConfigMaps and nothing else: the broker never writes
a bundle.

## The keys the broker trusts

The broker trusts exactly the keys in its own configuration, never a key read from the
cluster (ADR-0026 decision 2): whoever could write a ConfigMap could otherwise choose the
policy. notaio's key id is `notaio:v<N>`, the version of its transit key, and the public
key is what OpenBao reports for that version, standard base64:

```sh
bao read -format=json transit/keys/notaio \
  | jq -r '.data.keys | to_entries | max_by(.key | tonumber) | "notaio:v\(.key) \(.value.public_key)"'
```

```yaml
# mediatore.yaml
policy:
  trusted_keys:
    - { id: "notaio:v1", public_key: "<base64 Ed25519 public key>" }
  namespaces: [sandboxes]        # default: sandboxes.namespace
```

During a key rotation list the old and the new version side by side until every bundle
has been re-signed, then drop the old one. A key that is not a 32-byte Ed25519 key, or
an id listed twice, stops the start. Leaving the `policy` section out is how the broker
reads no bundle; a section without keys is refused, not read as "off".

With the section present the broker logs `policy bundle reflector running` at start, then
`policy bundle admitted` with the policy and the version for each bundle it accepts, and
`policy bundle refused; nothing changed` with the reason for each it does not. A refusal
leaves the cache and the floor as they were: an expired bundle, one signed by a key not
listed, one below the floor, one copied from another namespace are all logged and ignored.

## The version floor

Every bundle carries a version that notaio bumps when the content changes. The broker
keeps, per policy, the highest version it admitted, with the policy's incarnation (its
`uid`) and the bundle's `issuedAt`, in the `policy_floors` table of the store, written
before the bundle is used (decision 5). A bundle below the floor is refused as a
`Downgrade`, one from an earlier incarnation of a recreated policy as `StaleIncarnation`,
and both stay refused after a restart because the floor came back from the store. The
rule is notaio's (`next_floor`); the store's part is a compare-and-set, so two replicas
cannot move a floor down between them. Rows are never deleted with their policy.

notaio re-signs every bundle when half its lifetime is left (the default lifetime is 15
minutes, a site value between 5 minutes and a day): the same version and content digest,
a later `issuedAt` and `notAfter`. The broker admits that refresh as it admits any bundle
at or above the floor, replaces the held copy so the new `notAfter` takes, and compares no
sandbox again, since nothing the comparison reads has changed. Expiry is strict: a bundle
past `notAfter` is gone for every reader at once, with no skew allowance, so the broker's
clock may run ahead of notaio's by less than the refresh margin (half the lifetime) or the
policy briefly reads as having no bundle (`P011`, and under ADR-0030's `enforce` the
gateway's answer shrinks to the audience endpoints on its next ask). Keep both on NTP.

## Naming a policy on a sandbox

`spec.policyRef` names the `SandboxPolicy` the sandbox is under, looked up in the
sandbox's own namespace first and then in the broker's `policy.namespaces` in their listed
order (ADR-0026 decision 6 as amended 2026-11-05): the pool and its sandboxes may live in
the controller's namespace while the policies live in `sandboxes`. It is optional in this
release and, like the rest of the spec, immutable after creation.

```yaml
spec:
  policyRef: { name: agents }
```

```sh
# through the API
curl -sS https://mediatore.sandbox.example/v1/claims -H "Authorization: Bearer $TOKEN" \
  -d '{ "pool_ref": "agents", "ttl_seconds": 3600, "audiences": ["api://trading-data"],
        "workload": { "image": "registry.internal:5000/sandbox/claude:latest", "args": ["sh"] },
        "policy_ref": "agents" }'

# with the CLI
mediatore sandbox create --pool agents --audience api://trading-data \
  --image registry.internal:5000/sandbox/claude:latest --policy agents
```

When the reconciler creates the claim record it looks the policy up in the bundles it
holds and writes the policy's uid and the bundle's version on the record
(`claims.policy_uid`, `claims.bundle_version`), for the audit and for the enforcing step.
A sandbox naming a policy with no verified bundle is admitted exactly like one naming
none, with nothing recorded; the record is never rewritten by a later bundle.

## Reading the findings

With a `policy` section configured, every sandbox carries a `PolicyConformant` condition
(decision 7), recomputed on each reconcile and whenever its policy's bundle changes. A
`Failed` sandbox keeps it, and keeps following the bundle: the verdict is about the spec,
not the claim. It is only written for sandboxes in the namespaces the `policy` section
lists; a sandbox elsewhere stays `Unknown`.

| Status | Reason | Meaning |
| --- | --- | --- |
| `True` | `Conformant` | the broker's configuration allows this sandbox nothing the bundle does not |
| `False` | `Gaps` | the message lists each gap as `<code> <detail>`, separated by `;` |
| `Unknown` | `BundlesNotRead` | the broker has not finished reading the bundles of this namespace yet |

```
$ kubectl -n agents get agentsandbox ledgers-2026-10-14 \
    -o jsonpath='{.status.conditions[?(@.type=="PolicyConformant")]}'
{"lastTransitionTime":"2026-11-02T09:14:07Z","message":"P002 max_ttl 900 for api://trading-data is above the bundle's ttlSeconds 300","observedGeneration":1,"reason":"Gaps","status":"False","type":"PolicyConformant"}
```

The codes, each also a `policy gap` warning in the broker's log with the sandbox, the
policy and the bundle version when it appears or changes:

| Code | The broker would allow |
| --- | --- |
| `P001` | an audience on the sandbox that the bundle does not list |
| `P002` | a `max_ttl` for an audience above the bundle audience's `ttlSeconds` |
| `P003` | an `egress` endpoint for an audience that the bundle audience does not list |
| `P004` | a rule for an audience that no bundle rule covers, or no rules where the bundle has some |
| `P005` | a sandbox `ttlSeconds` above the bundle's `lease.maxDurationSeconds` |
| `P006` | nothing: the bundle holds direct `egress[]`, which the broker does not provide while `policy.egress` is `shadow` (under `enforce` it does, and only an entry it cannot serve is reported, as `P007`) |
| `P010` | no `policyRef` on the sandbox |
| `P011` | a `policyRef` to no verified, unexpired bundle |

Reading them: `P001` to `P005` are the places where `audiences[]` in `mediatore.yaml`, or
the request itself, is looser than the reviewed policy; each becomes a refusal one for one
when the bundle is enforced, so the fix is in the configuration or the policy, now, while
nothing breaks. `P006` is a policy that expects direct egress while the broker is in
`shadow`; under `enforce` the exact `host:port` entries are served to the gateway and the
proxy gets a route for each with no credential ([ADR-0030](../adr/0030-policy-egress-enforced-at-the-gateway.md),
[ADR-0025](../adr/0025-phantom-token-egress-proxy.md) decision 8), and what cannot be
served (rules, a wildcard, an IP literal) is `P007`. `P010` says the sandbox is
outside the policy altogether; `P011` that it names one notaio has not published a bundle
for, or one the broker does not trust: check the broker's log for the refusal.

Two things the comparison deliberately does not claim. A bundle rule covers a broker rule
only when it admits every request the broker rule does: the same method or `*`, and a
path glob matching every path the broker's glob matches (`**` covers `*`, `*` does not
cover `**`); a covering the broker cannot prove is reported. And an audience grant without
`ttlSeconds`, whose ceiling lives in notaio's knob registry rather than in the bundle, is
not compared on `P002`.

## Proving it on a cluster

`make kind-e2e-policy` ([testing](testing.md#notaios-bundles-in-shadow)) runs this page
end to end in kind: notaio from its release signing with OpenBao, the bundle admitted and
recorded, four sandboxes with their verdicts and their claims, a newer version followed,
the earlier one replayed and refused before and after a broker restart.

## What comes next

The enforcing step makes `spec.policyRef` required, turns the codes into refusals at the
claim and at every mint, decides who may name which policy, and removes `egress` and
`rules` from the broker's configuration in favour of the bundle. Until then, the
condition is the list of what would break.
