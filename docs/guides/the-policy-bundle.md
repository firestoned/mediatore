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

The name is part of what the broker checks (notaio v0.8.0): the ConfigMap
`<policy>-bundle` must hold the bundle of `<policy>`, and an audience's `<audience>-audience`
the bundle of that audience. A valid bundle copied under another name, or into an object
notaio would not have written, is refused with `WrongSubject` and the broker's log names the
object; nothing is cached and no floor moves. Copy nothing by hand: notaio writes these.

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
  namespaces: [sandboxes]        # default: sandboxes.namespace (no default once sandboxes.namespaces is set)
  egress: shadow                 # ADR-0030: a bundle's direct egress at the gateway: shadow | enforce
  audiences: shadow              # ADR-0053: the bundle as the source of a claim's audiences: shadow | enforce
  # sources: { ... }             # optional: which of those namespaces a sandbox namespace draws from (below)
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
`uid`) and the bundle's `issuedAt`, as a `PolicyFloor` resource in the broker's namespace
(ADR-0034), written before the bundle is used (decision 5). A bundle below the floor is refused as a
`Downgrade`, one from an earlier incarnation of a recreated policy as `StaleIncarnation`,
and both stay refused after a restart because the floor came back from the store. The
rule is notaio's (`next_floor`); the store's part is a compare-and-set, so two replicas
cannot move a floor down between them. A floor is never deleted with its policy.

notaio re-signs every bundle when half its lifetime is left (the default lifetime is 15
minutes, a site value between 5 minutes and a day; the broker refuses a bundle signed to
live longer than a day, `LifetimeTooLong`, whatever signed it): the same version and content digest,
a later `issuedAt` and `notAfter`. The broker admits that refresh as it admits any bundle
at or above the floor, replaces the held copy so the new `notAfter` takes, and compares no
sandbox again, since nothing the comparison reads has changed. Expiry is strict: a bundle
past `notAfter` is gone for every reader at once, with no skew allowance, so the broker's
clock may run ahead of notaio's by less than the refresh margin (half the lifetime) or the
policy briefly reads as having no bundle (`P011`, and under ADR-0030's `enforce` the
gateway's answer shrinks to the audience endpoints on its next ask). Keep both on NTP.

## Naming a policy on a sandbox

`spec.policyRef` names the `SandboxPolicy` the sandbox is under, looked up in the
namespaces the sandbox's own namespace draws its policies from: its own namespace alone,
unless the operator wrote a `policy.sources` entry for it
([which policies a namespace may name](#which-policies-a-namespace-may-name),
[ADR-0054](../adr/0054-which-policies-a-namespace-may-name.md)). A build before ADR-0054
also looked in every namespace of `policy.namespaces`; that is gone. It is optional in this
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
(`status.record.policyUid`, `status.record.bundleVersion` on the `AgentSandbox`), for the
audit and for the enforcing step.
While `policy.egress` is `shadow`, a sandbox naming a policy with no verified bundle in
its namespace's sources is admitted exactly like one naming none, with nothing recorded;
under `enforce` it is refused (below). The record is never rewritten by a later bundle.

## Which policies a namespace may name

`policy.namespaces` says where the broker reads bundles, and nothing else. Which of those
namespaces a sandbox may take its policy from is a second, separate statement
([ADR-0054](../adr/0054-which-policies-a-namespace-may-name.md)):

- with nothing written, a sandbox finds a policy in **its own namespace only**;
- `policy.sources` gives a sandbox namespace the list of policy namespaces it draws from.

```yaml
# mediatore.yaml
policy:
  trusted_keys: [ ... ]
  namespaces: [team-a, team-b, infra-policies]   # where bundles are read
  egress: enforce
  sources:                                       # optional
    infra:
      namespaces: [infra-policies]               # the whole of where infra finds a policy
```

Here `team-a` and `team-b` have no entry: each draws from itself and from nowhere else.
`infra` has one, and the list is the whole of its sources: an entry replaces the default,
it does not add to it, so list the namespace itself if its own policies are to stay
nameable. Every listed namespace must also be in `policy.namespaces`, with the bundle
`Role` there, or the broker refuses to start. So do an empty `sources`, an entry with an
empty list or no `namespaces`, a namespace listed twice, a name that is not a DNS label,
a duplicate key and an unknown field: leaving the key out is how you say "no mapping".

The mapping is the broker's configuration and never a label or an annotation in the
cluster, for the reason the keys are: whoever could write that object would choose which
policies a tenant runs under. Review it as you review the keys.

**Within one policy namespace nothing separates tenants.** Whoever may place a sandbox in
a namespace may name every policy that namespace draws from; the broker does not check
which groups a policy was written for (the signed bundle does not carry them). If two
tenants draw from one policy namespace under `enforce`, both get every policy in it. To
keep tenants apart, give each its own policy namespace and let only that tenant draw from
it; share a namespace only for policies every tenant mapped to it is meant to have.

At start the broker logs, per namespace it knows, `policy sources: where this namespace
draws its policies from` with `namespace=` and `sources=`, and a warning, `no policy source
of this namespace is in policy.namespaces`, for one whose sources the broker does not read:
every `policyRef` there will be reported or refused. The warning does not stop the start.

What a name that does not resolve gets depends on the switch:

| | `policy.egress: shadow` (default) | `policy.egress: enforce` |
| --- | --- | --- |
| the name is in none of the namespace's sources (nowhere, expired, or only in a namespace it does not draw from) | created; `P011`; nothing recorded | refused: `400 policy_not_resolved` from `POST /v1/claims`, or the `AgentSandbox` goes `Failed` with `policy_not_resolved: no verified bundle for policy <name> in the namespaces <namespace> draws its policies from`; no claim is created |
| two of the namespace's sources hold the name | created; `P012`; nothing recorded | refused, the same answer; the order of the list never decides |
| a source has not been read yet on this replica | created; `Unknown` | held with `Unknown` / `BundlesNotRead` until it has; no claim meanwhile |
| no `policyRef` | created; `P010` | created; `P010`; the audience endpoints only |

The answer to the requester is the same whether the policy exists nowhere or in a namespace
theirs does not draw from: it never says where else a name exists. The broker's own log
does, for the operator: `policy held by a watched namespace outside this sandbox's sources`
with `held_in=` and `sources=`. Under `shadow` the API logs `enforce would refuse this
claim` for a request it would refuse.

Under `enforce` the check is made again whenever the broker answers a gateway: a claim
whose bundle was signed for a namespace outside its own namespace's sources is served the
audience endpoints only and no gateway-placed credential, and the broker logs `the claim's
bundle is outside its namespace's policy sources`. So removing a source takes effect on
running sandboxes on the gateway's next ask, as a tightened policy does; it does not fail
them. A sandbox held as `Unknown` / `BundlesNotRead` for longer than a broker start is a
watched namespace the broker cannot list: check the bundle `Role` there.

### Upgrading to a build with ADR-0054

Sandboxes and policies in one namespace: nothing to write, nothing changes.

Sandboxes in one namespace and policies in another (for example a pool in the controller's
namespace and policies in `sandboxes`): this build stops finding those policies until you
say so.

1. Add the entry, the policy namespace being one already in `policy.namespaces`:

    ```yaml
    policy:
      namespaces: [sandboxes]
      sources:
        banlieue-system:                 # the namespace the sandboxes are created in
          namespaces: [sandboxes]        # where their policies are
    ```

2. Roll the image and the configuration out together. An older broker refuses to start on
   the `sources` key it does not know; a newer one without the entry applies the
   own-namespace default. A rollback removes the key with the image.
3. Read the start log: one `policy sources` line per namespace, and no warning.
4. Without the entry, under `shadow`, new sandboxes report `P011` where they reported a
   comparison. Under `enforce`, new sandboxes naming a policy are refused, and running ones
   lose the policy's direct egress and their gateway-placed credentials on the gateway's
   next ask.
5. Before turning `enforce` on with this build, or back on: one week of `shadow` with no
   `P011`, no `P012` and no `outside this sandbox's sources` line that you did not expect.

## Reading the findings

With a `policy` section configured, every sandbox carries a `PolicyConformant` condition
(decision 7), recomputed on each reconcile and whenever its policy's bundle changes. A
`Failed` sandbox keeps it, and keeps following the bundle: the verdict is about the spec,
not the claim.

| Status | Reason | Meaning |
| --- | --- | --- |
| `True` | `Conformant` | the broker's configuration allows this sandbox nothing the bundle does not |
| `False` | `Gaps` | the message lists each gap as `<code> <detail>`, separated by `;` |
| `Unknown` | `BundlesNotRead` | the broker has not finished reading the bundles of the namespaces this sandbox's namespace draws from; the message names the ones still unread |

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
| `P011` | a `policyRef` to no verified, unexpired bundle in the namespaces the sandbox's namespace draws its policies from |
| `P012` | a `policyRef` that more than one of those namespaces holds: the name is ambiguous and no bundle is compared |

Reading them: `P001` to `P005` are the places where `audiences[]` in `mediatore.yaml`, or
the request itself, is looser than the reviewed policy; each becomes a refusal one for one
when the bundle is enforced, so the fix is in the configuration or the policy, now, while
nothing breaks. `P006` is a policy that expects direct egress while the broker is in
`shadow`; under `enforce` the exact `host:port` entries are served to the gateway and the
proxy gets a route for each with no credential ([ADR-0030](../adr/0030-policy-egress-enforced-at-the-gateway.md),
[ADR-0025](../adr/0025-phantom-token-egress-proxy.md) decision 8), and what cannot be
served (rules, a wildcard, an IP literal) is `P007`. `P010` says the sandbox is
outside the policy altogether; `P011` that it names one notaio has not published a bundle
for, one the broker does not trust, or one in a namespace the sandbox's namespace does not
draw from: check the broker's log for the refusal, or for the `outside this sandbox's
sources` line. `P012` is two policies of one name in two of the namespace's sources: rename
one, or drop a source. Under `policy.egress: enforce`, `P011` and `P012` come with a
refused sandbox ([above](#which-policies-a-namespace-may-name)).

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

## Enforcing a claim's audiences (`policy.audiences`)

Shadow mode is the default and changes nothing. With `policy.audiences: enforce` (ADR-0053 decisions 9 to 16) the verified bundle
of the sandbox's policy decides what a claim may use:

- the claim must name a policy (`policy_ref`, `--policy`): `400 policy_required`, and a declarative `AgentSandbox` without one fails;
- the policy must resolve to a verified, unexpired bundle: `400 unknown_policy`. Until every watched namespace has been listed once the
  answer is `503 policy_not_synced` and nothing is created, and a declarative sandbox is held rather than failed;
- every audience must be one the bundle grants, else `400 unknown_audience`, the same answer as an audience that does not exist;
- `ttl_seconds` must fit the bundle's `lease.maxDurationSeconds`: `400 ttl_exceeds_policy`. The broker's own
  `sandboxes.max_ttl_seconds` (one day by default) applies as well, with or without a policy, so the bound is the
  smaller of the two (`400 ttl_exceeds_maximum`).

What the claim then gets is the bundle's grant **bounded by the broker's own configuration**, never wider than either: a bundle rule is
kept only if the audience's own `rules` in `mediatore.yaml` (its ceiling) cover it, and a grant with no rules reads as the ceiling; a grant
whose rules all fall outside the ceiling makes the audience unusable (never an empty, every-path list); the audience's endpoints are those
the grant lists; and a credential lives at most the grant's `ttlSeconds`. The proxy's routes, the gateway's routes, the tunnel allowlist and
every token or credential read the **current** bundle at each ask, so a policy that tightens narrows running claims on their next ask, and a
bundle that is missing, expired or unverified takes the audiences away (fail closed). A claim created before `enforce`, with no recorded
policy, loses its audiences the same way.

Roll it out as ADR-0030's egress was: `shadow` everywhere, read the `P001` to `P005`, `P010` and `P011` lines and conditions for a week,
make sure no live claim lacks a policy, then `enforce` in dev and each tier in turn. Setting `shadow` again restores today's behaviour on the
next ask. The cost is a dependency: under `enforce` a notaio outage longer than the bundle lifetime (15 minutes by default), or a broker clock
ahead of notaio's by more than the refresh margin, takes the audiences away from every claim under a policy.

## A running claim and a newer bundle (`policy.follow`)

Under `policy.audiences: enforce` every answer for a claim reads its policy's **current** bundle. The guest, though, renders its
ruleset, its proxy's routes and rules and Landlock's ports once, from its first `GET /v1/me`, and the lease is checked only at the
claim. [ADR-0061](../adr/0061-a-running-claim-follows-a-new-bundle-only-while-it-is-still-inside-it.md) has a running claim follow a
newer version only while it is still inside it:

- the policy's name still resolves, in the namespace's sources, to the claim's policy, and `ttl_seconds` fits the newer lease;
- nothing the guest was handed (kept on the record as `status.record.rendered` at its first `GET /v1/me`) is wider than the newer
  version allows: every route's rules covered, every destination still served.

Otherwise, under `policy.follow: enforce` (which bites only with `policy.audiences: enforce`), the mint answers `403 policy_changed`
with the reason, the gateway denies the claim as it does a released one, and the sandbox's `PolicyFollowed` condition is `False`
with `Refused`, the reason and both versions. The refusal is final for the claim; its owner claims again, and tokens already minted
run out. Under `shadow` (the default) nothing is refused: the same line is logged with `enforced=false` and the condition reads
`WouldRefuse`, cleared once the claim is inside again. A claim whose guest rendered under a broker older than ADR-0061 has no
`rendered` and is refused as `rendered_unknown` at the first changed version. Roll it out after `policy.audiences`: shadow for a week,
read the `WouldRefuse` conditions, then `enforce`.

## Audience definitions from notaio (`policy.audience_definitions`)

An audience's definition (its backend, where its credential is placed, its endpoints, the widest
rules and token any grant may have) can come from notaio as a signed audience bundle instead of
from `audiences[]` in `mediatore.yaml` ([ADR-0055](../adr/0055-audiences-from-signed-sandboxaudience-bundles.md),
notaio ADR-0020). notaio publishes one `<audience>-audience` ConfigMap per `SandboxAudience`, the
envelope under `audience.dsse.json`, once `NOTAIO_AUDIENCE_PLATFORM_NAMESPACE` is set on its side.

```yaml
# mediatore.yaml
policy:
  trusted_keys: [ ... ]                  # the same keys verify both kinds of bundle
  audience_definitions:
    mode: shadow                         # config (default) | shadow | bundles
    platform_namespace: sandbox-platform # must match NOTAIO_AUDIENCE_PLATFORM_NAMESPACE
    credential_refresh_secs: 60          # default 60
    # openbao:                           # only for platform audiences whose credential is in OpenBao KV
    #   url: https://openbao.home.example:8200
    #   role: mediatore                  # the Kubernetes auth role (auth_mount, token_file, ca_file as for transit)
```

- **`config`** (or no `audience_definitions`): `audiences[]` serves and no audience bundle is read.
- **`shadow`**: the broker reads audience bundles in the platform namespace, in every sandbox
  namespace and in every `policy.namespaces` entry, verifies each (payload type, a trusted key, schema, digest, lifetime) and keeps a version
  floor per audience in the store beside the policy floors. `audiences[]` still serves.
- **`bundles`**: the catalog serves, in the API (`POST /v1/claims`, `POST /v1/token`, `GET /v1/me`,
  the gateway's allowlist and credential routes) and in the watcher, and `audiences[]` must be
  empty. A definition change reaches a claim at its next ask, with no restart. Until the platform
  namespace and a claim's namespace have been listed after a start, the API answers `503
  audiences_not_synced` and the watcher holds the sandbox. A `secret` audience whose credential is
  not readable answers `503 credential_unavailable`. Not served yet, and refused when admitted
  (`NotBuilt`): a `caRef`, and an operator-held credential in `basic` format.

An audience in the platform namespace is a platform audience, usable from every namespace; one in any
other namespace is a team audience, usable only by claims in that namespace. The kind comes from the
namespace, never from a field of the bundle. The broker checks each definition again as notaio does: a
team audience's backend is `secret` or `none` and its credential is never in OpenBao; no header is
reserved (`host`, `content-length`, `proxy-authorization` and the rest); every endpoint is an exact DNS
`host:port`. A name or an endpoint that two audiences share is refused, for both, from every namespace
that can see both, and nowhere else.

The broker needs the bundle `Role` of `deploy/policy-bundles` in the platform namespace and in each
sandbox namespace it does not already read policies in. At start it logs `policy.audience_definitions
(ADR-0055)` with the mode, the platform namespace and the namespaces read, then `audience definition
admitted` with the namespace, name, kind and version of each bundle it takes, `audience bundle
refused; nothing changed` for one that does not verify, and `audience definition not taken` with the
rule (`L022`, `L023`, `L026`, `L017`) for one that verifies but breaks a rule; that one also withdraws
any earlier definition of the audience.

Each admitted audience with a credential source has its credential read, under `shadow` as well,
so the access is proven before `bundles` serves from it: a team audience's Secret with a `get` by
name in its own namespace, a platform audience's from its Secret in the platform namespace or from
OpenBao KV. Every `credential_refresh_secs`, and at once when a definition changes. The broker needs
the `deploy/audience-credentials` Role in each namespace that holds such a Secret, with
`resourceNames` replaced by those Secrets' names (an empty list would grant them all, so the
component ships a name that matches nothing). The log says `audience credential read (ADR-0055)` the
first time and after a failure, and `audience credential not read (ADR-0055)` with `reason` (`not
found`, `denied`, `unavailable`, `malformed`, `no reader for this source`) when a read fails; never
the Secret's name, the path or the value. A failed read keeps the last good value for two refresh
periods, then the audience has no credential until a read succeeds.

Under `shadow`, once every namespace has been listed, each audience gets one `audience shadow
(ADR-0055)` line whenever its verdict changes: `matches the file`, `differs from the file in:` and
the fields (`backend`, `placement`, `format`, `header`, `extra_headers`, `endpoints`, `rules`,
`max_ttl`), `in the file, no platform definition`, or `would appear:` for a definition the file does
not have. A matching verdict is `info`; the others are `warn`. Neither a credential nor where it is
read from is ever logged. Run `shadow` until no audience logs a difference before `bundles` is built
and switched on: remove `audiences[]` and set `mode: bundles`. That switch is the last rollout an
audience needs.

## What comes next

`policy.audiences` enforces a claim's audiences, rules, endpoints and lifetimes (above), and `policy.sources` decides which namespace may
name which policy (above, ADR-0054). Still shadow-only: eligibility by group from the bundle (ADR-0054 decision 7, not built), a default
policy per namespace applied without being named, and removing `egress` and `rules` from the broker's configuration (the audience's
`rules` stay as the ceiling for now). Until `policy.audiences` is `enforce` in your environment, the condition on the sandbox is the
list of what would break.
