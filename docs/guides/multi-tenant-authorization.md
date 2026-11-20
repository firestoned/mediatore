<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# How to support multi-tenant authorization

Several teams share one mediatore and one pool platform. This guide says who may do what at each
step, what you can configure, how a service (not a person) claims programmatically, and how
per-team namespaces work since v0.3.0
([ADR-0046](../adr/0046-who-may-claim-a-list-of-groups-and-a-namespace-to-groups-mapping.md),
accepted and released 2026-11-17). Nothing in [section 5](#5-groups-per-namespace-v030) works
on a broker before v0.3.0 (v0.2.10 or earlier). Do not put the new keys in the configuration of
such a broker: its issuer and `sandboxes` blocks ignore a key they do not know (only the
`audiences` entries reject one,
[ADR-0040](../adr/0040-the-gateway-places-an-audiences-credential-the-pool-never-holds-it.md)),
so on such a broker a `required_groups` would be silently dropped, and an issuer with no
`required_group` gates nothing. [Upgrading](#upgrading) says the order.

Placeholders throughout: `login.example.com` (the Dex login hub), `mediatore.example.com` (the
broker), `example-org:APP_EXAMPLE_ADMIN` (a group as the GitHub connector spells it),
`APP_EXAMPLE_TEAM_A_USER` (a group as LDAP and Entra spell it), `svc-example` (a service ID),
`team-a` (a tenant namespace).

## 1. Who may do what: five separate checks

A request to create a sandbox passes five independent checks. A tenant is only as isolated as the
weakest of them, so know which one you are configuring.

| Check | Where it lives | Decides | Configured by |
| --- | --- | --- | --- |
| Issuer gate | the broker, `issuers[].required_group` or `required_groups` ([`crates/mediatore-entra/src/lib.rs`](https://github.com/firestoned/mediatore/blob/main/crates/mediatore-entra/src/lib.rs)) | whether this login may use the broker at all | `mediatore.yaml` |
| Namespace groups (v0.3.0) | the broker, `sandboxes.namespaces` ([`crates/mediatore/src/config.rs`](https://github.com/firestoned/mediatore/blob/main/crates/mediatore/src/config.rs)) | in which namespace this login may create, read and delete sandboxes through the API | `mediatore.yaml` ([section 5](#5-groups-per-namespace-v030)) |
| Policy subjects | the signed bundle for the `policyRef`, read from the policy namespaces ([ADR-0026](../adr/0026-notaio-bundles-verified-in-shadow.md)) | which groups a policy is written for, and the audiences and egress it grants | the policy repository, by pull request |
| Claim subject | banlieue's admission policy `banlieue-virtualmachineclaim-subject-authorization` | that a `VirtualMachineClaim` names its own creator, except for listed brokers | ConfigMap `banlieue-claim-subject-policy` (`brokers`, `issuers`, `usernamePrefix`) |
| Kubernetes RBAC | the API server | who may create an `AgentSandbox` directly, in which namespace (the declarative path) | a RoleBinding per namespace, for example to a role that grants `create` and `delete` on `agentsandboxes` |

The first, the second (once `sandboxes.namespaces` is set) and the fourth are checked for every
API claim. The fifth is the only check on the
declarative path (a team applying an `AgentSandbox` with `kubectl`), together with the
`mediatore-agentsandbox-subject` admission policy, which limits a requester to the subject it is.

The policy's group list is compared in shadow today: a named policy reports conformance and
grants nothing the broker's own configuration does not ([the policy bundle](the-policy-bundle.md)).
The issuer gate is the enforcement point for who may claim.

## 2. The issuer gate

```yaml
issuers:
  - url: https://login.example.com
    backend: sts
    client_id: mediatore
    subject_claim: preferred_username
    required_group: example-org:APP_EXAMPLE_ADMIN
```

- **One value, or a list.** `required_group` is a single string. Since v0.3.0 an issuer may
  write `required_groups`, a list matched any-of, instead ([section 5](#5-groups-per-namespace-v030)).
- **Exact match.** The check compares it, case-sensitively, with each entry of the token's
  `groups` claim and its `roles` claim (or only `groups_claim`, when the issuer sets one).
  There is no prefix stripping, no glob and no regex.
- **No group, no claim.** A login without the group gets `403`: `not in a required group` since
  v0.3.0, `not in required group <value>` from v0.2.10 and earlier. Since v0.3.0 an issuer must
  write its gate: one with none of `required_group`, `required_groups` and
  `allow_any_authenticated: true` refuses to start. On v0.2.10 and earlier an unset
  `required_group` gates nothing (the issuers guide says when that is acceptable).
- **Fail closed in the sense that matters.** A token with no groups claim at all does not match a
  set `required_group`.

### The spelling problem

Dex names a group differently by connector, and the broker does not normalize:

| Connector | A team or group appears as |
| --- | --- |
| GitHub | `<org>:<team>`, for example `example-org:APP_EXAMPLE_ADMIN` |
| LDAP, Entra | the bare name, for example `APP_EXAMPLE_ADMIN` |

The two spellings never match each other. A service ID signs in through the LDAP connector, so it
carries the bare name and can never satisfy a `required_group` spelled `example-org:...`; a person
signing in through the GitHub connector can never satisfy a bare one. With one string you must
pick a spelling and accept that the other population is refused, which is why the single value is
a limit for any deployment that has both people and services.

Since v0.3.0, list both spellings in `required_groups` ([section 5](#5-groups-per-namespace-v030)).
On v0.2.10 and earlier, gate on the spelling your callers share: if every claimant arrives through
LDAP or Entra, use the bare name; if you need both populations, you cannot do it with one string.

## 3. A service that claims programmatically

A service ID has no browser. Dex's LDAP connector doubles as the password-grant connector
(`oauth2.passwordConnector: ldap`), so the service exchanges its ID and password for a token
directly. This is the OAuth2 resource-owner password grant, enabled only for that connector;
people should never use it (they sign in through Entra or GitHub).

```sh
# Read the password without echo and keep it out of shell history and argv listings.
read -s SVC_PASS
curl -s --cacert "$CA_BUNDLE" https://login.example.com/token \
  -d grant_type=password -d client_id=mediatore \
  -d scope="openid profile email groups offline_access" \
  -d username=svc-example --data-urlencode password="$SVC_PASS"
unset SVC_PASS
```

The response carries an `id_token` and, because of `offline_access`, a `refresh_token`.
`mediatore` is a public client at Dex, so no client secret is sent.

Then claim over the API with both, because an issuer that has a `session` block requires the
refresh token to be delegated with the claim ([ADR-0013](../adr/0013-dex-session-delegation.md)):

```sh
curl -s --cacert "$CA_BUNDLE" https://mediatore.example.com/v1/claims \
  -H "Authorization: Bearer $ID_TOKEN" \
  -d '{ "pool_ref": "agents", "ttl_seconds": 600,
        "refresh_token": "'"$REFRESH_TOKEN"'",
        "audiences": ["example-audience"],
        "workload": { "image": "registry.internal:5000/sandbox/agent:latest",
                      "args": ["/usr/bin/agent"] },
        "policy_ref": "agents" }'
```

Rules that follow from how the tokens behave:

- **One grant per claim.** Dex rotates refresh tokens (`refresh tokens rotation enabled`), and the
  broker keeps the one it was given. Run the password grant again for the next claim.
- **A delegated audience needs its own secret.** An audience served from the requester's own
  credential (for example a git host that wants a personal access token) takes it in the same
  request as a `delegations` entry. The LDAP password only covers the login at Dex.
- **Groups are the service's LDAP groups, filtered by Dex.** Dex's LDAP connector reads direct
  group membership only, and only groups matching its configured filter. A group the service is in
  through nesting, or one the filter excludes, is absent from the token and cannot satisfy any
  gate. Decode the `id_token` payload and read `groups` before you debug anything else.
- **Never put credentials in a URL.** Dex's authorization endpoint takes no username or password,
  and a query string lands in gateway and proxy logs and shell history. The token endpoint above is
  the supported route.
- **The declarative path cannot carry a secret.** A service that must supply a delegated
  credential claims through the API. One that needs none can apply an `AgentSandbox` directly,
  governed by Kubernetes RBAC in its namespace.

To check a token without printing it, print only the claims:

```sh
python3 -c 'import sys,json,base64;t=json.load(sys.stdin);p=t["id_token"].split(".")[1];c=json.loads(base64.urlsafe_b64decode(p+"="*(-len(p)%4)));print({k:c.get(k) for k in ("iss","aud","preferred_username","groups")})'
```

## 4. Onboarding a tenant namespace with one claim namespace

What works on any broker, with `sandboxes.namespace` naming one namespace (on v0.3.0, the API
path of [section 5](#5-groups-per-namespace-v030) comes on top of this):

1. **A namespace per team**, labelled the way the platform selects tenants.
2. **A pool the platform owns in that namespace.** The team gets read-only access to
   `virtualmachinepools`; the platform keeps the `VirtualMachinePool`. A pool and its sandboxes are
   same-namespace, and a pool schedules only onto `Provider` objects in its own namespace, so a
   tenant namespace needs its own `Provider` (banlieue ADR-0130 and ADR-0131). Copying the
   platform's Provider and its credential into a tenant namespace exposes the infrastructure
   credential to anyone who can read Secrets there; use a per-tenant, least-privilege account.
3. **Team RBAC for sandboxes only.** `create`, `get`, `list`, `watch` and `delete` on
   `agentsandboxes`, and read-only on `virtualmachinepools` and `virtualmachineclaims`. A team
   that can create a `VirtualMachineClaim` by hand takes a pool VM with no broker identity, no
   policy and no egress, so it should not be able to.
4. **Say where each namespace's policies are.** A sandbox names its policy by `policyRef`, and the
   broker looks the name up in the namespaces that sandbox's namespace draws from: its own alone,
   unless `policy.sources` lists others for it
   ([the policy bundle](the-policy-bundle.md#which-policies-a-namespace-may-name),
   [ADR-0054](../adr/0054-which-policies-a-namespace-may-name.md)). To keep `SandboxPolicy`,
   `ExposureCeiling` and the published bundles in one platform namespace, list that namespace under
   `policy.namespaces` and give each tenant namespace a `policy.sources` entry naming it. Under
   `policy.egress: enforce` every tenant that draws from a namespace may name every policy in it, so
   a tenant whose policies must not be used by another gets a policy namespace of its own. Teams
   change policy by pull request, never in the cluster.
5. **Create the sandbox in the team's namespace** with `kubectl apply`. With one claim namespace,
   `POST /v1/claims` and the CLI create sandboxes in `sandboxes.namespace` only.

What this setup does not do: an API claim into a team's own namespace, and a gate that depends on
the namespace. Both are v0.3.0's ([section 5](#5-groups-per-namespace-v030)); on v0.2.10 and
earlier this section is all there is.

## 5. Groups per namespace (v0.3.0)

This section describes
[ADR-0046](../adr/0046-who-may-claim-a-list-of-groups-and-a-namespace-to-groups-mapping.md)
(Accepted; released in v0.3.0, 2026-11-17). The keys below do not exist in a broker before
v0.3.0, and such a broker ignores them without a warning (see the note at the top).

The two limits above (one `required_group` string, one claim namespace) are the same problem seen
twice: the gate cannot say "this group may claim here". The decision:

- **`required_groups`**, a list with OR semantics, beside the existing `required_group`, which
  stays valid and means a list of one. A login passes if any entry matches exactly (case-sensitive,
  no prefix stripping), so one issuer admits both spellings of the same group by listing both.
  Both keys on one issuer, an empty list, a duplicate or a padded entry are refused at start. The
  `403` no longer names the group: `not in a required group`.
- **An issuer must write its gate.** Exactly one of `required_group`, `required_groups` or
  `allow_any_authenticated: true`. An issuer with none of the three refuses to start rather than
  gating nothing; `allow_any_authenticated: true` is v0.2.10's "no gate", written down, with a
  comment giving the reason (a Google issuer: who may log in is decided at Google).
- **A namespace-to-groups map**, `sandboxes.namespaces`. Each namespace lists the groups (any-of,
  exact) whose members may create, read and delete sandboxes in it. The operator's own admin group
  maps to the controller namespace (an `infra` namespace) and a team's group to the team's
  namespace. Each entry needs a non-empty `groups`; there is no open entry in a map.
- **No default namespace once the map is set.** `sandboxes.namespace` and `sandboxes.namespaces`
  are exclusive: writing both is a start error. A create that omits `namespace` is
  `400 namespace_required`, and so are `GET` and `DELETE` without `?namespace=`. A caller in several
  namespaces' groups always names one; the broker never picks. Without the map, everything is as
  before v0.3.0: one namespace, open to whoever passes the issuer gate.
- **The issuer gate and the namespace groups are two checks, and both must pass to create.** The
  namespace check only narrows what the issuer gate admitted; it never implies it. To make the map
  the only gate, set `allow_any_authenticated: true` on the issuer, knowing anyone the IdP
  authenticates can then log in (and can claim nowhere the map does not allow).
- **One refusal for "not listed" and "not qualified".** On create the `403` is byte-identical in
  both cases and names neither groups nor other namespaces. On `GET` and `DELETE`, a namespace that
  is not in the map, one the caller is not in the groups of, and a claim that is not there are all
  `404`.
- **Membership gates create, get and delete.** A person who leaves a namespace's group can no longer
  read or delete the sandbox they created through the broker; it runs to its TTL. The owner check
  (the claim's subject) still applies on top. Break-glass: a cluster administrator's
  `kubectl delete agentsandbox`, which the finalizer then releases.
- **No super-user namespace.** The operator's admin group maps to the admin namespace and gets no
  access to other tenants' sandboxes through the API.
- **Pool and policy stay same-namespace, and policy stays in one namespace.** A tenant namespace
  still needs its own pool and its own `Provider` ([section 4](#4-onboarding-a-tenant-namespace-with-one-claim-namespace)).
  The map does not widen `policy.namespaces`, and no per-tenant policy `Role` is added by it. Which
  policy namespaces a tenant's sandboxes draw from is `policy.sources`, its own namespace alone when
  nothing is written ([ADR-0054](../adr/0054-which-policies-a-namespace-may-name.md)); a build
  before that ADR looked in every listed policy namespace. **With the map set, an empty `policy.namespaces` is a start
  error** telling you to list the policy namespaces: it no longer defaults to the claims' namespace,
  because there is none. Without the map the old default stands.
- **The declarative path is not governed by the map.** A person with `create agentsandboxes` in a
  namespace holds a Kubernetes grant; the map is a control on the broker's front door only.
- **Unknown keys are refused across the whole config file.** A misspelled key (`group:` for
  `groups:`, a misspelled `sandboxes`) is a start error naming the key, in the issuer, `session`,
  `entra`, `sandboxes` and namespace-entry blocks and at the top level.

The shape, as a v0.3.0 broker takes it (not working configuration on v0.2.10 or earlier):

```yaml
# v0.3.0 and later (ADR-0046)
issuers:
  - url: https://login.example.com
    backend: sts
    client_id: mediatore
    subject_claim: preferred_username
    required_groups:                      # who may log in at all, any of
      - example-org:APP_EXAMPLE_ADMIN
      - APP_EXAMPLE_ADMIN
      - APP_EXAMPLE_TEAM_A_USER
sandboxes:
  # `namespace:` is not written here: with the map set it is a start error.
  namespaces:
    infra:  { groups: [example-org:APP_EXAMPLE_ADMIN, APP_EXAMPLE_ADMIN] }
    team-a: { groups: [APP_EXAMPLE_TEAM_A_USER] }
```

A request then names its namespace, for example `mediatore sandbox create --namespace team-a`.
A person in `APP_EXAMPLE_TEAM_A_USER` can create, read and delete their sandboxes in `team-a` and
nowhere else; a person in `APP_EXAMPLE_ADMIN` can do so in `infra`.

The trust boundary this moves is real: the broker becomes the enforcement point for where a person
may place a sandbox, and a mapping mistake grants cross-tenant claims, so review the map as a
security configuration. The ADR states the checks, the tests that prove them and the
threat-model entries. On a broker before v0.3.0, use sections 2 to 4, and do not rely on any
isolation between tenants beyond what Kubernetes RBAC and the pool's namespace give you.

### Upgrading

Two start-time refusals are breaking changes for every config, by design, from v0.3.0 (items 3
and 4 below apply only when you adopt the map):

1. **Unknown keys are refused.** A stray or misspelled key anywhere in `mediatore.yaml` (the issuer,
   `session`, `entra` and `sandboxes` blocks, and every other section and the top level) stops the
   broker from starting, with an error naming the key and the block. On v0.2.10 such a key is a
   silent no-op that may have been meant as a gate. Remove or fix it before upgrading.
2. **An issuer with no written gate is refused.** Every issuer needs exactly one of `required_group`,
   `required_groups` or `allow_any_authenticated: true`. An issuer that gates nothing on v0.2.10
   (a Google issuer, a test issuer) needs `allow_any_authenticated: true` added, a one-line edit
   the error message spells out. A config that already sets `required_group` is unchanged.

3. **Under a map, list the policy namespaces.** If the config has a `policy:` block with no
   `namespaces`, it used to read the claims' namespace. Once `sandboxes.namespaces` is set that
   default is gone and the broker refuses to start until `policy.namespaces` lists the namespaces
   whose bundles it reads.
4. **Claims from before the map are unreachable unless you list their namespace.** A claim created
   before the move answers `404` unless its old namespace (the former `sandboxes.namespace`) is an
   entry in the map.

The CLI's `mediatore sandbox delete --namespace <ns>` does a `GET` first, checks that the answer
comes from that namespace, and sends the `DELETE` only if it does: an older broker ignores
`?namespace=` and would otherwise delete in its default namespace. `sandbox get --namespace` runs
the same check on its answer.

**Order: the broker first, then the configuration.** Deploy v0.3.0 and confirm it started (its
log has one line per issuer naming the gate in force, and one for the namespaces) before adding
`required_groups`, `sandboxes.namespaces` or `--namespace`. Doing it the other way round, new keys
on an older broker, is the fail-open case: that broker drops the keys silently and an issuer with
no `required_group` gates nothing. To roll back to v0.2.10, remove the new keys first. v0.3.0 is
the floor.

## 6. Which audiences a namespace may use (ADR-0053)

Section 5 decides where a person may claim. This decides what a claim in that namespace may reach. By
default an audience is usable from every namespace with its `rules`. Scope it with `namespaces`, each
entry giving that namespace's rules (its **grant**), under the audience's own `rules`, which is then the
platform's **ceiling**:

```yaml
audiences:
  - name: artifactory
    via: delegated
    credential: basic
    inject: gateway
    max_ttl: 300
    egress: ["artifactory.example.com:443"]
    rules:                                   # the ceiling: no namespace may be granted more than this
      - {method: GET,  path: "/artifactory/api/docker/**"}
      - {method: HEAD, path: "/artifactory/api/docker/**"}
    namespaces:
      team-a:
        rules:                               # team-a's grant
          - {method: GET,  path: "/artifactory/api/docker/app-team-a-docker/v2/**"}
          - {method: HEAD, path: "/artifactory/api/docker/app-team-a-docker/v2/**"}
      team-b:
        rules:
          - {method: GET,  path: "/artifactory/api/docker/app-team-b-docker/v2/**"}
```

- A namespace not listed cannot claim the audience. Asking for it is `400 unknown_audience`, the same
  answer as an audience that does not exist, so the response says nothing about what exists elsewhere.
- The host, credential kind, lifetime and CA are the audience's and are written once.
- A grant the ceiling does not cover, an empty grant, a namespace key that is not a namespace you let anyone
  claim in (section 5), or two audiences on one host without disjoint namespaces, stops the broker at start with
  a message naming the audience and the namespace. Without a top-level `rules` there is no ceiling.
- An audience with no `namespaces` stays open to every namespace. With the namespace map set, the broker logs
  each such audience by name at start (`audience unscoped`).
- The configuration is read at start, so adding or removing a namespace is a rollout, and a bound claim loses a
  removed audience at its next token or gateway ask.
- **Grants from the policy bundle.** With `policy.audiences: enforce` the per-namespace grants come from the verified
  `SandboxPolicy` bundle the claim names instead (phase 2 of ADR-0053, see [the policy bundle](the-policy-bundle.md)): the platform
  writes a policy per tenant namespace, the tenant can read it and cannot change it, and nothing restarts. The audience's own
  `rules` stay as the ceiling, and a `namespaces` entry, if you keep one, intersects with the bundle.

## 7. Checking an access decision

- **The token.** Decode `groups` as above and compare it, character for character, with the gate.
- **The broker's answer.** A `403` with `not in a required group` (`not in required group ...`
  from v0.2.10 and earlier) is the issuer gate. A
  `delegation_refused` or `session_required` is the claim body or the login, not the gate.
- **banlieue's side.** A claim stuck `Pending` with `sandbox reconcile failed` in the broker log
  carries the admission policy's own message. Reproduce it without creating anything: a
  server-side dry-run as the broker's ServiceAccount shows which check fails.
  ```sh
  kubectl --as=system:serviceaccount:banlieue-system:mediatore create --dry-run=server -f claim.yaml
  ```
- **Kubernetes RBAC.** `kubectl auth can-i create agentsandboxes -n team-a --as <user>` tells you
  whether a declarative requester may apply one there.
