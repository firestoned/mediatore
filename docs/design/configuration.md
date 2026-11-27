<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Configuration

The broker is configured by one YAML file, read at start (`crates/mediatore/src/config.rs`, `Config::load`). Its path is
`--config` or `MEDIATORE_CONFIG`. A file that fails any rule below stops the process before it listens: a
misconfiguration is refused, not served. The guide [Deploying](../guides/deploying.md) shows a whole deployment; this
page is the reference for what each section means and where it is read.

Every value in the example is a placeholder.

## The sections

| Section | Fields | Read by |
| --- | --- | --- |
| `trust_domain` | the SPIFFE trust domain of the deployment | the identity scheme, the mTLS verifiers ([Identity and mTLS](identity-and-mtls.md)) |
| `listen` | `user`, `sandbox`: the two listener addresses | [Broker API](broker-api.md) |
| `spire` | `workload_api_socket`; `entries.class_name` (the SPIRE Controller Manager's class) | [Identity and mTLS](identity-and-mtls.md) |
| `issuers[]` | `url`, `backend`, `client_id`, `subject_claim`, `required_group`, `required_groups`, `allow_any_authenticated`, `groups_claim`, `session`, `entra`, `ca_file`, `subject_prefix` | [Issuers and audiences](issuers-and-audiences.md) |
| `audiences[]` | `name`, `via`, `max_ttl`, `egress`, `rules`, `ca_file`, `secret_file`, `secret_header`, `secret_extra_headers`, `header`, `extra_headers`, `refresh`, `inject`, `credential`, `traps_body` (`match`, the default, or `skip`: ADR-0069) | [Issuers and audiences](issuers-and-audiences.md) |
| `sts` | `issuer`, `kid`, `signing_key_file` | the token service |
| `registries[]` | `host`, `username`, `password_file`, `reach` (`segment` or `relay`) | the pull ([The guest](guest.md)) |
| `gateways`, `gateway_inject_port` | each gateway's sandbox address and data-plane port; the inject listener's own port | [The gateway](gateway.md), [Broker API](broker-api.md) |
| `sandboxes` | `namespace`: where `POST /v1/claims` creates `AgentSandbox` resources; or `namespaces`: a map from a namespace to the groups whose members may claim there, and the issuers those groups are read from (the two are exclusive); `max_ttl_seconds`: the longest lifetime a claim may ask for (default `86400`, one day; positive); `declarative_issuers`: the issuers an `AgentSandbox` created through the Kubernetes API may name (default the one issuer, or none with two or more) | [Claims and reconcilers](claims-and-reconcilers.md) |
| `watcher` | `resync_secs`, `resolve_timeout_secs`, `lease_duration_secs`; `x509pop_pools`: the pools, each as `<namespace>/<pool>`, whose machines attest with `x509pop` and never with a TPM (ADR-0049 decision 9; empty by default, every machine is `tpm`; an entry of another shape, or one listed twice, is a start error); `provider_namespace`: where a machine's `Provider` is read when the machine's own namespace holds none (decision 10; unset by default, read only for the machines of `x509pop_pools`). With `x509pop_pools` set, the Providers of every namespace are listed once per pass, two of them asserting different host CAs under one common name give neither's machines an entry, and every `Bound` claim is resolved through the machine its `status.virtualMachineRef` names; with it empty no machine and no Provider is read for a claim. The files of the SPIRE server's host CA bundle are checked with `mediatore x509pop-bundle check <file>...`, a subcommand of the same binary that needs no configuration | [Claims and reconcilers](claims-and-reconcilers.md), [the deploying guide](../guides/deploying.md#pools-whose-guests-have-no-vtpm-x509pop-adr-0049) |
| `store` | `retention_secs` (at 900 or less the `no_record` class of ADR-0070 is not judged), `node_grace_secs`, `sealing` (`key_file` or `transit`) | [The store and the sealing](store-and-sealing.md) |
| `token` | `rate_per_minute`: the per-claim limit on `POST /v1/token` | [Broker API](broker-api.md) |
| `logs` | `enabled` (default `false`), `max_bytes` (the newest output kept per claim, 64 KiB to 4 MiB, default 1 MiB), `retention_secs` (default `store.retention_secs`): the workload output ring of ADR-0045, written only for a sandbox that opted in with `workload.logs` | [The store and the sealing](store-and-sealing.md), [the store guide](../guides/the-store.md#workload-output) |
| `policy` | `trusted_keys[]`, `namespaces[]`, `egress` (`shadow` or `enforce`); `traps` (`off`, the default, `shadow` or `enforce`) and `traps_denied` (`loopback_port`, `private_range`, `unknown_host`, each `report`, the default, or `trip`): tripwires on the VM, ADR-0069 | [Policy](policy.md), [Tripwires](../guides/tripwires.md) |
| `tripwires` | the twelve classes of ADR-0070 (`identity_shape`, `foreign_route`, `unknown_route`, `no_record`, `audience_outside_rendered`, `claim_never_issued`, `credential_outside_inject`, `deny_outside_rendered`, `gateway_port`, `gateway_output`, `pool_inbound`, `pool_output`), each `report` (the default) or `trip`; only `foreign_route`, `unknown_route` and `audience_outside_rendered` may be `trip` (`deny_outside_rendered` records only: the claim it names is the authorizer's word) | [Tripwires](../guides/tripwires.md#past-the-jail-the-twelve-classes-of-adr-0070) |
| `dev_mode` | `true` for a local run only | everywhere a peer identity could be read from a header |

## An example

```yaml
trust_domain: sandbox.home.example
listen: { user: 0.0.0.0:8080, sandbox: 0.0.0.0:8443 }
spire:
  workload_api_socket: unix:///run/spire/sockets/agent.sock
  entries:
    class_name: spire-server-spire

issuers:
  - url: https://login.home.example
    backend: sts
    client_id: mediatore
    subject_claim: preferred_username
    required_group: org:sandbox-users
    ca_file: /etc/mediatore-ca/root.pem
    session: { client_id: mediatore }       # claims from this issuer delegate a refresh token

# The pool and the gateways. With `gateways` set, `registries[]` is refused: a registry is an
# audience of `role: registry` the claim names, pulled through its proxy and a gateway (ADR-0063).
gateways: ["192.0.2.10:8443", "192.0.2.11:8443", "192.0.2.12:8443"]
gateway_inject_port: 3133

audiences:
  # The registry the pool pulls from: read-only rules, its routes the puller's alone.
  - name: mirror
    via: none
    role: registry
    egress: ["mirror.example.com:443"]
    rules:
      - { method: GET, path: "/v2/**" }
      - { method: HEAD, path: "/v2/**" }
  # A person's own user name and token, placed by the gateway as Authorization: Basic.
  - name: gitserver
    via: delegated
    credential: basic
    inject: gateway
    max_ttl: 300
    egress: ["git.home.example:443"]
    rules:
      - { method: GET, path: "/*/*/info/refs" }
      - { method: POST, path: "/*/*/git-upload-pack" }

sandboxes: { namespace: sandboxes }       # or the `namespaces` map, below
store:
  retention_secs: 3600
  sealing:
    transit:
      url: https://openbao.home.example
      ca_file: /etc/mediatore-ca/root.pem
      mount: transit
      key: mediatore-seal
      role: mediatore
      auth_mount: kubernetes
policy:
  trusted_keys:
    - { id: "notaio:v1", public_key: "<base64 of a 32-byte Ed25519 public key>" }
  namespaces: [sandboxes]
  egress: shadow
logs:                                     # ADR-0045; off unless enabled
  enabled: true
  max_bytes: 1048576
```

## Who may claim where

An issuer states its login gate and the `sandboxes` section states where a person may create a sandbox
([ADR-0046](../adr/0046-who-may-claim-a-list-of-groups-and-a-namespace-to-groups-mapping.md)).

```yaml
issuers:
  - url: https://dex.home.example
    backend: sts
    client_id: mediatore
    subject_claim: preferred_username
    # Exactly one of required_group, required_groups, allow_any_authenticated: true.
    # Any-of, exact and case-sensitive: list both spellings of a group when both are wanted.
    required_groups: ["example-org:APP_EXAMPLE_ADMIN", APP_EXAMPLE_ADMIN, APP_EXAMPLE_TEAM_A_USER]

sandboxes:
  # `namespace:` is not written with the map: there is no default namespace.
  namespaces:
    infra:
      groups: ["example-org:APP_EXAMPLE_ADMIN", APP_EXAMPLE_ADMIN]
    team-a:
      groups: [APP_EXAMPLE_TEAM_A_USER]
```

- `required_groups` admits a token that carries at least one listed value. `required_group: X` is the alias for
  `required_groups: [X]`. `allow_any_authenticated: true` is the written-down "no group gate"; `false` counts as absent.
  An issuer with none of the three, or with more than one, does not start.
- `sandboxes.namespaces` maps a namespace (an RFC 1123 label) to `groups`, a non-empty list of exact values with no
  empty or whitespace-padded entry and no repeat inside one entry. The same group may appear under several namespaces.
  An entry takes `groups` and `issuers`; a typo such as `group:` is a start error.
- `issuers` on an entry lists the `issuers[].url` values whose tokens its groups are read from
  ([ADR-0074](../adr/0074-a-namespaces-groups-read-only-from-the-issuers-it-names.md)): a token of another issuer does not
  qualify, whatever its groups, and gets the answer of a caller without the group. With two or more issuers every entry
  writes it; with one it is optional and read as that issuer.
- `sandboxes.declarative_issuers` lists the issuers an `AgentSandbox` created through the Kubernetes API, not by
  `POST /v1/claims`, may name in `spec.subject.issuer`
  ([ADR-0072](../adr/0072-a-hand-created-sandbox-names-only-an-issuer-its-creator-can-come-from.md)). Not written, it is the
  one issuer when there is one and none when there are two or more, so adding a second issuer closes that path until it
  is written; `[]` closes it. A sandbox the broker created carries the annotation `mediatore.io/front-door: api`, which
  the admission policy reserves to the broker, and is not asked. Where the list leaves an issuer out, the broker proves
  at start that the policy guards the annotation (a dry-run create it must refuse) and does not start otherwise.
- With the map set, a request must name its namespace (`namespace` in the body, `?namespace=` on `GET` and `DELETE`);
  omitted is `400 namespace_required`. A namespace outside the map, or one the caller holds no listed group for, is `403`
  on create and `404` on get and delete, with one message that names neither the groups nor the other namespaces.
  The issuer's gate still applies first: the namespace groups only narrow it.
- Without the map, `sandboxes.namespace` (default `sandboxes`) is the one namespace, open to every caller who passed
  the issuer gate, exactly as before.
- Under a map, list `policy.namespaces` explicitly when a `policy` section is present: there is no default namespace to
  fall back to, and the map does not widen it.
- `sandboxes.max_ttl_seconds` (default `86400`) is the longest lifetime a claim may ask for, with either form of the
  namespaces and with or without a policy: above it `POST /v1/claims` answers `400 ttl_exceeds_maximum` and a declarative
  `AgentSandbox` is `Failed` before any claim exists. A policy's lease only narrows it. Zero or a value that is not a
  number of seconds is a start error. The default is the gateways' `TUNNEL_MAX_SECS` default, and the two are raised
  together. It is read when a claim is created: lowering it leaves the claims already bound to run to their TTL
  ([ADR-0008](../adr/0008-agentsandbox-crd-owned-by-mediatore.md) decision 9, amended 2026-11-26).

## What is refused at start

These rules live in `Config::parse` and the section types, so a bad file never reaches a listener:

- an audience that uses the `sts` backend with no `sts` section;
- an issuer that requires a session (`session`) with no sealing configured (`store.sealing.key_file` **or**
  `store.sealing.transit`, not both, and a transit `url` must be `https` outside `dev_mode`);
- `inject: gateway` on an audience with no `gateways` and `gateway_inject_port`, no `egress` or `rules`, an IP-literal
  host, a `max_ttl` above 300, a gateway whose data-plane port is the inject port, or no credential to place;
- `credential: basic` on an audience that is not `via: delegated`, `inject: gateway`, header `authorization` and without a
  `refresh`;
- with `gateways` set, a registry with no `reach`, or one listed twice (Docker Hub and its API host are one host);
- an issuer with no gate (`required_group`, `required_groups` or `allow_any_authenticated: true`), with more than one,
  or with an empty or padded `required_groups` list;
- `sandboxes.namespaces` empty, with a key that is not an RFC 1123 label, a duplicate key, an entry with no, empty,
  padded or repeated `groups`, or written together with `sandboxes.namespace`; and, outside `dev_mode`, a map on a broker
  with no Kubernetes front;
- with two or more issuers, a namespace entry without `issuers`; on any entry an empty `issuers`, a value that is not an
  `issuers[].url` byte for byte, or one listed twice (ADR-0074);
- a `sandboxes.declarative_issuers` value that is not an `issuers[].url` byte for byte, or one listed twice (ADR-0072);
- a key the file spells wrongly at any level of `Config` and its sections, the top level included
  (`deny_unknown_fields`): a misspelt `sandboxes` is not silently the default;
- an audience field the file spells wrongly (`deny_unknown_fields`): a misspelt `inject` must not fall back to the default;
- a value of `policy.traps` other than `off`, `shadow` and `enforce`, an unknown class or value in `policy.traps_denied` or
  `tripwires`, and `policy.traps: enforce` under `policy.audience_definitions.mode: bundles`, where no audience can be
  marked `traps_body: skip` (ADR-0069 decision 5);
- `trip` on a class of `tripwires` that records only: the four `segment` classes, the authorizer's two
  (`claim_never_issued`, `credential_outside_inject`), `deny_outside_rendered` (a claim named on the authorizer's word)
  and the two scoped to nothing (`identity_shape`, `no_record`), refused as `tripwires.<class>: trip is refused, this
  class records only: ...` (ADR-0070 decisions 3, 5 and 6, as amended).

`store.retention_secs` is not refused at any value. At 900 seconds or less (the claim SVID's longest lifetime) the
`no_record` class is not judged, since an honest claim released a moment ago would read as one, and the start log says
so. `policy.traps` needs the `policy` section, and so `trusted_keys`: a deployment with no signed policy cannot turn
tripwires on the VM on.

A broker that starts logs what it understood: each issuer's gate form (`required_groups`, `required_group` or
`none (explicit)`) with its group values, `single open namespace <ns>` or `map of <n> namespaces` with each namespace's
group values (configuration, never a token), the sealing mode, the egress mode, each issuer's CA, each audience served
and how, and the tripwires mode with one line per class set to `trip`. Read it off the log instead of inferring it from the start succeeding, and run **one claim** after any change
to the file, since a clean start does not show that a claim can be served (a `gateways` list with no audience of
`role: registry` starts cleanly and then refuses every claim, `registry_not_granted`).

## Rules this part keeps

- A secret is a path to a file or a reference to OpenBao, never a value in the YAML.
- A file that is wrong stops the process; nothing falls back to a permissive default.
- The configuration is read at start: changing the file means restarting the broker. A changed `ConfigMap` alone does not
  reach the running pods.

## Read next

ADR-0015 (the transit sealer), ADR-0017 (issuer profiles), ADR-0029 (registries on a routeless segment), ADR-0030 (the
egress mode), ADR-0040, ADR-0041 and ADR-0043 (placed audiences), ADR-0069 and ADR-0070 (tripwires). Guides:
[Deploying](../guides/deploying.md), [Tripwires](../guides/tripwires.md).
