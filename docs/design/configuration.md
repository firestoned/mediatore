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
| `issuers[]` | `url`, `backend`, `client_id`, `subject_claim`, `required_group`, `groups_claim`, `session`, `entra`, `ca_file` | [Issuers and audiences](issuers-and-audiences.md) |
| `audiences[]` | `name`, `via`, `max_ttl`, `egress`, `rules`, `ca_file`, `secret_file`, `secret_header`, `secret_extra_headers`, `header`, `extra_headers`, `refresh`, `inject`, `credential` | [Issuers and audiences](issuers-and-audiences.md) |
| `sts` | `issuer`, `kid`, `signing_key_file` | the token service |
| `registries[]` | `host`, `username`, `password_file`, `reach` (`segment` or `relay`) | the pull ([The guest](guest.md)) |
| `gateways`, `gateway_inject_port` | each gateway's sandbox address and data-plane port; the inject listener's own port | [The gateway](gateway.md), [Broker API](broker-api.md) |
| `sandboxes` | `namespace`: where `POST /v1/claims` creates `AgentSandbox` resources | [Claims and reconcilers](claims-and-reconcilers.md) |
| `watcher` | `resync_secs`, `resolve_timeout_secs`, `lease_duration_secs` | [Claims and reconcilers](claims-and-reconcilers.md) |
| `store` | `retention_secs`, `node_grace_secs`, `sealing` (`key_file` or `transit`) | [The store and the sealing](store-and-sealing.md) |
| `token` | `rate_per_minute`: the per-claim limit on `POST /v1/token` | [Broker API](broker-api.md) |
| `policy` | `trusted_keys[]`, `namespaces[]`, `egress` (`shadow` or `enforce`) | [Policy](policy.md) |
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

# The pool and the gateways. With `gateways` set, every registry needs a `reach`.
gateways: ["192.0.2.10:3128", "192.0.2.11:3128", "192.0.2.12:3128"]
gateway_inject_port: 3133
registries:
  - { host: mirror.example.com, reach: relay }

audiences:
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

sandboxes: { namespace: sandboxes }
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
```

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
- an audience field the file spells wrongly (`deny_unknown_fields`): a misspelt `inject` must not fall back to the default.

A broker that starts logs what it understood: the sealing mode, the egress mode, each issuer's CA, each audience served
and how. Read it off the log instead of inferring it from the start succeeding, and run **one claim** after any change
to the file, since a clean start does not show that a claim can be served (a `gateways` list without `registries[].reach`
starts cleanly and then refuses every claim whose image is on a registry).

## Rules this part keeps

- A secret is a path to a file or a reference to OpenBao, never a value in the YAML.
- A file that is wrong stops the process; nothing falls back to a permissive default.
- The configuration is read at start: changing the file means restarting the broker. A changed `ConfigMap` alone does not
  reach the running pods.

## Read next

ADR-0015 (the transit sealer), ADR-0017 (issuer profiles), ADR-0029 (registries on a routeless segment), ADR-0030 (the
egress mode), ADR-0040, ADR-0041 and ADR-0043 (placed audiences). Guide: [Deploying](../guides/deploying.md).
