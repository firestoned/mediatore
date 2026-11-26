<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Design

How mediatore is built, part by part. The other sections answer different questions:

| Section | Answers |
| --- | --- |
| [ADRs](../adr/0001-record-architecture-decisions.md) | *Why* a decision was taken, and what was rejected |
| [Guides](../guides/running-workloads.md) | *How* to run, deploy and use it |
| [Architecture](../architecture/diagrams/system.md) | *What* the components and flows are, as a model (CALM) |
| [Threat model](../security/threat-model.md) | *What can go wrong* at each trust boundary, and what stops it |
| **Design** (this section) | *How the code is organised*: what each part owns, how a request moves through it, and the rules it keeps |

Every page names the crate and the files it describes, so the code is one click from the explanation, and
links the ADRs that decided it and the threat-model boundary that covers it. Where something is built and not
yet proven on a live cluster, the page says so.

## The parts

| Page | Part | Where in the code |
| --- | --- | --- |
| [Broker API](broker-api.md) | The HTTP surface: the user API (bearer) and the sandbox API (SPIFFE mTLS) | `crates/mediatore-api` |
| [Claims and reconcilers](claims-and-reconcilers.md) | The `AgentSandbox` request, the claim watcher, the Lease, node collection | `crates/mediatore-claims` |
| [The store and the sealing](store-and-sealing.md) | Where claim records and sealed secrets live, and how long | `crates/mediatore-store`, `crates/mediatore-claims/src/kubestore.rs`, `crates/mediatore-openbao` |
| [Identity and mTLS](identity-and-mtls.md) | SPIFFE IDs, registration entries, the mutual TLS between parts | `crates/mediatore-spire`, `crates/mediatore-tls` |
| [Issuers and audiences](issuers-and-audiences.md) | Validating a login, the token backends, how a credential is placed | `crates/mediatore-entra`, `crates/mediatore-sts`, `crates/mediatore/src/config.rs` |
| [Policy](policy.md) | notaio's signed bundles, the version floor, shadow and enforce | `crates/mediatore-policy`, `crates/mediatore-claims/src/{policy,shadow}.rs` |
| [Who may use a policy: overview](policy-subjects-overview.md) | Proposal, plain language: why a policy's groups should be checked | not built |
| [Who may use a policy: design](policy-subjects.md) | Proposal: carrying `subjects.groups` in the signed bundle and checking it | not built; notaio `crates/sandboxpolicy-bundle`, `crates/mediatore-api` |
| [The guest](guest.md) | What runs on a pool VM: the lifecycle of a claim from the inside | `crates/mediatore-guest` |
| [The egress proxy](egress-proxy.md) | The jail's only way out, and how it places a credential | `crates/mediatore-guest/src/{egress,forward}.rs` |
| [The gateway](gateway.md) | The authorizer and the three Envoys on each gateway VM | `crates/mediatore-gateway`, `image/gateway/` |
| [The CLI](client-cli.md) | `login`, `sandbox`, and how a person's credential is read | `crates/mediatore-client` |
| [Configuration](configuration.md) | The broker's configuration file, section by section | `crates/mediatore/src/config.rs` |
| [Testing and fakes](testing-and-fakes.md) | The test kit, the store conformance suite, what each tier proves | `crates/mediatore-testkit`, `crates/mediatore/tests/` |

The wire types every part shares live in `crates/mediatore-proto` (the claim request, the routes, the token and
credential shapes, the registry reference). They are versioned together: a breaking change is a new API version.

## One binary, many roles

mediatore ships as one static binary and every part above is a subcommand of it (ADR-0014), so the VM image pins
one file and the node's registration entry selects on its path.

| Subcommand | Runs where | Part |
| --- | --- | --- |
| `serve` | the management cluster | the broker: both APIs, the watcher, the store |
| `guest` | each pool VM, as root | [the guest](guest.md) |
| `egress-proxy` | each claimed VM, as the sandbox user, outside the jail | [the egress proxy](egress-proxy.md) |
| `jail-exec` | inside the jail, before the workload | Landlock, then the workload (ADR-0024) |
| `token` | where a Workload API socket and a broker route exist (not inside the jail since ADR-0025) | trade the claim identity for a token; the egress proxy does this for the workload |
| `gateway` | each gateway VM | [the authorizer](gateway.md) |
| `login`, `logout`, `sandbox`, `session` | the person's machine | [the CLI](client-cli.md) |
| `revoke` | an operator | revoke a claim at once (an admin stub) |

## A claim, from login to release

The path through the parts, in order. Each step links to the page that owns it.

1. **Login.** The person logs in at the issuer through the CLI (PKCE, loopback redirect) and keeps an ID token and a
   refresh token in a session file. ([CLI](client-cli.md))
2. **Request.** `POST /v1/claims` with the ID token as the bearer. The body names the pool, the TTL, the audiences, the
   workload, an optional policy, the delegated session, and any credentials the person delegates for an audience. The
   broker validates the token, checks the body against its configuration, seals every secret with OpenBao transit and
   creates an `AgentSandbox` whose subject is the token's. ([Broker API](broker-api.md),
   [Store and sealing](store-and-sealing.md))
3. **Reconcile.** The `AgentSandbox` reconciler refuses what the configuration cannot serve (an unknown audience, an
   unreachable registry, an image on a gateway-placed registry whose audience is not named), then creates one
   banlieue `VirtualMachineClaim` and a store record. ([Claims](claims-and-reconcilers.md))
4. **Bind.** banlieue binds a pool VM to the claim. The watcher resolves the VM's node by the endorsement-key hash,
   declares the claim's registration entry as a `ClusterStaticEntry`, and records it. ([Identity](identity-and-mtls.md))
5. **Start.** On the VM the guest learns it is bound (`GET /v1/me`), creates the per-claim Linux user, mounts a
   tmpfs, pulls the workload image, loads the claim's firewall rules, starts the egress proxy and then the jail.
   ([Guest](guest.md))
6. **Run.** The workload holds only a phantom token. Its requests go to the egress proxy, which swaps in a real token
   from the broker, tunnels through a gateway, or sends the request to a gateway that places the credential itself.
   ([Egress proxy](egress-proxy.md), [Gateway](gateway.md), [Issuers and audiences](issuers-and-audiences.md))
7. **End.** The TTL, a delete, or the workload's own exit under its restart policy ends the claim. The
   entry is retracted, the record is revoked, the sealed envelopes are deleted, and the guest tears the VM's
   state down. ([Claims](claims-and-reconcilers.md), [Store and sealing](store-and-sealing.md))

## Rules every part keeps

These are enforced by tests, not just stated; the pages say which.

- **Fail closed.** A path that is not implemented returns an error (`501 not_implemented`), never a permissive
  default. A refusal is a refusal, not a retry with less.
- **`dev_mode` is for local runs.** Anything that reads the peer identity from a header is gated on it.
- **Never log a secret.** Tokens, refresh material, passwords and keys are never logged; the logs name claim UIDs,
  SPIFFE IDs, audiences and subjects. Secret-carrying types print `[redacted]`.
- **A fake is no more permissive than the real thing.** `MemoryStore`, the in-memory entries and the test CA behave as
  the production ones do; the conformance suite pins what `MemoryStore` must share with `KubeStore`, which the kind
  tiers prove on a real API server.
- **The pool VM and the sandbox never see a person's secret.** A credential for an audience that opts in is placed at
  the gateway (ADR-0040, ADR-0041, ADR-0043), and no secret is stored longer than its claim's TTL.
- **One decision, one record.** A change to a trust boundary, a token shape, the SPIFFE ID scheme or the storage
  contract starts with an ADR, then the CALM model, then a failing test, then the code, then these pages and the
  threat model (`.claude/rules/architecture-driven-development.md`).
