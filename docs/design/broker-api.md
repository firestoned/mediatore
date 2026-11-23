<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Broker API

The broker's HTTP surface, in `crates/mediatore-api/src/lib.rs`. It is two routers served on two listeners, and
which one a caller reaches decides how it proves who it is.

| Router | Listener (reference deployment) | The caller is proven by | Callers |
| --- | --- | --- | --- |
| `user_router` | `listen.user`, port 8080, plain HTTP behind the ingress | an upstream **bearer token** | people and their tools, and programmatic requesters |
| `sandbox_router` | `listen.sandbox`, port 8443, SPIFFE mutual TLS | the **peer's SPIFFE ID**, taken from the verified client certificate | pool VMs, claimed VMs, and the gateways |

The user listener carries no TLS of its own: the ingress ends TLS and forwards plain HTTP, so a claim body is
plaintext for one hop on the cluster network. That is an accepted risk (threat model R-32). The sandbox listener
never sits behind a TLS-ending proxy: it is exposed as a TLS passthrough so the client certificate survives.

## Routes

**User API** (`user_router`)

| Route | Does |
| --- | --- |
| `GET /healthz` | liveness |
| `GET /.well-known/jwks.json` | the STS's public keys, when the STS backend is configured |
| `POST /v1/claims` | request a sandbox (below) |
| `GET /v1/claims/{name}` | the sandbox's status, mirrored from its `AgentSandbox`; only its subject may read it, in a namespace the caller's groups admit (`?namespace=`, ADR-0046: a namespace they do not admit answers `404`, the same as no such sandbox) |
| `DELETE /v1/claims/{name}` | delete the `AgentSandbox` (`?namespace=` as for `GET`); the reconciler's finalizer does the rest |
| `GET /v1/claims/{name}/logs` | the workload's output, for a sandbox created with `workload.logs: true` (ADR-0045): NDJSON, a header, the records and gaps in sequence (a record marked `partial` is a piece of a line that continues in the next record of its stream), an end line; a follower is sent a batch when it is stored, and reads at least every two seconds; `?follow=`, `?since=`, `?tail=`, `?namespace=` as for `GET`; the same subject and namespace checks; `501` unless the broker's `logs.enabled` |

**Sandbox API** (`sandbox_router`)

| Route | Called by | Does |
| --- | --- | --- |
| `GET /healthz` | anyone on the listener | liveness |
| `POST /v1/nodes` | a pool VM | register the node: its EK hash and DMI UUID |
| `GET /v1/me` | the guest, as the node | the claim bound to that node: workload, routes, gateways, registry credential. The guest writes the routes to files for the egress proxy, which then needs no route of its own to read them |
| `POST /v1/me/report` | the guest | what the VM found: the image digest, the ruleset's hash, the host table |
| `POST /v1/me/exit` | the guest | the workload ended under its restart policy; the broker releases the claim |
| `POST /v1/me/logs` | the guest, as the node | a batch of the workload's redacted output for a claim that opted in (ADR-0045): `204`, or `400` (malformed, or the claim did not opt in), `413`, `429` with `Retry-After: 1`, `501` unless `logs.enabled`; a node with no live claim is `204` and the batch dropped |
| `POST /v1/token` | the egress proxy, as the claim | a token for one audience (below) |
| `GET /v1/gateway/claims/{uid}` | a gateway only | what a claim may reach (the allowlist for tunnels) |
| `POST /v1/gateway/claims/{uid}/credential` | a gateway only | the credential for a gateway-placed audience (ADR-0040) |

The two gateway routes answer only the gateway identity, `spiffe://<td>/gateway`; any other peer, a node or a claim
included, is refused.

## Who is the peer

On the sandbox listener `mediatore-tls` verifies the client certificate and attaches a `PeerSpiffeId` request
extension; the handlers read the identity from that and from nothing the client sent. Only a server started with
`dev_mode`, on a plain loopback listener, reads it from the `x-mediatore-peer-spiffe-id` header instead. A route that
needs a claim identity checks the SPIFFE ID's shape (`/banlieue/claim/<uid>`), and a route that needs a node checks
`/banlieue/node/<ek-hash>`. See [Identity and mTLS](identity-and-mtls.md).

## `POST /v1/claims`: what a request goes through

`create_claim` checks in this order, each failure a stable error code and nothing created:

1. **The bearer.** Validated against the configured issuers: signature through the JWKS, expiry, audience, and the
   issuer's authorisation gate (one of `required_groups`, any of; `required_group`, its alias; or an explicit
   `allow_any_authenticated`). See [Issuers and audiences](issuers-and-audiences.md).
2. **The namespace** (`resolve_create`, ADR-0046). With a namespace map, the body must name one (`400
   namespace_required`) that the token's groups admit (`403`); with a single namespace every caller past the gate
   claims there. Nothing is parked for a refusal.
3. **`invalid_pool`.** Exactly one of `pool_ref` and `pool_selector` (ADR-0044); neither is never read as "any pool".
   `selection.strategy`, when present, is one of banlieue's `LongestReady`, `MostAvailable` and `Spread` or the body does
   not parse (`422`, ADR-0047); absent stays absent on the sandbox and the claim.
4. **`unknown_audience`.** Every audience the body names must be one the broker is configured to serve.
5. **`invalid_workload_image`**, then **`registry_not_granted`.** The image must parse, and in an environment with
   gateways its registry must be served by one of the claim's own audiences of `role: registry` (ADR-0063); the
   sentence names no other registry.
6. **The session** (`session_for`). An issuer configured with a `session` requires the refresh token in the body
   (`session_required`); any other issuer refuses one (`session_unexpected`); an Entra issuer exchanges the caller's
   token On-Behalf-Of here (`session_refused` when Entra says no, `audience_needs_entra` for an audience Entra alone
   serves).
7. **The delegations** (`delegations_for`). A `delegated` audience needs exactly one delegation with a token
   (`delegation_required`); an audience that is not `delegated` takes none (`delegation_refused`); a `credential:
   basic` secret must be `user:secret` with no control character; a credential the caller says dies before the
   claim's TTL is refused (`delegation_expires_first`); a pending one (the envelope sealed on the caller's machine)
   is not served yet (`501`).
8. **Sealing must be configured** when there is anything to seal; otherwise `501 sealing`, never a plaintext store.
9. **`invalid_ttl`** for a TTL of zero.

Then, outside `dev_mode`, `create_sandbox` creates the `AgentSandbox` with the token's subject (the broker's
`ServiceAccount` is exempt from the subject admission policy for exactly this, so the token validation above is the
control), seals the session and each delegation with the new sandbox's UID, and parks the envelopes. A sealing or
store failure withdraws the resource and fails the request, so nothing half-made is left. The answer is `201` with
the sandbox's name and status. In `dev_mode` the API writes the record itself and a dev binder binds it, with no
cluster resource.

A parked delegation's envelope is given an expiry: the least of the credential's own and the claim's creation plus
its TTL (`parked_expiry`), so a secret is stored no longer than its claim. See [The store and the
sealing](store-and-sealing.md).

## `POST /v1/token`: issuing a credential

`token` finds the claim from the peer's identity (it must be live, and name the audience), applies a per-claim rate
limit (`Limiter`, `rate_limited`), then `issue_token` picks the backend for the audience in this order:

| Order | Backend | Source of the credential |
| --- | --- | --- |
| 1 | `delegated` | the person's own credential, opened from the claim's sealed envelope (ADR-0035) |
| 2 | `secret` | an operator-held credential read at start from a mounted file (ADR-0032) |
| 3 | `entra-obo` | the claim's Entra session, refreshed for the audience's resource (ADR-0016) |
| 4 | `sts` | a token the broker mints itself, with an RFC 8693 `act` claim naming the claim (ADR-0003) |

For an issuer with a session the refresh runs under a per-claim lock, over the record as it is once the lock is held,
because the previous refresh may have rotated the envelope or released the claim.

An audience that is gateway-placed (`inject: gateway`) is **never** issued here: `POST /v1/token` for it is `403`,
so the pool VM cannot obtain it. The gateway asks the credential route instead, which runs the same per-backend
code and the same gate, then adds the policy admission `/v1/token` does not have (under `policy.egress: enforce` the
claim must name a policy whose verified bundle lists the audience).

## The shared state

`AppState` carries what the handlers need and nothing mutable that is not behind a lock: the validator, the store
(`dyn ClaimStore`), the sealer, the audience maps (`audiences`, `delegated`, `secrets`, `obo_audiences`), the
registries and `reachable_registries`, the `gateways` and inject port, the sandbox front door, the limiter, the
`policy_egress` mode, and `dev_mode`. It is built once in `crates/mediatore/src/main.rs` from the
[configuration](configuration.md).

## Rules this part keeps

- A body is checked before anything is created; a failure leaves no resource and no envelope.
- A secret-carrying type prints `[redacted]`; no log line carries a token, a password or a refresh token.
- The gateway routes answer the gateway identity only, and a pool VM cannot read a placed credential.
- A path not implemented is `501`, never a permissive default.

## Read next

ADR-0008 (the front door), ADR-0013 and ADR-0035 (delegating a session or a credential), ADR-0040 and ADR-0041 (placing
it at the gateway), ADR-0043 (the registry pull). Threat model TB-1 (user to API), TB-6 (VM to sandbox API), TB-17
(the gateway places a credential). Guide: [Requesting a sandbox](../guides/requesting-a-sandbox.md).
