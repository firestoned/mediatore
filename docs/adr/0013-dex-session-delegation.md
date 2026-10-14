<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0013: The Dex path: the upstream session is delegated at claim creation, sealed, and refreshed before every issue

**Status:** Accepted · **Date:** 2026-10-14

Roadmap 04, first slice. Implements the `sts` half of [ADR-0003](0003-token-backends.md)
("before every issue, mediatore refreshes the upstream session so revocation upstream
propagates") on the resource of [ADR-0008](0008-agentsandbox-crd-owned-by-mediatore.md)
and the store of [ADR-0012](0012-persistent-store.md). The Entra On-Behalf-Of half and the
transit sealer are the next slices of the same roadmap.

## Context

`POST /v1/token` mints an STS token for any audience on a live record, from the record
alone. Nothing upstream is consulted: a user removed from the GitHub organisation, or
whose Dex session was revoked, keeps getting tokens until the claim's TTL. That is
accepted risk R-2, and the gap ADR-0003 named.

Closing it needs an upstream session mediatore can exercise: a refresh token. Three
things had to be decided.

**Whose refresh token, and how it reaches mediatore.** The person logs in at Dex with a
CLI. ADR-0008 moved the request onto an `AgentSandbox` resource, which must never carry
a credential, and the store record for the request does not exist until the reconciler
creates the claim. So the credential needs its own path from the API call to the record.

**Which OAuth client.** The roadmap sketched a separate CLI client with Dex's
cross-client (`trustedPeers`) audience. Refreshing a public client's token needs only
its `client_id`, so whichever client issued the refresh token is the one mediatore has
to impersonate at the token endpoint.

**What a refusal means.** Dex answers a refresh with `invalid_grant` when the session was
revoked or the user is gone, and with a 5xx when it is down. Only the first is a
revocation.

## Decision

**1. The caller delegates its session with the request.** `POST /v1/claims` takes an
optional `refresh_token`. An issuer configured with a `session` block
(`issuers[].session.client_id`) requires it: a claim without one is refused with `400
session_required`, and `/v1/token` never mints for a record of that issuer without an
envelope. An issuer without a `session` block (an app-only principal, a `dev_mode` fake,
Entra until On-Behalf-Of lands) takes no refresh token and mints as before. The refresh
token is never logged and has a redacting `Debug`.

**2. The session is a sealed row keyed by the sandbox.** The API seals the refresh token
with the `AgentSandbox` UID as associated data and writes a `sessions` row keyed by that
UID in the same request, after the resource exists; a sealing or store failure deletes
the resource and fails the request. When the reconciler creates the record it takes the
session row (read and delete, one transaction) and the envelope becomes
`ClaimRecord::refresh`, with the new `sandbox_uid` column recording which UID opens it.
This revises ADR-0012 decision 3 on one point: the associated data is the sandbox UID,
the one identifier that exists at every stage, not the claim UID. A session whose sandbox
is refused, fails before a claim exists, or is deleted is removed by the reconciler;
sessions older than one hour with no record to go to are swept at resync. Under
`dev_mode` the API writes the record directly and seals with the record's own UID.

**3. The CLI logs in as mediatore's own public client.** `mediatore-cli login` runs the
PKCE flow (RFC 7636, loopback redirect per RFC 8252) against the issuer as client
`mediatore` with scopes `openid profile email groups offline_access`, so the ID token's
`aud` is mediatore without a cross-client step and the refresh token belongs to the client
mediatore refreshes as. Cross-client tokens still validate (any `aud` naming mediatore
does), so an agent with its own Dex client keeps working for login; delegation needs the
`mediatore` client's refresh token. The CLI stores the session in
`~/.config/mediatore/session.json` (mode 0600) and `mediatore-cli claim` hands the refresh
token to mediatore and forgets it: Dex rotates refresh tokens, so after the first refresh
by mediatore the CLI's copy would be dead anyway. A second claim is a second login.

**4. Refresh before every issue, revoke on refusal.** On `POST /v1/token` for a record
with an envelope, mediatore opens it, calls the issuer's `token_endpoint` (from the
discovery document the validator already fetches) with `grant_type=refresh_token` and the
session's `client_id`, validates the returned ID token exactly as a login token (signature,
issuer, audience, the group gate against the groups it carries now), re-seals the rotated
refresh token into the record, and only then mints, with those fresh groups in the token.
`invalid_grant`, or a fresh ID token that fails the group gate, is a revocation:
`Reconciler::release` runs at once (entry retracted, record revoked, envelope dropped) and
the answer is `403 session_revoked`. A 5xx or a network failure is `503
upstream_unavailable` and revokes nothing: an identity provider that is down must not
destroy every sandbox.

**5. Per-claim rate limiting on `/v1/token`.** A token bucket per claim UID, in process
memory, `token.rate_per_minute` (default 10, burst the same): a workload that asks faster
gets `429 rate_limited` before any upstream call, so a looping agent cannot turn mediatore
into a refresh hammer against the issuer. Per replica, which is the bound that matters
(the two replicas share nothing else on this path either).

**6. The fake issuer grows the real protocol.** `FakeIdp` serves an authorization
endpoint, a token endpoint with the `authorization_code` (PKCE S256 verified) and
`refresh_token` grants, rotation, and test hooks to change a user's groups and revoke a
session, so the e2e suite drives the CLI's login, the delegation, the refresh, the
rotation, the group change and the revocation end to end without a browser. A Dex in
kind is the live tier for the same flow and is the next slice if the CLI can be driven
from inside the cluster.

## Consequences

- `crates/mediatore-cli` is new: `login`, `claim`, `get`, `delete`, `status`. It depends
  on `mediatore-proto` only.
- `crates/mediatore-entra`: `IssuerConfig.session`, `Validator::refresh` (token endpoint
  from discovery, cached with the JWKS), `IdpError::SessionRevoked` distinct from
  `Upstream`.
- `crates/mediatore-store`: migration `0002` adds `claims.sandbox_uid` and the `sessions`
  table on both engines; `ClaimStore` gains `put_session`, `take_session`,
  `delete_session` and `sweep_sessions`; the conformance suite covers them on all three
  backends.
- `crates/mediatore-api`: `ClaimRequest.refresh_token`, the delegation in `create_claim`
  and `create_sandbox`, the refresh in `token`, the limiter.
- `crates/mediatore-claims`: the reconciler moves the session into the record and removes
  it on refusal and deletion; the resync sweeps stale sessions.
- Config: `issuers[].session.client_id`, `token.rate_per_minute`; an issuer with a
  `session` block and no `store.sealing` key refuses to start.
- Threat model: TB-1 gains the delegation rows, TB-5 the refresh rows, TB-6 the rate
  limit and the refusal row; R-2 narrows to the Entra half.
- A claim from a session issuer costs one upstream round trip per token (at most
  `rate_per_minute` per claim), which is the price ADR-0003 chose for revocation that
  propagates.
