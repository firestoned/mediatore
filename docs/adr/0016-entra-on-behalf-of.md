<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0016: The Entra path: On-Behalf-Of at claim creation, the session refreshed before every issue, the broker's credential a signed assertion

**Status:** Accepted · **Date:** 2026-10-16

Roadmap 04, fourth slice. Implements the `entra-obo` half of
[ADR-0003](0003-token-backends.md) on the session shape of
[ADR-0013](0013-dex-session-delegation.md) and the sealers of
[ADR-0012](0012-persistent-store.md) and [ADR-0015](0015-transit-sealer.md).

## Context

ADR-0003 chose two backends: Dex-shaped issuers get mediatore's own STS, Entra gets
On-Behalf-Of, because only OBO can produce a token a downstream Entra-protected API will
accept as "this user, through mediatore". ADR-0013 built the Dex half and left the Entra
half as accepted risk R-2: an `entra-obo` audience answers `501`, and a claim from an Entra
login has no session to refresh, so a revocation at Entra does not reach it.

Three things about Entra's protocol shape the design; all three are Microsoft's documented
behaviour, not choices here.

**The assertion is the caller's access token, and OBO can return a refresh token.** OBO
exchanges an access token whose `aud` is the middle tier (mediatore) for a token to a
downstream resource; an ID token is refused. With `offline_access` in the scope the
response carries a refresh token, issued to mediatore for that user, and an Entra refresh
token is valid for every resource the user has consented to for that client, not only the
one it was obtained for: a later `refresh_token` grant names the resource it wants in
`scope`. So one exchange at claim creation yields a session that serves every audience of
the claim for as long as Entra honours it.

**A refresh for a downstream resource cannot be validated by mediatore.** The ID token a
refresh response may carry is unsigned by design, and Microsoft says not to read tokens
for APIs one does not own. What mediatore can validate is a token for itself: a refresh
with `scope=<client_id>/.default` returns an access token whose audience is mediatore,
signed by Entra, carrying `oid`, `groups` or `roles`, exactly what the login carried.

**The broker's credential is a signed JWT, and it need not be a key the broker holds.**
A confidential client authenticates with `client_assertion`: a JWT with `alg: PS256`,
`x5t#S256` naming the registered certificate, `aud` the token endpoint, `iss` and `sub`
the client id, a `jti`, and a lifetime of minutes. Entra also accepts a token from a
federated issuer in the same slot (workload identity federation), which on AKS is the
pod's projected ServiceAccount token with audience `api://AzureADTokenExchange`.

## Decision

**1. The bearer is the delegation.** An issuer with `backend: entra-obo` carries an
`entra` block and takes no `refresh_token` in the claim request (`400 session_unexpected`,
as today for any issuer without a `session`). At `POST /v1/claims` the caller's validated
access token is the OBO assertion: mediatore exchanges it at the issuer's token endpoint
with `requested_token_use=on_behalf_of` and `scope=offline_access <resource>/.default`,
where the resource is the first `entra-obo` audience the request names, or mediatore's own
`client_id` when it names none. The refresh token in the response is the session; it is
sealed and parked under the sandbox UID exactly as a delegated Dex session (ADR-0013
decision 2), and nothing else from the response is kept. A refusal (`invalid_grant`,
`interaction_required`, `consent_required`) is `403 session_refused` with Entra's error
code, and no sandbox is created; an outage, a credential problem (`invalid_client`) or any
other failure is `503 upstream_unavailable`. A sandbox created declaratively (no bearer to
exchange) has no session, and `POST /v1/token` refuses it as it refuses a Dex record
without an envelope.

**2. Before every issue the session is refreshed for the audience's resource.** For an
`sts` audience, `scope=offline_access <client_id>/.default`: the access token Entra
returns is a token for mediatore and is validated exactly as a login (signature, `iss`,
`aud`, the group gate on the groups it carries now, the subject against the record), and
those groups are what the STS token carries, as on the Dex path. For an `entra-obo`
audience, `scope=offline_access <audience>/.default`: the access token Entra returns is
handed to the workload as is, with the `expires_in` Entra set; mediatore does not parse
it. `offline_access` is on every refresh, as MSAL puts it, so the response carries the
refresh token to keep; Entra does not retire the old one, the fake does (as Dex does),
and either way the one in the response is re-sealed into the record before anything is
minted. `invalid_grant`,
`interaction_required` and `consent_required` are revocations: the claim is released at
once and the answer is `403 session_revoked`; everything else is `503
upstream_unavailable` and revokes nothing. An `entra-obo` audience on a claim from a
non-Entra issuer is refused at claim creation (`400 audience_needs_entra`) and at issue
(`403`), since there is no session Entra would honour.

**3. The lifetime of an OBO token is Entra's.** mediatore reports Entra's `expires_in` as
`expires_at` and does not cache or re-issue: every issue is an exchange, bounded by the
per-claim rate limit (ADR-0013 decision 5). ADR-0003's fifteen-minute cap applies to the
tokens mediatore signs; the lifetime of a token Entra signs for a downstream is the
tenant's token lifetime policy, and the threat model's R-3 says so. The roadmap's
"15-minute re-issue cap" is therefore "no re-issue at all".

**4. The broker's credential is a client assertion, signed where the configuration says.**
`issuers[].entra` names exactly one of:

- `key_file` with `certificate_file`: an RSA private key (PKCS#8 PEM) in a Secret volume
  and the certificate registered on the app registration. The homelab shape.
- `transit` with `certificate_file`: an RSA key in OpenBao transit (`sign` with PSS and
  SHA-256, the salt the hash's length), reached with the same Kubernetes login as the
  transit sealer (ADR-0015); the certificate was issued for that key (OpenBao's
  `transit/keys/<key>/csr` signs a request without releasing it). The work shape: the
  credential that lets mediatore act as itself at Entra never enters the process.
- `token_file`: a projected ServiceAccount token presented as the assertion itself, for
  an app registration with a federated credential naming the cluster's issuer and the
  broker's ServiceAccount. The AKS shape: no key anywhere.

The assertion is `PS256` with `x5t#S256` from the certificate, `aud` the token endpoint
from the issuer's discovery document (nothing in a request names it), `iss` and `sub` the
`client_id`, a fresh `jti`, five minutes of life, signed for each request. At startup the
signer is exercised: a probe assertion is signed and verified against the certificate's
public key, so a key that does not match the registered certificate, a wrong transit role
or key, or an unreadable file stops the process, not the first claim.

**5. The fake issuer speaks Entra's protocol and is as strict as Entra.** `FakeIdp`
gains the `jwt-bearer` grant with `requested_token_use=on_behalf_of` (the assertion must
be an access token it issued for the client, with `offline_access` for a refresh token),
the `refresh_token` grant with a `scope` naming the resource (a token for the client's own
resource is signed and carries the user's groups; a token for another resource is opaque
to the caller), and client authentication by `client_assertion`: PS256 against a
certificate registered for the client, `aud` checked against its token endpoint, `jti`
never accepted twice, or a federated token from a registered issuer. The fake OpenBao
gains `sign` over an RSA key with the same PSS parameters. The e2e suite drives the
exchange, the two refresh shapes, the revocation, the outage, the subject check and the
three credential shapes without a tenant.

**6. The live proof is by hand, against a tenant.** Entra cannot run in kind. An ignored
test, `crates/mediatore/tests/live_entra.rs`, takes the issuer, client id, credential
files, a user's access token for mediatore and a downstream audience from the environment
and runs the exchange, the refresh for mediatore's own resource and the refresh for the
audience against the real token endpoint; it fails, never skips, when its fixture is
missing. Roadmap 04 closes when that run is green; until then the threat model keeps the
Entra path listed as proven against the fake only.

## Alternatives considered

- **A client secret.** Accepted by Entra anywhere an assertion is; a static secret in a
  Secret volume. Rejected: a signed assertion is the recommended credential, and only an
  assertion allows the key to live in OpenBao or not to exist (federation).
- **Validating the downstream token's `oid` before handing it over.** Would catch a
  session that Entra re-pointed at another user. Rejected: Microsoft documents those
  tokens as not for the middle tier to read, and the refresh token is sealed to the
  claim and was issued for exactly one user; the subject check runs on every `sts` issue,
  where mediatore gets a token it owns.
- **Caching the OBO token for fifteen minutes.** Fewer calls to Entra. Rejected: a cache
  is a window in which a revocation at Entra is not seen, and the per-claim limit already
  bounds the call rate.
- **OBO at every issue with the caller's original token.** The caller's token is gone
  after the claim is created (it is never stored), and it expires within the hour.

## Consequences

- `crates/mediatore-openbao` is new: the OpenBao client (`TransitConfig`, the Kubernetes
  login, the token with its lease, one call with a retry on 403), moved out of
  `mediatore-store` so the signer and the sealer share it.
- `crates/mediatore-entra`: `IssuerConfig.entra` (`EntraConfig`), `ClientAssertion` (the
  three signers), `Validator::exchange` (OBO) and `Validator::refresh` taking a `scope`
  and returning the access token with its expiry; `IdpError::SessionRevoked` now also
  covers `interaction_required` and `consent_required`. The unused `Obo` type is gone.
- `crates/mediatore-api`: the exchange in `create_claim` and `create_sandbox`, the
  per-audience refresh in `token`, audiences carried with their backend.
- `crates/mediatore-testkit`: the fake issuer's OBO and refresh-by-scope grants and its
  client authentication, the fake OpenBao's `sign`, a fixed RSA test key with its
  certificate.
- Config: `issuers[].entra { certificate_file, key_file | transit | token_file }`;
  `backend: entra-obo` requires it, any other backend refuses it; `entra` and `session`
  are exclusive; an `entra-obo` audience needs an Entra issuer.
- Threat model: TB-5 gains the OBO rows, TB-10 the signing row, a new asset A-13 (the
  client assertion credential in its three shapes), R-2 rewritten around the pending live
  proof, R-3 widened to Entra's token lifetime.
- Every issue on an Entra claim costs one round trip to Entra and two to the sealer, as
  on the Dex path.
