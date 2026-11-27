<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Issuers and audiences

Two questions, answered by two kinds of configuration. An **issuer** answers *who is this person?* An **audience**
answers *what may a sandbox reach on their behalf, and with what credential?* The code is `crates/mediatore-entra`
(issuers: validation, sessions, Entra), `crates/mediatore-sts` (mediatore's own token service),
`crates/mediatore-openbao` (the client both depend on for keys) and `crates/mediatore/src/config.rs` (the
configuration and its cross-field rules). The guides [Issuers](../guides/issuers.md) and
[The Entra path](../guides/the-entra-path.md) cover setting them up.

## Issuers: who is this person

`IssuerConfig` (`mediatore-entra/src/lib.rs`) describes one trusted issuer:

| Field | Meaning |
| --- | --- |
| `url` | the `iss` value, byte for byte |
| `backend` | `sts` (mediatore signs its own tokens; the issuer is only for login) or `entra-obo` (Entra On-Behalf-Of) |
| `client_id` | mediatore's client at this issuer, and the required `aud` |
| `subject_claim` | the claim carrying the person's id: `oid` for Entra, `preferred_username` for Dex |
| `required_groups`, `required_group`, `allow_any_authenticated` | the login gate, exactly one of the three: a list of groups of which the token must carry at least one (exact, case-sensitive; `required_group: X` is `[X]`), or `allow_any_authenticated: true` for no group gate, written down. An issuer with none, or more than one, does not start (ADR-0046) |
| `groups_claim` | the claim that carries groups when it is not `groups` or `roles` |
| `session` | present when a claim from this issuer must delegate a refresh token (ADR-0013); `client_secret_file` for a token endpoint that wants one |
| `entra` | present for `entra-obo`: the broker's own credential for the exchange (a key file, an OpenBao transit key, or a federated service-account token) |
| `ca_file` | the CA that signs this issuer's certificate, for an issuer on a private PKI; discovery, the JWKS and token requests then trust exactly it |
| `subject_prefix` | what the STS puts in front of this issuer's subject id in `sub`, such as `dex:` (1 to 31 of `a-z`, `0-9`, `.`, `_`, `-`, the first a letter or digit, then one `:`). Optional with one issuer: `sub` is then the bare id. With two or more issuers under an `sts`, every issuer needs one and no two may be equal, or the broker does not start (ADR-0071) |

**One person, one `sub`.** A subject id is unique only inside the issuer that gave it: `octocat` at one issuer and
`octocat` at another are two people. Inside the broker a person is always the pair of issuer and id (the claim's
owner check compares both). In a token the STS mints, a resource server usually reads `sub` alone, so with several
issuers `sub` is `<subject_prefix><id>` (`dex:octocat`, `google:octocat@example.com`) and `upstream_iss` still carries
the issuer's URL. The prefix of a `sub` is everything up to and including the first `:`. `SubjectPrefixes`
(`mediatore-sts/src/lib.rs`) checks the set at start and again when the STS is built, and the STS refuses to mint for
an issuer without a prefix once any issuer has one.

**Validating a bearer** (`POST /v1/claims`): the issuer is known, the audience is mediatore's client, the signature
verifies through the issuer's JWKS (cached for five minutes), the token is not expired, the subject claim is present,
and the **group gate** passes (a token carrying one of `required_groups`, or `allow_any_authenticated: true`). Where a person may then create a sandbox is the namespace map, `sandboxes.namespaces`, checked on the same groups ([Configuration](configuration.md)). Failures are `IdpError` variants (`UnknownIssuer`, `Invalid`, `Forbidden`, and for a session `SessionRevoked`,
`Upstream` and `Credential`).

**A session.** For an issuer with a `session`, the caller delegates its refresh token with the claim. The broker seals
it and, **before every token issue**, refreshes it upstream and validates the ID token that comes back the same way,
including the group gate, so a person removed from the group loses the claim's tokens at the next issue. An upstream
that refuses the refresh (`invalid_grant`, or Entra's `interaction_required` and `consent_required`) is a
**revocation**, not an outage: the claim is released. An upstream that is down is a `503` and revokes nothing.

**Entra.** For `entra-obo` the broker exchanges the caller's access token On-Behalf-Of at claim creation and keeps the
Entra session, then refreshes it for the audience's resource before each issue. It authenticates to Entra with a signed
client assertion (`assertion.rs`), whose key is a file, an OpenBao transit key (signing without holding the key), or a
federated service-account token.

## Audiences: what a sandbox may reach

`AudienceConfig` (`config.rs`) is one downstream service a claim may ask for. `via` says where its credential comes
from, and `inject` says where it is placed:

| `via` | The credential is | Defined in |
| --- | --- | --- |
| `sts` | a token mediatore mints, an RFC 8693 token with the person as `sub` (qualified by the issuer's `subject_prefix` when one is set, ADR-0071) and the claim identity in `act` | ADR-0003, `mediatore-sts` |
| `entra-obo` | an Entra token for the audience's resource, from the claim's Entra session | ADR-0016 |
| `secret` | an operator-held credential read from a mounted file at start (ADR-0032); not a person's | ADR-0032 |
| `delegated` | the **person's own** credential, delegated with the claim and sealed per audience | ADR-0035, ADR-0041 |
| `none` | nothing: the workload reaches the host through the proxy with no credential; the route, rules and CA still apply | ADR-0025 decision 8 |

The remaining fields describe the route the egress proxy and the gateway enforce:

| Field | Meaning |
| --- | --- |
| `egress` | the host and port the audience is reached at (an `Endpoint`); exactly one per audience that is gateway-placed |
| `rules` | `{ method, path }` entries: what the workload may ask of the audience. Empty admits every method and path; once any rule exists, a request outside them is refused |
| `max_ttl` | the longest a token or placed credential lives (default 900 seconds; at most 300 for a gateway-placed one) |
| `ca_file` | a PEM the proxy trusts for this audience's host instead of the public roots |
| `header`, `extra_headers` | the request header a delegated credential goes in (default `authorization`), and headers sent beside it |
| `secret_file`, `secret_header`, `secret_extra_headers` | the same, for `via: secret` |
| `refresh` | how the broker renews a delegated bearer from its refresh token; absent, the claim cannot outlast the bearer |
| `credential` | `bearer` (default) or `basic` (a user name and secret, joined `user:secret`, placed as `Authorization: Basic`) |
| `inject` | `proxy` (default) or `gateway` |
| `namespaces` | optional: a map from a namespace to its `rules` (a grant). Absent, the audience is usable from every namespace; present, only from the namespaces listed, and the top-level `rules` is the ceiling every grant must sit inside (ADR-0053, [Multi-tenant authorization](../guides/multi-tenant-authorization.md#6-which-audiences-a-namespace-may-use-adr-0053)) |

**Path rules are segment-wise globs.** A segment is exactly `*` (one segment), exactly `**` (zero or more), or a literal
compared for equality. `*.git` is therefore a literal segment, not a pattern: the rule that admits
`/org/repo.git/info/refs` is `/*/*/info/refs`. The query string is not part of the path the rules see.

### Where the credential is placed

| `inject` | Who puts the credential on the request | The pool VM holds it |
| --- | --- | --- |
| `proxy` | the egress proxy on the claimed VM swaps its phantom token for a token it fetched from the broker (`POST /v1/token`) | the proxy process does, outside the jail, for a short time |
| `gateway` | the gateway's authorizer fetches it from the broker for each claim and the inject Envoy writes it into the request | **never** |

See [The egress proxy](egress-proxy.md) and [The gateway](gateway.md). A `delegated` audience that is `credential:
basic` is **always** gateway-placed, because a password must never reach a pool VM; the configuration refuses a `basic`
audience that is not `via: delegated`, `inject: gateway`, header `authorization` and without a `refresh`.

The configuration refuses, at start, an audience that cannot be served safely: `inject: gateway` without `gateways`
and `gateway_inject_port`, without `egress` and `rules`, with an IP-literal host (the upstream's certificate is
verified by name), with a `max_ttl` above 300, or with no credential to place. A misspelt `inject` or a field the
audience does not know is an error, never a silent default (`deny_unknown_fields`).

### A registry is an audience too

The host of a gateway-placed audience counts as a registry the pool reaches (`Config::placed_registries`,
`reachable_registries`). A claim whose image is on it must name that audience and delegate a credential for it, and its
pull is placed at the gateway (ADR-0043); see [The guest](guest.md).

## The STS and OpenBao

`mediatore-sts` is mediatore as a token service, used when the upstream cannot delegate (Dex with GitHub, in a
homelab) and optionally for internal services that validate JWTs against a JWKS (`/.well-known/jwks.json`). Its signing
key is a PEM file (`sts.signing_key_file`); a signer over an OpenBao transit key is planned, not built.

`mediatore-openbao` is the one client for OpenBao. The broker logs in at the Kubernetes auth method (at the mount
`auth_mount` names, one per cluster on this platform) with its projected service-account token, keeps the OpenBao
token with its lease, exchanges it again before the lease ends or at once on a `403`, and makes one transit call at a
time (`encrypt`, `decrypt`, `sign`). The transit sealer and the Entra assertion signer are its two callers; neither
holds a key, only that leased capability to use one.

## Rules this part keeps

- The group gate is checked at claim creation **and** at every refresh, and an issuer must state one (`allow_any_authenticated: true` is a statement).
- An upstream refusal releases the claim; an upstream outage does not.
- A credential a person delegated is never placed on a pool VM when its audience is gateway-placed, and a `basic` one
  always is.
- Misconfiguration is refused at start, not served.

## Read next

ADR-0003, ADR-0013, ADR-0015, ADR-0016, ADR-0017 (issuer profiles), ADR-0025 (the phantom token), ADR-0032, ADR-0035,
ADR-0040, ADR-0041, ADR-0043, ADR-0046 (who may claim). Threat model TB-5 (to the issuer) and TB-10 (OpenBao). Guide: [Issuers](../guides/issuers.md).
