<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0032: An operator-held credential as an audience backend, placed by the proxy, never in the jail

**Status:** Proposed · **Date:** 2026-11-08

Roadmap 04 (the backends) and roadmap 07 (what the proxy puts on the wire). Adds a third
backend to [ADR-0003](0003-token-backends.md), beside `entra-obo` and `sts`, and amends
[ADR-0025](0025-phantom-token-egress-proxy.md) decision 3 (where the phantom may be
presented and what replaces it) and the `TokenResponse` of ADR-0003 (which header the
credential travels in). Changes no SPIFFE ID, no entry shape, no storage contract and no
route shape: a route for such an audience is an ordinary `credential: token` route.

## Context

Everything the proxy swaps the phantom for today is minted per claim: an STS token the
broker signs, or an Entra token exchanged for the subject. Both carry who acts and for whom,
and both die with the claim. Many APIs a sandboxed agent is pointed at accept neither. The
first one asked for is Anthropic's: the agent in the jail is to call Claude, through the
SDK or Claude Code. The Messages API takes an API key in `x-api-key`, or an OAuth access
token as `Authorization: Bearer` with the `anthropic-beta: oauth-2025-04-20` header; a JWT
of mediatore's means nothing to it. The same holds for most SaaS APIs a lab reaches: a key
the operator was issued, long-lived, shared.

The workload side costs nothing: the SDKs and Claude Code read `ANTHROPIC_BASE_URL` and
`ANTHROPIC_AUTH_TOKEN`, so the jail is given
`ANTHROPIC_BASE_URL=$MEDIATORE_EGRESS_PROXY/api.anthropic.com` and
`ANTHROPIC_AUTH_TOKEN=$MEDIATORE_TOKEN`, and sends `Authorization: Bearer <phantom>` like
every other tool ([ADR-0025](0025-phantom-token-egress-proxy.md) decision 3). What is
missing is on the broker's side: something to swap the phantom for, and a way to say which
header it goes in. The one thing that must not happen is the obvious shortcut: the key in
the image, or in the jail's environment. ADR-0025 closed R-3 by taking every credential out
of the hostile process; a key handed to the workload reopens it for the one API that
matters most to an agent.

Two things are not this ADR, and are named so they are not forgotten. Anthropic supports
workload identity federation: a JWT from a registered issuer exchanged at
`/v1/oauth/token` for a short-lived token. The broker's STS already issues exactly such a
JWT, with `sub`, `act` and `claim_uid`. A per-claim, attributed, short-lived Anthropic token
is therefore an exchange away, and the right end state; it needs an organisation-level
federation rule and a live run, so it is a roadmap item, not this decision. And the Entra
path already covers the case where the upstream speaks OAuth and the subject has an
account there.

## Decision

1. **A third backend, `via: secret`: the operator's credential for that audience.** The
   audience names a file, `secret_file`, holding the credential and nothing else; the
   broker reads it once at start, trims one trailing newline, and refuses to start on a
   file that is missing or empty (fail closed, as with `signing_key_file` and `ca_file`).
   The file is a Secret mounted read-only into the broker (`deploy/base` gains nothing; the
   overlay mounts it as it mounts the STS key), never a value in `mediatore.yaml`, never an
   environment variable. The credential is the operator's, not the subject's: one per
   audience, shared by every subject the policy admits there.

2. **Where it goes on the wire is the audience's to say.** `audiences[].secret_header`
   names the request header the proxy sets, default `authorization`, in which case the
   value is `Bearer <credential>` as for every token today; any other name (`x-api-key`)
   carries the bare credential. `audiences[].secret_extra_headers` is a list of
   `{ name, value }` the proxy adds beside it on every credentialed request (Anthropic's
   `anthropic-beta: oauth-2025-04-20` for an OAuth token); they are not secrets and travel
   on the route. `POST /v1/token` for such an audience answers the same `TokenResponse` as
   today with two additions: `header`, the name from the configuration, and
   `extra_headers`; `token_type` is `Bearer` when the header is `authorization` and
   `Header` otherwise. The proxy's cache keeps the header with the token.

3. **The phantom may be presented where the credential will go.** ADR-0025 decision 3
   recognised the phantom in `Authorization: Bearer` alone, and `judge` looked at no other
   header. On a route whose audience is `via: secret` with a header other than
   `authorization`, the phantom is recognised in that header too (a tool reading
   `ANTHROPIC_API_KEY` sends it there), and the proxy strips that header from every request
   it forwards on every route, phantom or not, before setting its own on a credentialed one:
   a value that is not the phantom is `401 unknown_credential`, exactly as a foreign bearer
   is. The same rule applies to `authorization` already. A header the proxy does not own
   passes through, as before. This closes a gap decision 3 of ADR-0025 left: a workload
   could carry a key of its own in a header the proxy never read.

4. **Lifetime and revocation.** The credential does not expire with the claim; the proxy's
   copy does. `POST /v1/token` hands it with `expires_at` at `now + max_ttl` (the
   audience's, 900 s by default), so the proxy re-asks within that bound and the broker's
   rate limit, audit row and `is_live` check apply to every fetch as they do for a minted
   token. Revocation is the operator's, at the upstream: rotate the Secret, restart the
   broker; every proxy holds the old value for at most `max_ttl` more, and a released claim
   fetches nothing. Nothing of the credential is written anywhere: not the store, not a
   log, not the audit row (`backend=secret` and the audience are logged, as today).

5. **Attribution stays in mediatore.** The upstream sees one key for every subject. Who
   acted is the broker's record: the audit row of every issue names the subject, the claim
   and the audience, and the proxy's log line names the host, the method and the path.
   The operator is told, in the guide, that the key should be one the upstream lets them
   scope and cap (a Console workspace key with a spend limit, for Anthropic), and that the
   audience's `rules` are what bounds the agent's reach there: `POST /v1/messages` and
   `POST /v1/messages/count_tokens`, nothing on `/v1/organizations/**` or the Admin API.

6. **The shadow comparison treats it as an audience.** A `via: secret` audience is in
   `audiences[]` like any other: `P001` to `P005` compare it against the bundle as they
   do today. notaio's bundle does not know which backend serves an audience and does not
   need to; `max_ttl` keeps its meaning as the proxy's cache bound and is compared to
   `ttlSeconds` as before.

7. **Not decided here.** The federation exchange (decision 0 of a later ADR: the STS token
   exchanged at the upstream's token endpoint for a short-lived, attributed one; Anthropic
   first); per-subject credentials (a Secret per subject, or the subject bringing one at
   claim time, which ADR-0013 deliberately does not do); the proxy rewriting request bodies
   (a credential inside a JSON body is not placed by this ADR).

## Consequences

- `Backend::Secret` and `audiences[].secret_file`, `secret_header`, `secret_extra_headers`
  (`crates/mediatore-entra`, `crates/mediatore/src/config.rs`: refused on an issuer like
  `none`, the file read and checked at start); `AppState::secrets` keyed by audience, held
  as a `Secret` that prints redacted; `POST /v1/token` answering the credential with
  `header` and `extra_headers` (`crates/mediatore-api`); `TokenResponse::header`,
  `TokenResponse::extra_headers`, `Route::credential_header`
  (`crates/mediatore-proto`); the proxy recognising the phantom in the route's header,
  stripping the owned headers, placing the credential and the extra headers (`judge`,
  `rewrite`, `TokenCache`, `crates/mediatore-guest/src/egress.rs`).
- Proven end to end in `e2e_egress.rs`: an audience `via: secret` with `x-api-key`, the
  phantom presented in `x-api-key` and in `Authorization` both swapped, the upstream
  seeing the key in `x-api-key` and no `Authorization`, a foreign `x-api-key` refused, the
  token cached and re-fetched past `max_ttl`, the credential absent from the routes file
  and from every log line. Then live: a claim running the Python SDK or Claude Code against
  `api.anthropic.com` through the gateways, the answer from Claude in the workload's log.
- The threat model gains an asset (the operator's credential, in the broker's and the
  proxy's memory), TB-6 and TB-7 rows, and an accepted risk: a shared long-lived key has no
  per-subject revocation at the upstream; the bound is the rules, the claim and the
  operator's cap; revisit when the federation exchange exists.
- Rejected: the key in the jail's environment or the image (R-3 reopened for the API an
  agent uses most); a per-claim derived key (Anthropic issues none); the proxy terminating
  the API's TLS to read bodies (ADR-0025's reasons stand); storing the credential in the
  store (it is configuration, the Secret is its home).
