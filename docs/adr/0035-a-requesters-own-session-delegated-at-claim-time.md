<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0035: A requester's own upstream session, delegated at claim time and placed by the proxy

**Status:** Proposed · **Date:** 2026-11-10

Roadmap 12 (the path to the Anthropic API) and roadmap 04 (the backends). Adds a fourth
backend to [ADR-0003](0003-token-backends.md), beside `entra-obo`, `sts` and `secret`,
generalising [ADR-0013](0013-dex-session-delegation.md) (a session the requester delegates
to the broker, sealed, refreshed before every issue) from the issuer to an audience, and
keeping [ADR-0025](0025-phantom-token-egress-proxy.md) decision 3 and
[ADR-0032](0032-operator-held-credentials-as-an-audience-backend.md) whole: the proxy
places the credential, the jail sees the phantom. Builds on
[ADR-0015](0015-transit-sealer.md) for the shape where the envelope is sealed on the
requester's machine. Changes the `POST /v1/claims` request (a delegation per audience, or
a pending one), adds `PUT /v1/claims/{name}/delegations/{audience}`, the session Secret's
shape (ADR-0034 decision 2, one envelope per delegation) and one condition on the
`AgentSandbox`; no SPIFFE ID, no entry shape, no route shape.

## Context

The requirement is a person's own Claude session inside the sandbox: Claude Code in the
jail, running under that person's subscription, as it does on their machine. ADR-0032
gave the jail Claude through an operator-held API key: one key for every subject, paid for
by the operator, attributed only in the broker's log. That is the lab's shape, not the
person's. What a person has locally is what `claude login` left in Claude Code's credential
store (the macOS Keychain item `Claude Code-credentials`, or `~/.claude/.credentials.json`
elsewhere): an OAuth access token that lives hours, a refresh token that renews it, an
expiry, the scopes and the subscription type; or, from `claude setup-token`, one
long-lived OAuth token meant for headless use, read by Claude Code from
`CLAUDE_CODE_OAUTH_TOKEN`. The Messages API takes either as `Authorization: Bearer` with
`anthropic-beta: oauth-2025-04-20`, which Claude Code sends itself.

The obvious way, the one this ADR exists to refuse, is to copy that store into the jail:
the session file mounted, or the token in the jail's environment. It works in five
minutes and reopens the finding ADR-0025 closed (R-3): a credential inside the hostile
process, good for the account's whole scope and life, usable from anywhere it is
exfiltrated to, and revocable at the claim's end only by the person logging out
everywhere. The threat model's first assumption is that the agent will be steered; a
subscription-wide token is the prize that steering is for.

What the architecture already has is the shape that fits. ADR-0013 lets a person delegate
a refresh token to the broker at claim time; the broker seals it with the sandbox's UID,
refreshes it before every issue, and the proxy places what it minted. The only differences
here are that the session is for an audience rather than the issuer, that the upstream is
Anthropic rather than Dex, and that the refresh endpoint is Anthropic's own OAuth server,
whose location is not documented and has moved; so refreshing is a configured thing, and
phase 2.

One more thing the architecture has is the transit sealer (ADR-0015): when the broker's
sealing key lives in OpenBao, an envelope is `transit/encrypt` under a derived key with the
sandbox's UID as the context, and anyone OpenBao lets encrypt can produce one. That anyone
can be the requester. The plaintext then never crosses the leg from the CLI to the broker
and never passes through the broker's claim path at all; the broker opens it at token time
with `transit/decrypt`, as it opens a transit-sealed Dex session today; and OpenBao's audit
log records which person sealed a session for which sandbox, under their own identity,
which the broker's log cannot say. The one thing in the way is that the context, the
sandbox UID, is Kubernetes' and does not exist until the sandbox does.

Two boundaries this bends, named plainly. First, ADR-0003's and ADR-0025's rule that a
credential the workload could spend is never the person's: here it is, for the one upstream
where the person's subscription is the point. It still never enters the jail. Second,
ADR-0032 decision 7 named workload identity federation (the broker's STS token exchanged
for a short-lived Anthropic token) as the end state; a subscription session has no
federation path, so this is a second interim beside the operator key, not a replacement
for that end state. The delegated session is for the person's own Claude Code in the jail:
Anthropic binds subscription sessions to Claude's own harnesses, and a policy that hands
one to another workload is the operator's misuse, not a thing the broker can tell apart.

## Decision

1. **A fourth backend, `via: delegated`: the audience's credential comes from the requester,
   per claim.** `audiences[].via: delegated` names an audience whose bearer is delegated in
   the claim request and placed by the proxy; `header` (default `authorization`) and
   `extra_headers` say where it goes and what travels beside it, as ADR-0032's
   `secret_header` and `secret_extra_headers` do. The broker holds no credential for it
   between claims. Never an issuer's backend; the configuration refuses it there.

2. **The claim carries the delegation, or promises it; the claim binds only once every
   delegation has landed.** `POST /v1/claims` gains
   `delegations: [{ audience, token?, refresh_token?, expires_at?, pending? }]`, one per
   `delegated` audience the claim names, each secret field a `Secret` the API never echoes.
   Under the local sealer the delegation carries the token and the broker seals it. Under
   the transit sealer the delegation is `pending: true`: the broker creates the
   `AgentSandbox`, answers with its `sandbox_uid`, and the CLI seals under that context and
   completes it with `PUT /v1/claims/{name}/delegations/{audience}` carrying the envelope
   (`key_id`, `ciphertext`), as the same subject, within `delegations.grace_secs` (default
   120). The reconciler sets the condition `DelegationsPending` and creates no
   `VirtualMachineClaim` while it is `True`; a sandbox whose grace passes is released as a
   failed claim with that reason. A claim naming a `delegated` audience with neither a token
   nor a pending promise is `400 delegation_required`; a delegation for any other audience,
   a `PUT` for an audience not pending, by another subject, or after the grace, is
   `400 delegation_refused`; a plaintext token sent to a broker in the transit shape is
   `400 delegation_refused` too, so the plaintext path cannot be chosen by the client. Fail
   closed every way.

3. **Sealed like the issuer's session, one envelope per delegation; sealed on the
   requester's machine when the sealer is transit.** Each delegation ends up as a `Sealed`
   envelope bound to the sandbox's UID and parked in its own Secret,
   `mediatore-session-<sandbox uid>-<audience>`, labelled `mediatore.io/sandbox-uid`,
   `mediatore.io/session` and `mediatore.io/audience`, owned by the `AgentSandbox` as the
   issuer's session Secret is (ADR-0034 decision 2), claimed by the reconciler with the
   record, emptied on release and revocation, deleted by the retention sweep. The record
   type has no plaintext field; nothing of it is logged beyond the audience and the expiry.
   Who seals it depends on the broker's sealer:

   - With the local sealer (`sealing.key_file`) the CLI sends the plaintext delegation in
     the claim over TLS and the broker seals it, as it seals the issuer's refresh token
     today (ADR-0013).
   - With the transit sealer (`sealing.transit`, ADR-0015) the CLI seals it itself:
     `transit/encrypt/<key>` on the operator's OpenBao, `context` the sandbox UID, and sends
     the `vault:vN:…` ciphertext as the envelope (`key_id` `transit:<mount>/<key>`, no
     nonce, the ciphertext as returned); the broker stores what it received and opens it at
     token time with `transit/decrypt`, never having held the plaintext. The requester's
     access to OpenBao is an encrypt-only door: a `jwt` auth role that accepts the Dex ID
     token the CLI already holds from `mediatore login` (`bound_audiences` the broker's
     client id, `bound_claims` on the `groups` claim, a short `token_ttl`) with the policy
     `path "transit/encrypt/<key>" { capabilities = ["update"] }` and nothing else; the
     broker's own role keeps `encrypt` and `decrypt` (the store guide's role). A requester
     token stolen from the desktop can therefore produce envelopes and read none, and the
     derived key makes an envelope sealed for one sandbox useless on another. The broker
     advertises which shape it is in on `GET /v1/delegations` (the sealer kind, the OpenBao
     address, mount and key), so the CLI needs no configuration of its own; `GET` is open
     to any logged-in requester and reveals no secret.

4. **`POST /v1/token` opens the envelope and the proxy places it.** For a `delegated`
   audience the response is the delegated bearer, `header` and `extra_headers` as
   configured, `expires_at` the earlier of the delegation's own expiry and the claim's
   deadline; the proxy keeps it for at most `max_ttl` (ADR-0025) and asks again. Revocation
   empties the envelope and every later ask is `403 claim_revoked`, as for any backend;
   the upstream session itself is the person's to end.

5. **Refresh is configured, never assumed (phase 2).** When the delegation carries a
   `refresh_token` and the audience declares
   `refresh: { token_endpoint, client_id, scope? }`, the broker refreshes before an issue
   when the access token is within its last fifth of life, re-seals what came back, and
   rotates the refresh token if the endpoint rotated it, exactly as the Dex session is
   handled; in the transit shape the re-sealed envelope is the broker's `transit/encrypt`
   under the same context, so the desktop seals the first envelope only. The endpoint and client id are the operator's configuration: the broker ships
   no default for Anthropic's, which is undocumented, and the configuration refuses a
   `token_endpoint` that is not `https`. Without a `refresh` block the delegation lives as
   long as its token: a claim whose TTL would outlast the token's `expires_at` is
   `400 delegation_expires_first` rather than a claim that stops minting halfway.

6. **The CLI reads the person's session; it never keeps, prints or logs it.**
   `mediatore sandbox create --delegate <audience>=<source>` fills a delegation from a named
   source, read at that moment and sent once over TLS: `claude-code` reads Claude Code's own
   store (the Keychain item on macOS, the credentials file elsewhere: the access token, the
   refresh token, the expiry); `env:<NAME>` reads a token from the environment (a
   `setup-token` in `CLAUDE_CODE_OAUTH_TOKEN`); `file:<path>` a file with the token alone.
   Nothing read is written to the CLI's session file, which keeps the issuer's session only.
   In the transit shape the CLI does the two steps itself: `GET /v1/delegations` for the
   sealer, the claim with the promise, `auth/jwt/login` at OpenBao with its ID token,
   `transit/encrypt` under the returned UID, the `PUT`; the OpenBao token is dropped as soon
   as the envelope exists. The CLI prints one line per delegation: the audience, the shape
   ("sealed here, at <openbao address>" or "sealed by the broker") and the sandbox.

7. **The jail sees the phantom, and the workload says which variable wants it.** The guest
   sets nothing audience-specific; the image's entrypoint, or the argv, maps
   `MEDIATORE_TOKEN` to what the tool reads: for Claude Code,
   `CLAUDE_CODE_OAUTH_TOKEN=$MEDIATORE_TOKEN` and
   `ANTHROPIC_BASE_URL=$MEDIATORE_EGRESS_PROXY/api.anthropic.com`, so it sends
   `Authorization: Bearer <phantom>` and its own `anthropic-beta` header, and the proxy
   swaps the phantom for the delegated bearer on the route (ADR-0025 decision 3). An example
   image carrying Claude Code with that entrypoint joins `examples/`.

8. **The shadow comparison treats it as an audience.** A `delegated` audience is in the
   bundle like any other (`audiences[].name`, access, TTL, endpoints, rules); its `max_ttl`
   enters the `P002` comparison. notaio's K3.1 (credential delivery) stays at the brokered
   step: the credential is placed outside the jail.

9. **Rejected.** Copying the session store into the jail or its environment (R-3 reopened:
   the hostile process holds a subscription-wide, long-lived credential, and the claim's end
   revokes nothing). A `setup-token` held by the operator as a `via: secret` Secret for
   everyone (one person's subscription spent by every subject, against the terms it was
   issued under, and attribution lost). Waiting for federation (the right end state for an
   organisation's API usage, with no path for a person's subscription). Sending the
   delegation on every `POST /v1/token` from the CLI (the CLI is not online for the claim's
   life; the broker is). A client-chosen binding context so the desktop could seal before
   the sandbox exists (a context that travels with the ciphertext opens on any sandbox the
   broker is told it belongs to; the two-step claim keeps the UID as the context instead).

### STRIDE, per boundary

| Threat | Category | Control |
| --- | --- | --- |
| The delegation read from the wire, in transit from the CLI | I | TLS to the user API as for the issuer's refresh token (ADR-0013); sent once, in the claim body, never in a query or a header; in the transit shape it is ciphertext already, bound to the sandbox UID |
| The broker's claim path holding the plaintext | I | in the transit shape it never does: the envelope arrives sealed and is opened at token time alone; in the local shape it is sealed before the record is written and never logged |
| A requester's OpenBao token stolen from the desktop | E | encrypt-only policy on the one transit key, a `jwt` role bound to the broker's client id and the requesters' group, a short TTL; it can seal envelopes and read none, and the derived key voids an envelope on any other sandbox |
| A pending delegation never completed, or completed by someone else | D/S | `DelegationsPending` blocks the bind; the grace releases the sandbox as failed; the `PUT` is accepted from the claim's subject alone, for a pending audience alone, once |
| The delegation at rest in etcd | I | a `Sealed` envelope only, key id, nonce, AES-256-GCM with the sandbox UID as associated data, the key with the local sealer or in OpenBao transit; an envelope copied onto another sandbox's Secret does not open (ADR-0012, ADR-0034 TB-9) |
| The bearer read from the proxy's memory on the member | I | the proxy runs as the sandbox user outside the jail, keeps the bearer for at most `max_ttl`, and the member is destroyed with the claim (ADR-0025, ADR-0021) |
| The jailed workload spends the bearer elsewhere | E | it never has it: the phantom is what the jail holds, the proxy forwards only to the audience's endpoints under the audience's rules through a gateway authorized on the claim (ADR-0025, ADR-0028) |
| A delegation replayed for another sandbox or after release | S | the envelope opens for its sandbox UID alone; `take` flips the Secret to `claimed` once; release and revocation empty it; the sweep deletes it |
| The broker's log leaking the token | I | the audience, the expiry and the subject are logged; the token, the refresh token and the envelope never (the rule every backend obeys) |
| A refresh endpoint substituted by configuration | T | `https` only; the operator's value, reviewed with the overlay; a refresh error is `503` on the request that needed it and revokes nothing |
| The person's session used by a workload that is not Claude Code | R | not distinguishable by the broker; the policy's rules bound the calls to the Messages API; the terms are the operator's to honour, recorded as an accepted risk |
| A delegation that outlives the claim's deadline, left sealed | I | `expires_at` bounds the token's use; the envelope is emptied at release and deleted at the sweep; without `refresh` the claim cannot outlast the token (decision 5) |

## Consequences

- `crates/mediatore-proto`: `ClaimRequest.delegations: Vec<Delegation>`
  (`audience`, `token: Option<Secret>`, `refresh_token: Option<Secret>`,
  `expires_at: Option<DateTime>`, `pending: bool`), `ClaimResponse.sandbox_uid`,
  `DelegationEnvelope` for the `PUT` (`key_id`, `ciphertext`, `expires_at`), the
  `GET /v1/delegations` answer (the sealer kind, the OpenBao address, mount and key);
  `TokenResponse` unchanged (ADR-0032 already carries `header` and `extra_headers`).
  `crates/mediatore-entra`: `Backend::Delegated`. `crates/mediatore`: `via: delegated`,
  `header`, `extra_headers`, `refresh { token_endpoint, client_id, scope }`; refused on an
  issuer; `token_endpoint` must be `https` outside `dev_mode`.
  `crates/mediatore-store`: `SessionRecord` gains `audience: Option<String>` (`None` is
  the issuer's session), `put_session`/`take_session`/`delete_session` keyed by sandbox UID
  and audience; the conformance suite covers both. `crates/mediatore-claims`: the Secret
  per delegation in `KubeStore`, the reconciler claiming every parked envelope of a sandbox
  with the record, the sweep deleting them, the `DelegationsPending` condition and the
  grace in the reconciler (`delegations.grace_secs` in the config). `crates/mediatore-api`:
  the delegation sealed at `POST /v1/claims` or promised there and completed by the `PUT`
  (every refusal of decision 2), `GET /v1/delegations`, opened at `POST /v1/token`,
  refreshed under decision 5, emptied at release. `crates/mediatore-store`: the transit
  sealer accepts an envelope it did not produce (`key_id` naming its own mount and key) and
  opens it with the sandbox context. `crates/mediatore-client` and the CLI: `--delegate`, the
  three sources, the Keychain read through the `security` tool on macOS and the file
  elsewhere, the OpenBao `jwt` login and `transit/encrypt` in the transit shape, with the
  one-line notice per delegation. `deploy/`: an example OpenBao policy and `jwt` role for
  requesters beside the broker's (the store guide's section); the homelab moves its broker
  to the transit sealer, which is where the shape is proven live.
  `examples/claude-code/`: the image and its entrypoint.
- Tests first: `e2e_dev.rs` (a claim with a delegation minting the bearer with its headers;
  the refusals of decision 2; `delegation_expires_first`; a revoked claim refused; the
  envelope emptied after release; the pending claim that binds only after the `PUT`, the
  grace releasing one that never completes, a `PUT` by another subject refused) against the
  testkit's fake OpenBao, which gains `transit/encrypt` and the `jwt` login, the conformance suite (sessions per audience), the config tests
  (an issuer refusing `delegated`, the `https` rule), a unit on the Keychain and file
  readers with fixtures (never a real store). Phase 2 adds the refresh against the
  testkit's fake OAuth server (rotating and non-rotating refresh tokens).
- Docs: the audiences section of the Entra path guide, requesting a sandbox (`--delegate`),
  the end-to-end Claude guide (a section H, the person's session beside the operator's
  key), the research-agent walkthrough's cast, README's status table, the Claude Code
  example; the threat model: a new asset (the person's delegated upstream session, beside
  A-2), TB-1 (the delegation in the claim body) and TB-9 (the Secret per delegation) rows,
  an accepted risk (the session spent by a workload that is not Claude Code), a full pass
  and the stamp. CALM: the user API relation gains the delegation.
- Phases: (1) the local shape, token-only, the three sources, the example image, the live
  run with Claude Code in the jail recorded in `docs/guides/testing.md`; (2) the transit
  shape: the homelab broker on the transit sealer, OpenBao's requester door on the tailnet,
  the two-step claim, the live run again with the envelope sealed on the desktop and
  OpenBao's audit line beside the broker's; (3) refresh, once the endpoint is known and
  configured; federation stays ADR-0032 decision 7's roadmap item for API usage.
