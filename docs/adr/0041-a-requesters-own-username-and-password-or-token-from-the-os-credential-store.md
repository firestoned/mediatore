<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0041: A requester's own username and password, or token, from the OS credential store, for an audience that is not OAuth

**Status:** Accepted 2026-11-15, not yet implemented (the ADD cycle of ADR-0040 decision 10 is the order; open questions 1 and 2 are checked at implementation) · **Date:** 2026-11-15

Roadmap 04 (the backends) and roadmap 12 (the path to the upstreams). Extends
[ADR-0035](0035-a-requesters-own-session-delegated-at-claim-time.md) (`via: delegated`, the
`--delegate <audience>=<source>` CLI, one sealed envelope per delegation) in two ways: the
delegated credential may be a username and password, or a personal access token, and not only an
OAuth bearer; and the CLI gains two sources, the operating system's credential store and a prompt.
Places the credential the way [ADR-0040](0040-the-gateway-places-an-audiences-credential-the-pool-never-holds-it.md)
does (the gateway, never the pool VM) and seals it the way [ADR-0015](0015-transit-sealer.md) does.
Changes no SPIFFE ID, no entry shape, no route shape. Adds one credential shape, one header form
(HTTP Basic), three CLI sources and one `logout` command.

## Context

Two upstreams the sandbox must reach want a person's own credential, and neither is an OAuth bearer
of the kind ADR-0035 delegates:

| Upstream | How a person authenticates | What the sandbox needs to present |
| --- | --- | --- |
| `ghe.example.com` | Entra (the broker's Entra backend, ADR-0016, already exists) | a bearer, or a token minted On-Behalf-Of |
| `git.home.example` | LDAP: a user name and password; `401` without them | HTTP Basic with a user name and a password or a personal access token |

Measured 2026-11-15 on mediatore 0.2.6 with the `gitserver` policy: a request from the jail reaches
the host through the gateway over TLS 1.2 and is answered `401`. The transport is proven; there is
nothing to present. The audience has `audiences: []`, so the broker holds no credential for it.

Three questions follow, and this ADR answers each:

1. What may the CLI read on the requester's machine? A browser's cookie store is the tempting
   source (the person is already signed in) and is refused (decision 6).
2. Where does a secret that mediatore itself asks for live between runs?
3. What does the sandbox hold? Nothing: the credential is placed at the gateway (ADR-0040), and a
   password in particular must never reach a pool VM.

## Decision

1. **A delegated credential has a kind: `bearer` (today's) or `basic`.** `audiences[].via: delegated`
   gains `credential: bearer | basic` (default `bearer`, so nothing changes for an existing
   audience). `basic` places `Authorization: Basic base64(user:secret)`, where `secret` is a
   password or a personal access token; the broker does not say which and never parses it. `header`
   defaults to `authorization` and `extra_headers` keeps its meaning (ADR-0035 decision 1). A `basic`
   audience has no `refresh` block: there is nothing to renew, and the delegation lives as long as
   the claim (the check `delegation_expires_first` does not apply; the claim's TTL bounds it).

2. **A `basic` audience is gateway-placed, always.** `inject: gateway` is required for `credential: basic`
   and the configuration refuses `inject: proxy` with it (ADR-0040 decision 1 gives the whole rule set:
   exact `host:port`, `rules`, no wildcard, `max_ttl` at most 300). The reason is the credential's value:
   a password is reusable well past one claim and is likely the person's login for other systems, so the
   rule ADR-0035 accepts for a bearer ("the jail sees the phantom, the proxy holds the real token",
   ADR-0025) is not enough here. The proxy-placed shape puts the credential in a process on the pool
   VM; for `basic` that is refused. Under `inject: gateway` the pool VM never holds it, and a request
   from the jail for that audience carries no `Authorization` the client set (ADR-0040 decision 4
   overwrites it).

3. **The delegation carries a user name and a secret.**
   `delegations: [{ audience, username, secret, pending? }]` for a `basic` audience. Each secret field
   is a `Secret` the API never echoes and `Debug` never prints (ADR-0035 decision 2). The user name is
   not secret but is sealed in the same envelope, so a claim's identity at the upstream is not
   readable from the Secret. Sealing, the `pending` handshake, the `PUT
   /v1/claims/{name}/delegations/{audience}` completion, the grace period, the fail-closed refusals and
   the one-envelope-per-delegation Secret are ADR-0035 decisions 2 and 3 unchanged. In the transit
   shape (ADR-0015) the plaintext is sealed on the requester's machine and the broker never sees it
   until the gateway asks (ADR-0040 decision 2: `POST /v1/gateway/claims/{uid}/credential`, which opens
   the envelope, returns a `GatewayCredential` holding the header as a `Secret`, and logs one line
   with the claim, audience and subject, never the value).

4. **The CLI has three sources for a `basic` delegation, tried in a fixed order and never mixed.**
   `mediatore sandbox create --delegate gitserver=<source>`, where `<source>` is one of the existing
   `env:<NAME>` and `file:<path>` (ADR-0035 decision 6) and these new ones:

   | Source | Reads | Notes |
   | --- | --- | --- |
   | `store` (the default for a `basic` audience, then `prompt`) | mediatore's own item in the OS credential store | macOS Keychain, Windows Credential Manager, Secret Service (libsecret) on Linux |
   | `prompt` | the terminal | user name on one line, secret read with echo off, from a TTY only |
   | `env:<NAME>` / `file:<path>` | as ADR-0035; for `basic`, `env:` names two variables `<NAME>_USER` and `<NAME>` and `file:` a file of `user` then `secret` | for CI and for a host with no credential store |

   With no source given the order is `store`, then `prompt`, then an error that names the other two.
   It stops at the first source that has a value and never falls through after a refusal by the
   broker. A secret is **never** an argument (`--password` does not exist: argv is in shell history and
   in every process listing), and a non-TTY with no store and no `env:`/`file:` is an error, not a
   prompt that hangs.

5. **The credential store holds mediatore's own item, per audience, and only mediatore's.**
   Service `mediatore`, account `<issuer>/<audience>/<username>`, one item per audience, so a
   credential for one upstream is never offered to another. `prompt` offers to save what it just read
   (`Save to the macOS Keychain? [y/N]`, default no, never saved on a non-TTY), and a later run reads
   it without a prompt. `mediatore logout --audience <name>` deletes the item and `mediatore logout
   --all` deletes every mediatore item; both are idempotent. The item is created with the platform's
   default access control: on macOS only the `mediatore` binary's code identity is added to the item's
   access list (no "allow all applications"), so a prompt appears the first time a different binary
   asks; on Windows it is a generic credential for the current user's logon session; on Linux it
   needs a running Secret Service and, with none, the source reports "no credential store" and moves
   on. **An item lives six hours at most.** The CLI records the time it saved the item (in the item's
   own attributes, not a side file) and treats an item older than `credential_store.max_age_secs`
   as absent: it deletes it and goes on to `prompt`. The ceiling, 21600 seconds, is a constant; the
   setting may only lower it. A secret on a laptop is a long-lived credential for as long as it sits
   there, and the six hours bounds that to a working day's morning or afternoon. **macOS is the first
   and only platform built** (the Keychain, through the `security` tool as ADR-0035 does for the
   Claude item); Windows and Linux report "no credential store" and fall to `prompt` and
   `env:`/`file:` until someone who runs them tests it. The CLI reads the store through the platform API (`security` on macOS as ADR-0035 already does
   for the Claude item, the Credential Manager API on Windows, the Secret Service over D-Bus on
   Linux), writes nothing to its own session file (which keeps the issuer's session only), and logs
   the source's name, never a value.

6. **The browser's cookie store is not a source, now or later.** The CLI does not read, import or
   decrypt any browser's cookies, local storage or saved passwords, with or without a flag. Three
   reasons, each enough alone:

   - It is another application's private store. Reading it is what an infostealer does; Chrome's
     app-bound encryption and Safari's sandbox exist to prevent it, so any working implementation is
     an exploit of a protection and breaks with each browser release.
   - It carries the wrong credential. A session cookie authorizes everything the person can do on that
     site until it expires, far beyond one audience, and cannot be scoped, narrowed or revoked on
     its own.
   - It removes the person's consent: the Keychain prompt, the browser's account chooser and the
     upstream's own sign-in are the points where the person agrees to hand a credential over, and
     the cookie path skips all of them.

   When a person wants single sign-on to the upstream, the way is the upstream's own OAuth or an
   Entra On-Behalf-Of (ADR-0016), where the browser is used to sign in and mediatore receives a token
   it was granted, as `mediatore login` already does for the issuer.

7. **The LDAP password is the accepted shape; a personal access token is allowed and not required.**
   The operator has decided to delegate the person's own password for `git.home.example`, though
   the host accepts personal access tokens for Git over HTTPS, and this ADR records that as a
   decision and an accepted risk, not a recommendation to revisit. The broker cannot tell a password
   from a token and does not try (decision 1), so a person who has a token may send it with the same
   command. Because the password is the person's login for other systems, the controls around it
   carry the weight: it is gateway-placed only (decision 2), sealed to the claim (decision 3), never on
   a pool VM, in the jail, in a log or in the status, bounded by the claim's TTL, held by the CLI
   for six hours at most (decision 5), and the route's `rules` allow only the smart-HTTP read paths
   (decision 8). The CLI says once per claim that it is sending a user name and a secret, and which
   audience it is for, with no advice attached.

8. **The gateway places it as `Authorization: Basic`, over the fixed route, and nothing else.** The
   authorizer's inject answer (ADR-0040 decision 4) gains the `basic` form: it builds the header
   value as `Basic ` plus base64 of `user:secret`, sets it with `OVERWRITE_IF_EXISTS_OR_ADD`, and
   removes the other credential-bearing headers (`x-api-key`, and `authorization` when the route's
   header is another) as today. A user name containing `:` is refused at the claim (`400
   delegation_refused`: RFC 7617 forbids it in the user-id); a value with a control character is
   refused the same way. The route's `rules` bound the method and path (for `gitserver` the
   smart-HTTP read paths `GET /<org>/<repo>.git/info/refs`, `POST /<org>/<repo>.git/git-upload-pack`);
   a write path (`git-receive-pack`) is not in a policy's rules unless the operator adds it in a
   reviewed change.

9. **A `basic` audience is its own SandboxPolicy audience, with its own group.** Entra's and LDAP's
   audiences are two audiences (`ghe`, `gitserver`), each with its own `subjects.groups`, so a
   person in the Entra group has no access to the LDAP upstream by that fact (ADR-0035 and the policy
   model, unchanged). The `ExposureCeiling` for the audience lists the one `host:port` and nothing
   else, and widening it needs a Security approval in a separate pull request, as for every ceiling.

## Consequences

- A person's LDAP user name and secret reach the broker only as a sealed envelope (the transit
  shape) and the gateway only as a header for one request to one fixed host; neither the pool VM,
  the jail, the broker's log, the `AgentSandbox` status nor the API ever holds or shows the value.
- The credential store item is mediatore's own. A person can see it in their Keychain, Credential
  Manager or `seahorse`, and remove it with `mediatore logout`. If it is never saved, nothing
  persists on the machine beyond the claim.
- A claim for a `basic` audience needs the gateway's inject path (ADR-0040) to be live. Until it is,
  the broker refuses such an audience at start (decision 2), so the configuration cannot be written
  into a shape that places a password on a pool VM.
- `--delegate` now takes a source per audience kind, and the CLI's existing `claude-code`, `env:` and
  `file:` sources keep their behaviour for `bearer`. For `basic`, `claude-code` is refused.
- Windows and Linux without a Secret Service fall back to `prompt` and `env:`/`file:`; the person
  who wants no credential on disk uses `prompt` and answers `n`.
- The audience's secret is, for the claim, as exposed as the delegated envelope is: the transit
  key's derivation context is the claim's UID, so one claim's envelope opens for that claim only.

## Alternatives rejected

- **Read the browser's cookies.** Refused in decision 6: another application's store, the wrong
  credential, no consent.
- **A `--password` flag.** It lands in shell history and in `ps`. Refused in decision 4.
- **Keep the secret in the CLI's own session file.** That file keeps the issuer's session only
  (ADR-0035 decision 6); mixing audiences there would let one upstream's secret travel with another's.
- **An operator-held shared account for `gitserver` (`via: secret`, ADR-0032).** Works with no CLI
  change, and attributes every clone to one account in the upstream's own log; a person's own
  identity is the requirement (ADR-0035 context). Kept as the lab shape for a read-only mirror.
- **Place a `basic` credential at the guest's proxy.** The password would live in a process on the
  pool VM; refused in decision 2.
- **Delegate the LDAP password to the broker in plaintext and let it seal.** Allowed by ADR-0035 only
  in the local sealer shape; for `basic` the transit shape is required when the broker offers one, so
  the plaintext path is not chosen by the client (the same rule as ADR-0035 decision 2).

## What was proven, and what was not

Proven 2026-11-15 on mediatore 0.2.6, `sandbox-pool-mtest`, with `TESTING.md` T-rows kept in
`sc90-agent-sandbox/TESTING.md` section 5:

- A claim under the `gitserver` policy reaches `git.home.example:443` through the gateway over
  TLS 1.2 and the host answers `401` to `GET /org-oss/curl-curl.git/info/refs` (exit `4`).
- A claim under the `ghe` policy needs a bearer; not tested here.

Not proven: the `basic` credential kind, the credential-store source, the `logout` command, the
header form and the user-id refusal. None is implemented. The ADD cycle (ADR-0040 decision 10) is the
order: write the failing tests (a `basic` audience refused with `inject: proxy`; a user name with `:`
refused; `Basic` header built and the client's `Authorization` overwritten; the store source returns
nothing on a non-TTY with no store; the cookie path does not exist), then the code.

## Open questions

1. **Entra shape for `ghe.example.com`: decided to try On-Behalf-Of first, then the login's own token.**
   The first attempt is ADR-0016's Entra On-Behalf-Of, minted by the broker from the requester's
   issuer session: no new CLI source and no credential on the requester's machine beyond the login. If the
   app registration does not allow OBO for the GitHub Enterprise audience, the fallback is to delegate
   the token the login itself yielded (ADR-0013 and ADR-0035: the issuer session, then a bearer per claim
   for a `delegated` audience). The fallback needs a check before it is built: that the token's
   audience and scopes are the upstream's, not the issuer's own, since delegating a token meant for
   the issuer widens what the sandbox can do. For the operator to confirm which the app registration
   allows; the test is one claim against `ghe.example.com` with each.
2. **Windows and Linux.** Not built (decision 5). Whether a managed Windows machine lets a CLI write
   to the Credential Manager is for whoever runs one to find out; until then those platforms use
   `prompt`, `env:` and `file:`.
3. **Kerberos.** `proxy.home.example:8080` wants Kerberos, not Basic. It is a different shape and has
   its own ADR: [ADR-0042](0042-the-corporate-forward-proxy-through-a-kerberos-holder-on-the-gateway.md).
