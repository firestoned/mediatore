<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0017: Issuer profiles: any OIDC issuer on the session path, Entra on its own

**Status:** Accepted · **Date:** 2026-10-21

Corrects the framing of [ADR-0013](0013-dex-session-delegation.md) and
[ADR-0016](0016-entra-on-behalf-of.md), and closes the gaps that kept Google and Auth0
from working as banlieue's own documentation says they do.

## Context

ADR-0003 chose the backends by audience: the `sts` backend for services that validate
mediatore's own tokens, `entra-obo` for Entra-protected APIs. The issuer side was written
as if there were two issuers in the world: "the Dex path" (ADR-0013) and "the Entra path"
(ADR-0016). That is not the model banlieue runs with. banlieue's claim subject policy
accepts whatever OIDC issuer the API server trusts, and its developer guide covers three:
GitHub, which is OAuth2 only and therefore sits behind Dex; Google; and Auth0, both genuine
OIDC providers that need no Dex. A corporate tenant on Entra is a fourth.

mediatore's issuer model was already generic (`issuers[].url`, `client_id`,
`subject_claim`, `required_group`, `session`, `ca_file`), and the session path of ADR-0013
is the OAuth refresh grant of a public PKCE client, which Google and Auth0 both serve. What
was missing was small and specific:

- `mediatore login` asked for one fixed scope set (`openid profile email groups
  offline_access`). Google refuses `offline_access` as a scope and issues a refresh token
  only when the authorization request carries `access_type=offline` (and `prompt=consent`
  to get one again). Auth0 takes `offline_access` and often wants an `audience`.
- Google's token endpoint wants the client secret of an installed-app client, PKCE or not.
  That secret is not confidential (it ships in every copy of the app); it is still a
  parameter the login and every refresh must carry.
- The group gate read `groups` and `roles`. Auth0 can only put groups under a namespaced
  custom claim; Google has no groups claim at all.
- Neither issues `preferred_username`; the subject is `email` there, which banlieue's
  policy already prefixes per issuer (`google:`, `auth0:`) when it compares usernames.

## Decision

**1. One session path, any OIDC issuer.** An issuer with a `session` block is any OIDC
provider that serves the authorization-code flow with PKCE to a public client and the
`refresh_token` grant on what it issued. Dex (with GitHub or LDAP behind it), Google and
Auth0 are that; the fake issuer plays each as a profile. Entra is the only issuer with its
own path, because only it exchanges a token On-Behalf-Of (ADR-0016). The documentation
says "session issuer", not "the Dex path", from here on.

**2. The login's parameters belong to the issuer, so the CLI takes them.** `mediatore
login` gains `--scope` (repeatable; the former fixed set is the default), `--auth-param
key=value` (repeatable, appended to the authorization request) and `--client-secret-file`.
The library's `LoginOptions` carries the same three. The session file keeps storing the
client id and the tokens only: the secret is read for the one login and dropped.

**3. The broker carries the same secret on refreshes.** `issuers[].session` gains
`client_secret_file`; when set, the secret is read at startup and sent as `client_secret`
on every refresh at that issuer, as Google wants. It is kept in a Secret volume like any
other file the broker reads, logged never, and treated by the threat model as what it is:
a parameter, not a credential.

**4. The groups claim is configurable.** `issuers[].groups_claim` names the claim the
gate reads when it is not `groups` or `roles`; when set, only that claim is read. Auth0
deployments name their namespaced claim; Google deployments leave `required_group` unset
and gate on who may log in at Google (Workspace domain, the `hd` claim) or on nothing,
which the issuers guide says plainly.

**5. The fake issuer has profiles.** `FakeIdp::start_as(Profile::Google | Auth0)` mints
the identity those providers do (`email` and a numeric or `auth0|` `sub`, no username;
groups under the namespaced claim for Auth0, none for Google), refuses `offline_access`
and wants `access_type=offline` and the registered client secret in the Google profile,
and is as strict as the provider in each. The CLI's login, the broker's refresh and the
group gate run against both in `make check`.

## Consequences

- `crates/mediatore-client`: `LoginOptions.extra_params`, `.client_secret`; the three
  flags; the token exchange sends the secret when given.
- `crates/mediatore-entra`: `SessionConfig.client_secret_file`, `IssuerConfig.groups_claim`,
  `Validator::with_session_secret`; the refresh grant carries the secret; the gate reads
  the named claim.
- `crates/mediatore-testkit`: `Profile`, `FakeIdp::start_as`, `set_client_secret`,
  `AUTH0_GROUPS_CLAIM`.
- Tests: `crates/mediatore/tests/e2e_issuers.rs` (Google and Auth0 through the real login
  code, the claim, the refresh with the secret, revocation, the group gate on the
  namespaced claim), the client's login unit test, a config test.
- Docs: an issuers guide (`docs/guides/issuers.md`: Dex with GitHub, Google, Auth0, Entra,
  what each needs registered and what `subject_claim` and `groups_claim` to set), the
  "Dex path" wording replaced across the README, the guides and the threat model.
- No change to the store, the wire types, the entries or the deployment manifests.
