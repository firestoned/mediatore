<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Issuers

mediatore trusts whatever OIDC issuers its configuration names, and banlieue's claim
subject policy does the same on its side. Which backend mints a token is a property of
the audience (`sts` or `entra-obo`, [ADR-0003](../adr/0003-token-backends.md)); which
issuer a person logs in at is a property of the issuer block
([ADR-0017](../adr/0017-issuer-profiles.md)). Every issuer but Entra works the same way:
`mediatore login` runs the authorization-code flow with PKCE as mediatore's public
client, hands the refresh token over with the claim, and the broker refreshes it before
every token it mints ([ADR-0013](../adr/0013-dex-session-delegation.md)). Entra adds the
On-Behalf-Of exchange ([the Entra path](the-entra-path.md)).

The same four providers banlieue's developer guide covers, and what each needs:

| Provider | OIDC? | Dex needed? | `subject_claim` | Groups | Refresh token | Token endpoint secret |
| --- | --- | --- | --- | --- | --- | --- |
| GitHub | no, OAuth2 only | yes | `preferred_username` (the GitHub login) | `groups` (Dex's `org:team`) | `offline_access` | no |
| Google | yes | no | `email` | none; gate on who may log in at Google | `--auth-param access_type=offline --auth-param prompt=consent` | yes, the installed-app client's |
| Auth0 | yes | no | `email` | a namespaced claim, `groups_claim` | `offline_access` | no |
| Entra ID | yes | no | `oid` | `groups` or `roles` | the On-Behalf-Of exchange, nothing to delegate | the client assertion |

## GitHub, through Dex

GitHub mints no ID tokens, so Dex authenticates against it and mints one in GitHub's
name. Register a GitHub OAuth App whose callback is Dex's, put the GitHub connector in
Dex's config, and give Dex a public client for mediatore:

```yaml
staticClients:
  - id: mediatore
    name: mediatore
    public: true
    redirectURIs:
      - http://127.0.0.1/callback   # the CLI's loopback listener, any port
```

Dex accepts any loopback port for a public client. On the broker:

```yaml
issuers:
  - url: https://dex.home.example
    backend: sts
    client_id: mediatore
    subject_claim: preferred_username
    required_group: firestoned:sandbox-users    # a GitHub org:team, as Dex names it
    session: { client_id: mediatore }
    ca_file: /etc/mediatore-dex/ca.pem          # if Dex is on a private PKI
```

```sh
mediatore login --issuer https://dex.home.example
```

The kind tier `make kind-e2e-dex` runs exactly this against a real Dex (with an LDAP
directory behind it instead of GitHub) and is where a change to the session path is
proven live.

## Google

Google is an OIDC issuer (`https://accounts.google.com`) and needs no Dex. Create an
OAuth client of type **Desktop app** in the Google Cloud console; it gets a client id and
a client secret. The secret is not confidential, Google says so itself, but the token
endpoint refuses a request without it, PKCE or not. Three Google particulars shape the
configuration:

- there is no `offline_access` scope; a refresh token comes only when the authorization
  request carries `access_type=offline`, and only on the first consent unless
  `prompt=consent` is sent too;
- there is no `preferred_username` and no groups claim; the subject is `email`;
- the refresh grant wants the client secret as well.

```yaml
issuers:
  - url: https://accounts.google.com
    backend: sts
    client_id: 1234567890-abc.apps.googleusercontent.com
    subject_claim: email
    session:
      client_id: 1234567890-abc.apps.googleusercontent.com
      client_secret_file: /etc/mediatore-google/client-secret   # a Secret volume
```

```sh
mediatore login --issuer https://accounts.google.com \
  --client-id 1234567890-abc.apps.googleusercontent.com \
  --client-secret-file ~/.config/mediatore/google-client-secret \
  --scope openid --scope email --scope profile \
  --auth-param access_type=offline --auth-param prompt=consent
```

Leave `required_group` unset: there is nothing in the token to gate on. Who may log in
is decided at Google (a Workspace domain, which the token shows as `hd`); a deployment
that needs a group gate puts Dex in front of Google and uses its Google connector's
group support instead.

## Auth0

Auth0 is an OIDC issuer (`https://<tenant>.<region>.auth0.com/`, the trailing slash is
part of the issuer value) and needs no Dex. Create a **Native** application, enable the
authorization-code grant with PKCE and the refresh-token grant, allow `http://127.0.0.1`
callbacks, and on the API the login targets tick *Allow Offline Access*. Auth0 issues no
`preferred_username`, so the subject is `email`, and it puts groups in an ID token only
through an Action that adds a namespaced claim:

```js
exports.onExecutePostLogin = async (event, api) => {
  api.idToken.setCustomClaim("https://example.com/groups", event.user.app_metadata?.groups ?? []);
};
```

```yaml
issuers:
  - url: https://tenant.us.auth0.com/
    backend: sts
    client_id: aBcDeFg
    subject_claim: email
    required_group: sandbox-users
    groups_claim: https://example.com/groups
    session: { client_id: aBcDeFg }
```

```sh
mediatore login --issuer https://tenant.us.auth0.com/ --client-id aBcDeFg \
  --auth-param audience=https://mediatore.example
```

`audience` makes Auth0 issue a JWT access token for that API alongside the ID token;
mediatore uses the ID token and ignores the access token, so the parameter is only
needed when the tenant requires it.

## Entra ID

Entra is covered on its own page: [the Entra path](the-entra-path.md). The login is the
same PKCE flow (or `az account get-access-token` for a token the CLI did not obtain),
but the session is not delegated: mediatore exchanges the caller's token On-Behalf-Of.

## What stays the same everywhere

- The subject written on the sandbox is the issuer URL plus the `subject_claim` value.
  banlieue's policy prefixes usernames per issuer (`github:`, `google:`) when it compares
  a declarative requester with `spec.subject`; the token side never carries a prefix.
- The gate is `required_group` against `groups` and `roles`, or against `groups_claim`
  when set. It runs on the login and on every fresh token a refresh returns.
- A refresh refused with `invalid_grant` (and at Entra `interaction_required` or
  `consent_required`) releases the claim; an issuer outage is `503` and releases nothing.
- `ca_file` pins an issuer on a private PKI to exactly that CA, for the broker and the
  CLI (`--ca-file`) alike.

The fake issuer the suite runs against plays each provider as a profile
(`crates/mediatore-testkit`, `FakeIdp::start_as`), as strict as the provider where it
matters, and `crates/mediatore/tests/e2e_issuers.rs` runs the real login code, the
claim, the refresh and the gate against the Google and Auth0 profiles.
