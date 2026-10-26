<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# The Entra path

At work the issuer is Entra ID and the downstream APIs want Entra tokens. mediatore gets
them On-Behalf-Of the user ([ADR-0016](../adr/0016-entra-on-behalf-of.md)): the access
token a caller presents to `POST /v1/claims` is exchanged once for a refresh token issued
to mediatore for that user, that session is sealed into the claim's record like a Dex
session ([ADR-0013](../adr/0013-dex-session-delegation.md)), and every `POST /v1/token`
refreshes it for the audience's resource before anything is handed out. This page is the
operator's side: the app registration, the broker's credential, the configuration, and
the proof against a tenant.

## What Entra needs to know about mediatore

One app registration for the broker. On it:

- **Expose an API** with a delegated scope (`sandbox.access`, say) and set
  `accessTokenAcceptedVersion` to `2`, so the tokens callers present carry `aud` equal to
  the application (client) id. That id is `issuers[].client_id`: the required `aud` of a
  login and the client mediatore authenticates as.
- **API permissions**: a delegated permission on every downstream API the audiences name
  (`api://trading-data/.default` for an audience `api://trading-data`), with admin
  consent, so the exchange needs no user interaction.
- **Known client applications** or pre-authorised clients: the Azure CLI, an
  orchestrating agent, whatever obtains the user's token for mediatore (the paths A, B
  and C of [running workloads](running-workloads.md)).
- **Groups or app roles in the token**, if `required_group` is set: the gate reads
  `groups` and `roles` from the login and from every token Entra mints for mediatore.
- **A credential**, one of the three below.

The caller's token must be an access token for mediatore, never an ID token: Entra
refuses to exchange one. `az account get-access-token --scope <client id>/.default` is
the simplest way for a person to get one.

## The broker's credential

mediatore authenticates at the token endpoint with a client assertion: a JWT it signs
with `PS256`, naming the registered certificate by `x5t#S256`, addressed to the token
endpoint and good for five minutes. Where the signature comes from is the choice under
`issuers[].entra`, exactly one of:

```yaml
issuers:
  - url: https://login.microsoftonline.com/<tenant>/v2.0
    backend: entra-obo
    client_id: <broker app id>
    subject_claim: oid
    required_group: <group object id>
    entra:
      certificate_file: /etc/mediatore-entra/cert.pem   # the certificate on the app
      key_file: /etc/mediatore-entra/key.pem            # its RSA key, from a Secret
```

**A key file** (above): an RSA-2048 or larger private key in PKCS#8 or PKCS#1 PEM, the
homelab shape. `openssl req -x509 -newkey rsa:3072 -nodes -keyout key.pem -out cert.pem
-subj /CN=mediatore -days 365` makes both; upload `cert.pem` under the app's
*Certificates & secrets*.

**OpenBao transit**: the key lives in the transit engine and never enters the broker,
the work shape, with the same Kubernetes login as the [transit sealer](the-store.md):

```yaml
    entra:
      certificate_file: /etc/mediatore-entra/cert.pem
      transit:
        url: https://openbao.home.example:8200
        ca_file: /etc/mediatore-openbao/ca.pem
        key: mediatore-entra        # bao write -f transit/keys/mediatore-entra type=rsa-3072
        role: mediatore
```

The broker's policy needs `update` on `transit/sign/mediatore-entra`. The certificate
has to be the key's: `bao write transit/keys/mediatore-entra/csr csr=@template.pem`
signs a request without releasing the key, and any CA (or the request signed by the
same key as a self-signed certificate, where the CA allows it) turns it into the file to
register and to name in `certificate_file`.

**A federated credential**: no key anywhere. On AKS, or any cluster whose OIDC issuer
Entra can reach, add a federated credential on the app naming the cluster's issuer, the
subject `system:serviceaccount:banlieue-system:mediatore` and the audience
`api://AzureADTokenExchange`, project a token with that audience into the pod, and point
at it:

```yaml
    entra:
      token_file: /var/run/secrets/entra/token
```

Whatever the shape, the broker exercises it at startup: a probe assertion is signed and
verified against the certificate (or the token file is read), so a key that is not the
registered certificate's, a wrong transit role or key, or an unreadable file stops the
process, not the first claim. `key_file` and `transit` need `certificate_file`;
`token_file` refuses one. `transit.url` must be `https` outside `dev_mode`.

## Audiences

```yaml
audiences:
  - { name: api://trading-data, via: entra-obo, egress: ["api.trading.example:443"] }
  - { name: grafana.home.example, via: sts, max_ttl: 900, egress: ["grafana.home.example:443"] }
```

`egress` is where the workload reaches the audience's API from the jail ([ADR-0020](../adr/0020-jail-network-nftables-keyed-by-sandbox-uid.md)): the
guest admits those `host:port` pairs for the sandbox uid and nothing else beyond the
broker and DNS. Without it the jail reaches the broker only.

An `entra-obo` audience is the downstream app's id URI (or client id); the token
mediatore hands the workload is Entra's for `<name>/.default`, with the lifetime Entra
gave it (the tenant's token lifetime policy, an hour by default), reported in
`expires_at`. An `sts` audience on a claim from an Entra login works as on the session path:
the session is refreshed for mediatore's own resource, the token Entra returns is
validated like a login, its groups are minted into the STS token. An `entra-obo`
audience needs an Entra issuer in the configuration, and a claim from any other issuer
asking for one is refused with `400 audience_needs_entra`.

## What a claim does

| Moment | Call to Entra | On refusal |
| --- | --- | --- |
| `POST /v1/claims` | On-Behalf-Of exchange of the bearer, `offline_access` plus the first `entra-obo` audience's `/.default` (mediatore's own when the claim names none); the refresh token is sealed and parked under the sandbox UID | `403 session_refused` with Entra's code (`invalid_grant`, `interaction_required`, `consent_required`); no sandbox. Anything else `503 upstream_unavailable` |
| `POST /v1/token` for an `entra-obo` audience | `refresh_token` grant, `offline_access <audience>/.default`; the access token goes to the workload unread, the refresh token is re-sealed | `403 session_revoked`, the claim released at once. An outage `503`, nothing revoked |
| `POST /v1/token` for an `sts` audience | `refresh_token` grant, `offline_access <client_id>/.default`; the token is validated (signature, `aud`, group gate, subject), then the STS mints with its groups | the same, and a login that left the group releases the claim here |

A sandbox created declaratively has no bearer to exchange and therefore no session;
`POST /v1/token` refuses it as it refuses a Dex record without an envelope. The
per-claim rate limit (`token.rate_per_minute`) sits ahead of every call, so a looping
workload cannot turn the broker into a refresh hammer against the tenant.

## Proving it against a tenant

Entra does not run in kind. `crates/mediatore/tests/live_entra.rs` is the live proof,
ignored by default and failing loudly when its fixture is missing:

```sh
MEDIATORE_LIVE_ENTRA_ISSUER=https://login.microsoftonline.com/<tenant>/v2.0 \
MEDIATORE_LIVE_ENTRA_CLIENT_ID=<broker app id> \
MEDIATORE_LIVE_ENTRA_CERTIFICATE_FILE=cert.pem \
MEDIATORE_LIVE_ENTRA_KEY_FILE=key.pem \
MEDIATORE_LIVE_ENTRA_USER_TOKEN=$(az account get-access-token --scope <broker app id>/.default --query accessToken -o tsv) \
MEDIATORE_LIVE_ENTRA_AUDIENCE=api://trading-data \
cargo test -p mediatore --test live_entra -- --ignored --nocapture
```

It validates the user's token, runs the exchange, refreshes for mediatore's own resource
and checks the subject is the same user, refreshes for the audience, and confirms a bogus
refresh token is a refusal rather than an outage. `MEDIATORE_LIVE_ENTRA_TOKEN_FILE` in
place of the certificate and key runs it with a federated credential. Nothing secret is
printed. Until this run is green against a tenant, the threat model lists the Entra path
as proven against the fake issuer only (accepted risk R-2).

The fake issuer the suite runs against (`crates/mediatore-testkit`) speaks the same
protocol and is as strict as Entra where it matters: it refuses an exchange without a
client assertion or with one it has seen before, an assertion that is not an access
token for the client, a scope naming two resources, and it returns a refresh token only
with `offline_access`.
