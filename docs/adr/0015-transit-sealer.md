<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0015: The transit sealer: OpenBao holds the wrapping key

**Status:** Accepted · **Date:** 2026-10-15

Roadmap 04, third slice. Builds the work shape that [ADR-0012](0012-persistent-store.md)
decision 3 named and deferred: a `Sealer` whose key never enters the broker process.

## Context

Since ADR-0012 every refresh token the broker keeps (the Dex sessions of
[ADR-0013](0013-dex-session-delegation.md), the Entra material still to come) rests in
the store as a `Sealed` envelope, and since ADR-0013 the broker opens one before every
token it mints. The only sealer so far is `LocalKeySealer`: AES-256-GCM under a 32-byte
key read from a Secret volume at startup and held in memory. That is the homelab shape,
and the threat model's R-4 says what it costs: a compromised broker, or anyone who can read
its Secret, holds the key that opens every envelope in the store, now and for as long as
the key stays in use. Rotating it means re-sealing every live envelope, which nothing does.

OpenBao's transit engine is encryption as a service: the key is created and kept inside
OpenBao, callers send plaintext and get ciphertext back (and the reverse), every call is
authorised by a token OpenBao issued and audited by OpenBao, and the key can be rotated
in place with old versions still readable. The broker already has an identity OpenBao can
verify without a shared secret: its Kubernetes ServiceAccount, through OpenBao's
Kubernetes auth method and a projected token with an audience of OpenBao's choosing.

## Decision

**1. `TransitSealer` implements the same `Sealer` trait over OpenBao transit.** `seal`
is `POST <mount>/encrypt/<key>`, `unseal` is `POST <mount>/decrypt/<key>`. The envelope
keeps its shape: `key_id` is `transit:<mount>/<key>`, `nonce` is empty (OpenBao owns the
nonce), `ciphertext` is the `vault:vN:...` string OpenBao returned, whose version prefix
is how a rotated key stays readable. Nothing in `ClaimRecord`, the store or the migrations
changes; the sealer chosen at startup is the only difference between the two shapes.

**2. The binding is the transit key's derivation context.** The key is created
`derived`, and the broker sends the binding UID (the sandbox UID, ADR-0013) as `context`
on every encrypt and decrypt, so an envelope moved onto another claim does not open:
OpenBao derives a different key for a different context and the decrypt fails, which is
the same guarantee the local sealer gets from associated data. A key created without
`derived` refuses a context, so a mis-created key fails the first seal, never silently
drops the binding.

**3. The broker authenticates as its ServiceAccount, with a token meant for OpenBao.**
`store.sealing.transit.token_file` is a projected ServiceAccount token with audience
`openbao` (the base Deployment mounts it at `/var/run/secrets/openbao/token`), which the
broker exchanges at `auth/kubernetes/login` for role `store.sealing.transit.role`. The
OpenBao client token is kept in memory with its lease and exchanged again before it
expires, or at once when OpenBao answers 403. No OpenBao token, no shared secret and no
key material is ever in a Secret or on disk: what the broker holds is a short-lived
capability to use the key, which the OpenBao administrator can cut by deleting the role.

**4. Startup fails closed, over TLS the broker verifies.** `store.sealing.transit.url`
must be `https` outside `dev_mode`, and `ca_file` names the CA OpenBao's certificate
chains to (nothing else is trusted for it, as for an issuer's `ca_file`). At startup the
sealer logs in and seals and unseals a probe under a random binding, so a wrong role,
policy, mount, key name or a key created without `derived` stops the process, not the
first claim. An OpenBao outage later is what it is today for a store outage: the claim
that needs the envelope fails that request, nothing is minted on a plaintext the broker
does not have.

**5. One sealer, chosen by configuration.** `store.sealing` holds exactly one of
`key_file` (the local sealer) or `transit` (this one); both set, or neither for a session
issuer, refuses to start. The kind tiers run the broker on transit against an OpenBao the
`make kind-openbao` target brings up (TLS, Kubernetes auth, a derived key, the policy and
the role), so the work shape is what every live tier proves; the local sealer stays the
single-replica homelab shape and keeps its unit tests. The fake in the testkit speaks
the same API (the login, the two transit calls, the context check, the 403 on a bad or
expired token) and is as strict as OpenBao.

**6. Rotation is OpenBao's, not the broker's.** `bao write -f transit/keys/<key>/rotate`
makes new envelopes `vN+1` while every older version still decrypts until the
administrator raises `min_decryption_version`; the broker re-seals a session on every
refresh anyway (ADR-0013 decision 4), so a live claim migrates to the new version within
one issue. Nothing in the broker needs to know a rotation happened.

## Alternatives considered

- **Envelope encryption with a transit-wrapped data key held by the broker**: fewer
  OpenBao calls, but the data key would again be in broker memory for its lifetime and
  rotation would again be the broker's problem. Rejected: the point is that the broker
  cannot open an envelope without OpenBao's say-so at that moment.
- **A Kubernetes Secret with an external-secrets operator**: moves where the key is
  stored, not who holds it at run time. Rejected for the same reason.
- **Vault instead of OpenBao**: the API is the same; OpenBao's licence fits the workspace
  rule and the homelab. The sealer takes a URL and a mount, so either serves.

## Consequences

- `crates/mediatore-store`: `seal::TransitSealer`, `TransitConfig`; the crate gains an
  HTTPS client (`reqwest` on the workspace TLS config).
- `crates/mediatore-testkit`: `FakeTransit`, the fake OpenBao (Kubernetes login, encrypt,
  decrypt, derived-context check, token revocation, outage).
- Config: `store.sealing.transit { url, ca_file, mount (default `transit`), key, role,
  token_file (default `/var/run/secrets/openbao/token`) }`; `store.sealing` is a choice.
- `deploy/base/deployment.yaml` mounts a projected ServiceAccount token with audience
  `openbao`; a deployment on the local sealer can leave it unused.
- Kind: `make kind-openbao` (OpenBao 2.7.1 by digest, TLS from `tls-fixture`, initialised
  and configured by the target), the broker overlay on transit, every live tier on it.
- Threat model: new boundary TB-10 (broker to OpenBao); A-10 becomes the transit key in
  OpenBao plus the broker's short-lived token; R-4 narrowed to "while its OpenBao token
  lives"; the diagram gains OpenBao.
- The broker now has an outbound dependency on OpenBao for every claim creation and every
  token issue on a session issuer: one round trip each, inside the per-claim rate limit.
