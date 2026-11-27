<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0003: Two token backends, chosen per audience

**Status:** Implemented · **Date:** 2026-09-26 · **Implemented:** 2026-10-16 (both backends in
`crates/mediatore-entra`, `enum Backend`: `sts` with [ADR-0013](0013-dex-session-delegation.md)
on 2026-10-14, `entra-obo` with [ADR-0016](0016-entra-on-behalf-of.md) on 2026-10-16, proven
against the fake IdP; the live runs are roadmap 04's) · **Amended:** 2026-11-08 (a third backend,
`secret`, an operator-held credential placed by the proxy:
[ADR-0032](0032-operator-held-credentials-as-an-audience-backend.md)); 2026-11-08 (`none`, a
route without a credential: [ADR-0025](0025-phantom-token-egress-proxy.md) decision 8);
2026-11-10 (a fourth backend, `delegated`, the requester's own session for an audience:
[ADR-0035](0035-a-requesters-own-session-delegated-at-claim-time.md)) · **Amended:** 2026-11-27 by [ADR-0071](0071-sub-qualified-by-issuer-when-the-broker-trusts-several.md) (the STS token's `sub` carries its issuer's `subject_prefix` when one is set)

## Context

At work, downstream APIs are Entra-protected and need Entra tokens: only On-Behalf-Of can
produce a delegated token for them. In a homelab, Dex bridges GitHub and has no OBO. In both
cases the sandbox must never hold the user's original token.

## Decision

Each configured audience names its backend:

- `entra-obo`: mediatore is a confidential client with a certificate credential; tokens come
  from Entra, refresh material is stored encrypted and never returned.
- `sts`: mediatore signs its own ES256 tokens with an RFC 8693 `act` claim naming the claim
  SVID as actor; downstream services validate against mediatore's JWKS. Before every issue,
  mediatore refreshes the upstream (Dex) session so revocation upstream propagates.

Tokens are capped at 15 minutes, one audience each, and issued only to a peer whose SVID is
the claim's SPIFFE ID.

*Amended:* the two backends above are now five, each a variant of `Backend` in
`crates/mediatore-entra/src/lib.rs`: `entra-obo` and `sts` as decided here; `none`
(2026-11-08, ADR-0025 decision 8: an audience reached through the proxy with no credential);
`secret` (2026-11-08, ADR-0032: an operator-held credential placed by the proxy);
`delegated` (2026-11-10, ADR-0035: the requester's own credential, delegated with the claim
and placed by the proxy). The three later ones are never an issuer's backend.



## Consequences

- One build serves both environments; the difference is configuration.
- The `sts` backend is usable at work for services that validate JWTs, reducing Entra app
  registrations.
- mediatore is a single point of trust; see the threat model for mitigations.
- *Added 2026-11-19:* an `sts` token lives for the shortest of fifteen minutes, its own
  audience's `max_ttl` and the time left on the claim, and no backend states an expiry later
  than the claim's.
