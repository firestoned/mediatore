# ADR-0003: Two token backends, chosen per audience

**Status:** Proposed · **Date:** 2026-09-26

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

## Consequences

- One build serves both environments; the difference is configuration.
- The `sts` backend is usable at work for services that validate JWTs, reducing Entra app
  registrations.
- mediatore is a single point of trust; see the threat model for mitigations.
