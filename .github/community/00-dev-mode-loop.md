<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 00: Dev-mode loop

**Status: done** (2026-09-26, PR #1). The full trust chain runs front to back with every
network edge faked and fail-closed, so each later roadmap replaces one fake with the
real thing behind an existing trait.

- [x] Wire types + username derivation (`mediatore-proto`, ADR-0004)
- [x] Upstream token validation: JWKS discovery, cache, kid rotation, `aud`/group gates (`mediatore-entra`)
- [x] STS: ES256, RFC 8693 `act`, JWKS derived from the signing key (`mediatore-sts`)
- [x] Claim lifecycle: create / dev-bind (either order) / mirror / release (`mediatore-api`, `mediatore-claims`)
- [x] Node registry with cloned-EK 409 (`mediatore-store` in-memory)
- [x] Guest agent lifecycle: register → poll `/v1/me` → user → nsjail supervision → teardown (`mediatore-guest`; jail path needs a Linux host)
- [x] `sandbox-token` CLI (dev header transport)
- [x] 10-test e2e over real HTTP + `make e2e` demo with real binaries (`fake-idp`)
- [x] ADD infrastructure: ADR-0001..0005, CALM + drift gate, threat model, rules, CI suite

What it deliberately did not do: real peer identity (roadmap 01), a real SPIRE server
(roadmap 02), real claims (roadmap 03), real token exchange (roadmap 04), durable state
(roadmap 05).
