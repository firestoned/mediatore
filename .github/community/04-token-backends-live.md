<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 04: Token backends live

**Status: in progress.** Both delegation paths issue real tokens (runbook Parts 4/4b);
deletes threat-model accepted risk **R-2**. The Dex half is built
([ADR-0013](../../docs/adr/0013-dex-session-delegation.md), 2026-10-14); the Entra half and
the transit sealer are the next slices.

- [x] Dex path first (everything before OBO is testable without Entra): the refresh token
      is delegated with `POST /v1/claims`, sealed with the `AgentSandbox` UID into a
      `sessions` row and moved into the record by the reconciler; every `POST /v1/token`
      refreshes it first (rotation re-sealed, the fresh groups minted) so upstream
      revocation propagates, then mints STS (ADR-0013; `crates/mediatore/tests/e2e_session.rs`)
- [x] `mediatore login` (PKCE with a loopback redirect, as mediatore's own public
      client; `offline_access` for the refresh token), `sandbox create` (delegates and
      forgets the refresh token), `sandbox get`, `sandbox delete`, `session`
      (`crates/mediatore-client`, tested against the fake issuer's authorization-code
      flow; subcommands of the one binary since ADR-0014)
- [x] Refusal handling: `invalid_grant`, a fresh ID token outside the group, or one naming
      another subject releases the claim at once (entry retracted, record revoked,
      envelope dropped) and answers `403 session_revoked`; an issuer outage is
      `503 upstream_unavailable` and revokes nothing (runbook 5.6 rule 5)
- [x] Per-claim rate limiting on `/v1/token`: a token bucket per claim UID,
      `token.rate_per_minute` (default 10), `429 rate_limited` before any upstream call
- [ ] Dex in kind (`make kind-e2e-dex`): the same flow against a real Dex with a static
      password connector, the CLI driven from inside the cluster; the runbook 8.7
      negative case "Dex org removal" becomes a group change there
- [ ] Entra OBO: client_assertion signing (key via OpenBao transit or file for now),
      first exchange at claim creation, refresh within TTL, 15-minute re-issue cap
- [ ] OpenBao transit `Sealer` (ADR-0012 decision 3): the work shape, where the broker
      never holds the wrapping key; the local key file stays the homelab shape
- [ ] Negative tests from runbook 8.7 that need real backends (revoked Entra session)
