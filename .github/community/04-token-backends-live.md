<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 04: Token backends live

**Status: in progress.** Both delegation paths issue real tokens (runbook Parts 4/4b);
deletes threat-model accepted risk **R-2**. The Dex half is built
([ADR-0013](../../docs/adr/0013-dex-session-delegation.md), 2026-10-14), the transit
sealer ([ADR-0015](../../docs/adr/0015-transit-sealer.md), 2026-10-15) and the Entra half
([ADR-0016](../../docs/adr/0016-entra-on-behalf-of.md), 2026-10-16) too; what is left is
the live run against a tenant, by hand.

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
- [x] Dex in kind (`make kind-e2e-dex`, 2026-10-15): a real Dex over TLS the broker
      verifies with `issuers[].ca_file`, a glauth directory behind its LDAP connector, the
      real CLI driven from a pod by the testkit's `dex-driver` (`mediatore login --ca-file`
      with PKCE and the loopback redirect, then `mediatore sandbox create`); every issue
      refreshes at Dex first; the runbook 8.7 negative case "Dex org removal" is a group
      change in the directory, and a deleted refresh token at Dex is the other refusal
- [x] Entra OBO (ADR-0016, 2026-10-16): the caller's access token exchanged On-Behalf-Of
      at claim creation (`offline_access` plus the first `entra-obo` audience's resource,
      mediatore's own when the claim names none), the refresh token sealed and parked like
      a Dex session; every issue a `refresh_token` grant for the audience's resource, the
      token for mediatore itself validated like a login for an `sts` audience, Entra's
      token handed over unread for an `entra-obo` audience, no re-issue and no cache (the
      "15-minute cap" is Entra's own lifetime, reported as is); the client assertion
      PS256 with `x5t#S256`, signed by a key file, by OpenBao transit (`sign`, PSS) or
      presented as a federated ServiceAccount token, exercised at startup; the fake
      issuer playing Entra and the fake OpenBao signing (`crates/mediatore/tests/e2e_entra.rs`)
- [x] OpenBao transit `Sealer` (ADR-0015, 2026-10-15): the work shape, where the broker
      never holds the wrapping key; a derived transit key with the binding UID as context,
      Kubernetes auth with a projected token (audience `openbao`), a startup probe, an
      outage as `503 sealer_unavailable`; every kind tier runs the broker on the OpenBao
      `make kind-openbao` brings up; the local key file stays the homelab shape
- [x] Issuer profiles (ADR-0017, 2026-10-21): the session path is any OIDC issuer, not
      Dex's alone; `mediatore login --scope/--auth-param/--client-secret-file`, the
      secret on refreshes, `groups_claim`; Google and Auth0 as fake profiles with the
      real login code run against them (`crates/mediatore/tests/e2e_issuers.rs`); the
      issuers guide covers GitHub-through-Dex, Google, Auth0 and Entra
- [ ] The live run against a tenant (`crates/mediatore/tests/live_entra.rs`, ignored,
      by hand): the exchange, the refresh for mediatore's own resource, the refresh for
      a downstream audience, a revoked Entra session answering `invalid_grant`; the
      negative cases of runbook 8.7 that need the real backend. Until it is green the
      threat model keeps R-2 as "proven against the fake only"
