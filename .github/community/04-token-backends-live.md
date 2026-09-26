<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 04: Token backends live

**Status: not started.** Both delegation paths issue real tokens (runbook Parts 4/4b);
deletes threat-model accepted risk **R-2**.

- [ ] Dex path first (everything before OBO is testable without Entra): store the Dex
      refresh token at claim creation, refresh-before-issue on every `POST /v1/token`
      so upstream revocation propagates, then mint STS
- [ ] `mediatore-cli login` (PKCE against Dex, `audience:server:client_id:mediatore`
      cross-client scope)
- [ ] Entra OBO: client_assertion signing (key via OpenBao transit or file for now),
      first exchange at claim creation, refresh within TTL, 15-minute re-issue cap
- [ ] Refusal handling: upstream refuses → revoke row + delete entry in one step
      (runbook 5.6 rule 5)
- [ ] Per-claim rate limiting on `/v1/token`
- [ ] Negative tests from runbook 8.7 that need real backends (revoked Entra session,
      Dex org removal)
