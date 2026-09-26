<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 07: Credential-injecting egress proxy

**Status: design reference** (runbook open decision #7; threat-model R-3's revisit
condition). Phase 2 of the delegation model: instead of handing the workload a
15-minute token it could exfiltrate, the sandbox's egress goes through a proxy that
injects the credential on the way out — the workload never sees a token at all.

Not scheduled until roadmap 04 is live and the token-in-workload model has real usage
to learn from. Design questions to answer in the ADR when this activates:

- Where the proxy runs (in-guest beside the agent vs on the host vs central) and what
  identity it holds
- How the audience is chosen per request (SNI/host allowlist vs explicit CONNECT)
- What replaces `sandbox-token` for tools that want raw tokens (nothing, ideally)
- TLS: MITM-with-installed-CA vs CONNECT-only header injection for known APIs
- What R-3 becomes afterwards (exfiltration window shrinks to the proxy's per-request
  scope)
