<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Claude Code as a sandbox workload

Claude Code inside the jail, under your own Claude session (ADR-0035): the broker holds the
session sealed, the proxy outside the jail places it, and Claude Code in the jail only ever
holds the phantom. Build and mirror the image as the research agent is
(`make claude-code-image`, then push by digest to the registry your pool reaches), then:

```sh
mediatore login --issuer https://dex.home.example
mediatore sandbox create --mediatore https://mediatore.home.example --pool sandbox-pool \
  --audience anthropic --policy claude-agent --ttl 900 --restart never \
  --delegate anthropic=claude-code \
  --image registry.internal:5000/firestoned/claude-code@sha256:<digest> \
  --arg /usr/local/bin/claude-sandbox --arg=-p --arg "Summarise what /work holds"
```

`--delegate anthropic=claude-code` reads the session `claude login` left on your machine
(the Keychain on macOS, `~/.claude/.credentials.json` elsewhere) and sends it once with the
claim; `env:CLAUDE_CODE_OAUTH_TOKEN` takes a `claude setup-token` instead. The audience
`anthropic` must be `via: delegated` on the broker, with `anthropic-beta: oauth-2025-04-20`
among its `extra_headers` if the policy's rules let a bare SDK through; Claude Code sends
that header itself.

Two things the live run taught (`docs/guides/testing.md`, run 8):

- **The guest must be at ADR-0036 or later** (mediatore v0.2.2). Claude Code, like most
  Node programs, reads `/proc/self` on start; a jail without `/proc` fails it within a
  second with `Can't access working directory /work: Path "/work" does not exist`, the
  directory being there all along. The jail's `/proc` shows the workload's own processes
  and nothing else.
- **The Keychain session is fresh for eight hours after `claude auth login`.** Claude Code
  refreshes its access token in memory and does not write the refreshed one back to the
  Keychain item the `claude-code` source reads, so a session logged in yesterday is refused
  by the CLI ("the credential expired at ...") although `claude` itself still works. Run
  `claude auth login` again, or use `env:CLAUDE_CODE_OAUTH_TOKEN` with a `claude setup-token`.
  ADR-0035 phase 3, the CLI refreshing with the refresh token it already reads, removes
  this step.

The script `claude-sandbox` is the whole of the sandbox machinery in the image: it sets
`PATH` (the jail sets none), `CLAUDE_CODE_OAUTH_TOKEN` from the phantom and
`ANTHROPIC_BASE_URL` to the proxy's route for `api.anthropic.com`, then runs `claude` with
the claim's arguments.
