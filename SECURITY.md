<!--
Copyright (c) 2026 Erick Bourgeois, mediatore
SPDX-License-Identifier: Apache-2.0
-->
# Security Policy

## Supported Versions

mediatore is pre-1.0 and under active development. Only the latest commit on
`main` and the most recent release receive security fixes.

| Version | Supported |
| ------- | --------- |
| latest release / `main` | ✅ |
| anything older | ❌ |

## Reporting a Vulnerability

Use GitHub [private vulnerability reporting](https://github.com/firestoned/mediatore/security/advisories/new).
Do not open a public issue for a security finding, and do not record specific
unremediated findings in the public [threat model](docs/security/threat-model.md).

You can expect an acknowledgement within a week. Please include the commit or
release you tested, the component (server, guest agent, workload CLI), and a
reproduction.

## What is in scope

Anything that lets a caller mint a token for a subject who did not log in, for
an audience outside a claim's allowlist, or after a claim was released; anything
that lets one sandbox read another's identity or tokens; anything that breaks
the node/claim SPIFFE identity binding.
