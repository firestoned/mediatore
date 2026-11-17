<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0002: mediatore is a separate project, not a banlieue crate

**Status:** Accepted · **Date:** 2026-09-26 · **Amended:** 2026-10-14 by
[ADR-0008](0008-agentsandbox-crd-owned-by-mediatore.md) (mediatore serves one CRD of its
own, `AgentSandbox`); 2026-10-15 by [ADR-0014](0014-one-binary-roles-as-subcommands.md)
(the separate executables below are consolidated into the one `mediatore` binary, its
roles as subcommands; the separate repository and the `banlieue-api` pin stand)

## Context

banlieue's contract is "the Kubernetes API is the only transport" and "banlieue neither carries
nor validates the token". mediatore adds HTTPS and mTLS listeners, validates tokens, and pulls
in an IdP's dependency tree (Entra/OIDC, OBO, sqlx, tonic, OpenBao).

## Decision

mediatore lives in its own repository and consumes `banlieue-api` as a pinned dependency for
the `VirtualMachineClaim` and `VirtualMachine` types. banlieue never imports mediatore.
The in-guest agent (`mediatore-guest`) and the workload CLI (`sandbox-token`) live in this
repository too, sharing `mediatore-proto`, because their wire contract changes in lockstep
with the server.

*Amended 2026-10-15 by [ADR-0014](0014-one-binary-roles-as-subcommands.md):* the guest
agent and the workload CLI are no longer separate executables. One `mediatore` binary
carries every role as a subcommand (`crates/mediatore/src/main.rs`, `enum Cmd`): the guest
is `mediatore guest`, the workload's command is `mediatore token`.

## Consequences

- banlieue keeps its supply-chain scope and assurance level; mediatore gets a stricter one.
- Schema drift is caught at compile time by the pin, not at runtime.
- Three binaries, one version, one release (amended 2026-10-15 by ADR-0014: one binary,
  one version, one release).
