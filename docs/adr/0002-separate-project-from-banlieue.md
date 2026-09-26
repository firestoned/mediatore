<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0002: mediatore is a separate project, not a banlieue crate

**Status:** Accepted · **Date:** 2026-09-26

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

## Consequences

- banlieue keeps its supply-chain scope and assurance level; mediatore gets a stricter one.
- Schema drift is caught at compile time by the pin, not at runtime.
- Three binaries, one version, one release.
