<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# mediatore

> **mediatore** (Italian: *broker*, *go-between*; IPA /me.dja.ˈto.re/, "meh-dyah-TOH-reh")
>
> A trusted go-between for [banlieue](https://github.com/firestoned/banlieue) sandbox VMs.
> mediatore takes a person's login at the front, an attested virtual machine at the back, and
> makes sure the two are bound to each other before anything inside the VM can act on that
> person's behalf.

banlieue schedules VMs and hands them out through `VirtualMachineClaim`s, but deliberately
carries no credential: a claim records *who* a sandbox is for, and stops there. mediatore is
the component that finishes the story.

- **Front door.** Accepts an Entra ID token (or a Dex-bridged GitHub login in a homelab),
  validates it, and creates the `VirtualMachineClaim` with the subject taken from the token.
- **Binding.** When the claim binds to a pool member that has already attested its vTPM to
  SPIRE, mediatore registers a SPIFFE identity for that claim, scoped to that VM and to the
  per-subject Linux user the in-guest agent creates.
- **Delegation.** The jailed workload presents its SVID and asks for a token for one downstream
  audience. mediatore answers with a short-lived, audience-scoped token, minted via Entra
  On-Behalf-Of or by its own STS. The user's original token never enters the VM.
- **Cut-off.** When the claim expires or is deleted, mediatore removes the SPIFFE entry and
  the tokens stop.

## Where to start

- [Running workloads on a claimed VM](guides/running-workloads.md): the user, OBO-agent and
  app-only paths, end to end.
- [System architecture](architecture/diagrams/system.md) and
  [flows](architecture/diagrams/flows.md), rendered from the
  [CALM](https://calm.finos.org/) architecture-as-code model.
- [ADRs](adr/0001-record-architecture-decisions.md): every decision that shaped the trust
  boundaries, token shapes and SPIFFE ID scheme.
- [Threat model](security/threat-model.md): the living STRIDE pass over every trust boundary,
  re-verified after each implemented ADR.

## Project

mediatore is Apache-2.0 licensed and developed in the open at
[firestoned/mediatore](https://github.com/firestoned/mediatore). The roadmap status board
lives in [`ROADMAPS.md`](https://github.com/firestoned/mediatore/blob/main/ROADMAPS.md).
