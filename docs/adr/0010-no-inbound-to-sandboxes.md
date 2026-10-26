<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0010: No inbound to sandboxes

**Status:** Proposed · **Date:** 2026-09-30 · **Moved here:** 2026-10-12

Scope: banlieue, mediatore, mediatore-guest, the egress gateway. Origin: platform
ADR-0002, first recorded as banlieue
[ADR-0082](https://github.com/firestoned/banlieue/blob/main/docs/adr/0082-no-inbound-to-sandboxes.md).
This is now the canonical copy (see [ADR-0009](0009-kubernetes-orchestrates-vms-run-agents.md)
for why); banlieue's copy is frozen, with a pointer here. Its *What this means for
banlieue* section below still binds banlieue. Identifiers of the form `T4.5` or `K8.4` refer
to the AgentSandbox platform threat model, not to mediatore's
[threat model](../security/threat-model.md). Related: banlieue
[ADR-0043](https://github.com/firestoned/banlieue/blob/main/docs/adr/0043-guestready-installed-guest-signal.md)
(`GuestReady`, read over a host-side channel, not the network) and
[ADR-0008](0008-agentsandbox-crd-owned-by-mediatore.md) (`AgentSandbox`).

## Context

A supervisory agent needs to give instructions to agents running in sandbox
VMs, and operators sometimes want a way into a VM "in case of anything". An
inbound listener on each VM (SSH or an agent API) gives the network a path
into the most hostile environment in the system, and it is reachable by
anything that can route to the sandbox segment.

Guest-side firewall rules are enforced by guest root, so they cannot be the
only control: a guest-root attacker can remove them.

## Decision

1. Sandboxes accept no inbound connections (knob K4.5 stays at none).
2. SSH is disabled. Images ship without sshd. Break-glass access is the
   hypervisor console, protected by RBAC, with alerts on console and
   snapshot events (knob K8.4). If SSH is ever needed it is a time-boxed,
   signed grant with short-lived SSH certificates from a bastion, recorded
   and expiring automatically.
3. Instructions reach the agent over the outbound mutual-TLS stream that
   mediatore-guest already holds to mediatore. The guest never talks to a
   Kubernetes API server.
4. In-guest nftables is a second layer. Enforcement that holds against guest
   root sits outside the guest (host bridge rules, or distributed firewall /
   VLAN and upstream firewall on vSphere) and at the gateway.
5. The jailed process gets an empty network namespace and reaches the world
   only through a socket to mediatore-guest. *Amended 2026-10-24 by
   [ADR-0020](0020-jail-network-nftables-keyed-by-sandbox-uid.md): the jail keeps
   the VM's network namespace and the sandbox uid is bounded by the ruleset
   below; the relay socket is the credential-injecting proxy of roadmap 07,
   not this layer.*

## Guest ruleset outline

Rendered by mediatore-guest from the signed policy bundle and loaded
atomically before the agent starts:

- Table family inet (IPv4 and IPv6), policy drop on input, output and
  forward.
- Input: established and related only, plus loopback.
- Output for root (mediatore-guest): one address and port, mediatore, over
  mutual TLS.
- Output for the jailed uid, matched by skuid: the gateway only, and DNS
  only to the gateway resolver.
- Link-local and management ranges blocked.
- The ruleset hash is reported to mediatore so a flush or change is
  detected.

As implemented in mediatore (ADR-0020): the jailed uid's chain (the broker,
the audiences' declared endpoints, DNS to the VM's resolvers) is loaded per
claim by `mediatore guest` before the jail starts. The root rules, the input
policy, the gateway resolver and the hash report are still to come.

## Consequences

- The attack surface on each VM has no network listener.
- Task delivery and status use the existing authenticated channel, so no new
  inbound path exists.
- Debugging a broken VM requires the hypervisor console, which is slower
  than SSH.
- The outside enforcement layer depends on the hypervisor platform and needs
  a per-provider implementation.

### What this means for banlieue

Banlieue renders no guest ruleset and relays no task. Its share is to create
sandbox VMs that open no inbound path on their own: no SSH keys or listener
configuration injected through guest data, only allowlisted networks, and
lifecycle and console events a platform can alert on (K8.4). Which of these
exist today is tracked in the alignment report for this ADR and ADR-0009,
not assumed here.

## Still to decide

- Task delivery design. The proposed direction is an AgentTask resource
  reconciled by a separate task controller, with mediatore relaying over the
  existing stream and only the controller writing status. This is not yet
  accepted.
- The outside enforcement layer on vSphere: distributed firewall if
  licensed, or VLANs with upstream firewall ACLs.

## Verification

- A port scan of the sandbox segment finds no listening service on any
  guest.
- A test from a guest as root that flushes nftables still cannot reach
  anything the outside layer blocks.
- Changing the ruleset on a live guest raises an alert within one reporting
  interval.

## Related

- [ADR-0009](https://github.com/firestoned/banlieue/blob/main/docs/adr/0009-kubernetes-orchestrates-vms-run-agents.md): Kubernetes
  orchestrates, VMs run agents.
- Platform threat model: T4.5, T4.6, T5.7, K4.5, K8.4.
