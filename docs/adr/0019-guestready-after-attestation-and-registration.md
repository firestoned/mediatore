<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0019: The guest announces `GuestReady` after it is attested and registered

**Status:** Accepted · **Date:** 2026-10-24

Roadmap 06, the readiness item. Builds on banlieue
[ADR-0043](https://github.com/firestoned/banlieue/blob/main/docs/adr/0043-guestready-installed-guest-signal.md)
(`GuestReady`, the installed guest announcing itself over a host-side channel) and on
[ADR-0008](0008-agentsandbox-crd-owned-by-mediatore.md), whose consequences require
pools that serve sandboxes to use that signal. Changes nothing about the identities of
[ADR-0004](0004-spiffe-identity-scheme.md) or the attestation of
[ADR-0018](0018-tpm-attestation-with-the-spiffe-plugin.md).

## Context

A `VirtualMachinePool` hands a member to a claim once the member is Ready, and what
Ready means is the pool's `spec.readiness`. banlieue ADR-0043 defines `GuestReady` as
"booted from the installed disk, and said so": a cloud-config `boot` stage, guarded on
Kairos's installed-disk sentinels, writes a marker the hypervisor side reads out of band
(banlieue's `examples/16-cloud-config-guest-phase.yaml`). That is the right signal for a
pool of plain VMs. For a sandbox member it comes too early.

Between the installed system booting and the member being able to take a claim sit two
more steps, both of which can fail or take time: the SPIRE agent attests the vTPM
(ADR-0018), and `mediatore guest` registers the node over the SVID the agent issues
(ADR-0007). A member counted Ready at boot but still attesting is handed to a claim whose
sandbox then waits on a registration that comes late or never, until the watcher's
`resolve_timeout_secs` fails it ([the sandbox guide](../guides/requesting-a-sandbox.md)).
The pool's `Warm` count is wrong in the one direction that costs a user a sandbox.

banlieue ADR-0043 decision 9 is explicit that `GuestReady` is a liveness signal, never an
integrity one: a compromised guest can write the marker. Nothing here changes that. What
this ADR decides is *when* an honest guest says it, so the pool's count is honest too.

## Decision

1. **The sandbox image carries no phase layer; `mediatore guest` announces instead, after
   the node is registered.** The guest's unit starts only after `spire-agent healthcheck`
   succeeds (the Workload API is up, which on a fresh member means the agent attested),
   the guest connects with the SVID the Workload API hands it, and `POST /v1/nodes` is
   accepted. Only then does it announce. On a sandbox member `GuestReady` therefore means:
   booted from the installed disk, attested as a SPIRE agent, known to mediatore as a
   node. A member refused with `409` (a cloned EK) announces nothing and is never handed
   out; one that cannot reach mediatore keeps retrying and stays out of the pool meanwhile.

2. **The three channels banlieue reads, detected rather than configured.** The payloads
   are byte for byte what banlieue's providers parse:
   - the file `/run/banlieue/phase` containing `installed`, which libvirt's provider reads
     through `qemu-guest-agent`; written always, atomically (a rename), under `/run` so a
     power cycle clears it (ADR-0043 decision 3);
   - `vmware-rpctool "info-set guestinfo.banlieue.phase installed"` when the tool is on
     the path, which vSphere's provider reads from `config.extraConfig`;
   - the line `phase=installed` over vsock to the host (CID 2, port 1024) when `/dev/vsock`
     exists, which Cloud Hypervisor's provider listens for (banlieue ADR-0065 decision 5).

   The `--provider` flag stays what it was, an audit hint on the registration: the image is
   one image for every hypervisor, and detection is how banlieue's own layer selects the
   channel too.

3. **Re-asserted every boot.** The unit runs at every boot and the marker lives in runtime
   state; banlieue keeps `status.guestInstalled` sticky on its side, so a power cycle does
   not drop a member that has announced once.

4. **Both VM units carry the installed-disk guard.** `image/systemd/spire-agent.service`
   and `image/systemd/mediatore-guest.service` start only when `/run/cos/active_mode` or
   `/run/cos/passive_mode` exists (`ConditionPathExists=|`). Kairos boots the same image,
   with the same enabled units, as the live installer and in recovery; without the guard
   the installer would attest with the member's vTPM, register and announce while it is
   still writing the disk, which is exactly the failure ADR-0043 exists to prevent, moved
   one layer up. A non-Kairos image removes the two lines or provides the sentinel.

5. **A failed announcement is logged, not fatal.** The guest logs each channel's outcome
   (announced, absent, failed) at the point of the announcement and goes on to wait for a
   claim. A `GuestReady` pool never hands such a member out and says why
   (`Warm=False`, ADR-0043 decision 10); a pool on `InfrastructureReady` (a dev loop) is
   unaffected. Restarting the guest to announce again would only announce the same
   failure.

6. **Liveness, not integrity, restated.** What a forged announcement gains is a claim
   binding to a member whose node is not registered: the bind itself resolves through the
   EK banlieue published and the node the guest registered over its SVID
   (ADR-0011), so no subject reaches such a member, and the claim fails at the timeout.
   mediatore reads the announcement nowhere.

## Consequences

- A sandbox pool's `Warm` count is the number of members that can take a claim now. The
  "node registration that comes late or never" case in the sandbox guide shrinks to a
  member that was ready and then lost its agent, which the watcher already handles.
- `crates/mediatore-guest/src/ready.rs` is the announcement; `guest.rs` calls it right
  after `node registered`; `--phase-file` moves the marker for tests and dev loops. Unit
  tests pin the three payloads and that a stale marker is rewritten.
- The kind TPM tier (`make kind-e2e-tpm`) asserts the order: `GuestReady announced` appears
  in the guest's log after `node registered`, at first boot and after the pod is replaced.
  The live proof that `guestInstalled` flips only after registration is roadmap 06's
  libvirt item.
- The image item of roadmap 06 bakes banlieue's EK-certificate layer
  (`examples/20-cloud-config-guest-ek-certificate.yaml`: the EK leaves the guest as a file
  for libvirt's provider) but not its phase layer; the two units carry the guard.
- banlieue is unchanged: its providers read what they read, and ADR-0043's decision 9
  stands.
- Rejected: the cloud-config phase layer on the sandbox image (announces an unattested
  member); announcing when the SVID arrives rather than after registration (a `409` clone
  would be handed out); selecting the channel from `--provider` (the flag is optional, the
  image is one image, and a wrong hint would silence the signal); a fatal announcement
  failure (a restart loop announcing nothing, and a dev pool that never serves).
