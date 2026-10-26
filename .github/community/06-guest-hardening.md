<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 06: Guest completion + hardening

**Status: in progress.** Finish runbook Part 6 on a real VM.

- [ ] Rootfs population: unpack the claim's OCI workload image (`umoci`/`skopeo`) into
      `/mnt/sandbox/rootfs` (today the agent requires a pre-populated rootfs)
- [ ] `/mnt/sandbox` as size-limited tmpfs or dedicated partition, `nosuid,nodev`,
      mode 0700
- [x] Host nftables keyed by sandbox UID (`meta skuid`): broker + allowed downstream
      APIs only; Kube API and SPIRE server unreachable from the jail. Done 2026-10-24 as
      [ADR-0020](../../docs/adr/0020-jail-network-nftables-keyed-by-sandbox-uid.md):
      `nsjail` keeps the VM's network namespace (it had been isolating the jail
      entirely, so `mediatore token` could not have reached the broker), and before the
      jail starts the guest loads `table inet mediatore_sandbox`
      (`crates/mediatore-guest/src/net.rs`): the sandbox uid's packets go to a chain
      that admits TCP to the broker and to the `egress` endpoints the claim's audiences
      declare (`audiences[].egress`, the union returned by `GET /v1/me` as `Me::egress`)
      and DNS to the VM's resolvers, then logs and drops; no ruleset, no jail; the table
      deleted at teardown; the SHA-256 logged per claim. Ruleset text pinned by unit
      tests, accepted by `nft -c` on the build host
- [ ] The rest of ADR-0010's ruleset outline, with the image: root's egress (the broker
      only) and the input chain, once the image's system users (DHCP, NTP, the SPIRE
      agent) are known; the ruleset hash reported to the broker so a flush is detected
- [ ] Real seccomp policy for nsjail (the spec currently carries none)
- [x] `GuestReady` (banlieue ADR-0043) emitted after the SPIRE healthcheck so Ready
      means attested (runbook 2.5). Done 2026-10-24 as
      [ADR-0019](../../docs/adr/0019-guestready-after-attestation-and-registration.md):
      `mediatore guest` announces right after `POST /v1/nodes` is accepted
      (`crates/mediatore-guest/src/ready.rs`), on every channel the guest has (the
      `/run/banlieue/phase` marker, `vmware-rpctool`, vsock to the host), payloads byte for
      byte what banlieue's providers parse; both VM units gain
      `ConditionPathExists=|/run/cos/active_mode` and `passive_mode` so the live installer
      never attests, registers or announces; the kind TPM tier asserts the order in the
      guest's log, at first boot and after the pod is replaced. The image carries no phase
      stage of banlieue's
- [ ] Image baking via banlieue-imagebuilder: agent binaries, `nftables` (ADR-0020),
      trust bundle, units,
      `COS_PERSISTENT` for the agent key (runbook Part 2); banlieue's EK-certificate layer
      (its `examples/20`) in, its phase layer (`examples/16`) out (ADR-0019)
- [ ] Live proof on a libvirt member: reboot mid-claim re-attests with the same EK and
      recreates the jail (runbook 8.7 last row)
