<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 06: Guest completion + hardening

**Status: not started.** Finish runbook Part 6 on a real VM.

- [ ] Rootfs population: unpack the claim's OCI workload image (`umoci`/`skopeo`) into
      `/mnt/sandbox/rootfs` (today the agent requires a pre-populated rootfs)
- [ ] `/mnt/sandbox` as size-limited tmpfs or dedicated partition, `nosuid,nodev`,
      mode 0700
- [ ] Host nftables keyed by sandbox UID (`meta skuid`): broker + allowed downstream
      APIs only; Kube API and SPIRE server unreachable from the jail
- [ ] Real seccomp policy for nsjail (the spec currently carries none)
- [ ] `GuestReady` (banlieue ADR-0043) emitted after the SPIRE healthcheck so Ready
      means attested (runbook 2.5)
- [ ] Image baking via banlieue-imagebuilder: agent binaries, trust bundle, units,
      `COS_PERSISTENT` for the agent key (runbook Part 2)
- [ ] Live proof on a libvirt member: reboot mid-claim re-attests with the same EK and
      recreates the jail (runbook 8.7 last row)
