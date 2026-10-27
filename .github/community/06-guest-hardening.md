<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 06: Guest completion + hardening

**Status: in progress.** Finish runbook Part 6 on a real VM.

- [x] Rootfs population: unpack the claim's OCI workload image into
      `/mnt/sandbox/rootfs`. Done 2026-10-26 as
      [ADR-0021](../../docs/adr/0021-sandbox-filesystem-tmpfs-and-rootfs-from-the-registry.md): the guest
      pulls the image itself (`crates/mediatore-guest/src/image.rs`), no `skopeo` or
      `umoci` in the VM: the distribution API over HTTPS with the Mozilla roots,
      anonymously, one bearer challenge followed; OCI and Docker manifests, an index
      resolved to `linux/<arch>`; every blob verified against its digest, a digest-pinned
      reference checked against the manifest, the manifest digest logged with the claim;
      layers applied in order with whiteouts, an entry out of the rootfs (by `..` or
      through a symlink) refuses the image, setuid bits dropped, device nodes skipped,
      tar and tar+gzip only. Tested against a fake registry in `mediatore-testkit`
      (`registry.rs`) and against a real one by an ignored test on the build host
- [x] `/mnt/sandbox` as size-limited tmpfs, `nosuid,nodev`, mode 0700. Done 2026-10-26
      as [ADR-0021](../../docs/adr/0021-sandbox-filesystem-tmpfs-and-rootfs-from-the-registry.md): a
      fresh tmpfs mounted per claim before the pull (`--sandbox-size`, half the
      member's RAM by default), `rootfs/` root's and `work/` the sandbox user's (mode
      0700, which also fixes `/work` having been unwritable by the `sb-` user), one
      `umount` at teardown (`crates/mediatore-guest/src/sandboxfs.rs`); the mount proven
      for real by an ignored test on the build host
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
      and the workload image registry the guest pulls from, ADR-0021 decision 5) and the
      input chain, once the image's system users (DHCP, NTP, the SPIRE agent) are known;
      the ruleset hash and the image digest reported to the broker so a flush is detected
      and the record says which bytes ran
- [x] Pull credentials. Done 2026-10-27 as
      [ADR-0022](../../docs/adr/0022-registry-pull-credentials-from-the-broker.md):
      `registries[]` in the broker's config (host, username, a token file read at
      start, mounted from a Secret like the STS key); `GET /v1/me` carries the
      credential for the registry the claim's image names and no other
      (`Me::registry_credential`, the password a `Secret` that prints redacted); the
      guest presents it at the registry's token endpoint as HTTP Basic, or on the
      content when the registry challenges with `Basic`, for one pull, never over plain
      HTTP, and keeps nothing; the reference grammar moved to `mediatore-proto`
      (`ImageReference`) and `POST /v1/claims` refuses a `workload.image` it cannot
      parse. The fake registry demands the credential at `/token` or challenges with
      `Basic` in the tests
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
