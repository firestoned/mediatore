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
- [x] Kernel confinement inside the jail, beyond what the mounts and file modes give. Done
      2026-10-30 as [ADR-0024](../../docs/adr/0024-landlock-inside-the-jail.md): `nsjail`
      execs the one binary's `jail-exec` role, which applies Landlock to its own process
      through the `nono` library before the workload's argv runs
      (`crates/mediatore-guest/src/confine.rs`): the rootfs readable and executable,
      `/work`, `/tmp` and the home writable whatever the image says, TCP connect only to
      the ports of the ruleset's destinations, no bind, signals and abstract sockets
      scoped; a kernel that cannot enforce it or a claim with no port is refused with exit
      125 and the supervisor ends the claim instead of restarting. The plan is pinned by
      unit tests, the enforcement proven by an ignored test on the build host. The item
      had been "a real seccomp policy for nsjail": a syscall allowlist per arbitrary image
      is not writable and says nothing about paths or ports; a seccomp layer on top is a
      later item only if a threat needs it
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
- [x] Image baking. Done 2026-10-27 as
      [ADR-0023](../../docs/adr/0023-sandbox-vm-image-kairos-derivative.md): a Kairos
      Debian 13 derivative built from `image/Dockerfile` (the binary, the SPIRE agent and
      the plugin pinned by digest in the immutable rootfs, `nsjail` built from a pinned
      source commit (added 2026-10-28: the first build omitted it), `tpm2-tools`,
      `qemu-guest-agent`, `nftables`, listeners removed, the `spire` user, units enabled),
      checked by `image/check.sh` in CI and on the build host, published as
      `ghcr.io/firestoned/mediatore-guest` signed and attested; the pinned path moved to
      `/usr/bin/mediatore` (Kairos mounts the persistent partition over `/usr/local`);
      `/var/lib/spire` bound from the sealed partition for the agent's key; the trust
      bundle and `agent.conf` from the deployment's cloud-config layer
      (`image/cloud-config-deployment.example.yaml`); banlieue's EK-certificate layer in,
      its phase layer out; the `VMImage` and `VMClass` for libvirt in the homelab overlay
      (`deferred` until a Kairos 4.4 Debian base allows first-boot sealing)
- [x] `kernel.yama.ptrace_scope = 1` in the image's sysctl: Debian 13 ships 0, and since
      [ADR-0025](../../docs/adr/0025-phantom-token-egress-proxy.md) the egress proxy
      holds the claim's tokens as the same uid as the workload. The PID namespace and the
      absent `/proc` are what keep the workload from naming the proxy's process; the
      scope is a second line, cheap. Done 2026-10-31: `image/sysctl/99-mediatore.conf`,
      copied to `/etc/sysctl.d` by `image/Dockerfile` and proven present by
      `image/check.sh`; threat model TB-12 and R-16 cite it. In the same change the
      Workload API connect gained a bound (`WorkloadApiSource::connect(endpoint, wait)`,
      90 s for a VM-side role, since a process started at bind waits for the claim entry
      to reach the agent, 60 s for the broker; the guest's readiness wait for the proxy
      raised to 120 s to outlast it): a role whose agent socket is absent or silent fails
      closed with the cause instead of hanging, which the egress proxy did behind the
      guest's readiness wait
- [x] Live proof on a libvirt member: reboot mid-claim re-attests with the same EK and
      recreates the jail (runbook 8.7 last row). Done 2026-10-31 against v0.2.0-rc.3 on
      the homelab cluster (banlieue v0.4.8, SPIRE 1.15.3 with the `tpm` NodeAttestor, Dex):
      a Kairos member installed from an AuroraBoot ISO with the three layers embedded
      (a `BackingFile` VMImage, `installMode: deferred`, a vTPM class) attested as
      `spiffe://sandbox.home.example/spire/agent/tpm/6ed87b22…`, registered, went
      GuestReady; a claim ran the public curl image under nsjail and Landlock, and the
      four ADR-0025 cases came back 200 with the real token at the audience (a private
      CA), 401 `unknown_credential`, 403 `outside_rules`, 404 `no_route`; after
      `systemctl reboot` mid-claim the same agent ID loaded from the sealed partition, the
      guest re-registered, re-fetched the claim, recreated the proxy and the jail, and the
      workload's heartbeats through the proxy resumed within 40 s. The proof needed a
      deployment layer carrying stopgaps for defects the kind tier (the guest in a pod)
      cannot see: the image has no `/mnt`, the sandbox tmpfs is unreadable by the sandbox
      user, nsjail's user namespace maps the jail to global root and fails its remount on a
      systemd host, `/etc/spire` is created without the execute bit, and the agent unit
      lacks a writable `/tmp` and `CAP_SYS_PTRACE`. Those are the next change, with a tier
      that runs the guest under the image's own units on a VM.
