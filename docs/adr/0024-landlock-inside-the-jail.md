<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0024: Landlock inside the jail, applied by the one binary before the workload runs

**Status:** Accepted · **Date:** 2026-10-30

Roadmap 06, the confinement item (listed until now as "a real seccomp policy for
nsjail"). Adds an inner layer to the jail of
[ADR-0020](0020-jail-network-nftables-keyed-by-sandbox-uid.md) and
[ADR-0021](0021-sandbox-filesystem-tmpfs-and-rootfs-from-the-registry.md); extends
[ADR-0014](0014-one-binary-roles-as-subcommands.md) with one more role of the one binary.
Changes nothing about identities ([ADR-0004](0004-spiffe-identity-scheme.md)), tokens
([ADR-0003](0003-token-backends.md)) or what the workload reaches on the network
(ADR-0020 decision 2). The credential-injecting proxy that would take the token out of the
workload is roadmap 07, the next ADR, not this one.

## Context

The jail is an `nsjail` the guest starts as the per-subject user: a chroot into the
rootfs unpacked from the claim's image, `/work`, `/tmp` and a home writable, the Workload
API socket and the binary mounted read-only, rlimits, no `/proc`, the VM's network
namespace behind the uid-keyed nftables table. Everything it enforces is a property of
the mounts and of file modes: the rootfs is root's and read-only, so the workload cannot
write there, and the ruleset decides where its packets go.

Two things that layer leaves to chance. What the workload may write is whatever the image's
file modes say it may: a world-writable directory in the image is writable in the jail,
and an image is the requester's. And what the workload may do with sockets is anything
the kernel allows a process to do: it can bind a TCP port in the VM's namespace (threat
model R-13, "nothing reaches it" because the segment admits nothing inbound), and the
only thing stopping its `connect()` is a packet filter that root can flush (ADR-0020
decision 7). Roadmap 06 kept an item for "a real seccomp policy for nsjail" to close the
syscall side; a seccomp allowlist for an arbitrary workload image is a policy nobody can
write once, and a filter on syscall numbers says nothing about paths or ports.

The kernel has had the right primitive since 5.13: Landlock, an unprivileged LSM a process
applies to itself with `landlock_restrict_self`, irreversible, inherited by every child.
It expresses exactly the two properties above: which paths may be read, executed and
written, and (ABI 4 and later, kernel 6.7) which TCP ports may be connected to or bound.
ABI 6 (kernel 6.12, which is what Debian 13 and the image of ADR-0023 run) adds scoping:
signals and abstract Unix sockets confined to the sandbox's own domain. Landlock does not
need root, `CAP_SYS_ADMIN`, `/proc` or cgroups, so it works where the jail already puts
the workload.

nono ([always-further/nono](https://github.com/always-further/nono), Apache-2.0) is a
sandbox for AI agents built on Landlock. Its CLI is a supervisor that forks, confines the
child and runs an egress proxy that injects credentials, which is the design of roadmap
07 and the design its own NEP-0007 is moving towards (the supervisor split over vsock,
decisions and credentials on the host, enforcement in the guest: mediatore's shape). Its
`nono` library crate is the part that applies the policy: a `CapabilitySet` of paths with
access modes and TCP ports, applied to the calling process with ABI detection, the hard
requirements checked against the kernel and the scopes added where the ABI has them. That
crate depends on `landlock`, `nix` and the Sigstore verify stack only: no `ring`, no TLS,
no runtime (checked with `cargo tree` on the build host, 2026-10-30). The `nono-proxy`
and `nono-cli` crates pull `ring` through `rcgen` and the AWS SDK and are out of reach
of this workspace (ADR-0007, `deny.toml`).

## Decision

1. **nsjail stays the outer jail; Landlock is the inner layer, applied by the workload's
   own process.** nsjail keeps doing what only a privileged parent can: the rootfs as
   root, the user and group, the mounts, the rlimits, no `/proc`, the VM's namespace.
   What nsjail execs is no longer the workload but the one binary, mounted read-only at
   the pinned path already (ADR-0014 decision 4): `/usr/bin/mediatore jail-exec`, which
   builds the capability set, applies it to itself and execs the workload's argv. The
   restriction is in place before the first instruction of the workload runs and
   follows every process it spawns. A role of the one binary, as ADR-0014 says every
   piece of the guest is; nothing new enters the image.

2. **The capability set is the claim's, as data.** The whole rootfs readable and
   executable (the jail's `/`, which is the image plus the two mounts), `/work`, `/tmp`
   and the home writable, nothing else writable whatever the image's modes say; TCP
   `connect()` only to the ports of the broker and of the claim's `egress` endpoints,
   the same destinations the ruleset of ADR-0020 resolved, taken from it so the two
   layers cannot disagree; no TCP `bind()` at all; signals and abstract Unix sockets
   scoped to the jail. The set is a plain value (`Plan` in
   `crates/mediatore-guest/src/confine.rs`), pinned by unit tests on every platform
   like the nsjail arguments and the ruleset text are. UDP is not Landlock's: DNS to
   the resolvers keeps working and keeps being the ruleset's to bound (ADR-0020, R-12).

3. **Through the `nono` library, pinned exactly, with the keyring feature off.** Not
   the raw `landlock` crate: nono carries the ABI detection and the hard-requirement
   checks (a kernel that cannot enforce what was asked is an error, never a silently
   narrower ruleset), the scope policy, and a capability model that is the same shape
   as a nono manifest and as the policy the egress proxy of roadmap 07 will read, so
   one rendering of a claim (or, under notaio M3, of a bundle) feeds both layers.
   `nono-proxy` is not used; the proxy is ours, on this workspace's TLS stack. The pin
   is `=0.81.0` and moves only by hand: this is the primitive that decides what the
   workload may touch.

4. **Fail closed, with a distinct exit.** `jail-exec` refuses to run the workload when
   the kernel has no Landlock, when it cannot enforce the network rules (ABI below 4),
   when a granted path does not exist, or when the claim names no port at all (the
   broker is always one, so an empty list is a bug). It exits with status 125 and the
   supervisor treats that status as fatal for the claim: no restart, teardown, the
   claim stays bound with no workload until its deadline, as a claim whose image never
   pulls does (ADR-0021). Any other exit is the workload's and is restarted as before.
   On a platform without Landlock the role refuses outright; it is not a dev-mode path.

5. **No seccomp allowlist, no cgroups, no nono supervisor.** Landlock is the answer to
   roadmap 06's confinement item: it is path- and port-based, which is what the threat
   model asks of it, and it needs no syscall table per image. nono's own seccomp network
   filters, its cgroup limits (they need a delegated cgroup) and its supervisor and
   proxy processes are not used inside the jail; rlimits stay nsjail's. A seccomp filter
   on top is a later item if a threat needs it, not a placeholder.

## Consequences

- `crates/mediatore-guest/src/confine.rs` (the `jail-exec` role: `Plan`, the capability
  set, the apply and the exec), `jail.rs` (the nsjail command is now the binary's
  `jail-exec` with the writable dirs and the ports, then `--`, then the argv),
  `supervise.rs` (exit 125 stops the claim), `guest.rs` (the ports from the resolved
  ruleset), `crates/mediatore/src/main.rs` (the subcommand). `nono` is a Linux-only
  dependency of `mediatore-guest`.
- The image is unchanged: the binary is already in it and already mounted into the jail.
  The kind tiers run the guest with `--dev-skip-setup` and start no jail; the live proof
  is an ignored test that runs the real `jail-exec` on the build host
  (`crates/mediatore/tests/jail_exec_live.rs`: a write inside a granted directory
  succeeds, one outside fails, a TCP connect to a granted port succeeds, to another port
  fails, a bind fails, a run with no port is refused with 125).
- The workload sees `EACCES` where it used to see `EROFS` or `ECONNREFUSED`, and no
  `bind()` succeeds. An agent framework that opens a local listener (a debugger, a
  dashboard) does not work in the jail; it did not usefully before (nothing reached it),
  now it fails at `bind()`. If a legitimate case appears, it is a bind port in the plan,
  declared on the claim, never a default.
- Guest root is still outside both layers (ADR-0020 decision 7). What changes against a
  root compromise: nothing. What changes against the workload: its filesystem and TCP
  bounds hold in the kernel of its own process, independent of file modes and of the
  packet filter.
- Rejected: a seccomp allowlist per image (unwritable in general, blind to paths and
  ports); running the `nono` CLI inside the jail as the supervisor (it wants `/proc` for
  its connect mediation and a delegated cgroup, both deliberately absent, and the guest
  is already the supervisor); the raw `landlock` crate (it would mean re-implementing
  the ABI and scope handling nono maintains, for no gain in dependencies); applying
  Landlock from the guest before `nsjail` (the guest is root and must stay unconfined
  to tear down; the restriction belongs to the process that will run the workload).
