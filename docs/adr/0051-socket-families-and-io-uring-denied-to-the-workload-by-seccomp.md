<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0051: Socket families and io_uring denied to the workload by a seccomp filter

**Status:** Accepted, implemented 2026-11-19 · **Date:** 2026-11-18

Roadmap 06, the confinement item. Adds a third layer inside the jail of
[ADR-0020](0020-jail-network-nftables-keyed-by-sandbox-uid.md) (nftables keyed by uid) and
[ADR-0024](0024-landlock-inside-the-jail.md) (Landlock, applied by `jail-exec`), and
reverses only the last sentence of ADR-0024 decision 5 ("a seccomp filter on top is a later
item if a threat needs it"): a threat needs it, below. Changes nothing about identities
([ADR-0004](0004-spiffe-identity-scheme.md)), tokens
([ADR-0003](0003-token-backends.md)) or what the workload may reach by address and port.

## Context

The two layers inside the jail bound the workload by what they can name. nftables names
IP addresses and TCP ports for packets that carry the sandbox uid. Landlock names paths and
TCP ports. Neither names the **kind of socket** the workload may open, and the kernel offers
more kinds than IP:

- `AF_VSOCK` is the guest-to-host channel of the hypervisor. The nftables `inet` table
  never sees it (it is not an IP packet), and Landlock has no rule for it (ABI 6 scopes
  abstract Unix sockets and signals; vsock is not among its access rights). A workload
  that can `connect()` a vsock to the host's CID reaches whatever the host or the
  provider listens on there, bypassing the egress gateways entirely. Nothing in the repo
  opens a vsock for the workload, so the right bound is none at all.
- `AF_PACKET` and raw sockets (`SOCK_RAW`) need `CAP_NET_RAW`, which nsjail drops (the
  jail passes no `--keep_caps`), so today they fail. That is a property of one flag
  staying absent, not of a rule anything checks.
- `AF_NETLINK` is open to any uid for the read-only families and is the way `nft` talks to
  the kernel. Changing a ruleset needs `CAP_NET_ADMIN`, also dropped; again the bound is a
  dropped capability and one flag.
- `AF_INET` and `AF_INET6` datagram sockets (UDP) are not covered by Landlock's TCP rules.
  With gateways the uid's chain admits TCP to the gateways and the proxy and nothing else
  (R-12, R-13 revised 2026-11-04 and 2026-11-17), so UDP is closed by nftables. Without
  gateways (the dev loop, a pool before its gateways) the chain admits UDP and TCP port 53
  to the VM's resolvers, and a name is data (R-12 as it stands).
- `io_uring` can issue socket operations (`IORING_OP_SOCKET`, kernel 6.11 and later; the
  image of [ADR-0023](0023-sandbox-vm-image-kairos-derivative.md) runs 6.12) without
  going through the `socket` syscall, so a filter on `socket` alone is bypassed by it. It
  is also a standing source of kernel vulnerabilities, and no agent workload needs it.

The workload does not need any of these. By [ADR-0025](0025-phantom-token-egress-proxy.md)
decision 5 it connects to the egress proxy's loopback TCP port and to nothing else, and it
resolves no names of its own (the proxy, outside the jail, does). What it needs is
`AF_UNIX` (the Workload API socket, local IPC, language runtimes) and `AF_INET` or
`AF_INET6` stream sockets to that one port.

The question [ADR-0024](0024-landlock-inside-the-jail.md) rejected was a syscall
allowlist per image: unwritable once, blind to paths and ports. This is a different
filter. It is a **denylist of three things** (socket families, socket types, io_uring)
that is the same for every image because it describes what the workload is, not what
the image runs.

## Decision

1. **A seccomp-bpf filter, applied to the `jail-exec` process before it execs the
   workload, inherited by everything the workload spawns.** Like Landlock it is
   irreversible and needs only `no_new_privs`, which `jail-exec` already sets for
   Landlock. The filter is installed after the Landlock restriction and before the
   `exec`, so the one binary is never confined by a rule meant for the workload.

2. **What it denies, with `EAFNOSUPPORT` for families and `EPERM` for the rest** (an
   error the workload's runtime reports instead of a signal that looks like a crash):
   - `socket()` and `socketpair()` whose domain is not `AF_UNIX`, `AF_INET` or
     `AF_INET6`. This closes `AF_VSOCK`, `AF_PACKET`, `AF_NETLINK`, `AF_ALG`, `AF_BLUETOOTH`,
     `AF_KEY` and every family added later: an allowlist of three, not a list of the
     dangerous ones.
   - `socket()` whose domain is `AF_INET` or `AF_INET6` and whose type (after masking
     `SOCK_NONBLOCK | SOCK_CLOEXEC`) is not `SOCK_STREAM`. UDP, raw and `SOCK_PACKET`
     are refused in the jail whatever the network shape, which closes the direct
     shape's resolver channel (R-12) for the workload itself; the proxy's DNS is the
     proxy's, in its own process and outside the jail.
   - `io_uring_setup`, `io_uring_enter` and `io_uring_register`.
   - `bpf`, `userfaultfd`, `perf_event_open`, `kexec_load`, `init_module`,
     `finit_module`, `delete_module`, `mount`, `umount2`, `pivot_root`, `setns`,
     `unshare` and `open_by_handle_at`. Everything on this line is already refused by a
     dropped capability or by Landlock; the filter makes each refusal independent of
     the other two layers, which is its whole purpose. **`ptrace` is not on the list
     (amended at implementation):** a filter cannot tell a process of the jail from
     another, and refusing it outright would break a debugger on the workload's own
     children. It stays with the PID namespace and the `subset=pid` `/proc` of
     [ADR-0036](0036-proc-inside-the-jail-the-workloads-own-processes-only.md), and Yama's
     scope behind them.
   - Two filters, installed in turn, so the two errnos do not depend on the kernel's
     precedence between filters: the family filter (`EAFNOSUPPORT`) and the rest
     (`EPERM`). Their matches are disjoint (a unit test walks every family and type).
     The type is compared under the kernel's own `SOCK_TYPE_MASK` (`0xf`), which is the
     `SOCK_NONBLOCK | SOCK_CLOEXEC` masking and stricter: every value but `SOCK_STREAM`
     is refused. A process of another ABI (the 32-bit compat entry) is refused by the
     filter's architecture check.
   - Anything else is allowed (`DEFAULT ALLOW`). This is deliberate: a default-deny
     policy needs a syscall table per runtime and image, which ADR-0024 refused.

3. **Applied by the `nono` library if it offers the filter, otherwise by nsjail's own
   `--seccomp_string` (a Kafel policy the guest renders), and by a new crate in neither
   case.** The decision is the policy, not the carrier. Order of preference:
   1. nsjail's `--seccomp_string`: no new dependency, the policy is a string pinned by a
      unit test like the nsjail arguments and the ruleset text already are
      (`crates/mediatore-guest/src/jail.rs`). It applies to `jail-exec` too, which is
      harmless: `jail-exec` opens no sockets of its own, and the Landlock calls it makes
      are not in the policy.
   2. `seccompiler` (Apache-2.0 or BSD-3-Clause, rust-vmm) called from `confine.rs`, if
      Kafel cannot express the type mask. No `ring`, no TLS; `cargo deny` allowlist
      checked before it lands.
   3. `libseccomp` (LGPL) is out: not permissive (`deny.toml`).

   The choice is made by the first red test: whichever carrier passes the live test
   below with the least new surface is the one.

   **Chosen 2026-11-19: `seccompiler` 0.5 (option 2), called from `jail-exec`.** `nono`
   0.81.0 has no custom denylist (its seccomp is the network fallback and the supervisor's
   mediation, `SeccompOpts`), and the live test runs `jail-exec` directly, not under
   `nsjail`, so a Kafel string passed to `nsjail` would not be the filter that test proves.
   The policy is data in `crates/mediatore-guest/src/seccomp.rs` (`Filter`, `Rule`, `Cond`,
   an evaluator the unit tests drive on every platform), compiled and installed on Linux
   only, `default-features = false`, plus `libc` for the syscall numbers.

4. **Fail closed, with the same exit.** A kernel without seccomp-bpf, or a filter that
   fails to load, is an error before the argv and exits 125 (ADR-0024 decision 4): no
   restart, teardown, the claim bound with no workload until its deadline. Not a
   dev-mode path. On a platform without seccomp the role refuses outright, as it does
   without Landlock.

5. **No claim-level exceptions in this ADR.** There is no `allow_udp` or `allow_vsock`
   on the claim. A legitimate case (a workload that must do its own DNS, say) is an
   ADR that adds a declared, audited exception to the plan, never a default, as
   ADR-0024 said of bind ports.

6. **The plan carries it as data.** `Plan` in `crates/mediatore-guest/src/confine.rs`
   (or the nsjail spec, per decision 3) holds the filter as a plain value pinned by unit
   tests on every platform, with the kernel behaviour proven by the ignored live test.

## Consequences

- The workload sees `EAFNOSUPPORT` on a `socket(AF_VSOCK, ...)` and on `AF_NETLINK`,
  `EPERM` on a UDP socket and on `io_uring_setup`. Runtimes that probe for io_uring
  (libuv, tokio's optional `tokio-uring`, recent Node and Python event loops, `liburing`
  users) fall back to epoll, which is their documented behaviour; a hard dependency on
  io_uring is a bug in the workload under this model, recorded in the guide.
- A workload that resolves names through the libc resolver (`getaddrinfo` for a name that
  is not in `/etc/hosts`) now fails in the jail, in the direct shape too. By ADR-0025 it
  addresses the proxy on loopback; `/etc/hosts` and numeric addresses keep working. If
  an image's client insists on resolving the proxy's name, the fix is a hosts entry the
  guest writes, not a UDP exception.
- Threat model, the full pass after implementation (`rules/threat-modeling.md`):
  - §5 jail rows: a new Elevation-of-privilege row for the vsock, netlink and packet
    families, citing the policy and its live test.
  - R-12: narrowed again, the workload's own UDP is closed in both shapes; the direct
    shape's remaining resolver use is the proxy's.
  - R-13: unchanged for root (the filter binds the workload, not guest root, which is
    outside all three layers, ADR-0020 decision 7).
  - TB-6 or the jail's boundary row: one more layer named; the Mermaid diagram needs no
    new node, since the filter is a property of the existing jail process.
  - The header stamp is bumped with the ADR range.
- CALM (`docs/architecture/calm/architecture.json`): the jail node's description gains
  the layer; `make calm-validate` and `make calm-diagrams` pass before implementation.
- Guest root is unchanged: it can load a different filter for itself and flush nftables.
  What changes is the workload's bound if one of the other two layers has a bug or is
  not loaded: a vsock, a UDP socket or an `io_uring` socket op no longer depends on
  nftables or on a dropped capability.
- The TPM attestation path is not touched (`rules/testing.md`): `jail.rs`, `confine.rs`
  and the guest's jail spec are not on that list, so `make kind-e2e-tpm` is not required.
  The kind tiers run with `--dev-skip-setup` and start no jail, so the proof is the live
  test below on the build host.

*Amended 2026-11-19: two things the filter leaves, found in review after it was built.*

*First, the protocol. The filter checks the domain and the type of a `socket()` call and not
its third argument, so an inet stream socket opened with a protocol other than TCP (MPTCP,
protocol 262) passes it. That socket is still bounded by the layer below: the uid-keyed
nftables table drops its packets as it drops plain TCP (tested on the image's kernel line,
6.12, on 2026-11-19), and the image sets `net.mptcp.enabled = 0`
(`image/sysctl/99-mediatore.conf`). The filter should say it too, so the bound does not rest
on a kernel's behaviour staying as it is: in `crates/mediatore-guest/src/seccomp.rs`, a
constant `INET_STREAM_PROTOCOLS` (`0` and `IPPROTO_TCP`, 6) beside `INET_FAMILIES`, and one
more rule per inet family in the `EPERM` filter, next to the type rules. The unit test is
`an_inet_stream_socket_whose_protocol_is_not_tcp_is_refused_with_eperm`, and the live test in
`crates/mediatore/tests/jail_exec_live.rs` gains an MPTCP `socket()` that fails. Not built.*

*Second, user namespaces. `DENIED_SYSCALLS` refuses `unshare` and `setns`, and the filter has
no rule for `clone` or `clone3`. A rule on `clone` could compare its flags, but `clone3` takes
them in a structure behind a pointer, which a seccomp filter cannot read, so the filter cannot
refuse a child user namespace created that way. The bound belongs in the image instead:
`user.max_user_namespaces = 0` in its sysctl layer, asserted in `image/check.sh`. That key is
not set yet: it needs a boot of the image showing that `nsjail` (which runs as root and
creates no user namespace) and the SPIRE agent still start. Until then a child user namespace
is the workload's to create; `no_new_privs`, Landlock and this filter are expected to carry
across one, which is reasoning from how each is inherited and not a test of this repository
(threat model R-42).*

## Test plan (red first)

Unit, on every platform, in the source file:

- the filter or the Kafel string denies exactly the listed families, types and syscalls
  and allows `AF_UNIX`, `AF_INET` and `AF_INET6` with `SOCK_STREAM` and the
  `SOCK_NONBLOCK | SOCK_CLOEXEC` flag combinations a runtime uses;
- the `jail.rs` argument vector carries the policy once, before the `--`;
- a platform without seccomp refuses the role outright.

Live, `crates/mediatore/tests/jail_exec_live.rs` (ignored, fails loudly when the fixture
is missing): inside a real `jail-exec`, `socket(AF_VSOCK)` fails `EAFNOSUPPORT`,
`socket(AF_NETLINK)` and `socket(AF_PACKET)` fail, `socket(AF_INET, SOCK_DGRAM)` fails
`EPERM`, `socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK)` and a connect to the granted port
succeed, `AF_UNIX` works, `io_uring_setup` fails `EPERM`, and a child the workload forks
inherits all of it. A run where the filter cannot load exits 125.

## Alternatives rejected

- **A default-deny syscall allowlist.** ADR-0024's reason stands: a table per runtime and
  image nobody can write once.
- **nono's own seccomp network filters, or the nono CLI as supervisor.** The CLI needs
  `/proc` mediation and a delegated cgroup (ADR-0024); the policy here is three denials
  the guest renders itself.
- **Relying on dropped capabilities and nftables alone.** That is today's state, and it
  leaves vsock to a rule nothing checks. A bound that holds only because a flag is absent
  is not a control.
- **A vsock rule in the host table (`image/host-table`).** nftables does not see vsock.
  Only the hypervisor, provider-side, can bound it for guest root; that is a request to
  the providers (ADR-0009, ADR-0010), tracked separately, and does not replace a
  filter on the workload.
- **A claim field to opt into UDP or vsock now.** No consumer exists; adding it would be
  a permissive path with no test demanding it (fail closed).

## Open questions

1. *Answered 2026-11-19.* `nono` 0.81.0 does not expose a custom denylist; the carrier is
   `seccompiler` (decision 3). Not covered by the live test: a run where the filter cannot
   load exiting 125 (no kernel here can be made to refuse it on demand); the path is the
   same `JailExecError::Refused` as Landlock's, pinned by that type's unit test.
2. *Still open: `AF_NETLINK` is denied outright today.* Is there a workload class in the community docs that opens `AF_NETLINK` for a
   non-privileged read (`getifaddrs`, some Go and Java runtimes enumerate interfaces
   this way)? If so, the filter allows `AF_NETLINK` with `NETLINK_ROUTE` only
   (`socket` third argument), and that exception is spelled out here before
   implementation. Test it against the images in `docs/guides/research-agent-walkthrough.md`
   first.
3. Does the provider's hypervisor already refuse a guest vsock to the host's CID? If so,
   say so in the threat model as a second control; this ADR is still the control the
   mediatore repo owns.
