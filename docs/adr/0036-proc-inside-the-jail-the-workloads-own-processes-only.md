<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0036: `/proc` inside the jail, the workload's own processes only

**Status:** Accepted · **Date:** 2026-11-12

Roadmap 12, the live run of Claude Code in the jail (run 8). Amends
[ADR-0020](0020-jail-network-nftables-keyed-by-sandbox-uid.md) and
[ADR-0024](0024-landlock-inside-the-jail.md) decision 1 on one
point: the jail mounts a `/proc`. Everything else those ADRs say about the jail stands.

## Context

The jail has had no `/proc` since ADR-0020: nsjail runs with `--disable_proc`, and the
threat model leans on that in two places, the proxy's pid that the workload cannot name
(ADR-0025, R-16) and the phantom that `/proc/<pid>/cmdline` cannot carry (TB-12). Both
hold without `/proc` and both, it turns out, hold with the `/proc` chosen here.

The Python agent of runs 5 and 7 never noticed. Node does: Claude Code exits within a
second of starting, with

```
Error: Can't access working directory /work: Path "/work" does not exist
```

while the directory is there, owned by the sandbox user, listable from plain Node in the
same rootfs. The check needs `/proc`. Reproduced on a pool member outside the jail with
the unpacked rootfs: as root and as the sandbox uid, with and without a passwd entry,
with `/dev` bound in, the same error; with a `/proc` mounted, Claude Code goes on to its
login step. Every `/proc` shape tried lets it start, including the tightest the kernel
offers.

That tightest shape exists since Linux 5.8: `subset=pid` makes a procfs instance show
nothing but the process directories (no `/proc/net`, no `/proc/sys`, no `/proc/cpuinfo`,
no `/proc/mounts` beyond the per-process ones), and `hidepid=invisible` hides every
process the caller may not ptrace. Inside nsjail's PID namespace the jail's own
processes are all there is anyway; the proxy and the guest are in the VM's namespace and
have no entry to hide.

## Decision

1. **nsjail mounts a procfs at `/proc` with `subset=pid,hidepid=invisible`, and nothing
   else new.** `--disable_proc` stays, so nsjail's own full `/proc` is never mounted; the
   mount is an explicit `--mount none:/proc:proc:subset=pid,hidepid=invisible`
   (`JAIL_PROC_MOUNT`, `crates/mediatore-guest/src/jail.rs`). No `/dev`, no `/sys`:
   Claude Code starts without them, proven in the same rootfs, and ADR-0020's rule that
   the jail gets what the workload needs and nothing more keeps them out until a workload
   needs one.

2. **Read-only comes from Landlock, not from the mount flags.** nsjail's `--mount` takes
   filesystem options, not mount flags, so the procfs is `rw` at the mount. The inner
   layer already denies it: the capability set grants read on `/` and write on the three
   directories alone (ADR-0024 decision 2), and procfs is a path like any other to
   Landlock. Proven on a pool member: inside `nsjail` plus `jail-exec`, a write to
   `/proc/self/comm` and to `/proc/self/oom_score_adj` fails with `EACCES`, a read of
   `/proc/self/cwd` succeeds. The unit test fixes the argument; the live proof is run 8.

3. **The threat statements change wording, not substance.** "No `/proc`" becomes "a
   `/proc` that shows the jail alone": the proxy still has no pid the workload can name
   (it is in another PID namespace, and `hidepid=invisible` would hide it even if it were
   not), the phantom still travels in nsjail's environment and never in an argument list,
   and `/proc/self/environ` shows the workload its own phantom, which it holds already.
   What a workload gains is `/proc/self` and its children: what Node, Go and the JVM read
   to know their own cwd, limits and maps.

## Consequences

- `crates/mediatore-guest/src/jail.rs`: `JAIL_PROC_MOUNT` and the two arguments; the
  unit test `proc_is_mounted_with_the_jails_own_processes_only`. The guest image is
  unchanged (nsjail 3.6 has `--mount`); the pool's image is rebuilt from the released
  guest, as every guest change is (`docs/guides/deploying.md`).
- ADR-0020, ADR-0024 and ADR-0025 are annotated where they say "no `/proc`"; the threat
  model's TB-12 rows and R-16 say what the jail's `/proc` shows (§6, §8).
- `docs/guides/research-agent-walkthrough.md` no longer promises the absence of `/proc`
  to agent authors; `examples/claude-code/README.md` names the guest version it needs.
- A kernel older than 5.8 refuses `subset=pid` and the jail fails to start, loudly, which
  is the right failure: the pool image is Debian 13 (6.12), and the kind tiers start no
  jail (ADR-0024).
- Rejected: nsjail's default `/proc` (read-only, but the full tree: the VM's `/proc/net`
  and `/proc/sys` for an information gain nobody asked for); a `/proc` only for images
  that declare they need it (a knob on the claim for a mount that costs nothing to grant
  in this shape); patching Claude Code's check away in the example image (every Node
  program with the same check would need the same patch).
