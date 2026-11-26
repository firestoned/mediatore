<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 16: Per-binary policy inside a sandbox

**Status: not started** (opened 2026-11-24). A route a claim may use can be narrowed to the
binaries inside the jail that may use it: `git` reaches the Git host, `node` (Claude Code)
reaches the Anthropic API, and `curl` in the same sandbox reaches neither. The decision is the
guest's egress proxy's, made per connection from the process that holds the socket, against
digests taken from the sandbox's image. Needs an ADR (ADR-0066, not yet written): it changes
what the policy bundle carries, what `GET /v1/me` serves and what the jail trusts about a
process.

Builds on roadmap 06 (the jail's three layers: nsjail, Landlock, seccomp), roadmap 07 (the
egress proxy, its routes and rules), roadmap 09 and 11 (the signed bundle and how a claim
follows it). A sandbox runs under one policy (ADR-0065, several policies per sandbox, was
rejected), so the binaries need no composition rule. Prompted by a comparison with OpenShell, which attributes each connection to the
calling binary.

## Where it is today

- Every process in the jail shares one identity, the claim's: the claim SVID behind the proxy
  and the phantom token in the environment. The proxy (`crates/mediatore-guest/src/egress.rs`)
  checks host, method and path, never who asked.
- The jail keeps the VM's network namespace (`--disable_clone_newnet` in
  `crates/mediatore-guest/src/jail.rs`) and its own PID namespace; the proxy runs as the
  sandbox user outside it. So the proxy can see the jail's sockets and processes, which
  makes attribution possible without a new mechanism in the syscall path.
- Landlock grants `ReadWrite` on `/work`, `/tmp` and `/home/sandbox`
  (`capability_set` in `crates/mediatore-guest/src/confine.rs`). Whether nono's `ReadWrite`
  includes Landlock's execute right is not checked; if it does, a binary written there can be
  executed, and a path alone cannot identify a binary.
- seccomp (`crates/mediatore-guest/src/seccomp.rs`, ADR-0051) is a static deny filter that
  returns an errno. It denies neither `ptrace` (left to Yama and ADR-0036's `/proc`) nor
  `process_vm_writev`, `memfd_create` or `execveat`. `kernel.yama.ptrace_scope = 1` lets a
  parent ptrace its children, so a workload that starts `git` can drive it.
- A shared library is loaded with `mmap`, which Landlock's execute right does not cover:
  `LD_PRELOAD` of a file in `/work` runs inside any binary the workload starts.

## The design questions for ADR-0066

1. **Where the decision is made.** In the guest's egress proxy, the only enforcement point that
   can see processes. The gateway is unchanged: it still enforces the claim's whole allowlist,
   and per-binary rules only narrow what the proxy forwards inside it. A route with no
   `binaries` behaves as today.
2. **How a connection is attributed to a process.** Proposed: at accept, the proxy maps the
   peer's loopback address to the socket's inode (`NETLINK_SOCK_DIAG`), then to every process
   that holds that inode (`/proc/<pid>/fd` across the jail's processes). No holder, or holders
   of more than one identity, is a refusal. The alternative is seccomp user notification on
   `connect` (OpenShell's way): it gives the PID at the moment of the call, but it adds a
   supervisor in the syscall path and an fd injection (`SECCOMP_IOCTL_NOTIF_ADDFD`) to carry
   the verdict to the proxy. Record it as the option to revisit if attribution at accept proves
   racy.
3. **What a binary's identity is.** The executable as the kernel reports it
   (`/proc/<pid>/exe`) and the SHA-256 of its content, compared with digests the guest computes
   when it unpacks the verified image (ADR-0021), not trust on first use. A binary that is not
   in the image has no identity and matches no rule. An interpreter is the identity of every
   script it runs (`node`, `python3`): the ADR says so plainly, and the script path from argv is
   logged, never matched.
4. **Children.** Proposed: the rule matches the process that holds the socket, not its
   ancestors. Ancestry is spoofable through anything a named binary will run for the workload
   (`git` aliases, hooks, `core.sshCommand`). Helpers are named explicitly
   (`git-remote-https`, `ssh`).
5. **Connections that change hands.** A connected socket can be passed over `AF_UNIX`
   (`SCM_RIGHTS`) or inherited across `fork`. Proposed: the holders are checked again on each
   request of a kept-alive connection, and a holder of another identity is a refusal.
6. **The schema.** A `binaries` list (absolute paths) on a bundle's grant and direct-egress
   entry, signed with the bundle (ADR-0026, ADR-0055), and served on `GET /v1/me`. Rejected at
   admission with a new `P` code: a relative path, or a path under a writable directory.
7. **Rollout.** `policy.binaries: shadow | enforce`, with `shadow` by default as for ADR-0030
   and ADR-0061: in shadow mode the proxy logs `would_refuse` with the binary and forwards.
   Whether the proxy's decisions also go to the broker (as the gateway's do under ADR-0062) is
   left to the ADR.

## Phases

### Phase 0: design

- [ ] ADR-0066 written and accepted, the questions above decided. Phase 1 may become an ADR of
      its own that amends ADR-0024 and ADR-0051, if it lands before the rest.
- [ ] CALM: the egress proxy's reading of the jail's processes and the image digests;
      `make calm-validate` and `make calm-diagrams`.
- [ ] notaio: the bundle's `binaries` field agreed with its schema.

### Phase 1: an identity a workload cannot forge

Each item is test-first in `confine.rs` or `seccomp.rs`, and proven live in
`crates/mediatore/tests/jail_exec_live.rs` on the build host.

- [ ] No execute in the writable directories: Landlock's execute right granted on the image
      only. Live test: a binary copied to `/work` fails with `EACCES`.
- [ ] seccomp denies `ptrace`, `process_vm_writev` and `process_vm_readv` inside the jail.
      Decide whether only when a route names binaries, or always (a debugger in the jail is the
      cost). Live test: `strace` of a child is refused.
- [ ] seccomp denies `memfd_create` and `execveat` with `AT_EMPTY_PATH`, so no anonymous code
      can be executed.
- [ ] A loaded library outside the image: the proxy checks `/proc/<pid>/maps` of the holder,
      and any executable mapping of a file outside the image paths makes the process
      unidentified. Live test: `LD_PRELOAD=/work/x.so git` is refused on a `git` route.
- [ ] The image's digests: computed once at unpack, held by the guest outside the jail, keyed by
      the in-jail path.

### Phase 2: attribution in the proxy

- [ ] An `attrib` module in `crates/mediatore-guest`: socket inode from the peer address, then
      holders, then identities. The pure parts are unit-tested against a fake `/proc` tree that
      is never more permissive than the kernel (`rules/testing.md`, rule 2): a socket with no
      holder, two holders of one identity, two of different identities, a holder that has
      exited.
- [ ] Each request on a kept-alive connection checked again (question 5).
- [ ] A live test on the build host: two binaries from one image, only one attributed to the
      route.
- [ ] The cost per connection measured, and recorded in the ADR.

### Phase 3: the schema and serving

- [ ] `binaries` in `crates/mediatore-claims`' policy types, validated (the new `P` code).
- [ ] Served on `GET /v1/me`, and rendered into the proxy's routes.
- [ ] A running claim following a newer bundle (ADR-0061): a narrowed `binaries` list applies
      to the next connection.

### Phase 4: enforcement

- [ ] `policy.binaries: shadow | enforce` in the broker's configuration, refused at start when
      it is anything else.
- [ ] Enforce: `403 binary_not_allowed`, with the route, the binary path and its digest prefix
      in the log. Never the token, the phantom or the argv of a binary that is not an
      interpreter.
- [ ] e2e in `crates/mediatore/tests/e2e_egress.rs` using two test-kit binaries: the named one
      forwarded; the other refused under `enforce` and logged under `shadow`; a binary copied to
      `/work` refused; a route without `binaries` unchanged.

### Phase 5: docs, threat model, live proof

- [ ] `docs/guides/the-policy-bundle.md`: `binaries`, interpreters, helpers, and the rollout.
- [ ] Threat-model pass: the proxy as a reader of the jail's `/proc`; the named binary as a
      confused deputy (an allowed `git` still sends whatever the workload tells it to, within
      the route's rules); interpreters as one identity; stamp bumped.
- [ ] Live on the homelab: in one Claude Code sandbox, `git` clones through the gateway, `node`
      reaches the Anthropic API, and `curl` to either is refused.
