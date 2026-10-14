<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0014: One binary, the roles as subcommands

**Status:** Accepted · **Date:** 2026-10-15

Consolidates the four executables that [ADR-0002](0002-separate-project-from-banlieue.md)
and [ADR-0013](0013-dex-session-delegation.md) accumulated into the one `mediatore`
binary. Amends the node entry selector of
[ADR-0006](0006-registration-entries-as-clusterstaticentry.md) and the jail layout of
[ADR-0007](0007-broker-identity-and-spiffe-mtls.md) decision 5.

## Context

mediatore shipped four executables with four names: `mediatore` (the broker), `mediatore-guest`
(the root agent on a pool member), `sandbox-token` (the workload's client inside the jail)
and `mediatore-cli` (the user's login and claim tool). Each was its own crate with its own
`main.rs`, its own clap tree, its own tracing setup and, for the two guest roles, its own
copy of the SPIFFE mTLS client over the Workload API. The names leaked everywhere: the
Makefile and the build workflow listed them, the kind tier had a second, test-only image to
carry the guest pair, the VM image's systemd unit, the demo script, the guides and the
threat model each spelled them out, and a reader had to learn which name ran where before
they could follow a flow.

Nothing in the split was load-bearing. The roles already shared the wire types
(`mediatore-proto`) and the TLS stack (`mediatore-tls`), every one of them is a static musl
build on Linux, and none of them carries a secret or a privilege of its own: a role's
authority comes from what it can reach at run time (the broker's SVID over the CSI mount,
the node SVID over the agent socket as root, the claim SVID as the `sb-` user, the user's
session at the issuer), never from which file was executed. The `dev` cargo feature that
unlocks the loopback header path is the one build-time distinction, and it belongs to the
build, not to the name.

## Decision

**1. One binary, `mediatore`, and the roles are subcommands.** `mediatore serve` is the
broker; `mediatore guest` is the root agent on a pool member; `mediatore token --audience`
is what a workload runs inside the jail; `mediatore login`, `mediatore sandbox create`,
`mediatore sandbox get`, `mediatore sandbox delete` and `mediatore session` are the user's
tools; `mediatore revoke` keeps its place as the admin stub. The tree is one clap
definition in `crates/mediatore/src/main.rs`, and a test asserts it parses the invocations
the manifests, the units and the guides use. Every role initialises logging the same way,
to standard error, so standard output is the role's result alone: `mediatore token` prints
the token and nothing else, which is what `TOKEN=$(mediatore token ...)` needs.

**2. The roles stay in their crates, as libraries.** `crates/mediatore-guest` keeps the VM
side (`guest` and `token`, sharing one `SandboxClient` over the node or claim SVID) and
`crates/sandbox-token` folds into it. `crates/mediatore-cli` becomes
`crates/mediatore-client`, the user side (PKCE login, the session file, the user API
client). Each exports its clap `Args` and a `run`, and the `mediatore` crate composes them.
The `dev` feature lives on the `mediatore` crate and forwards to `mediatore-guest/dev`;
`make dist`, the Dockerfile and the build workflow never enable it, so a release binary
has no header path in any role (ADR-0007 decision 5 is unchanged). `mediatore-testkit`
stays a dev-dependency only.

**3. One artifact.** `make dist` builds one static musl `mediatore` and that file is what
the server image, the VM image and the kind tiers carry. The test-only guest image
(`dev/kind/Dockerfile.guest`) goes: the kind pods that play a node or a workload run the
server image with a different subcommand. The build workflow publishes the one binary with
its SBOM instead of a guest pair.

**4. The jail gets the same binary, bind-mounted read-only.** The guest adds its own
executable (`std::env::current_exe()`) to the nsjail spec as a read-only bind mount at
`/usr/local/bin/mediatore`, so the workload rootfs no longer has to ship a client:
`mediatore token` is on the path of every sandbox. The binary is static, read-only, not
setuid and holds no secret, so the mount adds no authority inside the jail: `mediatore
serve` in there has no broker SVID, `mediatore guest` has no TPM and no root, and the
Workload API socket yields the claim SVID only.

**5. The node entry pins the new path, and the uid is what tells the roles apart.** The
node entry's selectors become `unix:uid:0` and `unix:path:/usr/local/bin/mediatore`
(`GUEST_AGENT_PATH`), amending ADR-0006's table. Because the jailed workload can now
present that same path, the `unix:uid:0` selector is the one that distinguishes the node
from the jail; SPIRE requires every selector of an entry to match, as it always did, and
the claim entry keeps `unix:user:<sb-user>`. A node entry declared before this change is
not rewritten (the entry manager leaves an existing object alone): delete it and the next
registration declares it with the new selector.

## Alternatives considered

- **Keep the split, align the names** (`mediatore-serve`, `mediatore-guest`,
  `mediatore-token`, `mediatore-login`): four binaries, four trees, the same duplicated
  client and the same second image. Rejected; the names were the symptom, not the problem.
- **Two binaries, broker and guest**: halves the duplication but keeps a second artifact
  and still asks the reader which binary a role lives in. Rejected for the same reason.
- **Cargo features that strip roles out of the binary** (`--no-default-features
  --features guest`): one source, several artifacts, and the question of which artifact
  a host carries comes back. Rejected; the size difference is a few megabytes of static
  binary on hosts that carry a rootfs anyway.

## Consequences

- `crates/sandbox-token` is gone; `crates/mediatore-cli` is `crates/mediatore-client`;
  `crates/mediatore-guest` and `crates/mediatore-client` have no `[[bin]]`; the `mediatore`
  crate gains the `dev` feature and the command tree.
- The VM image carries one binary about three times the size of the old guest agent, and
  the jail mounts it instead of the rootfs shipping a client. `image/systemd/mediatore-guest.service`
  runs `mediatore guest`.
- The Makefile loses the `guest` target and the guest image; `make dist`, `make kind-images`
  and `make e2e` build the one binary; the build workflow's artifact is
  `mediatore-linux-amd64-musl`.
- ADR-0006's selector table reads `/usr/local/bin/mediatore`; the kind tiers start from a
  fresh cluster, so no entry there predates the change.
- The guides, the CALM model, the README and the threat model name the subcommands
  (`mediatore guest`, `mediatore token`, `mediatore login`, `mediatore sandbox create`)
  instead of the old binaries; the threat model's TB-7 gains the row for the binary in the
  jail.
