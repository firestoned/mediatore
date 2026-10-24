<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Testing Standards

## TDD is mandatory

Red → Green → Refactor for all code changes: new features start with a failing test,
bug fixes start with a test that reproduces the bug. Exceptions: marked prototype code
(removed before merging) and mechanical refactors covered by existing tests.

## Quality gate

After ANY `.rs` change, and before every commit:

```sh
make check   # fmt + clippy -D warnings (pedantic) + test + deny
```

The task is not complete until all four pass. Clippy warnings are fixed, not allowed,
unless the allow carries a one-line justification.

## Test placement (mediatore convention)

- **Unit tests:** embedded `#[cfg(test)] mod tests` at the bottom of the source file.
  (This deliberately differs from banlieue's separate `_tests.rs` files: mediatore's
  crates are small and single-file.)
- **End-to-end:** `crates/mediatore/tests/e2e_dev.rs` drives the full loop over real
  HTTP listeners with `mediatore-testkit`'s fake IdP. New endpoints get e2e coverage
  there, negative cases included (wrong audience, wrong SVID type, wrong subject,
  revoked claim).
- **Test-only helpers** live in `mediatore-testkit`, which must never become a
  dependency of a shipped binary.

## Rules the suite enforces

1. **Fail closed.** An unimplemented path returns an error (`501 not_implemented`),
   and there is a test proving the refusal. A permissive default is a bug.
2. **A fake more permissive than the real thing hides bugs.** When the mTLS, SPIRE
   gRPC or sqlx implementations land, any behaviour a live test finds that the fake
   (dev header, `Noop`, `MemoryStore`) got wrong is fixed in the fake in the same
   change.
3. **A test that skips must never report success.** Live tests (`#[ignore]`) fail
   loudly when their fixture is missing.
4. **Never log or assert on secret material.** Tests inspect token *claims* after
   verification, not raw tokens in logs.

## The TPM attestation path is proven on-prem before it merges

GitHub-hosted runners cannot run `make kind-e2e-tpm`: their Azure kernels have no
`tpm_vtpm_proxy` module (not even in `linux-modules-extra`, checked 2026-10-24). So the
tier is not in CI, and the rule is: **whenever a change touches the TPM attestation
path, run the tier by hand on the build host before the commit is handed back**, and
state the result (`PASS`, the agent ID it attested as) in the report and the PR.

What counts as the TPM attestation path, any file under or matching:

- `deploy/spire-tpm/` (the component: StatefulSet patch, EK CA ConfigMap, `server.conf` fragment)
- `dev/kind/spire/` (the rendered SPIRE and the generated `server-conf-patch.yaml`)
- `dev/kind/vtpm.sh`, `dev/kind/tpm-e2e.sh`, `dev/kind/cluster.yaml`
- `image/spire/`, `image/systemd/spire-agent.service`
- `crates/mediatore-proto/src/ek.rs` and anything else that computes or validates the EK hash
- the node entry's shape (`ensure_node_entry`, `agent_id`, `node_id` in `crates/mediatore-spire`)
- `crates/mediatore-guest/src/identity.rs` and the guest's registration path
- the `TPM_PLUGIN_*` pins, `kind-vtpm`, `kind-create`, `kind-delete` and `kind-e2e-tpm` in the `Makefile`

The command, from a tree synced to the build host (the cluster recreated so the device
is mounted at creation):

```sh
make kind-delete
make kind-e2e-ci KIND_E2E_SUITES=kind-e2e-tpm   # plus the provider and CLI variables the host needs
```

A green `make check` and a green CI are not a substitute: neither exercises a TPM. If the
host is unavailable, say so in the report and do not call the change verified.
