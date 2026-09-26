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
