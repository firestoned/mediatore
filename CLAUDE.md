<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Working on mediatore

- Read `docs/adr` first. A change to a trust boundary, token shape, SPIFFE ID scheme or storage
  contract starts with an ADR (ADR → CALM → TDD), not with code.
- Quality gate before any commit: `cargo fmt --all && cargo clippy --all-targets --all-features -- -D warnings && cargo test --all && cargo deny check`.
- No em-dashes in prose or comments.
- Never log tokens, refresh material or private keys. Log claim UIDs, SPIFFE IDs, audiences, subjects.
- Fail closed: an unimplemented path returns an error (`501 not_implemented`), never a permissive default.
- `dev_mode` exists for local runs only; anything that reads the peer identity from a header must be gated on it.
- Licenses: permissive or foundation-governed only; `cargo deny` enforces the allowlist.

Full rules, adapted from banlieue, live in `.claude/rules/`:

- `rules/architecture-driven-development.md` — the ADD cycle and when it applies.
- `rules/testing.md` — TDD, the quality gate (`make check`), test placement.
- `rules/threat-modeling.md` — full pass over `docs/security/threat-model.md` after every implemented ADR; the header stamp is the deliverable.
- `rules/github-workflows.md` — Makefile-driven workflows, firestoned/github-actions composites, SHA pinning, `workflow_call`.
- `rules/no-real-infrastructure.md` — public repo; placeholders only, sweep the diff before finishing.
