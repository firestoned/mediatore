# Working on mediatore

- Read `docs/adr` first. A change to a trust boundary, token shape, SPIFFE ID scheme or storage
  contract starts with an ADR (ADR → CALM → TDD), not with code.
- Quality gate before any commit: `cargo fmt --all && cargo clippy --all-targets --all-features -- -D warnings && cargo test --all && cargo deny check`.
- No em-dashes in prose or comments.
- Never log tokens, refresh material or private keys. Log claim UIDs, SPIFFE IDs, audiences, subjects.
- Fail closed: an unimplemented path returns an error (`501 not_implemented`), never a permissive default.
- `dev_mode` exists for local runs only; anything that reads the peer identity from a header must be gated on it.
- Licenses: permissive or foundation-governed only; `cargo deny` enforces the allowlist.
