<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# mediatore

> **mediatore** (Italian: *broker*, *go-between*; IPA /me.dja.ˈto.re/, "meh-dyah-TOH-reh")
>
> A trusted go-between for [banlieue](https://github.com/firestoned/banlieue) sandbox VMs.
> mediatore takes a person's login at the front, an attested virtual machine at the back, and
> makes sure the two are bound to each other before anything inside the VM can act on that
> person's behalf.

[![Build](https://github.com/firestoned/mediatore/actions/workflows/build.yaml/badge.svg?branch=main)](https://github.com/firestoned/mediatore/actions/workflows/build.yaml)
[![E2E](https://github.com/firestoned/mediatore/actions/workflows/e2e.yaml/badge.svg?branch=main)](https://github.com/firestoned/mediatore/actions/workflows/e2e.yaml)
[![Documentation](https://github.com/firestoned/mediatore/actions/workflows/docs.yaml/badge.svg?branch=main)](https://firestoned.github.io/mediatore/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Rust](https://img.shields.io/badge/rust-1.96%2B-orange.svg?logo=rust)

banlieue schedules VMs and hands them out through `VirtualMachineClaim`s, but deliberately
carries no credential: a claim records *who* a sandbox is for, and stops there. mediatore is
the component that finishes the story.

- **Front door.** Accepts an Entra ID token (or a Dex-bridged GitHub login in a homelab),
  validates it, and creates the `VirtualMachineClaim` with the subject taken from the token.
- **Binding.** When the claim binds to a pool member that has already attested its vTPM to
  SPIRE, mediatore registers a SPIFFE identity for that claim, scoped to that VM and to the
  per-subject Linux user the in-guest agent creates.
- **Delegation.** The jailed workload presents its SVID and asks for a token for one downstream
  audience. mediatore answers with a short-lived, audience-scoped token, minted via Entra
  On-Behalf-Of or by its own STS. The user's original token never enters the VM.
- **Cut-off.** When the claim expires or is deleted, mediatore removes the SPIFFE entry and
  stops issuing.

How a user, a delegating agent (On-Behalf-Of) or an app-only service actually gets code
running in a sandbox: [docs/guides/running-workloads.md](docs/guides/running-workloads.md).
Phase status: [ROADMAPS.md](ROADMAPS.md).

## Repository layout

```
crates/
├── mediatore-proto/    shared wire types (nodes, me, token); server and guest both depend on it
├── mediatore-api/      axum routers: user-facing (bearer) and sandbox-facing (SPIFFE mTLS)
├── mediatore-entra/    upstream token validation (Entra, Dex), Entra On-Behalf-Of
├── mediatore-sts/      self-issued ES256 tokens with an RFC 8693 `act` claim
├── mediatore-spire/    SPIRE server API boundary (registration entries)
├── mediatore-claims/   kube-rs watcher: Bound → entry, Releasing → cut-off
├── mediatore-store/    ClaimStore trait + in-memory impl (sqlx next)
├── mediatore/          server binary
├── mediatore-guest/    in-guest agent (static musl)
└── sandbox-token/      workload-side CLI (static musl)
deploy/                 raw manifests (kustomize), Traefik IngressRoute
image/                  systemd units + cloud-config fragments baked into the VM image
docs/adr/               architecture decision records
docs/architecture/      FINOS CALM model + rendered Mermaid diagrams
docs/guides/            operational guides (enterprise SPIRE topology, ...)
docs/security/          threat model (living document, stamped per ADR range)
```

## Methodology

mediatore follows the same **Architecture Driven Development** cycle as banlieue —
`ADR → CALM → TDD → implement → docs → threat model` — with the rules in
[`.claude/rules/`](.claude/rules/). The architecture is modeled in
[CALM](docs/architecture/calm/architecture.json) (`make calm-validate`,
`make calm-diagrams`; CI fails on diagram drift), and every implemented ADR ends with a
full pass over the [threat model](docs/security/threat-model.md). CI is Makefile-driven:
each workflow job calls a `make` target that runs identically locally.

## Status

The dev-mode loop is implemented and tested front to back: fake IdP login → claim →
bind → `/v1/me` → `/v1/token` → STS JWT verified against mediatore's own JWKS →
release → cut-off. The remaining edges fail closed (`501 not_implemented`):

| Piece | State |
| --- | --- |
| Wire types, username derivation, STS minting (JWKS derived from the key), in-memory store | implemented, unit-tested |
| HTTP routing, auth extractors, audience checks, token issuance (sts) | implemented, e2e-tested |
| JWKS validation of upstream tokens (discovery, cache, kid rotation, group gate) | implemented, tested against a fake IdP |
| Claim lifecycle in `dev_mode` (create, dev bind either order, mirror, release) | implemented, e2e-tested |
| Guest: node registration, subject fetch, user + jail supervision | implemented; jail path needs a Linux host |
| Entra OBO exchange | request shape done, untested |
| SPIRE entry management over `spire-api-sdk` | trait + `Noop` |
| `VirtualMachineClaim` watch (needs `banlieue-api` pin) | client wiring only |
| SPIFFE mTLS on the sandbox listener | stub (dev header) |
| sqlx store (PostgreSQL / SQLite) | not started |

## Development

```bash
# quality gate
cargo fmt --all && cargo clippy --all-targets --all-features -- -D warnings && cargo test --all
cargo deny check

# front-to-back dev-mode demo: fake IdP + server + guest agent + sandbox-token
./dev/demo.sh

# run the server in dev mode (header-based peer identity, in-memory store)
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out dev/sts.pem
cargo run -p mediatore -- serve --config dev/mediatore.yaml

# static guest binaries
cargo xguest
```

See [`docs/adr`](docs/adr) for decisions and the runbook for the end-to-end setup.

## License

Apache License 2.0. See [LICENSE](LICENSE).
