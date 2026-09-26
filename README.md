# mediatore

> **mediatore** (Italian: *broker*, *go-between*; IPA /me.dja.ˈto.re/, "meh-dyah-TOH-reh")
>
> A trusted go-between for [banlieue](https://github.com/firestoned/banlieue) sandbox VMs.
> mediatore takes a person's login at the front, an attested virtual machine at the back, and
> makes sure the two are bound to each other before anything inside the VM can act on that
> person's behalf.

[![Build](https://github.com/firestoned/mediatore/actions/workflows/ci.yaml/badge.svg?branch=main)](https://github.com/firestoned/mediatore/actions/workflows/ci.yaml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Rust](https://img.shields.io/badge/rust-1.96%2B-orange.svg?logo=rust)
![Status](https://img.shields.io/badge/status-scaffold-orange.svg)

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
```

## Status

Scaffold. The crate boundaries, wire types, state machine and configuration shape are the
design; the network edges are stubs that fail closed (`501 not_implemented`):

| Piece | State |
| --- | --- |
| Wire types, username derivation, STS minting, in-memory store | implemented, unit-tested |
| HTTP routing, auth extractors, audience checks, token issuance (sts) | implemented in `dev_mode` |
| JWKS validation of upstream tokens | stub |
| Entra OBO exchange | request shape done, untested |
| SPIRE entry management over `spire-api-sdk` | trait + `Noop` |
| `VirtualMachineClaim` watch (needs `banlieue-api` pin) | client wiring only |
| SPIFFE mTLS on the sandbox listener | stub (dev header) |
| sqlx store (PostgreSQL / SQLite) | not started |
| Guest: node registration, subject fetch, jail supervision | identity + jail builder only |

## Development

```bash
# quality gate
cargo fmt --all && cargo clippy --all-targets --all-features -- -D warnings && cargo test --all
cargo deny check

# run the server in dev mode (header-based peer identity, in-memory store)
openssl ecparam -name prime256v1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out dev/sts.pem
cargo run -p mediatore -- serve --config dev/mediatore.yaml

# static guest binaries
cargo xguest
```

See [`docs/adr`](docs/adr) for decisions and the runbook for the end-to-end setup.

## License

Apache License 2.0. See [LICENSE](LICENSE).
