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
├── mediatore-claims/   AgentSandbox CRD + reconciler; kube-rs watcher: Bound → entry, Releasing → cut-off
├── mediatore-store/    ClaimStore trait; sqlx store over SQLite or PostgreSQL; sealed refresh envelope; in-memory impl for dev_mode
├── mediatore/          server binary
├── mediatore-guest/    in-guest agent (static musl)
├── sandbox-token/      workload-side CLI (static musl)
└── mediatore-cli/      user-side CLI: PKCE login at the issuer, claims with the session delegated (ADR-0013)
deploy/                 raw manifests (kustomize), Traefik IngressRoute
image/                  systemd units + cloud-config fragments baked into the VM image
docs/adr/               architecture decision records
docs/architecture/      FINOS CALM model + rendered Mermaid diagrams
docs/guides/            operational guides (requesting a sandbox, the store, testing tiers, enterprise SPIRE topology)
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
| Wire types, username derivation, STS minting (JWKS derived from the key) | implemented, unit-tested |
| HTTP routing, auth extractors, audience checks, token issuance (sts) | implemented, e2e-tested |
| JWKS validation of upstream tokens (discovery, cache, kid rotation, group gate) | implemented, tested against a fake IdP |
| Claim lifecycle in `dev_mode` (create, dev bind either order, mirror, release) | implemented, e2e-tested |
| Guest: node registration, subject fetch, user + jail supervision | implemented; jail path needs a Linux host |
| Dex path (ADR-0013): the session delegated with the claim as a sealed envelope, refreshed before every issue with the fresh groups minted, `invalid_grant` or a failed group gate releasing the claim at once, an outage a `503` that revokes nothing, per-claim rate limiting, `mediatore-cli` (PKCE as mediatore's public client) | implemented (`mediatore-entra::Validator::refresh`, `mediatore-api`, `mediatore-cli`), e2e-tested against the fake issuer's real authorization-code and refresh grants (`crates/mediatore/tests/e2e_session.rs`); a Dex in kind is the next slice |
| Entra OBO exchange | request shape done, untested; next slice of roadmap 04 |
| SPIRE entries as `ClusterStaticEntry` through the Kubernetes API (ADR-0006, no gRPC) | implemented (`KubeEntryManager`), tested against a scripted fake API server, live against SPIRE in kind on every PR (`make kind-e2e`) and live against a real cluster (`make live-admission-test`), both as the broker ServiceAccount |
| `VirtualMachineClaim` watch: bind by the EK hash banlieue mirrors onto the claim, release on Releasing / Failed / deletion and at resync, node entries from pool members, one leader by Lease (ADR-0011, `banlieue-api` pinned) | implemented (`mediatore-claims::watch`, `::lease`), unit-tested over the in-memory store and entries, live in kind (`make kind-e2e-watcher`: the Lease, the node-entry trigger, a claim without a record binding nothing) |
| SPIFFE mTLS on the sandbox listener, broker SVID from the Workload API over the SPIFFE CSI driver, guests verifying the broker by SPIFFE ID (ADR-0007) | implemented (`mediatore-tls` on rustls, `spiffe` for the Workload API), e2e-tested with a test CA (`make check`) and live against SPIRE in kind on every PR (`make kind-e2e-mtls`: the broker image on the CSI driver's socket, agent-issued client SVIDs on the listener); the `dev_mode` header path is loopback-only |
| Post-quantum key exchange: X25519MLKEM768 only on the sandbox leg (AES-256-GCM-SHA384 only), offered first everywhere else; ML-DSA SVIDs already verified end to end | implemented, pinned by tests (`crates/mediatore-tls/tests/handshake.rs`); signatures wait on SPIRE and JOSE (threat model R-8) |
| Persistent store (ADR-0012): one sqlx query set over SQLite or PostgreSQL chosen by URL, PostgreSQL only over `verify-full` with the URL in a Secret, refresh material as a sealed envelope bound to its claim, ended rows swept into an audit table, revocations and the node registry surviving a restart, `/healthz` pinging the store | implemented (`mediatore-store::sql`, `::seal`), the conformance suite over the in-memory store and SQLite in `make check` and over PostgreSQL in kind on every PR (`make kind-e2e-store`; every kind tier runs the broker on it, the sandbox tier restarts it) |
| `AgentSandbox` CRD and reconciler (ADR-0008): one owned `VirtualMachineClaim` per sandbox, the store record keyed by the claim's UID, status mirrored plus `ready`, the subject pinned to the caller at admission, a finalizer that releases before the object goes; `POST /v1/claims` creates the resource | implemented (`mediatore-claims::sandbox`, `deploy/base/crds`, `deploy/base/admission/agentsandbox-subject.yaml`), unit-tested, the user API e2e-tested over a fake API server, live in kind on every PR (`make kind-e2e-sandbox`: policy, owned claim, bind to Ready with the guest fetching the subject, finalizer) |

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
