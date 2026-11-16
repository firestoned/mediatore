<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Testing and fakes

How the code is proven, in tiers, and the rules the fakes keep. The guide [Testing tiers](../guides/testing.md) says how to
run each tier and records the live runs; this page is how the suite is built and what each layer is for.

## The rules

These are the project's testing standards (`.claude/rules/testing.md`), and each is enforced by a test, not by a comment.

1. **Test first.** A feature starts with a failing test and a bug fix with a test that reproduces it. The test is written,
   seen to fail for the right reason, and only then is the code written.
2. **Fail closed.** An unimplemented path returns an error (`501 not_implemented`), and a test proves the refusal. A
   permissive default is a bug.
3. **A fake is no more permissive than the real thing.** When the real implementation lands and a live test finds a
   behaviour the fake got wrong, the fake is fixed in the same change.
4. **A test that skips never reports success.** A live test (`#[ignore]`) fails loudly when its fixture is missing.
5. **Never log or assert on secret material.** Tests inspect a token's claims after verification, not raw tokens.
6. **The gate** (`make check`): format, clippy with warnings as errors (pedantic is on through the workspace lints), the
   whole test suite and `cargo deny`. A change that touches a `.rs` file is not done until all four pass.

## Where a test lives

| Kind | Where | Runs |
| --- | --- | --- |
| unit | an embedded `#[cfg(test)] mod tests` at the bottom of the source file (crates are small and few-file; there is no separate `_tests.rs`) | `cargo test` |
| the store contract | `crates/mediatore-store/src/conformance.rs`: one case per behaviour, run against **each** store implementation | `cargo test` |
| end to end, hermetic | `crates/mediatore/tests/e2e_*.rs`: the real broker, the real proxy and guest code, over real HTTP listeners, with the test kit's fakes | `cargo test` |
| live, in a kind cluster | `make kind-e2e-*` (SPIRE, mTLS, the watcher, the sandbox CRD, policy, the gateway, Dex, TPM) | by hand and in CI |
| live, on the build host | `jail_exec_live.rs` (Landlock on a real kernel), `live_entra.rs` (a real Entra tenant), `kind-e2e-tpm` | by hand, `#[ignore]` |

A test that exercises a new endpoint lives in the hermetic end-to-end suite and covers the **negative** cases too: the wrong
audience, the wrong SVID type, the wrong subject, a revoked claim.

## The end-to-end files

| File | Proves |
| --- | --- |
| `e2e_dev.rs` | the dev-mode loop front to back over real listeners |
| `e2e_mtls.rs` | the sandbox API over SPIFFE mutual TLS, hermetically |
| `e2e_sandbox.rs` | the user API outside `dev_mode`: `POST` creates an `AgentSandbox` with the token's subject, `GET` answers from its status, `DELETE` deletes |
| `e2e_session.rs`, `e2e_issuers.rs` | the delegated session, issuer profiles, refresh and rotation |
| `e2e_entra.rs`, `live_entra.rs` | the Entra On-Behalf-Of path, against the fake issuer and (by hand) a real tenant |
| `e2e_egress.rs`, `e2e_forward.rs` | the egress proxy, and the forwarder through a gateway |
| `e2e_gateway.rs` | the gateway's authorizer against the broker |
| `egress_upstream_tls.rs` | the proxy's TLS to an upstream |
| `transit_sealer.rs` | the transit sealer against a fake OpenBao |
| `jail_exec_live.rs` | the real `jail-exec` on a kernel with Landlock |

## The test kit

`crates/mediatore-testkit` is **test-only and never a dependency of a shipped binary.** Its parts stand in for the
systems mediatore does not own:

| Part | Stands in for |
| --- | --- |
| `FakeIdp` | Dex or Entra: OIDC discovery and a JWKS over a real listener, ES256 tokens with whatever claims a test asks for, the authorization-code flow with PKCE, and the `refresh_token` grant with rotation, with hooks to change a user's groups, revoke a session or take the issuer down |
| `TestCa`, `MemoryMaterial` | the SPIRE server's CA and the Workload API: SPIFFE-shaped SVIDs the real mTLS verifiers accept, with rotation driven by hand |
| `MemorySandboxes` | the Kubernetes API behind the user API's `AgentSandbox` front door |
| `StandInGateway` | the egress gateway, on the production mTLS configuration, so the forwarder is proven with no Envoy (the proxy's own unit tests add a `FakeGateway` that records what reached an inject port) |
| `FakeRegistry` | an OCI registry: tags, digests, an index, a bearer or basic challenge, a token endpoint, a redirect, a tampered blob; `start_under(prefix)` serves it under a path as the guest's proxy presents a placed registry |
| the transit fake | OpenBao's transit engine: derived keys, the key id, token renewal after a revocation, an outage |
| `TlsUpstream` | a TLS upstream on a CA of its own, that records what reached it |
| `policy`, `ek` | a signed notaio bundle; endorsement-key fixtures |

Because the fakes sit on the **production code paths** (the same verifiers, the same stores' contract, the same proxy), a
hermetic test exercises what runs in production and differs only in the certificates and the network.

## What each tier cannot show

- The hermetic tiers cannot show a real kernel, a real TPM, a real registry or a real upstream. `jail_exec_live`, the kind
  tiers and a live run do.
- A clean start of the broker does not show a claim can be served. Run a claim after a configuration change.
- The TPM attestation path is **proven on the build host before a change to it merges**: GitHub-hosted runners have no
  `tpm_vtpm_proxy`, so `make kind-e2e-tpm` is not in CI. A green `make check` is not a substitute.

## Rules this part keeps

- A behaviour two implementations must share is a conformance case.
- A fake that disagrees with the real thing is a bug in the fake.
- A skipped live test fails.
- The test kit is never linked into a shipped binary.

## Read next

`.claude/rules/testing.md` for the standards as written, the guide [Testing tiers](../guides/testing.md) for the commands
and the live-run record, and the [threat model](../security/threat-model.md) for what each control's test is named.
