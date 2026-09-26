<!--
Copyright (c) 2026 Erick Bourgeois, mediatore
SPDX-License-Identifier: Apache-2.0
-->
# Threat Model

> **Status:** Living document. Last full pass **2026-09-26**, against the
> architecture defined by **ADR-0001 … ADR-0004**. This is the first pass; it
> covers the implemented dev-mode loop (upstream token validation, claim
> lifecycle, STS issuance, release cut-off) and records every not-yet-built
> edge (SPIFFE mTLS, SPIRE gRPC, Entra OBO, sqlx store) as either a
> fail-closed stub or an accepted risk with a revisit condition — never as a
> control that exists.
>
> **Method:** asset/actor enumeration, trust-boundary decomposition, STRIDE
> per boundary, control mapping to the crates in `crates/` and the manifests
> in `deploy/`.
>
> This document describes *what mediatore defends, from whom, and how*. It is
> the companion to [`SECURITY.md`](../../SECURITY.md), which describes how to
> **report** a vulnerability. Specific unremediated findings go through
> [private vulnerability reporting](https://github.com/firestoned/mediatore/security/advisories/new),
> never this page.

## 1. What mediatore is, in security terms

mediatore turns "a person logged in" into "a process on an attested VM may act
as that person, for one audience at a time, for fifteen minutes at a time". It
holds three things an attacker wants:

1. **The power to mint delegated tokens.** Via Entra On-Behalf-Of refresh
   material or its own STS signing key, mediatore can produce a token that
   downstream APIs accept as "on behalf of user X".
2. **The subject binding.** It writes `spec.subject` on every
   `VirtualMachineClaim` it creates; corrupt that and a sandbox is issued to
   the wrong person.
3. **SPIRE entry administration.** It decides which SPIFFE identity exists on
   which node; a forged entry is a forged workload identity.

## 2. Components

| Component | Crate / manifest | Runs where | Privilege |
| --- | --- | --- | --- |
| User API (bearer) | `crates/mediatore-api`, `crates/mediatore-entra` | `banlieue-system` pod | Creates claims as the broker ServiceAccount |
| Sandbox API (SPIFFE) | `crates/mediatore-api` | same pod | Issues tokens; reads node/claim identity |
| Claim watcher | `crates/mediatore-claims` | same pod (leader-elected) | SPIRE admin (entry create/delete) |
| STS | `crates/mediatore-sts` | same pod | Holds the signing key handle |
| Claim store | `crates/mediatore-store` | in-memory today; PostgreSQL/SQLite next | Refresh ciphertext, subject rows |
| In-guest agent | `crates/mediatore-guest` | root on each pool member | `useradd`, mount, nsjail |
| Workload CLI | `crates/sandbox-token` | inside the jail, as the `sb-` user | Holds one token in memory |
| Deployment | `deploy/base/*.yaml` | management cluster | SA, RBAC, ClusterSPIFFEID, ingress |

## 3. Assets

| # | Asset | Where | Impact if stolen / forged |
| --- | --- | --- | --- |
| A-1 | STS signing key | file (`sts.signing_key_file`) or OpenBao transit | Mint tokens for any configured audience and any subject |
| A-2 | Entra refresh material | store rows, ciphertext only | Act as the user for the claim's TTL against consented APIs |
| A-3 | Upstream bearer tokens in flight | `POST /v1/claims` request | Create claims as the user until `exp` |
| A-4 | Issued access tokens | workload memory, ≤ 15 min | One audience, until expiry |
| A-5 | Claim ↔ subject ↔ node binding | store + SPIRE entries | Sandbox issued to, or read by, the wrong person |
| A-6 | EK-hash ↔ DMI-UUID registry | store `nodes` table | A cloned or impostor VM accepted as a pool member |
| A-7 | Broker Kubernetes ServiceAccount | pod token | Create claims with arbitrary `spec.subject` (VAP-exempt) |

## 4. Actors

| Actor | Trust level | Notes |
| --- | --- | --- |
| Sandbox user | Authenticated, not trusted | May only claim for themself; group-gated |
| Jailed workload | Hostile by assumption | Prompt-injected agents run here; that is the design case |
| In-guest agent | Trusted root on the VM | Bounded by the VM's own blast radius |
| Pool VM (pre-claim) | Attested hardware identity, no subject | Holds a node SVID only |
| banlieue control plane | Trusted | Binds claims; never sees tokens |
| SPIRE server | Trusted | Root of workload identity |
| Upstream IdP | Trusted for authentication | Entra / Dex; group membership is the authz gate |
| Cluster operator | Trusted | Can read anything in the namespace; see §8 |

## 5. Trust boundaries

```text
                 (TB-1) bearer HTTPS                (TB-2) Kubernetes API
  Sandbox User ──────────────► mediatore ◄──────────────► banlieue / VAP
       │                      │  user API │ watcher
       │ OIDC login           │           │ (TB-3) SPIRE admin gRPC
       ▼                      │           ▼
  IdP (Entra/Dex) ◄───────────┘      SPIRE Server
   (TB-5) JWKS / OBO                      ▲
                                          │ (TB-4) TPM node attestation
  ┌─── sandbox network segment ───────────┼──────────────────────────────┐
  │  Pool VM:  spire-agent ───────────────┘                              │
  │            mediatore-guest ──(TB-6) mTLS──► mediatore sandbox API    │
  │            ┌─jail (nsjail)─┐                                         │
  │            │  workload ────┼──(TB-6) mTLS──► POST /v1/token          │
  │            │               ┼──(TB-7)──────► downstream APIs          │
  │            └───────────────┘                                         │
  └──────────────────────────────────────────────────────────────────────┘
```

- **TB-1** user ↔ mediatore user API (bearer token over HTTPS)
- **TB-2** mediatore ↔ Kubernetes API (claims; VAP `brokers` allowlist)
- **TB-3** mediatore ↔ SPIRE server (registration entries, admin)
- **TB-4** VM ↔ SPIRE server (TPM EK node attestation)
- **TB-5** mediatore ↔ IdP (JWKS discovery, OBO exchange)
- **TB-6** VM / jail ↔ mediatore sandbox API (SPIFFE mTLS; **dev header today, see §8 R-1**)
- **TB-7** jail ↔ downstream APIs (issued token only)

## 6. STRIDE, per boundary

Controls cite the file that implements them. *(stub)* marks a boundary whose
production control is not built yet; the current behaviour is fail-closed and
the residue is in §8.

### TB-1: user → user API

| Threat | S/T/R/I/D/E | Control |
| --- | --- | --- |
| Forged / replayed bearer token | S | JWKS signature, `iss`/`aud`/`exp`/`nbf` validation: `crates/mediatore-entra/src/lib.rs` (`Validator::validate`) |
| Token minted for another client (e.g. the kubernetes Dex client) | S | `aud` must equal mediatore's `client_id`; e2e-tested (`crates/mediatore/tests/e2e_dev.rs::a_token_for_another_audience_client_is_unauthorized`) |
| Authenticated but unauthorized user | E | Per-issuer `required_group` gate: `crates/mediatore-entra/src/lib.rs`; refused as 403 |
| Reading / deleting another subject's claim | I/T | Subject equality on GET/DELETE: `crates/mediatore-api/src/lib.rs` (`owned_claim`) |
| Audience smuggling at claim creation | E | Requested audiences must be a subset of configured ones: `crates/mediatore-api/src/lib.rs` (`create_claim`) |
| Token logged | I | Never log tokens, only claims/subjects (`CLAUDE.md` rule; `tracing` calls log uid/audience/subject only) |

### TB-2: mediatore → Kubernetes API

| Threat | S/T/R/I/D/E | Control |
| --- | --- | --- |
| Broker SA stolen → arbitrary-subject claims | S/E | RBAC limits the SA to claims + VM reads: `deploy/base/rbac.yaml`; VAP still validates shape. Residue in §8 R-4 |
| Anyone else creating a claim for another subject | S | banlieue's `banlieue-claim-subject-policy` VAP (caller-equals-subject unless in `brokers` allowlist) — control lives in the banlieue repo |

### TB-3: mediatore → SPIRE server *(stub)*

| Threat | S/T/R/I/D/E | Control |
| --- | --- | --- |
| Forged registration entry (workload identity for free) | S/E | Planned: admin identity restricted to `/banlieue/{node,claim}/` paths, entry create only after a Bound claim resolves to a registered node: `crates/mediatore-claims/src/lib.rs` (`Reconciler::bind`) is the only call site. Today: `Noop` (`crates/mediatore-spire/src/lib.rs`), no entries exist at all |
| Stale entry after release | E | Entry deleted before refresh material: `Reconciler::release` ordering, unit- and e2e-tested |

### TB-4: VM → SPIRE server (node attestation)

| Threat | S/T/R/I/D/E | Control |
| --- | --- | --- |
| Cloned TPM state (two VMs, one EK) | S | Second registration of an EK with a different DMI UUID refused 409: `crates/mediatore-store/src/lib.rs` (`put_node`), e2e-tested |
| Impostor node claiming someone's EK | S | Peer must present the node SVID matching the EK it registers: `crates/mediatore-api/src/lib.rs` (`register_node`) |
| EK cert from an untrusted CA | S | SPIRE server's `ek-ca.pem` allowlist — control lives in the SPIRE deployment (runbook Part 1), not in this repo |

### TB-5: mediatore → IdP

| Threat | S/T/R/I/D/E | Control |
| --- | --- | --- |
| JWKS substitution / MITM | S | HTTPS via rustls (`reqwest` `rustls-tls`, `Cargo.toml`); issuer URL is config, never taken from a token or CR |
| Key rotation lockout / stale keys | D | 300 s JWKS cache with forced refetch on unknown `kid`: `crates/mediatore-entra/src/lib.rs` (`key_for`) |
| Revoked upstream session still delegating | E | Design (ADR-0003): refresh-before-issue so upstream revocation propagates; OBO/refresh not implemented yet — see §8 R-2 |

### TB-6: VM / jail → sandbox API *(stub — the load-bearing one)*

| Threat | S/T/R/I/D/E | Control |
| --- | --- | --- |
| Peer identity forgery | S | Production control is SPIFFE mTLS (not built). Today the peer header is only honoured under `dev_mode` (`crates/mediatore-api/src/lib.rs` `peer_spiffe_id`), and a non-dev config refuses to start the scaffold at all (`crates/mediatore/src/main.rs`). §8 R-1 |
| Node SVID requesting tokens | E | Only claim IDs reach `/v1/token`: `Naming::claim_uid_from` + 403, e2e-tested (`a_node_svid_gets_no_token`) |
| Token for an audience outside the claim | E | Allowlist check, 400 (not 403, no enumeration): `crates/mediatore-api/src/lib.rs` (`token`) |
| Issuance after release / expiry | E | `ClaimRecord::is_live` gate + revocation drops refresh material: `crates/mediatore-store/src/lib.rs`, e2e-tested (cut-off in `full_loop_from_login_to_cutoff`) |
| Refresh token reaching the VM | I | `TokenResponse` has no refresh field by construction: `crates/mediatore-proto/src/lib.rs` |

### TB-7: jail → downstream

| Threat | S/T/R/I/D/E | Control |
| --- | --- | --- |
| Token exfiltration by the (assumed hostile) workload | I | Tokens are memory-only, ≤ 15 min (`Sts::max_ttl`, cap in `crates/mediatore-api/src/lib.rs`), single-audience; the exfiltration window is the design trade-off recorded in ADR-0003 and §8 R-3 |
| Acting without attribution | R | STS tokens carry `act` (claim SVID) + `claim_uid` + `upstream_iss`: `crates/mediatore-sts/src/lib.rs`; OBO tokens carry `azp` (Entra) |
| Escaping the jail to steal the node identity | E | nsjail: chroot, no proc, rlimits, tmpfs home, only the Workload API socket mounted: `crates/mediatore-guest/src/jail.rs` (`JailSpec::to_args`); root processes are outside the jail |

## 7. Hardening that exists today

- Fail closed everywhere: unimplemented paths return `501`, never a permissive
  default (`CLAUDE.md`; enforced by e2e negative tests).
- Workspace lints: `unsafe_code = "forbid"`, clippy pedantic as errors
  (`Cargo.toml`), `cargo deny` license/advisory/source gates (`deny.toml`).
- Secrets never in `Debug` output: `Sts` and `Validator` redact
  (`finish_non_exhaustive`), no token is ever logged.
- Server container: static musl binary on `cgr.dev/chainguard/static`,
  non-root UID (`Dockerfile`).
- Deployment: dedicated ServiceAccount, minimal RBAC, ClusterSPIFFEID scoped
  to the namespace/SA (`deploy/base/`).
- Revocation ordering: SPIRE entry first, then refresh material, so no live
  SVID without a token path (`Reconciler::release`).

## 8. Accepted risks

| # | Risk | Why accepted | Revisit when |
| --- | --- | --- | --- |
| R-1 | The sandbox listener has no mTLS; `dev_mode` header is the only peer identity | The scaffold refuses to run outside `dev_mode`, so nothing reachable in production carries the risk; dev runs bind to 127.0.0.1 | The `spiffe` crate mTLS lands (next stage). This row must be **deleted**, not weakened |
| R-2 | Entra OBO / Dex refresh-before-issue is unimplemented, so upstream revocation does not yet propagate to STS issuance | Only the STS backend works, and only in dev where the fake IdP has no sessions | The OBO / refresh path lands (ADR-0003 implementation) |
| R-3 | A prompt-injected workload can exfiltrate its ≤ 15-min single-audience token | Bounded by TTL, audience allowlist and full attribution; the credential-injecting egress proxy is the designed phase 2 (runbook open decision #7) | The egress-proxy ADR is written |
| R-4 | mediatore is a single trust point: a compromised broker mints for any active claim | Inherent to the broker pattern; mitigations planned: HSM/transit-held keys, two-person deploy, immutable audit sink | The production deployment ADR (key custody, audit) |
| R-5 | In-memory store loses claim state on restart (dev only): a restarted broker forgets revocations it has not propagated | Dev-only; the SPIRE `Noop` means no entries outlive the process either | The sqlx store lands; re-walk §6 TB-3/TB-6 ordering against real persistence |
| R-6 | vTPM EK attestation proves "this vTPM", not "this host"; hypervisor compromise breaks node identity | Same posture as banlieue ADR-0045; hypervisor is in the TCB | PCR / measured-boot selectors become available (runbook open decision #6) |

## 9. Assumptions and out of scope

- Single-tenant management cluster; a cluster admin is trusted (they can read
  the broker's SA token regardless).
- The IdP is authoritative for authentication and group membership.
- banlieue's own threat model covers the VM lifecycle, image supply chain and
  hypervisor credentials; this document starts where a Ready, attested pool
  member exists.
- Denial of service beyond per-claim rate limiting (planned, `5.6` in the
  runbook) is out of scope pre-1.0.

## 10. Revision log

| Date | Pass | ADRs covered | Outcome |
| --- | --- | --- | --- |
| 2026-09-26 | Initial full pass | 0001–0004 | Document created; 6 accepted risks recorded; TB-3/TB-6 marked stub, fail-closed verified by e2e |
