<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 01: SPIFFE mTLS + SPIRE entries

**Status: in progress.** Replace the two load-bearing fakes: the dev peer-identity
header becomes SPIFFE mTLS, and the `Noop` entry manager becomes a declarative writer of
`ClusterStaticEntry` resources. Deletes threat-model accepted risk **R-1** and narrows
**R-8** to signatures.

Design (decided 2026-10-10, no gRPC anywhere in mediatore's own code):

- [ADR-0006](../../docs/adr/0006-registration-entries-as-clusterstaticentry.md): entries
  are `ClusterStaticEntry` resources created through the Kubernetes API; the SPIRE
  Controller Manager renders them over its private socket. mediatore holds **no** SPIRE
  admin identity; a `ValidatingAdmissionPolicy` restricts the broker's ServiceAccount to
  the two entry shapes under `/banlieue/`. The node entry is derived from the EK
  certificate banlieue publishes (hex SHA-256 of the DER SubjectPublicKeyInfo, which is
  the tpm attestor's agent-ID hash), so `ListAgents` is gone.
- [ADR-0007](../../docs/adr/0007-broker-identity-and-spiffe-mtls.md): the broker's SVID
  comes from the Workload API over the SPIFFE CSI driver (read-only inline volume, key in
  memory only, PSS `restricted`); the sandbox listener terminates SPIFFE mTLS in-process
  with `spiffe-rustls` on `aws-lc-rs`; guests verify the broker by SPIFFE ID.

Stack: `spiffe` 0.18 (`x509-source`), `spiffe-rustls` 0.10 (`aws-lc-rs` feature),
`spiffe-rustls-tokio` 0.6; all Apache-2.0, same maintainer. `kube-rs` (already a
dependency) for the entries. No `tonic`/`prost` of our own, no vendored protos.

## Design (done)

- [x] ADR-0006 and ADR-0007 written and Accepted (2026-10-11); ADR-0005 amended (entry transport)
- [x] CALM updated: controller manager, k8s agent + CSI driver, `ClusterStaticEntry`
      data asset, `rel-watcher-entries` via the API server, node-bootstrap flow;
      `make calm-validate` and `make calm-diagrams` green
- [x] `deploy/base`: `admin: true` removed from the `ClusterSPIFFEID`; `className`,
      `workloadSelectorTemplates`, `ttl` added; RBAC gains `clusterstaticentries`
      (no update/patch); `admission/clusterstaticentry-mediatore.yaml` VAP + binding;
      `service-sandbox.yaml` (LoadBalancer, 443 to 8443); `SPIFFE_ENDPOINT_SOCKET` env

## Entries (ADR-0006)

- [x] `EntryManager` trait: `list_agents` and `Agent` dropped; `ensure_node_entry(ek_hash)`
      and `create_claim_entry(ek_hash, claim_uid, unix_user)` return the resource name;
      `delete_entry(name)` idempotent on 404; `list_entries()` for the sweep.
      `Noop` replaced by `MemoryEntries`, which validates inputs exactly like the real
      thing and remembers declarations so tests can assert retraction
- [x] `KubeEntryManager` (`crates/mediatore-spire/src/kube.rs`): deterministic names,
      labels, `className` from `spire.entries.class_name`, 409 tolerated, 403 surfaced as
      `Denied`; waits for `status.set && !masked` by polling (`poll_interval_ms`, default
      500 ms) with `ready_timeout_secs` (default 30 s); `masked` fails the claim; inputs
      that admission would refuse are refused before any request
- [x] EK hash from PEM (`mediatore_proto::ek`): certificate parsed, SubjectPublicKeyInfo
      DER-encoded, hex SHA-256; `ek_hash_from_pems` picks the RSA EK among what banlieue
      published; fixtures hashed with the guest's pipeline
      (`openssl pkey -pubin -outform der | sha256sum`), matching the tpm plugin's
      `GetPubHash` (`x509.MarshalPKIXPublicKey`)
- [ ] Node entry trigger: the function side exists (`ek_hash_from_pems` +
      `ensure_node_entry`); the `VirtualMachine` watch that calls it when
      `status.tpmEndorsementCertificates` appears lands with the claim watcher
      (roadmap 03, `banlieue-api` pin). No certificate, no entry, no pool membership
- [x] Orphan sweep: `Reconciler::sweep_orphans` retracts claim entries whose claim is
      unknown or revoked and leaves node entries alone; scheduling it on the leader at the
      resync interval is part of roadmap 03's loop
- [x] Tests: scripted fake API server (`tower-test`) covering create, 409, 403, poll until
      set, masked, timeout, delete 404 and list by label; reconciler bind/release/sweep
      over `MemoryEntries`; e2e runs on `MemoryEntries` with a 64-hex EK hash
- [x] Live admission test: `make live-admission-test` runs the full round trip as
      `system:serviceaccount:banlieue-system:mediatore` against a real cluster (declare, 409,
      wait, list, eleven refused shapes, RBAC refusing update and patch, retract);
      `#[ignore]`d, fails loudly without its fixture. First run found that `status.set` is a
      transient, which turned the poll into a watch (ADR-0006 decision 5)
- [x] kind tier: `make kind-e2e` installs the homelab's chart versions into a kind cluster,
      applies `deploy/base`'s ServiceAccount, RBAC and policy, and runs the live suite as a
      token for that ServiceAccount; `make kind-e2e-ci` is the E2E workflow's second job.
      Tiers and what each proves: `docs/guides/testing.md`
- [x] `spire.endpoint` (ADR-0005) never implemented; config gains `spire.workload_api_socket`
      and `spire.entries.{class_name, kubeconfig, ready_timeout_secs, claim_svid_ttl}`,
      required outside `dev_mode`

## Identity and mTLS (ADR-0007)

- [x] `aws-lc-rs` as the process-wide rustls provider, installed first thing in each
      binary; `reqwest` and `kube` on their no-provider features; `cargo deny` bans `ring`
      (R-8 revisit happens in the closing threat-model pass)
- [ ] `X509Source` from `spire.workload_api_socket`; startup fails closed without it
      outside `dev_mode`
- [ ] Sandbox listener: `spiffe-rustls` server config, TLS 1.3, client cert required,
      authorizer `/banlieue/node/*` and `/banlieue/claim/*` only; peer SPIFFE ID as a
      typed connection extension; `peer_spiffe_id` reads it and ignores the header
- [ ] `Config::load` refuses `dev_mode: true` unless `listen.sandbox` is loopback
- [ ] `mediatore-guest` and `sandbox-token`: client configs from their agent socket,
      server authorizer exactly `spiffe://<td>/mediatore`; `--dev-spiffe-id` behind a
      `dev` cargo feature, off in release builds
- [ ] `mediatore-testkit`: test CA minting SPIFFE X.509 SVIDs + in-memory source; e2e
      gains the mTLS variant and the negative cases from ADR-0007 decision 8
- [ ] kind tier for ADR-0007: the broker image in the cluster on the CSI socket with the
      `ClusterSPIFFEID`, a client pod with a claim-shaped SVID over mTLS, the negative
      cases; `make kind-e2e-mtls` joins `kind-e2e`
- [ ] NetworkPolicy for the broker pods: spec in ADR-0007 decision 7, manifest lands
      with roadmap 02 (CIDRs are deployment-specific)

## Closing the roadmap

- [ ] README status table, `docs/guides` and the runbook updated (operating rule: no
      entry is ever created outside `ClusterStaticEntry`)
- [ ] Threat model full pass: TB-3 becomes "mediatore → Kubernetes API
      (`ClusterStaticEntry`)" plus the controller-manager boundary; TB-6 and the new
      pod → agent boundary lose their *(stub)*; R-1 deleted; R-8 narrowed; stamp bumped
      to ADR-0007 (the deltas are itemised in both ADRs)
- [ ] ROADMAPS.md row to done
