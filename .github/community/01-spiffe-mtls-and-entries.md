<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 01: SPIFFE mTLS + SPIRE entries

**Status: done (2026-10-13).** Replace the two load-bearing fakes: the dev peer-identity
header becomes SPIFFE mTLS, and the `Noop` entry manager becomes a declarative writer of
`ClusterStaticEntry` resources. Deletes threat-model accepted risk **R-1** and narrows
**R-8** to signatures. Two items were deployment- or watcher-shaped and moved: the broker
`NetworkPolicy` to roadmap 02, the node-entry trigger to roadmap 03 (see the end).

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

Stack: `spiffe` 0.18 (`x509-source`: the Workload API client, SPIFFE ID and SVID
parsing; Apache-2.0) and the in-repo `mediatore-tls` crate for the rustls verifiers over
it (ADR-0007 as amended 2026-10-13: `spiffe-rustls` only accepts a live `X509Source`,
which would have put a fake Workload API, so gRPC, into the hermetic suite). `kube-rs`
(already a dependency) for the entries. No `tonic`/`prost` of our own, no vendored protos.

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
- [x] Node entry trigger, function side: `ek_hash_from_pems` + `ensure_node_entry`.
      The `VirtualMachine` watch that calls it when `status.tpmEndorsementCertificates`
      appears is roadmap 03's (`banlieue-api` pin). No certificate, no entry, no pool
      membership
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
- [x] Post-quantum review (2026-10-13): rustls `prefer-post-quantum` restored (the hybrid
      had been offered last), pinned by test; `mediatore_tls::sandbox_provider` allows only
      X25519MLKEM768 and AES-256-GCM-SHA384 on the sandbox leg; the identity-provider
      client is TLS 1.3 only over the Mozilla roots; ML-DSA-65 SVIDs verified end to end
      (`crates/mediatore-tls/tests/handshake.rs`). Signatures wait on SPIRE and JOSE
- [x] `X509Source` from `spire.workload_api_socket` (`mediatore_tls::WorkloadApiSource`);
      startup fails closed without it outside `dev_mode`, and when the SVID it delivers is
      not `spiffe://<td>/mediatore` (a wrong `ClusterSPIFFEID`)
- [x] Sandbox listener (`crates/mediatore-tls`): TLS 1.3 only, client cert required, no
      resumption; verifier = leaf constraints, local trust domain, chain to the bundle
      (rustls webpki), authorizer `/banlieue/node/*` and `/banlieue/claim/*` only, parsed
      by the same `Naming` rules the handlers use; peer SPIFFE ID as a `PeerSpiffeId`
      request extension; `peer_spiffe_id` reads it and ignores the header; configs
      rebuilt on every rotation of the source
- [x] `Config::load` refuses `dev_mode: true` unless `listen.sandbox` is a literal loopback
      address
- [x] `mediatore-guest` and `sandbox-token`: client configs from their agent socket, the
      server accepted only as `spiffe://<td>/mediatore` (derived from their own SVID's trust
      domain, no flag); `--dev-spiffe-id` behind a `dev` cargo feature that `make e2e`
      enables and release builds do not
- [x] `mediatore-testkit`: `TestCa` minting SPIFFE-shaped X.509 SVIDs (not CA,
      `digitalSignature`, `serverAuth` + `clientAuth`, one URI SAN), `MemoryMaterial` as a
      rotatable source; `crates/mediatore/tests/e2e_mtls.rs` runs the production listener,
      verifiers and client configs over loopback: full loop, then no client certificate,
      foreign trust domain, the broker's own identity as a client, expired SVID, CA-shaped
      leaf, node SVID at `/v1/token`, dev header on an mTLS connection, dev header outside
      `dev_mode`, server with another identity, rotation picked up by new handshakes
- [x] kind tier for ADR-0007 (2026-10-13): `make kind-broker` builds the musl binaries on
      the host (`make dist`), packages the broker with the shipped `Dockerfile`
      (`BINARY_FROM=host`) and the guests into a test-only image, and applies
      `dev/kind/broker` (a kustomize overlay of `deploy/base` as shipped) so the broker
      runs on the CSI socket with the `ClusterSPIFFEID`; `dev/kind/mtls-e2e.sh` runs four
      client pods with agent-issued SVIDs (claim, node, intruder, broker impersonator)
      through the shipped guest binaries and reads the broker's log; `make kind-e2e-mtls`
      is part of `kind-e2e` and the E2E workflow
- [x] NetworkPolicy for the broker pods: spec in ADR-0007 decision 7; the manifest is
      roadmap 02's (CIDRs are deployment-specific)

## Closing the roadmap

- [x] README status table, `docs/guides/testing.md` and `docs/guides/running-workloads.md`
      updated (operating rule: no entry is ever created outside `ClusterStaticEntry`)
- [x] Threat model full pass (2026-10-13): TB-3 is "mediatore → Kubernetes API
      (`ClusterStaticEntry`)" plus the controller-manager boundary; TB-6 lost its *(stub)*
      and cites `crates/mediatore-tls` and the mTLS suite; new TB-8 (broker pod → agent over
      the CSI mount); R-1 deleted; R-5 widened; R-8 narrowed to signatures; stamp bumped to
      ADR-0007
- [x] ROADMAPS.md row to done (2026-10-13)
