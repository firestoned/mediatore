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

- [ ] `EntryManager` trait: drop `list_agents` and `Agent`; `ensure_node_entry(ek_hash)`
      and `create_claim_entry(ek_hash, claim_uid, unix_user)` return an entry handle
      (resource name); `delete_entry(name)` idempotent on 404
- [ ] `KubeEntryManager` in `mediatore-spire`: deterministic names
      (`mediatore-node-<ek>`, `mediatore-claim-<uid>`), labels, `className` from
      `spire.entries.class_name`, tolerate 409 on create; wait for `status.set && !masked`
      with `spire.entries.ready_timeout` (default 30 s), `masked` fails the claim
- [ ] EK hash from PEM: parse the certificate, DER-encode the SubjectPublicKeyInfo,
      hex SHA-256 (`mediatore-proto`); unit test against a fixture whose hash was produced
      by `openssl pkey -pubin -outform der | sha256sum` (the guest's computation) and
      cross-checked against the tpm plugin's `GetPubHash`
- [ ] Node entry trigger: `VirtualMachine.status.tpmEndorsementCertificates` (or the
      claim mirror) observed by the watcher; no certificate, no entry, no pool membership
- [ ] Orphan sweep on the leader at the resync interval (label selector
      `app.kubernetes.io/managed-by=mediatore`)
- [ ] Tests: kube-rs `tower-test` mock API server driving create/409/404 and the
      `status.set` / `status.masked` transitions; e2e over the mock; VAP exercised by
      `make live-admission-test` (server-side `kubectl apply` of allowed and refused
      shapes with `--as=system:serviceaccount:banlieue-system:mediatore`, `#[ignore]`d
      until roadmap 02's cluster target exists and failing loudly without it)
- [ ] `spire.endpoint` (ADR-0005) never implemented; config gains `spire.entries.*`

## Identity and mTLS (ADR-0007)

- [ ] `aws-lc-rs` as the process-wide rustls provider; `reqwest`/`kube` on their
      no-provider features; acceptance: `cargo tree -i ring` is empty (R-8 revisit)
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
