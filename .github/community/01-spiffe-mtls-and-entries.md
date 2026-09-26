<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 01: SPIFFE mTLS + SPIRE entries

**Status: in progress.** Replace the two load-bearing fakes: the dev peer-identity
header becomes SPIFFE mTLS, and the `Noop` entry manager becomes a gRPC client of the
SPIRE server's entry API. Deletes threat-model accepted risk **R-1**.

Stack (decided during scouting, recorded in ADR-0006): the `spiffe` /
`spiffe-rustls` / `spiffe-rustls-tokio` crates (same maintainer, Apache-2.0) for the
Workload API source, rustls configs and authorizers; vendored `spire-api-sdk` protos
compiled with `tonic` for the entry/agent server APIs (`spire-api` on crates.io only
covers the agent Delegated Identity API).

- [ ] ADR-0006: transport and entry-management design (fail-closed rules, dev_mode
      boundary, test strategy with static SVIDs, `spire.endpoint` config)
- [ ] Sandbox listener terminates SPIFFE mTLS; peer ID from the client SVID; dev
      header honoured only in `dev_mode`
- [ ] `sandbox-token` and `mediatore-guest` connect with their SVIDs and verify the
      server is `spiffe://<td>/mediatore`
- [ ] `GrpcEntryManager` implementing `EntryManager`: BatchCreate/BatchDelete/List
      entries + ListAgents, authenticated with mediatore's own SVID (`admin_ids`)
- [ ] Node bootstrap sweep: `/banlieue/node/<ek-hash>` entry for every new tpm agent
      (runbook 7.2)
- [ ] Tests: static test SVIDs in `mediatore-testkit`; mock EntryService tonic server;
      e2e gains an mTLS variant; live-SPIRE tests `#[ignore]`d for roadmap 02
- [ ] Threat model pass: TB-3/TB-6 lose their *(stub)* markers, R-1 deleted, stamp
      bumped to ADR-0006
