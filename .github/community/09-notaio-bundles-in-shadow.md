<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 09: notaio's policy bundles, read and verified in shadow

**Status: in progress.** ADR-0026 accepted (2026-11-01). The first step of moving sandbox policy out
of the broker's configuration and into notaio's signed bundles (notaio roadmap 00, phase 1). The
broker watches the bundles, verifies each, keeps a version floor that survives restarts, and
compares every sandbox with its policy. It refuses nothing on the bundle's account: this roadmap
finds the gaps between what the broker allows today and what the policy says, while the broker's
configuration is still the authority. Enforcing the bundle is the next roadmap.

Depends on roadmap 08 (the `AgentSandbox` a policy is named on) and roadmap 05 (the store the
floor lives in). On notaio's side, depends on a released `sandboxpolicy-bundle` (v0.3.2 or later:
bundle schema v3, its conformance vectors, notaio ADR-0013 and ADR-0014).

## Why

Today `audiences[]` in the broker's configuration is the policy: per audience a backend,
`max_ttl`, `egress` endpoints and `rules`. notaio publishes a signed bundle per `SandboxPolicy`
beside it that nothing reads ([the research agent walkthrough](../../docs/guides/research-agent-walkthrough.md),
section 5). Two sources of policy drift apart silently, and only one is reviewed through a policy
repository, linted against an approved ceiling and signed. Reading the bundle in shadow first
shows every place the two disagree, on real sandboxes, before anything is refused because of it.

## Decisions (ADR-0026)

A new input to the broker, a new trust anchor and a new table in the store: an ADR first. These
are the questions it answers, with the recommendation this roadmap is built on.

1. **The dependency.** `sandboxpolicy-bundle` as a git dependency pinned to a notaio release tag
   (notaio ADR-0014), with notaio added to `allow-git` in `deny.toml`. It brings `ed25519-dalek`,
   new to this tree; `cargo deny` must stay green with `ring` and `openssl-sys` still banned. It
   does not bring `kube` or `schemars`.
2. **The trusted keys come from the broker's own configuration,** never from the cluster: a key
   read from a ConfigMap could be replaced by whoever can write one. A `policy.trusted_keys` list
   of `{ id, public_key }` (notaio's `notaio:v<N>` key ids), so a rotation lists the old and new
   versions side by side until every bundle is re-signed.
3. **Where bundles are read.** ConfigMaps labelled `app.kubernetes.io/managed-by=notaio` in the
   namespaces listed in `policy.namespaces` (default: `sandboxes.namespace`), through a reflector
   on the roadmap 03 loop. Every replica keeps the cache; only the leader writes the floor. RBAC is
   a Role per listed namespace with `get`, `list` and `watch` on ConfigMaps and nothing else.
4. **The floor lives in the store.** A `policy_floors` table (namespace, name, uid, version,
   issued_at), in both the SQLite and the PostgreSQL migrations and in the store conformance
   suite, so the floor survives restarts with the claims. The rules stay notaio's (its ADR-0008),
   not re-implemented here. One gap to close: notaio's `VersionFloor` is synchronous and
   `ClaimStore` is async. Recommended: notaio exposes the floor decision as a pure function
   (held entry and verified payload in, next entry or refusal out), released as a patch, and
   mediatore verifies, decides, awaits the write, and only then uses the bundle. The alternative,
   `block_in_place` inside a store-backed `VersionFloor`, ties a store write to a runtime detail.
5. **How a sandbox names its policy** (notaio roadmap 00, D3). `AgentSandbox.spec.policyRef`, the
   name of a `SandboxPolicy` in the sandbox's namespace, immutable like the rest of the spec and
   optional in this roadmap: a sandbox without one is reported, not refused. The claim record
   keeps the policy's uid and the bundle version seen at admission. Eligibility by group (the
   admission policy with the `SandboxPolicy` as its parameter) belongs to the enforcing roadmap.
6. **What is compared, and how a gap is reported.** For each sandbox with a `policyRef` and a
   verified bundle, every place the broker would allow more than the bundle:
   an audience the bundle does not list; a `max_ttl` above the bundle audience's `ttlSeconds`;
   an `egress` endpoint, or a rule, the bundle audience does not allow; `ttlSeconds` on the
   sandbox above the bundle's lease maximum. (The broker has no direct egress, so the bundle's
   `egress[]` has nothing to compare with; a non-empty one is reported.) Also reported: a
   `policyRef` to no policy, and a policy with no bundle that verifies (expired, signed by an
   unknown key, below the floor). The broker has no metrics endpoint, so each gap is a log line
   with a stable code and a condition on the `AgentSandbox` (`PolicyConformant`, with the codes
   in its message); metrics wait for a metrics endpoint of their own.
7. **Nothing fails open, and nothing new fails closed.** A bundle that does not verify is never
   used for anything, including the comparison; a sandbox is admitted and minted for exactly as
   today. The only new way to fail is the broker refusing to start on a malformed
   `policy.trusted_keys`.

## Work

- [x] ADR-0026 accepted, answering the decisions above. Done 2026-11-01 as
      [ADR-0026](../../docs/adr/0026-notaio-bundles-verified-in-shadow.md), with the finding codes
      `P001` to `P011`
- [x] The CALM model updated for the new flow (bundle ConfigMaps to the broker) and its trust
      anchor (the configured keys). Done 2026-11-01: notaio as a system on the management
      cluster with its bundles as a data asset, the configured keys as a data asset of the
      broker, the reflector relationship with its Role, the store relationship carrying the
      floor, the flow `flow-policy-shadow` (write, verify, floor, compare, mint unchanged);
      `make calm-validate` and the diagrams re-rendered
- [x] notaio: the floor decision as a pure function, in a patch release; mediatore pins that tag.
      Done 2026-11-01: `next_floor` in notaio v0.3.3, verified like every release
- [x] The dependency and `deny.toml`; the crate's conformance vectors run in mediatore's own tests,
      so mediatore's verifier is shown to reach notaio's verdict on every vector. Done
      2026-11-01: `sandboxpolicy-bundle` at notaio `v0.3.3`, notaio in `allow-git`; the new
      `mediatore-policy` crate (`trusted_keys`, `admit`); all 14 vectors pass through `admit`
      over the store, not through notaio's own `run`; no `kube`, `schemars`, `ring` or
      `openssl-sys` added, and no new duplicate crate
- [x] `policy.trusted_keys` and `policy.namespaces` in the configuration, a malformed key refusing
      the start; the reference and the configuration guide. Done 2026-11-01: `PolicySection`,
      checked at load through `mediatore_policy::trusted_keys` (an empty, malformed or
      duplicate key, a keyless section, a namespace that is not a Kubernetes name or is listed
      twice all refuse the start; ADR-0026, implementation notes); the example overlay's
      commented `policy` block and the deploying guide's step 1
- [x] `policy_floors` in both migrations, `ClaimStore` methods for it, the store conformance suite
      extended. Done 2026-11-01: `get_policy_floor` and `advance_policy_floor`, a compare and set
      (ADR-0026, implementation notes); three cases (a round trip to the nanosecond, a write
      decided from a floor that moved refused, a floor written under another policy refused) on
      the memory store, SQLite and PostgreSQL 17. The floor rule itself (a downgrade, a new
      incarnation, a replay) is notaio's `next_floor`, tested there and run by the broker
- [x] The bundle reflector and the per-namespace Role in `deploy/`: verify, decide the floor,
      persist, then cache the verified payload by policy; a bundle that fails is logged with its
      reason and leaves the cache as it was. Done 2026-11-01: `mediatore_claims::policy`
      (`BundleReflector`, `BundleCache`), on every replica outside the Lease, one watch per
      namespace on notaio's label; seven unit tests over notaio's vectors (admitted and cached,
      a non-bundle ignored, four refusals and an expiry leaving cache and floor as they were, a
      replay below the floor refused and a re-delivery admitted, a deletion and a relist
      dropping the policy with the floor kept, the sweep); `deploy/policy-bundles` the Role
      and its binding, the deploying guide's step 1
- [x] `spec.policyRef` on `AgentSandbox` (`make crds`), immutable under the existing admission
      policy; the record's policy uid and bundle version. Done 2026-11-01: an optional
      `{ name }` on the spec, `policy_ref` on `POST /v1/claims` and `--policy` on the CLI;
      `claims.policy_uid` and `claims.bundle_version` (migration 4, both engines, the
      conformance suite's round trip and update); the reconciler reads the reflector's cache
      once, when it creates the record, and a sandbox whose policy has no verified bundle is
      admitted with nothing recorded (three reconcile tests over a bundle the testkit signs
      at the real clock, `mediatore_testkit::policy`)
- [ ] The comparison, with its finding codes, on every reconcile of a sandbox and whenever its
      policy's bundle changes; the `PolicyConformant` condition
- [ ] Live test, `make kind-e2e-policy`: notaio installed from its release manifest in kind,
      signing with the kind OpenBao, a policy and its ceiling, an `AgentSandbox` naming it; a
      conformant sandbox reports no gap; a broker audience the policy lacks is reported with its
      code; a replayed older bundle is refused by the floor across a broker restart; nothing is
      refused that is not refused today
- [ ] User guide: naming a policy on a sandbox, the trusted keys, reading the findings; the
      research agent walkthrough's section 5 updated
- [ ] Threat model pass: the bundle as a new input across TB-2 (read from the Kubernetes API), the
      configured keys as a trust anchor, the floor as the T5.4 control (notaio's threat model), the
      shadow mode's residual risk (the configuration still rules)

## Out of scope

- Enforcing the bundle at claim and at every mint, the eligibility admission policy, and removing
  `egress` and `rules` from the broker's configuration: the next roadmap (notaio roadmap 00,
  phase 2).
- The guest verifying the bundle itself (D4) and a token claim naming the policy (D6): notaio
  roadmap 00, phases 3 and 2.

## Done when

Every sandbox on a test cluster with notaio installed reports `PolicyConformant`, with a code for
each gap where it is not; the floor holds across a broker restart; and nothing the broker allowed
before is refused.
