<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0026: notaio's policy bundles, verified by the broker and compared in shadow

**Status:** Accepted · **Date:** 2026-11-01

Roadmap 09, the first step of notaio's roadmap 00 (M3, "integrate the consumers"), phase 1.
Decides notaio's question D3 (where a sandbox names its policy) for this phase. Amends
[ADR-0008](0008-agentsandbox-crd-owned-by-mediatore.md) (a new, optional, immutable field on
`AgentSandbox`) and [ADR-0012](0012-persistent-store.md) (a new table). Changes nothing
about what the broker admits or mints: every decision here is observation, and the broker's
`audiences[]` configuration stays the authority until the enforcing ADR.

## Context

The broker's configuration is the sandbox policy today. Per audience it holds the backend, a
`max_ttl`, the `egress` endpoints the guest admits and the `rules` the egress proxy enforces
([ADR-0025](0025-phantom-token-egress-proxy.md)). Changing any of it is a change to the broker's
deployment, reviewed as such and checked by nothing.

notaio compiles a `SandboxPolicy` into a signed bundle and publishes it, per policy, in a
ConfigMap `<policy>-bundle` (key `bundle.dsse.json`, label
`app.kubernetes.io/managed-by=notaio`) in the policy's namespace. The bundle is a DSSE envelope
over the effective policy: per audience its access, scopes, `ttlSeconds`, `endpoints` and
`rules` (bundle schema v3, in the broker's own `{ method, path }` rule shape, notaio ADR-0013);
direct `egress[]`; the lease's `maxDurationSeconds`; the policy's namespace, name and `uid`; a
version that only goes up; and a `notAfter`. It is signed by a key in OpenBao transit that notaio
holds no copy of, and the policy behind it was reviewed in a policy repository, linted against a
Security-approved ceiling and applied only by GitOps. notaio ships the verifier,
`sandboxpolicy-bundle`, for consumers to link (notaio ADR-0014: a git dependency on a release
tag), with conformance vectors every consumer's verifier must agree with, and a version floor
(notaio ADR-0008) that stops a consumer accepting an older, looser bundle after a newer one.

Nothing reads the bundle. The research agent walkthrough says so in its section 5: the policy
someone reviewed and the policy the broker applies are two documents, and nothing tells when
they differ. Moving the authority to the bundle in one step would refuse, on the first day,
every sandbox whose configuration and policy disagree, and the first time anyone would learn
where they disagree is from refused sandboxes. This ADR reads the bundle first and reports.

## Decision

1. **The verifier is notaio's, linked, not rewritten.** `sandboxpolicy-bundle` as a git
   dependency pinned to a notaio release tag, notaio's repository added to `allow-git` in
   `deny.toml`. It brings `ed25519-dalek`, new here, and no `kube`, `schemars`, `ring` or
   `openssl-sys`; `cargo deny` stays as strict as it is. A bump of the tag is an ordinary
   dependency change, reviewed with the release notes of the notaio version it moves to. The
   conformance vectors run in this repository's tests through the same calls the broker makes,
   so the broker is shown to reach notaio's verdict on every vector, at the pinned tag.

2. **The trusted keys are configuration, never cluster state.** A new `policy` section:

   ```yaml
   policy:
     trusted_keys:
       - id: notaio:v1                 # notaio's key id: transit key name and version
         public_key: <base64 Ed25519>
     namespaces: [sandboxes]           # default: [sandboxes.namespace]
   ```

   A key read from the cluster could be replaced by whoever can write the object it lives in,
   and would then choose the policy. Listing two versions of the key covers a rotation: the
   operator adds the new version, notaio re-signs every bundle with it, the old version is
   removed. A key that does not decode to 32 bytes, or a duplicate `id`, refuses the start. An
   empty or missing `policy` section turns the whole of this ADR off: no watch, no comparison, no
   condition, exactly today's broker.

3. **Bundles are read by a reflector on the ConfigMaps notaio labels,** in each namespace of
   `policy.namespaces`, on the roadmap 03 controller loop. RBAC is a Role per listed namespace
   granting `get`, `list` and `watch` on ConfigMaps, and nothing else: the broker can neither
   write a bundle nor read any other kind there. A ConfigMap that is not a bundle notaio would
   write (no `bundle.dsse.json`, an envelope that does not parse) is logged and ignored.

4. **Verify, decide the floor, persist, then use.** For each bundle the broker verifies the
   envelope against the configured keys at the current time, applies notaio's floor rule (the
   same `uid` may not go down; a new `uid` is accepted only if issued after the held one), writes
   the new floor to the store, and only after the write succeeds puts the verified payload in the
   in-memory cache the comparison reads. A bundle refused at any step is logged with its reason
   (the error name the conformance vectors use) and changes nothing; an expired bundle is dropped
   from the cache. Every replica runs this, so each has the cache it will need when the bundle
   is enforced; the floor is shared, in the store.

   The floor rule is notaio's, not re-implemented: notaio's `VersionFloor` trait is synchronous
   and `ClaimStore` is async, so notaio exposes the decision as a pure function (the held entry
   and a verified payload in; the next entry or a refusal out), released as a patch, and its own
   `accept` uses it. The store applies it inside one transaction that reads the held row and
   writes the next one, so two replicas racing on the same bundle cannot move the floor down.

5. **The floor lives in the store** (amends ADR-0012). A `policy_floors` table keyed by
   (`namespace`, `name`), holding `uid`, `version` and `issued_at`, in the SQLite and PostgreSQL
   migrations and in the store conformance suite. It survives broker restarts with the claims,
   which is the point: a broker that forgot its floor could be handed an older bundle that is
   still signed and inside its validity. Rows are not deleted with their policy (notaio
   ADR-0008, consequences); they are a few dozen bytes each. `dev_mode`'s memory store keeps
   them in memory, as it keeps the claims.

6. **A sandbox names its policy with `spec.policyRef`** (amends ADR-0008; notaio's D3). The name
   of a `SandboxPolicy` in the sandbox's own namespace. Immutable, as the whole spec already is
   under the ADR-0008 admission policy. Optional in this ADR: a sandbox without one is reported
   (decision 7), never refused, so no existing sandbox or client breaks. The claim record gains
   the policy's `uid` and the bundle version current when the claim was created, for the audit
   and for the enforcing ADR. Who may name which policy (eligibility by group, notaio's K7.2) is
   the enforcing ADR's: in shadow, naming a policy grants nothing.

7. **The comparison reports every way the broker would allow more than the bundle,** on each
   reconcile of a sandbox and whenever its policy's bundle changes. Each gap has a stable code:

   | Code | The broker would allow |
   | --- | --- |
   | `P001` | an audience on the sandbox that the bundle does not list |
   | `P002` | a `max_ttl` for the audience above the bundle audience's `ttlSeconds` |
   | `P003` | an `egress` endpoint for the audience that the bundle audience does not list |
   | `P004` | a rule for the audience that admits a request no bundle rule admits, or no rules where the bundle has some |
   | `P005` | a sandbox `ttlSeconds` above the bundle's `lease.maxDurationSeconds` |
   | `P006` | nothing: the bundle holds direct `egress[]`, which the broker has no way to provide |
   | `P010` | no `policyRef` on the sandbox |
   | `P011` | a `policyRef` to no bundle in the cache (no policy, or none that verified and is unexpired) |

   `P004` compares rules as sets of `(method, path-glob)` and reports a broker rule unless a
   bundle rule covers it (same or `*` method, a path glob that matches every path the broker's
   does); a rule it cannot prove covered is reported, never assumed fine. The broker has no
   metrics endpoint, so gaps surface twice: a log line per gap with the code, the sandbox, the
   policy and the bundle version, and a `PolicyConformant` condition on the `AgentSandbox`,
   `True` with no gaps, `False` with the codes in its message, `Unknown` while `policy` is
   configured but no bundle has been read yet. Metrics wait for a metrics endpoint of their own.

8. **Nothing fails open, and nothing new fails closed.** A bundle that does not verify is never
   used, not even to compare. The comparison changes no admission, no claim and no mint: a
   sandbox with every code above is served exactly as today. The only new refusal is decision 2's,
   at start, for a malformed key.

## Implementation notes

What roadmap 09 fixed within the decisions above, so a reader of the code finds it here:

- **The floor's write is a compare and set** (decision 4). `ClaimStore::advance_policy_floor`
  takes the floor the caller read and decided from and the next one, and writes only if the
  row is still exactly what was read: an `INSERT` when there was none, an `UPDATE` matching
  `uid`, `version` and `issued_at` otherwise. A replica that lost a race gets `Conflict`,
  reads again and decides again. This gives decision 4's guarantee with no row lock, which
  sqlx's `Any` driver cannot express on SQLite.
- **The crate is `mediatore-policy`,** shared with the guest when it verifies too (notaio
  roadmap 00, phase 3). `trusted_keys` checks the configured keys (decision 2; notaio's
  `TrustedKeys` would let a duplicate id silently replace the first, so the broker refuses it)
  and `admit` is decision 4: verify, decide with notaio's `next_floor`, compare and set, retry
  a lost race twice, then use. A refusal carries a stable `code()`, notaio's error name where it
  is notaio's refusal.
- **A bundle must be read from its own policy's namespace.** `admit` takes the namespace the
  ConfigMap was read from and refuses a payload naming another (`Misplaced`): a bundle copied
  next to someone else's policy is a copy, not that policy's.
- **`issued_at` is kept to the nanosecond,** as RFC 3339 text, unlike the store's other
  timestamps (microseconds): notaio's `issuedAt` has nanoseconds, and the floor orders
  incarnations by it.

## Consequences

- The operator learns, per sandbox and before anything is enforced, where the reviewed policy and
  the broker's configuration disagree, in codes that the enforcing ADR turns into refusals one
  for one: `P001` to `P005` become refused claims or mints, `P010` and `P011` a refused claim.
- The broker gains a trust anchor (the configured keys) and a new input across TB-2 (bundles read
  from the Kubernetes API). Neither can loosen anything in this phase; both become load-bearing
  when the bundle is enforced, which is why the keys come from configuration, reviewed with the
  broker's deployment, and never from the cluster.
- A new dependency on notaio's release cadence. A notaio release that changes the bundle schema
  is a tag bump here, gated by the conformance vectors.
- The store schema grows a table; a downgrade of the broker past this ADR leaves an unused table
  behind, which is harmless.
- notaio needs a patch release before decision 4 can be built.
- `spec.policyRef` is the field the enforcing ADR makes required; adding it now, optional, means
  sandboxes can name their policy before it matters.

## Alternatives considered

- **Enforce from the start.** Rejected: the first evidence of a gap would be refused sandboxes.
  Shadow first costs one roadmap and finds the gaps safely.
- **Keys from a ConfigMap or Secret in the cluster.** Rejected (decision 2): whoever writes the
  object chooses the policy.
- **The floor in a file, notaio's `FileFloor`.** Rejected: the broker runs replicas with no
  shared disk, and the store already survives restarts and is shared.
- **`block_in_place` around a store write inside notaio's synchronous `VersionFloor`.** Workable,
  but ties a store write to a Tokio runtime flavour and puts an await behind a sync trait; the
  pure decision function keeps the rule in notaio and the I/O here.
- **Name the policy by annotation instead of a spec field.** Rejected: an annotation is mutable
  and outside the admission policy's immutability, and would be replaced by the spec field in the
  enforcing ADR anyway.
- **A ValidatingAdmissionPolicy comparing the sandbox with the policy.** Not possible in shadow
  (admission would refuse) and not sufficient later: admission cannot verify a signature.
