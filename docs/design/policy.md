<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Policy

How mediatore reads notaio's reviewed policy and what it does with it. The code is `crates/mediatore-policy` (the
admission rule), `crates/mediatore-claims/src/policy.rs` (the reflector that feeds it) and
`crates/mediatore-claims/src/shadow.rs` (the comparison). The guide [The policy bundle, in
shadow](../guides/the-policy-bundle.md) covers operating it.

## The split of responsibility

mediatore does not author or approve policy. **notaio** compiles each `SandboxPolicy` from a reviewed repository against
its profile and an approved ceiling, signs the result with its own OpenBao transit key, and writes it as a labelled
`ConfigMap` (`<policy>-bundle`) in the policy's namespace. mediatore only **reads** those bundles and verifies them.

| Question | Who answers | Where |
| --- | --- | --- |
| what is a person in this group allowed to reach | the policy repository, reviewed, signed by notaio | notaio |
| is this bundle genuine, and is it newer than the last one seen | the broker | `mediatore-policy`, `admit` |
| does the broker's configuration allow more than the bundle | the broker, as findings | `shadow.rs` |
| does the bundle add reachable hosts or gate a credential | the broker, under `policy.egress: enforce` | the API and the gateway routes |

## Admitting a bundle

`mediatore_policy::admit` is the one way a bundle comes in: **verify, decide the floor, persist it, and only then
hand back the payload.** The verifier and the floor's rule are notaio's (`sandboxpolicy-bundle`, linked at a release
tag and never re-implemented, ADR-0026 decision 1). What is the broker's:

- **The trusted keys come from configuration**, `policy.trusted_keys` (`notaio:v<N>` and a 32-byte Ed25519 key each),
  read at start and never from the cluster. A bundle signed by a key not listed fails.
- **The floor is a version,** kept in the store as a `PolicyFloor` (the policy's namespace and name, the incarnation's
  UID, the version and notaio's issue time) and moved only **upward** by a compare and set, so two replicas cannot race
  it down and an old bundle cannot be replayed. Which incarnation of a policy may replace the one on record is notaio's
  rule, applied through `sandboxpolicy-bundle`; a floor written under another policy is refused.

## The reflector

`policy.rs` watches the labelled `ConfigMap`s in each configured namespace (`policy.namespaces`), runs `admit` on each,
and caches the verified payloads. A bundle that fails any step is logged with its reason and changes nothing; an
expired one leaves the cache. **The reflector runs on every replica, outside the Lease**: each replica needs the cache
it will read, and a standby that could not verify a bundle could not answer.

Bundles are short-lived: each carries a `not_after` (about fifteen minutes ahead in the reference deployment) and notaio
re-signs them well before it, so a broker that stops receiving fresh ones drops the stale ones from its cache and fails
closed where a bundle is required.

## Shadow: reporting the gap

`shadow.rs` is a **pure** comparison: every way the broker's configuration would let a sandbox do more than the signed
bundle of the policy it names, as findings with stable codes. The reconciler turns them into a `PolicyConformant`
condition on the `AgentSandbox` and a log line per gap; a sandbox that names no policy is unaffected. For example the
condition reads `the broker allows nothing bundle v5 of artifactory does not` when there is no gap. Nothing in the
comparison refuses a sandbox.

## Enforce: the bundle starts to decide

`policy.egress` is `shadow` (the default) or `enforce` (ADR-0030), a switch in the broker's own configuration and never
cluster state.

| Mode | A bundle's direct `egress[]` |
| --- | --- |
| `shadow` | logged only (the gap a policy would add is a finding); the claim's routes and the gateway's allowlist are the audiences' endpoints alone |
| `enforce` | **served**: the union of the audiences' endpoints and the bundle's servable direct egress goes to the claim's proxy (as routes with no credential) and to the gateway's per-claim allowlist |

`enforce` also gives the bundle one more job, for a gateway-placed audience (ADR-0040): the gateway's credential route
asks that the claim name a policy whose verified bundle lists the audience, and fails closed if it does not. A bundle
that lists an audience as a delegated, rule-bounded endpoint is what lets the claim reach it by a placed credential, with
no direct egress entry for the same host (the host leaves the claim's tunnel list, so it is reached only the placed way).

The switch is one value; `shadow` is the rollback, restoring the previous answer on the gateway's next ask.

## Rules this part keeps

- mediatore never trusts a key it was not configured with, and never reads a key from the cluster.
- A floor moves only upward, by compare and set.
- A bundle that fails verification changes nothing; the previous valid one is used until it expires, then none.
- Shadow refuses nothing. Enforce changes only what the claim's routes and the gateway serve and what the credential
  route admits.

## Read next

ADR-0026 (bundles, verified in shadow), ADR-0030 (a policy's direct egress at the gateway), ADR-0040 (the credential
route's policy admission). Threat model TB-2 (the bundle `ConfigMap`s and who can write them) and the actors for notaio
and for anyone who can write `ConfigMap`s in a policy namespace. Roadmaps 09 and 11.
