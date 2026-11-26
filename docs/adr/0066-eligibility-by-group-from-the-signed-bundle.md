<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0066: Eligibility by group, from the signed policy bundle

**Status:** Proposed (no implementation yet; it needs notaio ADR-0022, the bundle that carries the
groups; CALM, the tests and the threat-model pass are owed before it is accepted) · **Date:** 2026-11-25

Completes [ADR-0054](0054-which-policies-a-namespace-may-name.md) decision 7, which left eligibility
by subject "to an ADR of its own", and the group-spelling question of
[ADR-0046](0046-who-may-claim-a-list-of-groups-and-a-namespace-to-groups-mapping.md) decision 2.
Builds on [ADR-0026](0026-notaio-bundles-verified-in-shadow.md) (the verified bundle) and uses the
policy list of [ADR-0065](0065-a-sandbox-under-several-policies-the-first-named-wins.md) decision 9.
Depends on notaio ADR-0022 (the bundle's `subjects`, schema v4). Changes no token shape, no SPIFFE ID
and no storage contract. It does change a trust boundary: who may name a policy becomes a rule the
broker applies, so the threat-model pass is part of done.

## Context

A policy's `spec.subjects.groups` says which identity provider groups may claim a sandbox under it.
Nothing reads it. ADR-0054 decision 7 says so in as many words: "Nothing in the tree reads a policy's
subjects." Until it is read, **whoever may place a sandbox in a namespace may name every policy that
namespace draws from.** The two gates that exist are exact and independent of any policy:

- the issuer's `required_groups`: may this person use the broker at all;
- `sandboxes.namespaces`: may this person claim in this namespace.

That is coarse. An operator that wants one namespace's members to hold a read-only policy and a
subset to hold a read-write one has no way to say so.

ADR-0054 gave the reasons the check must not read the `SandboxPolicy` object: it is unsigned cluster
state. The groups have to arrive in the signed bundle. notaio ADR-0022 puts them there, in bundle
schema v4.

What stays as it is, and why:

- **Matching is exact and case-sensitive** (ADR-0046 decision 2, `groups_intersect`). A group's
  spelling is the connector's: one group is `NAME` through LDAP or Entra and `org:NAME` through
  GitHub. Normalising would make two groups of different organisations the same group.
- **The declarative path.** A sandbox created straight through the Kubernetes API is governed by
  Kubernetes RBAC and the admission policy, and the broker never sees the creator's groups.

## Decision

1. **A mode, `policy.eligibility: off | shadow | enforce`, default `off`.** `off` is today's behaviour,
   byte for byte: nothing is read or checked. `shadow` evaluates the rule and logs the finding without
   refusing. `enforce` refuses. Each environment moves on its own, shadow first, as `policy.egress`
   and `policy.audiences` do (ADR-0030). A value outside the three is a start error, never a default.

2. **The rule, at claim creation.** The requester must hold at least one of the policy's groups, by
   `groups_intersect` against the groups the broker already has (`Validated.groups`, the same source as
   the issuer gate: `groups` plus `roles`, or `groups_claim`). It is evaluated **in addition to** the
   issuer gate and the namespace gate, never instead of them: all three must pass.
   - **An empty list is nobody**, not anyone. notaio warns on it (`L010`); the broker reads it as no
     eligible requester.
   - **With a list of policies** (ADR-0065), the requester must be eligible for every policy.

3. **Only a v4 bundle can carry the answer, and a bundle without it is never open.** The verifier
   accepts schema v3 and v4 (notaio ADR-0022 decision 6: consumers first). Under `enforce`, a policy
   whose verified bundle is v3, so with no `subjects`, refuses the claim with `P016`
   (`policy_without_subjects`); under `shadow` it reports `P016`. A missing list is never read as
   permission. The floor (ADR-0008, ADR-0026 decision 4) already refuses a replayed older version,
   because notaio keeps the version monotonic across the schema change.

4. **Spelling is unchanged.** A policy lists each spelling it wants to admit, exactly as the namespace
   map does (ADR-0046 decision 2). No prefix is stripped. The broker never guesses what a connector
   meant. A bare group does not match its prefixed twin, and the reverse.

5. **What a refusal says.** `403`, with a body that names no group and no policy's list, as ADR-0046
   does for the issuer gate. The finding in `shadow` and the log line in `enforce` carry the policy's
   name and namespace and the requester's subject, never the groups of either side.

6. **When it is checked.** At claim creation, at the front door (`create_claim`). The groups are not
   stored on the claim record. A later change to a policy's groups, or to the requester's membership,
   does not end a running claim by itself: a claim's life is bounded by its lease and its token
   lifetime. See open question 1 for the token refresh, where fresh groups are available.

7. **The declarative path is not covered, and the ADR says so.** The reconciler sees a sandbox's
   subject but not the creator's groups, and an admission policy cannot read a signed bundle. Mirroring
   the groups into an admission-readable object would put unsigned state back on the authorization
   path, which this ADR exists to avoid. So that path stays governed by Kubernetes RBAC and the
   admission policy, unchanged and not weaker. The documentation and the threat model record it: an
   operator must not read this ADR as protecting that path.

8. **New findings,** following P010 to P012 and the P013 and P014 that ADR-0065 reserves:

   | Code | Meaning |
   | ---- | ------- |
   | P015 | The requester holds none of the policy's groups (`policy_not_eligible`) |
   | P016 | The policy's verified bundle carries no subjects, so it is v3 (`policy_without_subjects`) |

   Both are reported under `shadow` and refuse under `enforce`.

## Security analysis

| Threat | STRIDE | Control |
| --- | --- | --- |
| A requester names a policy they are not eligible for | E | Decision 2, in addition to the issuer and namespace gates |
| The list is read from unsigned cluster state | T/E | Decision 3 and notaio ADR-0022: only from the verified bundle |
| A bundle with no subjects is read as open | E | Decision 3: `P016`, refused under `enforce`, never permissive |
| An empty list admits everyone | E | Decision 2: empty means nobody |
| A group of another organisation matches by prefix | S/E | Decision 4: exact, no normalising, both spellings listed |
| An older bundle with wider groups is replayed | T | The version floor, monotonic across the schema change (notaio ADR-0022 decision 4) |
| The refusal body reveals who may use a policy | I | Decision 5: no group in any body or line |
| An unset or mistyped mode weakens a deployment on upgrade | T | Decision 1: default `off` is today's behaviour; an unknown value does not start |
| The declarative path is mistaken for covered | E | Decision 7: stated in the ADR, the guide and the threat model; behaviour unchanged |
| A removed member keeps a running claim | E | Accepted: bounded by lease and token lifetime; open question 1 narrows it |

## Consequences

- An operator can give one namespace's members different policies by group, from the signed bundle
  alone, with one place (the policy repository) to review who may use what.
- A deployment that does nothing sees no change: the mode is `off`.
- The rollout order is fixed: the broker is upgraded first (it accepts v3 and v4), then notaio
  publishes v4, then the mode moves to `shadow`, then `enforce` after the log has been read.
- Two refusal codes, one mode key and a section in `docs/guides/the-policy-bundle.md`.
- No change to notaio beyond ADR-0022, and none to the token, the SPIFFE ID or the store.

## Alternatives considered

- **Read `spec.subjects` from the SandboxPolicy object.** Unsigned and cluster-writable (ADR-0054).
- **A second list of policies and groups in `mediatore.yaml`.** Two documents that disagree.
- **Normalise connector prefixes.** Merges groups of different organisations (ADR-0046).
- **Patterns in a policy's groups.** Makes a spelling a parameter of a signed grant; exact lists
  generated by the operator give the same reach.
- **Cover the declarative path by mirroring groups into an object an admission policy can read.**
  Unsigned state on the authorization path (decision 7).

## Open questions

1. **Re-check at token refresh?** The refresh path has the requester's fresh groups
   (`groups` in the issue, `crates/mediatore-api/src/lib.rs`). Re-evaluating there under `enforce`
   would make a membership removal take effect within a token lifetime. *Recommendation:* yes, but
   as its own decision after claim-time enforcement has run in `shadow`, because it can end claims
   that are working today.
2. **Should `shadow` also report the namespace gate's verdict beside the policy's?** Useful for
   operators finding which groups to add. *Recommendation:* yes, in the same finding, names only.
