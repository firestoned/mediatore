<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0066: Eligibility by group, from the signed policy bundle

**Status:** Accepted 2026-11-28, built in shadow only: decision 1's `off` and `shadow` (`enforce` does
not start), and decisions 2 to 4, 6 to 8 as findings that refuse nothing; decision 5's refusal is not
built. See the amendments of 2026-11-28 · **Date:** 2026-11-25

Completes [ADR-0054](0054-which-policies-a-namespace-may-name.md) decision 7, which left eligibility
by subject "to an ADR of its own", and the group-spelling question of
[ADR-0046](0046-who-may-claim-a-list-of-groups-and-a-namespace-to-groups-mapping.md) decision 2.
Builds on [ADR-0026](0026-notaio-bundles-verified-in-shadow.md) (the verified bundle). A sandbox
keeps one `policyRef`: ADR-0065 (several policies, composed by the broker) is rejected in favour of
notaio composing at the policy (notaio ADR-0023), so the broker checks one bundle's one list.
Depends on notaio ADR-0024 (the bundle's `subjects`, in schema v4). Changes no token shape, no SPIFFE
ID and no storage contract. It does change a trust boundary: who may name a policy becomes a rule the
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
state. The groups have to arrive in the signed bundle. notaio ADR-0024 puts them there, in bundle
schema v4.

A policy composed of others (notaio ADR-0023) is one policy to the broker: its `subjects` are its
own, signed as the effective content, and notaio refuses a composite whose groups are wider than any
include's (`L033`) before it signs. So the broker never combines lists and never reads an include.

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
   - **One policy per sandbox.** A composite is one policy and one list (see Context); the broker
     does no composition and checks no include.

3. **Only a v4 bundle can carry the answer, and a bundle without it is never open.** The verifier
   accepts schema v3 and v4 (notaio ADR-0024 decision 6: consumers first). Under `enforce`, a policy
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

8. **New findings,** following P010 to P014:

   | Code | Meaning |
   | ---- | ------- |
   | P015 | The requester holds none of the policy's groups (`policy_not_eligible`) |
   | P016 | The policy's verified bundle carries no subjects, so it is v3 (`policy_without_subjects`) |

   Both are reported under `shadow` and refuse under `enforce`.

*Note of 2026-11-27, from [ADR-0074](0074-a-namespaces-groups-read-only-from-the-issuers-it-names.md)
decision 8 (implemented that day):* a group name is unique only inside the issuer that gave it.
This ADR reads a policy's `subjects.groups`, names with no issuer, on the requester's token. It
runs after the namespace gate, so the token's issuer is already one the namespace's entry
lists; where the entry lists one issuer that is sufficient, and where it lists several the
bundle's names are read from each, as ADR-0074 decision 4 says of the map. That is the floor this
ADR inherits. Whether a bundle should carry an issuer per group is decided here, with notaio's
schema, before this ADR is implemented.

## Amendments of 2026-11-28: built in shadow only

The maintainer accepted this ADR on 2026-11-28, to be built in shadow only. Where the build differs
from the text above, these amendments say how, and they win.

1. **The mode key is `policy.eligibility: off | shadow`, default `off`.** As decision 1, minus
   `enforce`: `enforce` is not built, and a configuration that sets it does not start, with
   `policy.eligibility: enforce is not built: ADR-0066 is built in shadow only; set off or shadow`.
   Any other value does not start either. `off` reads nothing and writes nothing: no bundle is
   looked up for eligibility and no line is written. The default stays `off`, as decision 1 says,
   so an upgrade changes no log volume; an operator turns `shadow` on per environment. Every
   mention of refusing, `403`, or "refuse under `enforce`" above (decisions 1, 3, 5 and 8, the
   security analysis, Consequences) is **not built; shadow only**.

   Control: `EligibilityMode` (`crates/mediatore-claims/src/eligibility.rs`), read as
   `PolicySection::eligibility` (`crates/mediatore/src/config.rs`) and named in the start line of
   `policy_egress` (`crates/mediatore/src/main.rs`).

2. **What notaio's schema v4 carries (notaio v0.9.0, `sandboxpolicy-bundle`).** `content.subjects`
   is `Option<Subjects>`, and `Subjects` is `{ groups: Vec<String> }` (`members.rs`): identity
   provider group names, sorted, matched exactly, `[]` meaning nobody (notaio ADR-0024 decision 1).
   It holds **no user subject and no issuer per group.** So:
   - eligibility is by group only; there is no "by subject" rule to build;
   - the question of the 2026-11-27 note is answered by the schema: a bundle's group carries no
     issuer, and the broker reads each name against the groups of the token it validated, in the
     issuer's own spelling (amendment 3);
   - a v4 bundle without `subjects` is refused by the verifier (`Malformed`), so a verified v4
     bundle always carries the statement. The check still reads a v4 payload without it as not
     judged (`P016`), never as open.
   - a v3 bundle is read as before and is not judged (`P016`), as decision 3 says for `shadow`.

3. **The spelling: the upstream's, unchanged (decision 4, ADR-0073 decision 4, ADR-0074).** The
   requester's groups are `Validated.groups`, the groups of the validated token byte for byte: the
   same list the issuer gate and the namespace gate read. The `subject_prefix` is never added or
   stripped: ADR-0073 qualifies groups in the tokens the broker mints and nowhere else ("the
   broker's own decisions keep the upstream spelling"), and this is one of the broker's own
   decisions. A bundle listing `dex:team-a` does not match a Dex token's `team-a`, nor the reverse.
   The check runs after the namespace gate, so under `sandboxes.namespaces` the token's issuer is
   one the entry lists (ADR-0074 decision 1), and a name listed by the bundle is read from each of
   those issuers (ADR-0074 decision 4). Under the single-namespace form there is no per-namespace
   issuer list, and a bundle's name is read from every issuer the broker trusts: recorded as a
   residual in the threat model until the bundle carries an issuer per group or `enforce` is built.
   The line names the token's issuer beside the subject, so the operator sees which issuer matched.

4. **What is recorded, and where.** At the front door (`create_claim`), after the namespace gate
   and the check of ADR-0054 decision 4, before a session is built: one line per claim request,
   `policy eligibility decision (ADR-0066, shadow): recorded, nothing refused`, carrying
   `eligibility` (`eligible`, `not_eligible`, `not_judged`), `code` (`P015` for not eligible,
   `P016` for a bundle without subjects, else `none`), `reason` for a request not judged
   (`no_policy_ref`, `policy_not_resolved`, `v3_bundle`, `no_subjects`, `no_groups`), `path`
   (`front_door` or `declarative`), the sandbox namespace, the sandbox's name on the declarative
   path (`None` at the front door, which names it after the check), the policy's name, namespace and bundle
   version, the requester's `issuer` and `subject`, `matched_group`, and `policy_groups` (how many
   groups the policy lists). The verdict changes no status, header or body: the answer is the same
   byte for byte with the check judging "not eligible" and with the check off. Never a token.

   Control: `eligibility::judge` and `eligibility::record`
   (`crates/mediatore-claims/src/eligibility.rs`), called by `record_eligibility`
   (`crates/mediatore-api/src/lib.rs`).

5. **Decision 5, for the line.** The line names the one group of the policy's list the requester
   holds, as ADR-0046 decision 13's namespace audit line names the configured group it matched: a
   value of the signed bundle, never the requester's list. A "not eligible" line names no group and
   carries `policy_groups` instead, so `policy_groups=0` reads as the empty list (nobody, decision
   2). The refusal body of decision 5 is not built.

6. **Decision 7, the declarative path, recorded as not judged.** A sandbox created through the
   Kubernetes API (no front-door mark, ADR-0072 decision 3) is recorded by the reconciler before its
   claim exists, with `path=declarative` and `reason=no_groups` (or `v3_bundle`): the broker holds
   no creator groups there. A sandbox the front door created is judged at the front door only and
   never again by the reconciler.

   Control: `SandboxReconciler::record_declarative_eligibility`
   (`crates/mediatore-claims/src/sandbox.rs`).

7. **No metric.** The broker has no metrics facility: roadmap 15's OpenTelemetry foundations are
   not built. The log line is the signal, as ADR-0069 decision 11 and ADR-0070 have it for trips;
   a counter by `eligibility` and `code` (both enums) joins roadmap 15's schema when it exists.

8. **Bounded.** The check walks the bundle's list (bounded by notaio) against the token's groups,
   the list the namespace gate already walks, and stops at the first match. Nothing grows with a
   value the requester chooses beyond those two lists, and the bundle is the one the cache already
   holds: no read leaves the process.

## Security analysis

| Threat | STRIDE | Control |
| --- | --- | --- |
| A requester names a policy they are not eligible for | E | Decision 2, in addition to the issuer and namespace gates |
| The list is read from unsigned cluster state | T/E | Decision 3 and notaio ADR-0024: only from the verified bundle |
| A bundle with no subjects is read as open | E | Decision 3: `P016`, refused under `enforce`, never permissive |
| An empty list admits everyone | E | Decision 2: empty means nobody |
| A group of another organisation matches by prefix | S/E | Decision 4: exact, no normalising, both spellings listed |
| An older bundle with wider groups is replayed | T | The version floor, monotonic across the schema change (notaio ADR-0024 decision 4) |
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
- No change to notaio beyond its ADR-0024, and none to the token, the SPIFFE ID or the store.

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
