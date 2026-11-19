<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0054: Which policies a namespace may name

**Status:** Proposed · **Date:** 2026-11-19

Roadmap 09 (notaio's bundles, verified in shadow) and roadmap 11 (a policy's direct egress at
the gateway); the work lands under roadmap 11, which is the one still open. Amends
[ADR-0026](0026-notaio-bundles-verified-in-shadow.md) decision 6 as amended 2026-11-05 (where a
`policyRef` is resolved, and the eligibility question its last sentence left to "the enforcing
ADR"), [ADR-0030](0030-policy-egress-enforced-at-the-gateway.md) decisions 1 and 2 (which bundle
is a claim's, and when it is usable) and the policy sentence of
[ADR-0046](0046-who-may-claim-a-list-of-groups-and-a-namespace-to-groups-mapping.md) decision 8,
with its resolved question 5. Touches the admission of a gateway-placed audience
([ADR-0040](0040-the-gateway-places-an-audiences-credential-the-pool-never-holds-it.md)
decision 2). Changes no token shape, no SPIFFE ID, no CRD field, no request field and no
storage contract. It does change a trust boundary: which namespace's policies a sandbox may run
under becomes a rule the broker applies and the operator writes (TB-2, with rows in TB-1 and
TB-14; see the STRIDE table).

## Context

**Naming a policy was harmless when it was decided, and is not any more.** ADR-0026 decision 6
lets a sandbox name its policy (`spec.policyRef`, or `policy_ref` on `POST /v1/claims`) and
closes with: "Who may name which policy (eligibility by group, notaio's K7.2) is the enforcing
ADR's: in shadow, naming a policy grants nothing." That was true of the whole of ADR-0026. Two
later decisions made the name load-bearing wherever `policy.egress` is `enforce`:

- ADR-0030: the direct `egress[]` of the claim's bundle joins what the gateway admits for that
  claim (`served_direct_egress`, `crates/mediatore-api/src/lib.rs`).
- ADR-0040 decision 2: a gateway-placed credential is issued only when the claim's bundle lists
  the audience (`policy_admits`, same file).

Both find the bundle from the `policy_uid` on the claim's record, and the record gets that uid
from one lookup, made once, when the reconciler first sees the claim (`bundle_of` and
`record_for`, `crates/mediatore-claims/src/sandbox.rs`). So under `enforce` the policy a
sandbox names decides part of what it can reach, and the eligibility question ADR-0026 deferred
is no longer a question about a report. Neither ADR-0030 nor ADR-0040 answered it. This ADR
does, for the part the broker can answer today.

**Where the name is looked up is wider than who asked.** `BundleCache::resolve`
(`crates/mediatore-claims/src/policy.rs`) tries the sandbox's own namespace and then every other
namespace of `policy.namespaces`, in the listed order. The amendment of 2026-11-05 added that
fallback for a real deployment: the pool and its sandboxes in the controller's namespace,
notaio's policies in another, and a lookup bound to the sandbox's namespace finding nothing. It
was written while every use of the result was a comparison. ADR-0046 then made namespaces the
unit of tenancy (`sandboxes.namespaces`, a namespace to the groups that may claim there) and
kept the fallback as it was (decision 8: "the sandbox's own namespace first, then
`policy.namespaces` in order"), with the maintainer choosing one policy namespace for all
tenants (resolved question 5). The threat model's TB-2 row for that decision says "Unchanged"
for the policy half. Read together under `enforce`: a name is resolved in namespaces the
requester's own namespace has no stated relation to, and what it resolves to grants reach.

**What a watched namespace means today is two things at once.** `policy.namespaces` says where
the reflector reads bundles (ADR-0026 decision 3, a `Role` per namespace,
`deploy/policy-bundles/`). Through the fallback it also says, implicitly, that every sandbox
may draw from every one of them. The first is a statement about the broker's RBAC. The second
is an authorization nobody wrote down. This ADR separates them.

**What already exists, and what does not** (verified in the source and at the pinned notaio
tag, `v0.6.0`):

- A bundle states its policy's `namespace`, `name` and `uid` inside the signed content, and
  the broker refuses a bundle whose ConfigMap is in another namespace (`Misplaced`,
  `crates/mediatore-policy/src/lib.rs`). A cached bundle's namespace is therefore as
  trustworthy as its signature.
- The record carries the sandbox's namespace (ADR-0046 decision 9) and the policy's `uid`.
  Nothing else is needed to ask, at any later time, "may this namespace draw from that one".
- notaio's `SandboxPolicy` has `spec.subjects.groups` ("identity provider group ids allowed to
  claim a sandbox under this policy"; its lint warns on an empty list, `L010`). **The bundle
  does not carry it.** `BundleContent` (schema `bundle/v3`) holds the policy reference, the
  profile, knobs, audiences, egress, tools, lease and budgets, and no subjects. notaio's own
  plan for eligibility (its roadmap 00, D3) is a ValidatingAdmissionPolicy on `AgentSandbox`
  with the named `SandboxPolicy` as parameter.
- On the broker's front door the API server sees the broker's `ServiceAccount`, not the person
  (ADR-0046 decision 8 says so for pools). An admission policy on the requester's groups cannot
  see the person who asked through the broker.
- The declarative path has no token: `spec.subject` is written by a requester the subject
  admission policy admits (A-9). The broker has no groups to check there, only a namespace.

The namespace is the one fact both paths have, that the operator already reasons in, and that
the signed bundle already states. That is what this ADR builds on.

## Decision

1. **A policy is resolved in the namespaces the sandbox's own namespace draws from, and by
   default that is the sandbox's own namespace alone.** The fallback across
   `policy.namespaces` is removed. A new type, `PolicySources`, in
   `crates/mediatore-claims/src/policy.rs` answers one question, `sources_of(sandbox
   namespace) -> &[String]`, and `BundleCache::resolve` takes it and returns a `Resolution`
   (`Found(bundle)`, `NotFound`, `Ambiguous`, `NotRead`) instead of an `Option`. `bundle_of`
   in `crates/mediatore-claims/src/sandbox.rs` is its only caller on the creation side. There
   is one function for the rule so the reconciler, the front door and the gateway answer
   cannot disagree about it, as `groups_intersect` does for ADR-0046. `policy.namespaces`
   keeps exactly one meaning: where the reflector reads.

2. **`policy.sources`: an explicit mapping from a sandbox namespace to the policy namespaces it
   draws from, for the operator who keeps policies apart from sandboxes.**

   ```yaml
   policy:
     trusted_keys: [ ... ]
     namespaces: [team-a, team-b, infra-policies]   # where bundles are read (unchanged)
     egress: enforce
     sources:                                       # new, optional
       infra:
         namespaces: [infra-policies]               # the whole of where infra finds a policy
   ```

   - `team-a` and `team-b` have no entry: each draws from itself, and from nowhere else.
   - `infra` has an entry: the list is **the whole** of its sources. Its own namespace is a
     source only if listed. An entry replaces the default, it does not add to it, so reading
     one entry tells the reviewer everything about that namespace.
   - The mapping lives under `policy`, not under `sandboxes.namespaces`, because it must
     cover the single-namespace form (the deployment the 2026-11-05 amendment was written
     for has no map) and the declarative path, whose sandboxes may sit in a namespace the
     claim map does not list (ADR-0046 decision 11).
   - It is the broker's configuration, reviewed with its deployment, never cluster state: the
     standing of the trusted keys (ADR-0026 decision 2) and of the namespace map (A-26). A
     label or annotation on a namespace or a ConfigMap would let whoever can write that
     object choose which policies a tenant may run under.
   - The entry is a struct (`#[serde(deny_unknown_fields)]`), not a bare list, so a typo is a
     start error and a later narrowing (open question 1) has somewhere to go.

   Files: `PolicySection` and `check_policy` in `crates/mediatore/src/config.rs`; the wiring
   in `crates/mediatore/src/main.rs` (`policy_egress`, `WatcherConfig`).

3. **A name held by two of a namespace's sources is refused as ambiguous; the order of a list
   never decides.** First-wins would make the policy a sandbox runs under depend on which
   namespace happens to be written first, and would let a policy added to one source shadow
   the one of the same name in another without either changing. `Resolution::Ambiguous` is
   reported as a new code, `P012` ("the named policy is held by more than one of this
   namespace's sources"), in `crates/mediatore-claims/src/shadow.rs`.

4. **Under `enforce`, a sandbox that names a policy which does not resolve is refused at
   creation; it is never created without a policy.** Today such a sandbox is created with no
   `policy_uid` on its record and runs on the audience endpoints: fail closed for reach, but
   silent, and the requester learns it from a refused connection. Instead:
   - **The reconciler is the control**, since it sees both paths. Before any claim exists
     (the existing `refuse` step of `reconcile_sandbox`, `sandbox.rs`), `NotFound` and
     `Ambiguous` set `phase: Failed` and a `status.reason` of
     `policy_not_resolved: no verified bundle for policy <name> in the namespaces <namespace>
     draws its policies from`; the `PolicyConformant` condition is `False`/`Gaps` with `P011`
     or `P012`. No claim, no record, the parked session dropped, as for every other refusal.
   - **The answer does not say where else the name exists.** A policy in a namespace the
     sandbox may not draw from and a policy that exists nowhere produce the same reason and
     the same code. The broker's own log, which the operator reads, does say it (`policy held
     by a watched namespace outside this sandbox's sources`, with the namespaces), because
     during a migration that line is the instruction.
   - **`NotRead` is neither a refusal nor a pass.** While a source namespace has not completed
     its first list on the replica holding the Lease, a sandbox that names a policy is held
     (`PolicyConformant` `Unknown`/`BundlesNotRead`, requeued), and no claim is created. Only
     that sandbox's sources need to have been read, not every watched namespace
     (`BundleCache::synced` per source replaces `synced_all` here).
   - **The record is written from the resolution that admitted the sandbox.** Under
     `enforce`, a record for a sandbox that names a policy always carries a `policy_uid`; if
     the bundle is gone between admission and the record (expired, dropped), the claim is
     deleted and the sandbox refused, the shape of `refuse_without_delegation`.
   - **The front door answers early when it can.** `create_claim`
     (`crates/mediatore-api/src/lib.rs`) applies the same function to the resolved namespace
     of ADR-0046 decision 4, before the session is parked: `400 policy_not_resolved`, with the
     same message. When its replica has not read the sources it does not guess: it creates
     the sandbox and the reconciler holds it.
   - A sandbox that names **no** policy is unchanged: created, audience endpoints only,
     `P010`. Making `policyRef` required is still the enforcing ADR's (R-17).

5. **`shadow` applies the same rule and refuses nothing.** In `shadow` the resolution is the
   one of decisions 1 to 3; an unresolved name is reported (`P011`, `P012`, the operator's log
   line of decision 4) and the sandbox is created as today, its record without a
   `policy_uid`. Shadow exists to show what `enforce` would do; a looser lookup in shadow
   would report reach that `enforce` then withholds, and, worse, would write records whose
   `policy_uid` the switch to `enforce` then starts serving. The cost is to one shape of
   existing deployment and is stated under Consequences and decision 9.

6. **What is served is checked against the sources again, at the time it is served.**
   `served_direct_egress` and `policy_admits` (`crates/mediatore-api/src/lib.rs`) find the
   bundle by `uid` as now, then require the bundle's signed namespace to be one of the sources
   of the record's namespace. A bundle that fails is treated as ADR-0030 decision 1's
   "missing": audience endpoints only, a placed credential refused under `enforce`, one `warn`
   line naming the claim UID, the policy uid and the two namespaces. `PolicyEgress` gains the
   `PolicySources`. Three reasons: records written before this ADR, or by an older replica
   during a rollout, may hold a uid found by the fallback; removing a source from the mapping
   then takes effect on running sandboxes within the gateway's bound, as a tightened policy
   does (ADR-0030 decision 2); and the creation rule stops being the only place the boundary
   is held.

7. **Eligibility by subject (which groups may use a policy) is not decided here; it belongs
   with notaio's signed bundle, in an ADR of its own.** The reasons, in order of weight:
   - The data is notaio's and is reviewed where the policy is: `spec.subjects.groups`, in the
     policy repository, under its lint. A second list of policy names and groups in
     `mediatore.yaml` would be the two-documents problem ADR-0026 was written to end.
   - The broker must not read it from the `SandboxPolicy` resource: that is unsigned cluster
     state, a new RBAC grant, and the argument of ADR-0026 decision 2 against keys from the
     cluster applies word for word. It has to arrive inside the signed bundle, which today it
     does not: a notaio schema change, then a tag bump here.
   - notaio's planned admission policy covers the declarative path, where the API server sees
     the requester. It cannot cover the broker's front door (Context). So the check has two
     homes whatever is decided, and the broker's half (`create_claim`, `Validated.groups`,
     `groups_intersect`) needs the bundle to carry the groups.
   - Group spelling is the connector's (ADR-0046 decision 2). A policy's `subjects.groups`
     written for one connector does not match another's, and deciding that is not a detail.

   Until then the namespace is the unit of eligibility: **whoever may place a sandbox in a
   namespace may name every policy that namespace draws from.** That is the honest statement
   of what this ADR gives, and it is why resolved question 5 of ADR-0046 (one policy namespace
   for all tenants) is reopened: under `enforce`, mapping two tenants to one policy namespace
   gives both tenants every policy in it. An operator who needs the tenants apart keeps each
   tenant's policies in a namespace only that tenant draws from. A shared policy namespace
   remains right for policies every mapped tenant is meant to have.

8. **Validation at start, and the log of what was resolved.** Refused at start, the message
   naming the key and the value (`check_policy`, `crates/mediatore/src/config.rs`):
   - a `sources` entry naming a namespace that `policy.namespaces` does not list (the broker
     reads nothing there, so the entry could never resolve: a typo, or a missing `Role`);
   - a key or a listed namespace that is not an RFC 1123 label; a duplicate key (checked on
     the YAML parse, as ADR-0046 decision 14); an entry with no `namespaces` key, an empty
     list, or a namespace listed twice in one entry; an unknown field;
   - `sources` present and empty. No mapping is spelled by leaving the key out.

   An empty list is not "this namespace has no policies" and is not "any": it does not start.
   At start the broker logs at `info`, per namespace it knows (the claim map's, or the single
   namespace, and every `sources` key), where that namespace draws its policies from; and at
   `warn` each such namespace whose sources include no watched namespace, since every
   `policyRef` there will be refused under `enforce` (decision 4) or reported under `shadow`.
   Names from configuration, never a token.

9. **Migration: the broker and its configuration in one rollout, shadow first.**
   - *Sandboxes and policies in one namespace* (the default, and the kind tiers): nothing to
     write, nothing changes.
   - *Sandboxes in one namespace, policies in another* (the 2026-11-05 shape): add a `sources`
     entry for the sandbox namespace. Without it, in `shadow`, new sandboxes report `P011`
     where they reported a comparison, and the start log's `warn` line says why; in `enforce`,
     new sandboxes naming a policy are refused and running ones lose the policy's direct
     egress and placed credentials on the gateway's next ask (decision 6).
   - *Order.* An older broker refuses the unknown `sources` key (`deny_unknown_fields`), and a
     newer broker without the key applies the own-namespace default. So for a deployment that
     relies on the fallback, the image and the configuration change in the same rollout, and
     a rollback removes the key with the image. A deployment that does not rely on it
     upgrades the broker first, as ADR-0046 decision 18.
   - *Check before `enforce`.* One week of `shadow` on the new build with no `P011`, `P012` or
     "outside this sandbox's sources" line that was not expected, added to roadmap 11's
     rollout checklist and `docs/guides/the-policy-bundle.md`.

10. **Not changed, and fail closed.** Without a `policy` section nothing is read and nothing
    here exists. Under `dev_mode` no bundle is read (`policy_egress` is `None`) and the rule
    has nothing to apply to. `policy.namespaces`, the per-namespace `Role`
    (`deploy/policy-bundles/`), the trusted keys, the version floor, `by_uid` taking the
    current bundle, and every ADR-0030 serving rule stand. A `Resolution` the code does not
    handle is a refusal, never a lookup somewhere else.

### STRIDE: TB-2 (the broker and the Kubernetes API), with the rows that land in TB-1 and TB-14

None of these controls exists yet. Each names the file it will live in; the threat-model pass
after implementation cites them only once they are built and tested.

| Threat | STRIDE | Control (not yet built) |
| --- | --- | --- |
| A sandbox in one namespace runs under a policy of a namespace it has no stated relation to, and gains that policy's direct egress or placed audiences under `enforce` | E | Resolution in the sandbox's sources only: `PolicySources` and `BundleCache::resolve` in `crates/mediatore-claims/src/policy.rs`, called by `bundle_of` in `crates/mediatore-claims/src/sandbox.rs` (not yet built). Second layer at serving time: `served_direct_egress` and `policy_admits` in `crates/mediatore-api/src/lib.rs` compare the bundle's signed namespace with the record's sources (not yet built) |
| A record written before this rule, or by an older replica, keeps reach from a namespace its sandbox may not draw from | E | The serving check of decision 6, `crates/mediatore-api/src/lib.rs` (not yet built); no migration of records |
| A sandbox that names a policy is created without one and nobody is told | T/R | Under `enforce`, refusal before any claim exists and the record invariant of decision 4: `reconcile_sandbox` and `record_of` in `crates/mediatore-claims/src/sandbox.rs`; `400 policy_not_resolved` in `create_claim`, `crates/mediatore-api/src/lib.rs` (not yet built) |
| The refusal used to learn which policies exist in other tenants' namespaces | I | One reason and one code for "elsewhere" and "nowhere" (`sandbox.rs`, `lib.rs`); the distinguishing line is in the broker's log only (not yet built) |
| Two policies of one name in two sources, the list order choosing between them | T/E | `Resolution::Ambiguous`, refused or reported as `P012`: `policy.rs`, `crates/mediatore-claims/src/shadow.rs` (not yet built) |
| The mapping set by someone other than the operator, or a misspelling read as permissive | T/E | `policy.sources` is the broker's configuration only; `check_policy` in `crates/mediatore/src/config.rs` refuses an unwatched namespace, an empty list, an unknown field and a duplicate key (not yet built). Whoever edits the file already chooses the signing keys (A-19) |
| A replica whose cache has not read a source answers "not found" for a policy that exists, refusing or unpolicing a sandbox | D/T | `Resolution::NotRead` holds the sandbox, per source namespace: `policy.rs`, `sandbox.rs` (not yet built). At the gateway an unread cache already serves audience endpoints only (ADR-0030) |
| A mapping mistake: a tenant mapped to a policy namespace holding more than it was meant to have | E | Residual, to be accepted in §8 beside R-34: the mapping is a security configuration reviewed by hand, and within one policy namespace every mapped tenant may name every policy until the bundle carries subjects (decision 7). Bounded by the start log of decision 8 and the audit line of the create (not yet built) |

## Consequences

- **Tenants are kept apart by default.** With nothing written, a sandbox finds policies in
  its own namespace only. Reaching another namespace's policies takes a line of the operator's
  configuration that a reviewer can read.
- **The broker is the enforcement point for policy eligibility by namespace,** on both paths.
  A mistake in `policy.sources` grants a tenant another namespace's policies; it cannot place
  a sandbox, reach a pool or change what a token is minted for. It is a second
  hand-reviewed security configuration beside the namespace map.
- **Not compatible for one shape, by design.** A deployment with sandboxes and policies in
  different namespaces must write a `sources` entry when it takes this build (decision 9).
  In `shadow` the cost is a changed report; in `enforce` it is refused creations and withdrawn
  reach until the entry exists. The release notes and the guide say so first.
- **Within a policy namespace nothing separates tenants** (decision 7). An operator on
  `enforce` with several tenants either splits the policy namespaces per tenant (a `Role`
  overlay and a `policy.namespaces` line each) or accepts that the shared namespace is shared.
  ADR-0046's resolved question 5 was right for `shadow` and needs the maintainer's answer
  again for `enforce` (open question 1).
- **A requester gets a refusal at creation instead of a refused connection later,** under
  `enforce`. Clients that named a policy loosely will see `400` or a `Failed` sandbox where
  they saw a running one with less reach.
- **A sandbox may wait at start-up of a replica** (decision 4, `NotRead`), for as long as the
  first list of its sources takes. It waits on fewer namespaces than the comparison does
  today.
- **Threat model, the full pass after implementation** (`rules/threat-modeling.md`): the TB-2
  row for ADR-0046 decision 8 is split, the pool half standing and the policy half replaced;
  TB-2 gains the rows above, TB-1 the front-door refusal and what it does not disclose, TB-14
  the serving check; a new asset (the `policy.sources` mapping, the standing of A-19 and
  A-26); R-17 notes that naming a policy is bounded by namespace; a new accepted risk for the
  residual row, *Revisit when* notaio's bundle carries `subjects.groups`. The header stamp is
  bumped with the ADR range.
- **CALM** (`docs/architecture/calm/architecture.json`): the mapping as configuration on the
  broker and the TB-2 decision point; no new node. `make calm-validate` and
  `make calm-diagrams` before implementation.
- **Docs:** `docs/guides/the-policy-bundle.md`, `docs/guides/multi-tenant-authorization.md`,
  `docs/guides/requesting-a-sandbox.md` (the refusal), ADR-0026, ADR-0030 and ADR-0046 gain an
  "Amended" note pointing here, roadmap 11's detail doc and the board row.
- **The TPM attestation path is not touched** (`rules/testing.md`), so `make kind-e2e-tpm` is
  not required.

## Alternatives rejected

- **Keep the fallback and add a check only under `enforce`.** Two lookups for one name,
  chosen by a switch, and records written under the wide one served after the switch
  (decision 5). The rule would also be untested in the mode every environment starts in.
- **Own namespace only, with no mapping.** The simplest rule, and the right one if no
  deployment kept policies apart from sandboxes. One does (the reason for the 2026-11-05
  amendment), and forcing notaio's policies into the controller's namespace to satisfy the
  broker is the wrong direction of dependency. **This is the better choice for an operator
  who can co-locate:** such an operator writes no `sources` and gets exactly it.
- **Every watched namespace is a source for everyone, in a fixed order** (today). It is the
  implicit authorization the Context describes.
- **A name allowlist per sandbox namespace in `mediatore.yaml`** (namespace to policy names).
  It would let one shared policy namespace serve several tenants safely, and it is the better
  choice if the maintainer holds to one policy namespace under `enforce` before notaio's
  bundle carries subjects. Not proposed as the default because every new policy becomes a
  broker restart, and it duplicates in the broker's file what notaio already states per
  policy. Open question 1.
- **Read `subjects.groups` from the `SandboxPolicy` resource.** Unsigned cluster state
  deciding reach, and a new RBAC grant (decision 7).
- **Carry the policy's namespace in the request** (`policyRef: { namespace, name }`). The
  requester would then choose the namespace as well as the name; the question is who may,
  not how it is spelled. It also changes the CRD and the claim request for no gain.
- **A ValidatingAdmissionPolicy alone.** It cannot verify a signature (ADR-0026) and does not
  see the person behind the broker's `ServiceAccount`. It remains notaio's answer for the
  declarative path and is complementary.
- **A label on the policy namespace naming the tenants that may use it.** Cluster state
  again: whoever can label a namespace would grant its policies.
- **One broker per tenant.** The strongest separation, at the cost ADR-0046 already weighed.
  It stays the answer for a tenant that needs more than a namespace rule.

## What must be proven

Tests first and failing, by name. No kind tier and no test is claimed to pass today.

Unit, `crates/mediatore-claims/src/policy.rs` (the existing
`a_policy_is_resolved_in_the_sandboxs_namespace_first_then_across_the_watched_ones` is
replaced, not kept beside):

- `a_policy_is_resolved_in_the_sandboxs_own_namespace_and_nowhere_else`
- `a_policy_in_another_watched_namespace_is_not_found_without_a_sources_entry`
- `a_sources_entry_is_the_whole_of_a_namespaces_sources_its_own_included_only_if_listed`
- `a_name_held_by_two_sources_is_ambiguous_whatever_the_order`
- `a_namespace_is_not_read_until_its_own_sources_listed_and_no_other_is_waited_for`
- `an_expired_bundle_in_a_source_is_not_found`

Unit, `crates/mediatore/src/config.rs`:

- `a_config_without_policy_sources_draws_each_namespace_from_itself`
- `policy_sources_naming_an_unwatched_namespace_refuses_to_start`
- `policy_sources_present_and_empty_refuses_to_start`
- `a_sources_entry_with_an_empty_list_refuses_to_start`, `..._with_a_duplicate_namespace_...`,
  `..._with_a_non_dns_label_...`, `..._with_a_duplicate_key_...`,
  `..._with_a_typo_in_an_entry_field_...`
- `startup_logs_where_each_namespace_draws_its_policies_from_and_warns_on_none`

Unit, `crates/mediatore-claims/src/sandbox.rs` and `shadow.rs`:

- `under_enforce_a_policy_ref_that_does_not_resolve_is_refused_before_any_claim_exists`
- `the_refusal_is_the_same_for_a_policy_elsewhere_and_a_policy_nowhere`
- `under_enforce_an_ambiguous_policy_ref_is_refused_with_p012`
- `under_shadow_the_same_sandbox_is_created_and_reports_p011`
- `under_enforce_a_sandbox_is_held_while_its_sources_are_unread_and_no_claim_is_created`
- `under_enforce_a_record_for_a_sandbox_naming_a_policy_always_carries_its_uid`
- `a_bundle_gone_between_admission_and_the_record_refuses_the_sandbox_and_deletes_the_claim`
- `a_sandbox_without_a_policy_ref_is_created_as_before`

Unit and end to end over real HTTP, `crates/mediatore-api/src/lib.rs` and
`crates/mediatore/tests/e2e_gateway.rs` (the suite that builds a state with a bundle cache;
`e2e_dev.rs` runs under `dev_mode`, where no bundle is read), negative cases first:

- `under_enforce_a_claim_naming_a_policy_outside_its_sources_is_400_and_parks_nothing`
- `the_400_names_no_other_namespace`
- `a_claim_in_team_a_gets_nothing_from_a_policy_of_team_b` (the gateway answer and `/v1/me`)
- `a_record_holding_a_uid_from_outside_its_sources_gets_the_audience_endpoints_only`
- `a_placed_audience_is_refused_when_the_bundle_is_outside_the_records_sources`
- `removing_a_source_withdraws_the_direct_egress_on_the_next_ask`
- `a_mapped_policy_namespace_serves_its_direct_egress_under_enforce` (the positive case)
- `under_shadow_nothing_is_refused_and_the_log_says_what_enforce_would_refuse`
- the existing ADR-0030 tests unchanged where sandbox and policy share a namespace.

Live, in kind, on the build host:

- `make kind-e2e-policy` (`dev/kind/policy-e2e.sh`): a second namespace with a notaio policy
  of its own. A sandbox naming the other namespace's policy reports `P011` under `shadow` and
  is `Failed` with `policy_not_resolved` under `enforce`; with a `sources` entry and a restart
  it is admitted and recorded; the existing verdicts hold in the shared-namespace case.
- `make kind-e2e-gateway-policy` (`dev/kind/gateway-e2e.sh`): under `enforce`, the tunnel to
  the second port opens for a sandbox whose namespace draws from the policy's and stays
  `403 not_allowed` at the real Envoy for one whose namespace does not; the broker's `warn`
  line of decision 6 is present for the latter.

`make check` green on the build host, and the threat-model pass, before the status moves.

## Open questions

1. **One policy namespace for several tenants under `enforce`.** Resolved question 5 of
   ADR-0046 chose it; decision 7 says it then shares every policy in it. Three ways out: split
   the policy namespaces per tenant; add an optional `names: [...]` to a `sources` entry; wait
   for the bundle to carry subjects and keep such environments on `shadow`.
   *Recommendation:* split per tenant now and add no `names` list. It uses what exists, it is
   one configuration change per tenant instead of one per policy, and it does not have to be
   unpicked when subjects arrive. If the maintainer holds to one namespace, `names` is the
   honest interim and the entry type has room for it.
2. **Ask notaio to compile `subjects.groups` into the bundle, and plan the follow-on ADR
   here?** *Recommendation:* yes, as a request on notaio's roadmap 00 (D3), with the group
   spelling question of ADR-0046 decision 2 settled there first. The broker's check is small
   once the signed data exists.
3. **The key's name and place.** `policy.sources.<namespace>.namespaces` reads well beside
   `policy.namespaces` but the two are easy to confuse. *Recommendation:* keep it under
   `policy` (decision 2's reasons) and let the maintainer pick the word; `policy.draws_from`
   is the alternative.
4. **Should a claimable namespace with no watched source refuse the start under `enforce`?**
   *Recommendation:* no, a `warn` line (decision 8). A tenant with audiences and no policy is
   legitimate, and its `policyRef`s are already refused one by one. Refuse at start only if
   the maintainer wants ADR-0046's stricter reading.
5. **`400` at the front door, or only the `Failed` sandbox?** The early answer is kinder to a
   person at a terminal; it is also a second call site for the rule. *Recommendation:* keep
   both, with the one function and the test that pins the two messages equal.
6. **Does removing a source withdraw reach from running sandboxes (decision 6), or apply to
   new claims only?** *Recommendation:* withdraw. It matches how a tightened bundle behaves,
   and a mapping an operator narrows in a hurry should not wait out every sandbox's TTL.
7. **Is one release of warning wanted before the fallback goes?** A build that keeps the
   fallback in `shadow` and logs each use would let the one affected shape find its `sources`
   entry from its own log. *Recommendation:* no. The `warn` line at start and the unchanged
   behaviour of `shadow` (nothing refused) already give that, and ADR-0046 resolved question 7
   set the precedent of no warn-only release.
