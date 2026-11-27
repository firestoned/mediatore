<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0074: A namespace's groups are read only from the issuers it names

**Status:** Proposed · **Date:** 2026-11-27

Amends [ADR-0046](0046-who-may-claim-a-list-of-groups-and-a-namespace-to-groups-mapping.md)
decisions 3 (an entry of `sandboxes.namespaces` gains `issuers`), 14 (what is refused at start)
and 18 (what the start says). Lands with
[ADR-0071](0071-sub-qualified-by-issuer-when-the-broker-trusts-several.md),
[ADR-0072](0072-a-hand-created-sandbox-names-only-an-issuer-its-creator-can-come-from.md) and
[ADR-0073](0073-groups-qualified-by-issuer-when-the-broker-trusts-several.md): those make the
issuer part of every identity the broker hands out, and this one makes it part of the one
authorization decision the broker takes on a group name. Changes the broker's configuration
contract. Changes no token shape, no SPIFFE ID, no route and no storage contract. It narrows a
trust boundary, TB-1, so the threat-model pass is part of done.

## Context

ADR-0046 decision 3 maps each claimable namespace to the groups whose members may use it, and
decision 2 matches a group by its exact name. The issuer gate (`required_groups`) is a key of each
issuer; the namespace map is not. An entry says `team-a: { groups: [platform-admins] }`, and a
token from any trusted issuer that carries `platform-admins` qualifies.

A group name is unique only inside the issuer that gave it (ADR-0073's context). With one trusted
issuer that is the whole space and the map is exact. With two, the same string at the second
issuer is another set of people, chosen by another directory's administrators, and the map
admits them to the namespace. The operator who wrote the entry for one directory said nothing
about the other; the overlap is made by adding an issuer, not by editing the map.

### Every place the map is read

Read in the code for this ADR. The map is `Namespaces` (`crates/mediatore-api/src/lib.rs`), built
by `SandboxesSection::resolve` (`crates/mediatore/src/config.rs`) and handed to `AppState` in
`crates/mediatore/src/main.rs`.

| Place | What it reads | Is the issuer at hand? |
| --- | --- | --- |
| `POST /v1/claims`: `create_claim` calls `resolve_create`, which calls `Namespaces::resolve_for_create` and, for the audit line, `Namespaces::matched_group` | The groups of the bearer token, against the requested namespace's entry | Yes: `validated.subject.issuer`, the issuer the token was validated as (`caller`, then `validate_as` pins `iss`). Already in the audit line |
| `GET` and `DELETE /v1/claims/{name}`, `GET /v1/claims/{name}/logs`: `owned_sandbox` and `owned_claim` (the latter in `dev_mode`, and via `owned_record_for_logs`) call `resolve_existing`, which calls `Namespaces::authorise_existing` | The same, on every read and delete (ADR-0046 decision 5) | Yes, the same `Validated` |
| `dev_mode` | The same functions on the dev token's groups (ADR-0046 decision 12) | Yes: the dev token is validated as an issuer of the configuration like any other |
| The start: `Config::log_startup`, `claimable_at_home` and `check_home_namespace` (`crates/mediatore/src/main.rs`), `Config::audience_namespaces`, `Config::log_policy_sources`, `check_audience_scopes` | The map's keys only, never its groups | Not needed |
| `POST /v1/token`, `/v1/me`, `/v1/me/report`, `/v1/me/exit`, the gateway routes | Not the map: the namespace is the claim record's (ADR-0046 decision 9), fixed at create | Not needed |
| The reconciler (`crates/mediatore-claims/src/sandbox.rs`, `watch.rs`) | Not the map. `WatcherConfig` holds no namespace groups | Not needed |
| The declarative path (`create` on `agentsandboxes`) | Not the map, by ADR-0046 decision 11: Kubernetes RBAC and the admission policy govern it | Not applicable; see below |

So the map's groups are read in exactly two functions, `resolve_for_create` and
`authorise_existing` (with `matched_group` under both), and every caller of them holds a
validated token whose issuer is known. There is no listing of the namespaces a caller can reach;
the CLI is told the namespace or names it.

**The declarative path is unchanged by this ADR.** A person with `create` on `agentsandboxes` in
`team-a` holds a grant the cluster's administrator gave them, and the map has never been a
statement about it (ADR-0046 decision 11). What a hand-created sandbox may say about its subject's
issuer is ADR-0072's.

## Decision

1. **`sandboxes.namespaces.<ns>.issuers`: the issuers whose tokens this entry's groups are read
   from.** A list of `issuers[].url` values on each entry.

   ```yaml
   sandboxes:
     namespaces:
       team-a:
         issuers: [https://dex.example.com]
         groups: [platform-admins]
       infra:
         issuers: [https://dex.example.com, https://login.microsoftonline.com/<tenant>/v2.0]
         groups: [example-org:APP_EXAMPLE_ADMIN, APP_EXAMPLE_ADMIN]
   ```

   A token qualifies for the entry when its issuer is listed **and** its groups intersect the
   entry's `groups` (ADR-0046 decision 2, unchanged: exact, case-sensitive). A token of an
   unlisted issuer does not qualify whatever its groups; its answer is the answer for an
   unqualified caller (`403` on create, `404` on get, delete and logs, ADR-0046 decisions 5 and 6),
   so the response does not say which issuers an entry lists.

   Control: `Namespaces::matched_group`, `Namespaces::resolve_for_create` and
   `Namespaces::authorise_existing`, each taking the validated issuer beside the groups
   (`crates/mediatore-api/src/lib.rs`); `resolve_create` and `resolve_existing` pass
   `validated.subject.issuer`. The map's value becomes an entry of groups and issuers, never a
   bare list, so no caller can match groups without saying the issuer.

2. **Two or more issuers: every entry has `issuers`, or the broker does not start.** Refused at
   start, the message naming the key and the namespace:
   - an entry without `issuers`:
     `sandboxes.namespaces.team-a.issuers is not set: with 2 issuers a namespace's groups must say
     which issuers they are read from, or a group of the same name at another issuer would admit
     its members (ADR-0074)`;
   - an empty list;
   - a value that is not an `issuers[].url`, byte for byte;
   - an issuer listed twice in one entry.

   There is no default. "Every issuer" would be today's ambiguity under a new spelling, and "the
   first issuer" a guess.

   Control: `SandboxesSection::validate`, given the issuers, called from `Config::parse`
   (`crates/mediatore/src/config.rs`).

3. **One issuer: unchanged, and the list optional.** Without `issuers` an entry is read from the
   one issuer, as before; with it, the list is checked as in decision 2 (so it can only name that
   issuer). A deployment with one issuer that writes nothing gets the same answers, byte for
   byte, and the same start lines but one (decision 5). Writing the list ahead of a second issuer
   is what the guide recommends, as for `subject_prefix`.

4. **An entry may list several issuers, and then each of its groups is read from each of them.**
   That is the operator's explicit statement that the name means the same at both, which is what
   the `infra` example above says of `APP_EXAMPLE_ADMIN` when an LDAP service ID and a GitHub
   organisation both carry it (ADR-0046's motivating case). An operator who means different names
   at different issuers writes the names that are distinct. Open question 1 is the finer form.

5. **The start says it.** The existing `namespace groups` line of ADR-0046 decision 14 gains the
   entry's issuers: `namespace=team-a groups=platform-admins issuers=https://dex.example.com`.
   With one issuer and no list, `issuers=<the one url> (the only issuer)`.

   Control: `Config::log_startup`.

6. **The single-namespace form is untouched.** `sandboxes.namespace` (no map) is open to every
   caller who passes an issuer's gate: it reads no group, so there is nothing to bind. Its gate is
   the per-issuer `required_groups`, already bound.

7. **The audit line of a create names the issuer beside the matched group,** as it already does;
   a denial for an unlisted issuer is logged as `denied`, as an unqualified caller is.

8. **ADR-0066 must take the same rule before it is implemented.** Eligibility by group reads a
   policy's `subjects.groups`, a list of names with no issuer, on the requester's token. It runs
   after the namespace gate, so after this ADR the token's issuer is already one the namespace
   entry lists; where the entry lists one issuer that is sufficient, and where it lists several,
   the bundle's names are read from each, as decision 4 says for the map. The ADR records this in
   a note on ADR-0066 (phase 2), and whether a bundle should carry an issuer per group is a
   question for that ADR and notaio's schema, not this one.

## Security analysis

TB-1 is the requester to the user API: the issuer gate, the namespace map and the subject check.

| Boundary | Threat | STRIDE | Control |
| --- | --- | --- | --- |
| TB-1 | A member of a group at one trusted issuer is admitted to a namespace mapped to the same group name at another | E | An entry's groups are read only from tokens of the issuers it lists (decision 1). `a_group_of_the_same_name_at_an_unlisted_issuer_does_not_qualify`, `the_same_group_name_at_two_issuers_reaches_only_the_listed_issuers_namespace` |
| TB-1 | A second issuer added without saying which namespaces it serves, so its groups qualify everywhere by omission | E | The broker does not start until every entry lists its issuers (decision 2). `two_issuers_with_a_namespace_entry_without_issuers_refuse_to_start` |
| TB-1 | A typo in `issuers` that silently closes a namespace, or names an issuer the broker does not trust | D / E | A value that is not an `issuers[].url` refuses the start, naming the key and the value |
| TB-1 | The `403` or `404` tells a caller which issuers a namespace takes | I | An unlisted issuer gets the answer of an unqualified caller (decision 1). `the_refusal_for_an_unlisted_issuer_equals_the_refusal_for_an_unlisted_group` |
| TB-1 | A person who has left a namespace's directory keeps reading their sandbox through another issuer's account with the same group | E | Get, delete and logs pass through `authorise_existing` with the issuer, and the subject check already requires the same issuer and id (`owned_sandbox`) |
| TB-1 | An audit trail that cannot say which issuer's group admitted a caller | R | The create's line names the issuer and the listed group matched (decision 7) |

What this does not change: the declarative path (ADR-0046 decision 11, ADR-0072); a running claim
(its namespace is fixed in its record, and no token issue re-reads the map, as before); and an
entry that lists several issuers by the operator's choice (decision 4).

## Consequences

- **A deployment with one issuer sees no change** but one start line.
- **A deployment with two or more issuers and a namespace map does not start on the release that
  carries this ADR until each entry lists its issuers.** A breaking change, said in the release
  note and by the start error, which names the key and the namespace. The single-namespace form is
  not affected.
- **The map's type changes from groups to an entry,** so every test that builds a
  `Namespaces::Map` by hand is rewritten; the fixtures are in `crates/mediatore-api/src/lib.rs`
  (`tenant_map` and its neighbours) and `crates/mediatore/src/main.rs`.
- **`IssuerConfig` and `SandboxesSection` already reject unknown keys** (ADR-0046 decision 17), so
  a broker older than this ADR refuses a file with `issuers` on an entry: the configuration
  follows the broker.
- **No kind tier uses the namespace map today**: the kind broker's configuration
  (`dev/kind/broker/mediatore.yaml`) is the single form, `sandboxes.namespace`, and so is every
  e2e harness. Its two issuers therefore need no list. The live proof is added to the Dex tier
  (below), not forced on the others.

## Alternatives rejected

- **Groups written per issuer** (`groups: { https://dex.example.com: [a], <entra>: [b] }`). The
  finest form, and the one decision 4's limit points at. It changes the shape of every existing
  entry, including the one-issuer case that has nothing to disambiguate. Kept as open question 1,
  additive to this decision, if a deployment needs it.
- **Qualified group names in the map** (`groups: [dex:platform-admins]`, reusing ADR-0073's
  prefixes). One spelling for the token and the map, but it would rewrite every existing map, tie
  the broker's own decisions to a prefix a resource server was given (ADR-0073 decision 4 keeps
  them apart for that reason), and make a prefix rename a policy change.
- **Defaulting a missing `issuers` to every issuer.** It is the finding.
- **Defaulting it to the issuer that was first in the file.** The order of a list is not a
  statement about authorization.
- **Refusing the map under several issuers.** It would take multi-tenancy away from exactly the
  deployments that have the most tenants.
- **Requiring `issuers` even with one issuer.** It would stop every working single-issuer map on
  upgrade for an overlap it cannot have; ADR-0071 rejected the same trade for `sub`.

## What must be proven

Tests are written before the code they hold.

- Unit, `crates/mediatore-api/src/lib.rs`:
  `the_map_form_matches_a_group_only_from_a_listed_issuer`,
  `a_group_of_the_same_name_at_an_unlisted_issuer_does_not_qualify` (create `403`, get and delete
  `404`), `an_entry_listing_two_issuers_reads_its_groups_from_each`,
  `the_refusal_for_an_unlisted_issuer_equals_the_refusal_for_an_unlisted_group`,
  `the_single_form_reads_no_issuer_and_no_group`, and `dev_mode_enforces_the_namespace_groups`
  extended to a dev token of an unlisted issuer. The existing ADR-0046 tests
  (`the_map_form_needs_a_named_listed_namespace_and_a_listed_group`,
  `a_create_logs_subject_namespace_and_decision_and_never_a_token` and the namespace suite) pass
  with their fixtures given an issuer and no other edit.
- Unit, `crates/mediatore/src/config.rs`:
  `one_issuer_needs_no_namespace_issuers_and_may_name_it`,
  `two_issuers_with_a_namespace_entry_without_issuers_refuse_to_start`,
  `a_namespace_entry_with_an_empty_issuers_list_refuses_to_start`,
  `a_namespace_entry_naming_an_unknown_issuer_refuses_to_start`,
  `a_namespace_entry_naming_an_issuer_twice_refuses_to_start`,
  `startup_logs_each_namespaces_groups_with_its_issuers`, and
  `every_issuer_in_the_shipped_examples_and_guides_parses` with the guides' maps updated.
- End to end, `crates/mediatore/tests/e2e_issuers.rs`:
  `the_same_group_name_at_two_issuers_reaches_only_the_listed_issuers_namespace` (two issuers of
  the fake IdP, one group name at each, two namespaces, each listing one issuer: each person is
  `201` in their own namespace and `403` in the other's, over real HTTP).
- Live, **`make kind-e2e-dex`**: the only tier with a real issuer that puts groups in its tokens.
  Its broker configuration is given a map of two namespaces, one listing the Dex issuer and one
  listing the placeholder issuer, both with the group Dex gives `octocat`; the real CLI's create
  is admitted in the first and refused in the second. The other tiers keep the single form and
  prove that it is untouched.
- This is not the TPM attestation path.

## Open questions

1. **Groups per issuer inside one entry,** for a namespace that admits different names from
   different issuers without either name being read from both. Recommendation: not now. Decision
   4 covers the motivating case; the form can be added later beside `groups` without changing
   this one.
2. **Should an entry listing several issuers warn at start?** Recommendation: no warning, the
   start line already names them (decision 5), and listing them is a deliberate act.
3. **Does ADR-0066 need an issuer per group in the bundle?** Recommendation: decide it in
   ADR-0066, with notaio, before that ADR is implemented. Decision 8 is the floor it inherits.
