<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0046: Who may claim: a list of groups, and a mapping from namespaces to groups

**Status:** Accepted 2026-11-17 (the seven open questions were answered by the maintainer the same day; their answers are
folded into decisions 3, 4, 5, 14, 16 and 17 and listed at the end); implemented on `main` (#129)
and released in v0.3.0 (2026-11-17; v0.2.10 predates it) · **Date:** 2026-11-17

Roadmap 08 (the `AgentSandbox` CRD) and roadmap 04 (issuer profiles). Amends
[ADR-0017](0017-issuer-profiles.md) (the issuer's `required_group`),
[ADR-0008](0008-agentsandbox-crd-owned-by-mediatore.md) (the Namespace paragraph: claims are created in
`sandboxes.namespace`, one namespace) and [ADR-0044](0044-a-sandbox-selects-its-pool-by-label.md)
decision 6 (the namespace boundary). Touches the claim request and response
([ADR-0044](0044-a-sandbox-selects-its-pool-by-label.md)), the claim record
([ADR-0034](0034-the-kubernetes-api-as-the-brokers-store.md)) and the namespace the policy is resolved
from ([ADR-0026](0026-notaio-bundles-verified-in-shadow.md) decision 6). Changes no token shape and no
SPIFFE ID. It does change a trust boundary: the broker becomes the place that decides which
namespace a person may place a claim in (TB-1; see
Consequences).

## Context

Two things are wanted, and one real failure shows the first.

**Who may log in cannot be written for two spellings of one group.** Each issuer carries one
`required_group: Option<String>` (`IssuerConfig`, `crates/mediatore-entra/src/lib.rs`). The check
is an exact string comparison of that value against the token's groups: the `groups` claim plus
`roles`, or only `groups_claim` when set (`Validator` near the end of token validation:
`groups.iter().any(|g| g == required)`, else `IdpError::Forbidden("not in required group ...")`).
The spelling of a group is the connector's, not the group's:

- Dex's GitHub connector emits `<org>:<team>`, for example `example-org:APP_EXAMPLE_ADMIN`.
- Dex's LDAP connector, and Entra, emit the bare name, `APP_EXAMPLE_ADMIN`.

The two never compare equal and the broker strips nothing. The failure that motivated this: a
service ID logs in through the LDAP connector (a Dex password grant, no browser), its token carries
`APP_EXAMPLE_ADMIN`, the issuer's `required_group` is `example-org:APP_EXAMPLE_ADMIN` because the people
log in through GitHub, and the service ID is refused with `403` ("not in required group"). It can
never pass: one string cannot admit both spellings, and the operator cannot list the second.

**One namespace for every claim.** Claims are created in one namespace, `sandboxes.namespace` in
`mediatore.yaml` (`SandboxesSection`, `crates/mediatore/src/config.rs`; carried into
`AppState.sandbox_namespace` by `crates/mediatore/src/main.rs`). `create_sandbox`, `owned_sandbox`,
`delete_claim` and the exit handler in `crates/mediatore-api/src/lib.rs` all use that one value.
There is no list route today: the user API is `POST /v1/claims` and `GET`/`DELETE
/v1/claims/{name}`. Everyone who passes the issuer gate may claim in that one namespace; who may
claim *there* is the issuer gate and nothing more. For several teams sharing one broker, the operator
wants a tenant's people to claim in the tenant's namespace and nowhere else, and the operator's own
admins in the controller or infrastructure namespace.

What is already true and this ADR builds on (verified in the source):

- The claim watcher is cluster-wide, and the broker's `ClusterRole` already grants
  `agentsandboxes` (`get`, `list`, `watch`, `patch`, `create`, `delete`) and `virtualmachineclaims`
  across namespaces (`deploy/base/rbac.yaml`).
- A pool (`poolRef` or `poolSelector`, ADR-0044) and the `VirtualMachineClaim` are same-namespace;
  the policy is resolved from the sandbox's namespace, then across `policy.namespaces`
  (ADR-0026 decision 6 as amended 2026-11-05).
- The session and delegation Secrets live in the broker's home namespace; `owner_refs` in
  `crates/mediatore-claims/src/kubestore.rs` returns an owner reference only when the sandbox is in
  that namespace and none otherwise (an owner reference cannot cross a namespace). That path is
  therefore already written for a sandbox elsewhere, and the cleanup it relies on is a test below.
- The caller's groups are already available at the API: `Validated.groups`, read by the same code
  that applies `required_group`.
- The declarative path (`create` on `agentsandboxes` through the Kubernetes API) is governed by
  Kubernetes RBAC and the `mediatore-agentsandbox-subject` admission policy
  (`deploy/base/admission/agentsandbox-subject.yaml`, A-9), not by the broker.

## Decision

1. **`required_groups`: a list on the issuer, any-of, replacing the single string.**
   `required_groups: [<group>, ...]` admits a token that carries *at least one* of the listed
   values (OR). `required_group: <group>` keeps working and means exactly
   `required_groups: [<group>]`: it is an alias, read into the one list at load, so the validator has
   one code path. The rules, each refused at start with a message naming the issuer's `url` and the
   key, never read as a default:
   - both `required_group` and `required_groups` set on one issuer: refused (two spellings of one
     gate, and which one wins is not a thing to guess);
   - `required_groups: []`, or a list with an empty or whitespace-only entry, or an entry with
     leading or trailing whitespace: refused. An empty list is **not** "no gate" and is **not**
     "refuse everyone at runtime": it is a configuration that does not start, the same fail-closed
     reading as `policy:` with no keys (ADR-0026). No gate is spelled `allow_any_authenticated: true` (decision 19);
   - a duplicate value in one list: refused (a copy-paste mistake that looks like two groups).
   The match stays on the existing groups source (`groups` plus `roles`, or `groups_claim`).
   The `403` text no longer names the required values: "not in a required group". Today's message
   echoes the one value; a list would publish every group that admits a person.
   Control: `IssuerConfig` and its validator in `crates/mediatore-entra/src/lib.rs`, the load
   validation in `crates/mediatore/src/config.rs`. Tests: `required_groups_admits_any_one_of_them`,
   `required_groups_refuses_a_token_with_none_of_them`, `required_group_alone_behaves_as_before`,
   `an_issuer_with_both_required_group_keys_refuses_to_start`,
   `an_empty_required_groups_refuses_to_start`.

2. **Exact, case-sensitive match, no prefix stripping, both spellings listed when both are
   wanted.** A listed value must equal a groups-claim element byte for byte. The operator writes
   `required_groups: [example-org:APP_EXAMPLE_ADMIN, APP_EXAMPLE_ADMIN]` to admit the GitHub people and
   the LDAP service ID, and that is the whole mechanism. A normaliser that strips `<org>:` is
   rejected below: it would make `org-a:ADMIN` and `org-b:ADMIN` the same group, and the broker would
   be guessing what a connector meant. One shared function, `groups_intersect(held, wanted)`, in
   `mediatore-entra`, serves the issuer gate and the namespace check (decision 4), so the two cannot
   disagree about what matching is. Tests: `group_matching_is_exact_and_case_sensitive`,
   `a_prefixed_group_does_not_match_the_bare_name`, `a_bare_group_does_not_match_the_prefixed_name`,
   and the motivating case end to end over real HTTP in `crates/mediatore/tests/e2e_issuers.rs`:
   `a_service_id_with_a_bare_group_passes_when_both_spellings_are_listed` (a `201`),
   `the_same_service_id_is_refused_under_the_single_prefixed_required_group` (a `403` whose body names no
   group; the regression it records) and `a_prefixed_group_is_refused_under_a_gate_that_lists_only_the_bare_name`.

3. **`sandboxes.namespaces`: a map from a namespace to the groups whose members may create
   sandboxes there. `sandboxes.namespace` stays, for the single-namespace form; the two are
   exclusive.**

   ```yaml
   sandboxes:
     # `namespace:` is not written here: with the map set it is a start error (below).
     namespaces:                           # new, optional
       infra:
         groups: [example-org:APP_EXAMPLE_ADMIN, APP_EXAMPLE_ADMIN]   # any-of, exact (decisions 1, 2)
       team-a:
         groups: [APP_EXAMPLE_TEAM_A_USER]
   ```

   - **Only the old keys set (no `namespaces`): identical behaviour.** The broker behaves as if
     the map held one entry, `sandboxes.namespace`, open to every caller who passes the issuer gate.
     Nothing about that path changes: the same namespace, the same checks, the same responses. A
     request that carries `namespace` equal to that one value is accepted; any other value is `403`
     (decision 5). The default is still `sandboxes` when the key is absent. Proof:
     `crates/mediatore/src/config.rs` `a_config_without_namespaces_resolves_to_the_single_open_namespace`
     and the whole existing `e2e_dev.rs`, `e2e_sandbox.rs` and `e2e_issuers.rs` suites passing
     unchanged, with `create_sandbox_in_the_default_namespace_is_byte_identical_to_before` pinning
     the `AgentSandbox` a request produces (name aside).
   - **With `namespaces` set, the map is the whole of who may claim where.** A namespace not in the
     map is not claimable through the broker, whatever the caller's groups. `groups` is required on
     each entry and must be non-empty (decision 14); there is no "open" entry in a map. **There is no
     default namespace once the map is set:** `sandboxes.namespace` written together with
     `sandboxes.namespaces` is a start error (decision 14), so an operator never inherits
     `sandboxes` by accident or has two sources for the same answer, and a request that does not say
     which namespace it means is `400 namespace_required` (decision 4), not a guess.
   - **The issuer gate stays, and namespace groups do not imply it.** The issuer's `required_groups`
     answers "may this person log in to this broker at all" (it also guards `/v1/token`'s
     authentication, `me` and the refresh path); the namespace's `groups` answer "may this person
     create a sandbox in *that* namespace". Both must pass to create. The namespace check runs on the
     groups of a token the issuer already accepted, so it can only narrow, never admit. An operator
     who wants the namespace map to be the only gate sets `allow_any_authenticated: true` on the issuer (a valid
     "no gate", decision 19), accepting that anyone the IdP authenticates can then log in and can claim
     nowhere. The ADR does not derive one list from the other: a derived gate would be a second way
     for a mapping edit to change who can log in.
   Control and tests are those of decisions 4 to 6; the config shape is `SandboxesSection`
   (`crates/mediatore/src/config.rs`) with `#[serde(deny_unknown_fields)]` on the entry type, so a
   typo (`group:` for `groups:`) is a start error, never an entry with no groups.

4. **The claim request gains an optional `namespace`; with the map set it is required.**
   `ClaimRequest.namespace: Option<String>` (`crates/mediatore-proto`, skipped when `None`, so
   every existing client sends what it sent). `create_claim` resolves the target. **Without the
   map** (only `sandboxes.namespace`, decision 3) an omitted `namespace` means that one namespace,
   exactly as today. **With the map** an omitted `namespace` is `400 namespace_required`: the broker
   has no default to fall back to, and the message names no namespace (it would otherwise list what
   exists). With a `namespace` given, the broker requires the caller's groups (`Validated.groups`)
   to intersect that namespace's `groups` (decision 2's function). If they do not, the answer is
   `403` (decision 6). There is no "any namespace", no "first namespace the caller qualifies for"
   and no inference from the absence of the field. A caller in several namespaces' groups says
   which, always; the broker never picks one for them. The resolved namespace, not the request's raw value, is what `create_sandbox` writes
   to `sandbox.metadata.namespace` (replacing `st.sandbox_namespace` there). A malformed name (not an
   RFC 1123 label) is `400 invalid_namespace` before any lookup: it depends on the string alone, so
   it says nothing about which namespaces exist. Control: a `resolve_namespace(&NamespaceMap,
   requested: Option<&str>, groups: &[String]) -> Result<&str, Denied>` (as built:
   `Namespaces::resolve_for_create`, returning `NsDenied`) in
   `crates/mediatore-api/src/lib.rs`, called by `create_claim` before the session is parked and
   before anything is written. Tests: `omitting_namespace_without_a_map_targets_the_single_namespace`,
   `omitting_namespace_with_a_map_is_400_namespace_required`,
   `the_400_for_a_missing_namespace_names_no_namespace`,
   `a_caller_in_two_namespaces_must_name_one`, `a_namespace_outside_the_map_is_403_whatever_the_groups`,
   `a_namespace_value_that_is_not_a_dns_label_is_400`, and e2e in `e2e_dev.rs`:
   `a_tenant_claims_in_its_namespace_and_not_in_the_admin_namespace` and the reverse.

5. **A claim is read and deleted by name within a namespace; the caller must be in that
   namespace's groups and own the claim.**
   `GET` and `DELETE /v1/claims/{name}` take a query `?namespace=<ns>`, like the create (a path
   segment would break every client and the route table; a lookup by name alone would need a
   cluster-wide list on every call and would make a name unique across tenants a requirement it is
   not). Without the map an omitted `?namespace` means the single namespace, as today; with the map
   it is `400 namespace_required`, as for the create (decision 4). `owned_sandbox` reads
   `(namespace, name)`, requires the caller's groups to intersect that namespace's `groups`
   (decision 2's function), and keeps the existing subject check (`spec.subject.issuer` and `.id`
   equal to the validated subject), `403 claim belongs to another subject` as today.
   **Group membership gates every operation, not only the create:** a person who has left a
   tenant's group can no longer read or delete the sandbox they created through the broker. The
   maintainer chose this over letting the owner check stand alone: access to a namespace is its
   group's, end to end. The cost is stated in Consequences: the sandbox runs to its TTL unless a
   cluster administrator deletes the `AgentSandbox` (the break-glass path, decision 7). ADR-0045's
   rule is untouched and now stricter in practice: only the claim's subject may read its output, and
   only while in the namespace's groups. A namespace not in the map, and a namespace the caller does
   not qualify for, are both `404 not_found` on `GET` and `DELETE`, the same answer as a listed
   namespace with no such sandbox, so the response does not separate "not configured", "not yours"
   and "not there", and the broker issues no read in a namespace it was not configured with or the
   caller may not use. (The create keeps the `403` of decision 6: it has no object to hide.) The node-bound routes (`POST
   /v1/me/exit`, `/v1/me/report`) take the namespace from the claim's record (decision 9), never from
   the request. Control: `owned_sandbox`, `owned_claim`, `delete_claim` and `exit` in
   `crates/mediatore-api/src/lib.rs`. Tests: `get_and_delete_find_a_claim_in_its_own_namespace`,
   `get_without_namespace_with_a_map_is_400_namespace_required`,
   `another_subject_in_the_same_namespace_is_403`,
   `a_caller_who_left_the_group_can_no_longer_read_or_delete_their_claim` (`404`, and the claim is
   still there afterwards),
   `a_namespace_outside_the_map_is_404_on_get_and_delete`, and a test that `exit` releases a claim in a
   tenant namespace through that claim's namespace.
   A list route does not exist and this ADR adds none. If one is added, it lists only the caller's
   own claims, one namespace per call, with this decision's checks; it needs its own ADR.

6. **The `403` shape, and what it never says.** The refusal is the existing error body, one code,
   `forbidden`, one message: `not permitted to create sandboxes in namespace <ns>`, where `<ns>`
   is the value the caller sent. With the map an omitted namespace is `400 namespace_required`
   (decision 4), so no `403` is issued for it; without the map, an omitted namespace means the single
   namespace and the text names that one. The same status, code and
   text for a namespace that is not in the map and for one the caller does not qualify for, so the
   response is no oracle for which namespaces exist. It never lists the other namespaces, the groups
   a namespace requires, or the groups the caller holds. Control: one `Denied` type (as built,
   `NsDenied`; reads and deletes go through `Namespaces::authorise_existing`), one rendering,
   in `crates/mediatore-api/src/lib.rs`. Tests:
   `the_403_for_an_unlisted_namespace_equals_the_403_for_an_unqualified_one` (status and body byte
   equal) and `the_403_body_contains_no_group_and_no_other_namespace`.

7. **An admin namespace's group does not see or delete other tenants' sandboxes.** Default and
   only rule in this ADR: the owner check (decision 5) is the sole authority over an existing claim.
   Membership of `infra`'s groups gives no read, no delete and no output access in `team-a`, and the
   reverse. An operator who must remove a tenant's sandbox does so as a Kubernetes administrator
   (`kubectl delete agentsandbox`, the finalizer releases it), which Kubernetes RBAC and the audit
   log already govern. A narrow "namespace administrators may delete in their own namespace" rule is
   deliberately not defined here: it adds a second authority over a claim and a second path past the
   subject check, and nothing in the request needs it. Revisit when an operator asks for it (open
   question 3). A member of the admin namespace's groups who is **not** in the tenant's groups gets `404 not_found`
   on that tenant's claim, for `GET` and `DELETE` (decision 5: the namespace is not theirs to use). The
   `403 claim belongs to another subject` applies to a caller who **is** in the namespace's groups but
   is not the claim's subject (an admin who also holds a tenant group is such a caller). Test:
   `an_admin_namespace_member_cannot_get_or_delete_a_tenants_claim` (`404` for the admin outside the
   tenant's groups, `403` for the caller in the tenant's groups who is not the subject, and the claim
   still exists after both).

8. **Pool and policy stay same-namespace; ADR-0044 decision 6 is amended, and exactly this
   moves.** A `poolRef` and a `poolSelector` are resolved in the sandbox's namespace, which is the
   resolved namespace of decision 4: a pool in `team-a` is claimed by a claim in `team-a`, and no
   selector or name reaches another namespace's pool (ADR-0044 decision 6's last sentence stands).
   The `policyRef` is resolved as ADR-0026 decision 6 amended: the sandbox's own namespace first,
   then `policy.namespaces` in order. What changes in ADR-0044 decision 6: the sentence "who may
   claim from a pool is still the namespace RBAC question of ADR-0008 decision 5" described a
   boundary that, for a request through the broker, was the issuer gate alone (the broker's
   `ServiceAccount` creates the resource, so Kubernetes RBAC applied to the broker, not to the
   person). That boundary is now the broker's per-namespace group check (decisions 3 and 4) for
   requests through the broker; the Kubernetes RBAC answer is unchanged for the declarative path
   (decision 11). What does *not* move: where a selector is matched, that a pool is never named
   across namespaces, the `NoPoolMatches` and `PoolNotFound` reasons, and banlieue's ranking.
   **With the map set, an empty `policy.namespaces` is a start error** telling the operator to list
   the policy namespaces: it no longer defaults to the claims' namespace, because there is none
   (decision 3). Without the map the old default (the single `sandboxes.namespace`) stands; test
   `the_policy_namespaces_have_no_default_once_the_map_is_set`.
   `policy.namespaces` is not widened by the map: a tenant namespace whose policies notaio writes
   there must still be listed in `policy.namespaces` with its per-namespace bundle `Role`
   (`deploy/policy-bundles`) as today; with `policy` absent nothing is read. Tests:
   `a_selector_in_team_a_matches_only_team_as_pools` and
   `a_pool_ref_naming_another_namespaces_pool_is_carried_as_a_plain_name_in_the_resolved_namespace_only`
   (`crates/mediatore-api/src/lib.rs`), and the existing ADR-0026 tests unchanged. The broker has no pool
   lookup of its own: banlieue matches a selector, and answers `PoolNotFound` for a name, in the
   sandbox's namespace. So the tests pin what the broker controls: the `AgentSandbox` it writes lands
   in the one resolved namespace and nowhere else, carrying `poolSelector` or `poolRef` exactly as
   sent (a name such as `team-b/pool` stays a plain name, never split or resolved), and `claim_for`
   copies the sandbox's namespace and pool fields to the claim
   (`the_claim_is_owned_labelled_and_copies_the_spec`, `crates/mediatore-claims/src/sandbox.rs`). The
   `PoolNotFound` itself is banlieue's and is not asserted here.

9. **The record carries its namespace.** `ClaimRecord` (`crates/mediatore-store`) gains
   `namespace: String`, `#[serde(default = ...)]` to the broker's `sandboxes.namespace` (the single
   namespace) for a record written before (as built, the default is the constant
   `FALLBACK_NAMESPACE`, `"sandboxes"`, `crates/mediatore-store/src/lib.rs`); **an operator who
   moves to the map lists that namespace in it**, or those records answer `404` (no default exists
   once the map is set, decision 3). Put
   plainly: a claim created before the move to the map is unreachable (`404`) unless the operator
   lists its old namespace in the map
   (ADR-0034: the record is rebuilt from the `AgentSandbox` resource and its status, so the
   truth is the resource's `metadata.namespace`; the field is its copy for the paths that hold a
   record and not a resource: `exit`, `report`, `get_claim_by_name` in `dev_mode`). `ClaimResponse`
   gains `namespace`, always present (an `Option<String>` on the wire, `crates/mediatore-proto`,
   so an older broker's answer still parses; a current broker always sets it). The store trait is
   otherwise unchanged and `ClaimRecord` stays a Rust-side contract, not a CRD schema change: no
   `AgentSandbox` spec or status field is added and
   banlieue is untouched. `get_claim_by_name` becomes `get_claim_by_name(namespace, name)` for the
   dev store, so a name in one namespace cannot return another's record. The session and delegation
   Secrets stay in the broker's home namespace, keyed by the sandbox UID as now; for a sandbox in
   another namespace they carry no owner reference (`owner_refs`), so their removal on release is the
   explicit path and the sweep, not Kubernetes garbage collection. Tests:
   `an_old_claim_record_reads_as_the_fallback_namespace`, `a_name_in_one_namespace_is_not_found_in_another`
   (the store conformance suite),
   `releasing_a_claim_in_a_tenant_namespace_deletes_its_session_and_delegation_secrets` (the
   `kubestore` fake), `a_claim_response_carries_its_namespace` (`crates/mediatore-proto`).

10. **RBAC: the `ClusterRole` stays; a new tenant namespace needs no new grant for the
    broker.** The grants the code needs are already cluster-wide (`deploy/base/rbac.yaml`) because
    the watcher and the reconciler are, so per-namespace `Role`s for `agentsandboxes` would not
    narrow what the broker can do: the controller still watches every namespace. The least privilege
    that applies is in the code: the user API reads and writes sandboxes only in namespaces named in
    `sandboxes.namespaces` (or the one default), enforced by decisions 4 and 5. A new tenant namespace
    needs: the namespace itself, the tenant's `VirtualMachinePool` (banlieue), an entry in
    `sandboxes.namespaces`, and, only if notaio writes that tenant's policies there, an entry in
    `policy.namespaces` with the `deploy/policy-bundles` `Role` and `RoleBinding` copy for that
    namespace. If policies stay in the one policy namespace, nothing. The admission policy
    `mediatore-agentsandbox-subject` matches the resource in every namespace already
    (`deploy/base/admission/agentsandbox-subject.yaml`), so it needs no change. Test:
    `the_brokers_cluster_role_is_pinned` (`crates/mediatore-claims/src/sandbox.rs`, beside the other
    `deploy/base` checks) parses `deploy/base/rbac.yaml` and asserts the `ClusterRole`'s rules equal a
    literal, so a change to it is a visible diff that needs the ADR and the threat-model pass. It reads
    the base file, not a `kustomize build` of an overlay. The live create in a second namespace is
    `make kind-e2e-sandbox`, run by hand on the build host before release (Follow-on).

11. **The declarative requester is unchanged.** A requester with `create` on `agentsandboxes`
    in a namespace is governed by Kubernetes RBAC and the admission policy (`spec.subject.id` must
    equal the requesting username, except the broker and the A-9 `brokers` lists). The broker's
    namespace map does not apply to it, by design: the map is a control on the broker's front door,
    and a person with `create agentsandboxes` in `team-a` holds a Kubernetes grant the operator gave
    them directly. It is recorded here so nobody reads the map as a statement about the cluster's
    RBAC. No test is added: the existing `make kind-e2e-sandbox` cases (admin, impersonated stranger,
    listed broker, `ServiceAccount`) are the proof and must stay green.

12. **`dev_mode`.** The map and the checks apply in `dev_mode` the same way: the dev token's
    groups (the testkit's fake IdP issues them) are checked against the namespace's groups, so a dev
    run does not skip the control it exists to exercise (`.claude/rules/testing.md`: a fake more permissive
    than the real thing hides bugs). The dev store has no resources and records the namespace on the
    record (decision 9). Nothing reads a namespace, a group or an identity from a header; the
    existing gate on the header-driven peer identity (`dev_mode` only) is untouched and no new
    header is introduced. Tests: `dev_mode_enforces_the_namespace_groups` and
    `no_header_can_select_a_namespace_or_supply_groups`.

13. **Audit.** Every create logs one `info` line: subject, issuer, requested namespace (`omitted`
    when none), resolved namespace, decision (`allowed` or `denied`), and for an allow the *listed*
    group the caller matched (a configuration value, not a claim of the caller's). A denial logs
    the subject, the namespace and `denied`; it does not log the caller's group list. Reads and
    deletes keep their lines and gain the namespace. Never a token, a refresh token or a header. Tests:
    `a_create_logs_subject_namespace_and_decision_and_never_a_token` (the two merged into one, the existing
    tracing capture helper).

14. **Validation at start, and the log of what was resolved.** Refused at start, message naming the
    key and the value: `sandboxes.namespaces` present and empty; a key that is not an RFC 1123 label
    (`is_dns_label`, in `crates/mediatore-proto`); a duplicate key (the YAML parse is checked, a duplicate map key
    must not silently take the last); an entry with no `groups` key, an empty `groups`, an empty or
    whitespace-padded group, or a duplicate group inside one entry (the same group in two
    namespaces is allowed: it is how one person belongs to several, and is why decision 4 requires
    them to name one); `sandboxes.namespace` written together with `sandboxes.namespaces` (the two
    are exclusive, decision 3); an unknown field in an entry. The
    broker cannot check at start that a namespace exists (it holds no `get namespaces`); a map entry
    whose namespace does not exist fails the create with the API server's error, answered as the
    catch-all `500 internal` (`front_door_error` sends a `404` to `FrontDoorError::Api`; no `502` exists
    in the user API, and the earlier text of this decision said `502` in error), nothing is parked
    (the sandbox has no UID for a session to be sealed under), and the startup log says so. At start the broker logs, at
    `info`, two lines of different kinds. One is the gate and namespace-mode line of decision 18
    (per issuer: the gate form; and `single open namespace <ns>` or `map of <n> namespaces`). The
    other is the per-namespace group values of this decision: each namespace name and its group
    values (the maintainer chose values over counts), and each issuer's gate with its group values:
    names from configuration, never a token. Tests:
    `a_namespaces_map_with_an_empty_groups_list_refuses_to_start`, `..._with_a_duplicate_key_...`,
    `..._with_a_non_dns_label_key_...`, `..._together_with_sandboxes_namespace_...`,
    `..._with_a_typo_in_an_entry_field_...`, `a_group_in_two_namespaces_is_accepted`,
    `startup_logs_the_namespace_names_and_no_token`,
    `a_listed_namespace_that_does_not_exist_fails_the_create_and_parks_nothing`
    (`crates/mediatore-api/src/lib.rs`) and `a_404_from_the_api_server_is_the_catch_all_error`
    (`crates/mediatore-claims/src/sandbox.rs`).

15. **Fail closed.** A path the build cannot honour answers `501 not_implemented`, as today: a
    namespace map on a broker with no Kubernetes front (`st.sandboxes` is `None`, outside
    `dev_mode`) is refused at start, and a create that reaches `create_sandbox` without the front
    returns `501 claim creation via the kubernetes api`. A `namespace` sent to a broker built
    before this ADR is dropped by it silently and the claim lands in the default namespace; the
    client therefore compares the response's `namespace` with the one it asked for and treats a
    difference as an error (decision 16). Test: `a_namespace_map_without_the_kubernetes_front_refuses_to_start`
    and `create_without_the_front_is_501_with_a_namespace_set`.

16. **The CLI.** `mediatore sandbox create --namespace <ns>` sends `namespace`; omitted, it sends
    nothing and, against a broker with the map, prints the broker's `400 namespace_required`
    message as the error; against a single-namespace broker it says on stderr, one line, which
    namespace the broker used (the response's `namespace`), in the way ADR-0044 decision 3 says the
    pool default. `sandbox get`, `sandbox delete` and `sandbox logs` (ADR-0045; pending, with that
    ADR, since the command does not exist yet) take `--namespace`
    and send it as `?namespace=`; omitted, nothing is sent (the broker's answer decides, decision 5).
    If a response's `namespace` differs from the flag the user gave, the CLI prints an error naming
    both and exits non-zero (an old broker ignored the field), without deleting anything on its
    own. **`sandbox delete --namespace` does a `GET` first**, runs the namespace check on the
    response, and sends the `DELETE` only if it passes: an old broker ignores `?namespace=` and would
    otherwise delete in its default namespace, and a delete cannot be undone by the check that
    follows it. `sandbox get --namespace` runs the same check on its answer. The CLI holds no list of namespaces and does not remember one. Tests in
    `crates/mediatore-client/src/cli.rs`: `namespace_flag_is_sent_in_the_request_and_the_query`,
    `a_response_namespace_that_differs_from_the_flag_is_an_error`, `without_the_flag_the_request_has_no_namespace`,
    the delete tests `delete_with_a_namespace_gets_first_and_deletes_when_it_matches`,
    `delete_with_a_namespace_does_not_delete_when_the_get_reports_a_different_namespace`,
    `delete_with_a_namespace_does_not_delete_when_the_get_reports_none`,
    `delete_with_a_namespace_sends_no_delete_when_the_get_is_404`,
    `delete_without_a_namespace_sends_no_get`, and the get tests
    `get_with_a_namespace_that_differs_from_the_response_is_an_error`,
    `get_with_a_namespace_and_a_response_without_one_is_an_error`,
    `get_without_a_namespace_does_not_check`.

17. **The issuer and sandboxes blocks reject unknown keys.** Today only `AudienceConfig`
    carries `#[serde(deny_unknown_fields)]` (`crates/mediatore/src/config.rs`, added by
    [ADR-0040](0040-the-gateway-places-an-audiences-credential-the-pool-never-holds-it.md) for the
    same reason: a misspelled `inject` must not fall back to the default silently). `IssuerConfig`
    (`crates/mediatore-entra/src/lib.rs`) and `SandboxesSection` do not, so a binary that predates
    this ADR, given `required_groups` or `sandboxes.namespaces`, ignores the key, and an issuer
    with no `required_group` gates nothing: fail-open on a trust boundary. The precedent is applied
    here: `#[serde(deny_unknown_fields)]` on `IssuerConfig`, `SessionConfig`, `EntraConfig`,
    `SandboxesSection` and the namespace entry (decision 3), so a build that has the deny refuses to
    start on a key it does not know, and so does a new build on a typo. This is itself a behaviour
    change: **a config that today carries a stray or misspelled key in those blocks stops
    starting** with an error naming the key and the block. That is the intent (such a key is today
    a silent no-op that may have been meant as a gate), and the release notes say so. Neither type
    uses `flatten`, so the attribute applies. **The top-level `Config` is covered too** (the
    maintainer chose to do it in this change): `#[serde(deny_unknown_fields)]` on `Config` and on
    every section struct that does not carry it (`listen`, `policy`, `store`, and the rest of the
    file), so a misspelled `sandboxes` is no longer silently the default. The same behaviour-change
    note applies to the whole file. Tests: `an_issuer_with_an_unknown_key_refuses_to_start`,
    `a_misspelled_required_groups_refuses_to_start`, `sandboxes_with_an_unknown_key_refuses_to_start`,
    `an_entra_or_session_block_with_an_unknown_key_refuses_to_start`,
    `a_top_level_unknown_key_refuses_to_start` and `a_misspelled_sandboxes_section_refuses_to_start`, and
    `every_issuer_in_the_shipped_examples_and_guides_parses` (the YAML in `docs/guides` and
    `deploy` is parsed, so the change cannot strand a documented config).

18. **Rollout order: the broker first, then the config; and a startup line states the gate in
    force.** An operator deploys the broker build that has the new parser, confirms it started, and
    only then adds `required_groups`, `sandboxes.namespaces` or `--namespace` use. The reverse
    (new config, old broker) is the fail-open case: builds that carry decision 17's deny refuse the
    unknown key, but the builds before it cannot, so the release notes and the guide
    (`docs/guides`) state the order and that the release carrying this ADR (v0.3.0) is the floor. A
    rollback to an older build removes the new keys first. At start the broker logs, per issuer,
    one `info` line naming the issuer `url` and the gate form in force: `required_groups` (with the
    count), `required_group` (the alias, count 1) or `none (explicit)` (decision 19); and for the
    namespaces, `single open namespace <ns>` or `map of <n> namespaces`. Nothing is inferred from
    the absence of a key, and the line is how an operator sees a gate that is not the one they
    meant. Tests: `startup_logs_the_gate_form_per_issuer`,
    `startup_logs_single_open_namespace_without_a_map`.

19. **No gate must be written down: an issuer with neither key refuses to start unless it says
    `allow_any_authenticated: true`.** Today the absence of `required_group` is a silent "no
    gate". That default is what makes an unknown key or a typo fail open: the broker cannot tell an
    operator who meant "no gate" from one who meant a gate and lost it. Chosen: an issuer carries
    exactly one of `required_group`, `required_groups`, or `allow_any_authenticated: true` (a
    boolean, default false; `false` counts as absent). Zero of them, or more than one, is a start
    error whose message names the issuer and the three keys. The marker means exactly today's
    no-gate behaviour and shows in the decision 18 log line as `none (explicit)`. Effect on
    existing configs: every config whose issuer has no group gate (the Google case of
    `docs/guides/issuers.md`, "Leave `required_group` unset", and the e2e fixtures that set
    `required_group: None`) stops starting until the operator adds `allow_any_authenticated:
    true`, a one-line edit the error message spells out; the guide's Google section is rewritten
    to say so, and its reason (who may log in is decided at Google) becomes the comment beside the
    key. A config that already sets `required_group` is unchanged. Decisions 1 and 3 do not themselves make
    "write neither key" mean "no gate"; the reading this decision replaces is the one the code and
    the guides had before this ADR (an issuer with no `required_group` gates nothing), which
    decision 1's alias (`required_group` means a list of one) leaves in place. Wherever a guide
    or older text says "leave the key unset for no gate", read `allow_any_authenticated: true`. Tests: `an_issuer_with_no_gate_key_refuses_to_start`,
    `an_issuer_with_allow_any_authenticated_admits_a_token_with_no_groups`,
    `allow_any_authenticated_with_required_groups_refuses_to_start`,
    `allow_any_authenticated_false_is_not_a_gate`, and in `config.rs`
    `a_google_issuer_needs_the_explicit_marker`.

## Consequences

- **The trust boundary, honestly.** Until now the broker had one namespace and one gate, and
  tenant separation, if any, was Kubernetes' (RBAC on the declarative path). After this ADR the
  broker is the enforcement point for multi-tenant claim placement on its own front door: it decides
  from a token's groups which namespace a claim is created in, with its own `ServiceAccount` that can
  create in all of them. **A mistake in the mapping grants cross-tenant claims**: a group listed
  under the wrong namespace, a group spelling that matches a broader population than intended, or
  an operator listing `example-org:APP_EXAMPLE_ADMIN` and the bare `APP_EXAMPLE_ADMIN` where the bare name
  is held by people the operator did not mean. Exact match and no normalisation (decision 2) keep
  the failure on the side of "listed explicitly", and the start-time validation (decision 14) turns
  the typos into start errors, but the mapping is a security configuration and is reviewed as one.
- **What a mapping mistake can and cannot do.** It can place a sandbox in a namespace the person
  should not use, consuming that tenant's pool and running under that tenant's policy
  (ADR-0026). It cannot read or delete another tenant's sandboxes (decisions 5 and 7), cannot reach
  another namespace's pool (decision 8) and cannot change what a token is minted for: audiences and
  the sandbox's policy are the same checks as before. A claim in the wrong namespace is visible in
  the audit line (decision 13) and the `AgentSandbox`'s namespace.
- **Compatible for every existing deployment.** No `namespaces` key means one open namespace as
  today (decision 3, proven by the unchanged suites); `required_group` means `required_groups` of one
  (decision 1); without the map a request without `namespace` and a `GET` without `?namespace=`
  mean the one namespace; an old record reads as that namespace (decision 9). The visible
  differences for an existing operator are the `403` text on an issuer gate, which no longer prints
  the group, and the two start-time refusals the maintainer chose: an unknown key anywhere in the
  file (decision 17) and an issuer with no written gate (decision 19). **Those two are not
  backward compatible by design**; the release notes and the guide say so.
- **Spelling is now the operator's to write.** The cost of rejecting a normaliser is that an
  operator with GitHub and LDAP people lists both spellings, in the issuer's list and in each
  namespace that both populations use. That is the intended trade: two lines of configuration the
  operator can read in review, rather than a rule inside the broker nobody sees.
- **A group removed from a namespace ends the person's access to that namespace, running sandboxes
  included.** A sandbox already created keeps running to its TTL, but its former owner can no longer
  read its output or delete it through the broker (decision 5, the maintainer's choice). Stopping
  it early is a cluster administrator's `kubectl delete` of the `AgentSandbox` (the broker's
  finalizer then releases the claim and the entry). Revoking a person at the IdP or in the map is
  therefore followed by deleting what they created, if that is wanted.
- **Cross-namespace Secrets lack an owner reference.** For a sandbox outside the broker's home
  namespace, the delegated-session Secrets are removed by release and the sweep, not by Kubernetes
  garbage collection (`owner_refs`). The test in decision 9 is what makes that safe; a Secret that
  outlived its sandbox is sealed under the sandbox's UID and bounded by its envelope expiry
  (ADR-0013, ADR-0035), as R-33 already accepts for a deleted envelope.
- **Not changed:** every token's shape, the SPIFFE ID scheme (the claim's identity is its UID,
  not its namespace), the sandbox API on the node mTLS listener, the admission policy, the CRD, the
  store's Kubernetes objects and banlieue.
- **Threat model.** TB-1 gains rows (a namespace the caller does not qualify for; an unlisted
  namespace indistinguishable from an unqualified one; a caller in several namespaces; a mapping
  mistake) and one reworded row (the issuer gate and the namespace gate are two checks); TB-2
  gains a note that the declarative path is not governed by the map; A-9 is read and its text is
  expected to stand (the `brokers` lists are untouched), with a sentence that the map is not an
  A-9 list; a new asset (the namespace map, in `mediatore.yaml`) and a residual-risk entry for
  the mapping being a security configuration reviewed by hand, with a *Revisit when* of "a
  second broker deployment shares the map" or "the map is generated from the IdP".

## Rejected alternatives

- **A prefix-stripping normaliser** (strip `<org>:` before matching). It fixes the one case and
  breaks the exact one: groups from two organisations with the same team name become the same
  group, and the broker guesses what the connector meant. It also changes what a groups-claim
  match means for every existing issuer. Listing both spellings (decision 2) costs one line.
- **One issuer entry per spelling.** Issuers are matched by `iss` (`url`), so two entries for one
  Dex differ in nothing the token carries; the validator would have to try both, and the
  per-issuer session and `subject_claim` settings would be written twice and drift.
- **Regex or glob group matching.** A pattern grants every group it happens to match, now and later;
  an IdP team created next year can match `*:ADMIN`. The match is an allowlist of names, never a
  pattern.
- **Per-namespace broker deployments.** One broker per tenant gives the strongest separation and
  costs a SPIRE-registered identity, a signing key, a store and an upgrade per tenant. It remains the
  answer for a tenant that needs isolation the map cannot give (decision 7's Kubernetes
  administrators share a broker); it is not the default for several teams.
- **Deriving the namespace from a group-name convention** (the namespace is whatever follows
  `TEAM_` in the group). The mapping then lives in the IdP's naming, where anyone who can create a
  group can mint access to a namespace, and an unreviewed rename moves a tenant. The map is
  config in this repository's deployment, reviewed where the broker's other configuration is.
- **Group membership implying the issuer gate.** One list would then drive two decisions, and an
  edit to a namespace's groups would change who can log in (decision 3).
- **Inferring the namespace when the caller qualifies for exactly one.** It makes the same request
  mean different things as a person's groups change, and a person added to a second namespace would
  find their old command now refused. Absent means the default, always.
- **The namespace in the URL path.** It would change every existing route and client for a lookup
  the query parameter does with no break.

## Resolved questions

Answered by the maintainer on 2026-11-17 and folded into the decisions above.

1. **A map with no default namespace:** no default. With the map set, an omitted `namespace` is
   `400 namespace_required`, and `sandboxes.namespace` together with the map is a start error
   (decisions 3 and 4).
2. **An admin namespace's group is not a super-user** (decision 7, unchanged).
3. **A person who left the group loses access to what they created through the broker:** group
   membership gates read and delete as well as create (decision 5, changed from the draft).
4. **Group values are logged at start** (decision 14).
5. **Tenant policies stay in one global policy namespace,** for simplicity and compatibility:
   `policy.namespaces` is not widened by the map and no per-tenant bundle Role is added
   (decision 8).
6. **Top-level unknown keys are rejected in this change** (decision 17).
7. **Decision 19 refuses at start immediately,** with no warn-only release.

## Follow-on work

- [x] CALM: `docs/architecture/calm/architecture.json` (the namespace map as configuration on the
  broker, the TB-1 decision point, no new node); `make calm-validate` and `make calm-diagrams`.
- [x] Tests, first and failing, by name: decisions 1 and 2 (`required_groups_admits_any_one_of_them`,
  `required_groups_refuses_a_token_with_none_of_them`, `required_group_alone_behaves_as_before`,
  `an_issuer_with_both_required_group_keys_refuses_to_start`, `an_empty_required_groups_refuses_to_start`,
  `group_matching_is_exact_and_case_sensitive`, `a_prefixed_group_does_not_match_the_bare_name`,
  `a_bare_group_does_not_match_the_prefixed_name`,
  `a_service_id_with_a_bare_group_passes_when_both_spellings_are_listed`, and its e2e twin and the two
  refusals in `e2e_issuers.rs`); decision 3
  (`a_config_without_namespaces_resolves_to_the_single_open_namespace`,
  `create_sandbox_in_the_default_namespace_is_byte_identical_to_before`); decisions 4 and 5 (the
  namespace resolution, get and delete, and owner tests listed there); decision 6 (the two `403`
  tests); decision 7; decision 8 (the two tests above); decision 9; decision 10 (`the_brokers_cluster_role_is_pinned`);
  decisions 12 to 16 (decision 14's `500` for a missing namespace included).
- [x] Implementation: `mediatore-entra` (`required_groups`, `groups_intersect`), `mediatore-proto`
  (`ClaimRequest.namespace`, `ClaimResponse.namespace`), `mediatore-store` (`ClaimRecord.namespace`),
  `mediatore-api` (`resolve_namespace`, namespace-aware `owned_sandbox`, `delete_claim`, `exit`),
  `mediatore` (`SandboxesSection`, validation, startup log), `mediatore-client` (`--namespace`),
  `mediatore-claims` (the Secrets' cleanup in another namespace).
- [x] Docs: `README.md` status table, `docs/guides` (the config reference and a multi-tenant
  example with placeholder groups), the ADR-0008 Namespace paragraph and ADR-0044 decision 6 gain a
  pointer to this ADR, ADR-0017's `required_group` text gains one.
- [x] Threat-model full pass (`rules/threat-modeling.md`): every section, TB-1 and TB-2 rows as above,
  A-9 re-read, the namespace map as an asset, the residual-risk entry with its *Revisit when*, the
  Mermaid diagram checked, the header stamp bumped (date and ADR range to ADR-0046).
- [ ] (open, manual, build host) `make kind-e2e-sandbox` with a second namespace, run by hand before release
  (`.claude/rules/testing.md`; a cluster is needed and the tier is not in CI): `make kind-delete && make kind-e2e-ci KIND_E2E_SUITES=kind-e2e-sandbox`
  (plus the provider and CLI variables the host needs). Not run for this change.
- [x] `make check` overall: `cargo fmt`, `clippy` and `cargo test` pass; `cargo deny` advisories failed on
  RUSTSEC-2026-0543 (`chrono`), which failed on `main` too and was not caused by this change
  (cleared 2026-11-17 by #131, chrono replaced with jiff across the workspace).
- [x] Infrastructure sweep of the diff (`rules/no-real-infrastructure.md`): placeholders only in the
  docs, tests and examples (`example-org:APP_EXAMPLE_ADMIN`, `APP_EXAMPLE_TEAM_A_USER`, `team-a`).
