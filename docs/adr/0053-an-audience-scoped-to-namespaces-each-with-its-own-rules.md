<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0053: An audience scoped to namespaces, each with its own rules

**Status:** Phase 1 (decisions 1 to 8) accepted and implemented 2026-11-19; **phase 2 (decisions 9 to 16, the verified policy bundle as the source of the grants) accepted and implemented 2026-11-19, behind `policy.audiences: shadow` by default; not yet run live** (the two open questions of phase 2 were left at their defaults: eligibility is the policy's location only, and a claim names its own policy) (the three open questions were left at their defaults by the maintainer: namespace names, an unscoped audience stays open with a warning, the key is `namespaces`; amended at implementation: decision 3's top-level `rules` is a ceiling, not a refusal, and decisions 4 to 6 name what was built) · **Date:** 2026-11-19

Amends [ADR-0040](0040-the-gateway-places-an-audiences-credential-the-pool-never-holds-it.md)
(the audience's `rules` and the routes the gateway holds),
[ADR-0025](0025-phantom-token-egress-proxy.md) decision 4 (the proxy's rules) and
[ADR-0046](0046-who-may-claim-a-list-of-groups-and-a-namespace-to-groups-mapping.md) (which
namespace a claim lives in). Builds on [ADR-0026](0026-notaio-bundles-verified-in-shadow.md),
whose enforcing step is the end state this ADR does not replace. Changes no token shape, no
SPIFFE ID and no storage contract. It does change what the gateway and the proxy admit for a
claim, so the threat-model pass is part of done.

## Context

`audiences[]` in `mediatore.yaml` is one flat list for the whole broker. An audience carries a
host (`egress`), a credential kind, a lifetime and `rules`, the method and path pairs the proxy
and the gateway admit. Nothing in it names a namespace.

The consequence, found while writing the Artifactory audience for one application:

```yaml
- name: artifactory
  via: delegated
  credential: basic
  inject: gateway
  max_ttl: 300
  egress: ["artifactory.example.com:443"]
  rules:
    - {method: GET,  path: "/artifactory/api/docker/app-team-a-docker/v2/**"}
    - {method: HEAD, path: "/artifactory/api/docker/app-team-a-docker/v2/**"}
```

These rules are specific to one team's repository, yet any claim from any namespace can name
`artifactory` and get them (and, with the person's own credential placed at the gateway, can read that
repository as the person). The only checks are that the audience exists
(`create_claim`, `crates/mediatore-api/src/lib.rs`, and `refusal` in
`crates/mediatore-claims/src/sandbox.rs` for a declarative `AgentSandbox`) and that the caller may
claim in the namespace (ADR-0046). N applications means N repositories and N rule sets, and
today the only way to write them is N audiences that every namespace can still name.

What already exists and this ADR uses (verified in the source):

- The claim record carries its namespace (`ClaimRecord.namespace`, set from the resolved
  namespace of ADR-0046 decision 4). It is the broker's own value, never read from a later request.
- Three places turn an audience's `rules` into enforcement, each from a per-audience map built once
  in `crates/mediatore/src/main.rs`: the proxy's routes in `GET /v1/me`
  (`st.rules`, `crates/mediatore-api/src/lib.rs`), the gateway's inject routes
  (`st.inject`, from `AudienceConfig::inject_routes`), and the shadow comparison with the policy
  bundle (`Audience.rules` in `crates/mediatore-claims/src/shadow.rs`).
- `inject: gateway` already refuses an audience with no `rules` at start (ADR-0040 decision 1), because
  an empty list means "every method and path".
- The notaio policy bundle is per policy and per namespace, but in shadow it refuses nothing
  (ADR-0026), so `P001` to `P004` report a looseness and the broker's configuration is still the
  only control.

## Decision

1. **An audience may carry `namespaces`: a map from a namespace to the rules that apply there.**

   ```yaml
   - name: artifactory
     via: delegated
     credential: basic
     inject: gateway
     max_ttl: 300
     egress: ["artifactory.example.com:443"]
     namespaces:
       team-a:
         rules:
           - {method: GET,  path: "/artifactory/api/docker/app-team-a-docker/v2/**"}
           - {method: HEAD, path: "/artifactory/api/docker/app-team-a-docker/v2/**"}
       team-b:
         rules:
           - {method: GET,  path: "/artifactory/api/docker/app-team-b-docker/v2/**"}
           - {method: HEAD, path: "/artifactory/api/docker/app-team-b-docker/v2/**"}
   ```

   Everything else (`via`, `credential`, `inject`, `egress`, `max_ttl`, `ca_file`, headers) is the
   audience's and is written once. Only the rules differ by namespace. A repeated rule set is shared
   with a YAML anchor; the broker adds no inheritance. The entry type is
   `#[serde(deny_unknown_fields)]`, so `rule:` for `rules:` is a start error, never an entry with no
   rules.

2. **Without `namespaces`, nothing changes.** An audience with no `namespaces` key keeps today's
   meaning: usable from every namespace, with its top-level `rules`. The existing suites pass
   unchanged. This is a compatibility choice, not a safe default: a scoped audience is the way to
   lock one, and an operator who wants every audience scoped checks the config with the lint of
   decision 6.

3. **With `namespaces`, the map is the whole of where the audience is usable, and the audience's top-level
   `rules` is the platform's ceiling over every grant.** A namespace not in the map cannot claim the
   audience, whatever the caller's groups. There is no wildcard namespace and no default entry; a
   namespace is listed or it is not. Each namespace's `rules` is a **grant**, and the audience's
   top-level `rules`, when written, is the **ceiling**: a grant rule that no ceiling rule covers
   (`rule_covers` in `crates/mediatore-claims/src/shadow.rs`, the sound-not-complete glob test
   ADR-0026's `P004` already uses, so a covering it cannot prove is refused) is a start error naming
   the audience and the namespace. The effective rules of a claim are its namespace's grant. This is
   the defence in depth: the platform sets the outer bound once per audience, a namespace's grant sits
   inside it, and a mistaken or hostile grant cannot widen a path past the ceiling. With **no**
   top-level `rules` there is no ceiling and a grant is bounded only by itself (R-41), as an empty
   `rules` has always meant every path. (The first draft refused a top-level `rules` together with
   `namespaces`; that threw away the ceiling and is withdrawn.) Each grant must be non-empty: an empty list is
   not "no rules" and is not "refuse": it is a configuration that does not start, because under the proxy an empty list
   admits everything (the reading ADR-0040 already refuses for a placed audience). A grant that wants every
   path says so: `{method: "*", path: "/**"}`, and needs a ceiling that covers it or none.

4. **The check runs where the audience is named, and at every use after.**
   - **At the claim:** `create_claim` and the reconciler's `refusal` (the declarative path) resolve
     each requested audience against the claim's namespace. An audience that is scoped and does not
     list the namespace is answered **exactly as an audience that does not exist**:
     `400 unknown_audience` with the caller's own value echoed (the API), and
     `audience <name> is not configured` (the reconciler). The response does not separate "not
     configured" from "not yours", so it does not tell a caller which audiences exist elsewhere. The
     namespace check of ADR-0046 comes first: a caller outside the namespace's groups is refused there.
   - **At a token mint and at the gateway's answer:** `POST /v1/token` and
     `GET /v1/gateway/claims/{uid}` take the namespace from the claim record and drop an audience the
     record's namespace no longer lists. The configuration is read at start, so this takes effect
     when the broker restarts with the entry removed: a bound claim loses the audience at its next
     mint or its next gateway ask, and keeps nothing it was given. That is the fail-closed direction.
   Control, as built: `AudienceConfig::scoped_rules()` (`crates/mediatore/src/config.rs`) is the one place
   the grants are read from; `main.rs` hands the map to the API (`AppState.scopes`) and to the watcher
   (`WatcherConfig.scopes`). In the API every mint, route and allowlist reads `claim_audiences`, which
   drops an audience the claim record's namespace does not list, and `AppState::rules_in` gives the
   rules; in the watcher `scope_allows` and `audiences_in`. Nothing reads an audience's top-level `rules`
   for a scoped audience's claim.

5. **A scoped audience's routes carry its namespace's grant.** `AppState.scopes` and
   `WatcherConfig.scopes` hold the grants per audience and namespace; `st.rules` and `st.inject` keep
   their one key per audience and, for a scoped one, hold the ceiling, which a claim's routes replace with
   its namespace's grant (`inject_of`, `rules_in`). The proxy's routes (`GET /v1/me`), the gateway's inject routes
   and the `egress_of` allowlist are computed from the claim's `rec.namespace`. The gateway's
   authorizer is unchanged: it is handed the routes the claim may use and enforces them as before
   (ADR-0040 decision 2), so it needs no namespace of its own.

6. **What the broker refuses to start on**, each message naming the audience and the key:
   - `namespaces` written together with a top-level non-empty `rules`;
   - `namespaces: {}` (an empty map), or an entry with empty `rules`, or a rule that fails the
     existing rule checks (method, absolute path glob);
   - a key that is not an RFC 1123 label;
   - with `sandboxes.namespaces` set (ADR-0046), a key that is not one of its namespaces: an audience
     scoped to a namespace nobody can claim in is a typo, not a policy. With the single-namespace form,
     the key must equal `sandboxes.namespace`;
   - two audiences whose `egress` share an authority, unless both are scoped to **disjoint**
     namespaces and neither is `inject: gateway`: a claim would then have two audiences for one
     endpoint, and "one audience per endpoint" is what the proxy's routing relies on (ADR-0025,
     `crates/mediatore-api/src/lib.rs` where the routes are built). Two gateway-placed audiences never
     share a host even in disjoint namespaces, because the registry-by-host map of ADR-0043 names one
     audience per host. Disjoint scoped audiences are a way to give two teams different credential
     kinds against one host.

7. **A warning, not a refusal, for an unscoped audience.** The start log lists, once, each audience with
   no `namespaces` while `sandboxes.namespaces` is set: `audience unscoped: usable from every namespace`
   (`Config::log_startup`). The line names the audience only, never a rule or a host.

8. **The policy bundle is not replaced, and the grants move to it in phase 2.** `P001` to `P004` compare the bundle with the **effective**
   rules of the claim's namespace (`WatcherConfig::audiences_in`), so a scoped audience is judged on what the claim
   can actually do. Phase 1 is the file form: the grants are read at start, so a new team is a configuration change and a
   restart. Decisions 9 to 16 make the verified `SandboxPolicy` bundle of the claim's policy the source of the
   grants, which is what the maintainer asked for: the platform writes a policy per tenant namespace, the tenant can read
   it and not change it (a change is a ticket), and nothing restarts. The enforcement of phase 1 does not change when
   the source does, and the ceiling of decision 3 is what bounds that source if it is ever wrong.

### Phase 2: the verified bundle is the source of the grants (Implemented, shadow by default)

This is the enforcing step that [ADR-0026](0026-notaio-bundles-verified-in-shadow.md) (decisions 6 to 8) and
[ADR-0030](0030-policy-egress-enforced-at-the-gateway.md) left to "the enforcing ADR": it turns `P001` to `P005`, `P010` and `P011` into
refusals behind a switch, and it is written here, in the ADR that already defines the effective grant, so the two
cannot disagree. It reuses everything ADR-0026 built (the verifier, the keys from configuration, the floor, the
reflector, `policyRef`) and adds no component.

9. **A switch, `policy.audiences: shadow | enforce`, default `shadow`.** It is the broker's own configuration, reviewed with
   the deployment like the trusted keys (ADR-0026 decision 2), never cluster state, and global to a broker process, so rollout is
   per environment. Without a `policy` section there is nothing to enforce and the switch does not exist. In
   `shadow` the broker behaves exactly as phase 1 and as ADR-0026 does today, and additionally logs, per claim, each
   refusal `enforce` would make (the code, the claim, the policy and the bundle version; never a rule, a host or a token).

10. **Under `enforce`, a claim is admitted only under a verified bundle that grants what it asks for.** At `POST /v1/claims` and
    in the reconciler (the declarative path), after the namespace check of ADR-0046:
    - `policyRef` is required (`P010`): `400 policy_required`, and the reconciler fails the sandbox in the same words.
    - It must resolve, in the claim's own namespace first and then in `policy.namespaces` (ADR-0026 decision 6), to a bundle that
      verified and is unexpired (`P011`). A policy that does not exist is `400 unknown_policy`; before every watched namespace has
      completed its first list (`BundleCache::synced_all`) the answer is `503 policy_not_synced` and nothing is created,
      so a restart never reads "no bundle yet" as "no policy".
    - Every requested audience must be a grant of that bundle (`P001`). A refusal is `400 unknown_audience`, the same
      code and body as an audience that does not exist (decision 4), so it tells a caller nothing about another namespace's policy.
    - `ttl_seconds` must not exceed the bundle's `lease.maxDurationSeconds` (`P005`): `400 ttl_exceeds_policy`.

11. **The effective grant is the bundle's, bounded by the broker's own configuration, never wider than either.** For a claim under a
    bundle, per audience:
    - **Rules.** A bundle rule is kept only if a rule of the audience's top-level `rules` (the ceiling, decision 3) covers it
      (`rule_covers`). A bundle grant with no rules reads as notaio reads it, every method and path, so the effective rules are the
      ceiling. A grant that has rules **none of which survive** the ceiling makes the audience unusable for that claim: an empty
      list would mean every path, so the broker never produces one from a non-empty grant. If the audience also lists the claim's
      namespace in `namespaces` (phase 1), a rule must be covered by that file grant too: the two sources intersect.
    - **Endpoints.** The effective `egress` is the audience's `egress` intersected with the grant's `endpoints` (`P003`).
    - **Lifetime.** A token or placed credential lives at most the least of the audience's `max_ttl` and the grant's `ttlSeconds` (`P002`).
    The same function feeds `GET /v1/me`, the gateway's claim answer, the mint and the allowlist (`egress_of`), so they cannot disagree.

12. **Every use reads the current bundle, and an unusable bundle takes the audience away.** As ADR-0030 decision 2 does for direct
    egress, a mint, `GET /v1/me` and the gateway's answer look the bundle up by the claim's recorded policy `uid` and use the
    **current** one, so a policy that tightens narrows running claims on their next ask, and the version floor keeps it from ever
    being older than one already accepted. A bundle that is missing, expired or no longer verified at that moment grants
    **nothing**: the claim's audiences are dropped (fail closed), not served from the last bundle it saw. A claim recorded with no policy
    (created before `enforce`) loses its audiences the same way at its next ask, so the rollout of decision 15 drains them first.
    *Amended by [ADR-0061](0061-a-running-claim-follows-a-new-bundle-only-while-it-is-still-inside-it.md) (2026-11-21):* a claim
    follows a newer version only while it is still inside it: the lease and the policy's name are checked again, and what the guest
    rendered must not be wider than the newer version allows; otherwise `403 policy_changed` under `policy.follow: enforce`.

13. **The platform writes the policies; the tenant reads them.** A `SandboxPolicy` per tenant namespace is authored in the policy
    repository, linted by notaio against Security's ceiling and applied by GitOps. The tenant namespace gives its users `get`, `list`
    and `watch` on `SandboxPolicy` and the bundle `ConfigMap` and no write, enforced by RBAC and by a
    `ValidatingAdmissionPolicy` that admits only the GitOps identity as a writer (the pattern of A-9,
    `deploy/base/admission/agentsandbox-subject.yaml`). This is a requirement on the deployment, which notaio's repository and the
    platform's own manifests carry, and not a check the broker can make; the broker relies on the signature and the configured keys.
    The reason it is stated here: a `SandboxPolicy` applied by anyone who could write one would be compiled into a signed bundle
    if it passed notaio's ceiling, so a tenant with write access could widen its own grant up to that ceiling. The audience's own
    `rules` (decision 3) is the second, independent bound, owned by the broker's operator and never a tenant's. Eligibility is the
    policy's location: a claim may name a policy in its own namespace, or in a namespace listed in `policy.namespaces`
    (platform-shared base policies); it cannot name one in a namespace the broker does not watch.

14. **Phase 1 stays, and an unscoped audience stops being open under `enforce`.** `audiences[].namespaces` keeps working and
    intersects with the bundle (decision 11). An audience with no `namespaces` is usable under `enforce` only by a claim whose
    policy grants it, which closes the open reading R-41 records for claims under a policy. This ADR does not remove `namespaces`
    from the file: once every claim runs under `enforce` it is optional, and a configuration may keep just the top-level `rules`
    as the ceiling. Removal, if wanted, is its own change.

15. **Rollout and rollback.** `shadow` everywhere first (the code ships dormant, and the would-refuse lines of decision 9 are the
    evidence). Then `enforce` in the dev environment after a week of shadow with no line nobody expected, and with no live claim
    lacking a policy; then each tier in turn, a configuration change per environment with the previous value as rollback:
    setting `shadow` restores phase 1's behaviour on the next ask. `make kind-e2e-policy` is extended to run both modes.

16. **Nothing fails open, and what is new is named.** A bundle that does not verify is never used; an expired one is gone for every
    reader at once with no skew allowance (ADR-0026); the floor still refuses a downgrade; a policy can narrow what the broker's
    configuration allows and never widen it. What becomes a refusal under `enforce` is exactly: a missing `policyRef`, an
    unresolved or not-yet-synced policy, an audience, a lifetime or a rule the bundle does not grant, and a claim whose bundle is
    unusable at an ask. Default-deny, exact matching and the gateway's checks are untouched, and each has a test that says so.

### Phase 2 implementation notes

What was built within decisions 9 to 16, so a reader of the code finds it here:

- **The switch** is `policy.audiences` (`PolicySection`, `crates/mediatore/src/config.rs`), the same `shadow | enforce` type as
  `policy.egress`, read into `PolicyEgress.audiences` (the API) and `WatcherConfig.audiences_mode` (the reconciler). A
  misspelling refuses the start.
- **The effective grant** is one pure function, `effective_grant` in `crates/mediatore-claims/src/policy.rs`, built on
  `shadow::rule_covers`. The API reads it through `effective_in` and `effective`, and the reconciler through
  `WatcherConfig::grants`.
- **The API** (`crates/mediatore-api/src/lib.rs`): `admit_under_policy` is decision 10 (`policy_required`, `policy_not_synced` as
  `503`, `unknown_policy`, `unknown_audience`, `ttl_exceeds_policy`); `claim_audiences` now filters by the effective grant, so the
  proxy routes, the gateway's inject routes, the tunnel allowlist, the mint and the credential route all read the claim's
  **current** bundle by its recorded policy `uid` (decision 12); `issue_token` caps the lifetime at the grant's `ttlSeconds`
  (the STS mints with it, every other backend is clamped on the way out). The dev path records the policy `uid` it was admitted under.
- **The reconciler** (`crates/mediatore-claims/src/sandbox.rs`): `refuse_under_policy` is decision 10 for a declarative
  `AgentSandbox`, and `awaiting_bundles` holds an unsynced sandbox (`Action::requeue`) instead of failing it, because a failed sandbox's
  spec is immutable.
- **`policy.egress` is unchanged and separate.** The credential route's existing `policy_admits` (the bundle must list a
  gateway-placed audience, under `policy.egress: enforce`) still runs after the new checks.
- **Shadow logs** are the reconciler's existing per-gap lines and the `PolicyConformant` condition (`P001` to `P005`, `P010`, `P011`), which
  already say, per sandbox, what `enforce` would refuse. The API adds no separate would-refuse line under shadow: a claim made through
  `POST /v1/claims` on a cluster becomes an `AgentSandbox`, which the reconciler reports.
- **Not done in this change:** decision 13's RBAC and admission policy for the policy namespaces are a requirement on the deployment
  and notaio's manifests, and nothing in this repository enforces them; decision 15's extension of `make kind-e2e-policy` to run both
  modes was not made, and phase 2 has not been run on a cluster. The unit and end-to-end suites cover the logic over real HTTP listeners.

## Consequences

- **One audience per service, not per application.** The host, credential kind and lifetime are
  written once and reviewed once. A new team is a new entry under `namespaces`, in a reviewed
  config change, with no new audience name for clients to learn.
- **A namespace can no longer reach another team's rules by naming the audience.** Combined with
  ADR-0046, the chain is: the person is in the namespace's groups, the namespace lists the audience,
  and the claim gets only that namespace's rules.
- **A configuration change is a restart.** The broker reads `audiences[]` at start, so adding or
  removing a namespace is a rollout, as every other audience change is today. Running claims lose a
  removed audience at their next mint or gateway ask (decision 4), not instantly.
- **An unscoped audience stays open.** An operator who leaves `namespaces` off an audience gets what
  they got before. That is stated, not hidden (decision 7), and it is the one place a mistake keeps
  the old behaviour; this is why it is a candidate accepted risk for the threat model rather than a
  closed one.
- **Cost:** a second dimension in three maps, and a rule that two scoped audiences cannot share an
  endpoint across overlapping namespaces. Both are small and tested below.
- **Not done here:** a per-namespace `max_ttl`, `ca_file` or credential kind. The lifetime and the
  credential are the audience's; a different one is a different audience (disjoint namespaces,
  decision 6). Revisit when a real need appears.

- **Phase 2 changes the failure mode of onboarding and of an outage.** A new team is a policy in the policy repository and one
  namespace Role, with no restart and no `mediatore.yaml` edit, and the tenant can read what it was granted. But under `enforce`
  the broker depends on notaio re-signing: a bundle lives its lifetime (15 minutes by default, a site value up to a day) and is
  refreshed at half, so a notaio outage longer than that takes the audiences away from every claim under a policy (decision 12), and a
  broker clock ahead of notaio's by more than the refresh margin does the same. That is R-42 in the threat model once phase 2 is
  implemented; the mitigations are a lifetime sized to the site's tolerance, the NTP requirement ADR-0026 already states, and the
  `shadow` rollback.
- **Two bounds, two owners.** The bundle's grant is bounded by notaio's approved ceiling and by the audience's own `rules`; the
  second is the broker operator's and survives a mistake or a compromise in the first.

## Order of work (ADD)

1. This ADR to Accepted (the open questions below answered).
2. CALM: if `docs/architecture/calm/architecture.json` models audiences at this grain, update it;
   `make calm-validate` and `make calm-diagrams`. If it does not, record "no change" in the PR.
3. TDD, failing test first. Unit, in `crates/mediatore/src/config.rs`:
   `an_audience_without_namespaces_behaves_as_before`,
   `top_level_rules_with_namespaces_are_the_ceiling_and_grants_inside_it_start`,
   `a_grant_outside_the_ceiling_refuses_to_start`, `with_no_top_level_rules_there_is_no_ceiling`,
   `an_empty_namespaces_map_refuses_to_start`,
   `a_namespace_entry_with_no_rules_refuses_to_start`,
   `a_namespace_key_that_is_not_a_label_refuses_to_start`,
   `a_namespace_key_outside_sandboxes_namespaces_refuses_to_start`,
   `scoped_audiences_sharing_an_endpoint_in_overlapping_namespaces_refuse_to_start`,
   `scoped_audiences_sharing_a_host_in_disjoint_namespaces_start`,
   `scoped_rules_hold_the_namespaces_own_rules_and_nothing_for_an_unlisted_one`,
   `startup_names_each_unscoped_audience_when_the_namespace_map_is_set`.
   In `crates/mediatore-api/src/lib.rs`:
   `create_claim_refuses_a_scoped_audience_in_an_unlisted_namespace_as_unknown`,
   `the_refusal_for_an_unlisted_namespace_is_the_refusal_for_a_missing_audience` (same status, same
   code, same body shape),
   `me_routes_carry_the_rules_of_the_claims_namespace`,
   `the_gateways_claim_answer_carries_the_rules_of_the_claims_namespace`,
   `a_mint_for_an_audience_the_namespace_no_longer_lists_is_refused`. In
   `crates/mediatore-claims/src/sandbox.rs`: `a_declarative_sandbox_naming_a_scoped_audience_in_an_unlisted_namespace_is_refused`.
   End to end in `crates/mediatore/tests/e2e_dev.rs` (negatives included, per `rules/testing.md`):
   two namespaces, one audience, each claim reaches its own repository path and is refused the
   other's through the real proxy and the fake gateway.
4. Implement the minimum, then `make check`.
5. Docs: `docs/design/issuers-and-audiences.md` (the audience table), `docs/guides/configuration.md`,
   the README status table, ADR-0040 and ADR-0046 cross-links.
6. Threat model: a full pass over `docs/security/threat-model.md`, stamp bumped (date and ADR range).
   The questions to answer: TB-1 (the namespace now selects which rules a claim gets), the
   gateway and proxy tables, and an accepted risk for the unscoped default. Controls cited by file
   only once they exist.

### Order of work, phase 2 (done 2026-11-19 except the kind tier and a live run; the tests as built are named in the implementation notes' files)

1. Accept decisions 9 to 16 (the open questions below answered). Phase 2 needs no new CRD, no new crate and no new route.
2. CALM: the broker's description gains the switch and the refusals; `make calm-validate`.
3. TDD, failing test first. Unit in `crates/mediatore-claims` (the effective grant as a pure function beside `shadow::compare`):
   `a_bundle_rule_the_ceiling_does_not_cover_is_dropped`,
   `a_grant_with_rules_none_of_which_survive_the_ceiling_makes_the_audience_unusable`,
   `a_grant_with_no_rules_reads_as_the_ceiling`, `a_file_grant_and_a_bundle_grant_intersect`,
   `endpoints_are_the_intersection_and_the_lifetime_the_least`. In `crates/mediatore-api`:
   `under_enforce_a_claim_without_a_policy_is_policy_required`, `an_unknown_policy_is_unknown_policy`,
   `before_every_namespace_is_synced_the_answer_is_503_and_nothing_is_created`,
   `an_audience_the_bundle_does_not_grant_is_unknown_audience`, `a_ttl_above_the_lease_is_ttl_exceeds_policy`,
   `a_tightened_bundle_narrows_a_running_claims_routes_at_its_next_ask`,
   `an_expired_missing_or_unverified_bundle_takes_the_audiences_away`,
   `shadow_serves_phase_1_and_logs_each_refusal_enforce_would_make`. In `crates/mediatore-claims/src/sandbox.rs`: the same refusals on
   the declarative path. End to end in `crates/mediatore/tests/e2e_dev.rs` and `make kind-e2e-policy`: two namespaces with their own
   policies, each claim reaching its own paths and refused the other's, the replay of an older bundle refused, a tenant identity
   unable to write a policy.
4. Implement the minimum; `make check`.
5. Docs: `docs/guides/the-policy-bundle.md` (the enforcing mode, the codes as refusals, the rollout), `multi-tenant-authorization.md`
   section 6, the README row.
6. Threat model: a full pass, stamp bumped. TB-1 (the claim now needs a policy), TB-2 (the reflector's input now gates claims), the
   notaio availability and clock coupling as R-42, R-41 narrowed, and the tenant-read-only requirement of decision 13 stated as an
   assumption with its control cited only where it exists.

## Open questions

1. **Names or groups.** The key is a namespace, and who may claim there is ADR-0046's map. The
   alternative, listing groups on the audience, would make a second place that says who may do what.
   The default here is the namespace; say if you want groups.
2. **Unscoped audiences once `sandboxes.namespaces` is set.** Decision 2 keeps them open and decision 7
   only warns. The stricter reading is a start error unless the audience writes
   `namespaces: all` (or a flag) to say so in words, as `allow_any_authenticated: true` does for the
   issuer gate (ADR-0046 decision 19). It would break every existing multi-namespace config on upgrade.
3. **The word `namespaces`.** `sandboxes.namespaces` is a map to groups and `audiences[].namespaces` is a
   map to rules. The same word with two shapes is easy to misread; `scopes` or `per_namespace` are
   the alternatives.
4. **Eligibility from the bundle (phase 2).** notaio has a notion of who may name a policy (its K7.2, eligibility by group). Decision 13
   makes eligibility the policy's location. If the bundle carries a group list, the broker could also require the caller's groups to
   intersect it; that is a second place that says who may do what, next to ADR-0046's map. The default here is the location only.
5. **A base policy per namespace, applied without being named (phase 2).** `policyRef` is a single name, and notaio composes no base plus
   extras. To make "the team's base policy" apply by default, the broker could take `policy.default_name` (for example `base`) and use that
   policy in the claim's namespace when a claim names none. It is one setting, not one per team, but it makes `policyRef` optional again
   under `enforce`. The default here is that a claim names its policy.
