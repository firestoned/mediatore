<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0072: A hand-created sandbox names only an issuer its creator can come from

**Status:** Accepted and implemented 2026-11-27 (built on each open question's recommendation; what was built differently from the text is under *As built*) · **Date:** 2026-11-27

Amends [ADR-0008](0008-agentsandbox-crd-owned-by-mediatore.md) decision 5 (what admission pins of
`spec.subject`, and what the reconciler refuses of it) and
[ADR-0046](0046-who-may-claim-a-list-of-groups-and-a-namespace-to-groups-mapping.md) decision 11
(the declarative requester is no longer unchanged when the broker trusts several issuers). Follows
[ADR-0071](0071-sub-qualified-by-issuer-when-the-broker-trusts-several.md), which made the issuer
part of what a resource server reads, and so made a wrong issuer on a sandbox worth as much as a
wrong id. Changes the broker's configuration contract (one key under `sandboxes:`), the admission
policy on `AgentSandbox`, and the object the broker writes (one annotation). Changes no token
shape, no SPIFFE ID, no route and no storage contract. It narrows a trust boundary, TB-2, so the
threat-model pass is part of done.

## Context

An `AgentSandbox` reaches the cluster through two doors. `POST /v1/claims` validates a bearer
token at exactly one issuer and writes `spec.subject` from it (`create_sandbox`,
`crates/mediatore-api/src/lib.rs`). The declarative path is a `create` on `agentsandboxes` by
anybody Kubernetes RBAC lets, and for that path ADR-0008 decision 5 put a
`ValidatingAdmissionPolicy` in front (`deploy/base/admission/agentsandbox-subject.yaml`).

ADR-0008 decision 5 says the policy requires `spec.subject.id` and `spec.subject.issuer` to match
the requesting user. What ships checks the id only, and says so in its header: the API server
cannot tell which issuer minted the caller's token. The code was read for this ADR, and this is
what it does:

| Place | What it does with `spec.subject.issuer` |
| --- | --- |
| Admission, `expectedPrefix` in `agentsandbox-subject.yaml` | Picks the username prefix: the pair in `issuerPrefixes` whose issuer equals the one the object declares, and **the single `usernamePrefix` for any issuer that is not listed**. The issuer itself is not compared with anything |
| Admission, a line of `issuerPrefixes` that is not a pair | Dropped without a word (`filter(e, size(e) == 2)`), so the issuer on it counts as not listed |
| The reconciler, `Watcher::refuse` (`crates/mediatore-claims/src/sandbox.rs`) | Refuses an issuer that is not one of `issuers[].url`, before any claim exists. Nothing else |
| The record, `record_for` | Copies the whole subject, issuer included |
| The token route, `issue_token_capped` (`crates/mediatore-api/src/lib.rs`) | For an issuer with a `session`, or an Entra issuer, a refresh is made first and a record with no session envelope is refused (`no delegated session for this claim`). For an issuer with neither, the STS mints with no upstream round trip |

So the issuer on a hand-created sandbox is its creator's own statement. With one trusted issuer
that statement has one possible value and the id binding is the whole control, which is the case
ADR-0008 was written for. With two trusted issuers, and an `issuerPrefixes` list that does not
give each its own prefix, a Kubernetes user is bound to their id and is free to choose which
issuer it is an id *at*. The sandbox, its record, the user in the guest and the audit trail then
attribute the work to the holder of that id at the other issuer, and where that issuer has no
`session` and is not Entra the STS mints for the pair. ADR-0071 made `sub` say which issuer; this
is the path on which the issuer said is not the issuer authenticated.

### Can the reconciler tell the two doors apart?

Not today, in any way a tenant cannot copy. This was checked, because the rule below needs it:

- `create_sandbox` builds the object with `AgentSandbox::new(name, spec)` and a namespace. It sets
  no label, no annotation and no owner reference.
- The name (`sandbox-` and eight hex characters) is a spelling anybody can use.
- `metadata.managedFields` names a field manager, which is a string the client chooses.
- A parked session (`park_session`, the Secret under the sandbox's UID in the broker's namespace)
  is something a tenant cannot write, but it exists only for an issuer with a `session` or an
  Entra issuer. A sandbox the broker created for a person of a plain STS issuer parks nothing, so
  "no parked session" does not mean "created by hand". It is also written after the create, so a
  reconciler pass can run before it exists.
- `status` is the broker's alone (`agentsandbox-status.yaml`), but a create cannot set it: a stamp
  there would arrive in a second write, after the reconciler may already have looked.

What the cluster does have is the admission policy itself, which sees the requesting username on
every create and already knows the broker's (`params.data.broker`, ADR-0056 decision 4). Decision 3
uses it.

## Decision

1. **Once `issuerPrefixes` lists anything, an issuer that is not listed is refused at admission.
   There is no fallback.** "Lists anything" is one non-blank line, whether or not it parses, so a
   list of typos is not read as an empty list. With the key empty or absent the policy is exactly
   what it was: the single `usernamePrefix`, any issuer, the single-issuer cluster of ADR-0008.
   The refusal names the issuer and the key:
   `spec.subject.issuer <url> is not listed in issuerPrefixes of ConfigMap
   mediatore-agentsandbox-subject-policy: this cluster's users come from the issuers listed there
   and no other`. The two exemptions stand as they are (the broker's own username, and the
   `brokers` list).

   Control: the variables `issuerLines`, `issuerPrefixes` and `expectedPrefix`, and validation 1,
   of `ValidatingAdmissionPolicy` `mediatore-agentsandbox-subject`
   (`deploy/base/admission/agentsandbox-subject.yaml`).

2. **A list that cannot tell its issuers apart admits nothing.** Three shapes, each refused with a
   message naming `issuerPrefixes`, for every creator the id check applies to: a non-blank line
   that is not exactly `<issuer> <prefix>`; an issuer listed twice; two prefixes that are equal or
   one the start of the other. The last is the property ADR-0071 decision 3 holds for `sub`,
   applied to usernames: with it, `prefix_a + id_a` equals `prefix_b + id_b` only when the issuer
   is the same, so a username names one listed issuer at most. An issuer whose API-server prefix
   is empty cannot be written as a pair and cannot sit beside another: an empty prefix is the
   start of every other.

   Control: the variable `issuerPrefixesAreSound` and validation 1 of the same policy.

3. **A sandbox the broker created says so, in an annotation only the broker may write.**
   `create_sandbox` sets `mediatore.io/front-door: api` on the object. The admission policy
   reserves the key: on `CREATE` it is admitted only from the broker's username
   (`params.data.broker`) and only with the value `api`, a rule that binds the broker too; on
   `UPDATE` it can be neither added, changed nor removed, by anybody. The `brokers` list does not
   lift this. The reconciler reads it through one function,
   `created_through_the_api(sb)`, and treats anything else, a second value included, as created
   by hand.

   The mark is exactly as strong as the id binding of ADR-0008 decision 5: both are validations of
   one policy, bound with `Deny`, parameterised by one ConfigMap. A cluster without the policy has
   neither. It is not a second root of trust, and decision 5 keeps the broker from relying on it
   where the policy does not yet guard it.

   Control: `FRONT_DOOR_ANNOTATION`, `created_through_the_api`
   (`crates/mediatore-claims/src/sandbox.rs`); `create_sandbox`
   (`crates/mediatore-api/src/lib.rs`); validations 3 and 4 of the policy.

4. **`sandboxes.declarative_issuers`: the issuers a hand-created sandbox may name. Default none
   once the broker trusts two or more.** A list of issuer URLs under `sandboxes:` in
   `mediatore.yaml` (`SandboxesSection`, `crates/mediatore/src/config.rs`): the issuers the
   operator says the API server's users come from.

   | `issuers:` | `sandboxes.declarative_issuers` | A hand-created sandbox may name |
   | --- | --- | --- |
   | one | not written | that issuer, as before this ADR |
   | two or more | not written | no issuer: the declarative path is closed |
   | any | written | exactly the issuers listed; `[]` closes the path |

   Each entry must equal an `issuers[].url` byte for byte and appear once; anything else is a
   start error naming the key and the value, so a typo is not a silently closed path.
   `SandboxesSection` already rejects unknown keys (ADR-0046 decision 17).

   The rule is applied where the reconciler already refuses an issuer, before any claim exists and
   only then (`refuse_before_the_claim`): a sandbox that is not `created_through_the_api` and
   whose issuer is not in the resolved set is `Failed` with the reason
   `issuer <url> may not be named by a sandbox created through the Kubernetes API: it is not in
   sandboxes.declarative_issuers (ADR-0072)`, no claim is created and nothing is recorded. A
   sandbox the broker created is not asked the question: its issuer is the one that validated the
   token. A sandbox that already has its claim is not judged again, as for every other refusal
   there.

   So a second issuer added to `issuers:` does not become nameable by anybody with `create` on
   `agentsandboxes`: adding it closes the declarative path until the operator has said which
   issuers that path speaks for.

   Control: `SandboxesSection::declarative_issuers`, `Config::declarative_issuers` (the resolved
   set) and its check in `Config::parse` (`crates/mediatore/src/config.rs`);
   `WatcherConfig::declarative_issuers` (`crates/mediatore-claims/src/watch.rs`), filled in
   `crates/mediatore/src/main.rs`; `Watcher::refuse` (`crates/mediatore-claims/src/sandbox.rs`).

5. **Where the rule is in force, the broker proves at start that the policy guards the mark.**
   "In force" is: the resolved set of decision 4 is smaller than `issuers:`. The broker then sends
   one server-side dry run (`dryRun=All`) of an `AgentSandbox` in its own namespace carrying the
   annotation with a value that is not `api`, which the policy must refuse by name. Admitted, or
   refused by anything else, the broker says which and does not serve, as it does for its SPIRE
   entries (`KubeEntryManager::self_check`, `crates/mediatore-spire/src/kube.rs`, ADR-0056).
   Without this, a broker deployed ahead of its manifests would trust a mark that any creator
   could set. Where the rule is not in force the mark decides nothing and no probe is sent.

   Control: `KubeSandboxes::self_check` and `judge_front_door_check`
   (`crates/mediatore-claims/src/sandbox.rs`), called from `crates/mediatore/src/main.rs`.

6. **The start says what the declarative path may name.** One line, always:
   - one issuer, key not written: `info`, the issuer, "an AgentSandbox created through the
     Kubernetes API may name this issuer (the only one configured)";
   - two or more, key not written: `warn`, the count, "sandboxes.declarative_issuers is not set
     and this broker trusts N issuers: an AgentSandbox created through the Kubernetes API is
     refused whatever issuer it names; list the issuers the API server's users come from";
   - key written: `info`, the list, or that the path is closed;
   - two or more listed: one more `warn`, that the ConfigMap's `issuerPrefixes` must list each of
     them with a prefix of its own, because the broker does not read it (open question 3).

   Control: `Config::log_startup` (`crates/mediatore/src/config.rs`).

7. **ADR-0008 decision 5 is corrected, not only amended.** Its sentence that admission requires
   the issuer "to match the requesting user" described an intent the policy never held. After
   this ADR the true statement is: admission pins the id to the username, and pins the issuer to
   the username's prefix when the operator has listed the issuers; the broker refuses, for a
   sandbox created by hand, an issuer the operator has not declared; and with one issuer and
   nothing listed, the issuer is the only one there is.

### What an operator sets

| The cluster | In `mediatore.yaml` | In the ConfigMap |
| --- | --- | --- |
| One issuer | nothing | `usernamePrefix`, as today |
| Several issuers, people use `POST /v1/claims` only | nothing (the `warn` of decision 6 is the expected line) | nothing |
| Several issuers, the API server authenticates against one of them | `sandboxes.declarative_issuers: [<that url>]` | `usernamePrefix`, or one `issuerPrefixes` pair |
| Several issuers, the API server authenticates against several | every one of them in `sandboxes.declarative_issuers` | one `issuerPrefixes` pair each, prefixes distinct |

## Security analysis

TB-2 is the broker to the Kubernetes API, the admission policies included. TB-7 is where a minted
token reaches a resource server.

| Boundary | Threat | STRIDE | Control |
| --- | --- | --- | --- |
| TB-2 | A creator bound to their own id declares an issuer they did not authenticate at, and the sandbox is attributed to the holder of that id there | S/E | Admission refuses an unlisted issuer once any is listed (decision 1); the reconciler refuses, for a sandbox created by hand, an issuer outside `sandboxes.declarative_issuers`, which is empty by default under several issuers (decision 4). `the_subject_policy_has_no_fallback_once_issuer_prefixes_is_set`, `with_two_issuers_a_hand_created_sandbox_is_refused_unless_its_issuer_is_declared` |
| TB-2 | A second issuer added to the broker becomes nameable on the declarative path by omission | E | The default is none; the path closes and the start line says so (`two_issuers_without_declarative_issuers_close_the_declarative_path_and_say_so`) |
| TB-2 | A list whose prefixes overlap, or a mistyped line, lets one username answer for two issuers or sends an issuer to the fallback | S | A list that is not sound admits nothing (decision 2); a non-blank line is a list (decision 1) |
| TB-2 | A creator sets the broker's mark on a hand-created sandbox to be excused from decision 4 | S/E | The annotation is admitted only from the broker's username and is immutable (decision 3); the broker proves the policy refuses it before relying on it (decision 5). `the_subject_policy_reserves_the_front_door_annotation_to_the_broker`, and live in `make kind-e2e-sandbox` |
| TB-2 | The broker is rolled out before the policy that guards the mark | E | The start self-check: admitted or unjudged, the broker does not serve (decision 5) |
| TB-7 | A token minted for a hand-created sandbox carries a `sub` qualified by an issuer nobody authenticated at | S | The record that would be minted from is never written: the refusal is before the claim (decision 4) |
| TB-2 | The audit trail names a person who was not there | R | The refusal is logged with the sandbox, its namespace and the issuer named; the Kubernetes audit log holds the creating username |
| TB-2 | The refusal reveals configuration | I | It names the issuer the creator wrote and a key name; the list of configured issuers is not in it |
| TB-2 | The declarative path stops on an upgrade or when an issuer is added | D | Intended and loud: the start `warn`, and the reason on each refused sandbox's status. A sandbox that already has its claim is untouched |

What this does not close, stated so nobody reads more into it:

- **One issuer, and an API server whose users do not come from it.** The policy binds an id to a
  username; that the username and the issuer's subject are the same person is the operator's
  `usernamePrefix` statement, as in ADR-0008. Nothing here changes it.
- **Several issuers declared and `issuerPrefixes` left empty.** The operator has then told the
  broker that the API server speaks for several issuers and has not told admission how to tell
  them apart. The broker cannot see the ConfigMap; it warns (decision 6).
- **A username mapping that is not a prefix.** An `AuthenticationConfiguration` can compute a
  username with an expression. A pair in `issuerPrefixes` states a prefix and nothing else.
- **The two exemptions.** The broker's ServiceAccount, and a principal on the `brokers` list, may
  name any id. A listed broker is still held to the declared issuers by decision 4; the broker's
  own credential is not, and remains the trust concentration ADR-0008 says it is.
- **Whoever can edit the ConfigMap** can change the broker's username, the lists and the
  prefixes. That is the standing note in the file, unchanged.

## Consequences

- **A cluster with one issuer sees no change,** in admission or in the broker, unless it sets a
  key. Its sandboxes gain an annotation when they come through the API.
- **A broker with two or more issuers stops serving hand-created sandboxes on the release that
  carries this ADR until `sandboxes.declarative_issuers` is written.** A breaking change for those
  deployments, said in the release note, in the start `warn` and on each refused sandbox.
- **A cluster that had set `issuerPrefixes` for some of its issuers and relied on the fallback for
  the rest must list the rest.** The refusal message names the key.
- **The manifests go first.** A broker with the rule in force does not start against a policy
  that does not guard the annotation (decision 5). The policy that guards it is harmless to an
  older broker, which never writes the key.
- **A sandbox the previous broker created and that has no claim yet at the upgrade has no mark,**
  so under several issuers it is judged as created by hand. The window is the seconds between a
  create and its first reconcile; the person asks again.
- **Fixtures that create sandboxes with `kubectl` as the broker's ServiceAccount** (the kind
  tiers) are hand-created as far as the reconciler is concerned unless their manifest carries the
  annotation, which that account may set. The kind broker trusts two issuers, so its
  configuration declares the fixture issuer.
- `create_sandbox_in_the_default_namespace_is_byte_identical_to_before`
  (`crates/mediatore/tests/e2e_sandbox.rs`, ADR-0046) pins the object a request produces: it is
  amended to expect the one annotation and nothing else new.
- The fakes follow (`rules/testing.md`, rule 2): `MemorySandboxes` in `mediatore-testkit` keeps
  the annotation it is given and gives none of its own, so a test cannot pass on a mark the real
  API server would have refused.

## Alternatives rejected

- **Keying the rule on a parked session.** The one existing artefact a tenant cannot write, and
  the first thing looked at. It exists only for a `session` or Entra issuer, so the broker's own
  sandboxes for a plain STS issuer would be refused; and it is written after the create, so a
  correct sandbox could be refused for good by a reconcile that ran first. Sound in one direction
  only.
- **A stamp in `status`.** Only the broker writes it, but not at create: the reconciler would have
  to hold every unmarked sandbox for a grace period and guess when to stop waiting.
- **A marker Secret per sandbox in the broker's namespace,** written for every create. Unforgeable
  without the policy's help, at the price of one more object per sandbox, the same
  written-after-the-create race, and a sweep for the ones left behind.
- **Refusing the declarative path altogether under several issuers.** Simple, and it is the
  default here. As the only behaviour it would take the path away from a cluster whose API server
  does authenticate against one of the issuers, which is the common shape.
- **Requiring `declarative_issuers` to be written, as a start error under several issuers.**
  ADR-0071 did this for `subject_prefix` because there was no safe value to assume. Here there is
  one: none. A broker whose people all come through `POST /v1/claims` should not be stopped for a
  path it does not use.
- **Leaving the fallback and documenting it.** The fallback is the finding: an unlisted issuer was
  checked against a prefix that says nothing about it.
- **Having admission compare the issuer with the broker's `issuers:`.** Admission would need the
  broker's configuration mirrored into the ConfigMap, a second copy that can disagree with the
  first, and it still would not know which issuer the caller came from.
- **Reading the issuer from the request's `userInfo.extra`.** A structured authentication
  configuration can map a token's `iss` into an extra attribute, and a policy could then compare
  it. That would be a real binding, and it is open question 5; it cannot be the base's default,
  because it holds only on clusters configured that way and admission cannot tell whether one is.

## What must be proven

Tests are written before the code they hold.

- Unit, the reconciler, `crates/mediatore-claims/src/sandbox.rs`:
  `with_one_issuer_a_hand_created_sandbox_naming_it_is_admitted_as_before`,
  `with_two_issuers_a_hand_created_sandbox_is_refused_unless_its_issuer_is_declared`,
  `with_two_issuers_a_sandbox_created_through_the_api_names_any_configured_issuer`,
  `an_empty_declarative_issuers_closes_the_declarative_path_with_one_issuer_too`,
  `a_front_door_annotation_with_another_value_is_a_hand_created_sandbox`,
  `a_refused_issuer_creates_no_claim_no_record_and_drops_nothing_it_did_not_park`,
  `a_sandbox_already_claimed_is_not_failed_when_declarative_issuers_changes`.
- Unit, the admission-policy parsing tests, same file (they read
  `deploy/base/admission/agentsandbox-subject.yaml` as `the_admission_policy_matches_every_served_version`
  does): `the_subject_policy_has_no_fallback_once_issuer_prefixes_is_set`,
  `the_subject_policy_refuses_a_list_that_cannot_tell_its_issuers_apart`,
  `the_subject_policy_reserves_the_front_door_annotation_to_the_broker`,
  `the_annotation_the_policy_guards_is_the_one_the_broker_writes` (the key and the value in the
  CEL equal `FRONT_DOOR_ANNOTATION` and its value), and the existing
  `the_three_policies_read_the_broker_from_one_parameter_and_deny_without_it` unchanged. These pin
  the text; that an API server evaluates it so is the kind tier's.
- Unit, the self-check, same file: `the_front_door_check_passes_on_the_policys_refusal`,
  `a_probe_that_is_admitted_or_refused_by_something_else_stops_the_broker`.
- Unit, the API, `crates/mediatore-api/src/lib.rs`:
  `a_sandbox_created_through_the_api_carries_the_front_door_annotation`.
- Unit, the configuration, `crates/mediatore/src/config.rs`:
  `one_issuer_needs_no_declarative_issuers`,
  `two_issuers_without_declarative_issuers_close_the_declarative_path_and_say_so`,
  `a_declarative_issuer_that_is_not_configured_refuses_to_start`,
  `a_declarative_issuer_listed_twice_refuses_to_start`,
  `startup_logs_what_the_declarative_path_may_name`, and
  `every_issuer_in_the_shipped_examples_and_guides_parses` still passing.
- End to end, `crates/mediatore/tests/e2e_sandbox.rs`:
  `post_creates_an_agentsandbox_marked_as_created_through_the_api`, and
  `create_sandbox_in_the_default_namespace_is_byte_identical_to_before` amended.
- Live, **`make kind-e2e-sandbox`** (`dev/kind/sandbox-e2e.sh`) is the tier that proves the CEL,
  with impersonated requesters as it does today: with `issuerPrefixes` listing one issuer, a
  sandbox naming another is denied by the policy and one naming the listed issuer under its
  prefix is admitted; a list with two overlapping prefixes denies; the annotation from an
  impersonated requester and from the listed broker is denied, and a change of it on an existing
  sandbox is denied; the broker's log carries the self-check line; a sandbox created by the
  listed broker naming the second configured issuer is admitted by the policy and `Failed` by the
  reconciler with the reason of decision 4. The existing cases stay green.
- This is not the TPM attestation path: no file `rules/testing.md` lists is touched.

## As built (2026-11-27)

Every decision is built, with the tests named above, and the threat model's pass of the same day
cites each control. Where the build differs from the text, or says more than it:

- **The policy has two more variables than decision 1 names.** `issuerListed` (no line, or a pair
  naming the sandbox's issuer) and `frontDoor` (the annotation, as a CEL optional) beside
  `issuerLines`, `issuerPrefixes`, `issuerPrefixesAreSound` and `expectedPrefix`. `issuerPrefixes`
  now keeps every non-blank line as its words, so a line that is not a pair is seen by the
  soundness check instead of being dropped. Validation 1's message is chosen by a conditional: the
  unsound list first, then the unlisted issuer (the sentence of decision 1), then the id sentence
  as before.
- **The reconciler's rule is its own function,** `refuse_declarative_issuer`, called in
  `refuse_before_the_claim` right after `Watcher::refuse` and under the same "only before a claim"
  guard, since `refuse` reads the spec alone and the rule needs the annotation. The reason is the
  sentence of decision 4 (`issuer_not_declarative`).
- **The self-check takes the home namespace** (`KubeSandboxes::self_check(namespace)`, called from
  `prove_front_door` in `main.rs` with the client's default namespace), and its errors are
  `FrontDoorCheckError`: `Admitted`, `Parameter` (the policy bound but unable to evaluate),
  `Refused` (anything that is not validation 3's message, an older policy included) and
  `Unreachable`. The probe is named `mediatore-selfcheck-` and twelve hex digits and names the
  issuer `https://selfcheck.invalid`; it is schema-valid so the CRD's own validation cannot be what
  refuses it. It runs at start only; the entries self-check's repetition at resync is not copied.
- **The start line has a case decision 6 does not list:** with no issuer configured it says, at
  `info`, that a hand-created sandbox is refused whatever issuer it names.
- **The resolved set lives on `Config`** (`Config::declarative_issuers`, and
  `Config::front_door_rule_in_force` for decision 5's "in force"); the check of written values is in
  `SandboxesSection::validate`, which `Config::parse` calls with the configured issuer URLs.
- **The fake needed no change.** `MemorySandboxes` already kept the annotations it was given and
  added none.
- **Open question 3 is not built:** the broker does not read the ConfigMap; the `warn` stands.
  **Open question 5 is not built** and is recorded as the *Revisit when* of R-70.
- **Live:** `make kind-e2e-sandbox` sets `issuerPrefixes` on the running parameter and proves each
  case of *What must be proven* through the API server; the kind broker declares
  `https://issuer.example.com`, the issuer every tier's `kubectl` fixtures name.

## Open questions

1. **The mark: an annotation guarded by the policy, or something that does not lean on the
   policy?** Recommendation: the annotation. It is atomic with the create, costs no object, and
   rests on exactly what the id binding already rests on; decision 5 covers the one new way it
   could be wrong. The alternatives above each trade that for a race.
2. **Is a failed self-check fatal?** Recommendation: yes, only where the rule is in force, as for
   the entries self-check. The softer choice (start, and treat every sandbox as created by hand)
   would refuse the broker's own sandboxes for every issuer not declared, which is an outage that
   looks like a policy.
3. **Should the broker read the ConfigMap and refuse to start when two or more declared issuers
   are not each in `issuerPrefixes`?** Recommendation: not in this ADR. It needs a `get` on one
   named ConfigMap in the broker's Role, and it checks a value that can change after start. The
   `warn` of decision 6 is what is proposed; if the maintainer wants the check, it is one rule in
   `deploy/base/rbac.yaml` and belongs with decision 5's probe.
4. **Is a principal on the `brokers` list held to `declarative_issuers`?** Recommendation: yes, as
   written. It is exempt from the id check by the operator's choice; nothing says it speaks for
   an issuer the operator did not declare.
5. **Binding the issuer at admission through `userInfo.extra`.** Recommendation: a later ADR, as
   an optional key in the ConfigMap naming the extra attribute. It would make the issuer a fact
   the API server vouches for, on clusters that map it.
6. **The names.** `sandboxes.declarative_issuers` and `mediatore.io/front-door: api`.
   Recommendation: keep both; "declarative" is the word ADR-0008 and ADR-0046 use for the path.
