<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0073: `groups` qualified by issuer when the broker trusts several

**Status:** Accepted and implemented 2026-11-27 (built with ADR-0071 and ADR-0074; what was built differently from the text is under *As built*) · **Date:** 2026-11-27

Amends [ADR-0003](0003-token-backends.md) (the shape of the token the STS mints: each element of
`groups` may carry a prefix) and
[ADR-0071](0071-sub-qualified-by-issuer-when-the-broker-trusts-several.md) (what
`issuers[].subject_prefix` qualifies: `groups` as well as `sub`). Changes a token shape. Changes
no configuration key, no SPIFFE ID, no storage contract, no route and no trust boundary: what
reaches a resource server across TB-7 is the same token with one more claim spelled so that it
cannot be read as another issuer's.

## Context

The token the STS mints carries `groups` when the broker has any to give
(`Claims.groups`, `crates/mediatore-sts/src/lib.rs`). They are the upstream's strings, copied.

A group name is unique only inside the issuer that gave it, exactly as a subject id is.
`platform-admins` at one directory and `platform-admins` at another are two sets of people. A
resource server that maps `groups` to roles, and many do nothing else, cannot tell them apart:
ADR-0071 qualified `sub` and left the claim beside it bare. Its own reasoning applies word for
word: a verifier reads the claims it knows, `upstream_iss` is not one of them, and an overlap
between two issuers is created by adding a list item.

### Where the groups in a token come from

Read in the code for this ADR:

- `issue_token_capped` (`crates/mediatore-api/src/lib.rs`) mints with `fresh.groups`.
- For an issuer with a `session`, and for an Entra issuer asked for an audience the STS serves,
  `refresh_session` refreshes upstream first and the groups are those of the fresh token,
  validated as that issuer (`validate_as` pins `iss`; `groups` plus `roles`, or the issuer's
  `groups_claim`).
- For an issuer with neither, the groups are empty and the claim is left out of the token
  (`skip_serializing_if`). Nothing is kept from the login: the record holds no groups.

So a token carries groups only for an issuer the broker holds a session at, and they are always
the groups of the record's own issuer, read at that moment. The ambiguity is real where two such
issuers are trusted under one `sts`.

### What the broker itself decides on groups

Every place the broker reads a group was looked at, as ADR-0071 did for the subject:

| Place | What it compares | Bound to the issuer? |
| --- | --- | --- |
| The login gate, `required_group` / `required_groups` (`IssuerConfig::gate`, applied in `validate_as`, `crates/mediatore-entra/src/lib.rs`) | The token's groups against the list written on that issuer | Yes: the list is a key of the issuer, and the token was validated as that issuer |
| The same gate at every refresh (`refresh_session`) | The fresh token's groups against the record's issuer's list | Yes, and the subject id is compared on one issuer's terms |
| The namespace map, `sandboxes.namespaces.<ns>.groups` (`Namespaces::matched_group`, `crates/mediatore-api/src/lib.rs`), on create, get and delete | The validated token's groups against the namespace's list, by exact name (ADR-0046 decision 2) | Yes, by [ADR-0074](0074-a-namespaces-groups-read-only-from-the-issuers-it-names.md), which lands with this ADR: an entry's groups are read only from tokens of the issuers it lists |
| Eligibility by group from the bundle (ADR-0066) | Nothing yet: the ADR is Proposed and no code reads a policy's `subjects` | Not applicable today. It runs after the namespace gate and takes ADR-0074's rule (ADR-0074 decision 8) |
| Policy bundles, audiences, egress (`crates/mediatore-claims/src/policy.rs`) | No group is read | Not applicable |
| The claim's record, the `AgentSandbox`, the logs | No group is stored; the audit line names the listed group that matched, a configuration value | Not applicable |

The one place a group leaves the broker without its issuer is the STS token. That is what this
ADR changes.

## Decision

1. **A group in the minted token carries its issuer's `subject_prefix`.** With
   `subject_prefix: "dex:"`, the upstream's `platform-admins` is minted `dex:platform-admins`,
   beside `sub: dex:octocat`. One key qualifies both claims: a deployment that told a resource
   server "`dex:` means this Dex" has said it once. Every element is qualified, in the upstream's
   order, and the name after the prefix is the upstream's string byte for byte: nothing is
   folded, trimmed or split. A group that already holds a `:` (`example-org:admins`) becomes
   `dex:example-org:admins`; under ADR-0071 decision 1 the prefix of a qualified value is
   everything up to and including its first `:`, whatever follows.

   Control: `SubjectPrefixes::groups` and `mint_at` (`crates/mediatore-sts/src/lib.rs`).

2. **One issuer and no prefix: the token is unchanged,** byte for byte in every claim, `groups`
   included. One issuer with a prefix has its groups qualified, as its `sub` is: that is the
   deployment preparing for a second issuer, and half a qualified token would be the ambiguity
   this ADR removes.

3. **No new check and no new key, because the set is the one ADR-0071 already checked.**
   `SubjectPrefixes` is built only by `SubjectPrefixes::new`: under an `sts`, two or more issuers
   each have a prefix and no prefix is the start of another, or the broker does not start. So
   `prefix_a + group_a` equals `prefix_b + group_b` only when the issuer is the same: two issuers
   can never be minted the same group. A subject whose issuer has no prefix while any issuer has
   one is `StsError::NoSubjectPrefix` before anything is signed, for `groups` as for `sub`: the
   two are computed from the same lookup, and a token is never minted with one qualified and the
   other bare.

4. **The broker's own decisions keep the upstream's spelling.** `required_groups` and
   `sandboxes.namespaces.<ns>.groups` are written as the issuer spells a group and compared with
   the groups of the validated token, before and apart from any minting. The prefix is in the
   token and nowhere else, as ADR-0071 decision 6 has it for the subject: no record, resource,
   log line or configuration list holds a qualified group, and renaming a prefix migrates
   nothing inside the broker.

5. **The start line of ADR-0071 decision 7 says both.** Per issuer under an `sts`: that `sub` and
   each of `groups` are the `subject_prefix` followed by the upstream's value, or that both are
   bare.

   Control: `Config::log_startup` (`crates/mediatore/src/config.rs`).

6. **Other backends are untouched.** An Entra On-Behalf-Of token is Entra's, with Entra's own
   group claims; a `via: secret` or delegated credential carries no claim the broker wrote.

## Security analysis

TB-7 is where a token the broker minted reaches a downstream resource server. TB-5 is the
broker's trust in its upstream issuers.

| Boundary | Threat | STRIDE | Control |
| --- | --- | --- | --- |
| TB-7 | Two different groups with one name at two trusted issuers are minted as the same `groups` element, and a resource server that authorizes on `groups` gives the members of one what it grants the other | S/E | Each element is the issuer's `subject_prefix` then the upstream's name (`SubjectPrefixes::groups`); the set of prefixes is the one checked at start (`SubjectPrefixes::new`). `the_same_group_at_two_issuers_mints_two_different_groups`, `the_same_group_at_two_issuers_reaches_the_resource_server_as_two` |
| TB-7 | A token with a qualified `sub` and bare `groups`, or the reverse | S | One lookup yields both; a missing prefix under a non-empty set signs nothing (`a_token_never_carries_a_qualified_sub_beside_bare_groups`) |
| TB-7 | A group name chosen upstream so that, once qualified, it reads as another issuer's (a name that itself begins with another issuer's prefix) | S | The value starts with the minting issuer's own prefix, and no prefix is the start of another: the first `:` ends the prefix whatever the name holds (`a_group_holding_the_delimiter_is_still_its_own_issuers`) |
| TB-5 | A second issuer added without prefixes, so the overlap exists by omission | E | Unchanged from ADR-0071 decision 3: the broker does not start |
| TB-7 | A resource server's audit trail that cannot say which directory a group came from | R | The prefix is readable and the operator's choice; `upstream_iss` is unchanged |
| TB-7 | The prefix discloses something | I | It is the value already in `sub`, beside the issuer's URL in `upstream_iss` |
| TB-7 | A resource server's group mapping stops matching on upgrade | D | Only where a prefix is set (decision 2); said in the release note and by the start line. Tokens live fifteen minutes at most |

Tampering is not in the table: the claim is inside the signed payload, as before.

## Consequences

- **A deployment with one issuer and no `subject_prefix` sees no change.**
- **A deployment with a `subject_prefix` on an issuer that mints groups must give its resource
  servers the qualified names** (`dex:platform-admins`) before the release that carries this ADR.
  ADR-0071 is not yet in a release; shipped together, the two are one change to one mapping, and
  that is the intent. Apart, this would be a second rename a week after the first.
- **`groups` and `sub` can no longer be qualified separately.** A resource server that wanted the
  new `sub` and the old group names has no setting for it. That is deliberate: the bare names are
  the ambiguity.
- **An issuer with no `session` that is not Entra still mints no groups.** Nothing here adds
  groups to a token that had none.
- The kind tiers' broker has `dex:` on its Dex issuer; a check of the minted token's `groups` in
  the Dex tier expects the qualified names.
- `MintRequest.groups` keeps taking the upstream's strings: the caller cannot hand the STS
  pre-qualified names, and the qualification has one home.

## Alternatives rejected

- **Dropping `groups` when the broker trusts several issuers.** Nothing ambiguous is minted, and
  every resource server that authorizes by group stops working the day a second issuer is added,
  including the ones for which the groups were unambiguous. It answers a spelling problem by
  removing the information.
- **A separate claim** (`groups` bare as today, plus `qualified_groups`, or `groups` as objects
  with an issuer beside each name). The bare claim would still be there, and it is the one
  resource servers read: the control would work only for a verifier rewritten to prefer the new
  claim, which is the objection ADR-0071 made to relying on `upstream_iss`.
- **Leaving it to `upstream_iss`.** Present today, and the ambiguity stands for every verifier
  that maps `groups` without reading it. A control only some resource servers implement is not
  one the broker can claim.
- **A prefix of its own for groups** (`issuers[].groups_prefix`). One more key that must be
  unique across issuers by the same rule, a second name to agree with every resource server, and
  a way to set one and forget the other.
- **Qualifying only under two or more issuers, whatever the prefix says.** The token of a
  single-issuer deployment that set a prefix ahead of time would change shape the day the second
  issuer arrives, which is the event the prefix was set early to make uneventful.
- **Qualifying the names in the broker's own lists too** (`required_groups: [dex:admins]`). The
  gate is already a key of its issuer, so the prefix would say nothing new there, and every
  existing configuration would have to be rewritten.

## What must be proven

Tests are written before the code they hold.

- Unit, `crates/mediatore-sts/src/lib.rs`:
  `a_prefixed_issuers_groups_are_the_prefix_then_each_group`,
  `one_issuer_without_a_prefix_keeps_the_bare_groups`,
  `the_same_group_at_two_issuers_mints_two_different_groups`,
  `a_group_holding_the_delimiter_is_still_its_own_issuers`,
  `a_token_never_carries_a_qualified_sub_beside_bare_groups` (the refusal at mint leaves nothing
  signed), `no_groups_mints_no_groups_claim_with_or_without_a_prefix`, and the order of the
  upstream's list kept.
- Unit, `crates/mediatore/src/config.rs`:
  `startup_logs_each_issuers_subject_prefix_or_that_sub_is_the_bare_id` amended to the line of
  decision 5.
- Unit, the admission-policy parsing tests in `crates/mediatore-claims/src/sandbox.rs`: none.
  This ADR touches no manifest, and no kind tier is needed to prove a CEL expression.
- End to end, `crates/mediatore/tests/e2e_issuers.rs`:
  `the_same_group_at_two_issuers_reaches_the_resource_server_as_two` (two session issuers of the
  fake IdP, one group name at each, two claims, two tokens);
  `crates/mediatore/tests/e2e_session.rs`: the existing fresh-groups assertion unchanged for an
  issuer without a prefix, and `fresh_groups_are_minted_under_the_issuers_prefix` with one.
- End to end, the broker's own gates unchanged: the existing ADR-0046 tests
  (`a_service_id_with_a_bare_group_passes_when_both_spellings_are_listed` and the namespace-map
  suite) pass without edits under a configuration that has prefixes, which is the proof of
  decision 4.
- Live: `make kind-e2e-dex`, whose broker has `dex:` on the Dex issuer, checks the minted token's
  `groups` beside its `sub`.
- This is not the TPM attestation path.

## As built (2026-11-27)

Built as written, with the tests named above. Where the build says more than the text:

- `SubjectPrefixes::groups(subject, groups)` is the public form of the rule; `mint_at` takes the
  issuer's prefix once through the private `prefix_for` and builds `sub` and every element of
  `groups` from it, so the one lookup of decision 3 is literal. `the_upstreams_order_and_spelling_are_kept`
  is the order test the text asks for.
- Three existing assertions on a minted `groups` changed, each for an issuer that already had a
  prefix: the Auth0 login of `e2e_issuers.rs` (`auth0:`) and the two Entra assertions of
  `e2e_entra.rs` (`entra:`). The gate tests of ADR-0046 pass unedited.
- Live, `make kind-e2e-dex` checks that the token's groups are non-empty, all begin with `dex:` and
  include `dex:sandbox-users`.

## Open questions

1. **Should the token say that its groups are qualified,** for a resource server that serves
   several brokers? Recommendation: no new claim. A qualified `sub` beside it already says so,
   and `upstream_iss` names the issuer in full.
2. **A group claim that is not a list of strings** (Entra can emit an overage reference in place
   of `groups`). Not changed here: `string_array` reads strings and nothing else, so such a token
   mints no groups. Recommendation: leave it; it is ADR-0016's subject.
