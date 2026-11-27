<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0071: `sub` qualified by issuer when the broker trusts several

**Status:** Accepted and implemented 2026-11-27 · **Date:** 2026-11-27 · **Amended:** 2026-11-27 by [ADR-0073](0073-groups-qualified-by-issuer-when-the-broker-trusts-several.md) (`subject_prefix` qualifies each element of `groups` as well as `sub`, from the same lookup)

Amends [ADR-0003](0003-token-backends.md) (the shape of the token the STS mints: `sub` may carry a
prefix) and [ADR-0017](0017-issuer-profiles.md) (the issuer's keys: one more, `subject_prefix`).
Changes a token shape and the broker's configuration contract. Changes no SPIFFE ID, no storage
contract, no route and no trust boundary: what reaches a resource server across TB-7 is the same token
with one claim spelled so that it cannot be read as somebody else.

## Context

The broker trusts a list of upstream issuers (`issuers:` in `mediatore.yaml`, `IssuerConfig` in
`crates/mediatore-entra/src/lib.rs`). A person is validated at exactly one of them, and the
broker's own notion of a person is the pair: `Subject { issuer, id }`
(`crates/mediatore-proto/src/lib.rs`), where `id` is the value of the issuer's `subject_claim`.

A subject id is unique only inside the issuer that gave it. `octocat` at a Dex in front of GitHub
and `octocat` at a second Dex in front of a company directory are two people. Two issuers that both
use `subject_claim: email` (Google and Auth0, the two profiles of ADR-0017) overlap by construction:
the same address can be an account at each.

The token the STS mints (`mint_at`, `crates/mediatore-sts/src/lib.rs`) wrote the bare id as `sub`
and the issuer's URL as `upstream_iss`. A resource server validates the token against the broker's
JWKS and then, in almost every product that takes a JWT, maps `sub` to an account. It does not read
a claim it has never heard of. So with two issuers whose subject spaces overlap, such a resource
server treats two different people as one, and the second inherits whatever the first is allowed.

Nothing in the configuration said so. Adding a second issuer was one more list item, and the
overlap was created by omission.

### What the broker itself compares

Every place the broker uses a subject as an identity was read for this ADR. Each one already
carries the issuer, so none of them changes:

| Place | What it compares or keys by |
| --- | --- |
| The owner of a claim: `GET`, `DELETE` and the logs of `/v1/claims/{name}` (`owned_sandbox`, `owned_claim`, `owned_record_for_logs`, `crates/mediatore-api/src/lib.rs`) | `issuer` and `id`, both |
| The `AgentSandbox` (`spec.subject`) and the claim's record (`ClaimRecord.subject`) | the whole `Subject`: issuer, id and display |
| A sandbox whose issuer the broker is not configured with | refused at reconcile, before a claim exists (`crates/mediatore-claims/src/sandbox.rs`) |
| A claim whose issuer was removed from the configuration | no token (`still_configured`, `crates/mediatore-api/src/lib.rs`) |
| A refreshed session naming another subject | the refresh is made at the record's issuer and validated as that issuer (`validate_as` pins `iss`), then the id is compared: one issuer on both sides |
| Parked sessions and delegations, and the sealed envelopes | keyed by the sandbox UID or the claim UID, never by a subject id |
| The user in the guest | `sb-` and a hash of `issuer \| id` (`Subject::sandbox_username`) |
| `GET /v1/me` and every token answer to the guest | the whole `Subject` |
| An Entra On-Behalf-Of token | minted by Entra for its own subject; the broker writes no `sub` |
| Group gates (the issuer's, the namespace map's) | evaluated on the groups of the token of the issuer that was validated; the spelling question is ADR-0046's |

The one place a subject left the broker without its issuer attached to the identifying claim was
the STS token. That is what this ADR changes.

## Decision

1. **`issuers[].subject_prefix`, optional: what the STS puts in front of this issuer's subject id
   in `sub`.** `subject_prefix: "dex:"` makes `sub` `dex:octocat`. The form is fixed: 1 to 31
   characters of `a-z`, `0-9`, `.`, `_` and `-`, the first a letter or a digit, followed by exactly
   one `:`, 32 bytes at most. Lower case only, so a resource server that folds case cannot merge two
   prefixes. The delimiter is last and appears nowhere else, so the prefix of a `sub` is everything
   up to and including its first `:`, whatever the id holds after it. Anything else is a start
   error naming `issuers[<url>].subject_prefix`, with one issuer or several, with an `sts` or
   without. `upstream_iss` stays, with the issuer's URL: nothing that reads it today changes.

   Control: `subject_prefix_is_well_formed` and `SubjectPrefixes::new`
   (`crates/mediatore-sts/src/lib.rs`), `Config::check_subject_prefixes`
   (`crates/mediatore/src/config.rs`). Tests:
   `a_prefix_outside_the_charset_or_without_the_delimiter_is_refused`,
   `a_prefixed_issuers_sub_is_the_prefix_then_the_subject_id` (sts);
   `a_malformed_subject_prefix_refuses_to_start_whatever_the_number_of_issuers` (config).

2. **One issuer and no prefix: `sub` is the bare id, as before.** A deployment with one issuer
   that changes nothing gets the same token, byte for byte in every claim. One issuer with a prefix
   is allowed, and is what a deployment sets ahead of adding a second.

   Tests: `one_issuer_without_a_prefix_keeps_the_bare_sub` (sts),
   `one_issuer_needs_no_subject_prefix_and_may_have_one` (config),
   `one_issuer_without_a_prefix_mints_the_bare_sub` (e2e).

3. **Two or more issuers under an `sts`: every issuer has a prefix and no two overlap, or the
   broker does not start.** "Overlap" is: equal, or one the start of the other. Under decision 1's
   form the second cannot happen without the first (a prefix that began another would put its `:`
   inside the other's body), and the check tests for both anyway so that the property does not rest
   on the form alone. With that, `prefix_a + id_a` equals `prefix_b + id_b` only when the issuer is
   the same: two issuers can never be minted the same `sub`.

   There is no default and nothing is derived from the URL. A prefix invented by the broker would
   be a name the operator never agreed with a resource server, and one that changes when a URL
   does. The start error names the key and the issuer:
   `issuers[https://accounts.example.com].subject_prefix is not set: with 2 issuers every one needs
   a subject_prefix ...`.

   This is the fail-closed half. An overlapping subject space cannot be configured by omission.

   Control: `SubjectPrefixes::new`, called by `Config::parse` through
   `Config::check_subject_prefixes`. Tests:
   `two_issuers_without_prefixes_are_refused_naming_the_key`,
   `two_issuers_with_one_prefix_missing_are_refused`,
   `two_issuers_with_the_same_prefix_are_refused`, `no_prefix_can_be_the_start_of_another`,
   `the_same_subject_id_at_two_issuers_mints_two_different_subs` (sts);
   `two_issuers_without_subject_prefixes_refuse_to_start_under_an_sts`,
   `two_issuers_with_one_subject_prefix_missing_refuse_to_start`,
   `two_issuers_with_the_same_subject_prefix_refuse_to_start`,
   `two_issuers_with_distinct_subject_prefixes_start` (config);
   `two_issuers_without_subject_prefixes_refuse_to_start` (e2e, the real binary: exit status 1 and
   the key on stderr), `the_same_subject_id_at_two_issuers_gets_two_different_subs` (e2e, one
   address logged in at the Google and at the Auth0 profile).

4. **The STS is built from the checked set and refuses what the set does not cover.**
   `SubjectPrefixes` has one constructor, the check of decision 3, so the type itself is the
   evidence. `sts` in `crates/mediatore/src/main.rs` builds the set from the configuration again
   and hands it to `Sts::with_subject_prefixes`. At mint, a subject whose issuer has no prefix
   while any issuer has one is `StsError::NoSubjectPrefix`: the route answers `500` and no token is
   signed. The bare id is minted only when no issuer has a prefix at all.

   Test: `an_issuer_without_an_entry_is_refused_at_mint_once_any_prefix_is_configured` (sts).

5. **Without an `sts` section the set is not required, only the form.** A broker with no `sts`
   signs no token: its audiences are On-Behalf-Of, secrets, delegated credentials or none, and none
   of those carries a `sub` the broker wrote. Requiring prefixes there would stop a working
   deployment for a claim it never issues. The day an `sts` section is added, the same file is
   refused until the prefixes are there.

   Test: `without_an_sts_no_sub_is_minted_and_two_issuers_need_no_subject_prefix` (config).

6. **The prefix is in the token and nowhere else.** `spec.subject` on the `AgentSandbox`, the
   claim's record, the answer of `GET /v1/me`, the user in the guest and the CLI's listings keep
   the raw id with the issuer's URL beside it. The broker's own comparisons already use both
   (the table above), and a prefix stored in a record would make a rename of the prefix a
   migration.

7. **The start says which form `sub` takes.** One `info` line per issuer under an `sts`: its
   `subject_prefix`, or that `sub` is the bare id. Five audit lines of the user API that named a
   subject without a claim or sandbox UID beside it (the two policy-source lines of ADR-0054 and
   the three On-Behalf-Of lines) now carry `issuer` as well; the others name a claim UID or a
   sandbox, which resolves to one record.

   Test: `startup_logs_each_issuers_subject_prefix_or_that_sub_is_the_bare_id` (config).

## Security analysis

TB-7 is where a token the broker minted reaches a downstream resource server. TB-5 is the broker's
trust in its upstream issuers, which the `issuers:` list states.

| Boundary | Threat | STRIDE | Control |
| --- | --- | --- | --- |
| TB-7 | Two people with the same subject id at two trusted issuers are minted the same `sub`, and a resource server that authorizes on `sub` gives one the other's access | S/E | With two or more issuers under an `sts` every issuer has a `subject_prefix` and no two overlap, checked at start (`SubjectPrefixes::new`, `crates/mediatore-sts/src/lib.rs`; `Config::check_subject_prefixes`, `crates/mediatore/src/config.rs`); `sub` is the prefix then the id (`SubjectPrefixes::sub`). `the_same_subject_id_at_two_issuers_mints_two_different_subs`, `the_same_subject_id_at_two_issuers_gets_two_different_subs` (`crates/mediatore/tests/e2e_issuers.rs`) |
| TB-5 | A second issuer added without prefixes, so the overlap exists by omission | E | The broker does not start; the error names `issuers[<url>].subject_prefix` (`two_issuers_without_subject_prefixes_refuse_to_start`, the real binary, `crates/mediatore/tests/e2e_issuers.rs`) |
| TB-7 | A prefix chosen so that one issuer's qualified `sub` equals another's (`a:` beside `a:b:`, `Dex:` beside `dex:` at a verifier that folds case) | S | The form: lower case, one `:` and only at the end, and the set check refuses a prefix that starts another (`a_prefix_outside_the_charset_or_without_the_delimiter_is_refused`, `no_prefix_can_be_the_start_of_another`) |
| TB-7 | An STS built or reached with a set that does not cover the subject's issuer mints its bare id beside qualified ones | S | `SubjectPrefixes` is built only by the check; a subject without a prefix under a non-empty set is `StsError::NoSubjectPrefix` and nothing is signed (`an_issuer_without_an_entry_is_refused_at_mint_once_any_prefix_is_configured`) |
| TB-7 | An audit trail at the resource server that cannot say which issuer a `sub` came from | R | The prefix is readable and the operator's own choice; `upstream_iss` is unchanged; the broker's start log names each issuer's prefix |
| TB-5 | A prefix that leaks something | I | A prefix is configuration, a short name the operator picks; it carries no credential and appears in a token beside the issuer's full URL, which was already there |
| TB-5 | The check stopping a broker that issues no `sub` | D | Without an `sts` only the form is checked (decision 5) |

Tampering is not in the table: the token is signed as before, and the prefix is inside the signed
payload.

## Consequences

- **A deployment with one issuer sees no change** unless it sets the key.
- **A deployment with two or more issuers and an `sts` does not start on the release that carries
  this ADR until it adds prefixes.** That is the point, and it is a breaking change for those
  deployments: the release note says so, and the start error says which key.
- **Adding prefixes changes `sub` for every issuer, the first one included.** `octocat` becomes
  `dex:octocat` on the restart. A resource server that maps `sub` to an account needs the new value
  before that restart. Tokens live fifteen minutes at most, so the two spellings overlap for no
  longer than that.
- **A deployment that never had two issuers at once is outside decision 3.** Replacing the one
  issuer with another, with no prefix before or after, leaves the old issuer's ids and the new
  one's in the same bare space at a resource server that remembers accounts. The guide says to
  give the new issuer a prefix at the switch, and that a deployment which may ever trust a second
  issuer should set one from the first day. The broker cannot check a history it does not keep.
- **A subject space that overlaps inside one issuer is not this ADR's.** One issuer that federates
  several directories under one `subject_claim` decides what its ids mean; the choice of
  `subject_claim` is ADR-0017's.
- `IssuerConfig` rejects unknown keys (ADR-0046 decision 17), so a broker older than this ADR
  refuses a file with `subject_prefix`: the configuration follows the broker, never the reverse.
- The kind tiers' broker trusts two issuers under an `sts`, so its fixture carries prefixes
  (`example:`, `dex:`) and the Dex tier's token check expects `dex:octocat`.

## Alternatives rejected

- **Always qualifying `sub`.** Every deployment with one issuer would have its resource servers'
  account mapping broken on upgrade, to defend against an overlap it cannot have. The cost lands on
  everybody and the benefit on nobody new.
- **A hash of the issuer and the id as `sub`.** Unambiguous and needs no configuration, but opaque:
  the resource server's own audit log would name `f3a9...` and nobody reading it could say who that
  is without the broker. It also changes every deployment's `sub`, as the alternative above does.
- **Leaving it to `upstream_iss`.** It is there today and the finding stands: a verifier that reads
  only `sub` is the common case, and a control that works only for the resource servers that
  implement an extra check is not a control the broker can claim.
- **A prefix derived from the issuer's URL** (its host, say). No configuration, but two issuers on
  one host with different paths (two Entra tenants) collide, a URL change renames every account,
  and the operator never chose the name the resource server has to be given.
- **The issuer's URL itself as the prefix** (`https://dex.example.com|octocat`). Unambiguous, but
  long, full of characters that account names in resource servers do not accept, and it still
  changes every single-issuer deployment unless made optional, at which point it is this decision
  with a worse spelling.
- **Requiring the prefixes even without an `sts`.** Simpler to state. It stops deployments that
  sign nothing, for a claim they never issue (decision 5).
- **Storing the qualified id in the record or on the sandbox.** The broker already compares issuer
  and id; a second spelling of the same identity in storage would have to be migrated when a prefix
  is renamed and could disagree with the first.

## What must be proven

Each of these is a test named above, written before the code it holds.

- Unit, `crates/mediatore-sts/src/lib.rs`: the form; one issuer bare; a prefixed `sub`; two issuers
  with the same id minted two `sub`s; the three refusals of a set (none, one missing, the same
  twice); a prefix that would start another; the refusal at mint.
- Unit, `crates/mediatore/src/config.rs`: the same refusals as start errors that name the key;
  two distinct prefixes start; one issuer with and without; no `sts`; the start log; and every
  shipped configuration and every configuration block in the guides still parses
  (`every_issuer_in_the_shipped_examples_and_guides_parses`).
- End to end, `crates/mediatore/tests/e2e_issuers.rs`: one address logged in at two issuers through
  the real login code gets two claims whose tokens carry two different `sub`s; one issuer without a
  prefix mints the bare id; the real binary given two issuers without prefixes exits with status 1
  and the key on stderr, and the same with one prefix missing and with the same prefix twice.
- Live: the kind tiers whose broker reads `dev/kind/broker/mediatore.yaml` start with the prefixed
  fixture, and the Dex tier's token carries `dex:octocat`.
