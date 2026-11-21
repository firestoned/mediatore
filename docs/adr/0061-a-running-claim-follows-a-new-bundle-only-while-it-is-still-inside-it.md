<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0061: A running claim follows a new bundle version only while it is still inside it

**Status:** Accepted 2026-11-21 (the four open questions decided by the maintainer at their recommendations); not yet implemented · **Date:** 2026-11-21

Amends [ADR-0053](0053-an-audience-scoped-to-namespaces-each-with-its-own-rules.md) decision 12
(every use reads the current bundle). Builds on [ADR-0026](0026-notaio-bundles-verified-in-shadow.md)
decision 6 (what the claim's record keeps of its policy),
[ADR-0054](0054-which-policies-a-namespace-may-name.md) (where a policy is resolved),
[ADR-0055](0055-audiences-from-signed-sandboxaudience-bundles.md) (audience definitions from
bundles) and [ADR-0057](0057-a-claims-record-written-by-compare-and-set-and-bound-to-its-sandbox.md)
(the record written by compare-and-set). notaio's roadmap 00, phase 2, "at every mint", states the
same rule from notaio's side.

## Context

A claim is admitted under one version of its policy's bundle. When the policy changes, notaio
publishes a newer version. ADR-0053 decision 12 has every mint, `GET /v1/me` and gateway answer
read the policy's **current** verified bundle, found by the policy `uid` the record holds, and the
version floor keeps that bundle from ever being older than one already accepted. That is right
at the two outer enforcement points: an audience removed, a rule narrowed, a lifetime shortened
or direct egress closed narrows the running claim at its next request, at the broker's mint and
the gateway's answer.

It is not enough in two places that exist today:

1. **The guest renders once.** `wait_for_subject` (`crates/mediatore-guest/src/guest.rs`)
   returns on the first `200` from `GET /v1/me`, and nothing reads `/v1/me` again during the
   lease; later calls are the report, the logs and the exit. From that one answer the guest
   renders the nftables ruleset (egress and gateways), the egress proxy's routes and rules, and
   Landlock's ports. When a newer version narrows an audience's rules or egress, the broker and
   the gateway narrow and the jail's inner layer stays as it was rendered until the lease ends.
   The outer enforcement point holds; defence in depth runs at the old version.
2. **What is checked only at the claim is never checked again.** `ttl_seconds` against the
   bundle's `lease.maxDurationSeconds` is a claim-time check (`admit_under_policy`,
   `refuse_under_policy`); a version that shortens the lease does not touch a running claim.
   Eligibility by `subjects.groups`, once it exists, would be the same.

A mint, `/v1/me` and the gateway's answer already repeat the rest of admission:
`claims_bundle` finds the bundle by the recorded `uid`, verified and unexpired, signed for a
namespace the claim's namespace still draws from (ADR-0054); `effective_in` keeps only the
audiences the bundle still grants inside the ceiling, applies ADR-0055 decision 3 to a team
audience, and caps the lifetime.

Two further cases arrive when the guest renders its jail from the bundle's knobs and tools
(notaio's phase 3, D4): a tightened knob would leave a running sandbox in a looser jail while it
receives tokens under the newer version's grants, a combination notaio's lint never evaluated, and
an expiring `KnobGrant` would last until the lease ends instead of until its `expiresAt`.
mediatore reads no knobs today (`Me` has no knob or profile field, the guest has no bundle
dependency), so those cases do not exist yet. This ADR leaves room for them and decides nothing
about them.

Refusing on every new version, which notaio's roadmap first wrote, would end every running
sandbox on any change, including the narrowings decision 12 already handles well. Following on
every new version leaves the two gaps above. The rule here sits between them.

## Decision

1. **A running claim follows a newer version only while it is still inside it.** At every mint,
   `GET /v1/me` and gateway answer, with `current` the claim's current verified bundle
   (`claims_bundle`) and `rendered` what the record kept when the guest rendered (decision 2):
   1. `current` is missing, unverified or expired: the claim's audiences are dropped, as today.
   2. `current`'s version is the one `rendered` names: served, as today.
   3. Otherwise served under `current` only if every leg of decision 3 holds; if any does not,
      the claim is refused with `policy_changed` (decision 4).

   Narrowing the audiences, the lifetime or the gateway's answer stays what decision 12 made it,
   so a change the sandbox is already inside never ends it.

2. **The record keeps what the guest was handed.** A new field on the claim's record,
   `rendered`, written once by compare-and-set (ADR-0057) when `GET /v1/me` first answers `200`
   for the claim, and never overwritten:
   - the bundle's version and the SHA-256 of its verified payload;
   - the routes as `/v1/me` answered them (audience, endpoint, rules) and the egress list.
   It holds no credential and no header value. A claim with no policy keeps no `rendered`. The
   bundle cache holds only the current version, so what an older version said cannot be
   recovered later: it is recorded at the moment the guest takes it. The knob set and the tools
   with their digests join `rendered` when the guest renders from them (phase 3).

3. **The legs, one pure function.** `serve_under(rendered, current, claim) -> Result<(), Reason>`
   in `mediatore-claims`, used by the mint, `/v1/me`, the gateway's answer and the reconciler, so
   they cannot disagree:
   - **Admission** (`PolicyUnresolved`, `LeaseExceeded`): the claim would be admitted under
     `current`. The policy's name still resolves, in the namespace's sources, to the same `uid`
     (ADR-0054); `ttl_seconds` is within `current`'s `lease.maxDurationSeconds`. The audiences are
     already filtered per answer and are not a leg here. Eligibility by group joins this leg when
     it exists (`NotEligible`).
   - **What the guest rendered** (`RenderedWider`): every route `rendered` holds is covered by a
     route the claim has under `current` (the same endpoint, each rule covered by `rule_covers`),
     and every egress endpoint `rendered` holds is in the claim's egress under `current`
     (`egress_of`). The inner layer may be tighter than `current`; it may never be wider.
   - With phase 3, **knobs** (`KnobTightened`) and **tools** (`ToolRemoved`), as notaio's roadmap
     states them. Not built here.

   A claim recorded before this ADR has a `bundle_version` and no `rendered`. It is served while
   `current` is that version, and at the first different one it is refused: it is never treated
   as if the guest had rendered nothing.

4. **A refusal is final for the claim, and says why.** Under enforce (decision 5):
   - a mint answers `403 policy_changed`, its body naming the reason (`lease_exceeded`,
     `policy_unresolved`, `rendered_wider`) and never a rule, a host or a token;
   - the gateway's answer for the claim is a deny, as for a released claim;
   - the reconciler sets a `PolicyFollowed` condition on the `AgentSandbox`, `False`, with the
     reason and both versions; it is the condition's only writer, as for every other condition;
   - one audit line names the claim, the policy `uid`, both versions and the reason.
   Tokens already minted run out within their lifetime; nothing is revoked. A refused claim stays
   refused even if a later version would admit it again.

5. **Shadow first: a switch of its own, `policy.follow: shadow | enforce`, default `shadow`.**
   Under `shadow` nothing is refused; each would-refuse is logged once per claim and version with
   its reason (`would_refuse`), and the reconciler sets `PolicyFollowed` to `False` with the
   reason, so the condition counts the cases per namespace. `enforce` refuses as decision 4 says.
   The rule only bites where the bundle is the authority: under `policy.audiences: shadow` it
   is reported, never enforced, whatever `policy.follow` says. A misspelling refuses the start.

6. **Nothing fails open.** A `rendered` that cannot be read or written leaves the claim unserved
   under `enforce` at the first changed version, as a claim with no `rendered`. A `current` that
   is the same version as `rendered` with a different payload digest is refused under `enforce`
   (`rendered_wider` is not the reason; `bundle_changed_in_place`), because a signed bundle never
   changes under one version.

## Open questions

Decided 2026-11-21 by the maintainer: each at its recommendation.

1. **Refuse, or have the guest render again?** nftables and the proxy's routes could be
   re-rendered on a narrowing; Landlock cannot be re-applied to a running process, so a re-render
   is possible for a narrowing and not in general. *Recommendation:* refuse (decision 4) now, and
   revisit with D4, when the guest gains a reason to re-read the bundle at all.
2. **Release the claim, or leave it to its owner?** The broker already releases a claim on the
   workload's exit (ADR-0033) and on the subject's `DELETE`. *Recommendation:* leave it; the
   condition tells the owner, the deadline bounds the VM, and the broker gains no new release
   path. Revisit if refused claims hold pool members long enough to matter.
3. **The version in the token (D6).** With this rule a claim spans versions. *Recommendation:*
   when D6 is decided, a token carries the version it was minted under, never the claim's first.
   Nothing to build here.
4. **Alerting.** *Recommendation:* routine. The audit line is `info`; `rendered_wider` and
   `bundle_changed_in_place` are `warn`. What alerts is the operator's choice.

## Consequences

- The jail's inner layer is never wider than the policy the claim is served under, and a lease
  shortened by a newer version reaches running claims.
- A narrowing of rules or egress ends a running sandbox under `enforce` instead of narrowing it
  outside the VM only. That is the price of refusing over re-rendering (open question 1), and
  `shadow` shows how often it happens before anything is refused.
- The record grows by the routes and egress `/v1/me` handed out: small, no secret.
- Storage contract change (a new record field), so CALM's record description and the threat
  model change with it.

## What is not decided here

The knob and tool legs and their tests (phase 3, with D4), eligibility by group (its own ADR, per
ADR-0054 decision 7), and the token's policy claim (D6).
