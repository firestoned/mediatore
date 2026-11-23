<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0065: A sandbox under several policies, the first named wins

**Status:** Proposed (no implementation yet; CALM, the tests and the threat-model pass are owed
before it is accepted) · **Date:** 2026-11-23

Roadmap 16. Amends [ADR-0026](0026-notaio-bundles-verified-in-shadow.md) decision 6 (one
`policyRef` per sandbox), [ADR-0054](0054-which-policies-a-namespace-may-name.md) decision 1 (the
rule resolves one name; it now resolves each of a list) and
[ADR-0061](0061-a-running-claim-follows-a-new-bundle-only-while-it-is-still-inside-it.md)
decisions 2 and 3 (what the record keeps and what `serve_under` compares). Adds one optional
field to the `AgentSandbox` spec in both served versions
([ADR-0048](0048-agentsandbox-served-as-v1beta1.md),
[ADR-0049](0049-agentsandbox-served-as-v1alpha1-and-v1beta1.md)) and one to the claim record
([ADR-0057](0057-a-claims-record-written-by-compare-and-set-and-bound-to-its-sandbox.md)).
Changes no token shape, no SPIFFE ID and no signed artifact: notaio still signs one bundle per
`SandboxPolicy`, and every bundle is verified alone, as today.

## Context

A sandbox names one `SandboxPolicy` (`spec.policyRef`, `crates/mediatore-claims/src/sandbox.rs`).
Under `policy.audiences: enforce` that one bundle is the whole of what the claim may use: its
audiences, their endpoints and rules, its direct egress, its lease, its knobs
(`claims_bundle` and `egress_of` in `crates/mediatore-api/src/lib.rs`).

Policies are written per capability, and reviewed per capability. In the homelab's policy
repository `claude-agent` grants `anthropic` and `git-agent` grants `github-git`, each with its
own ceiling and its own review. A workload that needs both (Claude Code that clones a private
repository and then works on it) has two choices today, both bad:

- **A third policy that copies both.** `claude-git-agent` duplicates two grants, drifts from
  them at the next change of either, and needs its own review and ceiling approval for what is
  only a combination of two already approved.
- **Two sandboxes.** The clone and the agent do not share a filesystem, so this does not work
  at all.

What already exists and shapes the answer:

- **A bundle is verified and resolved alone.** `BundleCache::resolve` (ADR-0054) answers for one
  name in the namespace's sources: `Found`, `NotFound`, `Ambiguous`, `NotRead`. Nothing here
  needs to change to resolve several.
- **A bundle's content has two kinds of parts.** Named, keyed parts: `audiences` (by `name`),
  `egress` (by `endpoint`), `tools` (by `name`). And sandbox-wide parts that exist once per
  sandbox: `profile`, `knobs`, `lease`, `budgets`. Composition means a different thing for each.
- **Audiences are already checked twice.** Each audience the claim names must be configured on
  the broker for the sandbox's namespace (ADR-0053, `audiences_in`), and the grant in the bundle
  must cover what the broker would serve (`shadow::compare_with`, P001 to P005). Neither check
  cares which bundle the grant came from.
- **The record keeps one policy.** `policy_uid` and `bundle_version`, and since ADR-0061
  `rendered` with one bundle version and one payload digest. `serve_under` compares one
  `current` with one `rendered`.
- **`lease.maxConcurrent` is not enforced by the broker today.** Nothing reads it.

## Decision

1. **`spec.policyRefs`: an ordered list, the first named wins.** A new optional field on the
   `AgentSandbox` spec, in `v1alpha1` and `v1beta1`: a list of `LocalObjectReference`, one to
   four items, names unique (`x-kubernetes-list-type: set` is not used, because order matters;
   a CEL rule checks uniqueness). A sandbox carries exactly one of `policyRef` and `policyRefs`
   (a second CEL rule, in the shape of the `poolRef`/`poolSelector` rule). `policyRef: x` and
   `policyRefs: [x]` mean the same thing, and the reconciler treats them as one code path. The
   spec stays immutable. `POST /v1/claims` takes `policy_refs` beside `policy_ref` with the same
   exclusivity, and `mediatore sandbox create --policy` becomes repeatable, in the order given.

2. **Each name resolves alone, under ADR-0054, before anything is composed.** Every name in the
   list must resolve to `Found` in the sandbox namespace's sources. Any `NotFound` or
   `Ambiguous` refuses the sandbox under `enforce` with the code of that name (P011, P012),
   naming which entry of the list failed; any `NotRead` holds it. A list that names the same
   policy `uid` twice (two names, one object, impossible today but cheap to state) is refused.

3. **The composition, one pure function.** `compose(&[Arc<BundlePayload>]) -> Composite` in
   `crates/mediatore-claims/src/policy.rs`, the only place the rule lives, used by the
   reconciler, the front door, the mint, `/v1/me`, the gateway's answer and `serve_under`, so
   none of them can disagree:
   - **Named parts are a union, keyed; on a collision the first policy's entry is taken whole.**
     An audience grant named by two policies is the first one's grant, all of it: its access,
     scopes, TTL, endpoints and rules. Never a field-by-field merge: a merged grant is one that
     nobody wrote and nobody reviewed. The same for a direct egress entry (keyed by `endpoint`,
     the first one's rules) and a tool (keyed by `name`, the first one's manifest digest).
   - **Sandbox-wide parts are the first policy's.** `profile`, `knobs`, `lease` and `budgets`
     come from the first bundle in the list, and only from it.
   - **The `Composite` remembers where each part came from:** for every audience, egress entry
     and tool, the index of the policy that supplied it, so a finding, an audit line and the
     status can say "audience `github-git` from `git-agent`".

4. **The first policy may not be looser than a later one on a sandbox-wide part.** "First wins"
   decides which value is taken; it must not hand a later policy's author a sandbox they never
   allowed. So composition is refused (`P013`, `policy_composition_looser`) when the first
   bundle's sandbox-wide parts are wider than any later bundle's:
   - a knob whose step is above the later bundle's step for the same knob (`Step::index`);
   - `lease.maxDurationSeconds` above the later one's;
   - any budget above the later one's.
   The sandbox's `ttlSeconds` is then checked against the first lease (P005), which is now the
   tightest of the list. The fix for a refused list is to name the tighter policy first, or to
   tighten it in the policy repository. `profile` is not compared: it is a name and a digest,
   and what it means is in the knobs.

5. **Composition is the operator's choice, per sandbox namespace, off by default.**
   `policy.max_policies` (default `1`) and the same key on a `policy.sources` entry (ADR-0054
   decision 2, whose struct entry was made for a later narrowing like this one). A list longer
   than the namespace's limit is refused before anything resolves (`P014`,
   `too_many_policies`). With the default, nothing changes for any existing deployment: a
   `policyRefs` of one item is accepted, a longer one is refused.

6. **The record keeps the list, in order.** A new field `policies: [{uid, version}]` on the
   claim record, written at creation like `policy_uid` today. `policy_uid` and
   `bundle_version` keep the first entry's values, so a replica from before this ADR serves
   the claim under its first policy alone: narrower, never wider, which is the safe side of a
   mixed rollout. `rendered` (ADR-0061 decision 2) keeps the list of `{uid, version, payload
   digest}` and the routes and egress as the guest took them from the composite.

7. **Following a newer bundle follows the composite.** `serve_under` (ADR-0061 decision 3)
   takes the `Composite` of the current bundles of the recorded uids, in the recorded order.
   The admission leg holds when every name still resolves to its recorded `uid` and decision 4
   still holds; the rendered leg is unchanged, against the composite. A new version of any one
   policy in the list is a new composite and is judged as one. `bundle_changed_in_place`
   applies per entry.

8. **The shadow verdict reports against the composite.** `compare_with` takes the `Composite`.
   P001 becomes "audience not granted by any policy of the list"; every other finding names
   the policy that supplied the part it is about. P013 and P014 are new codes, reported under
   `shadow` and refusing under `enforce`, like P011 and P012.

9. **What is not composed.** Group eligibility (ADR-0046, and the policy's `groups` once the
   broker reads them): the requester must be eligible for **every** policy of the list, never
   any one of them. `lease.maxConcurrent`, when the broker enforces it, counts the sandbox
   against every policy of the list. The audience configuration of ADR-0053 is unchanged: an
   audience must be configured for the namespace whichever policy grants it.

## Consequences

- One sandbox can be under `claude-agent` and `git-agent` together, each reviewed and approved
  once, with no third policy to keep in step.
- A combination is something no single review saw. The worst case is direct egress from one
  policy beside an audience from another: data read through the second can leave through the
  first. Decision 5 keeps this off until an operator turns it on for a namespace; the
  threat-model pass records the combination as a risk, with decision 5 as its control.
- What a sandbox may do is no longer one signed artifact but a function of several. The audit
  line on admission and on every follow names the ordered `uid`s and versions and the
  composite's digest (SHA-256 over the canonical bytes of the composite), so the answer to
  "what was this claim allowed" is still one value.
- `PolicyConformant` and `PolicyFollowed` messages get longer: they name the policy a finding
  is about.
- The CRD grows a field in both served versions; the CLI's `--policy` changes from single to
  repeatable, which accepts every command line that worked before.
- No change to notaio, to the bundle format or to `sandboxpolicy-bundle`.

## Alternatives considered

- **Most restrictive wins on sandbox-wide parts, silently.** Taking the minimum of every knob,
  lease and budget always produces a safe sandbox, but the maintainer's rule is that the first
  named wins, and a silent minimum makes the order meaningless and the result surprising.
  Decision 4 keeps the first-wins rule and refuses, with a reason, the one case where it would
  loosen something.
- **Field-by-field merge of a shared audience.** Rejected in decision 3: the result is a grant
  nobody wrote.
- **A composite signed by notaio** (a `SandboxPolicy` that includes others, resolved and signed
  at publish time). The cleanest audit story, and the right long-term shape if composition
  becomes common, but it is a notaio schema change and moves the decision away from the
  sandbox that needs it. Revisit if the audit line of the consequences proves not enough.
- **A third policy per combination.** What has to be done today; it is what this ADR removes.

## Open questions

1. **Decision 4 or pure first-wins?** Pure first-wins lets a broad first policy widen the lease
   or the knobs under which a later policy's audience is used. *Recommendation:* decision 4 as
   written; revisit if real lists keep being refused for it.
2. **The limit of four.** Enough for a capability split (model, source, registry, one more).
   *Recommendation:* four in the CRD; the operator's `max_policies` narrows it.
3. **Should a policy be able to refuse being composed?** notaio could carry a
   `composable: false`. *Recommendation:* not now; decision 5 is the operator's control.
