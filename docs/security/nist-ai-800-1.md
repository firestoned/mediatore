<!--
Copyright (c) 2026 Erick Bourgeois, mediatore
SPDX-License-Identifier: Apache-2.0
-->
# NIST AI 800-1: a crosswalk to mediatore

> **Status:** Reference document, written 2026-11-26 against the **initial public draft** of
> NIST AI 800-1, *Managing Misuse Risk for Dual-Use Foundation Models* (U.S. AI Safety
> Institute, July 2024, <https://doi.org/10.6028/NIST.AI.800-1.ipd>). Later drafts renumber
> or reword practices; check the version before citing a row. This document maps practices
> to controls. It is not a claim of conformance, and it adds no control: every control it
> names exists in `crates/`, `deploy/` or `image/`, or is marked as proposed or as a gap.

## Why a model-misuse guideline applies to an identity broker

800-1 is written for the organizations that train foundation models. Its §2 names the
others in the chain ("downstream developers and deployers", the "cloud service provider that
leads deployment") as sharing the work without being its focus. mediatore sits in that chain
as deployment infrastructure: it decides **who** may run an agent, **which** model and service
APIs that agent may reach, **with what credential**, and **what is recorded** about it. It
never trains or hosts a model and never reads a prompt.

So the practices fall into three groups:

- **Ones mediatore implements for the operator** who deploys agents: limiting access,
  attributing use to a person, detecting and cutting off misuse, keeping monitoring private
  (Objective 6, Appendix B).
- **Ones mediatore's own project practises**, as any security-critical open-source project
  should: threat profiles, red teaming, disclosure, transparency (Objectives 1, 4, 6.4, 7).
- **Ones outside its reach**: training data, capability evaluation, weight release decisions
  (Objectives 3 and 4.1 in the main, the first and fourth rows of Appendix B). These are
  listed so the gap is stated rather than silent.

The threat actor 800-1 has in mind is a person misusing a model. mediatore's design case adds
one more: the agent itself, prompt-injected or otherwise misaligned, acting against the person
who started it. The [threat model](threat-model.md) §4 classes the jailed workload as "hostile
by assumption", and most rows below are read with both actors in mind.

**Legend.** **Met**: a control exists and is cited. **Partial**: a control covers part of the
practice; the gap is stated. **Proposed**: an ADR or roadmap covers it, nothing is built.
**Gap**: nothing covers it yet. **Out of scope**: belongs to the model developer.

## Appendix B: example safeguards

Appendix B is where mediatore maps most directly, so it comes first.

| Safeguard (800-1 Table 1) | Status | mediatore |
| --- | --- | --- |
| Improve the model's training | Out of scope | mediatore does not train models. |
| Detect and block attempted misuse: infrastructure around the model that monitors for misuse | Partial | Every token issue is one audit line naming claim, audience, subject, backend and expiry, never the credential (`issue_token` in `crates/mediatore-api/src/lib.rs`, pinned by the test `each_issue_is_one_audit_line_with_claim_audience_subject_backend_and_expiry_and_never_the_credential`). The gateway refuses any authority outside the claim's routes ([ADR-0030](../adr/0030-policy-egress-enforced-at-the-gateway.md), `crates/mediatore-gateway`). No content classifier, by design: see "Privacy" below. The gateway's decisions are reported to the broker, one line each ([ADR-0062](../adr/0062-the-gateway-reports-its-decisions-to-the-broker.md), `crates/mediatore-gateway/src/report.rs`). Behavioural detection is proposed: tripwires on the VM (ADR-0069, roadmap 17) and beyond it (ADR-0070, roadmap 18). |
| Detect and block: block unsafe queries, place limitations on users who misuse or circumvent safeguards | Partial | Token issue is rate-limited per claim (`429 rate_limited`, `crates/mediatore-api/src/lib.rs`). A requester can release a claim (`DELETE /v1/claims/{name}`), and a one-shot workload releases its own ([ADR-0033](../adr/0033-a-one-shot-workload-the-restart-policy-and-the-claim-released-when-it-is-done.md)). **Gap:** the operator's revoke is a stub that refuses (`revoke` in `crates/mediatore/src/main.rs`), and no limit follows a person across claims. ADR-0069 proposes a backoff after repeated trips. |
| Limit access: monitor with a limited audience, expand gradually | Met | Signed policy and audience bundles take effect in `shadow` before `enforce` (`EgressMode` in `crates/mediatore-claims/src/policy.rs`, [ADR-0026](../adr/0026-notaio-bundles-verified-in-shadow.md), [ADR-0055](../adr/0055-audiences-from-signed-sandboxaudience-bundles.md)), so a new audience can be watched before it is served. |
| Limit access: to contexts and users where risk is lower | Met | A claim is gated by the issuer's groups and, with a namespace map, by the groups listed for its namespace ([ADR-0046](../adr/0046-who-may-claim-a-list-of-groups-and-a-namespace-to-groups-mapping.md), `matched_group` in `crates/mediatore-api/src/lib.rs`). Which policies a namespace may name is bounded ([ADR-0054](../adr/0054-which-policies-a-namespace-may-name.md)). Eligibility per audience from the signed bundle is proposed ([ADR-0066](../adr/0066-eligibility-by-group-from-the-signed-bundle.md)). |
| Limit access: reduce it reactively when misuse is detected | Partial | A running claim is checked against its current bundle at every mint and gateway answer, and loses its audiences when that bundle is missing, unverified or expired ([ADR-0061](../adr/0061-a-running-claim-follows-a-new-bundle-only-while-it-is-still-inside-it.md); its refusal of a bundle that moved outside the claim runs behind `policy.follow: shadow` by default). Killing one sandbox on detection is proposed (ADR-0069). The operator's revoke is the gap named above. |
| Limit access: target particular capabilities | Met | Access is per audience, not per model provider account: a claim reaches only the audiences and direct egress its policy grants ([ADR-0030](../adr/0030-policy-egress-enforced-at-the-gateway.md)). A route narrowed to particular binaries inside the sandbox is roadmap 16 (not started). |
| Limit access: internal protections (log interactions, restrict to a subset, require several people, keep every interaction behind the safeguards) | Partial | The real model API credential never enters the sandbox: the workload holds a phantom token that the egress proxy swaps outside the jail ([ADR-0025](../adr/0025-phantom-token-egress-proxy.md), `crates/mediatore-guest/src/egress.rs`), so no interaction can skip the broker, its policy or its audit line. Each call is attributed to the person who claimed. **Gap:** nothing requires two people to approve a claim. |
| Ensure the access to weights is appropriate | Out of scope, with one aid | Release decisions belong to the developer. Where an operator serves weights to sandboxes, the controls under Objective 3 bound how they could leave. |
| Stop development if risk is too high | Out of scope | |

### Privacy (practice 6.1, recommendation 1: "while maintaining privacy of users")

mediatore detects misuse from **behaviour** (who claimed, which audience, which authority was
refused, how fast tokens were drawn), never from **content**. It never logs a token, a refresh
credential, a key or a request body (repository rule, and the audit test above). A workload's
output reaches its owner only through the redactor, which removes the claim's credentials in
literal, base64 and percent-encoded forms (`crates/mediatore-guest/src/redact.rs`, [ADR-0045](../adr/0045-a-sandbox-workloads-output-streamed-to-its-owner.md)), and is stored
sealed per batch ([ADR-0052](../adr/0052-a-sandbox-workloads-stored-output-sealed-per-batch-with-the-transit-key.md)). A content classifier on model traffic would contradict this
and is not planned; an operator who needs one places it at the model provider or as an
audience of its own.

## Objective 1: anticipate potential misuse risk

| Practice | Status | mediatore |
| --- | --- | --- |
| 1.1 Keep a list of threat profiles (capability of concern, actor, malicious task) | Partial | [threat-model.md](threat-model.md) lists actors (§4), boundaries (§5) and STRIDE per boundary (§6). **Gap:** no profiles in 800-1's shape. The candidates: an agent that takes credentials out of its sandbox; an agent that moves sideways to services it was not granted; a sandbox used to attack other systems (800-1 §1 names offensive cyber operations); a person who uses a sandbox to reach a model without attribution. Each would cite the STRIDE rows that cover it. |
| 1.2 Assess the impact of each profile | Partial | §8 Accepted risks states impact and *Revisit when* per risk. Impact per threat profile follows once 1.1 exists. |
| 1.3 Estimate capabilities before development | Out of scope | |

## Objective 2: establish plans for managing misuse risk

| Practice | Status | mediatore |
| --- | --- | --- |
| 2.1 Define unacceptable risk | Partial | §8 records which risks are accepted and on what condition they are revisited. The operator's own threshold is expressed as policy: which groups may claim, which audiences a policy grants. |
| 2.2 Keep a roadmap for managing misuse risk | Met | `ROADMAPS.md` and `.github/community/`, with every trust-boundary change behind an ADR first (`docs/adr/`). |

## Objective 3: manage the risk of model theft

mediatore does not hold weights. Where an operator lets sandboxes reach weights or an
inference server, these controls bound how they could leave (recommendation 3.3.2,
"protections against exfiltrating large amounts of data"):

| Practice | Status | mediatore |
| --- | --- | --- |
| 3.1 Assess theft risk, including insiders and red teams | Partial | The threat model treats the cluster operator and the API server's administrators as trusted (§4, §8), which is the insider case stated rather than mitigated. Red teaming: see 4.2. |
| 3.3 Security practices against theft and exfiltration | Partial | Egress is denied by default per sandbox uid in a per-claim nftables table ([ADR-0020](../adr/0020-jail-network-nftables-keyed-by-sandbox-uid.md), `crates/mediatore-guest/src/net.rs`); the jail may connect only to the proxy's port (Landlock, `crates/mediatore-guest/src/confine.rs`); raw and other socket families and `io_uring` are refused by seccomp ([ADR-0051](../adr/0051-socket-families-and-io-uring-denied-to-the-workload-by-seccomp.md), `crates/mediatore-guest/src/seccomp.rs`); everything that leaves goes through the gateway, which admits only the claim's routes ([ADR-0028](../adr/0028-egress-gateway-envoy-with-spiffe-identity.md), [ADR-0030](../adr/0030-policy-egress-enforced-at-the-gateway.md)); the cloud metadata service is dropped for every uid on Azure ([ADR-0068](../adr/0068-the-cloud-platforms-host-addresses-root-alone-on-azure-the-metadata-service-for-nobody.md), `image/host-table`). **Gap:** no volume limit; a claim may send as much as it likes to a route it was granted. |

## Objective 4: measure misuse risk

| Practice | Status | mediatore |
| --- | --- | --- |
| 4.1 Measure model capabilities | Out of scope | |
| 4.2 Red teams try to bypass model and system safeguards | Partial | The design assumes the attacker has read the source (recommendation 4.2.7, "at least as much information about the system as would be available to an attacker", is the default for an open-source project), and roadmap 17 states it as a design rule. The end-to-end suite drives refusals over real listeners (`crates/mediatore/tests/e2e_dev.rs`), and the kind tiers prove the gateway against the real Envoy. **Gap:** no independent red-team exercise with a stated goal, access level and period (recommendations 4.2.2, 4.2.3, 4.2.8, 4.2.9), and no adversarial agent suite that runs against a booted sandbox. |

## Objective 5: manage misuse risk before deploying

| Practice | Status | mediatore |
| --- | --- | --- |
| 5.1 Assess what each deployment's access level does to risk | Met | Each audience and each policy is a signed bundle ([ADR-0026](../adr/0026-notaio-bundles-verified-in-shadow.md), [ADR-0055](../adr/0055-audiences-from-signed-sandboxaudience-bundles.md)) approved through notaio's policy repository before mediatore will serve it, so a new level of access is a reviewed change. |
| 5.2 Safeguards proportionate to risk, with evidence they work | Partial | The safeguards are listed in threat-model §7 with file citations, and every implemented ADR ends with a threat-model pass. **Gap:** no evidence that detection works in production; see 6.1. |
| 5.3 Deploy only when risk is managed, with a margin | Met | `shadow` before `enforce` for bundles; fail closed throughout (an unimplemented path answers `501`). |

## Objective 6: collect and respond to information about misuse after deployment

| Practice | Status | mediatore |
| --- | --- | --- |
| 6.1 Monitor for misuse; automate detection; keep checking that detection works | Partial | Audit lines per issue, per claim create and per log read (`crates/mediatore-api/src/lib.rs`). The gateway's decisions reach the broker's log (ADR-0062). Detection signals are proposed: trips (ADR-0069, ADR-0070), a claim's egress on its sandbox's status ([ADR-0064](../adr/0064-a-claims-egress-summarised-on-its-sandboxs-status.md), Proposed), and metrics through roadmap 15 (not started). **Gap** against recommendation 6.1.3 ("evidence that misuse is not going undetected"): nothing checks on a schedule that a trip is still detected, contained and reported. |
| 6.2 Respond to incidents: roles, prepared plans, drills | Gap | Containment of one sandbox is proposed (ADR-0069). No written response runbook, no operator revoke (stub, above), and no drill that fires a synthetic incident (recommendation 6.2.4). |
| 6.3 Protect internal reporting | Not applicable | A project-governance practice for organizations with staff. |
| 6.4 Safe harbor for third-party research | Partial | `SECURITY.md` takes reports through GitHub private vulnerability reporting and states what is in scope. **Gap:** no safe-harbor statement for good-faith research. |
| 6.5 Bounties | Not applicable | No funded programme. |

## Objective 7: provide transparency about misuse risk

| Practice | Status | mediatore |
| --- | --- | --- |
| 7.1 Publish transparency reports on risks and safeguards | Met, for the project | The [threat model](threat-model.md) is public, dated and re-stamped after every implemented ADR; the ADRs carry their own STRIDE analysis. Specific unremediated findings are kept out of it (recommendation 7.1.2, "without rendering the safeguards ineffective"). |
| 7.2 Disclose risk-management practices for accountability | Met, for the project | The ADD cycle (ADR, CALM, TDD, docs, threat model) and the CALM model in `docs/architecture/calm/`. |
| 7.3 Report incidents in a machine-readable format | Gap | Audit lines are structured logs, not incident records. Nothing emits a misuse event (claim, subject, kind, time, never a credential or bait value) that an operator can forward to an incident database or a SIEM. |

## Gaps, in the order they are worth closing

1. **Operator revoke.** The admin endpoint behind `mediatore revoke` is not wired. Appendix B
   "reduce access reactively" and practice 6.2 both depend on it.
2. **Detection that is proven to work (6.1.3).** A scheduled canary claim that takes a
   tripwire on purpose and checks the kill and the report. Belongs with roadmap 17.
3. **Incident drills and a runbook (6.2).** A command that fires a synthetic trip against a
   test claim, and a guide naming who does what.
4. **Machine-readable incident records (7.3).** One schema for a trip, a gateway refusal and a
   revocation, exported through roadmap 15's channel.
5. **Two-person approval for marked audiences (Appendix B, internal protections).** Changes
   who may obtain a token: needs an ADR.
6. **Threat profiles (1.1)** in threat-model.md, each citing its STRIDE rows.
7. **Safe-harbor wording (6.4)** in `SECURITY.md`.
8. **A red-team exercise (4.2)** with a stated goal, access level and period, and an
   adversarial agent suite against a booted sandbox.
9. **A volume limit per route (3.3.2)**, for operators who serve weights to sandboxes.

## Keeping this current

Revisit when NIST publishes a later version of 800-1, when an ADR named here as Proposed is
implemented (its row moves to Met or Partial in the same change as its threat-model pass), or
when a gap above is closed.
