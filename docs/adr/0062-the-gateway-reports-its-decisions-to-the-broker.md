<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0062: The gateway reports its decisions to the broker

**Status:** Accepted 2026-11-26; implemented 2026-11-22 (#157: `crates/mediatore-gateway/src/report.rs`,
`gateway_decisions` in `crates/mediatore-api/src/lib.rs`, `GatewayDecisions::check` in
`crates/mediatore-proto/src/lib.rs`), released in v0.4.0; the threat-model pass done 2026-11-26 (A-33,
R-68, R-69), with the route's test over the real listener added the same day
(`crates/mediatore/tests/e2e_gateway.rs`); not yet run on a booted gateway · **Date:** 2026-11-22

Roadmap 10 (the gateway). Adds one route to the gateway authorizer's surface at the broker beside
[ADR-0028](0028-egress-gateway-envoy-with-spiffe-identity.md) decision 4 and
[ADR-0040](0040-the-gateway-places-an-audiences-credential-the-pool-never-holds-it.md) decision 2,
under the identity of [ADR-0053](0053-the-gateways-authorizer-has-an-identity-of-its-own.md).
Changes no token shape, no SPIFFE ID, no storage contract and no existing route.

## Context

Each gateway's authorizer decides every tunnel (`CONNECT host:port`) and every inject request a
claim makes, and logs one line per decision on its own VM: the claim UID, the authority, the
verdict, the refusal code and where the allowlist came from (`crates/mediatore-gateway/src/serve.rs`,
`answer_tunnel` and `answer_inject`). Those lines are the only record of **which gateway** carried
**which host** for a claim, and they stay in the gateway VM's journal.

The broker sees much less. Its one trace of a claim's egress is the answer to
`GET /v1/gateway/claims/{uid}`, logged at `debug` as "claim egress answered to the gateway". That
ask happens on a cache miss only (`fresh_secs`, 30 by default), carries neither the gateway nor
the host, and every gateway's ask arrives under the same SPIFFE ID
(`spiffe://<td>/gateway/authorizer`, by ADR-0053 one static entry for all of them) and, on a
deployment behind NAT, from the same address. So the broker log gives a lower bound on how often
some gateway checked a claim, and nothing about where the claim went.

Two readers want the rest:

- **The operator** answering "which gateway carried this claim's traffic, to where, and what was
  refused" without logging in to each gateway VM.
- **A walk-through UI** (Recess) that shows a run's path through the system and today must label
  the carrying gateway as a guess.

Shipping each gateway's journal off the VM (a log collector) answers the operator and is an
operations choice this ADR does not preclude. It does not make the record part of mediatore: a
deployment without the collector has no answer, and the claim's owner never has one.

## Decision

1. **The authorizer reports its decisions.** Every tunnel and inject decision about a claim (the
   peer parsed as `spiffe://<td>/banlieue/claim/<uid>`) is reported to the broker, at
   `POST /v1/gateway/decisions`, over the same mutual TLS and the same SVID the authorizer asks
   with. A decision with no claim (`not_a_claim`) is not reported: there is no claim to attribute
   it to, and the gateway's own line keeps it.

2. **What a decision carries.** The body is one gateway's batch:

   ```json
   { "gateway": "gateway-02",
     "decisions": [
       { "at": "2026-11-22T14:41:58.469Z", "claim_uid": "…", "kind": "tunnel",
         "authority": "pypi.org:443", "verdict": "allow", "served": "cache" },
       { "at": "…", "claim_uid": "…", "kind": "inject", "authority": "api.anthropic.com",
         "audience": "anthropic", "verdict": "deny", "reason": "not_allowed" } ] }
   ```

   The same fields as the gateway's own line, and no others: never a path, a query, a header or a
   credential. `served` is absent on an inject decision, `reason` on an allow, `audience` where no
   route matched.

3. **The gateway's name is its own claim.** `mediatore gateway --name` (`MEDIATORE_GATEWAY_NAME`),
   by default the kernel's host name. Every gateway authenticates as the one authorizer identity,
   so the name is attribution, not authentication: the broker cannot tell one gateway from another
   by anything but what it says. That is enough for the readers above, and it is why the name
   decides nothing.

4. **Reporting is never on the decision's path.** A decision is handed to a bounded queue (1024)
   without waiting; a full queue drops the decision and counts it, and the count is logged with
   the next batch that goes. A batch goes every two seconds, or at 256 decisions, in one attempt
   with the ask's timeout and no retry. A failed batch is dropped and logged once per run of
   failures (a broker that does not know the route, an older one, answers `404` or `405`). The
   verdict Envoy receives is the same whether the broker hears of it or not.

5. **The broker logs and keeps nothing.** The route accepts the authorizer's identity alone (with
   ADR-0053 decision 7's transition switch, as the other gateway routes), checks the batch's shape
   and refuses the whole batch with `400` if any part is off: at most 256 decisions; a name of 1
   to 63 characters of `a-z`, `0-9`, `-` and `.`; an authority of at most 261 bytes of the
   characters a `host[:port]` can hold; an audience and a refusal code of the characters a name
   holds. A batch that passes is `204`, and each decision is one `info` line, "gateway decision",
   with the claim UID, the gateway, the kind, the authority, the audience, the verdict, the
   reason, where the allowlist came from and the gateway's time. The broker does not look the
   claim up: a line about a claim it no longer knows is still a fact about the gateway. Nothing
   is stored.

## Consequences

- **Exact attribution.** For each tunnel and inject request a claim made through a gateway, the
  broker's log names the gateway (as the gateway named itself), the host, the verdict and the
  time, so a reader of the broker log alone, such as Recess, can mark the gateway that carried a
  run and the audiences it reached.
- **More broker log.** One line per check, where a check is a new tunnel or an inject request,
  not a byte count. A busy claim's batches are capped by the queue and the batch size; the gateway
  keeps its own line, so the record is duplicated by design.
- **A false line is possible.** Anything holding the authorizer identity can report decisions that
  were not made, under any gateway name. The same identity already decides every tunnel; a false
  report changes no verdict and no state. The shape checks of decision 5 keep a report from
  writing anything into the broker's log but the fields above (no line breaks, no control
  characters).
- **Destinations in the broker log.** The hosts a claim reached now sit in the broker's log as
  well as the gateway's. Both are operator-only; neither carries a path or a credential.
- **A dropped report is lost.** No retry and no buffering past the queue: the record is best
  effort, and the gateway's journal stays the complete one.

## Open questions

1. **The owner's view.** A route for the claim's owner (`GET /v1/claims/{name}/egress`, the owner
   and namespace checks of ADR-0045's logs route) would let a user see their claim's path without
   reading the broker log. It needs a place to keep the decisions (the claim's record, or a ring in
   memory that a broker restart empties) and is left for an ADR of its own.
2. **A gateway's identity of its own.** A per-gateway SPIFFE ID (`spiffe://<td>/gateway/<name>`)
   would turn decision 3's name into an authenticated one. It changes ADR-0053's static entry and
   ADR-0004's scheme, and is not needed for attribution.
