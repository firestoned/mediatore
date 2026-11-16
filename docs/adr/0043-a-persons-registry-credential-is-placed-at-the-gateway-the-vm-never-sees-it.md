<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0043: A person's registry credential is placed at the gateway for the image pull; the VM never sees it

**Status:** Proposed 2026-11-15; built and unit-tested 2026-11-16, not yet run live (the direction was set by the operator on 2026-11-15; see "Implementation notes" for what is built and what is left) · **Date:** 2026-11-15

Roadmap 10 (the gateways) and roadmap 12 (the path to the upstreams). Extends
[ADR-0040](0040-the-gateway-places-an-audiences-credential-the-pool-never-holds-it.md) (the gateway
places an audience's credential) and [ADR-0041](0041-a-requesters-own-username-and-password-or-token-from-the-os-credential-store.md)
(a person's own user name and secret, delegated per claim) to the one place neither reaches yet: the
pool's pull of a private workload image. Changes how [ADR-0022](0022-registry-pull-credentials-from-the-broker.md)'s
pull credential is supplied in an environment that forbids what it does. Adds no SPIFFE ID, no entry
shape and no new port; adds one kind of audience (a registry), one route shape for the guest's pull and a
shorter life for the stored envelope.

## Context

A private repository on the operator's Artifactory answers the anonymous `GET /v2/` with `401` and a
Bearer challenge whose realm is on a second host (observed 2026-11-15). So an image in it cannot be pulled
by the pool as things are: the pull is anonymous unless the broker hands the guest a credential
(ADR-0022), and the way ADR-0022 does that has two properties this deployment now refuses:

1. **The credential is an operator-held file in a Kubernetes Secret volume** (`registries[].password_file`,
   threat model A-16). The operator's rule, 2026-11-15: a user name and password, or anything like
   them, is never stored in a Kubernetes Secret in the clear.
2. **The credential is held by the guest, as root, in memory for the pull** (A-16, "in a guest's memory for
   one pull, outside the jail"). The operator's rule, 2026-11-15: the pool VM and the sandbox never see the
   secret.

The operator also wants the credential to be a person's own, taken as input for the claim (not a service
account's, held by the operator), and the same body to work for a requester with no CLI.

What the code does today, so the decisions below are about a real starting point:

- The guest's pull is `serve_claim` in `crates/mediatore-guest/src/guest.rs`: it runs **as root**, before the
  egress proxy exists, with the node's identity, and passes `me.registry_credential` to the puller
  (`crates/mediatore-guest/src/image.rs`), which answers a Bearer challenge itself by fetching a token from
  the challenge's realm with the credential presented there.
- The gateway's inject listener accepts only a **claim** identity (`spiffe://<td>/banlieue/claim/...`),
  and the claim's SVID is issued to the claim's `sb-` user, not to root (ADR-0040 decision 2).
- A person's own secret already travels from the requester to the broker in the claim body, sealed there
  with OpenBao transit under a key derived from the claim's UID, stored only as ciphertext, and placed at
  the gateway on request, proven live on v0.2.9 against a real host with a token (ADR-0041, "What was
  proven").

## Decision

1. **A registry is an audience the gateway places a credential for.** It is declared like any placed
   audience (`audiences[]`: `via: delegated`, `credential: basic`, `inject: gateway`, the registry's
   host and port as the one `egress` entry, `rules` that admit only the read paths of the registry API,
   a `max_ttl` of at most 300 seconds), and the claim names it by delegating a credential for it
   (`--delegate <audience>=prompt`, or a `delegations` entry in `POST /v1/claims`, ADR-0041). The broker
   treats the host of such an audience as a registry the pool can reach, and refuses a claim whose image is on
   it unless the claim names that audience (the reconciler's `refuse`), where a `delegated` audience already
   refuses a claim that carries no credential for it (ADR-0035). A claim may also name that audience for other
   requests to the host; the ADR does not require the image to be on it. A registry that is not such an audience
   keeps ADR-0022's behaviour (anonymous, or the operator's credential).

2. **The pull's requests go to the gateway and the credential is placed there, never on the VM.** For a
   registry that is a placed audience the guest's puller sends each request in origin form to a gateway's
   inject port, `Host` the registry's, with no credential, as the egress proxy does for a placed route
   (ADR-0040 decision 7), and streams the response. The gateway adds what the registry accepts, and the
   VM never holds the secret **or anything derived from it**:
   - if the registry accepts `Authorization: Basic` on its `/v2/` requests, the gateway places that, as it
     does for ADR-0041's audience; or
   - if it insists on a Bearer, the authorizer does the realm's token exchange itself (Basic at the
     realm, a scoped Bearer back), keeps the Bearer in its cache like any placed credential (threat model
     A-24: at most 60 seconds, never past the claim), and the inject Envoy places `Bearer`.
   The guest therefore sees a `200` or a refusal, and never a challenge it must answer. Artifactory accepts Basic on `/v2/`
   requests (open question 1, answered 2026-11-15), so the first branch is the design and the second is a
   fallback for a registry that does not.

3. **The pull is made under an identity the inject listener already accepts.** The listener keeps
   accepting claim identities only (TB-17 does not widen). So the pull cannot run as root with the node's
   identity. The guest starts the claim's egress proxy, which runs as the claim's `sb-` user with the
   claim's SVID, **before** the pull, and the puller reaches the gateway through a second
   listener of that proxy: a loopback port of its own (`MEDIATORE_EGRESS_PULL_PORT`, default 18129) that
   serves the one registry and nothing else, for gateway-placed routes only. The sandbox cannot reach it
   because no jail rule lists it: the sandbox uid's firewall set names `127.0.0.1` at the proxy's port and the
   claim's destinations only, Landlock admits the proxy's port alone, and root's puller reaches it because the
   host table admits the loopback interface (`image/host-table`, `crates/mediatore-guest/src/net.rs`,
   `jail.rs`). The guest refuses the claim when the pull port is the proxy's or a destination's. (An earlier
   draft of this decision named a unix socket outside the jail; a loopback port is the same property with the
   existing listener code.) Open question 2 records the alternative (the node identity accepted for the
   registry route alone) and why it is not the choice.

4. **The stored envelope lives only as long as it is useful, and is deleted, not blanked.** The credential is
   sealed with OpenBao transit under the claim's derived key and stored only as ciphertext in the claim's
   Secret (ADR-0034), as today. Two changes:
   - when the claim is released, the broker **deletes** that Secret object. Today it nulls `key_id`,
     `nonce` and `ciphertext` and leaves an empty marker; the marker's job (a released claim cannot be
     used again) moves to the `AgentSandbox` status record, which already says the claim is released;
   - **no secret is stored longer than the claim's TTL (the operator's rule, 2026-11-16).** When a delegation is
     parked its envelope's `expires_at` is the least of the credential's own expiry, when the caller said one, and
     the claim's creation plus its `ttl_seconds` (`parked_expiry`, `crates/mediatore-api/src/lib.rs`). A sweep
     removes an envelope past that instant, whether it is still parked or already on a bound claim's record, and it
     runs every 15 seconds (`ENVELOPE_SWEEP_SECS`, `crates/mediatore-claims/src/watch.rs`), not only at the resync,
     whose interval is minutes. A use after the instant is refused by the credential route as before. The cost is
     deliberate: a claim's TTL counts from bind, the envelope's from creation, so a claim that waited for a VM loses
     the credential for that long at its end, and one that waited its whole TTL never gets it (it fails closed);
   - the issuer's own session (the login's refresh token, ADR-0013) is **not** bounded this way: it renews the
     claim's tokens for the claim's whole life and is already deleted at release; whether to bound it too is for
     the operator.

5. **The CLI keeps the credential no longer than the claim.** ADR-0041 decision 5's six hours become the
   least of six hours and the claim's `--ttl`: the saved item's age limit is the claim's TTL, the prompt
   says so ("keep it for the claim's TTL, 15 minutes? [y/N]", default no), and an item older than that is
   deleted and refused. `mediatore logout --audience` is unchanged.

6. **No credential in a Kubernetes Secret in the clear, ever, and none held by an operator for a person.**
   This deployment does not use `registries[].password_file` or `via: secret` for a person's credential.
   ADR-0022's mechanism is left in the code for a deployment that accepts it, and whether to retire it is
   open question 3; nothing in this ADR extends it.

7. **The interface is the claim body, so a requester with no CLI is served.** `POST /v1/claims` already
   takes `delegations`; this ADR adds no field. A declarative `AgentSandbox` (a resource a requester
   applies) cannot carry a credential, because its `spec` is stored in the cluster in the clear. That
   case is its own design: [roadmap 13](https://github.com/firestoned/mediatore/blob/main/.github/community/13-declarative-agentsandbox-credentials.md).

## Consequences

- **The VM and the sandbox never hold the person's secret, and never hold a registry token derived from
  it.** This closes the one place ADR-0040's "the pool never holds it" did not reach (the pull, which
  ADR-0022 handled on the VM).
- **The gateway carries image bytes.** The layers of a private image stream through the inject Envoy
  (`INJECT_STREAM_IDLE_SECS`, `INJECT_MAX_STREAM_SECS` apply), where today the registry leg is a plain
  layer 4 relay. Large images lengthen a claim's start and add load to a gateway; the limits and the cost
  are measured at implementation (open question 4).
- **The pull needs the claim's proxy earlier.** The guest's order changes (proxy, then pull), for a registry
  that is a placed audience only; every other claim keeps today's order. A failure to start the proxy
  fails the claim before any bytes are pulled.
- **The pull listener is a new surface** on the VM (a second loopback port of the proxy). It is one more
  thing the jail must not reach: the property rests on the firewall set and Landlock listing the proxy's port
  alone, and the guest refuses a pull port that collides with either. The unit tests cover the listener, the
  collision refusal and the proxy's refusal of any host but the registry's; that the jail cannot connect to the
  port is the existing rule sets' behaviour, to be shown on a pool member with a connect attempt from the
  jail.
- **A bigger broker surface to delete things.** The broker deletes Secret objects it created (it already
  has the RBAC for Secrets in its own namespace, ADR-0034); no new permission.
- **The token the registry mints (option 2's second branch) is a new credential in the authorizer's
  cache.** It is bounded like A-24 (60 seconds, never past the claim) and is the registry's, scoped to the
  repository and the pull.
- **A personal access token is still the shape on a host that refuses passwords** (ADR-0041 decision 7);
  the same two limits apply (R-30).

## Alternatives rejected

- **Hand the guest the credential for one pull (ADR-0022's shape, with a per-claim person's credential).**
  The secret would sit in root's memory on the pool VM. Refused by the operator's rule that the VM never
  sees it.
- **Place only the token request at the gateway and let the guest pull with the Bearer it gets back.** The
  guest would hold a credential derived from the secret, for the registry, for the length of the pull.
  Smaller, but the VM would still see a credential; refused by the same rule.
- **An operator-held service account in a Secret (`registries[].password_file`).** It is a stored
  credential in a Kubernetes Secret (decision 6) and it is not the person's.
- **Client-side encryption of the credential to a broker key.** Needs the CLI, or a library every client
  must carry; a requester with no CLI must be served (decision 7).
- **Accept the node identity at the inject listener.** Widens TB-17 for a pull instead of running the pull
  under the identity that already exists (decision 3, open question 2).
- **Keep the six-hour Keychain default.** A credential would outlive the claim it was typed for by hours;
  the operator asked for the claim's TTL (decision 5).

## What was proven, and what was not

Nothing of this ADR is built. One thing was measured: a registry that challenges with Bearer took Basic on
`GET /v2/` and on a manifest (open question 1). What it reuses was proven live on 2026-11-15 on mediatore 0.2.9, broker, three
gateways and the CLI (ADR-0041, "What was proven"): a person's secret delegated in the claim body, sealed
with transit, issued to the gateway for five minutes, placed as `Authorization: Basic`, the upstream
answering `200`, and removed from the authorizer's memory about ten seconds after the workload exited.

Not proven, and each is a test or a spike before the code is called done:

- That Basic is accepted on a blob `GET` and through the gateway: the API root and a manifest `GET` were
  tried, and a blob `HEAD` (`200`, no redirect), from a workstation, not through the gateway.
- A pull of a real image streamed through the inject Envoy, its time and its memory use.
- That the egress proxy can start before the pull and serve a root-only route the jail cannot reach.
- That a released claim's Secret is deleted and an unbound claim's envelope is deleted at its TTL.
- That the saved item's age limit follows the claim's TTL.

## Implementation notes (2026-11-16)

Built in this repository, each piece with a test written first (`make check` green):

- **Broker.** A gateway-placed audience's host is a reachable registry and is mapped to its audience
  (`Config::placed_registries`, `reachable_registries`, `crates/mediatore/src/config.rs`); an image on it needs the
  audience named (`Watcher::refuse`, `crates/mediatore-claims/src/sandbox.rs`).
- **Envelopes.** `parked_expiry` bounds a parked delegation at the claim's TTL; the store's `sweep_sessions` removes
  expired envelopes parked or on a bound record, in both stores (conformance cases
  `an_envelope_is_swept_when_it_expires_and_not_only_when_it_is_old` and
  `a_bound_claims_delegation_is_removed_when_it_expires`); the watcher sweeps every 15 seconds
  (`sweep_envelopes`); release deletes the envelope's Secret (`envelope_write`, `crates/mediatore-claims/src/kubestore.rs`).
- **Guest.** The puller's placed mode (`Puller::with_placed_registry`, `crates/mediatore-guest/src/image.rs`): plain HTTP to
  the proxy under `/<registry host>/`, no credential, a `401` is an error that never reaches the realm, a redirect is
  refused. The proxy's pull listener (`Proxy::serve_pull`, `crates/mediatore-guest/src/egress.rs`), `placed_registry`
  and `pull_args`. The guest's sequence for a placed registry: ruleset, proxy, then the pull, then the report
  (`crates/mediatore-guest/src/guest.rs`); every other claim keeps its order.
- **CLI.** A saved item records the claim's TTL and honours it, at most six hours (`parse_stored`,
  `crates/mediatore-client/src/delegate.rs`); the prompt names the TTL.

Not built, or not shown:

- **Not run live.** The deployment needs, in this order: a release carrying these changes; the registry declared as an
  audience in the broker's configuration (`via: delegated`, `credential: basic`, `inject: gateway`, the registry's
  host as `egress`, rules admitting `GET` and `HEAD` on `/v2/**`); the registry's host in the gateways'
  `INJECT_ENDPOINTS` (and the datacenter firewall's allowance for the gateways); a pool image with the new guest; then a
  claim with `--audience <registry> --delegate <registry>=prompt`.
- **The jail's inability to reach the pull port** is argued from the rule sets above, not yet shown by a connect attempt
  from a jail.
- **Large layers** through the inject Envoy (open question 4's second half) and the first-request latency.
- **A rejected redirect** is the whole answer to a registry that redirects blobs: it fails the pull. A blob `GET` was not
  tried against the operator's registry.

## Open questions

1. **Basic, or a token exchange? Answered 2026-11-15: Basic.** The challenge says Bearer, and the operator's
   Artifactory accepts `Authorization: Basic` anyway: a workstation spike with the operator's own
   credential (typed by the operator, never seen by the assistant, never printed) got `200` on `GET /v2/`
   and `200` on `GET /v2/<name>/manifests/<tag>` (an OCI image manifest, not an index), against `401`
   for the anonymous `GET /v2/`. So decision 2's first branch is the whole design for this registry, and
   the authorizer does no token exchange. The same spike's Bearer flow also worked (the token endpoint with
   Basic, `200`, then the manifest with that Bearer, `200`), and the Bearer it returned lives `9000` seconds,
   two and a half hours: longer than a claim here, so a guest that held one would hold a long-lived
   credential derived from the secret, a further reason decision 2 keeps every registry credential off
   the VM. The token branch stays in the ADR for a registry that refuses Basic. Not shown by the spike: that the same holds for a blob request and through the gateway (the
   spike's blob step is open question 4's first half).
2. **The identity of the pull.** Decision 3 runs the pull through the claim's own proxy. The alternative,
   the inject listener accepting the node's identity for the registry route when the broker confirms the
   node's bound claim names that registry, needs no reorder but widens TB-17 and gives a node identity a
   placed credential. Decided for the proxy; revisited if the reorder proves fragile.
3. **Retire the operator-held pull credential?** `registries[].password_file` and `via: secret` read a
   credential from a Secret volume. A deployment may still want them (a service account for a mirror that
   needs no person). Whether to keep them behind an explicit opt-in flag, or remove them, is for a later
   decision.
4. **Cost of streaming layers through the gateway.** The inject Envoy's stream limits, a gateway's
   memory and bandwidth for a multi-gigabyte image, and whether blobs a registry redirects to another
   host (a cloud store) work at all (the registry leg's limit in ADR-0038 applies: one that redirects layers
   to a host the route does not list fails the pull). First half answered 2026-11-15: a `HEAD` of a layer
   with Basic got `200` and no redirect, so that layer is served by the registry's own host. A `GET` was not
   tried (a registry can answer `HEAD` directly and redirect the `GET`); a one-byte ranged `GET` with no
   redirect followed settles it without downloading the layer.

## The ADD checklist

- [x] ADR written, Status and Date present
- [ ] CALM updated (`docs/architecture/calm/architecture.json`); `make calm-validate` passes; diagrams render
- [ ] Tests written first; quality gate green (`make check`)
- [ ] README and guides updated
- [ ] Threat-model full pass done; header stamp bumped (the registry audience on TB-17, TB-15's registry leg
      for the anonymous case, the deleted envelope on TB-9, the proxy-before-pull order on TB-6 and TB-12)
