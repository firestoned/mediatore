<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0055: Audiences from signed SandboxAudience bundles, platform or team, read live

**Status:** Accepted, implemented 2026-11-20 (amended at implementation, each amendment in its decision: decision 1 reads the policy namespaces too and names the floor objects, decision 2 refuses both sides of a collision from the namespaces that see both and reads a snapshot per decision, decision 4 lists the checks built, decision 5 polls with `get` and does not zeroize; a `caRef` and a `basic` operator-held credential are refused, `NotBuilt`; threat-model pass of 2026-11-20, R-56 to R-60) · **Date:** 2026-11-20

Roadmap 04 (audiences and backends) and roadmap 11 (policy at the gateway). The consumer side of
notaio's [ADR-0020](https://github.com/firestoned/notaio/blob/main/docs/adr/0020-sandbox-audience.md)
(`SandboxAudience`). Deprecates `audiences[]` in `mediatore.yaml`, including the per-namespace
map of [ADR-0053, an audience scoped to namespaces](0053-an-audience-scoped-to-namespaces-each-with-its-own-rules.md)
phase 1 (its phase 2, the grants from the policy bundle, stands). Amends
[ADR-0032](0032-operator-held-credentials-as-an-audience-backend.md) (where an operator-held
credential comes from), [ADR-0040](0040-the-gateway-places-an-audiences-credential-the-pool-never-holds-it.md)
(placement is the definition's), [ADR-0041](0041-a-requesters-own-username-and-password-or-token-from-the-os-credential-store.md)
(the credential format) and [ADR-0026](0026-notaio-bundles-verified-in-shadow.md) (a second
bundle kind under the same keys). Changes no token shape and no SPIFFE ID. It changes a trust
boundary (where an audience's definition and credential are trusted from, TB-2, TB-6, TB-9, TB-14)
and the broker's RBAC (read on named Secrets in team namespaces).

## Context

What is true today, read in the source:

- **Every audience is read once, at start.** `audiences[]` in `mediatore.yaml` (`AudienceConfig`,
  `crates/mediatore/src/config.rs`) is turned at start into about a dozen maps keyed by audience
  name on `AppState` (`audiences`, `obo_audiences`, `egress`, `rules`, `scopes`, `cas`,
  `no_credential`, `secrets`, `delegated`, `inject`; `crates/mediatore-api/src/lib.rs`) and into
  the watcher's `WatcherConfig.audiences`. A `via: secret` credential is read from `secret_file`
  once (`crates/mediatore/src/main.rs`). Adding an audience, rotating a credential or narrowing a
  rule is a broker rollout.
- **The definition is unsigned.** Everything else on the authorization path is verified: the
  grant comes from notaio's signed bundle (ADR-0026, ADR-0053 phase 2), the ceiling is signed by
  Security (notaio ADR-0015). The definition is trusted from whoever can write one ConfigMap.
- **The definition is global.** One list for every namespace; ADR-0053 phase 1 scoped a shared
  definition per namespace, but a team cannot bring a credential of its own.

The platform this serves is one where each team runs its own delivery: a team that pushes images
to its registry with a service id it already holds in its own OpenBao should be able to use that
credential from its sandboxes without the platform team holding it, and without a restart of
anything. notaio ADR-0020 defines `SandboxAudience`, platform or team by namespace, and signs it.
This ADR is how the broker reads it.

## Decision

1. **The broker reads audience definitions from notaio's signed audience bundles.** A new key
   under `policy`, beside the trusted keys it shares with policy bundles:

   ```yaml
   policy:
     trusted_keys: [ ... ]                  # the same keys verify both bundle kinds
     audience_definitions:
       mode: bundles                        # config (default) | shadow | bundles
       platform_namespace: sandbox-platform # must match NOTAIO_AUDIENCE_PLATFORM_NAMESPACE on notaio
   ```

   The broker reads `<audience>-audience` ConfigMaps (`audience.dsse.json`) in the platform
   namespace, in every namespace a sandbox may live in (the keys of `sandboxes.namespaces`, or
   `sandboxes.namespace`) and in every policy namespace (`policy.namespaces`: a team audience is
   granted by a policy of its own namespace, and the watcher reconciles a sandbox wherever it is
   created), with a reflector beside the one that reads policy bundles and under the same `Role`. An envelope is admitted
   only if it verifies under notaio ADR-0002 decision 5 with the audience payload type
   (`application/vnd.firestoned.sandboxaudience.bundle.v1+json`), a trusted key, the schema, the
   digest, the lifetime and a version floor kept per audience namespace and name with the rules of
   notaio ADR-0008, persisted like the policy floor: under notaio's floor name `audience/<name>`,
   which no policy name can take, and in the Kubernetes store as a `PolicyFloor` named `aud-` and a
   hash of the namespace and that name (one label with no dot, where every policy floor's name has
   one), whose spec a read checks against the floor asked for. **The CRD is never read**; nor is any field of
   the bundle trusted to say which kind the audience is: the kind is derived from the namespace the
   bundle was read in and the namespace the bundle says, which must agree.

2. **One live catalog, read once per request.** The verified definitions and their resolved
   credentials form an immutable snapshot, an `AudienceCatalog`
   (`crates/mediatore-claims/src/audience.rs`), swapped atomically when a bundle is admitted,
   replaced, expires or is withdrawn, or when a credential changes. It replaces the per-audience
   maps on `AppState` and `WatcherConfig.audiences` under `bundles` (built as `AppState::view`,
   an `AudienceView` of one namespace, and `WatcherConfig.catalog`). Every decision reads the
   snapshot current when it is made; two decisions in one request may read two snapshots, each a
   whole verified state, so a definition withdrawn between them is refused or skipped by the
   later one, never assumed present. Every reader asks `catalog.resolve(namespace, name)`: a team audience of that name in that namespace,
   else a platform audience of that name, else none. Both present is a refusal, never resolved by
   order, and logged with the two namespaces. notaio refuses the newcomer of a collision on a name
   or an endpoint (`L024`, `L025`: the object with no published bundle yet, both if neither), so a
   platform audience added later does not take a team's working audience away and the broker
   normally never sees two; its own refusal is the backstop for what notaio missed. The broker
   cannot tell a newcomer (it reads bundles in no fixed order, and each replica in its own), so its
   backstop refuses both sides of a collision, and only from the namespaces that see both: a team
   audience with a platform audience's name breaks that name in the team's namespace and nowhere
   else, so one team cannot take a platform audience away from another. The readers are the
   front door and the reconciler's checks, `POST /v1/token`, `GET /v1/me` and the proxy's routes,
   the gateway's allowlist and its inject routes, and the shadow comparison.

3. **A team audience is locked to its namespace, here as at notaio.** It resolves only for a
   claim whose record namespace (`ClaimRecord.namespace`, ADR-0046 decision 9) is the audience's
   namespace, and is granted only by a bundle of a policy in that same namespace: a policy reached
   through `policy.sources` (ADR-0054) may grant platform audiences, never another namespace's
   team audience. An audience outside that reads as one that does not exist (`unknown_audience`,
   `audience <a> is not configured`), so a refusal tells a tenant nothing about another tenant's
   audiences.

4. **The broker checks again what notaio checks** (`.claude/rules/testing.md`: the consumer does
   not trust that the producer was right). A team audience whose backend is not `secret` or
   `none`, whose credential source is OpenBao, or whose header is not a lowercase token or is
   reserved (notaio's `L026` list), is not admitted, nor is any audience with an endpoint that is
   not an exact DNS `host:port`, a rule the proxy cannot match, a `secret` backend with no source or
   a zero `maxTtlSeconds`; each with one `warn` line naming the audience and the rule, never the
   reference. An endpoint shared with another audience visible from the same namespace is refused
   when resolved, for both audiences and from that namespace (decision 2). A `secretRef` or `caRef` carries no namespace
   (notaio ADR-0020) and the broker resolves it in the audience's own namespace, whatever the
   bundle says elsewhere. A platform audience must come from `platform_namespace` and nowhere
   else.

   notaio publishes audience bundles only once `NOTAIO_AUDIENCE_PLATFORM_NAMESPACE` is set; until
   then it reconciles no `SandboxAudience` and policies behave as before. So a deployment turns
   notaio's side on first, with every audience it uses defined, and runs the broker in `shadow`
   (decision 8) before `bundles`.

5. **Credentials are read live and never leave the broker except where they are placed.**
   Every audience with a credential source is read again every `credential_refresh_secs`
   (default 60) and at once when the catalog changes, so a rotation (an External Secrets
   refresh, a new KV version) is served within one period and without a restart.
   - **`secretRef`** (a team audience, or a platform audience in `platform_namespace`): a `get` by
     name through the Kubernetes API in the audience's own namespace. Polling needs neither `list`
     nor `watch`, so the broker holds `get` alone, on exactly those Secrets, through a `Role` with
     `resourceNames` in each namespace, created at onboarding with the namespace (a kustomize
     component, `deploy/audience-credentials`); the broker cannot create or widen it. An empty
     `resourceNames` would grant every Secret in the namespace, so the component ships a name that
     matches nothing and each overlay replaces the list.
   - **`openbao`** (platform audiences only): a KV v2 read (`GET /v1/<mount>/data/<path>`) with the
     identity the broker already uses for OpenBao (ADR-0015, Kubernetes auth), configured under
     `policy.audience_definitions.openbao` (`url`, `ca_file`, `role`, `auth_mount`, `token_file`,
     `https` outside `dev_mode`), under a policy that grants `read` on the platform's audience paths
     and nothing else. The login happens at start, so a wrong URL, CA or role stops the start.
     Without the subsection an `openbao` audience has no credential, and the log says so.
   - **A failed read keeps the last good value for at most two refresh periods**, then the audience
     is unusable (`503 credential_unavailable` at the token route, the gateway's credential route
     refusing) until a read succeeds; a source that changed drops the old value at once. Each
     transition is logged once, with the audience and the kind of failure (`not found`, `denied`,
     `unavailable`, `malformed`), never the Secret's name, the path or the value. The value is held
     as ADR-0032 holds one (a type that prints redacted, never logged, never in a bundle or a
     route); it is not zeroized when replaced.
   - Under `shadow` the credentials are read too and only the outcome is logged, so the RBAC and
     the OpenBao policy are proven before `bundles` serves from them.

6. **Placement, format and rules are the definition's.** `placement` decides gateway or proxy
   (ADR-0040), `format` bearer or basic (ADR-0041), `header` and `extraHeaders` what is set. The
   definition's `rules` are the ceiling every grant must sit inside (ADR-0053 phase 2's effective
   grant, with the definition in the place of the file's top-level `rules`). For a platform audience
   that ceiling is the platform's; for a team audience it is the team's, and the independent bound
   is Security's `ExposureCeiling`, which must cover the definition's endpoints for any policy that
   grants it (notaio ADR-0020 decision 8).
   A grant's `endpoints` must be a subset of the definition's and an empty list reaches nothing;
   its `rules` must sit inside the definition's and an empty list means the definition's (notaio
   `L028` refuses a wider grant; the broker filters what is outside, as `effective_grant` does
   today, so neither side alone is trusted).
   Until the platform namespace and a claim's own namespace have completed their first list, the
   catalog cannot say an audience is missing: the API answers `503 audiences_not_synced` and the
   watcher holds the sandbox, as it does for unread policy bundles (ADR-0054 decision 4).

   Not served yet, and refused at admission with `NotBuilt` rather than served without it: a
   definition with a `caRef` (no CA ConfigMap is read yet) and an operator-held credential in
   `basic` format. ADR-0043's check that a sandbox pulling from a gateway-placed registry names
   that registry's audience is derived from `audiences[]` and is not made under `bundles`; the
   pull fails later instead.

7. **What a running claim sees.** A change reaches a claim at its next use: its next token, its
   next `GET /v1/me`, the gateway's next ask after its fresh window (ADR-0028). An audience
   withdrawn, expired or no longer resolvable is gone at that point: no token, no route, the
   gateway refusing; the claim itself is not released, as ADR-0053 decision 12 has it for a grant.

8. **Three modes, and the migration.**
   - `config` (the default): today's behaviour, `audiences[]` from the file; audience bundles are
     not read.
   - `shadow`: both are read; the file serves; for each audience the broker logs once per change
     whether the bundle's definition matches the file's (backend, placement, format, endpoints,
     rules, TTL; never a credential or a reference's value) and which team audiences would appear.
   - `bundles`: the catalog serves, and an `audiences[]` in the file refuses the start.

   The migration is: publish the definitions, run `shadow` until no difference is logged, switch to
   `bundles` with the file's `audiences[]` removed. The mode switch is a configuration change and
   is the last rollout an audience needs; after it, no audience change restarts anything.

9. **Deprecated, then removed.** `audiences[]` in `mediatore.yaml`, with ADR-0053 phase 1's
   `namespaces` map and `secret_file`, is deprecated by this ADR: kept under `config` and `shadow`,
   refused under `bundles`, removed in a later release once `bundles` is the default. Registries
   keep their place in the file until ADR-0060.

10. **Start checks and logs.** `shadow` and `bundles` require `policy.trusted_keys` and
    `platform_namespace` (an RFC 1123 label); `bundles` refuses a non-empty `audiences[]`. At start,
    one `info` line names the mode, the platform namespace and the namespaces read; each admitted
    or withdrawn definition is logged with namespace, name, kind and version, never a credential.

## Security analysis

| Threat | STRIDE | Control (to be built) |
| --- | --- | --- |
| An audience definition changed by whoever can write an object in the cluster | T/E | Only signed bundles are read (decision 1); the CRD is never read |
| A policy bundle replayed as an audience bundle, or the reverse | S/T | The payload type is checked before the signature (notaio ADR-0002 decision 5); DSSE signs the type |
| An old definition replayed after a tightening | T | The version floor per audience, persisted (notaio ADR-0008) |
| A team audience used from another namespace, or granted by a mapped policy | E | Decision 3, at every reader through `AudienceCatalog::resolve` |
| A team audience shadows a platform audience's name | S/T | `resolve` refuses both present (decision 2) |
| A team audience points the broker at another team's or the platform's credential | I/E | Decision 4: same-namespace `secretRef` only, OpenBao refused for teams; RBAC `resourceNames` per namespace (decision 5) |
| A team audience opens egress Security did not approve | E | Security's ceiling over the definition's endpoints (notaio ADR-0020 decision 8); the grant is still required |
| Two audiences on one endpoint, so the gateway places the wrong credential | I | Both refused at `resolve` from every namespace that sees both (decisions 2 and 4) |
| The broker reads every Secret in a team namespace | I | `Role` with `resourceNames`, created at onboarding, never by the broker |
| A credential source fails and the audience serves an old credential forever | T/D | Two refresh periods, then unusable (decision 5) |
| A credential or a reference logged | I | Decision 5 and 10; the log tests assert on the absence of the value |
| The two configurations disagree during the migration | T | `shadow` logs every difference before `bundles` is switched on (decision 8) |
| Which definition served a token cannot be reconstructed | R | The audit line of a token or a placement names the audience, its namespace, kind and bundle version |

## Consequences

- **No restart for any audience change** once `bundles` is on: a new team audience, a rotated
  credential, a narrower rule.
- **The definition is signed**, so the whole authorization path is verified: definition, ceiling
  and grant.
- **Teams own their credentials**: their OpenBao, their sync, their namespace. The platform team
  never holds them.
- **New dependencies and RBAC**: a notaio release with `SandboxAudience` and its pin here; a KV
  read on OpenBao; `get`/`list`/`watch` on named Secrets in team namespaces. No write verb is
  added.
- **The largest refactor of the API crate since ADR-0034**: every per-audience map becomes the
  catalog. The tests that build `AppState` gain a catalog builder in `mediatore-testkit`.
- **CALM:** a relationship from the watcher to the audience bundles, the credential reads (Secrets,
  OpenBao KV) as flows, the audience node's source. **Threat model:** a full pass after
  implementation; the rows that cite `audiences[]` move to the catalog.
- **Docs:** the audiences guide rewritten around `SandboxAudience`, a guide for a team bringing its
  own credential, the migration in the deploying guide.

## Alternatives rejected

- **Reload `mediatore.yaml` live.** It removes the restart but keeps the definition unsigned and
  global, and gives teams no place for their own credentials.
- **A `SandboxAudience` CRD read by the broker directly.** Write access to the object would be
  enough to change where a credential is placed.
- **Every audience in the platform namespace.** The platform team would hold every team's
  credential.
- **The broker reading a team's OpenBao.** A team would name the path the broker's identity reads.

## Questions settled on acceptance

1. **The stale window for a failed credential read:** two refresh periods, then unusable, with the
   refresh configurable (decision 5).
2. **`delegated` for team audiences:** not now; platform only. A team's own OAuth application could
   be useful, but the refresh is the broker's work under the broker's identity (notaio `L022`).
3. **The mode switch itself is one rollout:** accepted; it happens once per deployment.

## What must be proven

Tests first, red before the code.

- `crates/mediatore-claims/src/audience.rs`: a verified bundle admitted; a policy-bundle envelope
  refused as an audience bundle; a downgrade refused; `resolve` for a team audience in its namespace
  only, for a platform audience everywhere, and refusing both present; each rule of decision 4
  refused at admission; a withdrawn or expired definition gone from the next snapshot.
- `crates/mediatore-api/src/lib.rs`: a team audience usable by a claim in its namespace and
  `unknown_audience` from another; a mapped policy granting a team audience refused; a rotated
  Secret served at the next token; a failed source unusable after the stale window; the gateway's
  inject route carrying the team's credential for its claims only; no credential in any log.
- `crates/mediatore/src/config.rs`: the three modes and their start checks.
- `crates/mediatore/tests/e2e_dev.rs`: two namespaces with a team audience each and a platform one,
  over real listeners, with the negative cases.
- Kind, on the build host: a team audience from a Secret synced into its namespace, served through
  the gateway and rotated without a restart; a platform audience from OpenBao KV; a team audience
  refused from another namespace.
- `make check`, `make calm-validate`, `make calm-diagrams`; the threat model pass.

## What was proven (2026-11-20)

- `make check` on the build host: the audience conformance vectors through `admit_audience`, the
  catalog and the reflector, the credential cache against a table reader and against the fake
  OpenBao's KV, the API's view over the routers (team and platform audiences, `503
  credential_unavailable`, `503 audiences_not_synced`, rotation, gateway placement, collisions,
  withdrawal, a team audience granted only by its own namespace's policy), the watcher's checks,
  the three modes and their start checks, and an e2e over real listeners with a tenant map.
- `make kind-e2e-policy` and `make kind-e2e-gateway-audience` on the build host, notaio
  v0.7.0-rc.1: both audience bundles published by notaio and admitted; the claim's tunnel through
  the real Envoy carrying the team Secret, then after a rotation the new one, on the same broker
  pod with no restart; the platform credential read from OpenBao KV; a sandbox of another
  namespace naming the team audience `Failed` with the reason of one not configured; neither
  credential in the broker's log.
- Not proven on a cluster: a gateway-placed team audience (the API tests cover it), a platform
  audience served to a claim (read, not served, in kind), and any live deployment.

