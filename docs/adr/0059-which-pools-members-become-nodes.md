<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0059: Which pools' members become nodes: a list notaio signs

**Status:** Proposed (rewritten 2026-11-27 around the decision of 2026-11-20: the list is an object
notaio signs, not a key of the broker's configuration. Not built, and it cannot be: notaio defines
no pool object today, and decision 13 is what a notaio ADR that does not exist yet has to provide.
One part exists ahead of it: a node entry whose machine is gone is retracted since 2026-11-23,
[ADR-0039](0039-a-node-leaves-the-register-when-its-vm-is-gone.md) decision 7, #157. CALM, the
tests and the threat-model pass are owed before it is accepted) · **Date:** 2026-11-19 ·
**Rewritten:** 2026-11-27 (renumbered from ADR-0055 on 2026-11-20)

Roadmap 03 (the claim watcher), roadmap 08 (the `AgentSandbox` CRD) and roadmap 09 (notaio's
bundles). This is the *Revisit when* of accepted risk R-44 (`docs/security/threat-model.md` §8).
Amends [ADR-0011](0011-claim-watcher.md) decision 5 (every labelled member with a certificate
gets a node entry),
[ADR-0046](0046-who-may-claim-a-list-of-groups-and-a-namespace-to-groups-mapping.md)
decisions 3 and 14 (the namespace map gains a companion key it cannot start without),
[ADR-0026](0026-notaio-bundles-verified-in-shadow.md) (a third bundle kind under the same keys,
after [ADR-0055](0055-audiences-from-signed-sandboxaudience-bundles.md)'s second) and
[ADR-0039](0039-a-node-leaves-the-register-when-its-vm-is-gone.md) decisions 1 and 7 (an excluded
machine counts as one that is gone). Builds on
[ADR-0044](0044-a-sandbox-selects-its-pool-by-label.md) (the pool bound from is on the claim's
status) and on notaio's
[ADR-0020](https://github.com/firestoned/notaio/blob/main/docs/adr/0020-sandbox-audience.md)
(how a signed kind beside the policy bundle is defined, signed and delivered) and
[ADR-0008](https://github.com/firestoned/notaio/blob/main/docs/adr/0008-consumer-version-floor.md)
(the version floor). Changes no token shape and no SPIFFE ID
([ADR-0004](0004-spiffe-identity-scheme.md)). It changes a trust boundary (TB-2, TB-4: which
machines the broker vouches for to SPIRE, and where that list is trusted from) and the lifecycle of
the node entry, which `.claude/rules/testing.md` counts as the TPM attestation path.

What the first text of this ADR decided and this one does not: a `sandboxes.pools` key in
`mediatore.yaml` (superseded by decision 1, see *Alternatives rejected*), and `namespaces` on a
registry or an audience (decision 7 says where each went). Everything else is kept, and the seven
open questions answered on 2026-11-20 keep their answers.

## Context

ADR-0046 made the broker the place that decides **who may claim where**. Nothing yet decides
**which machines may serve a claim**, and the two are not the same question. What is true today,
read in the source:

- **Any labelled machine, in any namespace, is declared a node.** The machine controller is
  `Api::<VirtualMachine>::all` filtered on the presence of the pool label (`LABEL_POOL`,
  `banlieue.io/pool`; `run` in `crates/mediatore-claims/src/watch.rs`). `reconcile_machine` reads
  the endorsement certificate the VM publishes and calls `ensure_node_entry` for its EK hash. It
  reads neither the VM's namespace nor the label's value. A label is set by whoever may create or
  patch a `VirtualMachine`, and a pool's template by whoever may edit the pool.
- **Attestation proves the device, not the software.** ADR-0018 verifies that the EK was signed
  by a hypervisor's CA. Nothing measures what the VM booted, so the image a member runs is the
  control plane's word (TB-2 already records that a pool's editor decides what its members run).
- **The bind follows banlieue.** `Watcher::resolve` binds a claim to the registered node whose EK
  hash is on the claim's status. The claim's namespace and the pool it was bound from
  (`status.poolRef`, ADR-0044 decision 5) are not consulted.
- **A node entry is retracted when its machine is gone, and only then.** Since 2026-11-23
  (ADR-0039 decision 7, #157) the Lease holder runs `Watcher::collect_node_entries` after each
  resync, behind `Watcher::collect_nodes` (`collect_gone`, `crates/mediatore-claims/src/watch.rs`).
  The rule is the pure function `nodegc::node_entries_to_delete`
  (`crates/mediatore-claims/src/nodegc.rs`): a TPM node entry (`nodegc::tpm_node_entry_ek`) whose
  hash no labelled `VirtualMachine` publishes is deleted, never one under an unended claim's node
  or one whose node registered inside `store.node_grace_secs`, at most `MAX_DELETIONS_PER_PASS`
  (20) a pass, nothing on a failed listing, and an empty machine list believed only when no node
  is young and no claim is active. "Publishes" is `Watcher`'s `list_machines`, every labelled
  machine in every namespace: nothing is excluded, because nothing yet says what excluded means.
  `register_node` (`crates/mediatore-api/src/lib.rs`) checks the peer's SPIFFE ID against the EK
  hash it registers and nothing about the machine.
- **Audiences are no longer one global list.** When this ADR was first written, `audiences` and
  `registries` in `mediatore.yaml` carried no namespace. Since then ADR-0053 scoped an audience to
  namespaces, ADR-0055 reads audience definitions from notaio's signed `SandboxAudience` bundles
  (a team audience locked to its namespace), and
  [ADR-0063](0063-the-image-pull-goes-through-the-claims-proxy-and-the-gateway-like-any-egress.md)
  made a registry an audience a namespace's signed bundles must grant, in an environment with
  gateways. What is left global is in decision 7.
- **notaio has no pool object.** Its kinds are the policy, the ceiling and `SandboxAudience`;
  nothing under its ADRs or crates names a pool (read 2026-11-27, at fifteen commits past v0.8.0).

R-44 states the limit that follows: rights on a pool are rights on what its members are handed,
and the namespace map governs who may claim, not who may run a pool. It was accepted because the
operator alone created pools and images (ADR-0029). The revisit condition is a second team with
rights on pools or images. The namespace map exists for exactly that deployment, so the
condition is met by the first operator who uses the map as intended.

The first text answered with a list in the broker's configuration file. On 2026-11-20 the
maintainer decided against the file, for the reasons ADR-0055 gives for audiences: the file is
unsigned and trusted from whoever can write one ConfigMap, while every other statement on the
authorization path (the grant, the ceiling, the audience's definition) is signed by notaio and
delivered from a reviewed repository; and a change to the file is a broker rollout. The list of
machines the broker vouches for is the root of that path. It belongs under the same signature.

## Decision

1. **The list is one object notaio signs, read by the broker from its signed bundle in the
   platform namespace and from nowhere else.** The object, as this ADR proposes it to notaio
   (decision 13; the kind's name and its fields are notaio's to fix in its own ADR):

   ```yaml
   apiVersion: sandbox.firestoned.io/v1alpha2
   kind: SandboxPoolAdmission          # proposed name
   metadata:
     name: pools
     namespace: sandbox-platform       # the platform namespace, and only there
   spec:
     pools:
       - { namespace: infra,  name: pool }
       - { namespace: team-a, name: research }
       - { namespace: team-a, name: build }
   ```

   The broker's side is one key, a mode and never a list:

   ```yaml
   policy:
     trusted_keys: [ ... ]                  # the same keys verify all three bundle kinds
     audience_definitions:
       platform_namespace: sandbox-platform # ADR-0055; the one name notaio is configured with
     pools: enforce                         # any | shadow | enforce (decision 3)
   ```

   - **Read.** A third reflector beside the two that exist (`BundleReflector`,
     `crates/mediatore-claims/src/policy.rs`; `AudienceReflector`,
     `crates/mediatore-claims/src/audience.rs`), on the ConfigMaps notaio labels
     (`BUNDLE_SELECTOR`) in `policy.audience_definitions.platform_namespace` alone. **It never
     reads a namespace a sandbox may live in**: the start is refused when the platform namespace
     is `sandboxes.namespace` or a key of `sandboxes.namespaces`, and a bundle whose content names
     a namespace other than the one it was read in is not admitted. **The CRD is never read.**
   - **Verified.** An envelope is admitted only if it verifies with notaio's verifier for the
     kind: the pool list's own payload type, checked before the signature, a trusted key, the
     schema, the content digest and the lifetime (`notAfter`).
   - **The replay floor.** A version floor for the object's namespace and name, with the rules
     of notaio ADR-0008 (the same incarnation never goes down; a new incarnation only if it was
     issued later), persisted before the list is used, as a `PolicyFloor` moved by compare-and-set
     (ADR-0034) under a floor name no policy and no audience can take. A list that was shrunk is
     therefore not put back by delivering the older envelope again.
   - **One list, one snapshot.** The whole list is one object, one bundle, one version and one
     floor, so every removal of a pool is a newer signed version, which the floor makes stick,
     and never the deletion of an object, which a re-delivered envelope could undo until its
     lifetime ends. Two objects of the kind that both verify are refused together, never merged
     and never resolved by order (open question 8).
   - **Live.** The verified list is an immutable snapshot swapped atomically when a bundle is
     admitted, replaced, expires or is withdrawn, as the audience catalog is (ADR-0055 decision
     2). A change to the list is no broker rollout.

   Types: a new module `crates/mediatore-claims/src/pools.rs` with `PoolReflector`, `LivePools`
   and the resolved value `Pools` (`Any`, `Listed`, or `Unknown`, decision 3), carried in
   `WatcherConfig` (`crates/mediatore-claims/src/watch.rs`) and `AppState`
   (`crates/mediatore-api/src/lib.rs`), with one function, `Pools::admits(namespace, pool,
   revision)`, that every enforcement point below calls so they cannot disagree. The key is
   `PolicySection::pools` in `crates/mediatore/src/config.rs`.

2. **The key is the namespace and the pool name. An image revision is a narrowing, decided and
   not built, and is not the key.** A machine is **admitted** when the list has an entry whose
   `namespace` is the machine's `metadata.namespace` and whose `name` is the value of its
   `banlieue.io/pool` label. Exact match, no pattern and no "every pool in the namespace": a pool
   created next month would be admitted by a wildcard nobody re-read (the reasoning of ADR-0046's
   rejected glob). The list is its own object and not a field of the namespace map, because it
   governs the watcher for both paths: a pool in a namespace reached only declaratively (ADR-0046
   decision 11) is listed and is not in the map. The three things the broker can read about a
   member, and what each is worth:
   - the **namespace** is set by the API server and cannot be chosen by someone whose grant is
     in another namespace. It is the only element a tenant cannot write;
   - the **pool name** is a label. Inside a listed namespace, whoever may create or patch a
     `VirtualMachine` can write it. Listing `(namespace, pool)` is therefore a statement about
     that namespace's RBAC: the operator vouches for everyone who may edit that pool or write
     machines beside it;
   - the **image revision** (`banlieue.io/pool-image-revision`, written by banlieue from the
     `VMImage` build a member was created from) is also a label, and nothing attests it.

   A digest as the sole key reads well and is the weaker choice here. It is a label's word, not
   a measurement; it changes at every image rebuild, so a list that is one rebuild behind admits
   no member and the environment stops; and it says nothing about the namespace, the one thing
   that is not forgeable. So `(namespace, name)` is required, and `imageRevisions` is an optional
   per-entry list, compared byte for byte with the member's revision label, for the one case
   where it is the better control: a team may edit a pool's template in a listed namespace but
   may not write `VirtualMachine` objects, and the images are the operator's. Without the label,
   a pinned entry admits nothing. **It is decided and not built** (answered question 1): the
   first schema of the bundle does not carry it, notaio refuses the field, and the broker's
   verifier refuses a member the schema does not model, so the pin is never read and ignored.
   When a deployment needs it, it arrives as a second schema version that a broker built before
   it refuses whole (the route notaio's ADR-0022 took for `role`). The end state for "which
   software" is a measured boot checked at attestation, which is a different ADR (ADR-0018's
   successor), and this one does not pretend to be it. Control: `Pools::admits`,
   `crates/mediatore-claims/src/pools.rs`.

3. **Three modes. Without a namespace map the default is today's behaviour; with a map the key
   must be written; and a list the broker does not hold admits nothing new.**
   - `any`: every labelled machine in every namespace, exactly as now (`Pools::Any`). No pool
     bundle is read. The start log says so in one line (`pools: every labelled VirtualMachine,
     every namespace (no list)`).
   - `shadow`: the list is read, verified and held, nothing is refused, and each refusal
     `enforce` would make is logged once per machine, claim or sandbox, with what a first pass
     would retract and release. It is the migration step, as `shadow` is for audiences.
   - `enforce`: decisions 4 to 6, 9 and 10 apply.

   **What "absent" means now.** The key left out, *without* a namespace map, is `any`. The key
   left out *with* `sandboxes.namespaces` set refuses the start, with a message naming both keys:
   an operator who separated tenants by namespace has said the single-operator assumption no
   longer holds, and must say which machines serve them. Under a map, `any` and `shadow` are
   legal only as written words and are warned about at start and at every resync, since neither
   narrows anything (R-44 as it stands, by the operator's choice): `any` is the only route of an
   operator who has a map and no notaio (open question 10), `shadow` is a migration and not a
   resting state (open question 11). `shadow` and `enforce` require `policy.trusted_keys` and the
   platform namespace.

   **A list the broker does not hold** is the other absence, and it is never read as "every
   pool". Under `enforce` the broker holds no list (`Pools::Unknown`) before the reflector's first
   list of the platform namespace completes, when no bundle of the kind is there, when the one
   there fails verification or the floor, when it has expired, and when two verify. In that
   state:
   - nothing new is admitted: `reconcile_machine` declares no entry, `resolve` binds no claim,
     `refuse()` refuses a sandbox (before the first list completes it holds the sandbox instead,
     as `awaiting_bundles` does for unread policy bundles, ADR-0054 decision 4), and
     `register_node` answers `503 pools_not_synced`;
   - **nothing is torn down on the strength of it.** The retraction pass falls back to the rule
     that is built (a machine that is gone), and a bound claim keeps running. Only a verified
     list withdraws trust in a pool; a missing, expired or unverifiable one stops growth and says
     so in a `warn` line at each resync. An outage of notaio longer than a bundle's lifetime then
     costs new sandboxes, not the running ones (open question 9).

   Control: `PolicySection` and `Config::validate` in `crates/mediatore/src/config.rs`;
   `LivePools::snapshot` in `crates/mediatore-claims/src/pools.rs`; the start log in
   `crates/mediatore/src/main.rs`.

4. **Enforced first where the node is made: `reconcile_machine` declares no entry for a machine
   outside the list.** The check runs before the certificate is read. A refused machine gets one
   `info` line per resync naming the VM, its namespace, its pool label, the list's version and
   the reason (`pool not listed`, `no pool list held`), never the certificate. The broker writes
   no condition on a `VirtualMachine`: it holds no write verb on banlieue's kinds and gains none
   here. The controller stays cluster-wide (`Api::all`), so the `ClusterRole` is unchanged and
   the pinned test (`the_brokers_cluster_role_is_pinned`) stays as it is. A new list version
   reconciles every machine again, as a bundle change reconciles the sandboxes that name its
   policy (`bundle_changes`), so a pool added to the list gets its entries without waiting for a
   resync. `list_machines` returns admitted machines only under a held list, so the node
   collection of ADR-0039 sees an excluded machine as absent (decision 9). The watcher does not
   yet declare a node entry for a guest without a vTPM (ADR-0049, waiting on ADR-0050 decision
   6); when it does, that entry passes the same check. Control: `Watcher::reconcile_machine` and
   `KubeClaims::list_machines`, `crates/mediatore-claims/src/watch.rs`.

5. **Enforced again at the bind: a claim is not bound to a member of a pool outside the list.**
   `Watcher::resolve` requires the claim's namespace and `status.poolRef.name` to be admitted.
   An unlisted pool is `Resolution::Refused`; a `Bound` claim whose status names no pool, or a
   bind attempted while no list is held, is `NotYet` and fails at the resolve timeout, never
   bound on a guess. The refusal goes through the existing `fail` path (record revoked, claim
   deleted, banlieue destroys the member), and its reason is written to the owning sandbox's
   `status.reason` before the claim is deleted, so the sandbox does not end as a bare `claim
   gone`. This is the check that holds for a `poolSelector`, where the pool is banlieue's choice
   and is known only once bound. (When `imageRevisions` is built, this is where the bound
   `VirtualMachine`, `status.virtualMachineRef`, is read for its revision label, with a `get` the
   `ClusterRole` already holds.) Control: `Watcher::resolve` and `Watcher::fail`,
   `crates/mediatore-claims/src/watch.rs`.

6. **Enforced before any claim exists: `refuse()` refuses a sandbox that names an unlisted
   pool.** `refuse` already takes the sandbox's namespace beside its spec. A `poolRef` that is
   not listed in the sandbox's namespace, and a `poolSelector` in a namespace with no listed
   pool at all, end `Failed` with `status.reason` `pool <name> is not served in namespace <ns>`
   (for a selector, `no pool is served in namespace <ns>`) and a warn line; no claim is created
   and no member is consumed. The text does not list the pools that are served, and is the same
   whether the pool is unlisted or no list is held. A selector in a namespace that has listed
   pools is passed to banlieue as today; decision 5 catches a choice outside the list, at the
   cost of one member destroyed. As every refusal before the claim, it is made only while no
   claim exists (`refuse_before_the_claim`): a sandbox already bound is decision 9's. Control:
   `Watcher::refuse`, `crates/mediatore-claims/src/sandbox.rs`.

7. **Which sandboxes are handed which credential is not decided here.** *Rewritten 2026-11-27.*
   The first text gave an audience and a registry a `namespaces` list. Neither is this ADR's any
   more, and what is true of each is:
   - **Audiences are ADR-0055's** (and ADR-0053's under `config`): a team audience is locked to
     its namespace, a platform audience is usable where a signed grant reaches. This ADR adds
     nothing.
   - **Registries.** The decision of 2026-11-20 moved a registry's scope to a `SandboxPolicy`
     grant and named ADR-0060 for it; ADR-0055 decision 9 refers to that number. **No ADR-0060
     was written**: there is no such file in `docs/adr`. What was written and built instead, on
     2026-11-22, is ADR-0063: with `gateways` set a registry is an audience marked
     `role: registry`, a claim may pull only from a registry its namespace's signed bundles
     grant (`400 registry_not_granted`), and `registries[]` refuses the start. Under
     `policy.audience_definitions.mode: bundles` that waits on notaio carrying the marker
     (notaio ADR-0022, Proposed; R-63).
   - **What stays global.** In an environment without gateways, `registries[]` and its pull
     credential (A-16) are still the broker's configuration and are served to any bound claim
     whose image names the registry. This ADR does not scope them; decision 8 and the residue of
     R-44 say so.

8. **A credential shared by every namespace should be gateway-placed, and the broker says so.**
   Scoping bounds which sandboxes are handed a credential; it does not change that a
   proxy-placed credential is in a pool VM's memory, outside the jail, where the member's root
   reads it (A-23). ADR-0040's placement keeps it off every pool VM whatever image the member
   runs. So an operator-held audience placed in the proxy that more than one namespace can use
   (under `config`, `via: secret` with `inject: proxy`, unscoped or scoped to several; under
   `bundles`, a platform audience with `placement: proxy`) is named in one `warn` line with
   ADR-0040, at start for the file and when the definition is admitted for a bundle. notaio's
   `L029` already warns for a team audience. It is a warning and not a refusal (answered
   question 6), because an operator without gateways has no other placement. For a registry
   without gateways the equivalent is an anonymous mirror on the segment (ADR-0029). Not built.
   Control: the start log in `crates/mediatore/src/main.rs`, the admission log in
   `crates/mediatore-claims/src/audience.rs`; the guide, `docs/guides/deploying.md`.

9. **A node entry is retracted when no admitted machine publishes its EK hash: one rule, of which
   the gone half is built.** A list that stops new entries and leaves the old ones is not a
   control: the entry is what yields the node identity. And once the broker can say "this entry's
   machine is not admitted", "this entry's machine does not exist" is the same predicate with an
   empty machine (answered question 3).
   - **Built** (ADR-0039 decision 7, 2026-11-23, #157): `nodegc::node_entries_to_delete` and
     `Watcher::collect_node_entries`, with the guards listed under *Context*, for TPM node
     entries, with every labelled machine counted as publishing. The `SandboxNode` record goes
     by `nodegc::nodes_to_delete` and `Watcher::collect_nodes` (ADR-0039 decision 1). Neither
     function changes.
   - **To build:** under a held list both passes are fed the EK hashes of **admitted** machines
     only (decision 4's `list_machines`), so an excluded machine's entry and record go by the
     rule that exists. Under `any`, `shadow` or no held list they are fed every labelled machine,
     as today.
   - **One guard differs, and is to build.** Today a node an unended claim is bound to is kept.
     Under a held list it is kept **when its machine is admitted**. When its machine is outside
     the list, the claim is released first (entry retracted, tokens cut off, the sandbox `Failed`
     with the reason of decision 6), then the node entry and the record go, inside the same cap
     per pass. Shrinking the list is the operator withdrawing trust in a pool, and a sandbox
     there does not run to its TTL on it (answered question 2). This is the one place a change
     to a signed bundle releases a running claim: an audience or a grant that is withdrawn only
     stops being served (ADR-0055 decision 7, ADR-0061).
   - **When.** On the replica holding the Lease, after each resync as now, and once more when a
     newer list version is admitted, so a withdrawal does not wait up to a resync period.

   Control: `nodegc::node_entries_to_delete` and `nodegc::nodes_to_delete`
   (`crates/mediatore-claims/src/nodegc.rs`, exist), `Watcher::collect_nodes` and
   `Watcher::collect_node_entries` (`crates/mediatore-claims/src/watch.rs`, exist; their inputs
   and the release are to build), `EntryManager::list_entries` and `delete_entry` in
   `crates/mediatore-spire` (exist).

10. **The window a retracted entry leaves is closed at the broker.** Retracting a
    `ClusterStaticEntry` stops renewal; a node SVID already issued stays valid until it expires,
    and the broker holds no SPIRE admin identity to evict an agent (ADR-0006). In that window
    the node's calls already fail once its `SandboxNode` is gone (`claim_of_node_peer`), but
    `POST /v1/nodes` would write the record back. So under `enforce`, `register_node` refuses
    (`403`, the EK hash logged) an EK hash that no admitted machine publishes, read from a
    per-replica cache of the labelled machines and the replica's own snapshot of the list (every
    replica runs the pool reflector, as every replica runs the audience one). A registration
    that precedes the cache or the list is refused once (`403`, or `503 pools_not_synced`) and
    retried by the guest's unit (ADR-0039 decision 5). Under `any` and `shadow` nothing is
    checked, as today. Not built. Control: `register_node` in `crates/mediatore-api/src/lib.rs`,
    a machine reflector in `crates/mediatore-claims/src/watch.rs`.

11. **Checks at start, checks at admission, and what is logged.** The list is no longer in the
    file, so what the first text checked at start is split:
    - **At start**, each refusal naming the key and the value: a namespace map without
      `policy.pools` (decision 3); a value that is not one of the three modes; `shadow` or
      `enforce` without `policy.trusted_keys` or without a platform namespace; a platform
      namespace that is a sandbox namespace (decision 1). An older build refuses the key itself
      (`PolicySection` denies unknown fields).
    - **At notaio**, before anything is signed (decision 13): an empty or duplicate entry, a
      namespace or a pool name that is not an RFC 1123 name, a pattern, a field the schema does
      not carry, a second object, an object outside the platform namespace.
    - **At the broker, on every bundle, again** (`.claude/rules/testing.md`: the consumer does
      not trust that the producer was right): the same shape checks, and a list that fails one
      is not admitted, whole. An empty `pools` is a valid list that admits nothing (open
      question 14).
    - **Logged**, at `info`, configuration values and never a credential: at start the mode and
      the platform namespace; at each admitted version the version, each namespace with its pool
      names, and what was added and removed since the version held before; at `warn`, a
      namespace of the map with no pool listed (it can never bind; a live list makes this a
      line and no longer a refused start), and every state of decision 3 in which no list is
      held.

    `dev_mode` applies the same checks and the same enforcement from the same verified bundle:
    there is no development shortcut that reads an unsigned list. The dev binder (`free_node`)
    has no pools, so under `enforce` a dev claim carries the pool the request named and
    `MemoryStore` records the namespace; a fake that admitted what the real path refuses would
    hide the bug (`.claude/rules/testing.md`). Control: `crates/mediatore/src/config.rs`,
    `crates/mediatore/src/main.rs`, `crates/mediatore-claims/src/pools.rs`.

12. **Migration.** A deployment without a namespace map changes nothing and needs no edit. A
    deployment with a map, in this order:
    1. notaio at the release that carries the kind, with the platform namespace set, and the
       object applied from the platform's policy repository;
    2. the broker build that carries this ADR, with `policy.pools: shadow` **in the same apply**:
       the new build refuses a map without the key (decision 3), and a build before this ADR
       refuses the key, so both halves fail closed and neither order of ADR-0046 decision 18 is
       available;
    3. `shadow` until the log names no refusal the operator did not intend, then `enforce`,
       which is the last rollout the list needs.

    At the first pass under `enforce` with a list held, entries and records of machines outside
    the list are retracted and claims bound on them released (decision 9), each logged. The
    entries of machines that are gone have been draining since ADR-0039 decision 7 and are not
    part of this migration. An operator with a map and no notaio writes `policy.pools: any` and
    keeps R-44 as accepted, in words. The release notes say all of it.

13. **What notaio has to provide, in an ADR of its own that does not exist yet.** This ADR is
    the consumer's half and is blocked on the producer's. It names no number for notaio's ADR,
    because there is none; the names below are proposals, and where notaio's ADR differs, this
    one is amended to match before anything is built. Required:
    1. **A kind**, proposed `SandboxPoolAdmission` (`sandbox.firestoned.io/v1alpha2`,
       namespaced), reconciled only in the platform audience namespace
       (`NOTAIO_AUDIENCE_PLATFORM_NAMESPACE`) and only while that is set. An object of the kind
       in any other namespace is a finding and is never published.
    2. **The spec:** `pools`, a list of entries with exactly two required fields, `namespace`
       (an RFC 1123 label) and `name` (the pool's name, a valid label value), matched exactly by
       the consumer. No pattern, no selector, no "all". `imageRevisions` is not in the first
       schema and is refused (decision 2).
    3. **At most one published list.** A second object of the kind never yields a second
       bundle: at least one side of the pair is refused, as notaio ADR-0020 decision 6 refuses
       colliding audiences.
    4. **Findings with stable codes**, in the controller and in `notaio lint`: an object outside
       the platform namespace; a second object; a duplicate `(namespace, name)`; an invalid
       name; a pattern character; a field the schema does not carry (in `notaio lint`, which
       reads the file before the API server prunes it); an empty `pools` as a warning that
       still publishes.
    5. **A signed bundle of its own type:** a DSSE envelope with a payload type and a schema
       distinct from the policy's and the audience's (proposed
       `application/vnd.firestoned.sandboxpooladmission.bundle.v1+json` and
       `sandbox.firestoned.io/pool-admission-bundle/v1`), RFC 8785 canonical form with the
       entries sorted by namespace then name, signed under the custody and the keys of the
       other two kinds (notaio ADR-0004). Content: the object's namespace, name and `uid`, and
       the entries. Meta as for the others: a version that only goes up and moves only with the
       content digest, `issuedAt`, and `notAfter` on the policy bundle's lifetime (notaio
       ADR-0018), re-signed before it lapses.
    6. **Delivery as for audiences** (notaio ADR-0003, ADR-0020 decision 10): one ConfigMap in
       the object's namespace (proposed `<name>-pools`, key `pools.dsse.json`), labelled
       `app.kubernetes.io/managed-by=notaio`, owned by the object, written by notaio alone,
       deleted with the object.
    7. **The verifier, in `sandboxpolicy-bundle`**, for the broker to link at a release tag
       (notaio ADR-0014), with no `kube` and no `schemars` under default features: the payload
       type refused before the signature when it is another kind's; a member the schema does
       not model refused, not dropped (notaio ADR-0026 decision 8); and a later schema version
       refused whole by a consumer built before it.
    8. **The floor:** a floor name for the kind that no policy name and no audience name can
       take (as `audience_floor_name` gives `audience/<name>`), and the pure function that
       applies ADR-0008's rules to it (as `next_audience_floor` does), so the broker persists
       the floor in its own store without rewriting the rule.
    9. **Conformance vectors** for the kind, which this repository runs through the calls the
       broker makes.
    10. **Status like a policy's:** `Ready`, `Valid` with the findings, the published version
        and digest. A finding blocks a new version and the last valid bundle serves until its
        lifetime ends; so a removal that shares an edit with a finding is not published, which
        is why the same findings run at pull request time.
    11. **Who may write it,** as a requirement on the deployment (notaio ADR-0020 decision 12):
        the object and the ConfigMaps of the platform namespace admit the platform's GitOps
        identity and notaio as writers, nobody else.

## Security analysis

STRIDE for the boundaries this ADR changes (TB-2, TB-3, TB-4, TB-6). "Control" names what the
implementation must provide. **Only the rows marked *exists* are built**; the others are not, and
the threat model records a control only once the code exists (`.claude/rules/threat-modeling.md`).
Rows that depend on notaio depend on an ADR it has not written.

| Threat | STRIDE | Control |
| --- | --- | --- |
| A machine in a namespace the operator never listed is vouched for to SPIRE as a node | S/E | `Pools::admits` called by `Watcher::reconcile_machine`, `crates/mediatore-claims/src/watch.rs` (not yet built) |
| A pool label written by hand on a machine in an unlisted namespace | S | The namespace is the key and is the API server's, `Pools::admits`, `crates/mediatore-claims/src/pools.rs` (not yet built). Inside a listed namespace the label is trusted by design (decision 2) |
| A claim bound by banlieue to a member of an unlisted pool, through a selector | E | `Watcher::resolve` refuses on the claim's namespace and `status.poolRef`, `crates/mediatore-claims/src/watch.rs` (not yet built) |
| The list changed by whoever can write an object or a ConfigMap in the cluster | T/E | Only a signed bundle is read, under `policy.trusted_keys` (exists for the other two kinds, ADR-0026 decision 2); the CRD is never read; `PoolReflector`, `crates/mediatore-claims/src/pools.rs` (not yet built; the kind does not exist in notaio) |
| A list published from a tenant's namespace | E | The reflector reads the platform namespace alone, the start refuses a platform namespace that is a sandbox namespace, and a bundle naming another namespace is not admitted (not yet built) |
| A policy bundle or an audience bundle presented as the pool list, or the reverse | S/T | A payload type of its own, checked before the signature; DSSE signs the type (notaio's verifier; does not exist for this kind) |
| A wider, older list delivered again after the list was shrunk | T | The version floor for the object, persisted before use as a `PolicyFloor` (the store's floor exists, ADR-0034; the floor name and rule for this kind do not) |
| A newer, narrower list held back by whoever can write ConfigMaps in the platform namespace | T | Bounded by the held bundle's `notAfter`, after which nothing new is admitted (decision 3); the writers of that namespace are notaio and the platform's GitOps identity (decision 13, a requirement on the deployment, not a check the broker can make) |
| The list deleted, expired or unverifiable, and the broker falls back to every pool | E | `Pools::Unknown` admits nothing new and is never `Any` (decision 3; not yet built) |
| The list deleted, expired or unverifiable, and every running sandbox is released | D | The same state tears nothing down; only a verified list withdraws (decision 3; not yet built) |
| Two lists, and the broker takes the wider | T/E | Both refused, never merged or ordered (decision 1; not yet built); at most one published by notaio (decision 13) |
| A refusal tells a tenant which pools another tenant has | I | The refusal texts of decision 6, pinned by test, `crates/mediatore-claims/src/sandbox.rs` (not yet built) |
| A node entry left behind by a machine that no longer exists | E | `nodegc::node_entries_to_delete`, run by `Watcher::collect_node_entries` (**exists**, ADR-0039 decision 7) |
| The list is shrunk and the node entries already declared stay | E | The same rule fed admitted machines only, and the release of a claim bound on an excluded one, `Watcher::collect_node_entries`, `crates/mediatore-claims/src/watch.rs` (not yet built) |
| A node identity still valid after its entry was retracted registers again | S | `register_node` refuses an EK hash no admitted machine publishes, `crates/mediatore-api/src/lib.rs` (not yet built). Residual: the SVID's remaining lifetime at the SPIRE layer |
| A lagging or failed machine list retracts the entries of a healthy pool | D | The guards of ADR-0039 in `nodegc::node_entries_to_delete` and `nodegc::nodes_to_delete` (grace, cap, a failed list removes nothing; **exist**) |
| A map-era deployment started on a build, or with a configuration, that reads no list | E | `PolicySection` denies unknown fields (**exists**), so an older build refuses the key; the refusal of a map without `policy.pools`, `crates/mediatore/src/config.rs` (not yet built) |
| Who was refused, under which list, cannot be reconstructed | R | One log line per refused machine, bind and sandbox with namespace, pool, list version and reason; the admission line of each version with what it added and removed; `status.reason` on the sandbox (not yet built) |
| A shared credential read by root on a pool VM that runs a tenant's image | I | Not closed by this ADR: gateway placement (exists, ADR-0040) is the control, and decision 8 only warns. Stays in R-44 as its residue, with the pull credential of an environment without gateways (decision 7) |

## Consequences

- **What the list is.** A signed statement by the platform, reviewed in its policy repository
  like a policy, where the namespace map (A-26) is still a file reviewed by hand. It is a
  security configuration all the same: a pool listed under the wrong namespace, or a namespace
  listed whose RBAC is wider than the operator believes, grants what R-44 describes for that
  namespace. The list moves the boundary from "rights on any pool anywhere" to "rights on a
  listed pool, or on machines in its namespace", which is something the operator can read from
  RBAC.
- **What it is not.** It does not attest software. A person who may edit a listed pool still
  decides what its members run. Gateway placement and, once built, the narrowing of decision 2
  are what bound that; measured boot is what would end it.
- **No restart to list or withdraw a pool.** The first text needed a broker rollout per change;
  a signed list is read as it arrives. The mode switch is the one rollout.
- **A hard dependency on notaio for the namespace map's intended use.** `enforce` needs a notaio
  release with the kind, its pin here (`sandboxpolicy-bundle`, `sandboxpolicy-types`), and the
  platform namespace. An operator with a map and without notaio has `any`, written out, and
  nothing narrower.
- **Shrinking the list ends running sandboxes on the excluded pools** (decision 9), unlike every
  other bundle change, which only stops serving. An edit that drops an entry by mistake is
  signed and acted on like any other; the admission line names what a version removed, and
  `shadow` shows a first pass before it happens.
- **The lifetime of the bundle is an availability bound.** Past `notAfter` with no newer bundle,
  no new node is declared and no new sandbox is served, until notaio signs again. Running
  sandboxes are not touched (decision 3).
- **Node entries stop accumulating**, which ADR-0039 decision 7 already delivered for machines
  that are gone; this ADR adds the entries of machines that exist and are not admitted.
- **RBAC.** No verb is added. `get`, `list`, `watch` on `virtualmachines` and `delete` on
  `clusterstaticentries` are already in `deploy/base/rbac.yaml`. The bundle reader's `Role`
  (`get`, `list`, `watch` on ConfigMaps) is needed in the platform namespace, where a deployment
  that reads audience bundles already has it. No verb on pools, images or events.
- **banlieue is untouched**, and needs v0.5.9 or later for the claim's `status.poolRef`, which
  the workspace already pins.
- **CALM** (`docs/architecture/calm/architecture.json`): a relationship from the watcher to the
  pool bundle beside the two bundle relationships that exist, and the list as a control on the
  watcher's relationship to banlieue's machines; `make calm-validate` and `make calm-diagrams`
  before implementation.
- **Threat model**, the full pass after implementation (`.claude/rules/threat-modeling.md`): a
  new asset (the pool list, its bundle and its floor, beside A-30); TB-2 gains rows for the
  unlisted machine, the selector bound outside the list and the refused sandbox; TB-3 and TB-4
  gain the retraction fed by the list and its guards; TB-6 gains the registration refusal; the
  bundle rows gain the third kind; R-44 is rewritten to what remains (a listed pool's editors, a
  proxy-placed shared credential, the pull credential without gateways, and every deployment
  that runs `any`) with a new *Revisit when*; the Mermaid diagram gains the bundle's edge. The
  header stamp is bumped with the ADR range.
- **Docs:** `docs/guides/deploying.md` (the mode, the migration), `docs/guides/the-policy-bundle.md`
  (the third kind), `docs/guides/multi-tenant-authorization.md`, the README status table.

## Alternatives rejected

- **`sandboxes.pools` in `mediatore.yaml`** (the first text of this ADR, superseded 2026-11-20):
  a map from a namespace to its pool names in the broker's configuration, validated at start,
  with `Pools::Any` when absent. It decides the same question with the same key, and it was
  rejected for where it lives. The file is unsigned: whoever can write the broker's ConfigMap
  chooses which machines the broker vouches for, which is the widest statement on the whole
  authorization path, while the grant, the ceiling and the audience's definition beneath it are
  each signed. It has no replay protection: an older, wider file is as good as a newer one. And
  every change, a pool added for a new team included, is a rollout of the broker. A signed
  object answers the three with machinery the broker already runs for two other kinds.
- **Both: the signed list, and the file's list as a fallback for an operator without notaio.**
  Two sources for one decision, the unsigned one the easier to change, and the comparison of
  the two a permanent chore. The operator without notaio gets a word (`any`), not a second list.
- **The object in each tenant's namespace** (a team lists its own pools). The decision moves to
  the party the list exists to bound; the 2026-11-20 decision rules it out by name.
- **One object per tenant namespace, or one per pool, in the platform namespace.** Closer to
  notaio's "one object, one bundle" for audiences, and it keeps one team's edit out of another's
  file. But removing the last entry is then deleting an object, and a deletion is the one change
  the floor does not protect: the last envelope delivered again is admitted until its lifetime
  ends. It also gives "no bundle for this namespace" three meanings (never listed, withdrawn,
  not delivered yet) where one object gives each a different, visible state. Open question 8.
- **The CRD read by the broker directly.** Write access to the object would be enough (the
  argument of ADR-0055 and of notaio ADR-0020).
- **The image digest as the key.** Decision 2: a label's word, stale at every rebuild, and
  silent about the namespace.
- **A wildcard, or "every pool in a listed namespace".** It admits pools that do not exist yet.
  The cost of listing is one line per pool.
- **Reading a missing or expired list as "every pool", or as "no pool, tear down".** The first
  is fail open on the root of the path. The second makes an outage of the signer, or one deleted
  ConfigMap, end every sandbox. Decision 3 stops growth and keeps what runs.
- **Watching only the listed namespaces** (one namespaced controller each). It narrows nothing
  the `ClusterRole` grants, loses the log line that says a machine was refused and why, and
  makes the watch set a function of a list that now changes live. The filter in code is the
  same control with the evidence kept.
- **Per-namespace `Role`s for `virtualmachines` instead of the `ClusterRole` rule.** It would
  make Kubernetes enforce the namespace half. It also makes every new tenant a manifest change
  to the broker's RBAC, which ADR-0046 decision 10 chose against; worth revisiting with
  ADR-0056, not here.
- **Deriving the list from the namespace map** (every pool in every mapped namespace). The map
  says who may claim; reading it as who may run a pool is the confusion R-44 names.
- **A label or annotation on the pool that the operator sets** (`mediatore.io/admit: "true"`).
  It moves the decision into an object the pool's editor can write.
- **Leaving retraction for excluded machines to a later ADR.** The list would then stop new
  entries only, and an operator who removed a pool from it would have changed nothing for the
  machines already declared.
- **Banning excluded nodes** (`ban_node`). A ban is a security record an operator removes by
  hand (ADR-0039 decision 2); a pool that is listed again would come back banned.

## What must be proven

Nothing below is written yet except where a test is named as existing. Tests first, red before
the code, by name.

Unit, `crates/mediatore/src/config.rs`:
`without_a_map_and_without_the_key_every_pool_is_admitted`,
`a_namespace_map_without_policy_pools_refuses_to_start`,
`under_a_map_any_and_shadow_start_only_when_written_and_are_warned_about`,
`shadow_and_enforce_need_trusted_keys_and_a_platform_namespace`,
`a_platform_namespace_that_is_a_sandbox_namespace_refuses_to_start`,
`an_unknown_pools_mode_refuses_to_start`,
`a_sandboxes_pools_key_refuses_to_start` (the superseded key is an unknown field, not a list),
`under_a_map_a_shared_proxy_placed_secret_audience_is_named_in_a_warning`,
`every_config_in_the_shipped_examples_and_guides_still_parses`.

Unit, `crates/mediatore-claims/src/pools.rs`: `pools_any_admits_everything`,
`a_listed_pool_is_admitted_in_its_namespace_only`, `pool_matching_is_exact`,
`no_held_list_admits_nothing_and_is_never_any`,
`a_verified_list_is_admitted_and_its_floor_persisted_before_use`,
`a_policy_or_an_audience_envelope_is_refused_as_a_pool_list`,
`an_older_version_is_refused_after_a_newer_one_across_a_restart`,
`a_list_read_outside_the_platform_namespace_is_never_admitted`,
`two_lists_that_verify_are_both_refused`,
`an_expired_list_is_dropped_at_the_sweep`,
`a_list_carrying_image_revisions_is_refused_until_it_is_built`,
`an_empty_list_is_a_list_that_admits_nothing`,
`notaios_pool_conformance_vectors_reach_notaios_verdict`.

Unit, `crates/mediatore-claims/src/watch.rs`:
`a_member_of_an_unlisted_pool_gets_no_node_entry`,
`a_member_in_an_unlisted_namespace_gets_no_node_entry_whatever_its_label`,
`under_any_a_member_anywhere_gets_its_node_entry_as_before`,
`with_no_list_held_no_entry_is_declared_and_none_is_retracted_for_it`,
`a_newly_listed_pool_gets_its_entries_without_a_restart`,
`a_claim_bound_from_an_unlisted_pool_is_failed_and_its_sandbox_says_why`,
`a_bound_claim_whose_status_names_no_pool_is_not_bound_under_a_list`,
`an_excluded_machine_does_not_keep_its_node_or_its_entry_alive`,
`a_claim_bound_on_an_excluded_machine_is_released_before_its_node_goes`,
`shadow_logs_each_refusal_and_refuses_nothing`. Existing and kept green, unchanged:
`a_node_entry_whose_vm_is_gone_is_retracted_and_one_whose_vm_exists_is_kept`,
`a_retracted_node_entry_is_declared_again_when_its_vm_comes_back`,
`a_failed_vm_listing_retracts_no_node_entry`.

Unit, `crates/mediatore-claims/src/nodegc.rs`: the rule does not change, so its existing tests
stay as they are (`a_node_entry_whose_vm_is_gone_is_retracted_and_one_whose_vm_publishes_is_kept`,
`a_node_entry_under_an_unended_claim_or_a_young_node_is_kept`,
`an_empty_vm_list_retracts_nothing_while_a_claim_is_active_or_a_node_is_young`,
`claim_entries_and_x509pop_node_entries_are_not_this_rules`,
`at_most_the_cap_is_retracted_in_one_pass_in_name_order`). One new:
`a_claim_on_an_excluded_machine_does_not_hold_its_entry_and_one_on_an_admitted_machine_does`.

Unit, `crates/mediatore-claims/src/sandbox.rs`:
`a_sandbox_naming_an_unlisted_pool_is_refused_without_a_claim`,
`a_selector_in_a_namespace_with_no_listed_pool_is_refused_without_a_claim`,
`the_pool_refusal_lists_no_served_pool_and_reads_the_same_with_no_list_held`,
`a_sandbox_is_held_until_the_pool_list_is_first_read`,
`a_bound_sandbox_is_not_refused_by_refuse_when_its_pool_leaves_the_list`.

Unit, `crates/mediatore-api/src/lib.rs`:
`a_node_whose_machine_is_not_admitted_cannot_register_under_enforce`,
`registration_answers_pools_not_synced_until_the_list_is_read`,
`registration_is_unchecked_under_any_and_shadow`.

Store, `crates/mediatore-store/src/conformance.rs`: the pool list's floor is kept under a name
no policy floor and no audience floor can take, in the memory store and the Kubernetes store.

End to end, `crates/mediatore/tests/e2e_dev.rs` (real HTTP listeners, the test kit's fake IdP, a
list signed by the test kit's key): `a_claim_from_an_unlisted_pool_is_refused_over_real_listeners`
and `a_shrunk_list_releases_the_claim_and_a_replayed_wider_list_does_not_bring_it_back`, with
the negative cases of `.claude/rules/testing.md` for the new refusals. `mediatore-testkit` gains
a pool list builder and signer; `MemoryEntries` and `MemoryStore` refuse what the real ones
refuse.

Kind tiers, on the build host:
- `make kind-e2e-policy` (the tier that runs notaio, at the release that carries the kind): the
  list published by notaio is admitted; a labelled machine in an unlisted namespace gets no
  entry and one in a listed pool gets one; removing the pool from the object retracts the entry
  within a pass **with no restart of the broker**; the older envelope written back over the
  ConfigMap is refused and nothing returns.
- `make kind-e2e-watcher` (ADR-0011 live, no notaio): under `any` every case passes as today;
  under `enforce` with no list published, no entry is declared and none is retracted.
- `make kind-e2e-sandbox` (ADR-0008 live): a sandbox naming an unlisted pool is `Failed` with
  the reason and owns no claim.
- **`make kind-e2e-tpm` is run by hand on the build host before this merges**, the cluster
  recreated first (`make kind-delete`, then `make kind-e2e-ci KIND_E2E_SUITES=kind-e2e-tpm`).
  This ADR changes when a node entry is declared, what retracts it and who may register, which
  `.claude/rules/testing.md` counts as the TPM attestation path; CI cannot run that tier. It is
  run twice: under `any`, to show the path is unchanged, and under `enforce` with a list signed
  by a test key the broker trusts, to show that a member of a listed pool attested, got its node
  entry and registered. The report and the PR state `PASS` and the agent ID it attested as for
  each. A green `make check` is not a substitute.

`make check`, `make calm-validate` and `make calm-diagrams` green before the commit.

## Open questions

### Answered 2026-11-20, and kept

The maintainer took each recommendation but the fifth, whose premise ADR-0053 changed; the
answer is the first line of each item. Decision numbers are this text's.

1. *Answered: the key now, `image_revisions` decided and unbuilt.* **Is the image revision built
   with the key, or left for the operator who asks?** It needs the exact format of banlieue's
   `banlieue.io/pool-image-revision` label value confirmed against banlieue, and it turns every
   image rebuild into a change to the list. Recommendation: build the `(namespace, pool)` key now
   and keep the pin in this ADR as decided but unbuilt: until a deployment needs it the field is
   refused, never read and ignored. (In the signed object the field is `imageRevisions`, and the
   refusal is notaio's and the verifier's, decision 2.)
2. *Answered: release.* **Does shrinking the list release claims already bound on the excluded
   pool (decision 9)?** The alternative is to stop new binds and let running sandboxes reach
   their TTL, as a changed audience does not flap a bound sandbox. Recommendation: release. The
   list is a statement of trust in a pool's members, a credential may already be on that member,
   and waiting for a TTL is waiting on the party no longer trusted.
3. *Answered: both, as one rule.* **Does this ADR take node-entry retraction for machines that
   are gone, or only for excluded ones?** Recommendation: both, as one rule (decision 9); the
   predicate is the same and a second ADR would re-open the same guards. (The gone half was then
   built first, as ADR-0039 decision 7; decision 9 feeds the same rule.)
4. *Answered: no, today's behaviour and the start line.* **Should no list, without a map, narrow
   to `sandboxes.namespace`?** It would close R-44 for the single-namespace operator too, and it
   would stop nodes for declarative sandboxes in other namespaces that work today.
   Recommendation: no, keep today's behaviour (`any`) and the start log line; revisit when the
   default namespace form is next touched.
5. *Answered: no marker; a warning.* **A marker `all_namespaces: true` on a shared credential:
   required under a map, or is absence enough?** The recommendation was "required", on the
   precedent of `allow_any_authenticated` (ADR-0046 decision 19). ADR-0053, merged after this was
   written, keeps an unscoped audience open with a warning and closes it under
   `policy.audiences: enforce`; requiring a marker here would reverse it. The maintainer chose to
   follow it. (The scoping itself has since left this ADR, decision 7.)
6. *Answered: warn.* **Should a shared, proxy-placed operator-held audience under a map be
   refused, not warned (decision 8)?** Recommendation: warn now, since gateways are optional;
   refuse once the gateway shape is the only supported one for multi-tenant deployments, in its
   own ADR.
7. *Answered: not in this ADR.* **The early answer at the front door.** `POST /v1/claims` could
   answer `400 invalid_pool` for an unlisted `pool_ref` instead of creating a sandbox that fails.
   Recommendation: not in this ADR; the sandbox's `status.reason` serves both paths, and a second
   answer is a second text to keep free of other tenants' names.

### Open, raised by the move to a signed object (2026-11-27)

None of these has been put to the maintainer. Each is decided above at its recommendation so the
text is whole; any of them can change before the status does.

8. **One object for the whole list, or one per tenant namespace?** Decision 1 takes one.
   Recommendation: one. Every removal is then a newer signed version the floor protects, "no
   list" has a single meaning, and the list is read whole in review, as the superseded map was.
   The cost is that every team's onboarding edits one file of the platform's repository, which
   onboarding already does for the namespace map and `policy.sources`. If notaio's ADR prefers
   one object per namespace, the broker must then treat a missing object as a withdrawal, and
   withdrawing a namespace durably means publishing its object empty before deleting it.
9. **With no valid list held, keep what runs or drain it (decision 3)?** Recommendation: keep.
   Absence is not a signed statement, and draining on it makes the signer's availability, or one
   deleted ConfigMap, the lifetime of every sandbox. The cost: an operator cannot withdraw
   everything by deleting the object, and must publish a narrower list (an empty one, open
   question 14). A bound on how long the broker serves from nodes admitted under a lapsed list
   could be added later; none is proposed.
10. **Does an operator with a namespace map and no notaio have a route (decision 3)?**
    Recommendation: yes, one, the written word `policy.pools: any`, warned about at start and at
    each resync, on the precedent of `allow_any_authenticated` (ADR-0046 decision 19, R-37). It
    is R-44 accepted in the file, not a list. The stricter answer, no route, makes notaio a
    requirement of the namespace map itself and would keep such an operator on an older build.
    No unsigned list is offered in either case.
11. **May `shadow` start under a map?** Recommendation: yes, written and warned about. The first
    text had no shadow and flipped in one apply; a list that arrives asynchronously and whose
    first enforced pass releases running claims needs a look before it bites. The risk is a
    deployment left in `shadow`; the warning at every resync is the bound, and a later release
    can refuse it under a map.
12. **Where the platform namespace is written.** Decision 1 reuses
    `policy.audience_definitions.platform_namespace`, so an operator who wants the list and
    still serves audiences from the file writes that section with `mode: config`.
    Recommendation: reuse it now, one key that two readers cannot disagree on; hoist it to
    `policy.platform_namespace` when a third reader appears, in that reader's ADR.
13. **The kind's name.** Recommendation: `SandboxPoolAdmission`. `SandboxPool` reads as the pool
    itself, which is banlieue's `VirtualMachinePool`, and a name ending in `List` collides with
    the API convention for list types. It is notaio's to choose (decision 13).
14. **Is an empty list valid?** Recommendation: yes: it is the signed way to withdraw every
    pool, which open question 9's answer otherwise leaves without one. notaio publishes it with
    a warning, and the broker logs what it removed like any other version.
