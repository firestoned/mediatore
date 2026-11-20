<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0055: Which pools' members become nodes: an operator list, and credentials served by namespace

**Status:** Proposed · **Date:** 2026-11-19

Roadmap 03 (the claim watcher) and roadmap 08 (the `AgentSandbox` CRD), with roadmap 04 for the
audiences. This is the *Revisit when* of accepted risk R-44 (`docs/security/threat-model.md` §8).
Amends [ADR-0011](0011-claim-watcher.md) decision 5 (every labelled member with a certificate
gets a node entry),
[ADR-0046](0046-who-may-claim-a-list-of-groups-and-a-namespace-to-groups-mapping.md)
decisions 3 and 14 (the namespace map gains a companion it cannot start without),
[ADR-0032](0032-operator-held-credentials-as-an-audience-backend.md) and
[ADR-0022](0022-registry-pull-credentials-from-the-broker.md) decision 5 (an operator-held
credential and a registry credential may be served to some namespaces only) and
[ADR-0039](0039-a-node-leaves-the-register-when-its-vm-is-gone.md) decision 1 (the node's entry
goes with its record). Builds on [ADR-0044](0044-a-sandbox-selects-its-pool-by-label.md) (the
pool bound from is on the claim's status) and
[ADR-0040](0040-the-gateway-places-an-audiences-credential-the-pool-never-holds-it.md) (gateway
placement). Changes no token shape and no SPIFFE ID
([ADR-0004](0004-spiffe-identity-scheme.md)). It changes a trust boundary (TB-2, TB-4: which
machines the broker vouches for to SPIRE) and the lifecycle of the node entry, which
`.claude/rules/testing.md` counts as the TPM attestation path.

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
- **What a bound member is handed is global configuration.** `audiences` and `registries` in
  `mediatore.yaml` (`AudienceConfig`, `RegistryConfig`, `crates/mediatore/src/config.rs`) carry no
  namespace. `refuse()` in `crates/mediatore-claims/src/sandbox.rs` checks that an audience is
  configured, not where the sandbox lives; `issue_token` in `crates/mediatore-api/src/lib.rs`
  hands a `via: secret` credential as it is to any live claim that names the audience, and `me`
  attaches the registry credential for whatever registry the claim's image names.
- **A node entry is never retracted.** `delete_entry` has two call sites, both for claim entries
  (`Reconciler::release` and `sweep_orphans`, `crates/mediatore-claims/src/lib.rs`; the sweep
  skips `EntryKind::Node` with the comment "Node entries are left alone: they live as long as
  the VM", which nothing enforces). ADR-0039 removes the `SandboxNode` record of a VM that is
  gone and leaves its `mediatore-node-<ek>` `ClusterStaticEntry` in place.

R-44 states the limit that follows: rights on a pool are rights on what its members are handed,
and the namespace map governs who may claim, not who may run a pool. It was accepted because the
operator alone created pools and images (ADR-0029). The revisit condition is a second team with
rights on pools or images. The namespace map exists for exactly that deployment, so the
condition is met by the first operator who uses the map as intended.

## Decision

1. **`sandboxes.pools`: the pools whose members may become nodes and be claimed, keyed by
   namespace and pool name.**

   ```yaml
   sandboxes:
     namespaces:                 # ADR-0046, unchanged
       infra:  { groups: [APP_EXAMPLE_ADMIN] }
       team-a: { groups: [APP_EXAMPLE_TEAM_A_USER] }
     pools:                      # new
       infra:
         - name: pool
       team-a:
         - name: research
         - name: build
           image_revisions: ["<revision label value>"]   # optional, decision 2
   ```

   A machine is **admitted** when its `metadata.namespace` is a key of `pools` and the value of
   its `banlieue.io/pool` label is a `name` listed under that key. Exact match, no pattern and no
   "every pool in the namespace": a pool created next month would be admitted by a wildcard
   nobody re-read (the reasoning of ADR-0046's rejected glob). The list is a separate key and not
   a field of each `namespaces` entry, because it governs the watcher for both paths: a pool in a
   namespace reached only declaratively (ADR-0046 decision 11) is listed here and is not in the
   map. Types: `SandboxesSection`, a new `PoolEntry` with `#[serde(deny_unknown_fields)]`, and
   `Config::pools() -> Pools` in `crates/mediatore/src/config.rs`; the resolved value is a small
   type `Pools` (`Any` or `Listed`) in `crates/mediatore-claims/src/lib.rs`, carried in
   `WatcherConfig` (`crates/mediatore-claims/src/watch.rs`) and `AppState`
   (`crates/mediatore-api/src/lib.rs`), with one function, `Pools::admits(namespace, pool,
   revision)`, that all the enforcement points below call so they cannot disagree.

2. **The key is the namespace and the pool name. An image revision is an optional narrowing,
   not the key.** The three things the broker can read about a member, and what each is worth:
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
   that is not forgeable. Recommended: `(namespace, pool)` is required; `image_revisions` is an
   optional per-entry list, compared byte for byte with the member's revision label, for the one
   case where it is the better control: a team may edit a pool's template in a listed namespace
   but may not write `VirtualMachine` objects, and the images are the operator's. Without the
   label, a pinned entry admits nothing. The end state for "which software" is a measured boot
   checked at attestation, which is a different ADR (ADR-0018's successor), and this one does
   not pretend to be it. Control: `Pools::admits`, `crates/mediatore-claims/src/lib.rs`.

3. **Absent means today's behaviour only without a namespace map; with a map, the broker does
   not start without the list.** With `sandboxes.namespaces` unset and `sandboxes.pools` unset,
   `Pools::Any`: every labelled machine in every namespace, exactly as now, and the start log
   says so in one `info` line (`pools: every labelled VirtualMachine, every namespace (no
   list)`). With the map set and no `pools`, the start is refused with a message naming both
   keys: an operator who separated tenants by namespace has said the single-operator assumption
   no longer holds. `pools` may be written without the map and then applies as written. Control:
   `SandboxesSection::validate`, `crates/mediatore/src/config.rs`.

4. **Enforced first where the node is made: `reconcile_machine` declares no entry for a machine
   outside the list.** The check runs before the certificate is read. A refused machine gets one
   `info` line per resync naming the VM, its namespace, its pool label and the reason
   (`pool not listed` or `image revision not listed`), never the certificate. The broker writes
   no condition on a `VirtualMachine`: it holds no write verb on banlieue's kinds and gains none
   here. The controller stays cluster-wide (`Api::all`), so the `ClusterRole` is unchanged and
   the pinned test (`the_brokers_cluster_role_is_pinned`) stays as it is. `list_machines`
   returns admitted machines only, so the node collection of ADR-0039 sees an excluded machine
   as absent. Control: `Watcher::reconcile_machine` and `KubeClaims::list_machines`,
   `crates/mediatore-claims/src/watch.rs`.

5. **Enforced again at the bind: a claim is not bound to a member of a pool outside the list.**
   `Watcher::resolve` requires the claim's namespace and `status.poolRef.name` to be admitted,
   and, for an entry with `image_revisions`, reads the bound `VirtualMachine`
   (`status.virtualMachineRef`, a `get` the `ClusterRole` already holds) for its revision label.
   An unlisted pool is `Resolution::Refused`; a `Bound` claim whose status names no pool is
   `NotYet` and fails at the resolve timeout, never bound on a guess. The refusal goes through
   the existing `fail` path (record revoked, claim deleted, banlieue destroys the member), and
   its reason is written to the owning sandbox's `status.reason` before the claim is deleted, so
   the sandbox does not end as a bare `claim gone`. This is the check that holds for a
   `poolSelector`, where the pool is banlieue's choice and is known only once bound. Control:
   `Watcher::resolve` and `Watcher::fail`, `crates/mediatore-claims/src/watch.rs`.

6. **Enforced before any claim exists: `refuse()` refuses a sandbox that names an unlisted
   pool.** `refuse` takes the sandbox, not only its spec, for the namespace. A `poolRef` that is
   not listed in the sandbox's namespace, and a `poolSelector` in a namespace with no listed
   pool at all, end `Failed` with `status.reason` `pool <name> is not served in namespace <ns>`
   (for a selector, `no pool is served in namespace <ns>`) and a warn line; no claim is created
   and no member is consumed. The text does not list the pools that are served. A selector in a
   namespace that has listed pools is passed to banlieue as today; decision 5 catches a choice
   outside the list, at the cost of one member destroyed. Control: `Watcher::refuse`,
   `crates/mediatore-claims/src/sandbox.rs`.

7. **An audience and a registry gain `namespaces`, the namespaces they are served to.**
   `audiences[].namespaces: [<ns>, ...]` and `registries[].namespaces: [<ns>, ...]`, optional.
   Absent, the entry is served to every namespace, as now. Present, a claim whose record's
   namespace (`ClaimRecord.namespace`, ADR-0046 decision 9) is not listed is treated as if the
   entry did not exist, at each place the entry is read:
   - `refuse()`: `audience <a> is not configured`, the same text as for an audience that does
     not exist, so the refusal is no oracle for another tenant's audiences;
   - `still_configured`, which `POST /v1/token` and the gateway's credential route both pass
     through (`issue_token`): `403`, with the claim UID, the audience and the namespace logged;
   - `me`: no route for that audience's endpoints and no `registry_credential` from a registry
     entry not served to the claim's namespace; with `gateways` set, the registry is also not
     reachable for that namespace (`reachable_registries`, `placed_registries`), so the sandbox
     is refused before a claim exists and not at the pull.

   With a namespace map set, an audience `via: secret` with `inject: proxy` and a registry entry
   that carries a credential must each say one of `namespaces: [...]` or `all_namespaces: true`,
   or the broker does not start: no gate must be written down, as ADR-0046 decision 19 required
   of an issuer. `via: sts`, `via: delegated` and `via: entra-obo` audiences mint or open something
   that is the subject's own; they may carry `namespaces` and need not. Control:
   `AudienceConfig`, `RegistryConfig` and `Config::validate` in `crates/mediatore/src/config.rs`;
   `Watcher::refuse` in `crates/mediatore-claims/src/sandbox.rs`; `still_configured` and `me` in
   `crates/mediatore-api/src/lib.rs`.

8. **A credential shared by every namespace should be gateway-placed, and the broker says so at
   start.** Scoping bounds which sandboxes are handed a credential; it does not change that a
   proxy-placed credential is in a pool VM's memory, outside the jail, where the member's root
   reads it (A-23). ADR-0040's placement keeps it off every pool VM whatever image the member
   runs. So: an audience with `via: secret`, `inject: proxy` and `all_namespaces: true` under a
   namespace map logs one `warn` line at start naming the audience and ADR-0040. It is a warning
   and not a refusal, because an operator without gateways has no other placement. For a
   registry the equivalents are an anonymous mirror on the segment (ADR-0029) or a credential
   listed for one namespace. Control: the start log in `crates/mediatore/src/main.rs`; the
   guide, `docs/guides/deploying.md`.

9. **This ADR takes on the retraction of node entries, for excluded machines and for machines
   that are gone, as one rule.** A list that stops new entries and leaves the old ones is not a
   control: the entry is what yields the node identity. And once the broker can say "this entry's
   machine is not admitted", "this entry's machine does not exist" is the same predicate with an
   empty machine. So ADR-0039 decision 1 is widened here and not left to a successor: **a node
   entry is retracted when no admitted machine publishes its EK hash**, on the replica holding
   the Lease, once per resync, together with the `SandboxNode` record. The rule is a pure
   function beside `nodegc::nodes_to_delete` and keeps ADR-0039's guards: a failed listing of
   machines, entries, nodes or claims retracts nothing; an entry younger than the grace
   (`store.node_grace_secs`) is kept; at most `MAX_DELETIONS_PER_PASS` per pass; an empty machine
   list is not believed while a claim is active. One guard differs: a node an unended claim is
   bound to is kept **when its machine is admitted**. When its machine is outside the list, the
   claim is released first (entry retracted, tokens cut off, the sandbox `Failed` with the
   reason of decision 5), then the node entry and the record go. Shrinking the list is the
   operator withdrawing trust in a pool, and a sandbox there does not run to its TTL on it.
   Control: a new `nodegc::entries_to_retract` in `crates/mediatore-claims/src/nodegc.rs`,
   `Watcher::collect_nodes` in `crates/mediatore-claims/src/watch.rs`, `EntryManager::list_entries`
   (which already returns node entries) and `delete_entry` in `crates/mediatore-spire`.

10. **The window a retracted entry leaves is closed at the broker.** Retracting a
    `ClusterStaticEntry` stops renewal; a node SVID already issued stays valid until it expires,
    and the broker holds no SPIRE admin identity to evict an agent (ADR-0006). In that window
    the node's calls already fail once its `SandboxNode` is gone (`claim_of_node_peer`), but
    `POST /v1/nodes` would write the record back. So with a list set, `register_node` refuses
    (`403`, the EK hash logged) an EK hash that no admitted machine publishes, read from a
    per-replica cache of the labelled machines. A registration that precedes the cache is
    refused once and retried by the guest's unit, as a `403` already is (ADR-0039 decision 5).
    Under `Pools::Any` nothing is checked, as today. Control: `register_node` in
    `crates/mediatore-api/src/lib.rs`, a machine reflector in `crates/mediatore-claims/src/watch.rs`.

11. **Start checks, each naming the key and the value.** Refused at start: a namespace map
    without `sandboxes.pools` (decision 3); `pools` present and empty, a namespace key with an
    empty list, a duplicate pool under one namespace, a namespace or pool name that is not an RFC
    1123 name, an unknown field in an entry, an empty `image_revisions`; a namespace of the map
    with no pool listed (it could never bind); an audience's or a registry's `namespaces` that is
    empty, repeats a value, or names a namespace that is neither in the map nor a key of `pools`
    (a typo that would serve nobody); `namespaces` together with `all_namespaces: true`; and the
    missing marker of decision 7. The broker logs at start, at `info`, each namespace with its
    pool names, and each scoped audience and registry with its namespaces: configuration values,
    never a credential. `dev_mode` applies the same checks and the same enforcement: the dev
    binder (`free_node`) has no pools, so under a list a dev claim carries the pool the request
    named and `MemoryStore` records the namespace, and a fake that admitted what the real path
    refuses would hide the bug (`.claude/rules/testing.md`). Control:
    `crates/mediatore/src/config.rs`, `crates/mediatore/src/main.rs`.

12. **Migration.** A deployment without a namespace map changes nothing and needs no edit. A
    deployment with a map adds `sandboxes.pools`, and the marker or the list on each credential
    of decision 7, **in the same apply as the new build**: the new build refuses the old
    configuration (decision 3) and a build before this ADR refuses the new keys
    (`deny_unknown_fields`, ADR-0046 decision 17), so neither order of ADR-0046 decision 18 is
    available and both halves fail closed. At the first resync after the grace, entries and
    records of machines outside the list are retracted and claims bound on them released
    (decision 9), each logged; so does every entry left by a machine that is gone, which on an
    old deployment is a one-time drain at the cap per pass. The release notes say both.

## Security analysis

STRIDE for the boundaries this ADR changes (TB-2, TB-3, TB-4, TB-6). "Control" names what the
implementation must provide. **None of it is built**; the threat model records a control only
once the code exists (`.claude/rules/threat-modeling.md`).

| Threat | STRIDE | Control |
| --- | --- | --- |
| A machine in a namespace the operator never listed is vouched for to SPIRE as a node | S/E | `Pools::admits` called by `Watcher::reconcile_machine`, `crates/mediatore-claims/src/watch.rs` (not yet built) |
| A pool label written by hand on a machine in an unlisted namespace | S | The namespace is the key and is the API server's, `Pools::admits`, `crates/mediatore-claims/src/lib.rs` (not yet built). Inside a listed namespace the label is trusted by design (decision 2) |
| A claim bound by banlieue to a member of an unlisted pool, through a selector | E | `Watcher::resolve` refuses on the claim's namespace and `status.poolRef`, `crates/mediatore-claims/src/watch.rs` (not yet built) |
| A sandbox in one namespace is handed an operator-held credential meant for another | I | `audiences[].namespaces` checked in `still_configured` and `Watcher::refuse`, `crates/mediatore-api/src/lib.rs`, `crates/mediatore-claims/src/sandbox.rs` (not yet built) |
| A member in one namespace is handed another namespace's registry credential | I | `registries[].namespaces` checked in `me`, `crates/mediatore-api/src/lib.rs` (not yet built) |
| A refusal tells a tenant which audiences or pools another tenant has | I | The refusal texts of decisions 6 and 7, pinned by test, `crates/mediatore-claims/src/sandbox.rs` (not yet built) |
| The list is shrunk and the node entries already declared stay | E | `nodegc::entries_to_retract`, `crates/mediatore-claims/src/nodegc.rs`, run by `Watcher::collect_nodes` (not yet built) |
| A node identity still valid after its entry was retracted registers again | S | `register_node` refuses an EK hash no admitted machine publishes, `crates/mediatore-api/src/lib.rs` (not yet built). Residual: the SVID's remaining lifetime at the SPIRE layer |
| A lagging or failed machine list retracts the entries of a healthy pool | D | The guards of ADR-0039 carried into `nodegc::entries_to_retract` (grace, cap, a failed list removes nothing), `crates/mediatore-claims/src/nodegc.rs` (not yet built) |
| A typo in the list or in a `namespaces` value silently serves everyone, or no one | T/D | Start validation in `crates/mediatore/src/config.rs` and the start log in `crates/mediatore/src/main.rs` (not yet built) |
| A map-era config started on a build that ignores the list | E | `deny_unknown_fields` (exists, ADR-0046 decision 17) refuses the key on an older build; the refusal of a map without `pools`, `crates/mediatore/src/config.rs` (not yet built) |
| Who was refused, and why, cannot be reconstructed | R | One log line per refused machine, bind and sandbox with namespace, pool and reason; `status.reason` on the sandbox, `crates/mediatore-claims/src/watch.rs`, `sandbox.rs` (not yet built) |
| A shared credential read by root on a pool VM that runs a tenant's image | I | Not closed by this ADR: gateway placement (exists, ADR-0040) is the control, and decision 8 only warns. Stays in R-44 as its residue |

## Consequences

- **What the list is.** A security configuration reviewed by hand, like the namespace map
  (A-26): a pool listed under the wrong namespace, or a namespace listed whose RBAC is wider
  than the operator believes, grants what R-44 describes for that namespace. The list moves the
  boundary from "rights on any pool anywhere" to "rights on a listed pool, or on machines in its
  namespace", which is something the operator can read from RBAC.
- **What it is not.** It does not attest software. A person who may edit a listed pool still
  decides what its members run. The narrowing of decision 2 and gateway placement are what
  bound that; measured boot is what would end it.
- **A pool goes dark when it leaves the list or its revision moves.** With `image_revisions`
  set, a rebuilt image admits no member until the list follows and the broker restarts. That is
  the fail-closed side, and it is an outage the operator causes by a rebuild; the guide says so
  and it is why the pin is optional.
- **Shrinking the list ends running sandboxes on the excluded pools** (decision 9), unlike an
  audience leaving the configuration, which only stops token issue. The maintainer may prefer
  the gentler rule (open question 2).
- **Node entries stop accumulating.** The register of `ClusterStaticEntry` objects settles at
  the size of the admitted pools, as the `SandboxNode` register does since ADR-0039; roadmap 05's
  live proof (a recycled pool) gains the entry count.
- **RBAC is unchanged.** `get`, `list`, `watch` on `virtualmachines` and `delete` on
  `clusterstaticentries` are already in `deploy/base/rbac.yaml`. No verb on pools, images or
  events is added.
- **banlieue is untouched**, and needs v0.5.9 or later for the claim's `status.poolRef`, which
  the workspace already pins.
- **CALM** (`docs/architecture/calm/architecture.json`): the watcher's relationship to
  banlieue's machines gains the list as a control, and the audience and registry nodes their
  scope; `make calm-validate` and `make calm-diagrams` before implementation.
- **Threat model**, the full pass after implementation (`.claude/rules/threat-modeling.md`): a
  new asset (the pool list, beside A-26); A-16 and A-23 gain "served to the listed namespaces";
  TB-2 gains rows for the unlisted machine, the selector bound outside the list and the refused
  sandbox; TB-3 and TB-4 gain the retraction and its guards; TB-6 gains the registration
  refusal; R-44 is rewritten to what remains (a listed pool's editors, and a proxy-placed
  shared credential) with a new *Revisit when*; the Mermaid diagram needs no new node. The
  header stamp is bumped with the ADR range.
- **Docs:** `docs/guides/deploying.md` (the list, the scoped credentials, the migration),
  `docs/guides/multi-tenant-authorization.md`, the example overlay's `mediatore.yaml` as
  comments, the README status table.

## Alternatives rejected

- **The image digest as the key.** Decision 2: a label's word, stale at every rebuild, and
  silent about the namespace.
- **A wildcard, or "every pool in a listed namespace".** It admits pools that do not exist yet.
  The cost of listing is one line per pool.
- **Watching only the listed namespaces** (one namespaced controller each). It narrows nothing
  the `ClusterRole` grants, loses the log line that says a machine was refused and why, and
  makes the watch set a function of configuration. The filter in code is the same control with
  the evidence kept.
- **Per-namespace `Role`s for `virtualmachines` instead of the `ClusterRole` rule.** It would
  make Kubernetes enforce the namespace half. It also makes every new tenant a manifest change
  to the broker's RBAC, which ADR-0046 decision 10 chose against; worth revisiting with
  ADR-0056, not here.
- **Deriving the list from the namespace map** (every pool in every mapped namespace). The map
  says who may claim; reading it as who may run a pool is the confusion R-44 names.
- **A label or annotation on the pool that the operator sets** (`mediatore.io/admit: "true"`).
  It moves the decision into an object the pool's editor can write.
- **Scoping credentials by group or by subject instead of by namespace.** The namespace is what
  the record carries and what the policy and the pool are already resolved by; a second axis is
  a second way to be wrong.
- **Leaving retraction to ADR-0039's successor.** The list would then stop new entries only, and
  an operator who removed a pool from it would have changed nothing for the machines already
  declared.
- **Banning excluded nodes** (`ban_node`). A ban is a security record an operator removes by
  hand (ADR-0039 decision 2); a pool that is listed again would come back banned.

## What must be proven

Tests first, red before the code, by name.

Unit, `crates/mediatore/src/config.rs`:
`a_config_without_a_map_and_without_pools_admits_every_pool`,
`a_namespace_map_without_pools_refuses_to_start`,
`a_mapped_namespace_with_no_listed_pool_refuses_to_start`,
`an_empty_pools_list_or_a_duplicate_pool_refuses_to_start`,
`a_pool_entry_with_an_unknown_field_refuses_to_start`,
`an_audience_scoped_to_an_unknown_namespace_refuses_to_start`,
`under_a_map_a_proxy_placed_secret_audience_must_say_its_namespaces`,
`under_a_map_a_credentialed_registry_must_say_its_namespaces`,
`namespaces_and_all_namespaces_together_refuse_to_start`,
`every_config_in_the_shipped_examples_and_guides_still_parses`.

Unit, `crates/mediatore-claims/src/lib.rs`: `pools_any_admits_everything`,
`a_listed_pool_is_admitted_in_its_namespace_only`, `pool_matching_is_exact`,
`a_pinned_entry_admits_only_its_revisions_and_nothing_without_the_label`.

Unit, `crates/mediatore-claims/src/watch.rs`:
`a_member_of_an_unlisted_pool_gets_no_node_entry`,
`a_member_in_an_unlisted_namespace_gets_no_node_entry_whatever_its_label`,
`without_a_list_a_member_anywhere_gets_its_node_entry_as_before`,
`a_claim_bound_from_an_unlisted_pool_is_failed_and_its_sandbox_says_why`,
`a_bound_claim_whose_status_names_no_pool_is_not_bound_under_a_list`,
`an_excluded_machine_does_not_keep_its_node_alive`.

Unit, `crates/mediatore-claims/src/nodegc.rs`:
`an_entry_whose_machine_is_gone_is_retracted_after_the_grace`,
`an_entry_whose_machine_left_the_list_is_retracted_and_its_claim_released_first`,
`an_entry_of_an_admitted_machine_is_kept_on_every_pass`,
`a_failed_listing_retracts_nothing`, `retractions_are_capped_per_pass`,
`a_claim_entry_is_never_touched_by_the_node_rule`.

Unit, `crates/mediatore-claims/src/sandbox.rs`:
`a_sandbox_naming_an_unlisted_pool_is_refused_without_a_claim`,
`a_selector_in_a_namespace_with_no_listed_pool_is_refused_without_a_claim`,
`the_pool_refusal_lists_no_served_pool`,
`an_audience_not_served_to_the_namespace_reads_as_not_configured`.

Unit, `crates/mediatore-api/src/lib.rs`:
`a_secret_audience_scoped_to_another_namespace_is_403_at_token_and_at_the_gateway_route`,
`me_carries_no_registry_credential_for_a_registry_scoped_to_another_namespace`,
`an_unscoped_audience_is_served_everywhere_as_before`,
`a_node_whose_machine_is_not_admitted_cannot_register_under_a_list`,
`registration_is_unchecked_without_a_list`.

End to end, `crates/mediatore/tests/e2e_dev.rs` (real HTTP listeners, the test kit's fake IdP):
`two_namespaces_each_get_their_own_secret_audience_and_not_the_others`, and the negative cases
of `.claude/rules/testing.md` for the new refusals. `MemoryEntries` and `MemoryStore` gain what
the retraction needs and refuse what the real ones refuse.

Kind tiers, on the build host:
- `make kind-e2e-watcher` (ADR-0011 live): a labelled machine in an unlisted namespace gets no
  entry; one in a listed pool gets one; removing the pool from the list and restarting the
  broker retracts the entry within a resync.
- `make kind-e2e-sandbox` (ADR-0008 live): a sandbox naming an unlisted pool is `Failed` with
  the reason and owns no claim.
- **`make kind-e2e-tpm` is run by hand on the build host before this merges**, the cluster
  recreated first (`make kind-delete`, then `make kind-e2e-ci KIND_E2E_SUITES=kind-e2e-tpm`).
  This ADR changes when a node entry is declared and adds its retraction, which
  `.claude/rules/testing.md` counts as the TPM attestation path; CI cannot run that tier. The
  report and the PR state `PASS` and the agent ID it attested as, and that a member of a listed
  pool attested and registered under the list. A green `make check` is not a substitute.

`make check`, `make calm-validate` and `make calm-diagrams` green before the commit.

## Open questions

1. **Is `image_revisions` built with the key, or left for the operator who asks?** It needs the
   exact format of banlieue's `banlieue.io/pool-image-revision` label value confirmed against
   banlieue, and it turns every image rebuild into a configuration change. Recommendation: build
   the `(namespace, pool)` key now and keep `image_revisions` in this ADR as decided but
   unbuilt: until a deployment needs it the field is refused at start as unknown, never read
   and ignored.
2. **Does shrinking the list release claims already bound on the excluded pool (decision 9)?**
   The alternative is to stop new binds and let running sandboxes reach their TTL, as a changed
   audience does not flap a bound sandbox. Recommendation: release. The list is a statement of
   trust in a pool's members, a credential may already be on that member, and waiting for a TTL
   is waiting on the party no longer trusted.
3. **Does this ADR really take node-entry retraction for machines that are gone, or only for
   excluded ones?** Recommendation: both, as one rule (decision 9); the predicate is the same
   and a second ADR would re-open the same guards. If the maintainer wants the smaller change,
   decision 9 is cut to excluded machines and ADR-0039's successor takes the rest.
4. **Should `pools` absent, without a map, narrow to `sandboxes.namespace`?** It would close
   R-44 for the single-namespace operator too, and it would stop nodes for declarative
   sandboxes in other namespaces that work today. Recommendation: no, keep today's behaviour and
   the start log line; revisit when the default namespace form is next touched.
5. **The marker `all_namespaces: true` (decision 7): required under a map, or is absence
   enough?** Recommendation: required, for operator-held and registry credentials only, on the
   precedent of `allow_any_authenticated` (ADR-0046 decision 19). It is not backward compatible
   for a map-era deployment and the release notes say so.
6. **Should a shared, proxy-placed `via: secret` audience under a map be refused, not warned
   (decision 8)?** Recommendation: warn now, since gateways are optional; refuse once the
   gateway shape is the only supported one for multi-tenant deployments, in its own ADR.
7. **The early answer at the front door.** `POST /v1/claims` could answer `400 invalid_pool` for
   an unlisted `pool_ref` instead of creating a sandbox that fails. Recommendation: not in this
   ADR; the sandbox's `status.reason` serves both paths, and a second answer is a second text to
   keep free of other tenants' names.
