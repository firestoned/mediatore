<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0056: The broker in a namespace of its own, and admission policies that do not depend on its name

**Status:** Accepted and implemented. Decisions 4 and 5 were built first, 2026-11-26 (#179), and released in v0.4.0; decisions 1 to 3, 6 and 7 and what was left of 4 and 5 were built 2026-11-27 (the notes under each decision say what was built and where it differs from the text). The eight open questions were answered 2026-11-27 by taking each recommendation. The procedure of decision 7 is written and rehearsed in kind; the migration of a running environment is its operator's to run and was not run by this change · **Date:** 2026-11-19

Roadmap 02 (SPIRE on the cluster: the deployment and its overlay) and roadmap 05 (the store,
whose Secrets are what moves). This is the *Revisit when* of accepted risk R-45
(`docs/security/threat-model.md` §8). Amends
[ADR-0007](0007-broker-identity-and-spiffe-mtls.md) (where mediatore runs: "a `Deployment` in
`banlieue-system`", and the `ClusterSPIFFEID`'s namespace selector),
[ADR-0006](0006-registration-entries-as-clusterstaticentry.md) decision 6 (the entries admission
policy is bound to requests from one literal username) and
[ADR-0034](0034-the-kubernetes-api-as-the-brokers-store.md) decisions 2 and 3 (which namespace
"the broker's own" is). Touches the subject policy of
[ADR-0008](0008-agentsandbox-crd-owned-by-mediatore.md) and the Lease of
[ADR-0011](0011-claim-watcher.md) decision 6. Changes no token shape, no SPIFFE ID
([ADR-0004](0004-spiffe-identity-scheme.md): the broker is `spiffe://<td>/mediatore` in any
namespace) and no storage contract. It changes the deployment topology and what the broker's
`ServiceAccount` can reach (TB-2, TB-9), which is why it is an ADR.

## Context

The base deployment puts every namespaced object of mediatore in banlieue's namespace:
`deploy/base/kustomization.yaml` sets `namespace: banlieue-system`. One namespace was the shape
of the first deployment and nothing since asked the question. What that means, read in
`deploy/base`:

- **The broker holds every verb on every Secret in that namespace.** The `mediatore-sessions`
  `Role` in `deploy/base/rbac.yaml` grants `get`, `list`, `create`, `update`, `patch` and
  `delete` on `secrets` with no `resourceNames`, because a Role cannot name Secrets that do not
  exist yet and the store makes one per sandbox (ADR-0034 decision 2). The grant is right in
  shape and wrong in place: it covers whatever else is kept in banlieue's namespace.
- **The reverse holds too.** The STS signing key (`mediatore-sts`), the local sealer's key
  (`mediatore-sealing`), the operator-held audience credentials and the registry tokens are
  Secrets in the same namespace. Anything granted `get` on Secrets there for banlieue's sake
  reads them, and with the local sealer reads the sealing key beside the envelopes it opens.
- **The broker's SPIFFE identity is selected by that namespace.** `deploy/base/clusterspiffeid.yaml`
  selects namespace `banlieue-system`, the pod label, the `ServiceAccount` and the container
  name. A principal who may create pods in banlieue's namespace is inside that selector's
  namespace half.
- **The `ClusterRole` holds no Secret verb.** Its rules, pinned by
  `the_brokers_cluster_role_is_pinned` (`crates/mediatore-claims/src/sandbox.rs`), are on
  `mediatore.io`, `banlieue.io` and `spire.spiffe.io` only. Everything the broker does in
  banlieue's namespace that is not a Secret or the Lease already goes through it, cluster-wide.
- **The code has no namespace of its own written in it.** The store's home is
  `client.default_namespace()` (`KubeStore::new`, `crates/mediatore-claims/src/kubestore.rs`),
  and so is the Lease's (`crates/mediatore/src/main.rs`): in a pod, the namespace of the pod's
  own `ServiceAccount`. No configuration key names it.
- **Three admission policies name the broker by one literal**,
  `system:serviceaccount:banlieue-system:mediatore`, and they do not fail the same way when it
  is wrong. `agentsandbox-status.yaml` uses it in a validation: a broker under another name is
  refused its own status writes, visibly. `agentsandbox-subject.yaml` uses it as an exemption:
  a broker under another name loses the exemption, visibly. `clusterstaticentry-mediatore.yaml`
  uses it in `matchConditions`: a broker under another name is **not matched**, so the policy
  that bounds what it may declare to SPIRE (TB-3's main control) no longer applies to it, and
  nothing says so. An overlay's `namespace:` rewrites object metadata; it does not rewrite a
  string inside a CEL expression or a label selector's value.

R-45 states the first two as a design limit, accepted while one namespace was the shape and
the cluster's administrators are trusted. Its revisit condition is this move.

## Decision

1. **mediatore runs in `mediatore-system`.** `deploy/base/kustomization.yaml` sets
   `namespace: mediatore-system` and the base gains `deploy/base/namespace.yaml`, the
   `Namespace` itself, labelled `pod-security.kubernetes.io/enforce: restricted` (the pod is
   already written for it, ADR-0007). The `mediatore-sessions` `Role` keeps its rules byte for
   byte and moves with the namespace: the same verbs on `secrets`, now over a namespace that
   holds only the broker's. The name follows banlieue's (`<project>-system`). The `Role` still
   cannot be narrowed by name, for the reason in Context; the namespace is the bound, which is
   what the comment in `rbac.yaml` already claims ("the broker reads no Secret elsewhere") and
   will then be true of the grant and not only of the code.

   *Built 2026-11-27, as written.* `deploy/base/kustomization.yaml` sets the namespace and
   lists `namespace.yaml` first; the `Role`'s rules are unchanged. One correction to the
   sentence above: "the broker reads no Secret elsewhere" was already untrue of the grants
   in one respect and still is, since ADR-0055 lets a team bind the broker to `get` on
   Secrets it names one by one in its own namespace (`deploy/audience-credentials`). That
   grant is the team's, by name, and not the base's. Controls:
   `the_base_deploys_into_mediatore_system_and_ships_the_namespace` and
   `the_secrets_role_is_namespaced_and_its_rules_are_pinned`
   (`crates/mediatore-claims/src/sandbox.rs`); `scripts/check_release_assets.py` holds the
   release manifest to one `Namespace` and to no object outside it.

2. **What moves with it.** Every namespaced object the base ships and everything that names
   the namespace:
   - `deploy/base/serviceaccount.yaml`, `deployment.yaml`, `service.yaml`,
     `service-sandbox.yaml`, `ingressroute.yaml`, and the generated `mediatore-config`
     ConfigMap, by the kustomization's `namespace`;
   - `deploy/base/rbac.yaml`: the `ClusterRoleBinding`'s subject, the `mediatore-watcher-lease`
     and `mediatore-sessions` `Role`s and `RoleBinding`s and their subjects;
   - the Secrets the operator creates (`mediatore-sts`, `mediatore-sealing` with the local
     sealer, `mediatore-audience-secrets`, `mediatore-registry`, any CA bundle mounted from
     one) and the Secrets the store writes (`mediatore-session-<sandbox uid>`, its
     per-audience delegation Secrets, `mediatore-logs-<claim uid>-<segment>`);
   - the store's two namespaced kinds, `SandboxNode` and `PolicyFloor` (ADR-0034 decision 3),
     and the Lease `mediatore-watcher`;
   - `deploy/base/clusterspiffeid.yaml`: `namespaceSelector` on
     `kubernetes.io/metadata.name: mediatore-system`;
   - the username in the three admission policies
     (`deploy/base/admission/clusterstaticentry-mediatore.yaml`, `agentsandbox-subject.yaml`,
     `agentsandbox-status.yaml`), as decision 4 rewrites them, and the subject policy's
     parameter ConfigMap `mediatore-agentsandbox-subject-policy` with the binding's
     `paramRef.namespace`;
   - `deploy/policy-bundles/rbac.yaml`: the `RoleBinding` subject's namespace (the `Role`
     itself stays in each policy namespace);
   - `deploy/overlays/homelab-example/` (`kustomization.yaml`, the `NetworkPolicy`, the
     ingress) and `dev/kind/broker/kustomization.yaml`;
   - the kind tiers: every `-n banlieue-system` and `banlieue-system.svc` in the `Makefile`
     that addresses the broker or its fixtures (Dex, glauth, OpenBao), `dev/kind/*.sh`
     (`sa-kubeconfig.sh`, `openbao-setup.sh`'s `bound_service_account_namespaces`, the
     `*-e2e.sh` scripts, `tpm-e2e.sh`), `dev/kind/{dex,openbao,mtls,gateway}/*.yaml` and
     `dev/kind/spire/server-conf-patch.yaml` where they name the fixtures' Services;
   - the tests and literals in the crates: `the_status_policy_admits_the_broker_alone_and_denies`
     (`crates/mediatore-claims/src/sandbox.rs`), `crates/mediatore-spire/tests/live_kube.rs`,
     `crates/mediatore/tests/e2e_entra.rs`, the example URL in `crates/mediatore/src/main.rs`;
   - the guides (`docs/guides/deploying.md`, `homelab-walkthrough.md`, `claude-end-to-end.md`,
     `requesting-a-sandbox.md`, `multi-tenant-authorization.md`, `the-entra-path.md`,
     `research-agent-walkthrough.md`, `testing.md`), the skill
     `.claude/skills/claude-e2e-setup/SKILL.md`, the CALM node's description and the threat
     model's component table.

   *Built 2026-11-27.* Everything in the list moved, with these differences from it:
   - **kustomize rewrites less than the list assumed.** A `namespace:` in an overlay does not
     rewrite a `RoleBinding` or `ClusterRoleBinding` subject that names its namespace, so
     the four subjects of `deploy/base/rbac.yaml` join the things an overlay that moves the
     broker patches by hand, with the parameter's `broker`, the three bindings'
     `paramRef.namespace` and the `ClusterSPIFFEID`'s `namespaceSelector`. Found when the
     rehearsal's overlay (`dev/kind/migration`) rendered the old subjects; the table is in
     `docs/guides/deploying.md`, and every omission fails closed.
   - `deploy/audience-credentials/rbac.yaml` (ADR-0055, after this ADR was written) binds
     the broker's `ServiceAccount` too and moved with `deploy/policy-bundles/rbac.yaml`.
   - `deploy/gateway/kustomization.yaml` keeps `namespace: banlieue-system`: its objects
     are banlieue's kinds and stay with the pools (decision 3).
   - The kind fixtures (Dex, glauth, OpenBao) moved into `mediatore-system` with the
     broker, as listed; all three already ran under Pod Security `restricted`, which the
     namespace now enforces.
   - In the guides, a sandbox namespace that happens to be `banlieue-system` (the worked
     example of `claude-end-to-end.md`, the skill, `the-policy-bundle.md`) stays: that is
     where that environment's pool lives. The dated transcripts in `docs/guides/testing.md`
     are left as they were taken, under a note.
   - Controls: `no_base_manifest_names_banlieues_namespace`,
     `the_cluster_spiffe_id_selects_the_brokers_namespace`
     (`crates/mediatore-claims/src/sandbox.rs`), and the kind mTLS tier's `lookalike` pod (the
     broker's label, `ServiceAccount` name and container name in another namespace, issued
     nothing).

   Three things outside the repository name the same username and move in the same change
   window, listed so the migration does not find them by failing: the `brokers:` line of
   banlieue's `banlieue-claim-subject-policy` ConfigMap, the OpenBao Kubernetes auth role of
   the transit sealer (ADR-0015, bound to the `ServiceAccount`'s name and namespace), and an
   Entra federated credential's subject where ADR-0016's keyless form is used.

3. **What stays in banlieue's namespace, and how the broker reaches it.** banlieue's
   controller, its own Secrets and ConfigMaps (the claim subject policy among them) stay where
   they are and are no longer in any `Role` of the broker's. Pools, claims, machines and
   sandboxes live wherever the operator puts them (`banlieue-system`, `sandboxes`, a tenant's
   namespace); the gateway objects of `deploy/gateway` are banlieue's kinds and stay with the
   pools. The broker reaches all of it through its `ClusterRole`, which is not changed by this
   ADR. Its rules, as `deploy/base/rbac.yaml` has them today:

   | API group | Resource | Verbs |
   | --- | --- | --- |
   | `mediatore.io` | `agentsandboxes` | `get`, `list`, `watch`, `patch`, `create`, `delete` |
   | `mediatore.io` | `agentsandboxes/status` | `patch` |
   | `mediatore.io` | `agentsandboxes/finalizers` | `update` |
   | `mediatore.io` | `sandboxnodes`, `policyfloors` | `get`, `list`, `watch`, `create`, `update`, `patch`, `delete` |
   | `banlieue.io` | `virtualmachineclaims` | `get`, `list`, `watch`, `create`, `delete` |
   | `banlieue.io` | `virtualmachineclaims/status` | `get` |
   | `banlieue.io` | `virtualmachines` | `get`, `list`, `watch` |
   | `spire.spiffe.io` | `clusterstaticentries` | `get`, `list`, `watch`, `create`, `delete` |

   **None is a verb on `secrets`, and none is on the core group at all.** The broker's only
   Secret grant is the `mediatore-sessions` `Role`; its only ConfigMap grant is the
   `mediatore-policy-bundles` `Role` in each policy namespace (`get`, `list`, `watch`); its only
   Lease grant is `mediatore-watcher-lease`. After the move the broker holds no grant of any
   kind that is scoped to banlieue's namespace, unless that namespace is also a policy
   namespace. Control: `deploy/base/rbac.yaml`, pinned by `the_brokers_cluster_role_is_pinned`
   and a new test on the two `Role`s.

   *Built 2026-11-27, with one change to the table* (open question 5, answered yes): the
   row `mediatore.io` `sandboxnodes`, `policyfloors` left the `ClusterRole` for a third
   `Role` in the home namespace, `mediatore-store`, with the same seven verbs. The store
   addresses both kinds in its home only (`KubeStore::nodes`, `KubeStore::floors`), so
   nothing else changed. The pinned literal of `the_brokers_cluster_role_is_pinned` lost
   that rule; `the_brokers_cluster_role_holds_no_verb_on_the_core_group` also refuses a
   wildcard and either store kind there, and
   `the_secrets_role_is_namespaced_and_its_rules_are_pinned` pins all three `Role`s (not
   two), their namespace, their bindings and the `ClusterRoleBinding`'s subject. "Its only
   Secret grant is the `mediatore-sessions` `Role`" is true of the base; the by-name grant
   of `deploy/audience-credentials` is the exception noted under decision 1.

4. **The entries policy applies to what is declared, not only to who declares it, and none of
   the three can fail open on a name.** In `deploy/base/admission/clusterstaticentry-mediatore.yaml`:
   - the `matchConditions` expression becomes a disjunction: the request is from the broker's
     `ServiceAccount`, **or** the object's name starts with `mediatore-`, **or** it carries
     `app.kubernetes.io/managed-by: mediatore`, **or** its `spec.spiffeID` has a path under
     `/banlieue/`. An entry that looks like the broker's is held to the two shapes whoever
     sends it. The gateway entries of `deploy/gateway/clusterstaticentries.yaml` (`gateway-*`,
     `spiffe://<td>/gateway`, labelled `mediatore.io/role: gateway`) match none of the three
     object tests and stay governed by RBAC as today;
   - one validation is added: an object matched by what it is must be sent by the broker's
     `ServiceAccount`. A wrong name in the policy then refuses the broker's own entries: no
     sandbox binds, and the denial is in the broker's log. That is the fail-closed twin of
     today's silent non-match, and the same failure the status policy already has;
   - the existing validations are unchanged.

   The status and subject policies already fail closed on a wrong name and keep their logic.
   All three read the username from **one** place: the key `broker` of the parameter ConfigMap
   the subject policy already uses (`mediatore-agentsandbox-subject-policy`, in the broker's
   namespace), bound with `parameterNotFoundAction: Deny`, in place of three literals in three
   files. An overlay that renames the `ServiceAccount` or the namespace patches one value.
   Control: the three files under `deploy/base/admission/`, and unit tests beside the existing
   ones in `crates/mediatore-claims/src/sandbox.rs` that parse them.

   *Built 2026-11-26, ahead of the namespace move, for the entries policy alone.* The match
   condition is the disjunction above and the sender validation is the policy's first, so a
   broker the policy does not name is refused its own entries and told why. What differs from
   the text: **the username is still a literal**, the same string as before, in three files.
   Open question 3 (one parameter or three literals) is not answered, so nothing reads
   `broker` from a ConfigMap, and an overlay that renames the `ServiceAccount` or its namespace still
   patches the literal (twice in `clusterstaticentry-mediatore.yaml`, once in each
   `AgentSandbox` policy). One exemption the text did not have: the sender validation admits an
   UPDATE that leaves `spec` as it was, from anyone, since the garbage collector removing a
   finalizer and an administrator's annotation declare nothing; the shape validations still
   judge it. Open question 4 is answered yes by this build, with its consequence: an administrator can no longer apply or
   edit the `spec` of an entry that looks like the broker's, by hand; deleting one is not
   matched and stays RBAC's. A gateway entry given a `mediatore-` name or the managed-by label
   is claimed by both policies and admitted by neither. Controls:
   `deploy/base/admission/clusterstaticentry-mediatore.yaml`,
   `the_entries_policy_claims_an_entry_by_what_it_is_and_names_its_one_sender` and
   `the_shipped_gateway_entries_carry_none_of_the_signs_of_a_brokers_entry`
   (`crates/mediatore-claims/src/sandbox.rs`), and the dry runs of the kind gateway tier
   (`dev/kind/gateway-e2e.sh`), which are what prove the CEL.

   *Built 2026-11-27: the parameter* (open question 3, answered: the parameter, confirmed on
   an API server before it was taken). The three policies declare `paramKind: ConfigMap` and
   read `params.data.broker.trim()`: the subject policy in its `isMediatore` variable, the
   status policy in its one validation, the entries policy in its match condition and its
   sender validation. No file carries a `ServiceAccount` username any more; the ConfigMap's
   `broker` is `system:serviceaccount:mediatore-system:mediatore`, and each binding names the
   ConfigMap and its namespace with `parameterNotFoundAction: Deny`. What differs from the
   text, and what the confirmation showed:
   - **A missing parameter refuses more than the broker's entries.** The parameter is
     resolved before the match condition is evaluated, so with the ConfigMap absent every
     create and update of a `ClusterStaticEntry` is refused, the gateway's entries
     included; with the ConfigMap present and the key absent the same, because a
     disjunction with an erroring term and no true one is an error under
     `failurePolicy: Fail`. That is the fail-closed side and the files say it in capitals.
   - **The self-check tells that case apart.** A refusal that names the policy because the
     policy could not be evaluated proves nothing, so it is a start error of its own
     (`SelfCheckError::Parameter`), beside `NotTheBroker` for a parameter that names
     another account.
   - **"An overlay patches one value" is not so**, for the reason under decision 2: one
     value and `paramRef.namespace` in three bindings, and the subjects and the selector.
   - The value is trimmed, so a `broker: |` block with its trailing newline works as the
     other keys of that ConfigMap do.
   - Controls: `the_three_policies_read_the_broker_from_one_parameter_and_deny_without_it`
     and `the_status_policy_admits_the_broker_alone_and_denies`, rewritten for the
     parameter (`crates/mediatore-claims/src/sandbox.rs`); live, the second test of
     `crates/mediatore-spire/tests/live_kube.rs` (an account of the broker's name in
     another namespace, with every RBAC verb, is refused a permitted node entry by the
     sender validation), run by `make kind-e2e-entries`.

5. **A startup self-check: the broker proves the entries policy binds it, or does not start.**
   Outside `dev_mode`, before either listener serves and before the watcher asks for the Lease,
   the broker sends a server-side dry-run create (`dryRun=All`, nothing is persisted) of a
   `ClusterStaticEntry` named `mediatore-selfcheck-<random>` in a shape the policy forbids and
   the CRD's schema accepts: a node SPIFFE ID whose parent is not a TPM agent ID. The start
   continues only if the API server refuses it **and** the refusal is the admission policy's
   (the status carries the policy's name and message). An admitted dry run, a refusal from
   anything else (RBAC, the schema) and an unreachable API server are each a start error naming
   `deploy/base/admission/clusterstaticentry-mediatore.yaml`. A second dry run, of a permitted
   node shape, must be admitted, so the fail-closed misconfiguration is reported at start and
   not at the first bind. The check needs no new verb (`create` on `clusterstaticentries` is
   held) and is repeated on the Lease holder at each resync; a failure there stops new entries
   from being declared and logs an error, and does not release what is bound. Control: a new
   `KubeEntryManager::self_check` in `crates/mediatore-spire/src/kube.rs`, called from
   `crates/mediatore/src/main.rs` and from `Watcher::resync` in
   `crates/mediatore-claims/src/watch.rs`; `MemoryEntries` answers it as the policy would.

   *Built 2026-11-26, ahead of the namespace move, in part.* `EntryManager::self_check`
   (`crates/mediatore-spire/src/lib.rs`, with `KubeEntryManager`'s in `kube.rs`) is called from
   `proven_entries` in `crates/mediatore/src/main.rs` as the first thing `serve` does with the
   cluster. What differs from the text: the forbidden entry is not a node ID under a wrong
   parent but `spiffe://<td>/banlieue/selfcheck/refused` parented to `spiffe://<td>/spire/server`,
   of a class no controller manager renders, so two validations refuse it and it is the shape
   of nothing real. **There is no second dry run of a permitted shape.** Its purpose is served
   by reading the denial: when the policy's answer is its sender validation, the broker is not
   the identity the policy names, and the start fails saying so (`SelfCheckError::NotTheBroker`).
   That rests on the API server reporting the first failed validation, which the kind tier
   shows and a unit test cannot. An RBAC refusal, a refusal that does not name this policy and
   an unanswered request are three more start errors, each under its own name; the trait's
   default refuses, so a manager that cannot ask does not start a broker. **The check is not
   repeated at resync** (open question 7 is not answered): a policy removed under a running
   broker is not noticed until the next start. It runs in `dev_mode` too, where
   `MemoryEntries` answers as a server that enforces the policy does.

   *Built 2026-11-27: the check at resync* (open question 7, answered: stop declaring).
   `Watcher::resync` (`crates/mediatore-claims/src/watch.rs`) runs the self-check first, on
   the replica holding the Lease, and logs a failure as an error. What stops the
   declarations is not in the watcher, and that is the difference from the text: the
   broker's entry manager is wrapped in `mediatore_spire::Gated`
   (`crates/mediatore-spire/src/lib.rs`, in `proven_entries`), which remembers the last
   answer and, while it was a failure, asks once more before each `ensure_node_entry` and
   `create_claim_entry` and refuses with `SpireError::Unproven` unless that passes. The gate
   covers every path that declares on that replica, the API's bind at node registration as
   well as the watcher's, and declaring resumes as soon as the policy answers, without
   waiting a resync. Retracting and listing are never gated, and nothing bound is released.
   Limits, stated in the threat model too: a replica that does not hold the Lease checks at
   its start only; between a policy's removal and the Lease holder's next resync
   (`watcher.resync_secs`) entries are unjudged. `MemoryEntries` can be told to answer the
   check as a server whose policy is gone (`answer_self_check_with`), which makes the fake
   less trusted and no more permissive. There is still no second dry run of a permitted
   shape, for the reason of the first note. Controls:
   `a_gate_declares_nothing_while_unproven_and_always_retracts`,
   `a_gate_never_checked_asks_before_its_first_declaration`,
   `a_policy_that_could_not_read_its_parameter_is_not_proof` (`crates/mediatore-spire`),
   `a_failed_self_check_at_resync_stops_new_entries_and_releases_nothing`
   (`crates/mediatore-claims/src/watch.rs`), and the first test of `live_kube.rs`, which now
   runs the self-check as the broker's `ServiceAccount` against the real API server.

6. **The home namespace is always the pod's own; it is not configuration.** The store, the
   Lease and the session Secrets stay on `client.default_namespace()`. No `store.namespace` key
   is added: it would be a second source for one fact, and an edit of `mediatore.yaml` could
   then point the broker's Secret reads at a namespace its `Role` was never meant for, or split
   the store between two. The startup line `store: the Kubernetes API (ADR-0034)
   namespace=<home>` already states it. Two start checks are added outside `dev_mode`: the
   home namespace is not `default` (what a client outside a pod falls back to), and the broker
   warns, one line, when a claimable namespace (`sandboxes.namespace`, or a key of
   `sandboxes.namespaces`) is its home, since sandboxes there put tenants' objects back beside
   the keys. Control: `crates/mediatore/src/main.rs`.

   *Built 2026-11-27, as written* (open question 6, answered: warned, not refused; the
   refusal one release later is not built and has no date). `check_home_namespace` runs in
   `kube_client`, as soon as there is a client and before the self-check, the store or a
   listener. A broker run outside a cluster through `spire.entries.kubeconfig` must name
   its namespace in that kubeconfig's context, or it is refused as `default`; the error
   says so. Controls: `a_home_namespace_of_default_refuses_to_start`,
   `a_claimable_namespace_equal_to_home_is_warned`.

7. **Migration of a running environment: the release that carries decisions 4 and 5 first, in
   place; then the move, with the old broker stopped before the new one starts.** The order,
   each step leaving the broker with its Secrets and the policies with a subject:
   1. Upgrade in the old namespace to the build and base that carry decisions 4 and 5, with the
      parameter's `broker` still the old username. From here no rename can fail open.
   2. Create `mediatore-system`. Copy into it what the operator created: the STS key (the same
      key, so the `kid` and the JWKS do not change and no verifier notices), the sealing key or
      nothing with transit, the audience and registry Secrets, the CA bundles, the config.
   3. Where a binding outside the repository names the username (decision 2's three), add the
      new subject **beside** the old one. Add the new `RoleBinding` subject in each policy
      namespace.
   4. Let the claims end, or accept step 6. Scale the old `Deployment` to zero. This is the
      one outage: no token is issued and no claim binds until step 7. Running sandboxes keep
      their SVIDs and the tokens their proxies hold. Two brokers must never run at once: the
      Lease is per namespace, so two namespaces would mean two leaders.
   5. Copy the store's objects that must survive: every `PolicyFloor` (the replay floor of
      ADR-0026; without it an older signed bundle would be admitted again) and every banned
      `SandboxNode` (a ban is a security record, ADR-0039). Unbanned nodes need no copy: an
      idle guest is refused once, restarts and registers again (ADR-0039 decision 5).
   6. Only if claims were not drained: copy their session, delegation and log Secrets and the
      `SandboxNode`s they are bound to. **The copies carry no `ownerReferences`, no `uid` and
      no `resourceVersion`.** An owner reference cannot cross a namespace, and the garbage
      collector deletes an object whose owner it cannot find in the object's own namespace;
      the broker itself writes none for a sandbox outside its home (`owner_refs`,
      `crates/mediatore-claims/src/kubestore.rs`), and release and the sweep remove them
      (ADR-0046 decision 9).
   7. Apply the base in `mediatore-system` with the parameter's `broker` set to the new
      username: the `ServiceAccount`, the `Role`s and bindings, the `ClusterRoleBinding`'s
      subject, the `ClusterSPIFFEID`'s selector, the `Deployment` and the Services. The
      sandbox Service keeps the address the pool's members and the gateways' relay dial
      (released from the old Service first); the user API keeps its host. The new broker
      starts only if its self-check passes, rebuilds its records from the `AgentSandbox`
      resources (ADR-0034 decision 1) and opens the copied envelopes.
   8. Verify (a login, a claim, a token; the `store:` line naming `mediatore-system`), then
      remove from banlieue's namespace the `mediatore-sessions` and Lease `Role`s and bindings,
      the old `ServiceAccount`, the old Lease, the store's leftovers and, last, the key
      Secrets, and remove the old subject from the bindings of step 3.

   **Existing Secrets can simply be re-created in the new namespace.** A sealed envelope is
   bound to a UID and a purpose and to nothing else: `SealPurpose::context` in
   `crates/mediatore-store/src/seal.rs` is the bare UID for a session and a fixed label plus the
   UID for stored output, used as the AEAD's associated data locally and as the derivation
   context at transit, and the UID is the sandbox's (`ClaimRecord::seal_binding`). Neither the
   namespace nor the Secret's name is in the binding, and a sandbox keeps its UID because the
   sandbox does not move. The recommended path is still the drain (ADR-0034 decision 6: claims
   are ephemeral, the cutover is at a release boundary, no migration tool); step 6 is for an
   environment that cannot drain. Control: the procedure in `docs/guides/deploying.md`.

   *Written and rehearsed 2026-11-27; not run on any real environment* (open question 8,
   answered: drain recommended, the copy path documented and rehearsed once). The eight
   steps are in `docs/guides/deploying.md` with their commands, and
   `make kind-rehearse-migration` (`dev/kind/migration-rehearsal.sh`) runs them by the copy
   path: the kind broker put back in `banlieue-system` under an overlay with the patches of
   decision 2, a claim bound there with its session sealed at the OpenBao transit engine,
   the move, and the same claim's token issued by the broker in `mediatore-system` from the
   copied session. The transcript is in `docs/guides/testing.md`. What the rehearsal does
   not cover: banlieue's `brokers` line and an Entra federated credential (neither exists
   in kind; the OpenBao role is the one outside binding it exercises), a `LoadBalancer`
   address handed from the old Service to the new (the kind pods dial the Service by its
   new name), and a `PolicyFloor` in the copy (the Dex tier reads no bundle; the command
   runs over an empty list). Step 1 has one more case than the text: on a base that
   carries the parameter, "the old username" is the parameter's `broker` in an overlay that
   keeps the broker in the old namespace, which is what the rehearsal's overlay is. Unit:
   `a_session_secret_without_an_owner_reference_in_a_new_home_opens_for_its_sandbox`
   (`crates/mediatore-claims/src/kubestore.rs`).

## Security analysis

STRIDE for the boundaries this ADR changes (TB-2, TB-3, TB-8, TB-9). "Control" names what the
implementation must provide. Written while none of it was built; **all of it is built as of
2026-11-27**, and the threat model's pass of that day (`docs/security/threat-model.md`, TB-2,
TB-3, TB-4, TB-8, TB-9, R-45) is where each control is cited as it exists. Three rows are a
procedure in a guide and not a mechanism (the two brokers, the copied session's owner
reference, the floors), and the threat model says so; "an API-server audit rule" is the
deployment's and is not shipped.

| Threat | STRIDE | Control |
| --- | --- | --- |
| A compromised broker reads or rewrites Secrets that are not its own | I/T | The `mediatore-sessions` `Role` in a namespace that holds only the broker's, `deploy/base/rbac.yaml` and `deploy/base/kustomization.yaml` |
| A principal granted Secret reads for banlieue's sake reads the STS key, the sealing key or an audience credential | I | The key Secrets in `mediatore-system`, `deploy/base/namespace.yaml` and the guide's step 2 |
| A pod created in banlieue's namespace is issued the broker's SVID | S/E | `namespaceSelector` on `mediatore-system` in `deploy/base/clusterspiffeid.yaml`; the pod label, `ServiceAccount` and container selectors exist |
| The broker runs under a name the entries policy does not match, and declares an entry outside the two shapes | E | Match on what is declared, `deploy/base/admission/clusterstaticentry-mediatore.yaml` |
| Another principal declares an entry that looks like the broker's | S | The added validation on the sender, same file; RBAC on `clusterstaticentries` for everyone else (deployment, exists) |
| The policy is absent, unbound or edited to `Warn`, and nothing notices | T/E | `KubeEntryManager::self_check`, `crates/mediatore-spire/src/kube.rs`, at start and at each resync |
| Three literals drift apart across the policies | T | One `broker` key in the parameter ConfigMap, `deploy/base/admission/agentsandbox-subject.yaml`, and a test that the three bindings read it, `crates/mediatore-claims/src/sandbox.rs` |
| The parameter ConfigMap is edited to name another account | S/E | It is in `mediatore-system`, written by whoever deploys the broker; an API-server audit rule on it (deployment). It is an A-9 asset already and gains this key |
| A configuration edit points the store at another namespace | T | No such key exists (decision 6); the refusal of `default` as home, `crates/mediatore/src/main.rs` |
| Two brokers hold a Lease each during the move and both bind | T/D | The order of decision 7 (old to zero first), `docs/guides/deploying.md`; `bind` is idempotent and entry creation tolerates a conflict (exists) |
| A copied session Secret is collected for an owner in another namespace, mid-claim | D | Copies carry no owner reference, decision 7 step 6, `docs/guides/deploying.md` |
| The replay floor is lost in the move and an older bundle is admitted | T | `PolicyFloor`s copied before the new broker starts, decision 7 step 5, `docs/guides/deploying.md` |
| An envelope copied to the new namespace opens for another sandbox | I | The binding is the sandbox UID and the purpose, `crates/mediatore-store/src/seal.rs` (exists, unchanged) |
| The self-check's dry run is itself a way to write an entry | E | `dryRun=All` persists nothing; the shape is one the policy refuses; the name is `mediatore-selfcheck-*`, never a node's or a claim's, `crates/mediatore-spire/src/kube.rs` |

## Consequences

- **R-45 narrows to what remains.** A compromised broker still reads and rewrites its own
  Secrets (R-4 is unchanged: the broker is a single trust point), and with the local sealer the
  sealing key is still a Secret beside the envelopes, now with nothing else's readers. The
  transit sealer (ADR-0015) remains the answer to that half.
- **The namespace becomes a boundary an operator can point at.** A `NetworkPolicy` that
  defaults to deny, Pod Security `restricted` and "who has any `Role` here" are each a
  one-namespace statement. The example overlay's `NetworkPolicy` moves as it is; shipping one in
  the base is the review's separate item and not decided here.
- **Not compatible for an existing deployment.** The base's namespace changes, so an operator
  who applies the new base over a running environment without the procedure gets a second,
  empty broker beside the first. The release notes lead with decision 7, and the release that
  carries the move is a minor version with the migration as its headline.
- **Every kind tier moves at once.** `make kind-broker` and the fixtures change namespace in
  one commit, since the tiers share them. The kind cluster then has the shape the guides
  describe (the broker in one namespace, pools in another), which the single namespace never
  exercised.
- **A sandbox in the broker's home namespace keeps working** and is warned about (decision 6).
  Its session Secret is owner-referenced as today; everywhere else release and the sweep
  remove it, the path ADR-0046 already tests.
- **The broker cannot start against an API server it cannot ask** (decision 5). That is one
  more dependency at start, on a server the store already needs for everything.
- **The `ClusterRole` is unchanged**, so the pinned test stays, and so is every token, SPIFFE
  ID, CRD and the store's contract. banlieue changes one line of one ConfigMap.
  *As built 2026-11-27:* the `ClusterRole` changed once, by open question 5 (the store's two
  kinds left it for a `Role`), and its pinned test changed with it; the rest of the
  sentence stands.
- **CALM** (`docs/architecture/calm/architecture.json`): the broker node's deployment detail
  and the admission controls on its relationship to the Kubernetes API; `make calm-validate`
  and `make calm-diagrams` before implementation.
- **Threat model**, the full pass after implementation (`.claude/rules/threat-modeling.md`):
  §2's component table (the namespace of each component); A-7 and A-9 (the parameter's new
  key); TB-2 and TB-3 (the entries policy's scope and the self-check, with the TB-3 row that
  says only the broker's account is constrained reworded); TB-8 (the selector's namespace);
  TB-9 (the Secrets' namespace); §7 hardening; R-45 rewritten to its residue with a new
  *Revisit when*; the Mermaid diagram's namespace subgraph, if it draws one. The header stamp
  is bumped with the ADR range.

## Alternatives rejected

- **Narrow the `Role` with `resourceNames`.** A Role cannot name objects that do not exist, and
  `create` cannot be bounded by name at all; the store makes a Secret per sandbox.
- **Keep the namespace and move banlieue's Secrets out.** It asks the other project to move
  for this one's grant, and leaves the `ClusterSPIFFEID` selecting a namespace two projects
  deploy pods into.
- **A second `ServiceAccount` for the Secrets in a second namespace, the broker staying put.**
  Two identities in one process, two tokens, and the keys still mounted in a pod in the shared
  namespace.
- **Only the keys in a namespace of their own, mounted across.** A pod mounts Secrets from its
  own namespace only.
- **A configurable home namespace.** Decision 6: a second source for one fact, and a way to
  aim the broker's reads by editing a ConfigMap.
- **Matching the broker by a pattern on the username** (any `ServiceAccount` named
  `mediatore`). It would match an account of that name in any namespace, a tenant's included.
- **Keeping three literals and a test that they agree.** The test exists for two of them today
  and did not stop the entries policy from failing a different way from the other two; one
  value and a fail-closed validation is the smaller thing to get right.
- **A webhook in place of the CEL policy, to read the broker's identity at run time.**
  ADR-0006 decision 6 chose CEL in the API server, with no webhook, so the restriction holds
  whatever mediatore's own code does; that stands.
- **The self-check alone, the policy left as it is.** The check proves the policy binds the
  broker that runs it; it does nothing for a second principal or for the hours between a
  policy edit and the next resync. Both are wanted.
- **An in-place rename with both brokers up for the overlap.** The Lease is namespaced, so the
  overlap is two leaders.

## What must be proven

Tests first, red before the manifests and the code, by name.

Unit, `crates/mediatore-claims/src/sandbox.rs`, beside the existing `deploy/base` checks:
`the_base_deploys_into_mediatore_system_and_ships_the_namespace`,
`no_base_manifest_names_banlieues_namespace`,
`the_secrets_role_is_namespaced_and_its_rules_are_pinned`,
`the_brokers_cluster_role_holds_no_verb_on_the_core_group` (and
`the_brokers_cluster_role_is_pinned` unchanged),
`the_cluster_spiffe_id_selects_the_brokers_namespace`,
`the_entries_policy_matches_by_name_prefix_label_and_spiffe_path_as_well_as_by_sender`,
`the_entries_policy_refuses_a_matched_object_from_any_other_sender`,
`the_gateway_entries_are_not_matched_by_the_entries_policy`,
`the_three_policies_read_the_broker_from_one_parameter_and_deny_without_it`, and
`the_status_policy_admits_the_broker_alone_and_denies` rewritten for the parameter.

Unit, `crates/mediatore-spire/src/kube.rs` (the scripted API fake) and `src/lib.rs`
(`MemoryEntries`): `the_self_check_passes_when_the_policy_denies_the_forbidden_shape`,
`an_admitted_forbidden_shape_fails_the_self_check`,
`a_refusal_that_is_not_the_policys_fails_the_self_check`,
`a_refused_permitted_shape_fails_the_self_check`,
`the_self_check_sends_dry_run_and_persists_nothing`.

Unit, `crates/mediatore/src/main.rs`: `a_failed_self_check_refuses_to_start`,
`dev_mode_runs_no_self_check`, `a_home_namespace_of_default_refuses_to_start`,
`a_claimable_namespace_equal_to_home_is_warned`. `crates/mediatore-claims/src/watch.rs`:
`a_failed_self_check_at_resync_stops_new_entries_and_releases_nothing`.

Unit, `crates/mediatore-store/src/seal.rs`: the existing
`the_session_context_is_the_bare_claim_uid_so_stored_sessions_still_open` is the proof that
the binding carries no namespace; `crates/mediatore-claims/src/kubestore.rs` gains
`a_session_secret_without_an_owner_reference_in_a_new_home_opens_for_its_sandbox`.

Live, `crates/mediatore-spire/tests/live_kube.rs` (ignored, fails loudly without its fixture):
the forbidden shape is denied for the broker's account, for an impersonated account of another
name, and the self-check passes against the real API server.

Kind tiers, all through `make kind-broker` in `mediatore-system`, on the build host:
- `make kind-e2e-entries`: the two shapes admitted, the refusals, and the new refusals by
  object for a sender that is not the broker.
- `make kind-e2e-mtls`: the broker's SVID issued under the new selector; a pod with the same
  label and `ServiceAccount` name in another namespace gets none.
- `make kind-e2e-sandbox`: the subject and status policies under the parameter.
- `make kind-e2e-watcher`, `make kind-e2e-dex`, `make kind-e2e-policy`, `make kind-e2e-gateway`
  and `make kind-e2e-gateway-policy`: green with the broker and its fixtures moved and the
  pools where they were (the Lease, the session Secrets and the `PolicyFloor`s in the new home).
- **`make kind-e2e-tpm` is run by hand on the build host before this merges**, the cluster
  recreated first. The change edits `dev/kind/tpm-e2e.sh` and the manifests that tier applies,
  which `.claude/rules/testing.md` lists as the TPM attestation path, and CI cannot run it. The
  report and the PR state `PASS` and the agent ID it attested as.
- The migration of decision 7 is rehearsed once on the build host's kind cluster (a claim
  bound before, its token issued after, by the copy path) and its transcript goes in
  `docs/guides/testing.md`.

`make check`, `make manifests`, `make calm-validate` and `make calm-diagrams` green before the
commit.

*As built.* The tests of 2026-11-27 carry the names above. Those of decisions 4 and 5 that
#179 wrote first keep the names it gave them, and are these:

| Name above | The test that holds it |
| --- | --- |
| `the_entries_policy_matches_by_name_prefix_label_and_spiffe_path_as_well_as_by_sender`, `the_entries_policy_refuses_a_matched_object_from_any_other_sender` | `the_entries_policy_claims_an_entry_by_what_it_is_and_names_its_one_sender` |
| `the_gateway_entries_are_not_matched_by_the_entries_policy` | `the_shipped_gateway_entries_carry_none_of_the_signs_of_a_brokers_entry` |
| `the_self_check_passes_when_the_policy_denies_the_forbidden_shape`, `the_self_check_sends_dry_run_and_persists_nothing` | `the_self_check_passes_on_the_policys_denial_of_a_dry_run` (the scripted API server asserts `dryRun=All` on the one request) |
| `an_admitted_forbidden_shape_fails_the_self_check` | `the_self_check_fails_when_the_forbidden_entry_is_admitted` |
| `a_refusal_that_is_not_the_policys_fails_the_self_check` | `a_refusal_that_is_not_the_entries_policys_is_not_proof`, `an_rbac_403_is_not_proof_and_is_reported_as_rbac` |
| `a_refused_permitted_shape_fails_the_self_check` | none: there is no second dry run (decision 5's notes); `the_policys_sender_refusal_is_a_broker_the_policy_does_not_name` and `a_policy_that_could_not_read_its_parameter_is_not_proof` hold what it was for |
| `a_failed_self_check_refuses_to_start` | `the_broker_refuses_to_start_when_the_forbidden_entry_is_admitted`, `every_other_self_check_fault_stops_the_start_under_its_own_name` |
| `dev_mode_runs_no_self_check` | none: the check runs in `dev_mode` and `MemoryEntries` answers it (`the_start_goes_on_when_admission_refuses_the_forbidden_entry`) |

The manifest tests were written after the manifests, against the order above, because a
second change was being made in the same tree and the Rust had to wait for it; they were
then run against the manifests as they stood before the change and nine failed, which is
the red this section asks for. The kind tiers, the TPM tier and the rehearsal were run on
the build host on 2026-11-27; their results are in the pull request.

## Open questions

**All eight were answered 2026-11-27 by taking the recommendation of each.** The questions stay
as they were asked; the answer follows each.

1. **The name: `mediatore-system`?** Recommendation: yes. It mirrors `banlieue-system` and
   `spire-server`, and `mediatore` alone reads as a tenant's namespace.
   *Answered 2026-11-27: yes, `mediatore-system`.*

2. **Does the base ship the `Namespace` object?** Recommendation: yes, with the Pod Security
   label, so `kubectl apply -k` works on an empty cluster and the label is not left to memory.
   An operator whose namespaces are created elsewhere deletes it in the overlay.
   *Answered 2026-11-27: yes, `deploy/base/namespace.yaml`, with the label.*

3. **One parameter for the broker's username, or three literals rewritten (decision 4)?**
   Recommendation: the parameter. It needs confirming on the supported Kubernetes floor (1.30)
   that `matchConditions` may read `params` and that a namespaced parameter is resolved for a
   cluster-scoped `ClusterStaticEntry` request through `paramRef.namespace`; if either fails,
   fall back to literals plus the fail-closed validation, which is the part that matters.
   *Answered 2026-11-27: the parameter.* Both points were confirmed on API servers before it was taken, on kind clusters of the build host at Kubernetes 1.30.13 (the floor) and 1.36.4 (the tiers' version): a policy whose only match condition is `request.userInfo.username == params.data.broker.trim()` matched the broker's request and no other, so `matchConditions` read `params`; and the namespaced ConfigMap was resolved for dry-run creates of the cluster-scoped `ClusterStaticEntry` through `paramRef.namespace` (the broker's permitted entry admitted, its forbidden one refused by a shape validation, another sender's refused by the sender validation, a gateway entry from another sender not claimed). With the key removed, and with the ConfigMap deleted, every create was refused on both versions. One run on a reused 1.30 cluster, right after every policy and the namespace had been deleted under it, admitted creates with the parameter missing; it did not reproduce on a fresh cluster of the same version, twice, and is recorded here because it was seen.

4. **Is the added validation on the sender wanted (decision 4), given that it forbids an
   operator from declaring a `/banlieue/` entry by hand?** Recommendation: yes. ADR-0006
   decision 7 already makes that an operating rule, and the validation is what turns a wrong
   name from silent to loud. Deletion by hand is not affected (the policy is on `CREATE` and
   `UPDATE`).
   *Answered 2026-11-26 by the build of decision 4: yes.*

5. **Do `sandboxnodes` and `policyfloors` leave the `ClusterRole` for a `Role` in the home
   namespace?** They are namespaced kinds used in the home namespace only, and the
   `ClusterRole` grants them everywhere. Recommendation: yes, in this ADR, as its one change
   to the pinned `ClusterRole`; it is the same argument as the Secrets. If the maintainer
   wants the `ClusterRole` untouched here, it becomes a follow-up of its own.
   *Answered 2026-11-27: yes, the `mediatore-store` `Role`; the pinned test changed with it.*

6. **Sandboxes in the broker's home namespace: warned, or refused (decision 6)?**
   Recommendation: warned in the release that moves, refused one release later, so a homelab
   that keeps everything in one namespace is told before it is stopped.
   *Answered 2026-11-27: warned at start, not refused. The refusal is not built.*

7. **The self-check at resync (decision 5): stop declaring entries, or only log?**
   Recommendation: stop declaring. A broker that knows its bound is gone and keeps writing
   entries is the permissive default the repository's rules refuse.
   *Answered 2026-11-27: stop declaring, release nothing (the gate of decision 5's second note).*

8. **Drain or copy (decision 7)?** Recommendation: drain for the maintainer's environment
   (claims are hours long at most), and keep step 6 documented and rehearsed for one that
   cannot. What banlieue itself keeps in its namespace was not verified in the review and does
   not change the decision.
   *Answered 2026-11-27: drain is the recommended path; the copy path is documented and was rehearsed once in kind.* The maintainer's environment was not migrated by this change.
