<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0049: AgentSandbox is served as v1alpha1 and v1beta1

**Status:** Accepted and implemented 2026-11-18, released in v0.4.0 (proposed the same day; `v1alpha1` served again beside `v1beta1`, deprecated, the same schema, `v1beta1` stored) · **Date:** 2026-11-18

Roadmap 08 (the `AgentSandbox` CRD). Amends [ADR-0048](0048-agentsandbox-served-as-v1beta1.md)
decisions 1 and 3 and its cut-over consequence; ADR-0048 decisions 2, 4 and 5 stand.

## Context

ADR-0048 renamed the version from `mediatore.io/v1alpha1` to `mediatore.io/v1beta1` and
stopped serving the old name, so a manifest naming `v1alpha1` is refused with `no matches for
kind "AgentSandbox" in version "mediatore.io/v1alpha1"`. That breaks every declarative
requester written before the rename (a manifest, a GitOps repository, a CI job, a client pinned
to an earlier release) on the day the CRD is applied, and it made the upgrade of a cluster with
the old CRD a delete-and-reapply. Erick's decision, 2026-11-18: both versions are served.

The two versions have the same schema: ADR-0048 changed the name and nothing else, and its
decision 4 (fields added optional, never removed or renamed) keeps it that way. A Kubernetes
CRD whose versions share a schema needs no conversion webhook: with conversion strategy `None`
the API server rewrites `apiVersion` and passes the object through unchanged.

## Decision

1. **Both `v1alpha1` and `v1beta1` are served; `v1beta1` is the storage version.** The CRD
   lists both, conversion strategy `None`. An object created or read as either version is the
   same object, stored as `v1beta1`. `v1alpha1` is marked `deprecated` with a warning naming
   `v1beta1`, so `kubectl` tells a requester still on the old name which one to move to,
   without refusing it.

2. **`v1alpha1` is not a second Rust type.** The CRD is rendered from the one type
   (`AgentSandbox`, `v1beta1`), and the `v1alpha1` entry is that version copied under the old
   name at render time (`sandbox::crd()`), with `served: true`, `storage: false` and the
   deprecation. Schema, printer columns and subresources are therefore identical by
   construction, and a unit test pins it. The broker reads, watches and owns objects as
   `v1beta1` only; a sandbox created as `v1alpha1` reaches its reconciler like any other.

3. **The admission policy matches both versions, by name.** `matchConstraints` lists
   `["v1alpha1", "v1beta1"]` and sets `matchPolicy: Equivalent` explicitly. A served version
   the policy did not name would be ungoverned (`spec.subject` unpinned, the spec mutable), so
   the list is kept equal to the CRD's served versions and is never widened to `*`. A unit test
   compares the two.

4. **Owner references stay `v1beta1`.** They are taken from the type
   (`AgentSandbox::api_version`, ADR-0048 decision 3). Garbage collection resolves an owner by
   UID through any served version, so a claim owned by a sandbox created as `v1alpha1` is
   collected the same way.

5. **The schemas never diverge.** ADR-0048 decision 4 now binds both versions: a field added
   to the type is added to both, because there is one type. A change that cannot be the same
   for both names is either the retirement of `v1alpha1` or a conversion webhook, each under its
   own ADR. Retiring `v1alpha1` takes a storage-version migration first, because a cluster
   upgraded from the old CRD still lists it in `status.storedVersions`.

## Consequences

- **Wire compatible again for declarative requesters.** A manifest naming `v1alpha1` is
  admitted, governed by the same policy, reconciled, and answered with a deprecation warning.
  `POST /v1/claims` is unchanged, as under ADR-0048.
- **The cut-over is an apply.** A cluster with the `v1alpha1`-only CRD applies the new one
  directly: `status.storedVersions` may keep listing `v1alpha1` because the CRD still names
  it, and any `v1alpha1` object left is served as `v1beta1` through strategy `None`. The
  delete-and-apply and the stored-versions patch in ADR-0048's consequences are no longer
  needed. A cluster that already took the `v1beta1`-only CRD (the core cluster, 2026-11-18)
  applies the new one the same way.
- **The broker is unchanged.** Its watches and writes use `v1beta1`; only the CRD and the
  admission policy change, and either order of applying them is safe (the policy naming a
  version the CRD does not yet serve matches nothing extra).
- **The kind tier proves it.** `make kind-e2e-sandbox` creates a sandbox as `v1alpha1`: refused
  by the subject policy for a stranger naming someone else, admitted for the broker
  ServiceAccount, answered with the deprecation warning, read back as `v1beta1` and owning its
  claim with a `v1beta1` owner reference.
- **Not done here.** No conversion webhook, no storage-version migrator, no date for removing
  `v1alpha1`.
