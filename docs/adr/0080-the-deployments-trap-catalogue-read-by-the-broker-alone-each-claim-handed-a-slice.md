<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0080: The deployment's trap catalogue read by the broker alone, each claim handed a slice

**Status:** Proposed · **Date:** 2026-11-28

Answers [ADR-0069](0069-tripwires-on-the-vm-a-decoy-the-workload-takes-ends-its-sandbox.md)'s
open question 2 ("Whether a separate, narrower-read source for the deployment catalogue is worth
its cost") and its unbuilt "deployment's own catalogue (the bundle's `traps` section)". If
accepted, it **supersedes ADR-0069 decision 4** (the catalogue as a `traps` section of the
signed policy bundle, served whole in `GET /v1/me`, and the admission code `P017`) and amends
the consequence "The policy repository's readers can read the deployment catalogue". It keeps
ADR-0069 decision 3 (the guest draws, from the OS CSPRNG, and the draw never leaves the VM).
Uses the envelope, the trusted keys and the floor of
[ADR-0026](0026-notaio-bundles-verified-in-shadow.md) and
[ADR-0055](0055-audiences-from-signed-sandboxaudience-bundles.md), and the broker's namespace of
[ADR-0056](0056-the-broker-in-a-namespace-of-its-own.md). Changes no token shape, no SPIFFE ID
and no wire type the guest reads. It adds a source the broker reads, a key it holds and a floor
it keeps, so the full ADD cycle and a threat-model pass apply when it is accepted.

## Context

**What a guest receives today**, from the code. Under `shadow` and `enforce` the broker answers
`GET /v1/me` with `traps: TrapsPolicy { mode, denied, catalogue }`
(`Tripwires::policy`, `crates/mediatore-api/src/tripwires.rs`; the type in
`crates/mediatore-proto/src/trip.rs`). `catalogue` is `Tripwires::catalogue`, **one value for
the whole broker**, today always `None`. The guest, root outside the jail, passes it to the
draw (`Arming::policy`, `arm`, `crates/mediatore-guest/src/arm.rs`, into
`DrawInputs::catalogue`, `crates/mediatore-guest/src/draw.rs`), which weights its entries 6
against the seeds' 2, the generated entries' 2 and the derived entries' 2. The proxy is handed
only the drawn result (`ProxyTraps`: decoy routes and bait values) over the trap socket; the
jail gets the drawn variables, the drawn files in its home and the decoy routes' variables. The
catalogue is not on the record (`Rendered` holds routes and destinations only,
`record_rendered`, `crates/mediatore-api/src/follow.rs`) and not in a log line.

So, once a catalogue is served:

- **A jailed workload** learns only the entries drawn for it, as decoys it sees. Which other
  entries exist it cannot read from the jail.
- **Root on a pool VM** (ADR-0070's actor: an escape, a compromised image) holds the node SVID
  and can read the **whole catalogue**: from the guest's memory, or by calling `GET /v1/me`
  itself, as often as it likes.
- **Under ADR-0069 decision 4 as written**, the catalogue would sit in notaio's policy bundle,
  which notaio publishes as the ConfigMap `<policy>-bundle` in the policy's own namespace (the
  policy bundle guide; `deploy/policy-bundles/rbac.yaml` applies the broker's read Role to
  `sandboxes`, "where the pool and the sandboxes already live"). Its readers are then not only
  "the policy repository's readers" (ADR-0069's consequence) but **whoever may read ConfigMaps
  in that namespace**: in the default layout the tenants who create `AgentSandbox`es there, and
  anyone bound to Kubernetes' built-in `view` role, which grants ConfigMaps and not Secrets.

The catalogue's value is exactly that an attacker has not read it: ADR-0069's red-team
simulation (`a_prober_that_avoids_every_seed_still_trips_within_n_probes_with_a_deployment_catalogue`,
`draw.rs`) gives a prober who avoids every public seed 19.5% of the traps avoided with a
deployment catalogue against 42.6% without. A catalogue the tenants can read is worth little
against a tenant's workload, which is the actor it exists for.

Also: the draw already redraws an entry that collides with the claim's routes, the guest's
variables and the lookup families (decision 3, amended), so a catalogue entry that overlaps a
grant cannot end an honest run on its own; `P017` was a second guard, at admission, that needed
the policy and the catalogue in one object.

## Decision

1. **The catalogue is an object of its own, deployment-wide, outside every tenant's
   namespace.** One catalogue per broker, which is what the code already holds
   (`Tripwires::catalogue`). Its content is today's `TrapCatalogue` exactly (seed ports, host
   stems, host suffixes, variables each with a generator from the fixed set, counts within the
   built-in bounds, at most `MAX_CATALOGUE_ENTRIES` per list): no literal value, no fixed set.
   It is never in a policy bundle; a policy bundle's `traps` section is not asked of notaio.

2. **Two sources, chosen in `tripwires.catalogue.source`** (`crates/mediatore/src/config.rs`),
   absent by default (no catalogue, today's draw):
   - **`bundle`, signed by notaio.** A notaio kind of its own (`SandboxTrapCatalogue`), linted
     for shape and signed with the same DSSE envelope and keys as the policy bundles
     (ADR-0026 decision 2: the broker trusts only `policy.trusted_keys`), under a payload type
     of its own so that no policy or audience bundle can verify as a catalogue, nor the
     reverse. notaio publishes it as a **Secret**, `<name>-traps` (key `traps.dsse.json`), in
     **notaio's own namespace**, named in `tripwires.catalogue.namespace` and `.name`. The
     broker reads it with a Role there granting `get` on that one `resourceNames` entry and
     nothing else (`deploy/trap-catalogue/rbac.yaml`, new), polled with `get` as ADR-0055
     decision 5 reads audience bundles. notaio keeps no write in the broker's namespace, so it
     gains no reach over the broker's own Secrets.
   - **`file`, the operator's own.** A JSON `TrapCatalogue` at `tripwires.catalogue.file`,
     mounted from a Secret in the broker's namespace (`mediatore-system`), unsigned. Its writers
     are the namespace's administrators, who already hold the broker's STS and sealing keys
     (`deploy/base/namespace.yaml`), so a signature would bound no one new; what it gives up is
     notaio's review and the floor. It exists so that a deployment can use a catalogue before
     notaio carries the kind, and without notaio at all.

   Either source is verified and validated (`TrapCatalogue::validate`, the same bounds the
   draw checks) before use; one that fails refuses the broker at start and, read again later,
   keeps the last good catalogue, logged at `warn`. Neither is a ConfigMap: Secrets stay out of
   the built-in `view` role.

3. **The replay floor, for `bundle`.** The broker keeps a version floor per catalogue, under
   notaio's floor rule and in the store with the others (a `PolicyFloor` named as ADR-0055
   names the audience floors, under notaio's floor name `traps/<name>`): a lower version is
   refused after a restart too, and the same version with another content digest is refused.
   The floor moves only after the floor write succeeds, then the catalogue is used (ADR-0026
   decision 4's order). `file` has no floor: a rollback of the file is a rollback of the
   broker's configuration, the operator's act.

4. **The broker hands each claim a slice, never the catalogue.** `GET /v1/me` carries in
   `traps.catalogue` a `TrapCatalogue` whose every list is a subset of the catalogue's, chosen
   per claim (`Tripwires::policy_for(claim_uid, routes)`, a new `trapslice` module in
   `crates/mediatore-api/src/`). The wire type is unchanged, so **the guest is unchanged**: it
   draws from what it is handed, mixed with the seeds, the generated and the derived entries,
   as today, and the draw never leaves the VM.
   - **Size.** Each list keeps `min(n, max(2 × u, ceil(n / 4)))` entries, where `n` is the
     list's length and `u` the upper count of its kind (five ports, three routes, six
     credentials): enough for any draw, about a quarter of a long list (16 of the 64 a list may
     hold). A short list, at most twice its kind's upper count, is handed whole: a catalogue
     that small gains nothing from this decision on a VM. `counts` is passed as is.
   - **Stable per claim.** The choice is seeded with
     `HMAC-SHA256(slice_key, catalogue content digest || claim UID)`, so every `GET /v1/me` for
     one claim, on any replica, returns the same slice: a VM's root that asks a thousand times
     learns one slice. `slice_key` is 32 random bytes in a Secret of the broker's namespace
     (`mediatore-traps-slice`, read at start like the STS key); a configured source with no key
     refuses the broker at start. A new catalogue version changes a claim's slice (the digest is
     in the seed); a guest draws once each time it serves the claim, so a running claim keeps
     its draw, and a root that asks after each new version learns one more slice per version.
   - **Filtered against the claim.** Entries that collide with the claim's own routes (a host,
     a port, a variable a routed tool reads) are left out of that claim's slice before the
     choice, so the guest's redraw is the second guard rather than the only one. This replaces
     `P017`.
   - **Never kept, never logged.** The slice is computed per request and stored nowhere: not on
     the record, not in `rendered`, not in a log line at any level. The broker logs, at start
     and on each new version, the catalogue's name, version and per-list counts, never an entry.

5. **Nothing else reads the catalogue.** The broker's process memory, the Secret, and its
   source in the operator's or notaio's repository. The gateway, the proxy, the CLI, the
   `AgentSandbox` status and every tenant-facing route carry no part of it. `status.tripwires`
   carries a trap's name only once that trap was used (ADR-0069 decision 9), as today.

## Security analysis

| Boundary | Threat | STRIDE | Control |
| --- | --- | --- | --- |
| TB-2 | A tenant, or anyone bound to `view`, reads the deployment's catalogue and avoids it | I | Decisions 1 and 2: a Secret outside every tenant namespace (notaio's namespace or `mediatore-system`), read by the broker through a Role with one `resourceNames` entry |
| TB-6 | Root on a pool VM reads the catalogue through `GET /v1/me` or the guest's memory | I | Decision 4: it reads one slice, about a quarter, stable per claim; repeated requests return the same slice. Across `m` compromised claims about `(3/4)^m` of a long list stays unseen: an accepted residue (a new R row), not a bound |
| TB-12 | A jailed workload learns the catalogue | I | Unchanged: it sees only the entries drawn for it |
| TB-2 / TB-9 | A forged or altered catalogue (narrowed to nothing, or overlapping grants) | T/D | `bundle`: verified under `policy.trusted_keys`, its own payload type; `file`: writers already hold the broker's keys. Either is validated to the built-in bounds and can never narrow a draw below them; decision 4 filters collisions per claim and the guest still redraws |
| TB-2 | An older, leaked catalogue replayed | T | Decision 3's floor for `bundle` |
| TB-9 | The slice key leaks | I | Without the catalogue it yields indices into an unknown list; with the catalogue it adds nothing. Rotating it changes the slices of claims whose guests restart |
| TB-6 | A guest is handed a different slice per replica, widening what one VM learns | I | The seed depends on the key, the digest and the claim UID only, shared by every replica |

## Consequences

- A tenant who can read its own namespace, and every holder of the `view` role, no longer reads
  the catalogue; root on one VM reads a quarter of it.
- The guest and the proxy are unchanged: an older guest takes a slice as it would have taken a
  whole catalogue. The broker and the RBAC are the change.
- notaio gains a kind, a payload type and a publication target in its own namespace; until it
  ships them, `source: file` is the way in. The bundle guide's "Traps: not yet in the bundle"
  section is rewritten to say the catalogue is not in the bundle at all.
- `P017` is not needed and is not asked of notaio; ADR-0069 decision 4 is superseded.
- One more Secret (`mediatore-traps-slice`), one more floor object, one more Role.
- ADR-0069's red-team number must be measured again with slices, and its live number still
  needs a deployment catalogue, which `source: file` makes possible without notaio.
- Readers of the source repository (the operator's or notaio's) still read the catalogue:
  accepted, and the narrowest set that can review it.

## Alternatives rejected

- **The `traps` section of each policy bundle** (ADR-0069 decision 4): its readers are the
  policy namespace's, tenants included, and a policy author is not necessarily trusted with the
  deployment's decoys.
- **The broker makes the draw** and hands it to the guest: rejected by ADR-0069 for good
  reasons (the draw leaves the VM and sits wherever the broker keeps it); a slice is an input
  to the draw, not the draw.
- **A fresh random slice per request**: a VM's root asks again until it has everything.
- **A slice stored on the record**: readable by whatever reads the record, which is the
  `AgentSandbox` status (ADR-0034).
- **Encrypting the catalogue to the guest** (sealed in the bundle): the guest's root is one of
  the readers this ADR narrows, and sealing does not narrow it.
- **A ConfigMap in the broker's namespace**: the `view` role reads ConfigMaps.
- **notaio writing into `mediatore-system`**: a Role there that can create Secrets could
  overwrite the broker's keys.

## What must be proven

- Hermetic (`make check`): the slice's size per list
  (`a_slice_keeps_twice_the_upper_count_or_a_quarter_whichever_is_more`), its stability
  (`every_request_for_one_claim_gets_the_same_slice_on_any_replica`), its spread
  (`two_claims_get_different_slices_of_a_long_catalogue`), the collision filter
  (`a_catalogue_entry_that_names_a_route_of_the_claim_is_never_in_its_slice`), nothing logged
  (`no_catalogue_entry_reaches_a_log_line_the_record_or_the_status`, in the canary scan); the
  source checks (`a_catalogue_bundle_signed_by_an_untrusted_key_or_under_another_payload_type_is_refused`,
  `a_policy_bundle_never_verifies_as_a_catalogue`), the floor
  (`an_older_catalogue_version_is_refused_after_a_restart`), the start refusals (no key; an
  invalid catalogue); `GET /v1/me` under `off` byte for byte unchanged.
- The red-team simulation again, with slices
  (`a_prober_that_avoids_every_seed_still_trips_within_n_probes_with_a_sliced_catalogue`), and
  one for a prober that holds one slice.
- kind: the Role's single `resourceNames` grant read by the broker; a tenant's ServiceAccount
  refused `get` on the Secret; under `source: file`, two claims' `GET /v1/me` differ and one
  claim's repeats agree.
- Live on the homelab under `shadow`: a deployment catalogue from `source: file`, the soak, and
  ADR-0069's red-team live number.

## Open questions

1. **Is it worth its cost?** (ADR-0069's own question.) Recommendation: yes, and `source: file`
   first. It is a broker-only change, it unblocks the deployment catalogue without waiting on
   notaio, and it moves the catalogue out of the tenants' reach, which ADR-0069 decision 4
   would have put it in.
2. **The slice fraction.** Recommendation: a quarter, with twice the kind's upper count as a
   floor; revisit after the red-team measurement with slices.
3. **One catalogue per broker, or per namespace.** Recommendation: one per broker. A catalogue
   per tenant namespace would be readable by whoever administers that namespace's sources.
4. **Should `source: file` remain once notaio carries the kind?** Recommendation: yes, for
   deployments without notaio; the start line says which source is used and whether it is
   signed.
