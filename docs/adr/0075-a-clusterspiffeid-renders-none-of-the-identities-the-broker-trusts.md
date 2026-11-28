<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0075: A ClusterSPIFFEID renders none of the identities the broker trusts

**Status:** Accepted and implemented 2026-11-27 · **Date:** 2026-11-27

Amends [ADR-0006](0006-registration-entries-as-clusterstaticentry.md) (what guards the entry
shapes), [ADR-0053](0053-the-gateways-authorizer-has-an-identity-of-its-own.md) decision 4 (the
gateway shapes) and [ADR-0056](0056-the-broker-in-a-namespace-of-its-own.md) decision 4 (the one
parameter that names the broker, now read by a fourth policy). Changes no token shape, no SPIFFE
ID, no route and no storage contract. It closes a second door across TB-3 and TB-8, so the
threat-model pass is part of done.

## Context

The broker trusts SPIFFE IDs by their path. `spiffe://<td>/banlieue/claim/<uuid>` is a claim:
it may ask for that claim's tokens. `spiffe://<td>/banlieue/node/<key>` is a pool member.
`spiffe://<td>/gateway/authorizer` reads any live claim's egress and, under ADR-0040, places
its credentials; `spiffe://<td>/gateway` is what a sandbox's forwarder accepts as the gateway.
`spiffe://<td>/mediatore` is what a guest, a gateway and the CLI accept as the broker.

ADR-0006 and ADR-0056 decision 4 put the first two shapes behind a `ValidatingAdmissionPolicy`
on `ClusterStaticEntry` (`deploy/base/admission/clusterstaticentry-mediatore.yaml`), and
ADR-0053 decision 4 the gateway's two (`clusterstaticentry-gateway.yaml`). The SPIRE controller
manager has a second kind that becomes registration entries, `ClusterSPIFFEID`: a template,
`spec.spiffeIDTemplate`, rendered per pod from the pod's and its node's metadata. No policy
looked at it.

Found live on 2026-11-27: a `ClusterSPIFFEID` with
`spiffeIDTemplate: 'spiffe://{{ .TrustDomain }}{{ index .PodMeta.Annotations "x/id" }}'` let
ordinary pods choose their own SPIFFE ID by annotation. SPIRE issued, to such pods,
`/banlieue/node/<hex>`, `/banlieue/claim/<uuid>` (the UID of a live claim among them, which then
called the broker as that claim and was answered) and `/gateway/authorizer` (which read that
claim's egress from the broker). Every one of the entry policies' refusals was bypassed, because
none of them is asked.

Creating a `ClusterSPIFFEID` takes cluster-scoped rights, so the door is an administrator's or a
compromised controller's, not a tenant's. But the template above hands the choice to whoever may
create a pod with an annotation anywhere the selector reaches, which is a tenant. And an
administrator who writes `{{ .PodMeta.Name }}` or `{{ .PodMeta.Namespace }}` as the first segment
has made the same mistake without meaning to: a namespace called `banlieue` or `gateway` then
renders a reserved path.

### What CEL can see

The policy sees the object as sent: `spec.spiffeIDTemplate` is a string, and the rendering
happens later, per pod, in the controller manager. CEL cannot render the template. What it can
decide from the string is whether the part of the path that matters is fixed text. Go's
`text/template` copies text outside `{{ … }}` to the output unchanged, so a template whose path
begins with a wholly literal segment renders that segment and nothing else, whatever the pod
carries. A SPIFFE ID admits no empty segment, no `.` or `..` and no percent-encoding (the
controller manager parses the rendered ID and drops one that is not valid), so a literal first
segment is the first segment of every ID the template can produce.

## Decision

1. **A `ValidatingAdmissionPolicy`, `mediatore-clusterspiffeid`**
   (`deploy/base/admission/clusterspiffeid.yaml`, with its binding, in the base), matches
   `clusterspiffeids` in `spire.spiffe.io/v1alpha1` on `CREATE` and `UPDATE`, from every
   principal. It is bound with `validationActions: [Deny]` and `failurePolicy: Fail`. `DELETE` is
   not matched: removing a `ClusterSPIFFEID` is RBAC's. The status subresource is not matched,
   so the controller manager's status writes are untouched.
2. **The path must begin with a literal segment.** `spiffeIDTemplate` must be
   `spiffe://` then the trust domain (`{{ .TrustDomain }}`, with optional spaces and trim
   markers, or a literal domain of lower-case letters, digits, dots and dashes), then `/`, then a
   segment of letters, digits, `.`, `-` and `_` that ends at the next `/` or at the end of the
   string. A template with no `spiffeIDTemplate`, a path that begins with a template action, a
   first segment that is partly templated (`/ns-{{ … }}`), a first segment of `.` or `..`, or
   anything else between the trust domain and the first `/` is refused. What follows the first
   segment is free: the chart's `/ns/{{ .PodMeta.Namespace }}/sa/{{ .PodSpec.ServiceAccountName }}`
   is admitted.
3. **Three first segments are reserved.** A template whose first segment is `banlieue` or
   `gateway` (the path `/gateway` itself or anything under it, `/banlieue` itself or anything
   under it) is refused from everyone. Those identities are declared as `ClusterStaticEntry`
   under their own policies, with unix selectors on a VM, and never as a pod's identity. A first
   segment of `mediatore` is refused unless decision 4 admits it.
4. **The broker's own identity is admitted by what it is, not by who sends it or by its name.**
   The base's own `ClusterSPIFFEID` (`deploy/base/clusterspiffeid.yaml`) renders `/mediatore`
   and must stay admitted. It is applied by whoever deploys the base (a person, a GitOps
   controller), whose username this repository cannot know, so the requester is no test. Its
   name is no test either: anyone who may update `clusterspiffeids` could keep the name and point
   its selectors at another pod. So the policy admits a template whose path is exactly
   `/mediatore` when the object selects only the broker: `namespaceSelector.matchLabels`
   carries `kubernetes.io/metadata.name` equal to the broker's namespace, and
   `workloadSelectorTemplates` contains `k8s:sa:<the broker's ServiceAccount>`, both read from
   the key `broker` of the ConfigMap `mediatore-agentsandbox-subject-policy`
   (`system:serviceaccount:<namespace>:<name>`, the same parameter ADR-0056 decision 4 gave the
   three other policies), and `admin` and `downstream` are not set. Both selectors only narrow
   (selector requirements and an entry's selectors are ANDed), so extra labels or selectors
   are admitted. `/mediatore/<anything>` is refused.
5. **An update that declares nothing is not judged.** A match condition leaves out an `UPDATE`
   whose `spec` is unchanged (a label, an annotation, a finalizer), so an object that was there
   before the policy can still be relabelled or let go of.
6. **The parameter fails closed, cluster-wide.** The binding names the ConfigMap by name and
   namespace with `parameterNotFoundAction: Deny`, as the other three do. Without the ConfigMap,
   every create and update of a `ClusterSPIFFEID` in the cluster is refused, the SPIRE chart's
   own included. Without the key `broker`, or with a value that is not a ServiceAccount
   username, a `/mediatore` template is refused (the expression errors and `failurePolicy:
   Fail` holds) and everything else is judged as before. An overlay that moves the broker
   patches this binding's `paramRef.namespace` as it patches the other three.
7. **No exemption list in the policy.** Nothing in a production cluster needs a reserved
   shape from a `ClusterSPIFFEID`. A test cluster that gives pods fixture identities (the kind
   tiers do: a claim, a node, a gateway, a broker impersonator) excludes those objects by name in
   its binding, `matchResources.excludeResourceRules[].resourceNames`
   (`dev/kind/broker/clusterspiffeid-fixtures.yaml`). Editing a binding takes the rights that
   could delete it, so the exclusion adds no door; the base's binding carries none, and a unit
   test holds that.
8. **Federation is not in scope.** `ClusterFederatedTrustDomain` and a `federatesWith` on a
   `ClusterSPIFFEID` bring another trust domain's bundle to a workload. Every one of the broker's
   listeners and clients accepts a peer of its own trust domain only (`local_only`,
   `crates/mediatore-tls/src/verify.rs`), so a foreign `/banlieue/claim/…` is refused at the
   handshake whatever bundle is present. The `ClusterStaticEntry` policies already refuse
   `federatesWith` on the broker's and the gateway's entries.

## Security analysis

| Boundary | Threat | STRIDE | Control |
| --- | --- | --- | --- |
| TB-3 | A `ClusterSPIFFEID` renders `/banlieue/claim/<uuid>` or `/banlieue/node/<key>` for a pod, which then calls the broker as that claim or node | S/E | Decision 3; proven on an API server (`dev/kind/clusterspiffeid-admission.sh`, `make kind-e2e-entries`) and held as text (`the_clusterspiffeid_policy_refuses_the_reserved_paths_and_any_templated_first_segment`) |
| TB-3 | A template lets a pod choose its own ID (an annotation, a label, a name as the first segment) | S/E | Decision 2: the first segment must be fixed text, so no pod metadata reaches it. The live template of the context is one of the kind tier's refused dry runs |
| TB-3 / TB-17 | A pod obtains `/gateway/authorizer` and reads or is placed a live claim's egress and credentials, or `/gateway` and stands in for a gateway | S/E/I | Decision 3, the same proofs |
| TB-8 | A second object renders `/mediatore` for another pod, which then stands in for the broker to guests and gateways | S | Decision 4: `/mediatore` only with the broker's namespace and ServiceAccount from the parameter; the kind tier's dry runs refuse it under another namespace and under a sub-path, and admit the base's object |
| TB-3 | The policy is absent or its parameter is missing and nothing says so | E/D | Absent policy: not detected by the broker (its self-check is about `ClusterStaticEntry`); the base lists the file and a unit test holds it (`the_base_kustomization_lists_every_admission_policy`). Missing parameter: decision 6, refused everywhere |

What this is not: a bound on a cluster administrator, who can delete the policy or its binding,
or on SPIRE's own admin API. A `ClusterStaticEntry` with a k8s selector and the ID `/mediatore`
is still judged by neither entry policy (they claim `/banlieue/` and `/gateway`); that is the
same population and a separate decision, recorded as an open question below.

## Consequences

- An existing `ClusterSPIFFEID` whose template begins with a template action, or renders a
  reserved segment, keeps working (a policy does not judge what exists) but cannot be changed
  until it is rewritten or deleted. Before the policy reaches a running cluster, list them:
  `kubectl get clusterspiffeids -o custom-columns=NAME:.metadata.name,TEMPLATE:.spec.spiffeIDTemplate`.
  The SPIRE chart's three defaults (the `ns/sa` fallback, the OIDC discovery provider's and the
  test keys' `ClusterSPIFFEID`, all `spiffe://{{ .TrustDomain }}/ns/{{ .PodMeta.Namespace }}/sa/{{ .PodSpec.ServiceAccountName }}`)
  are admitted on update.
- One more binding to patch when the broker moves (`paramRef.namespace`), and in the move
  itself the base's `ClusterSPIFFEID` can be judged against the old parameter for the moment
  between the binding's update and its enforcement: an apply that is refused there succeeds
  when repeated.
- The release manifest carries five policies and five bindings.
- Test clusters that give pods reserved identities say so in their binding, by name.

## Alternatives rejected

- **An exemption list in the parameter** (names of `ClusterSPIFFEID` objects allowed a reserved
  shape). A name is not a property of what the object selects, and it puts a door in the
  production policy that only a test cluster uses.
- **Exempt the base's object by name, `mediatore`.** Whoever may update it could keep the name
  and select another pod.
- **Exempt by requester.** Who applies the base is the deployment's choice and not knowable
  here.
- **Refuse every template action anywhere in the path.** The chart's own fallback uses them
  after a literal `/ns/`, and so do most clusters' identities; the first segment is what the
  broker's shapes depend on.
- **Let the broker check `ClusterSPIFFEID` objects itself.** The broker would need `list` on a
  cluster-scoped kind it otherwise never reads, and a check after creation is not a refusal.

## What must be proven

- Unit tests in `crates/mediatore-claims/src/sandbox.rs` evaluate the policy's own regular
  expressions (read from the YAML) against admitted and refused templates, and hold the file's
  structure: every principal, `CREATE` and `UPDATE`, `Fail`, the parameter as the other three
  read it, `Deny`, no `matchResources` in the base's binding, and a kind binding that excludes
  only `mediatore-e2e-*` names.
- On a real API server (`make kind-e2e-entries`), server-side dry runs as an administrator:
  the chart's template and the base's broker object admitted; `/banlieue/claim/<uuid>`,
  `/banlieue/node/<hex>`, `/gateway`, `/gateway/authorizer`, the live annotation template, a
  templated first segment, `/mediatore` for another namespace and `/mediatore/x` refused; each
  existing `ClusterSPIFFEID` of the chart admitted on a spec-changing update; an excluded
  fixture name admitted.
- `make kind-e2e-mtls` and `make kind-e2e-sandbox`: the broker's own `ClusterSPIFFEID` admitted
  and the broker issued its SVID with the policy in force.

## Open questions

- A `ClusterStaticEntry` naming `/mediatore` is judged only by RBAC: the broker's entries
  policy claims `/banlieue/` and the gateway policy `/gateway`. Whether the entries policy should
  claim `/mediatore` too is a separate decision.
