<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 13: Declarative `AgentSandbox` and a person's credential

**Status: not started** (design only, opened 2026-11-15). A requester who applies an `AgentSandbox`
resource (GitOps, CI, an app-only service, a person with `kubectl`) cannot give the sandbox a person's own
credential today. The credential belongs in `POST /v1/claims` (ADR-0035, ADR-0041, ADR-0043), whose body
the broker seals with OpenBao transit before anything is written. A resource's `spec` is stored in the
cluster in the clear, so a user name and password written there would sit in etcd, in its history and in a
backup, readable by anyone who can `get` the resource. This roadmap designs the declarative path so the
same audiences work without the API call, without breaking the rules the operator set on 2026-11-15:

- the pool VM and the sandbox never see the secret (ADR-0043);
- a user name and password, or anything like them, is never stored in a Kubernetes Secret in the clear;
- the broker removes a credential as soon as its claim is gone, and one for a claim that never binds
  when its TTL passes.

Depends on roadmaps 08 (the `AgentSandbox` CRD), 05 (the store), 10 and 12 (the gateways and the
placed audiences).

## What a declarative requester has that an API caller does not

A requester that can apply an `AgentSandbox` already has access to a namespace, an identity the API server
authenticates (a person, a `ServiceAccount`), and a subject policy that says whom it may name
(`mediatore-agentsandbox-subject-policy`, threat model A-9). The operator's suggestion is that this access
can be used two ways: store the secret there, or delegate it ourselves. The options below keep those two
and add two more; each is judged against the rules above.

## The options

| | Option | Where the secret is | Against the rules |
| --- | --- | --- | --- |
| A | **A Kubernetes Secret in the requester's namespace, named by the resource** (`spec.credentialRefs[]`), read by the broker, sealed with transit, then deleted by the broker | In the clear in etcd (and its history and backups) from when the requester creates it until the broker deletes it, and readable by anyone with `get secrets` in that namespace | Breaks "never in a Kubernetes Secret in the clear", for a short window. The broker would also need `get` and `delete` on Secrets in every requester namespace, a wide new authority (threat model A-7, A-11) |
| B | **The requester seals it itself** with OpenBao transit and puts only the envelope in the resource (ADR-0035 decision 3, the "transit shape": `pending`, then `PUT /v1/claims/{name}/delegations/{audience}`) | Ciphertext only, wherever the requester puts it | Keeps every rule. Needs the requester to hold an OpenBao identity that may encrypt with a key whose derivation context is known **before** the claim exists, so the context cannot be the claim's UID; it must bind the claim's namespace and name and be single-use. A cross-claim replay of an envelope is the design's main risk |
| C | **A reference to an OpenBao KV path** the requester wrote (`spec.credentialRefs[].openbao.path`), read by the broker at claim time with a role that maps a subject to a path prefix | In OpenBao, never in Kubernetes | Keeps every rule. The broker gains a standing read authority over a path prefix in OpenBao (a bigger blast radius than a derived key; the same shape as threat model R-27), and the requester needs a KV identity of its own. The credential is then plaintext in the broker's memory, as with any delegation |
| D | **Park it first through the API, then name the handle** (`POST /v1/credentials` returns an opaque handle; the resource's `spec.credentialRefs[].handle` names it) | Ciphertext only, parked sealed, single-use, bound to the subject, the audience and a TTL | Keeps every rule, and needs only what an API caller already has (an IdP bearer). The handle is not a secret. A claim consumes the handle at bind; an unused one is deleted at its TTL. Needs a way for a `ServiceAccount` to authenticate to the API |

The recommendation, to be confirmed before an ADR:

- **D** for any requester that can reach the user API with an IdP bearer or a projected `ServiceAccount`
  token the broker accepts: no secret in the cluster in the clear, the smallest new authority, and the same
  sealing as the API path.
- **C** for a service that already has an OpenBao identity and wants its credential to live in OpenBao
  between claims: a different shape (a credential that outlives a claim), with a different risk.
- **A** is not recommended: it is the one option that breaks the operator's rule, for a window, and widens
  the broker's RBAC. If it is ever chosen it needs encryption of Secrets at rest at the API server and a
  broker that deletes the Secret before anything else happens.
- **B** only if D proves unworkable for a requester with an OpenBao identity and no route to the API.

## Questions the design must answer

1. **Who applies declarative claims?** A person with `kubectl`, a GitOps controller, a service. The
   answer decides whether a person's own credential is even meaningful for a resource a controller
   applies on their behalf (the person is not at a terminal; the credential would have to exist before).
2. **Whose credential is it?** The resource's subject (the person the sandbox is for), or the requester's
   own? The subject admission policy forbids naming another person unless the requester is a listed broker
   (A-9); a parked credential must carry the same constraint, so a requester cannot place someone else's
   credential, or a credential for someone else.
3. **Single use and lifetime.** A parked credential should be consumed by exactly one claim, expire at
   its own TTL (never longer than the claim's TTL), and be deleted when consumed or when the claim is gone.
4. **Revocation and audit.** How a requester cancels a parked credential, and one audit line (claim,
   audience, subject, backend, expiry, never the value), as ADR-0040 already does for an issue.
5. **GitOps.** A resource in a repository cannot contain even a handle that is meant to be secret, but a
   handle is not a secret; whether a handle in a repository is acceptable, and what stops one claim from
   naming another requester's handle.
6. **The plaintext hop.** The in-cluster hop between the ingress and the broker pod is plaintext
   (threat model R-32, accepted 2026-11-15); a requester that applies a resource reaches the API server
   instead, not that hop, but a handle's creation still crosses it.

## Tasks

- [ ] Confirm the option (D recommended) and the answers to the six questions above
- [ ] ADR: the declarative claim's credential (ADR → CALM → TDD, `.claude/rules/architecture-driven-development.md`)
- [ ] CALM updated, `make calm-validate` and `make calm-diagrams`
- [ ] Failing tests first: a handle consumed once; an expired handle refused; a handle for another subject
      or another audience refused; a claim that is deleted before it binds deletes its parked envelope;
      nothing in the resource, its status or any log carries the value
- [ ] Implement, `make check`
- [ ] The guide ([requesting a sandbox](../../docs/guides/requesting-a-sandbox.md)) gains the declarative path
- [ ] Threat model: a full pass, with the new boundary for the credential endpoint and the handle

## Not in this roadmap

- The API and CLI path for a person's own credential (ADR-0035, ADR-0041 and ADR-0043).
- Retiring the operator-held credentials (`via: secret`, `registries[].password_file`): ADR-0043 open
  question 3.
- SSH keys for a git host (ADR-0041 open question 3).
