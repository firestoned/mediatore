<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0022: Registry pull credentials are the operator's, delivered per claim by the broker

**Status:** Accepted · **Date:** 2026-10-27

Roadmap 06, the pull-credentials item. Completes
[ADR-0021](0021-sandbox-filesystem-tmpfs-and-rootfs-from-the-registry.md), whose decision
7 left the pull anonymous and named the shape this ADR takes. Extends what `GET /v1/me`
carries ([ADR-0008](0008-agentsandbox-crd-owned-by-mediatore.md) decision 8,
[ADR-0020](0020-jail-network-nftables-keyed-by-sandbox-uid.md) decision 2). Changes
nothing about the transport ([ADR-0007](0007-broker-identity-and-spiffe-mtls.md)) or the
identities ([ADR-0004](0004-spiffe-identity-scheme.md)).

## Context

The guest pulls `workload.image` with no credential: it holds its node SVID and nothing
else, so a registry that wants one refuses the pull and the claim never runs. Workload
images are usually private: an organisation's agent image sits in its own registry, and a
homelab's in a registry on the segment that still wants a login. The member has no
credential of its own and should not: a secret baked into the pool image is on every
member's disk, rotated only by rebaking, and readable by whoever reads the image.

Where a credential can come from: the requester (on the `AgentSandbox`, which puts a
secret in a resource that GitOps commits and the API server stores), the cluster (a
Kubernetes pull Secret the broker reads, which grants the broker `secrets` RBAC it does
not have today), the image (rejected above), or the broker's own configuration, which is
already the operator's channel for every other secret the broker holds (the STS key, the
sealing key, the Entra credential: files from Secret volumes, read at start).

The channel to the guest exists: `GET /v1/me` is answered over the mutual-TLS session of
the node that holds the claim, and only that node can ask for that claim (ADR-0007, the
node SVID, the claim bound to the node by its EK). It already carries the subject, the
workload and the egress endpoints.

## Decision

1. **Credentials are the operator's, in the broker's config.** `registries` lists, per
   registry host, a `username` and a `password_file`; the file is read at start like the
   STS key, into memory, and a rotation is a restart. The host is the registry as a
   reference names it, so `docker.io` and `registry-1.docker.io` are one entry; two
   entries for one host fail the config. The credential is what the operator scoped at
   the registry: a read-only token for the images the pool runs.

2. **`GET /v1/me` carries the credential for the claim's image registry, and no other.**
   `Me.registry_credential` is the entry whose host the claim's `workload.image` names,
   absent when there is none (the pull stays anonymous, as before). The password is a
   `Secret`: it serialises as the string and prints as `[redacted]`. The broker logs the
   host it matched, never the credential. An old guest ignores the field; an old broker
   sends none.

3. **The guest uses it for one pull and keeps nothing.** With a credential, the request
   for the bearer token that the registry's challenge names carries HTTP Basic
   authentication, and a registry that challenges with `Basic` gets it on the retry
   directly. It is sent to the host the credential names only, over HTTPS only: a
   credential for a registry listed as plain HTTP is refused before any request is made
   (fail closed; a secret in the clear on the segment is worse than no pull). It lives in
   the guest's memory for the pull, outside the jail, never on the tmpfs, never in a log.

4. **The broker refuses a `workload.image` it cannot parse at claim creation.** The
   reference grammar moves to `mediatore-proto` (`ImageReference`) so the broker and the
   guest agree on what a registry host is; `POST /v1/claims` answers `400
   invalid_workload_image` instead of the guest finding out at bind. A sandbox declared
   through the `AgentSandbox` resource is not parsed at the API server (the CRD takes a
   string); its guest refuses the image at bind, as before.

5. **One credential per registry, shared by every member, is the design.** The sandbox's
   subject is a person; registries do not know them, and the image is the operator's to
   publish. What a credential grants is read access to the images the operator chose to
   put behind it, to members that are the operator's. Per-subject credentials are not
   this ADR's problem.

## Consequences

- `crates/mediatore/src/config.rs` gains `registries` and its checks; `main.rs` reads the
  files at start; `crates/mediatore-api` matches the host at `me` and validates the
  reference at `POST /v1/claims`; `crates/mediatore-proto` gains `ImageReference` and
  `RegistryCredential`; `crates/mediatore-guest/src/image.rs` takes the credential into
  the pull's session. The fake registry in `mediatore-testkit` learns to demand a
  credential at its token endpoint and to challenge with `Basic`.
- Deployment: a Secret per private registry, mounted like the STS key, and the
  `registries` section in the config ([the deploying guide](../guides/deploying.md)). The
  file's content is the password or token, whitespace trimmed.
- Threat model: a new asset (A-16, the pull credentials), a TB-6 row (the credential
  reaches the node holding the claim, over mTLS, and no other peer), TB-11 rows (HTTPS
  only, the named host only, never logged), a TB-7 row (the jail cannot reach it).
- Rejected: the credential on the `AgentSandbox` spec (a secret in a resource GitOps
  commits and the API server stores; the requester is not who publishes the image); a
  Kubernetes pull Secret read by the broker (`secrets` RBAC for the broker, which has
  none, and a second channel beside the config volume); a file in the pool image (on
  every disk, rotated by rebaking); the broker pulling and serving the image itself (a
  registry mirror inside the broker, with the broker's egress and memory on the path of
  every bind); re-reading the password file at each `me` (a rotation without a restart,
  but a broker whose files change under it, when every other secret it holds is read
  once).
