<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Identity and mTLS

Every part of mediatore proves who it is with a SPIFFE identity and talks to its peers over mutual TLS. The scheme
and the registration entries are in `crates/mediatore-spire`; the TLS in `crates/mediatore-tls`. The guide
[Enterprise SPIRE topology](../guides/enterprise-spire-topology.md) covers where SPIRE itself runs.

## The identity scheme

Four kinds of identity, all in the deployment's trust domain `<td>`. `Naming` (`mediatore-spire/src/lib.rs`) is the
one place they are built and parsed.

| Identity | SPIFFE ID | Held by | Proven by |
| --- | --- | --- | --- |
| the broker | `spiffe://<td>/mediatore` | the broker pod | a `ClusterSPIFFEID` for the pod, delivered over the SPIFFE CSI driver's Workload API socket |
| a node | `spiffe://<td>/banlieue/node/<node key>` | the guest agent on a pool VM, as root | the TPM node attestor or, for a guest without a vTPM, the `x509pop` one (ADR-0049), then selectors `unix:uid:0` and `unix:path:/usr/bin/mediatore` |
| a claim | `spiffe://<td>/banlieue/claim/<uid>` | the egress proxy of a claimed VM, as the sandbox user | the selector `unix:user:<sandbox user>` |
| a gateway | `spiffe://<td>/gateway` | the gateway VM's processes | one entry per Linux user: the data-plane Envoy, the authorizer, and, where an audience opts in, the inject Envoy |

A node's `<node key>` is 64 hex characters. For a TPM node it is the hash of the VM's endorsement key, so the identity
is anchored in the vTPM. For an x509pop node, in a pool the operator listed in `watcher.x509pop_pools`, it is the
SHA-256 of the agent ID `spiffe://<td>/spire/agent/x509pop/<host CA common name>/<machine UID>`, so it is anchored in
a certificate the VM's host signed for the guest's own key (ADR-0049). Either way it is not
anything the VM says about itself. A claim's `<uid>` is the banlieue claim's UID. The gateway is not a claim, so the
claim identity space never overlaps it: a route that must be answered to the gateway alone can check one exact ID.

## Entries are declared, not pushed

mediatore creates exactly two kinds of registration entry, the node's and the claim's (ADR-0006). It never holds a
SPIRE admin identity. Instead `KubeEntryManager` writes each as a `ClusterStaticEntry` through the Kubernetes API and
the **SPIRE Controller Manager** renders it into the server, reporting back when it is set. The two kinds:

- the **node entry**, parented to the VM's agent ID (the TPM one, computable from the EK hash, or the x509pop one,
  computable from the host CA's common name and the machine's UID), selecting the guest binary
  at its pinned path as uid 0;
- the **claim entry**, parented to the same agent, selecting the per-claim sandbox user, with a short lifetime
  (`MAX_CLAIM_SVID_TTL`).

A Kubernetes `ValidatingAdmissionPolicy` constrains what a `ClusterStaticEntry` under `/banlieue/` may say, so even a
compromised broker cannot declare an arbitrary workload identity. `EntryManager` is the trait; `KubeEntryManager` the
shipped one; `MemoryEntries` the fake for `dev_mode` and tests, which **validates its inputs exactly as the real one
does** (an EK hash's shape, a Unix user's name, a Go-style duration).

The gateways' entries are different: they are applied by the platform team against the agent IDs the SPIRE server
logs, one per Linux user per gateway, because a gateway VM is not a claim and mediatore does not manage it.

## The mutual TLS

`mediatore-tls` builds the two verifiers and the accept loop.

- **Material** arrives through `MaterialSource`: in production the Workload API (`WorkloadApiSource`, an in-memory
  X.509 source the agent rotates), in tests a test CA. The verification path is the same whichever feeds it, which is
  what lets the hermetic suite run the production path with no SPIRE.
- **A peer certificate must satisfy, in order:** leaf constraints (not a CA, `digitalSignature`, exactly one URI SAN
  that is a SPIFFE ID with a non-empty path); the trust domain is the local one (no federation); the chain verifies to
  the trust domain's bundle with the right extended key usage and is valid now; and the authorizer accepts the ID.
  A failure closes the handshake before a byte of HTTP is parsed.
- **The leg is pinned, not negotiated.** TLS 1.3 only, no session resumption (a resumed handshake would skip the
  verifier), key exchange `X25519MLKEM768` and nothing else, AES-256-GCM with SHA-384. A peer that offers only
  classical groups does not complete the handshake. Both ends of this leg are mediatore's own, which is why it can be
  pinned.
- **The verified identity reaches the handlers** as a `PeerSpiffeId` request extension, attached by `serve` after the
  handshake. Handlers read the peer from it and from nothing the client sent
  (see [Broker API](broker-api.md)).

The same verifiers serve the other mutual-TLS legs: the egress proxy to a gateway's tunnel and inject listeners, and the
gateway's authorizer to the broker. Each side checks the other's exact SPIFFE ID or prefix, never only that it chains
to the bundle.

## Rules this part keeps

- An identity's shape is checked where it is used: a claim route wants `/banlieue/claim/<uid>`, the gateway routes want
  exactly `/gateway`.
- mediatore declares entries and holds no SPIRE admin identity; admission policy bounds what it may declare.
- A certificate that fails any check ends the handshake before HTTP.
- `dev_mode` is the only place a peer identity is read from a header.

## Read next

ADR-0004 (the scheme), ADR-0005 (SPIRE topology), ADR-0006 (entries), ADR-0007 (the broker identity and mTLS), ADR-0018
(TPM attestation), ADR-0031 (a trust anchor that outlives the server's CA). Threat model TB-3 (entries), TB-4 (a VM to
the SPIRE server), TB-6 (a VM to the sandbox API), risk R-8 (post-quantum signatures).
