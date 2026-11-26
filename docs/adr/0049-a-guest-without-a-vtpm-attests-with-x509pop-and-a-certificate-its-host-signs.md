<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0049: A guest without a vTPM attests with `x509pop`, using a certificate its host signs for the guest's own key

**Status:** Accepted; the control-plane side implemented and released in v0.4.0 · **Date:** 2026-11-19 · **Proposed:** 2026-11-18 · **Amended:** 2026-11-26 (Decision 2: a bundle CA and a host CA must be a CA with a path length of zero, refused otherwise) and 2026-11-24 (Decision 5: the guest helper is a Rust subcommand, `mediatore node-cert`, with no `openssl` or Python, and the certificate's lifetime is the host's; Decision 6: the reply is the leaf followed by the host CA's chain, as banlieue ADR-0146 Decision 7 has the signer send it)

Builds on [ADR-0004](0004-spiffe-identity-scheme.md) (the identity scheme),
[ADR-0006](0006-registration-entries-as-clusterstaticentry.md) (no SPIRE admin identity,
entries declared as `ClusterStaticEntry`) and [ADR-0018](0018-tpm-attestation-with-the-spiffe-plugin.md)
(the TPM attestor and the hypervisors' CAs as the trust bundle). Changes none of them: the
TPM attestor stays the attestor of every guest that has a vTPM. This ADR adds the attestor
for a guest that has none. banlieue's `firecracker` provider class
(banlieue ADR-0137, ADR-0140 and ADR-0142, all Accepted) is that guest: Firecracker has no
TPM device, so there is no endorsement key to attest with.

## Context

The identity scheme of ADR-0004 and ADR-0006 hangs on one fact about the TPM attestor: a
pool VM's agent ID is `spiffe://<td>/spire/agent/tpm/<sha256 of the EK public key>`, which
the control plane can compute from the EK certificate banlieue publishes, **before the guest
boots**, so the node entry (`ClusterStaticEntry`, parent = that agent ID) is declared in
advance and the agent attests into an identity that already exists. A guest without a vTPM
must keep that property.

Three constraints, one of them new:

1. **No SPIRE admin identity, and no token minting (ADR-0006 Decision 1).** `join_token`,
   the obvious attestor for a guest with no hardware root, needs a join token created through
   the server's admin API. A first design for this class did exactly that (a broker minting a
   token per guest; the transport over vsock was built and tested). It conflicts with
   ADR-0006: a component that can create tokens can mint an agent identity for any alias.
   That attestor is not used.
2. **A compromised hypervisor must not be able to choose another host's guest's identity.**
   The TPM design has this property (an EK hash cannot be chosen; a forged EK certificate
   yields a hash of the forger's own key).
3. **The guest's private key must not leave the guest**, and the guest cannot be trusted to
   name itself.

SPIRE's built-in `x509pop` attestor fits: the agent proves possession of a private key for a
certificate that chains to a CA the server trusts statically, with no server-side call per
guest. It was prototyped on a bare-metal host with SPIRE 1.15.5 (trust domain a throwaway,
two Firecracker guests, two host CAs), and what follows was observed there, not read from
documentation.

## What the prototype showed

| Question | Observed |
| --- | --- |
| End to end | The guest generated its key and a CSR, sent only the CSR over vsock, the host signed it, the agent logged `Node attestation was successful reattestable=true`. VM start to attested: 4.4 s (the console was up at about 1.9 s). Over 26 signings the host saw 363 bytes each time and no private-key marker. |
| What the server enforces on the leaf | `keyUsage` must be present and include `digitalSignature` (without it: `certificate not intended for digital signature use`). Not enforced: extended key usage, `basicConstraints`, CN, SAN. A leaf with `CA:TRUE` attested, so **the signer must force `CA:FALSE`**. |
| Trust | A certificate from a CA not in the bundle was refused (`signed by unknown authority`). One `ca_bundle_path` file may hold several CAs. A leaf signed by an intermediate needs the intermediate on the agent (`intermediates_path`); the server needs only the root. |
| Proof of possession | Guest A's certificate with guest B's key: the stock agent refuses locally; a patched agent with that check removed was refused by the server (`challenge response verification failed: ECDSA signature verify failed`). |
| Default agent ID | `spiffe://<td>/spire/agent/x509pop/<40 hex>`: the **SHA-1 of the whole DER certificate**. **Renewing the certificate on a running agent changed the ID** and the agent carried on under the new one, orphaning any node entry keyed to the old one. It exists only after the host has signed. |
| Template data | `.PluginName`, `.Fingerprint`, `.SerialNumberHex` and the embedded certificate (`.Subject.CommonName`, `.Issuer.CommonName`, `index .DNSNames 0`, a SKI via `printf` and `%x`). A template must start with `/`; a segment allows letters, digits, dots, dashes, underscores. |
| Who can pick the ID | CN-only template: a signer under a second CA issued a CN equal to another guest's and **got the same agent ID**. Fingerprint template: different IDs. Issuer-qualified (`/<issuer CN>/<subject CN>`): different IDs, each confined under its own CA's name. With entries declared, guest A's workload entry was not issued to B under the fingerprint template. |
| Lifetime | An x509pop agent re-attests at about half its SVID lifetime and re-reads the certificate file each time. After the certificate expired it logged `Could not reattest agent`, then exited, one SVID lifetime after the expiry. **An agent does not outlive its certificate.** |
| Restart | The same key and certificate attest again with the same ID (`Can re-attest : true`), unlike `join_token`. |
| Entries | A node entry created **before** the agent started worked; the workload selector `unix:path:` separated an allowed binary from a denied one inside the guest, but only with `discover_workload_path = true` on the unix workload attestor. A fetch right after `entry create` can fail until the agent syncs (seconds). |
| Signer down | The guest's helper retried with backoff and gave up with no certificate and no agent; starting the signer during the backoff let it attest. A running agent is unaffected by a signer outage until its certificate expires. |

Not tested: a stable template built on the SKI with an issuer prefix; RSA or ed25519 guest
keys; the full error text for an expired leaf; the SPIRE server's own HA behaviour with this
attestor.

## Decision

### 1. A guest with no vTPM attests with `x509pop`

`NodeAttestor "x509pop"` on the server, with the per-host CAs as its `ca_bundle_path`
(assembled as ADR-0018 assembles the TPM bundle: the trust anchors are the hypervisors').
The in-guest agent keeps its place (a host-side agent cannot tell mediatore from the jailed
workload, so the `unix:path` selector of ADR-0023 still needs an agent inside the guest) and
its configuration changes only in the node attestor block and in
`discover_workload_path = true`.

ADR-0006 is unchanged: mediatore holds no SPIRE admin identity, mints no token, and never
connects to the SPIRE server. The capability to mint an agent identity exists, and it is the
per-host CA key (Decision 4), not a server-side call.

### 2. The agent ID is `x509pop/<issuer CN>/<subject CN>`

The server's `agent_path_template` is `/x509pop/{{ .Issuer.CommonName }}/{{ .Subject.CommonName }}`
(the template data above). The result is:

- **stable across renewal:** neither field changes when a certificate is renewed for the same
  guest, so node entries survive it (the fingerprint default does not);
- **declarable before the guest boots:** the issuer CN is the host's CA name, the subject CN
  is the VM's UID; both are control-plane facts, like the EK hash;
- **confined:** a CA can mint only IDs under its own name. A compromised host can therefore
  speak only for guests that were its own to begin with. It cannot receive another host's
  guests' entries. This is the property the prototype showed for an issuer-qualified
  template, and the CN-only template, which lacks it, is refused.

The confinement is **load-bearing on one rule: every CA in the bundle has a unique,
operator-chosen common name**, and the bundle's rendering refuses a duplicate. Both CN
fields are restricted to the path-segment alphabet.

*Amended 2026-11-26: a second rule carries the confinement, and it was not written here. The
server's template renders the common name of the leaf's immediate issuer
([ADR-0050](0050-host-trust-anchors-roots-in-the-bundle-and-a-short-lived-intermediate-per-host.md)'s
prototype table), so "a CA can mint only IDs under its own name" holds only for a CA that
cannot make another CA: one free to sign a CA could sign one carrying another host's name.
**Every CA in the bundle, and the host CA a node entry is rendered from, must therefore carry
`basicConstraints` with `cA` true and a path length of zero**; the server's own chain
validation then refuses anything a host signs below it. `refuse_duplicate_common_names` and
`host_ca_common_name` (`crates/mediatore-spire/src/x509pop.rs`) refuse a certificate that is
not a CA, or a CA with no path length or one above zero, naming it
(`refuse_unconfined_ca`; units `a_bundle_ca_that_may_sign_further_cas_or_is_no_ca_is_refused`,
`a_host_ca_that_may_sign_further_cas_or_is_no_ca_gives_no_attestation`). So no node entry is
declared under the name of a host whose CA is not so constrained: whoever creates a host's
signing CA must set the path length, or that host's guests do not attest. ADR-0050, if it is
accepted, replaces the rule with its own (roots in the bundle, the path length of zero on each
host's intermediate) and this check moves with it.*

### 3. The signer sets the subject; the guest does not name itself

The host's signer ignores the subject in the CSR. It takes only the public key, and sets: the
subject CN to the VM's UID (known to the provider, which started that guest's unit and
listens on that guest's own vsock socket, so the peer is the guest by construction);
`basicConstraints` `CA:FALSE`; `keyUsage` `digitalSignature`; no SAN; a bounded validity
(Decision 5). Guest key type v1: EC P-256 (the one tested).

### 4. The per-host CA is created at install and held by the provider

Like the per-host EK CA of banlieue ADR-0065, a per-host signing CA is created once, as the
provider's user, when the host is installed; its certificate (public) is what an operator adds
to the server's bundle when onboarding the host. The key never leaves the host and is readable
only by the provider. A compromised provider can mint certificates for its own host's
guests, and no others (Decision 2). This replaces the broader capability a token minter would
have had.

### 5. Certificates are renewed in the guest, over vsock, before they expire

A guest unit, before the agent starts, makes the key (if absent) and the CSR and requests a
certificate on vsock port 1025 (banlieue ADR-0137 Decision 6, ADR-0146 Decision 2); it fails
closed: no certificate, no agent, with retry and backoff as the prototype showed. A second
loop renews at half the remaining life, with the same key, so the node ID is unchanged. A
renewal that keeps failing ends the agent one SVID lifetime after the certificate's expiry:
fail closed, as for any lost root of trust.

*Amended 2026-11-24.* The helper is the `mediatore` binary the guest already runs
(ADR-0014), as a role of its own, `mediatore node-cert`, in `mediatore-guest`, written in
Rust with no subprocess: no `openssl`, no Python, nothing in the image that the other roles
do not already need. The prototype's shell helper is not carried forward. A minimal or
read-only guest root (banlieue ADR-0142's shared microvm root) has no interpreter to add,
and the host's half is pure Rust for the same reason (banlieue ADR-0143 Decision 6).

- **Two modes, two units.** `mediatore node-cert fetch` is the oneshot the agent's unit
  `Requires=` and is ordered after: it obtains a certificate or exits non-zero, so the agent
  never starts without one. `mediatore node-cert renew` is long-running beside the agent: it
  sleeps to half the remaining life of the certificate on disk, fetches again with the same
  key, and repeats. A failed renewal keeps the current files (still valid) and retries; it
  never deletes them.
- **Unprivileged.** Both run as the agent's own user (`spire`), which must read the key
  anyway. Connecting a vsock stream needs no capability, so the helper has none, and the
  agent's unit no longer needs the vTPM devices or the `tss` group.
- **The key** is EC P-256 (Decision 3), generated in process, written `0600` under the
  agent's runtime directory (`/run/spire/x509pop/`), and never sent: only the CSR leaves.
  It lives on `tmpfs` and is new at each boot. Nothing depends on it surviving one, because
  the agent ID is the issuer and subject CNs (Decision 2), not the key or the fingerprint.
- **The files** are two: the key, and the certificate as one file, the leaf followed by
  the chain (Decision 6). Each is written to a temporary name and renamed, so the agent,
  which re-reads them at every re-attestation, never sees a half-written one or a leaf
  without its chain. The agent configuration names them as `private_key_path` and
  `certificate_path`, which takes "the identity certificate followed by any intermediate
  certificates". There is no `intermediates_path`: SPIRE refuses one that holds no
  certificate ("no certificates found in file"), and that is every self-signed host CA's
  case.
- **What the guest checks in the reply.** The reply is size-capped; it must parse as PEM
  certificates; the leaf's public key must be the guest's own (a host answering with another
  key's certificate is refused before the agent ever sees it); the leaf must be valid now.
  The guest does not check the subject: it does not name itself (Decision 3), and the
  server's chain verification and the declared node entry are the checks that count.
- **Lifetime is the host's.** The signer chooses the validity, bounded by the host install
  to between five minutes and seven days (`--attestation-certificate-ttl`, banlieue
  ADR-0146 Decision 5). The guest reads `notAfter` from what it received and renews at half
  of what remains; it asks for no lifetime and has no setting for one. The fraction, one
  half, matches the agent's own re-attestation cadence (*What the prototype showed*).
- **Backoff respects the host's rate limit.** The signer accepts a bounded number of
  requests per guest per window and drops the rest; the helper's first retries are spaced so
  that the first minute stays under it, and later ones are capped, never tight.
- **Never logged:** the key, the CSR and the certificate bodies. The log carries the
  certificate's serial, issuer CN and `notAfter`.

### 6. The wire protocol is one request per connection, bounded

The guest sends a PEM CSR and half-closes; the host answers with a PEM certificate and
closes. The request is capped (the prototype's was 363 bytes); a non-EC-P-256 key, an
oversized request or a malformed CSR is refused without a reply. The provider never logs a
certificate request body.

*Amended 2026-11-24.* The answer is the PEM leaf **followed by the host CA's chain**, up to
but not including the root, when the host CA was signed by an upstream PKI (banlieue
ADR-0146 Decision 7, the signer's `ca-chain.pem`); for a self-signed host CA it is the leaf
alone, which is the original case. The guest writes the reply's certificates, leaf first,
as its agent's certificate bundle, and the agent presents the rest as intermediates, so the server's bundle
can hold the root and not one entry per host (ADR-0050). The guest caps the reply, as the
host caps the request.

### 7. The node key is the SHA-256 of the agent ID

ADR-0006's entry names, SPIFFE IDs and the admission policy all take a 64 lowercase hex "node
key", which for a TPM node is its EK hash. An `x509pop` node has no EK, so its key is the hex
SHA-256 of its agent ID (`x509pop/<issuer CN>/<subject CN>`). It is deterministic, has the
shape the admission policy already accepts, changes only when the issuer or subject CN does
(not on renewal), and is computed in one function (`node_key` in `x509pop.rs`), so a
different rule is a one-function change. The agent ID itself stays the entry's parent; the
key only names things.

Checked against the broker (`register_node` in `crates/mediatore-api/src/lib.rs`): it
compares the peer's node SPIFFE ID with `naming.node_id(key)`, which this key satisfies. It
then derives the stored agent ID with `naming.agent_id(key)`, which hard-codes the TPM path
(`/spire/agent/tpm/<key>`), and `bind` in `mediatore-claims` does the same. For an `x509pop`
node that agent ID is wrong, so its claim lookup would miss. The registration needs to carry
the attestation; [ADR-0050](0050-host-trust-anchors-roots-in-the-bundle-and-a-short-lived-intermediate-per-host.md)
Decision 6 (Proposed) designs that, so it is not built here.

## Consequences

- A Firecracker guest has a node identity with no new privileged component and no change to
  ADR-0006. An agent restart works (`reattestable` is true), which `join_token` could not do.
- The node entry's parent for this class is computed from two control-plane values: the
  issuer CN of the host's CA and the subject CN, the machine's UID. banlieue ADR-0143
  (Accepted) designs both: the **administrator** asserts the host's CA on the Provider
  (`spec.attestation.hostCa`, a single certificate, never discovered from the host, as
  banlieue ADR-0049 Decision 10 requires for any trust anchor) and the machine's status
  publishes the subject (`attestationSubject`), mirrored onto the claim. Until they
  exist, a `firecracker` pool member cannot be bound.
- The trust bundle now has a lifecycle per host: onboarding a host adds its CA (with a unique
  CN), retiring one removes it. A removed CA revokes every identity it signed, at the
  agents' next re-attestation.
- A compromised host can still mint certificates for its own guests. Nothing here
  attests the software on the host or in the guest (the TPM design does not either: it
  proves a key, not a measurement). A guest is trusted as far as the host that signed it.
- The guest image needs nothing new for the helper (*amended 2026-11-24*: it is the
  `mediatore node-cert` role of the binary already there, not `openssl` and Python): two
  units and an agent configuration with the `x509pop` attestor block, and the unix
  workload attestor keeps `discover_workload_path = true`. The earlier join-token layer in
  the sandbox's image build is replaced by a certificate layer.
- Threat model: a new trust anchor class (per-host signing CAs), a new vsock request path
  (bounded), and the removal of a server-side minting path that was never built. Pass due when
  implemented.
- Accepted, partly implemented: the control-plane side is in `crates/mediatore-spire/src/x509pop.rs`
  (the agent ID, the CA common-name checks, node entry rendering beside the TPM one); the claim
  watcher, the guest helper and the image are not; the host signer is built on the banlieue
  side for Cloud Hypervisor (banlieue ADR-0146, `banlieue-attestation-ca`), so the helper is
  proven there first and Firecracker reuses it unchanged. Settled 2026-11-24: the lifetime
  is the host's and the renewal fraction one half (Decision 5). Open: whether
  to reuse the SKI as the subject for a key-bound ID (untested); RSA and ed25519 keys; the
  bundle-rendering check for unique CNs (the check exists as `refuse_duplicate_common_names`;
  mediatore has no bundle-rendering code, the bundle is a deploy file, and ADR-0050 moves
  uniqueness to the issuer); how a host retires a CA without orphaning live guests;
  the registration and agent-ID derivation for an `x509pop` node (Decision 7, ADR-0050).
