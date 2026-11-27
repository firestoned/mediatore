<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0050: Host trust anchors at scale: roots in the bundle, a short-lived intermediate per host, enrolled by hardware attestation

**Status:** Proposed (the chain behaviour is proven in a prototype; three items remain, listed under "Not proven"). Decision 6 alone was built under [ADR-0049](0049-a-guest-without-a-vtpm-attests-with-x509pop-and-a-certificate-its-host-signs.md) on 2026-11-27, as its decisions 8 to 11, where the wire shape is; the rest is unchanged and Proposed · **Date:** 2026-11-19

Amends [ADR-0049](0049-a-guest-without-a-vtpm-attests-with-x509pop-and-a-certificate-its-host-signs.md)
decisions 1, 2 and 4 (what is in the server's bundle, and where a host's signing key comes
from); keeps its decision 2 property (a CA can mint only IDs under its own name), decision 3
(the signer sets the subject), decisions 5 and 6 (renewal and the wire protocol). Does not
amend [ADR-0018](0018-tpm-attestation-with-the-spiffe-plugin.md): the TPM path keeps its
per-hypervisor EK CAs here, and Consequences says how it could join later. Changes no
token shape and no workload SPIFFE ID ([ADR-0004](0004-spiffe-identity-scheme.md)); it does
change the node identity's storage contract (decision 6), which is why it is an ADR.

## Context

ADR-0049 trusts one signing CA per host, and each of those CAs is a certificate in the SPIRE
server's `ca_bundle_path`. That is the right shape for a handful of hosts and it was
prototyped at that size. The fleet this will run on is Cloud Hypervisor and Firecracker
hosts across the company, plausibly thousands of servers, built by several teams, over
years. At that size the per-host CA has five problems:

1. **The bundle grows with the fleet, and every change is a server change.** Onboarding or
   retiring a host edits the bundle every SPIRE server loads. A bundle of thousands of CAs is
   slow to load, hard to review, and a change that touches every server's trust for one
   host's lifecycle.
2. **Uniqueness is a human check.** The confinement of ADR-0049 decision 2 holds only if
   every CA's common name is unique; ADR-0049 leaves that to a rendering check and an
   operator choosing names across teams.
3. **Onboarding is manual.** banlieue ADR-0143 has the administrator assert the host's CA as
   one pasted certificate on the Provider. Thousands of hosts is thousands of pastes, and a
   rebuilt host (new key) is another.
4. **A long-lived CA key sits on every host with nothing rooting it.** Compromise of a host
   is bounded to that host's guests (good), but for as long as the CA lives, and the CA
   lives as long as the host's install.
5. **Retirement is slow and blunt.** Removing one host's CA means another bundle change on
   every server.

The TPM path has the same shape already (ADR-0018 decision 2: one EK CA per hypervisor in a
ConfigMap), so the scaling problem is the fleet's, not Firecracker's. A fix that serves
only x509pop would leave the other half to be redone.

SPIRE's design gives the fix without a new component class. The prototype (ADR-0049) showed
that a leaf signed by an intermediate verifies with only the root in the server's bundle,
the intermediate travelling with the agent (`intermediates_path`). The question is how a
host gets its intermediate, and how that stays at least as confined as the per-host CA.

## Decision

1. **The server's bundle holds roots only.** A small, reviewed set of root CAs per
   environment or region (two or three, so a root can be rotated with an overlap). The
   bundle changes when a root is rotated, which is rare, never when a host joins or
   leaves. Every SPIRE server of an environment loads the same roots, so the fleet scales by
   adding servers, not by growing any server's trust.

2. **Each host holds a short-lived intermediate CA, issued by a root.**
   - The host generates the intermediate's key on the host and sends a CSR; where the host
     has a TPM, the key is created non-exportable in it (an option, not a requirement).
   - The issuing policy, not the host, sets the certificate: `CA:TRUE`, **`pathlen:0`**
     (load-bearing: the server enforces it, and the template renders a leaf's immediate
     issuer, so any greater length would let a host mint a sub-CA with a CN of its
     choosing; see the prototype), `keyUsage` `keyCertSign` only, no SAN, and a lifetime of
     days (a configuration value, set at implementation).
   - **The subject CN is assigned by the issuer from the host's enrolled identity** (decision
     3), never taken from the CSR. It is a path segment (ADR-0049 decision 2's alphabet,
     length-bounded). This moves the uniqueness rule from an operator's care to the
     issuer's construction: two hosts cannot hold the same issuer name because the issuer
     derives it from a unique enrolled identity.
   - The agent ID stays `x509pop/<issuer CN>/<subject CN>` (ADR-0049 decision 2), where
     the issuer is now the host's intermediate. A host can still speak only for IDs under
     its own name.

3. **Enrollment is automatic and rooted in hardware.** A host proves its identity to an
   enrollment service with no shared secret and no operator pasting a certificate. v1: the
   host attests with its physical TPM through the SPIFFE TPM plugin (the machinery of
   ADR-0018, a separate host-tier trust domain so a host identity is never a sandbox
   identity), and the resulting SVID authenticates it to the issuing CA's API, whose role
   is bound to that host's SPIFFE ID path. The issuing CA is OpenBao's PKI engine, which
   the stack already runs for the trust domain's root (ADR-0031). The host-identity
   mechanism is the replaceable part: if the company already has an authoritative,
   hardware-rooted host identity, enrollment verifies that instead, and nothing else in
   this ADR changes. What does not change: the issuer sets the CN, the host gets nothing
   it can choose.

4. **Renewal replaces revocation; a ban is immediate through what mediatore declares.**
   - Intermediates and guest certificates are short-lived and renewed at half their life
     (ADR-0049 decision 5 for the guest; the host does the same against the issuing CA).
     There is no CRL: SPIRE's `x509pop` attestor does not read one.
   - **A compromised or retired host is cut off in two steps with two clocks.** At once:
     the broker's `banned` flag on the host's `SandboxNode` records and mediatore declares
     no node entry, and deletes the ones it has, under that issuer CN. An agent may still
     attest, but an agent with no entry holds no workload identity (ADR-0006: nothing is
     issued that mediatore did not declare). Within the intermediate's lifetime: the
     enrollment role refuses to renew it, and it expires.
   - The window an attacker with a stolen host key has is the intermediate's remaining
     life, minus nothing, for attesting; and zero for obtaining a workload identity once the
     ban is recorded. That second property is the one that matters and it does not depend
     on any CA operation.

5. **The guest side is ADR-0049's, unchanged.** A guest generates its key, sends a CSR over
   vsock, the host signs a leaf (subject CN the VM UID, `CA:FALSE`, `digitalSignature`,
   bounded validity) with its intermediate, and the guest carries the intermediate chain
   for the agent's `intermediates_path`.

6. **The node identity is generic, and the control plane already has the shape.**
   `crates/mediatore-spire/src/x509pop.rs` (ADR-0049, #140) has `NodeAttestation`
   (`Tpm { ek_hash }` or `X509pop { issuer_cn, subject_cn }`, chosen explicitly, never guessed
   from which data is present), `agent_id_for` and `node_key` (the 64 hex key every ADR-0006
   shape derives from: the EK hash for a TPM node, the SHA-256 of the agent ID for an x509pop
   node). This ADR changes none of that; the issuer CN simply becomes the host
   intermediate's. What it fixes is the part #140 left open (`node_key`'s "open design
   question"): the **registration** carries the attestation, not a bare `ek_hash`.
   `NodeRegistration` gains the attestation as `tpm { ek_hash }` or
   `x509pop { issuer_cn, subject_cn }`; absent means `tpm` and the existing `ek_hash` field
   keeps being accepted, so a v0.3 or v0.4 guest registers unchanged; an unknown kind is
   refused (fail closed); and the broker compares the registration's derived `node_key`
   against what the watcher derived from banlieue's published values. The wire shape is fixed
   by unit tests at implementation. The contract: a new attestor adds a variant, never a
   second registration path.

   *Built 2026-11-27 under ADR-0049, as its decisions 8 to 11: this decision depends on
   nothing else here, and the wire shape is recorded there (ADR-0049 decision 8).*

7. **Algorithms and lifetimes are configuration, in one profile.** Intermediate and leaf
   key types, validity and the renewal fraction live in one certificate profile
   (EC P-256 by default, the type tested). A different curve or a post-quantum signature
   scheme is a profile change plus whatever the SPIRE `x509pop` verifier supports, not a
   design change. Post-quantum is not decided here.

## What the prototype showed

Run 2026-11-19 in a throwaway container: SPIRE 1.15.5 (the version the dev deployment pins;
linux-arm64 build, sha256 verified), a throwaway trust domain, a throwaway PKI generated with
OpenSSL, the server's bundle holding the one root and `agent_path_template`
`/x509pop/{{ .Issuer.CommonName }}/{{ .Subject.CommonName }}`. Observed, not read from
documentation:

| Question | Observed |
| --- | --- |
| Leaf under a `pathlen:0` intermediate, root only in the bundle | Attested as `x509pop/host-a/vm-1`: `.Issuer.CommonName` rendered **the intermediate's** CN. |
| Intermediate not carried by the agent | Refused, `x509: certificate signed by unknown authority`. The intermediates must travel with the agent (`intermediates_path`), as ADR-0049 found. |
| Same subject CN under another host's intermediate | A different ID, `x509pop/host-b/vm-1`: the confinement holds through an intermediate. |
| A sub-CA below a `pathlen:0` intermediate issues a leaf | Refused, `x509: too many intermediates for path length constraint`. **The server enforces `pathlen:0`**, so a host cannot extend the chain. |
| An intermediate with the same CN as a trusted host (`host-a`) under a root the server does not trust | Refused, `signed by unknown authority`. The name alone buys nothing; the root does. |
| A `pathlen:1` intermediate with a legitimate sub-CA | Attested, and the ID carried the **sub-CA's** CN (`x509pop/sub-p1/vm-p1`), not the host intermediate's: the template renders the leaf's *immediate* issuer. |
| Host renews its intermediate (same CN, **new key**) and re-signs the same guest key | The same agent ID (`x509pop/host-a/vm-1`) on a fresh start, and the same as the original leaf. |

Two consequences for the design, both folded into the decisions above: `pathlen:0` is
**load-bearing**, because with any greater length a host could mint a sub-CA with a CN of
its choosing and the template would render that CN; and the issuing policy must therefore
set it, since the server only enforces what the certificate says.

Not proven (so this ADR stays Proposed):

1. **A running agent picks up the renewed intermediate and leaf at its next re-attestation,
   without a restart.** Two attempts did not settle it: `agent_ttl` did not shorten the
   agent SVID in 1.15.5 (no re-attestation in 100 s), and evicting the agent made the
   server deny its sync (`PermissionDenied`) without the agent re-attesting within 90 s.
   ADR-0049 observed that an agent re-reads its certificate file at each re-attestation;
   whether `intermediates_path` is re-read too is the open part, and the on-host prototype
   with a real SVID lifetime answers it. If it is not re-read, the guest's helper restarts
   the agent after a renewal, and that cost goes in this ADR.
2. **The issuing policy can force the CN from the enrolled identity and ignore the CSR's
   subject** (decision 2). Needs OpenBao's PKI engine (a role setting, or a thin issuing
   step in front of it); whichever works is the one this ADR names. Not testable with
   OpenSSL, where the signer is whatever it is told to be.
3. **Enrollment on a real host** (decision 3): the physical-TPM attestation of a host to the
   issuing CA, and its behaviour when the CA is unreachable at renewal.

## Consequences

- **The fleet's operations get simple.** Onboarding a host is enrollment, with no pull
  request against the bundle and no pasted certificate; retiring one is a ban plus
  not renewing. The cost moves to running the issuing CA and the enrollment path
  reliably, which is a service with an availability requirement (a host that cannot renew
  its intermediate can no longer sign guests' certificates once it expires; running
  guests are unaffected until their own certificates expire).
- **ADR-0049 stays Accepted.** Its decisions 2 (as to the property), 3, 5 and 6 are this
  ADR's too; 1, 2 (as to the bundle) and 4 are replaced by decisions 1 to 3 here once this
  one is Accepted, and ADR-0049 is amended in the same change.
- **banlieue changes.** ADR-0143's `spec.attestation.hostCa` (one certificate pasted per
  Provider) becomes a reference to a root or an enrollment endpoint, and the host's issuer
  CN comes from enrollment, not from the administrator. That ADR is banlieue's to amend;
  this one only states the requirement.
- **The TPM path can join, later and separately.** A Cloud Hypervisor host's `swtpm-localca`
  could be an intermediate under the same roots, collapsing ADR-0018's per-hypervisor
  ConfigMap the same way. That is its own ADR, with its own TPM-path proof on the build
  host (`rules/testing.md`); nothing here touches it.
- **Touches the TPM attestation path only through decision 6.** `NodeRegistration`, the node
  entry's shape, `identity.rs` and the claim binding are on the list in `rules/testing.md`:
  the change merges only after `make kind-e2e-tpm` has run on the build host, with the
  result stated, and a v0.3 guest registering against the new broker is a test.
- **Threat model, on implementation (`rules/threat-modeling.md`):** new assets (the roots,
  the issuing role, host intermediates), a new boundary (host to enrollment service), a
  new request path (host enrollment) and a new trust anchor class replacing the per-host
  CA; accepted risks: a compromised host forges identities for its own guests for the
  intermediate's lifetime, and a stolen root forges every host's (the roots are the crown
  jewels; held in OpenBao with an HSM-backed seal where the platform has one, rotated
  with an overlap, offline where the environment allows).
- **No guest of one host is confined from another host's by anything but the issuer name.**
  As in ADR-0049, nothing attests the software on the host or in the guest; a guest is
  trusted as far as the host that signed it.

## Alternatives rejected

- **A CA per host in the bundle (ADR-0049 as written).** The five problems in Context; right
  at a handful of hosts, wrong at a fleet.
- **One signing CA shared by all hosts.** A single host compromise forges any identity
  in the fleet. The confinement of decision 2 is what the per-host name buys.
- **A nested SPIRE server on every host.** It moves a SPIRE server's capability to sign
  X509-SVIDs for the trust domain onto every host, a larger capability than a CA confined
  to its own name, and thousands of servers to operate.
- **`join_token`.** ADR-0006: a component that can create tokens can mint an identity for
  any alias.
- **A CRL or OCSP for host revocation.** SPIRE's `x509pop` reads neither; short lifetimes
  plus the ban of decision 4 give the same effect with no new protocol.

## Open questions

1. Is there already a hardware-rooted host identity in the company that enrollment should
   verify instead of attesting with the SPIFFE TPM plugin (decision 3)? If so, decision 3
   names it and the host-tier trust domain is not built.
2. The intermediate's lifetime and the renewal fraction (decision 2, 4): a trade of
   enrollment-service load against the compromise window. Set from measured renewal cost
   at implementation, not decided here.
3. Do all Cloud Hypervisor and Firecracker hosts have a physical TPM 2.0 (decision 3, and
   the option in decision 2)? A host without one needs a stated alternative, not a silent
   downgrade.
4. How the issuing CA is made available per region, and what a host does when it is
   unreachable (the renewal window of decision 4).
5. banlieue ADR-0143's amendment and its timing against ADR-0049's implementation.
