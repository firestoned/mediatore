<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Testing tiers

mediatore is tested in four tiers. Each one proves something the tier below cannot,
and each one runs the same way locally and in CI (`.claude/rules/testing.md`,
`.claude/rules/github-workflows.md`). Nothing in any tier needs a real trust domain,
a real cluster address or a real credential in a tracked file.

| Tier | Command | What it proves | Where it runs |
| --- | --- | --- | --- |
| Unit | `make check` | Every crate's own contract, over fakes that validate like production | everywhere, every commit |
| Dev-mode loop | `make e2e` | The four shipped binaries agree on the wire contract as separate processes | everywhere, every PR |
| Live against SPIRE in kind | `make kind-e2e` | Kubernetes, the SPIRE Controller Manager and the admission policy behave as the ADRs say, as the broker's own ServiceAccount | CI on every PR, any laptop with a container runtime |
| Live against a real cluster | `make live-admission-test` | The same, against a deployment you operate | by hand, before a release or after changing the deployment |

## Unit: `make check`

`cargo fmt`, clippy with pedantic lints as errors, every test, `cargo deny`. The fakes
are deliberately as strict as the real thing: `MemoryEntries` refuses the same inputs
`KubeEntryManager` refuses, and `KubeEntryManager` itself is driven against a scripted
fake API server (`tower-test`) whose every step asserts the request it received
(`crates/mediatore-spire/src/kube.rs`). A fake more permissive than production hides
bugs, so anything a live tier finds the fake got wrong is fixed in the fake in the
same change.

## Dev-mode loop: `make e2e`

`dev/demo.sh` and `crates/mediatore/tests/e2e_dev.rs` run the whole claim loop over
real HTTP listeners with the fake IdP from `mediatore-testkit`: login, claim, bind,
`/v1/me`, `/v1/token`, verify against the broker's own JWKS, release, cut-off. The peer
identity is a header (`dev_mode`), entries live in memory. Negative cases are part of it:
wrong audience, wrong SVID type, wrong subject, revoked claim. The demo builds the two
guest binaries with their `dev` cargo feature, which is the only build that has the
header path at all.

`crates/mediatore/tests/e2e_mtls.rs` runs the same sandbox API over the production mTLS
listener (`crates/mediatore-tls`: the verifiers, the accept loop, the client configs) with
the testkit's `TestCa` minting SPIFFE-shaped SVIDs in place of a SPIRE agent. It proves
the handshake refuses what ADR-0007 says it refuses, before any HTTP is parsed: no client
certificate, a foreign trust domain, the broker's own identity used as a client, an
expired SVID, a CA-shaped leaf, a server that is not `spiffe://<td>/mediatore`. It also
proves the dev header is ignored on an mTLS connection and refused outside `dev_mode`,
and that a rotated SVID is used by the next handshake. It is part of `make check`.

`crates/mediatore-tls/tests/handshake.rs` looks at the handshake itself: TLS 1.3,
X25519MLKEM768 and AES-256-GCM-SHA384 negotiated, a client offering only classical key
exchange refused, and a trust domain whose CA and SVIDs are ML-DSA-65 accepted by the same
verifiers. The unit test in `crates/mediatore-proto/src/tls.rs` pins the provider's group
order so the post-quantum hybrid stays the first key share every client offers.

## Live entries round trip

`crates/mediatore-spire/tests/live_kube.rs` is the test behind both live tiers. It is
`#[ignore]`d and fails loudly, never skips, when its fixture is missing:

| Variable | Meaning |
| --- | --- |
| `MEDIATORE_LIVE_KUBECONFIG` | kubeconfig for the cluster that runs the SPIRE Controller Manager |
| `MEDIATORE_LIVE_TRUST_DOMAIN` | the SPIRE server's trust domain; the test refuses to guess it |
| `MEDIATORE_LIVE_CLASS_NAME` | the controller manager's `className` (the hardened chart derives `<namespace>-<release>`) |
| `MEDIATORE_LIVE_IDENTITY` | `impersonate` (default): the kubeconfig is an admin and every request impersonates `system:serviceaccount:banlieue-system:mediatore`; `self`: the kubeconfig already is that ServiceAccount, for example one built around `kubectl -n banlieue-system create token mediatore` |

Either way, what is exercised is what production gets: the `ClusterRole` in
`deploy/base/rbac.yaml` and the `ValidatingAdmissionPolicy` in
`deploy/base/admission/clusterstaticentry-mediatore.yaml`, never the credential that
runs the test. The scenario, in order:

1. Declare the node entry for a fixture EK hash (no real TPM has that key) and observe
   the controller manager set it on the server. Declare it again: a 409 is tolerated.
2. Declare a claim entry for a fresh claim UID, observe it set, check its selector and
   `x509SVIDTTL`.
3. List under the `app.kubernetes.io/managed-by=mediatore` label and find both with
   their kinds and the claim UID.
4. Eleven refused shapes through admission: a name outside `mediatore-*`, a SPIFFE ID
   outside `/banlieue/`, a non-tpm parent, a node entry whose EK hash differs from its
   parent's, a non-unix selector, a claim entry with the wrong selector, no `className`,
   a 24 h TTL, and `admin`, `downstream` and `storeSVID` set true. Each must come back
   as a policy denial (403 for `reason: Forbidden`, 422 for `reason: Invalid`) with the
   policy's own message.
5. RBAC refuses `update` and `patch`: entries are replaced, never edited.
6. Retract both entries, retract once more (404 tolerated), confirm the list is clean.

Cleanup runs before the scenario and after it, whether it returned an error or panicked
in an assertion, so a failing run leaves nothing behind.

### What the first live run found

`ClusterStaticEntry.status.set` is a transient, not a steady state. The controller
manager writes `set: true` on the reconcile pass that creates the server entry, and the
next pass, which that status write itself triggers, rewrites it to `false` about 20 ms
later because nothing was created or updated. A 500 ms poll never saw it, so every bind
timed out. `KubeEntryManager` now opens a watch before the create and succeeds on the
transition; ADR-0006 decision 5 records the measurement. That is the kind of thing the
live tiers exist for.

## Live against SPIRE in kind: `make kind-e2e`

`make kind-up` creates a one-node kind cluster (`dev/kind/cluster.yaml`), installs the
same hardened charts and versions the homelab runs (`spire-crds` and `spire`,
`dev/kind/spire-values.yaml`, release `spire` in namespace `spire-server` so the
controller manager's class is `spire-server-spire`), applies the broker's
ServiceAccount, RBAC and admission policy from `deploy/base`, and mints a one-hour
token for that ServiceAccount into `.kind/mediatore-sa.yaml` (`dev/kind/sa-kubeconfig.sh`;
the directory is git-ignored). `make kind-e2e` then runs every live suite with
`MEDIATORE_LIVE_IDENTITY=self`. `make kind-e2e-ci` is the CI shape: suites, cluster
state and logs on failure (`make kind-e2e-logs`), cluster deleted after.

Suites today:

| Target | ADR | Suite |
| --- | --- | --- |
| `make kind-e2e-entries` | 0006 | the live entries round trip above |

Planned, as the roadmap lands (`.github/community/01-spiffe-mtls-and-entries.md`):

- the broker pod in the cluster with the CSI driver socket, fetching its own SVID from
  the `ClusterSPIFFEID` in `deploy/base` (ADR-0007), a client pod with a claim-shaped
  SVID reaching the sandbox listener over mTLS, and the negative cases from ADR-0007
  decision 8;
- the claim watcher binding a `VirtualMachineClaim` to a node entry derived from a
  published EK certificate (roadmap 03), with banlieue's CRDs installed but no VM.

What kind cannot do, and the real-cluster tier covers: TPM node attestation (the
parent agent `spiffe://<td>/spire/agent/tpm/<ek>` never exists in kind; the server
accepts entries for a parent that has not attested, which is exactly the order a node
entry is declared in), real VMs and jails, and the broker's `LoadBalancer` exposure.

Pins live at the top of the `Makefile`: kind, the node image by digest (same
Kubernetes minor as the homelab), both chart versions, the placeholder trust domain
`sandbox.test`. Dependabot does not see them; bump them when the homelab moves.

Runtimes: kind needs Docker or rootless Podman (`KIND_EXPERIMENTAL_PROVIDER=podman`),
`kubectl` and `helm`. `make kind-install` fetches the pinned kind CLI, checksum
verified, into `KIND_BIN_DIR` (default `/usr/local/bin`).

## Live against a real cluster: `make live-admission-test`

The same test against a deployment you operate, with the variables above set by hand.
Pass the trust domain and class name from the deployment's own config (the controller
manager's ConfigMap has both); never write them into the repo. With an admin kubeconfig
the default `impersonate` mode is enough; where the admin credential is interactive
(an OIDC plugin, say) mint a token for the ServiceAccount and use `self`.

Troubleshooting a timeout: the controller manager's log names every entry it created
or refused (`kubectl -n spire-server logs statefulset/spire-server -c spire-controller-manager`),
and the test prints the resource as the API server last had it. A status that is
present but not `rendered` means the controller manager refused the spec; `masked`
means another entry already claims the same parent, selectors and ID.
