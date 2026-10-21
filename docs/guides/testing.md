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
| Dev-mode loop | `make e2e` | The roles of the one binary agree on the wire contract as separate processes | everywhere, every PR |
| Session e2e | `make check` (`crates/mediatore/tests/e2e_session.rs`) | The session path (ADR-0013) over real listeners against the fake issuer's real authorization-code and refresh grants: delegation, rotation, fresh groups, outage, revocation, the group gate at refresh, the per-claim limit; the CLI's PKCE login in `crates/mediatore-client` | everywhere, every commit |
| Live against SPIRE in kind | `make kind-e2e` | Kubernetes, the SPIRE Controller Manager and the admission policy behave as the ADRs say, as the broker's own ServiceAccount; the broker image runs on the CSI driver's socket and agent-issued SVIDs meet on the sandbox listener | CI on every PR, any laptop with a container runtime |
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
wrong audience, wrong SVID type, wrong subject, revoked claim. The demo builds the one
binary with the `mediatore/dev` cargo feature, which is the only build whose `guest` and
`token` roles have the header path at all.

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
| `make kind-e2e-mtls` | 0007 | the broker image on the CSI socket, agent-issued client SVIDs over SPIFFE mTLS, below |
| `make kind-e2e-watcher` | 0011 | the watcher Lease, a member's certificate becoming a node entry, a claim without a record binding nothing, below |
| `make kind-e2e-sandbox` | 0008, 0012 | the `AgentSandbox` CRD and its subject policy, a sandbox becoming an owned claim and a record, the claim bound end to end to a claim entry and the guest fetching the subject, a broker restart on the store with the sandbox staying `Ready`, deletion through the finalizer, the released row swept into the audit table, below |
| `make kind-e2e-store` | 0012 | the broker on PostgreSQL over `verify-full`, the store conformance suite against that database, below |
| `make kind-e2e-dex` | 0013 | the real CLI logging in at a real Dex from inside the cluster and delegating the session, a refresh at Dex before every issue, the claim released when the user leaves the gated group in the directory and when the refresh token is deleted at Dex, below |

### The store: PostgreSQL over TLS the client verifies

Every kind tier runs the broker on the store it would run on in production.
`make kind-postgres` (a dependency of `make kind-broker`) mints a CA and a server
certificate for `mediatore-postgres.banlieue-system.svc` and `localhost`
(`tls-fixture`, a testkit binary), puts them in a Secret, applies
`dev/kind/postgres/postgres.yaml` (PostgreSQL 18, one pod, no persistence, TLS 1.3
only) and waits for it. The broker overlay generates Secret `mediatore-store` with a
`postgres://...?sslmode=verify-full&sslrootcert=/etc/mediatore-pg/ca.pem` URL and
mounts the CA; the base Deployment reads the URL from that Secret as shipped.

`make kind-e2e-store` (`dev/kind/store-e2e.sh`) then checks the broker log says it
migrated and connected to PostgreSQL and that the password is nowhere in it,
port-forwards the database and runs the store conformance suite (the one `make check`
runs over `MemoryStore` and over SQLite in memory) against it as the `#[ignore]`
`sql::tests::postgres` cases, with `MEDIATORE_LIVE_STORE_URL` pointing through the
port-forward and `--test-threads=1`, since the cases share one database and each empties
it first. The same suite on three backends is what makes the one query set of
ADR-0012 a tested claim rather than a hope. The sandbox tier adds the restart: with a
sandbox `Ready`, the broker is restarted and must come back finding the record, the
entry id and the node in the store, with no second record and no second entry; after
the deletion, the kind config's zero retention and 15 s resync let the tier see the
released row archived.

Every kind tier also runs the broker on the transit sealer
([ADR-0015](../adr/0015-transit-sealer.md)). `make kind-openbao` (a dependency of
`make kind-broker`) mints a certificate for `mediatore-openbao.banlieue-system.svc`,
applies `dev/kind/openbao/openbao.yaml` (OpenBao 2.7.1, in-memory storage, TLS 1.3
only) and runs `dev/kind/openbao-setup.sh`, which initialises and unseals it, enables
transit with a derived key `mediatore`, configures the Kubernetes auth method against the
cluster, writes a policy allowing encrypt and decrypt on that key alone, and a role for
the broker's ServiceAccount with audience `openbao`. The broker overlay's config points
`store.sealing.transit` at it with the CA the target put in a ConfigMap; the base
Deployment's projected token is what the broker logs in with. The broker's startup
probe (a seal and unseal under a random binding, and a refusal under another) is what
every tier's `rollout status` waits on, and the Dex tier's sessions are sealed and
reopened there on every issue.

### The Dex path against a real Dex

`make kind-dex` (a dependency of `make kind-broker`, like the PostgreSQL) runs a Dex
(`dev/kind/dex/dex.yaml`, storage in its own CRDs) over TLS with a certificate the
target mints for `mediatore-dex.banlieue-system.svc`, and a glauth LDAP directory
behind it (`dev/kind/dex/glauth.yaml`, the users and groups in `dev/kind/dex/glauth.cfg`:
`octocat` in group `sandbox-users`, the service account Dex binds as). It also mints
the broker's STS signing key into a Secret. The broker overlay's config
names that Dex as a session issuer with `subject_claim: preferred_username`,
`required_group: sandbox-users` and `ca_file` pointing at the CA the target put in a
ConfigMap, so the broker verifies the issuer exactly as it would one on a private PKI.

`make kind-e2e-dex` (`dev/kind/dex-e2e.sh`) runs the user's side from a pod: the
test-only image (`dev/kind/Dockerfile.e2e`) holds the shipped binary and the testkit's
`dex-driver`, which spawns the real `mediatore login --no-browser --ca-file ...`, plays
the browser it would have opened (follows the authorization URL to Dex, posts the
password into Dex's form, lets Dex redirect to the CLI's loopback listener) and then
spawns the real `mediatore sandbox create`, so what runs against Dex is the CLI as
shipped. Then:

| Step | Expected |
| --- | --- |
| `cli-1` logs in and requests a sandbox | `logged in as octocat` in its log; the broker logs `session parked`; Dex holds exactly one refresh token |
| the claim is patched Bound with the fixture node's certificate (as in the sandbox tier) and a `ClusterSPIFFEID` points at the claim UID | the sandbox turns `Ready`; the guest fetches `octocat`'s subject |
| `token-1` runs `mediatore token` with the claim SVID | a token for `octocat`, `aud` `e2e-sts`, `claim_uid` the claim's; Dex's refresh token record shows `lastUsed` advanced: the issue refreshed first |
| `octocat` is taken out of `sandbox-users` in the directory (the ConfigMap rewritten, glauth restarted) and `token-2` asks again | `403 session_revoked`; the broker logs `upstream session refused; claim released`; the claim entry is gone. Dex re-read the group at refresh (its LDAP connector queries on every refresh) |
| the group restored, `cli-2` logs in again and requests a second sandbox; `token-3` issues | a token for the new claim |
| every refresh token is deleted at Dex (`kubectl delete refreshtokens.dex.coreos.com`) and `token-4` asks again | `403 session_revoked`, the claim released: Dex answered `invalid_grant` |

Dex, glauth and their passwords are fixtures of a throwaway cluster (`dev/kind/dex/`);
nothing in them is a deployment shape, and the Dex tier's namespace, entries and
directory change are undone when the script exits.

### Issuer profiles: Google and Auth0 against the fake

`crates/mediatore/tests/e2e_issuers.rs` runs the real CLI login code, the claim, the
refresh and the group gate against the fake issuer playing Google (`email` subject, no
groups, `access_type=offline`, the installed-app secret at the token endpoint) and
Auth0 (`email` subject, groups under a namespaced claim), ADR-0017. The [issuers
guide](issuers.md) is the operator's side; GitHub stays behind Dex and is the kind tier
above.

### The Entra path: by hand, against a tenant

Entra does not run in kind. The Entra path (ADR-0016) is proven in `make check` against
the fake issuer playing Entra (`crates/mediatore/tests/e2e_entra.rs`: the exchange at
claim creation, the refresh per audience, the refusals, the outage, the three credential
shapes, and `crates/mediatore-entra` for the assertion and the grants), and against a
real tenant by `crates/mediatore/tests/live_entra.rs`, an ignored test that takes the
issuer, client id, credential and a user's token from the environment and fails rather
than skips without them. [The Entra path](the-entra-path.md) has the command. Roadmap 04
closes when that run is green.

### Broker and client pods over SPIFFE mTLS

`make kind-broker` builds the one musl binary on the host (`make dist`), packages it
with the shipped `Dockerfile` (`BINARY_FROM=host`: the same runtime stage over the
host-built binary), loads that image into the cluster with `kind load` (the node and
workload pods run the same image with the `guest` and `token` subcommands, ADR-0014), and
applies `dev/kind/broker`: a kustomize overlay of `deploy/base` as shipped, with the
Traefik route removed, one replica and the image tag changed. The Deployment's CSI
inline volume, ServiceAccount, `ClusterSPIFFEID`, RBAC and admission policy are the
production manifests. The rollout succeeds only once the broker has its SVID: the
listeners answer nothing before `broker_identity` returns.

`dev/kind/mtls-e2e.sh` then applies `dev/kind/mtls/clients.yaml`: a namespace, four
`ClusterSPIFFEID` fixtures an admin creates (nothing goes through mediatore's own entry
path), and four pods that get their SVIDs from the real agent through the same CSI
volume and run the shipped binary's `guest` and `token` roles against `mediatore-sandbox` (the same server image, ADR-0014):

| Pod | SVID the agent issues | Expected |
| --- | --- | --- |
| `claim` | `spiffe://<td>/banlieue/claim/<fixture uid>` | `mediatore token` gets `403 unknown claim`: the handshake completed and the listener derived that UID from the certificate |
| `node` | `spiffe://<td>/banlieue/node/<fixture EK hash>` | `mediatore guest` logs `node registered`: `POST /v1/nodes` accepted because the peer ID matches the EK hash it claims |
| `intruder` | `spiffe://<td>/intruder` | refused in the handshake, no HTTP answer; the broker logs `peer authenticated but not authorized here` |
| `impersonator` | `spiffe://<td>/mediatore` | the same: the broker's own identity is not a client identity, even when a real agent issued it |

The script also reads the broker's log: the claim connection negotiated X25519MLKEM768
and AES-256-GCM-SHA384, the node connected, both refusals were logged by the authorizer.

### Claim watcher against banlieue's CRDs

`make kind-banlieue-crds` renders `VirtualMachine` and `VirtualMachineClaim` from the
pinned `banlieue-api` (`cargo run -p mediatore-testkit --bin banlieue-crds`, a `v1/List`
of the CRDs the watcher was compiled against, post-processed by banlieue's own
`crdgen_support::prepared`) and applies them with kubectl's client-side validation off,
because a nullable enum in the schema carries a `null` that only the API server's
structural validation accepts; `make kind-e2e-watcher`
then restarts the broker so its controllers start against existing CRDs and runs
`dev/kind/watcher-e2e.sh`. No banlieue controller runs: the script patches the statuses
banlieue would have written. It proves, as the broker ServiceAccount against the real
admission policy:

| Step | Expected |
| --- | --- |
| the broker pod holds `Lease` `mediatore-watcher` and logs `claim watcher running` | one leader, elected through the namespaced Role in `deploy/base/rbac.yaml` |
| `member-1` (label `banlieue.io/pool`) gets the fixture endorsement certificate patched into `status.tpmEndorsementCertificates` | `ClusterStaticEntry` `mediatore-node-<hash>` appears with `spiffe://<td>/banlieue/node/<hash>`; the broker logs `node entry declared` |
| `member-2` never publishes a certificate | no entry |
| `claim-orphan`, labelled `app.kubernetes.io/managed-by=mediatore`, patched to `Bound` with the same certificate, while the broker has no record for its UID | no claim entry, the claim is not deleted |

The certificate is `mediatore_testkit::ek::RSA_EK_PEM` (`cargo run -p mediatore-testkit
--bin ek-fixture`), a throwaway self-signed key whose hash the guest, the attestor and
the unit tests agree on. The watcher's own logic (bind by EK, the 60 s resolution
timeout, release on every phase, the resync) is unit-tested in
`crates/mediatore-claims/src/watch.rs` over the in-memory store and entries, and the
Lease verdicts in `crates/mediatore-claims/src/lease.rs`.
### AgentSandbox: from request to Ready and back

`make kind-e2e-sandbox` needs both sets of CRDs: banlieue's from the pin (above) and
mediatore's own `agentsandboxes.mediatore.io` from `deploy/base/crds/`, which
`make crds` renders from `crates/mediatore-claims/src/sandbox.rs` and the broker overlay
applies with the subject admission policy
(`deploy/base/admission/agentsandbox-subject.yaml`). The overlay's config names a
placeholder issuer and audience so the reconciler has something to accept, and lists
`e2e-broker` in the policy's `brokers` so the exemption can be exercised. The broker is
restarted so its controllers start against existing CRDs, then
`dev/kind/sandbox-e2e.sh` runs, as the admin and as the broker ServiceAccount
(`.kind/mediatore-sa.yaml`):

| Step | Expected |
| --- | --- |
| a `node` pod runs `mediatore guest` with the fixture EK hash and a `ClusterSPIFFEID` for `spiffe://<td>/banlieue/node/<hash>` | `node registered` over its agent-issued SVID: the broker now knows the node the bind will resolve to |
| the admin creates an `AgentSandbox` naming `octocat`; an impersonated stranger does the same | both denied at admission with `spec.subject.id is ...`: the default is caller-equals-subject |
| the admin names itself; `e2e-broker` (listed) names `octocat`; the broker ServiceAccount names `octocat` | all three admitted: the two exemptions of ADR-0008 decision 5, and the ordinary case |
| `kubectl patch` of `spec.ttlSeconds` on the existing sandbox | denied: `spec is immutable` |
| the reconciler sees `sb-e2e` | a finalizer `mediatore.io/sandbox`; a `VirtualMachineClaim` `sb-e2e` with a controller `ownerReference` to the sandbox, the managed-by label and the sandbox's `subject`, `poolRef` and `ttlSeconds`; the broker logs `record created` with the claim's UID; status `Pending` with `claimUid` |
| the claim is patched `Bound` with the fixture certificate and a `virtualMachineRef` | `ClusterStaticEntry` `mediatore-claim-<uid>` appears; the sandbox's status mirrors the member and `expiresAt`, `entrySet` and `ready` turn true; the `node` pod logs `subject fetched` for `octocat` and that claim UID (`GET /v1/me` over the node SVID) |
| the broker ServiceAccount creates `sb-bad` with audience `nope` | status `Failed`, reason `audience nope is not configured`, no claim |
| `kubectl delete agentsandbox sb-e2e` | the claim entry is retracted, the claim deleted, the sandbox gone, the broker logs `sandbox released`; no claim entry remains |

No banlieue controller runs, so the bind is the script's patch; everything else (the
policy, the owner reference, the record, the entry through the entries admission policy,
the guest's subject fetch, the finalizer) is the production path. The reconciler's own
logic is unit-tested in `crates/mediatore-claims/src/sandbox.rs` over the in-memory store,
entries and a fake API that refuses what the API server refuses; the user API's front door
(`POST/GET/DELETE /v1/claims` creating, reading and deleting the resource) in
`crates/mediatore/tests/e2e_sandbox.rs` over `mediatore_testkit::MemorySandboxes`.

What this tier proves and the hermetic suite cannot: the `ClusterSPIFFEID` in
`deploy/base` renders to `spiffe://<td>/mediatore` for the broker pod; the CSI inline
volume delivers the Workload API under PSS `restricted`; SVIDs the `k8s` workload
attestor issued chain to the bundle the broker got from the same agent.

What kind cannot do, and the real-cluster tier covers: TPM node attestation (the
parent agent `spiffe://<td>/spire/agent/tpm/<ek>` never exists in kind; the server
accepts entries for a parent that has not attested, which is exactly the order a node
entry is declared in), real VMs and jails, banlieue's claim controller binding a real
member, and the broker's `LoadBalancer` exposure.

Pins live at the top of the `Makefile`: kind, the node image by digest (same
Kubernetes minor as the homelab), both chart versions, the placeholder trust domain
`sandbox.test`. Dependabot does not see them; bump them when the homelab moves.

Runtimes: kind needs Docker or rootless Podman (`KIND_EXPERIMENTAL_PROVIDER=podman`
and `CONTAINER_CLI=podman` for the image builds), `kubectl` and `helm`; the images need
the `x86_64-unknown-linux-musl` target and a musl C compiler (`musl-tools`) for
`aws-lc-rs`. `make kind-install` fetches the pinned kind CLI, checksum verified, into
`KIND_BIN_DIR` (default `/usr/local/bin`).

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
