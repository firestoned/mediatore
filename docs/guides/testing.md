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
| TPM attestation in kind | `make kind-e2e-tpm` | A SPIRE agent on the image's own configuration attests with a vTPM through the pinned plugin on both sides, the EK trust bundle refuses what it should, the node entry lands under that agent; the agent starts from the OpenBao PKI root alone and the server's bundle is that root (ADR-0031) | by hand, a Linux host with `sudo`, swtpm and the `tpm_vtpm_proxy` module (not GitHub's runners) |
| Live against a real cluster | `make live-admission-test` | The same, against a deployment you operate | by hand, before a release or after changing the deployment |
| Live proofs on the homelab | the claims below, by hand | The whole path on real hardware: TPM-attested pool members and gateway VMs, the broker on a real cluster, a workload in the jail reaching a real API through a gateway's Envoy with the credential the design says, and nothing else | by hand, recorded in [Live proofs on the homelab](#live-proofs-on-the-homelab-2026-11-08) |

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

`make kind-up` creates a one-node kind cluster (`dev/kind/cluster.yaml`), applies SPIRE
from `dev/kind/spire` (SPIRE's distribution, the same hardened charts and versions the
homelab runs, rendered once by `make kind-spire-render` into tracked manifests from
`dev/kind/spire/values.yaml`, release name `spire` in namespace `spire-server` so the
controller manager's class is `spire-server-spire`; no Helm release, kustomize only)
together with the TPM node attestor component `deploy/spire-tpm` (ADR-0018), whose
loading `make kind-spire` asserts from the server's log, applies the broker's
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
| `make kind-e2e-policy` | 0026 | notaio installed from its release manifests and signing with the kind OpenBao, its bundle admitted by the broker and recorded on each claim, the `PolicyConformant` verdicts and codes on four sandboxes, a newer bundle followed, the earlier one delivered again refused by the version floor before and after a broker restart, nothing refused on the bundle's account, below |
| `make kind-e2e-gateway` | 0028 | the real egress proxy tunnelling a claim's requests through a real Envoy on the gateway SVID to its one destination and nothing else, the authorizer's cache through a broker outage, the cut-off on release, below |
| `make kind-e2e-gateway-policy` | 0030 | the gateway tier under a notaio bundle: a direct egress entry refused under `policy.egress: shadow` and opened at the real Envoy under `enforce`, an entry with rules never served, below |
| `make kind-e2e-tpm` | 0018 | an agent attesting with a vTPM behind the kind node through the `tpm` plugin, on `image/spire/agent.conf`, refused under a CA that never signed its EK and listed under the EK's hash under the right one, the member's certificate becoming the node entry under that agent, the guest registering over the SVID it issues and only then announcing `GuestReady` (ADR-0019), a fresh pod re-attesting as the same agent; since ADR-0031 the agent's bundle is the OpenBao PKI root alone and the server's `bundle show` is asserted to be that root and nothing self-signed of its own; not part of `make kind-e2e` and not in CI (it needs `sudo`, swtpm and the kernel's vtpm proxy on the host), below |

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

### The jail's ruleset: by hand, on the build host

The guest's nftables ruleset ([ADR-0020](../adr/0020-jail-network-nftables-keyed-by-sandbox-uid.md))
is rendered as text and pinned by unit tests in `crates/mediatore-guest/src/net.rs`.
Whether the installed `nft` accepts that text is a different question, and `nft -c` asks
the kernel even to check (it opens netlink, which wants `CAP_NET_ADMIN`), so that check
is an ignored test that takes the command from the environment and fails rather than
skips without it:

```sh
MEDIATORE_NFT='sudo /usr/sbin/nft' cargo test -p mediatore-guest net:: -- --include-ignored
```

Run it on the build host whenever `net.rs` changes; it hands `nft -c` both shapes, the
direct one and the gateway one ([ADR-0028](../adr/0028-egress-gateway-envoy-with-spiffe-identity.md)
decision 6: the relay, the gateways and the proxy by address, no DNS). The gateway host's
own table (`image/gateway/nftables.conf.in`, [ADR-0027](../adr/0027-control-plane-relay-on-the-egress-gateway.md)
decision 5) is checked the same way, rendered from the examples:

```sh
./image/gateway/render image/gateway/nftables.conf.in /tmp/gw.conf image/gateway/env.example image/gateway/vm.env.example
sudo /usr/sbin/nft -c -f /tmp/gw.conf
```

The pool VM's own host table ([ADR-0029](../adr/0029-the-pull-on-a-routeless-segment-and-the-pool-vms-root-rules.md)
decision 3, `image/host-table`) is pinned on any host by `make host-table-test` (the exact
render from a pool's files, names and missing inputs refused; a step of the image check in
CI) and checked by `nft -c` the same way on the build host, rendered from any four files of
the shapes the script documents:

```sh
make host-table-test
./image/host-table --render gateways registries env agent.conf | sudo /usr/sbin/nft -c -f -
```

The kind tiers run the guest with `--dev-skip-setup` and load no ruleset; the live proof is
a libvirt member (roadmap 06).

### The jail's confinement: by hand, on the build host

What the workload may touch under Landlock ([ADR-0024](../adr/0024-landlock-inside-the-jail.md))
is a plan pinned by unit tests in `crates/mediatore-guest/src/confine.rs` and `jail.rs` on
every platform. Whether the kernel enforces it is the question an ignored test answers by
running the real `mediatore jail-exec` around a probe: a write inside a granted directory
succeeds and one outside fails, a TCP connect to a granted port succeeds and to another
fails, a bind fails, and a run with no port is refused with exit 125. It needs Linux with
Landlock (6.7 or later for the ports; Debian 13 is 6.12) and `python3`, and it fails
rather than skips anywhere else:

```sh
cargo test -p mediatore --test jail_exec_live -- --include-ignored
```

Run it on the build host whenever `confine.rs` or `jail.rs` changes. The kind tiers run the
guest with `--dev-skip-setup` and start no jail.

### The egress proxy: in `make check`

The proxy of [ADR-0025](../adr/0025-phantom-token-egress-proxy.md) is proven front to
back in `make check`, with no socket and no jail: `crates/mediatore/tests/e2e_egress.rs`
runs the fake issuer, the dev-mode broker, a TLS upstream from the test kit
(`mediatore_testkit::TlsUpstream`, a fresh CA per test) that records what reaches it, and
the real `Proxy` in between, with a token source that is a client of the dev header path
(the Workload API is the one thing faked). It drives the proxy as the jailed workload
would: plain HTTP on loopback, the host as the first path segment, the phantom in
`Authorization`. The upstream is on the test kit's own CA, which the audience names as its
`ca_file` and the route carries, so the proxy runs through its production constructor and
the private-PKI path is the one proven. The upstream receives an STS token it verifies
against the broker's JWKS in place of the phantom; a second request reuses it (one fetch
for two calls); a request with no header is forwarded bare; a foreign bearer is `401`, a
request outside the audience's rules `403`, a host outside the routes `404`, none of them
reaching the upstream; a released claim gets `502`, not a bare forward; and the same
upstream with the CA stripped from the route is `502` with nothing reaching it, since the
Mozilla roots did not sign it. The policy itself (`judge`, the
route lookup, the rule glob) is unit-tested in `crates/mediatore-guest/src/egress.rs` and
`crates/mediatore-proto/src/lib.rs`, and the ruleset's two new lines in `net.rs`.

### The gateway's authorizer: in `make check`

The authorizer of [ADR-0028](../adr/0028-egress-gateway-envoy-with-spiffe-identity.md)
decision 4, `mediatore gateway`, is proven against the broker in `make check`, with no
Envoy and no VM: `crates/mediatore/tests/e2e_gateway.rs` runs the fake issuer, the broker's
sandbox listener over the production mTLS listener under the testkit's `TestCa`, the real
`Authorizer` with its broker client presenting the gateway SVID from that CA, and the check
service Envoy would call, on loopback. A stand-in for Envoy sends Envoy's own `Check` call
over gRPC with what Envoy fills in from the downstream connection (the peer's SPIFFE ID as
the principal, the method, the authority). What is proven: a bound claim reaches each
`host:port` of its audiences' egress and nothing else; a foreign method, a malformed
authority, the node that holds the claim, a check with no principal and a claim the broker
never saw are refused with their codes; a released claim still answers from the cache
within the fresh bound and is cut off by the broker's `404` after it; an authorizer whose
broker is down denies from the first check; one presenting a node SVID is refused by the
route and denies; one presenting an identity under the gateway path cannot complete the
handshake and denies. The cache's own bounds (fresh, stale, the claim's deadline, the size,
one ask per claim at a time) are unit tests in `crates/mediatore-gateway/src/lib.rs` over
a scripted source.

### The forwarder: in `make check`

The sandbox leg of [ADR-0028](../adr/0028-egress-gateway-envoy-with-spiffe-identity.md)
decisions 3 and 7, the dialer inside the egress proxy that
[ADR-0027](../adr/0027-control-plane-relay-on-the-egress-gateway.md) decision 8 made of
`mediatore forward`, is proven with no Envoy in `crates/mediatore/tests/e2e_forward.rs`:
the dev-mode broker with `gateways` in its config, the same TLS upstream as the proxy's
suite, and `mediatore_testkit::StandInGateway`, a mutual-TLS listener on the production
sandbox-leg configuration (`TlsConfigs`) presenting whatever SVID the test gives it from
the testkit CA, admitting claim identities only, answering `CONNECT` from a fixed allowlist
and relaying the tunnel. The proxy is built through its production constructor with the
routes and the gateways from `GET /v1/me` and a forwarder presenting the claim SVID. What
is proven: six requests reach the upstream with the STS token through a list whose first
gateway is down and whose second presents a valid SVID that is not the gateway's, every
tunnel recorded at the live gateway from the claim's SPIFFE ID to the upstream's
`host:port` and none at the rogue; a gateway refusing the tunnel is `502 gateway_refused`
with nothing reaching the upstream and no second gateway asked; two dead gateways are
`502 gateway_unreachable`; a forwarder holding the node's SVID gets no tunnel from a live
gateway while the claim's does. The walk itself (the start position, the wrap-around,
failover on a failure and not on a refusal, the one pass, the `CONNECT` line and the
answer's parsing) is unit-tested over a scripted attempt in
`crates/mediatore-guest/src/forward.rs`.

### The egress gateway: in `make kind-e2e`

`make kind-e2e-gateway` runs ADR-0028's data plane against a real Envoy and a real SPIRE:
`dev/kind/gateway` is a pod standing in for a gateway VM, Envoy from its official image
(pinned by digest, the digest the gateway image copies the binary from) on the bootstrap
the image carries (`image/gateway/envoy/gateway.yaml.in` rendered with
`dev/kind/gateway/envoy.env`; `make gateway-render-check` fails on drift and runs before
the tier) beside `mediatore gateway`, both
holding `spiffe://<td>/gateway` from the agent through the CSI volume, and a destination
behind it (the testkit's `gateway-probe` in its serve mode, over TLS on a certificate
`make kind-gateway` mints with `tls-fixture`, since the proxy speaks HTTPS to every
upstream). `dev/kind/gateway-e2e.sh` binds a sandbox as the sandbox tier does, so the
broker has a live claim whose allowlist is that one destination, then runs pods shaped
like a sandbox VM: the real `mediatore egress-proxy` as a native sidecar with the claim's
SVID through a fixture entry, the routes (the destination with the fixture CA as the
audience's, and two more the gateway will refuse), the gateway list and a phantom from a
ConfigMap, and beside it a workload with no socket and no route of its own,
`gateway-probe via-proxy`, asking the proxy as the jail does. Proven, as the workload sees
it: its request reaches the destination through the proxy's tunnel with the STS token
swapped in (`200`, the proxy's log naming the gateway and the credential), another host
and another port are `502 gateway_refused` with `not_allowed` in the proxy's log, a proxy
holding a node SVID is refused by Envoy's validator at the handshake and the workload sees
`502 gateway_unreachable`, with the broker scaled to zero the cached allowlist stands in
until the stale bound and then the outage is a refusal with `broker_unreachable`, a
deleted sandbox is cut off with `claim_gone` once its answer is stale, and Envoy's access
log, the authorizer's decisions, the proxy's forwards and the destination's requests agree
on who reached what. The checks are listed in the script; a mismatch names the authority,
the status and what was expected.

`make kind-e2e-gateway-policy` is the same run under a policy (ADR-0030): notaio (from
`make kind-notaio`) publishes the bundle of a policy whose direct `egress[]` names the
destination's second port and a host with rules, the broker's configuration gains a `policy`
section trusting notaio's key with `egress: shadow`, and the sandbox names the policy. Under
shadow the second port is refused at the gateway as in the plain run, the broker logs what
enforce would add and the sandbox reports P006; the script then switches the broker to
`enforce`, waits for P007 (the host with rules, never served) in place of P006, and a probe
reaches the second port through a tunnel the authorizer allowed from the broker's answer,
while the host with rules, another host and the audience endpoint behave as before. The
broker's configuration is restored to the overlay's at the end, for the tiers after it.

### The sandbox filesystem and the pull: by hand, on the build host

The tmpfs the guest mounts per claim and the image pull
([ADR-0021](../adr/0021-sandbox-filesystem-tmpfs-and-rootfs-from-the-registry.md)) are unit-tested
as far as a test can go without root or the network: the mount arguments and the layout
are pinned, and the pull runs against a fake registry in `mediatore-testkit`
(`crates/mediatore-testkit/src/registry.rs`), layers built in the test, hostile ones
included. Two ignored tests go the rest of the way and fail rather than skip without
their variable: the tmpfs mounted for real and its options read back from the kernel,
and an image pulled from a real registry:

```sh
MEDIATORE_SUDO=sudo cargo test -p mediatore-guest sandboxfs:: -- --include-ignored
MEDIATORE_PULL_IMAGE=docker.io/library/busybox:1.37 cargo test -p mediatore-guest image:: -- --include-ignored
```

Run them on the build host whenever `sandboxfs.rs` or `image.rs` changes.

### The VM images: built and checked in CI, booted by the live runs

The sandbox VM image ([ADR-0023](../adr/0023-sandbox-vm-image-kairos-derivative.md)) is a
Kairos derivative that CI builds on every pull request and checks with `image/check.sh`:
the binaries at the paths the units and `agent.conf` name, the plugin's checksum, the
packages, the `spire` user, the three units enabled, the host table script rendering
from a pool's files and refusing a name with the agent and the guest requiring its unit
(ADR-0029), the sysctl that raises Yama's `ptrace_scope`, no `sshd` and no other listener,
the distribution's `nftables` unit masked, no private key. The same on the build host:

```sh
make dist && make guest-image BINARY_FROM=host CONTAINER_CLI=podman && make guest-image-check CONTAINER_CLI=podman
```

The egress gateway image ([ADR-0028](../adr/0028-egress-gateway-envoy-with-spiffe-identity.md)
decision 10, `image/gateway/`) is built and checked the same way, `image/gateway/check.sh`:
Envoy at the pinned version and running, the authorizer, the agent and the plugin, the
render script and the templates, the example env files filling every template and both
rendered bootstraps accepted by `envoy --mode validate`, no admin block, the relay's
bootstrap with no TLS and no SDS, the three service users none of them in the TPM group,
the six units enabled and pointing where the image put things, the agent's unit the
gateway's own (requiring the gateway's host table, never the pool's, which a gateway does
not have), the sandbox interface rendered as a `10-` networkd file that sorts before the
base's DHCP catch-all, both Envoys unprivileged with no capability and a read-only root,
the relay kept out of `/run/spire`, both requiring the table and the interface first,
forwarding off, the table default-drop with the per-source cap, no `sshd`, the
distribution's `nftables` unit masked, no private key. The last two unit checks are what
the first gateway boot found missing (2026-11-05).

```sh
make dist && make gateway-image BINARY_FROM=host CONTAINER_CLI=podman && make gateway-image-check CONTAINER_CLI=podman
```

Nothing here boots either image: the install, the sealed partition, the EK export and a
claim on a real member, and the three gateways with a pool VM behind them, are roadmap
06's live item, run by hand on 2026-10-31 (the sandbox image) and 2026-11-05 (both, behind
the gateways). Each run found defects the checks had not, and each defect became a check
(threat model R-15).

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

What kind cannot do, and the real-cluster tier covers: real VMs and jails, banlieue's
claim controller binding a real member, the guest reading the EK from its own TPM
(`tpm2-tools` are the VM image's, not the broker image's), and the broker's
`LoadBalancer` exposure. TPM node attestation itself it can do, below. In every other
tier the parent agent `spiffe://<td>/spire/agent/tpm/<ek>` never exists: the server
accepts entries for a parent that has not attested, which is exactly the order a node
entry is declared in.

### notaio's bundles in shadow

`make kind-e2e-policy` (`dev/kind/policy-e2e.sh`) is ADR-0026 end to end. `make kind-notaio`
(`dev/kind/notaio-install.sh`) first installs notaio the way its install guide says an
operator should: the CRDs and the controller manifests of the pinned release, downloaded
from GitHub and checked against the SHA-256 values the Makefile pins (from the release's
own `checksums.sha256`, which is sigstore-signed; verify it with `cosign verify-blob` by
hand after a bump), the image pinned by digest inside, the two site-specific edits
applied (where OpenBao is, for the controller and its NetworkPolicy), and the signer set
up in the kind OpenBao as notaio's own setup does: a non-exportable Ed25519 transit key,
a policy that allows signing with it and nothing else, a Kubernetes auth role for
notaio's ServiceAccount. The public key comes out of OpenBao as `notaio:v1` and goes into
the broker's `policy` section for the run; the overlay's configuration is restored after.

The tier then applies notaio's bundle Role and the broker's read Role
(`deploy/policy-bundles`) in the e2e namespace, a `SandboxPolicy` with its
`ExposureCeiling` (notaio's example, the `internal-git` audience the kind configuration
mirrors exactly), waits for the signed bundle ConfigMap, and checks the broker admitted
it. Four sandboxes are created as the broker ServiceAccount: one conformant (`True`),
one asking for an audience the bundle does not list (`False`, `P001`), one without a
`policyRef` (`P010`), one naming a policy with no bundle (`P011`); each gets its claim
and stays `Pending`, which is the point of shadow mode. The policy is then changed, the
newer bundle is admitted and every verdict names it; the earlier envelope is delivered
again under another ConfigMap name and refused as a downgrade, its deletion leaves the
cache alone, and after a broker restart on the kind PostgreSQL the same replay is refused
again, because the floor came back from the store.

### TPM attestation with a vTPM behind the node

`make kind-e2e-tpm` (`dev/kind/tpm-e2e.sh`) runs the attestation path a pool VM takes
([ADR-0018](../adr/0018-tpm-attestation-with-the-spiffe-plugin.md)), with a vTPM in
place of libvirt's, and since
[ADR-0031](../adr/0031-a-trust-anchor-that-outlives-the-servers-ca.md) with the trust
bundle a layer would carry: the OpenBao PKI root `make kind-openbao` read from the `spire`
mount (`.kind/openbao/upstream-root.pem`), not the server's `bundle show`, which the
script asserts to be that root and nothing else before the agent starts. Every kind tier
runs the server under that upstream authority (`make kind-spire` depends on
`make kind-openbao` for it and copies OpenBao's CA into the server's namespace first). `make kind-vtpm` (`dev/kind/vtpm.sh`) starts swtpm behind the
kernel's vtpm proxy (`tpm_vtpm_proxy`), which makes it a character device on the host,
`/dev/tpmrmN`; the EK certificate is signed by a throwaway swtpm local CA the script
creates under `.kind/vtpm`, the way `swtpm_setup` does on a hypervisor, never the host's
own CA. `make kind-create` mounts that device into the node as `/dev/tpmrm0`, so the
vTPM must be up before the cluster exists (`make kind-delete` first; the target refuses
a node without the device). A rerun starts from `make kind-delete` too: the server keeps
the agent a previous run attested, and the first refusal step would find it listed. The server runs `deploy/spire-tpm` as in every tier. A
Deployment then plays the pool member: an init container copies the agent plugin out of
its pinned image, the SPIRE agent runs `image/spire/agent.conf` with its two placeholders
replaced and the trust bundle `spire-server bundle show` exported (the command the
deploying guide gives for the VM image), privileged for the device, and beside it the
guest runs as root on the pinned binary path, over the agent's socket, in the pod's one
PID namespace (the `unix` workload attestor reads its `/proc` entry, as on a VM):

| Step | Expected |
| --- | --- |
| ConfigMap `spire-tpm-ek-cas` replaced with a CA that never signed this EK, the server restarted, the agent started | the agent is refused (`could not verify cert`); `spire-server agent list` has no `tpm` agent |
| the ConfigMap replaced with the vTPM's local CA (its issuing certificate), the server restarted, the agent started again | `Node attestation was successful`; the server lists exactly one `tpm` agent, `spiffe://<td>/spire/agent/tpm/<hash>`, where the hash is what `vtpm.sh` computed from the EK certificate (sha256 of the DER `SubjectPublicKeyInfo`): the plugin's hash and mediatore's agree |
| `VirtualMachine` `member-1` patched with both EK certificates, as a vTPM carries them | `ClusterStaticEntry` `mediatore-node-<hash>` with `parentID` the attested agent; the guest logs `SVID from the Workload API` for `spiffe://<td>/banlieue/node/<hash>` and `node registered`: the entry reached the agent that attested |
| the same guest log, read for order (ADR-0019) | `GuestReady announced` with `file=announced` appears after `node registered`, never before: the pool hears a member only once it is attested and registered. In the pod the marker file is the one channel (a tmpfs at `/run/banlieue`, as a VM's `/run` is; without it the guest logs the write failing on the read-only root and stays out of the pool, which is decision 5 observed); the unit tests in `crates/mediatore-guest/src/ready.rs` pin the three payloads |
| the Deployment restarted (a new pod, empty agent state: a VM that lost its disk) | the new agent re-attests as the same ID (the plugin answers `CanReattest`), the server still lists one `tpm` agent, the new guest registers again and announces again, no clone reported |

What it found the first time it ran: the certificate that signs a vTPM's EK is the local
CA's issuing certificate (`issuercert.pem`, `CN=swtpm-localca`), not the root
(`swtpm-localca-rootca-cert.pem`), and the plugin verifies the EK against the files in
`ca_path` as trust anchors with no intermediates, so a bundle holding the root alone
refuses every VM. The deploying guide and `deploy/spire-tpm/ek-cas.yaml` collect
`issuercert.pem`.

The tier is not in `make kind-e2e` and not in CI: it needs `sudo`, `swtpm`,
`swtpm_setup` and the `tpm_vtpm_proxy` module on the host. A laptop with Docker Desktop
has none of that, and the Azure kernels of GitHub-hosted runners do not ship the module
(not even in `linux-modules-extra`, checked 2026-10-24). Debian's and Ubuntu's generic
kernels have it; the build host runs it by hand before a change to the attestation path
merges (`make kind-e2e-ci KIND_E2E_SUITES=kind-e2e-tpm` is the CI shape, cluster deleted
after). `make kind-vtpm` says so and stops when the module is missing.

Pins live at the top of the `Makefile`: kind, the node image by digest (same
Kubernetes minor as the homelab), the versions of SPIRE's distribution, the placeholder
trust domain `sandbox.test`. Dependabot does not see them; bump them when the homelab
moves, and after a SPIRE bump run `make kind-spire-render` and read the diff of
`dev/kind/spire`: the rendered manifests are what the tier applies, never edited by
hand, the `server.conf` patch generated from the component's fragment.

Runtimes: kind needs Docker or rootless Podman (`KIND_EXPERIMENTAL_PROVIDER=podman`
and `CONTAINER_CLI=podman` for the image builds) and `kubectl` (`helm` and `jq` only
for `make kind-spire-render`, which CI never runs); the images need
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

## Live proofs on the homelab, 2026-11-08

What the tiers above cannot show is the whole path on real hardware: a pool member
attested by its TPM, gateway VMs holding their own SPIFFE identity, the broker on a real
cluster behind a real policy bundle, and a workload in the jail reaching a real API. These
runs were made by hand on the maintainer's homelab on 2026-11-08 and are recorded here
with the lines each component printed, so the proof is in the repository and not only in a
terminal. Every name and address below is a placeholder for the real one (`rules/no-real-infrastructure.md`);
the run log with the real values lives outside the repository. Hashes, claim UIDs, digests
and request ids are as printed.

The environment, for all four runs: one cluster (banlieue v0.5.0, then v0.5.1 the same
evening; SPIRE 1.15.3 under the OpenBao upstream authority of ADR-0031), the broker
`mediatore` in `banlieue-system` from the homelab overlay, three gateway VMs
`gateway-01..03` on the hypervisor (ADR-0028, each attested through its own TPM), a pool `sandbox-pool` of one warm member on a routeless segment
(ADR-0029), the workload images from a pull-through mirror on that segment
(`registry.internal:5000`: `linuxcontainers/alpine`, the curl project's image, and since
the evening the example `ghcr.io/firestoned/research-agent` from `examples/research-agent`,
`make example-image`), notaio v0.5.1 publishing the bundles of two policies from the
`sandboxes` namespace (`proof-agent`, `research-agent`, each with a ceiling signed by
Security and admitted by Flux), and the CLI on the operator's machine. Every claim below
is `mediatore sandbox create --pool sandbox-pool --audience <a> --policy <p> --image <i>
--arg sh --arg=-c --arg <loop>`, after a `mediatore login` (the refresh token is spent per
claim, ADR-0013).

### 1. The 200 with the broker-minted bearer through a gateway (ADR-0028, roadmap 06)

v0.2.0-rc.6 end to end, 16:43 to 17:46 UTC; the open item of banlieue ADR-0109 (an allowed
request completing through a gateway's Envoy with a 200). Policy `proof-agent`: one
audience `proof.lab.home.example` (Read, `GET /v1/**`, `ttlSeconds` 480, endpoint
`proof.lab.home.example:443`), a TLS service on the hypervisor on the homelab's private PKI
(`audiences[].ca_file` on the broker, ADR-0025 decision 7) that answers `/v1/hello` with
`bearer=present` or `bearer=absent` according to the `Authorization` it received. The
workload is `linuxcontainers/alpine` (busybox, so `wget -S`), probing four URLs every 20 s.

Claim `sandbox-923281d0` (claim uid `0ce7577f…`), bound in under a
second, `PolicyConformant=True` ("the broker allows nothing bundle v1 of proof-agent does
not"). What each component printed, in order:

```
broker    token issued claim_uid=0ce7577f… audience=proof.lab.home.example subject=octocat
proxy     forwarded audience="proof.lab.home.example" host=proof.lab.home.example:443 method=GET path=/v1/hello status=200 OK credential=true via=192.0.2.13:8443
gateway-03 authorizer   verdict="allow" served="broker" authority=proof.lab.home.example:443
gateway-01 authorizer   verdict="allow" served="cache"  authority=proof.lab.home.example:443   (the next round, another gateway, the cached answer)
envoy     tunnel peer=spiffe://<td>/banlieue/claim/0ce7577f… method=CONNECT authority=proof.lab.home.example:443 status=200 upstream=192.0.2.1:443
workload  PROOF allowed proof.lab HTTP/1.1 200 OK bearer=present
workload  PROOF bare proof.lab    HTTP/1.1 200 OK bearer=absent
workload  PROOF denied outside-rules HTTP/1.1 403 Forbidden
workload  PROOF denied other-host    HTTP/1.1 404 Not Found
```

Read together: the broker minted one STS token for the claim's audience; the proxy
swapped the jail's phantom for it and tunnelled through a gateway, a different one each
round (the forwarder's random start, ADR-0028 decision 7); the authorizer allowed the
tunnel on the claim SVID from the broker's answer and then from its cache; Envoy carried
the CONNECT and logged the 200; the service saw the bearer. The bare probe beside it (no
`Authorization`) reached the same service with no credential, as ADR-0025 decision 3
says; `/admin` was refused at the proxy by the audience's rules; `api.github.com`, not on
this claim, had no route. Released at 17:46:29: `claim released: entry retracted, tokens cut
off`, the claim's entry gone from the SPIRE server, the member destroyed and the pool warm
again within the minute.

Two earlier claims the same afternoon are part of the record. `sandbox-ba355c5a` surfaced
`P002 max_ttl 900 above the bundle's ttlSeconds 480` (the broker's default against the
policy's value; the overlay now says `max_ttl: 480`) and an image without curl.
`sandbox-eb7a47fa` probed without `Authorization` and got `bearer=absent` on every round,
which is the design: the swap needs the phantom. The day also cost a hypervisor reboot
that crash-looped the SPIRE servers' TPM init container (`mkdir` over a surviving
emptyDir; fixed by PR #82 and proven with `make kind-e2e-tpm`), and a ceiling signed with
the wrong key, which Flux refused until re-signed.

### 2. A policy's direct egress at the real Envoy, in kind (ADR-0030, roadmap 11)

Not the homelab but the same day and the same Envoy: `make kind-e2e-gateway-policy` on the
build host, twice green (the second run with the credential-less route of the next
section). Under `shadow` the destination's second port is `403 not_allowed` at the gateway,
the broker logs `policy.egress is shadow: direct egress not served … would_add=<the second
port>` and the sandbox reports `P006 the bundle holds 2 direct egress entries the broker
cannot provide`; after the switch to `enforce` and a restart, the tunnel to the second port
opens (Envoy `status=200`, the authorizer's `allow` with `served=broker`, the destination's
request line on that port, the proxy's forward `credential=false` on the credential-less
route), the host with rules stays `not_allowed` and is `P007 … has_rules`, the audience
endpoint and the other host behave as before. Both PASS lines, exit 0, in about thirty
minutes including the cluster.

### 3. `policy.egress: enforce` on the homelab broker (ADR-0030 rollout step one)

22:04 UTC. A week of shadow with no `would_add` line in the broker's log (neither policy
names direct egress), then `egress: enforce` in the overlay, `kubectl apply -k` and a
restart. The broker started on the value (a malformed one refuses the start), `store:
migrated and connected`, `policy bundle reflector running namespaces=["sandboxes"]`,
`policy bundle admitted … policy=proof-agent version=1` and `… policy=research-agent
version=4`, the user API's `/healthz` 200. rc.6 logs no mode line; PR #87 adds one
(`policy.egress … mode=enforce`) for the next release, and the kind tier now waits on it.

### 4. The credential-less route live: GitHub reached bare (ADR-0025 decision 8, roadmap 07)

v0.2.0-rc.7 (the broker upgraded 23:04 UTC by the overlay procedure, store backed up
first; the pool image rebuilt from rc.7 and the pool recycled onto it; the gateways kept
their rc.6 image, nothing in rc.7 touches them). Policy `research-agent`: one audience
`github` (`GET /repos/firestoned/**`, `PUT /repos/firestoned/*/contents/**`, `ttlSeconds`
480, endpoint `api.github.com:443`), declared `via: none` on the broker.

Claim `sandbox-da419aec` (claim uid `9784c3d6…`, the alpine image), bound
in one second, `PolicyConformant=True` ("the broker allows nothing bundle v4 of
research-agent does not"):

```
guest     subject fetched claim_uid=9784c3d6… subject=octocat egress=1 routes=1 gateways=3
guest     egress proxy ready … routes=1 gateways=3 gateways_from=Broker
proxy     forwarded audience="github" host=api.github.com:443 method=GET path=/repos/firestoned/mediatore status=200 OK credential=false via=192.0.2.11:8443
workload  PROOF allowed github phantom HTTP/1.1 200 OK
proxy     forwarded audience="github" host=api.github.com:443 method=GET path=/repos/firestoned/mediatore status=200 OK credential=false via=192.0.2.11:8443
workload  PROOF allowed github bare    HTTP/1.1 200 OK
proxy     request refused method=GET path=/api.github.com/user status=403 Forbidden code="outside_rules"
workload  PROOF denied outside-rules   HTTP/1.1 403 Forbidden
proxy     request refused method=GET path=/proof.lab.home.example/v1/hello status=404 Not Found code="no_route"
workload  PROOF denied other-host      HTTP/1.1 404 Not Found
gateway-01 envoy  tunnel peer=spiffe://<td>/banlieue/claim/9784c3d6… method=CONNECT authority=api.github.com:443 status=200 upstream=<github>:443 rx=1685 tx=11966
broker    (no POST /v1/token at all during the claim)
```

The request carrying the phantom and the request carrying nothing both left the gateway
bare (`credential=false`), GitHub answered 200 with the repository, the broker was never
asked for a token, the rules and the route set still refused around it. Released clean.

Then the same with curl, as a reader would type it. Claim `sandbox-aa923665` (claim uid
`6455eb5c…`), the curl project's own image from GHCR through the mirror,
and inside the jail:

```sh
curl -sS -D - -H "Authorization: Bearer $MEDIATORE_TOKEN" \
  "$MEDIATORE_EGRESS_PROXY/api.github.com/repos/firestoned/mediatore"
```

```
curl 8.23.1-DEV (x86_64-pc-linux-musl) libcurl/8.23.1-DEV OpenSSL/3.5.9 …
proxy=http://127.0.0.1:3128
PROOF curl api.github.com/repos/firestoned/mediatore: HTTP 200 0.352937s
PROOF curl api.github.com/user (outside the rules): HTTP 403 0.000842s "error":"outside_rules"
PROOF curl github.com/firestoned (host not on the policy): HTTP 404 0.000948s "error":"no_route"
RAW response headers from GitHub through the proxy:
HTTP/1.1 200 OK
server: github.com
x-ratelimit-limit: 60
x-ratelimit-remaining: 58
x-github-request-id: <request id>
```

with the proxy's `forwarded … status=200 OK credential=false via=192.0.2.12:8443` for each
200. GitHub's `x-ratelimit-limit: 60` is its unauthenticated bucket, an independent
confirmation that the request arrived bare. `github.com` itself is not on the policy, only
`api.github.com:443` is, so the 404 is the policy's.

### 5. Claude from inside the sandbox (ADR-0032, roadmap 04)

v0.2.0-rc.8 on the broker and the pool image (2026-11-09, 00:47 UTC; the store backed up
first, the pool recycled onto the new ISO, the member registered in three minutes). The
operator's Anthropic key in a Secret mounted into the broker, the audience `anthropic`
declared `via: secret` with the key placed in `x-api-key` and `anthropic-version` beside
it, rules `POST /v1/messages` and its token count only; the start-up log reads
`audience served from an operator-held credential (ADR-0032) audience=anthropic
header=x-api-key`. The policy `claude-agent` names that one audience. The workload is the
curl image again; the jail's environment carries the phantom, which it sends as
`ANTHROPIC_API_KEY` would be sent, in `x-api-key`.

Claim `sandbox-9cc8274d`, bound in one second:

```
broker    token issued claim_uid=… audience=anthropic subject=octocat backend="secret" header=x-api-key
proxy     token fetched for the proxy audience="anthropic" expires_at=<now + 900 s> header="x-api-key"
proxy     forwarded audience="anthropic" host=api.anthropic.com:443 method=POST path=/v1/messages status=200 OK credential=true via=192.0.2.13:8443
gateway-03 envoy  tunnel peer=spiffe://<td>/banlieue/claim/… method=CONNECT authority=api.anthropic.com:443 status=200
workload  PROOF claude POST /v1/messages: HTTP 200 1.386741s "model":"claude-opus-5-5" "stop_reason":"end_turn" "output_tokens":20
workload  CLAUDE SAYS: Hello, Erick, the capital of France is Paris!
proxy     request refused method=GET path=/api.anthropic.com/v1/models status=403 Forbidden code="outside_rules"
workload  PROOF claude GET /v1/models (outside the rules): HTTP 403 "error":"outside_rules"
proxy     request refused method=POST path=/api.anthropic.com/v1/messages status=401 Unauthorized code="unknown_credential"
workload  PROOF claude with an image key (owned header): HTTP 401 "error":"unknown_credential"
```

The key never entered the jail: the workload sent the phantom, the proxy fetched the key
from the broker once (expiry `max_ttl`) and placed it as the request left through a
gateway, Anthropic answered `end_turn` with twenty output tokens, and the body carried the
sentence. The GET outside the rules was refused before anything was fetched or forwarded;
a key baked into the image, sent in the header the proxy owns, was refused on arrival.

Two earlier claims the same half hour are part of the record. The first carried a prompt
describing the sandbox and the proxy, and came back `200` with `claude-opus-5-5`, zero
output tokens and no text block: the shape of a zero-token refusal, the plumbing proven
(the broker's issue, the proxy's `credential=true`, Envoy's tunnel with six kilobytes back)
and nothing to quote. The second met a gateway whose Envoy answered `503 DNS resolution
failure` for the name that instant, which the forwarder takes as final (`502
gateway_refused`, ADR-0028 decision 7); a minute later every gateway resolved it. Decision
7 was amended the same day: a gateway's own `5xx` now moves the forwarder to the next
gateway, a `4xx` stays the verdict (`e2e_forward.rs`).

Then the example image, `ghcr.io/firestoned/research-agent`, through the Anthropic SDK
rather than curl: `/usr/local/bin/python3 /usr/local/bin/research-agent --hello`, the SDK
reading `ANTHROPIC_BASE_URL` (the proxy, then `api.anthropic.com`) and `ANTHROPIC_API_KEY`
(the phantom) from the environment the agent sets. Claim `sandbox-92a50de6`:

```
broker    token issued claim_uid=… audience=anthropic backend="secret" header=x-api-key
proxy     forwarded audience="anthropic" host=api.anthropic.com:443 method=POST path=/v1/messages status=200 OK credential=true via=192.0.2.11:8443
gateway-01 envoy  tunnel … method=CONNECT authority=api.anthropic.com:443 status=200 rx=2834 tx=5277 ms=4940
workload  PROOF claude model=claude-opus-5-5 stop=end_turn input_tokens=74 output_tokens=166
workload  CLAUDE SAYS: Hello, operator. I can't see my own runtime or network path, but in a setup like
          that I'd first verify that the egress gateway enforces a strict default-deny allowlist, so that
          injected credentials can only reach their intended destinations and can't be exfiltrated or
          misused elsewhere.
```

Two lessons from this run went into the guides. The jail sets no `PATH` and applies
nothing of the image's `ENTRYPOINT` or `ENV`, so a bare `research-agent` in
`workload.args` was exit `127` and the supervisor restarted it until the claim was
released; the interpreter and the program are named by absolute path. And a workload that
exited `0` before the deadline was restarted too, so a one-shot agent re-ran until the
claim was released by hand, as this one was after its first answer; that became
ADR-0033 the same day (`workload.restart`, the exit recorded and the claim released by the
broker), proven in `e2e_dev.rs` and awaiting its live run with the next release.

The `claude-agent` bundle reached the cluster afterwards (the ceiling signed by Security,
admitted by Flux, the bundle published by notaio and admitted by the broker at 01:31 UTC),
and one more curl claim, `sandbox-a9b83259` at 01:54, ran under it: `PolicyConformant=True`
("the broker allows nothing bundle v1 of claude-agent does not"), the proxy forwarding
`credential=true` through a gateway as before, the 403 and the 401 as before. Anthropic's
answer that time was `400 invalid_request_error: Your credit balance is too low to access
the Anthropic API`: the upstream's own refusal, on a key whose workspace had reached its
cap, which is the bound the guide asks the operator to set and the shape a spend limit
takes when it bites. The two answers above were given before it did.

### What is not proven live yet

The full agent reading a repository and asking Claude about it, which needs a policy
naming both the `github` and the `anthropic` audiences under a profile that allows two.
Recorded here when it has happened.
