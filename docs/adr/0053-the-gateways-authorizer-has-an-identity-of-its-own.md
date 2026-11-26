<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0053: The gateway's authorizer has an identity of its own

**Status:** Accepted, implemented 2026-11-19, released in v0.4.0 (amended at implementation, each amendment dated at
its decision; proven by the quality gate, the kind gateway tiers and the two image checks; nothing
is proven on a booted gateway VM yet, so decisions 2, 5 and 6 are built and not verified there:
*What was proven, and what was not*) · **Date:** 2026-11-19 · **Amended:** 2026-11-26 by
[ADR-0068](0068-the-cloud-platforms-host-addresses-root-alone-on-azure-the-metadata-service-for-nobody.md)
(decisions 5 and 6: ahead of every user's row the output chain drops IMDS for every user, root included,
and keeps Azure's WireServer to root at TCP 80 and 32526 and to `systemd-networkd`'s DHCP renewal, its
port 53 left to the rows), and 2026-11-26 at decisions 5 and 6 (open question 7 built: the tunnel check is the
authorizer's unix socket by default and the default table has no loopback exception)

Roadmap 10 (the gateway). Carries the separation of
[ADR-0040](0040-the-gateway-places-an-audiences-credential-the-pool-never-holds-it.md) decision 6
(the process that carries every tunnel never holds a credential) from the authorizer's sockets to
the broker and to the gateway's own host table. Amends
[ADR-0004](0004-spiffe-identity-scheme.md) (a sixth identity, and "nothing under it" no longer
holds for `/gateway`), [ADR-0007](0007-broker-identity-and-spiffe-mtls.md) decision 2 as
[ADR-0028](0028-egress-gateway-envoy-with-spiffe-identity.md) decision 4 amended it (who may
complete a handshake with the sandbox listener), ADR-0028 decisions 2, 4 and 8 (the entries, the
peer of the gateway-only route, the hardening), ADR-0040 decisions 2 and 3 (the peer of the
credential route, the identity column of the process table),
[ADR-0027](0027-control-plane-relay-on-the-egress-gateway.md) decision 5 (the gateway's host
table gains an output chain) and
[ADR-0006](0006-registration-entries-as-clusterstaticentry.md) decision 6 (a second admission
policy, for entries the broker does not declare). Changes no token shape, no storage contract and
no route's path or body. Implemented 2026-11-19; where the code differs from the text below, a
dated amendment at the decision says what the code does and why.

## Context

A gateway VM runs four processes, each a user of its own: the relay (`envoy-relay`, no identity,
ADR-0027), the tunnel Envoy (`envoy`, ADR-0028), the inject Envoy (`envoy-inject`, ADR-0040) and
the authorizer (`mediatore gateway`, user `mediatore-gateway`). ADR-0040 decision 3 divides them
so that "the one that carries every tunnel never holds a credential", and decision 6 enforces
that at the authorizer: two unix sockets, one per kind of Envoy, in directories of their own, so
the tunnel Envoy cannot ask an inject question.

That division was drawn at the authorizer and at nothing behind it. Three facts of the repository
as it stands:

- **One SPIFFE ID for three of the four processes.** `deploy/gateway/clusterstaticentries.yaml`
  gives `spiffe://<td>/gateway` to `unix:user:envoy` and to `unix:user:mediatore-gateway`, and
  ADR-0040 decision 3 adds a third entry of the same ID for `unix:user:envoy-inject`. The two
  Envoys need it as a server identity: the forwarder in every sandbox verifies exactly that ID
  (`Forwarder::new`, `crates/mediatore-guest/src/forward.rs`). The authorizer needs an identity
  as a client of the broker. Those are two different uses under one name.
- **The broker's two gateway routes ask only for that name.** `claim_egress`
  (`GET /v1/gateway/claims/{uid}`) and `gateway_credential`
  (`POST /v1/gateway/claims/{uid}/credential`) both test `Naming::is_gateway(peer)` and nothing
  else (`crates/mediatore-api/src/lib.rs`), and `sandbox_authorizer` admits the same ID at the
  handshake. So the broker cannot tell the authorizer from a listener. ADR-0040's consequences
  say as much for the VM as a whole ("it holds the gateway SVID"); the compartment between the
  processes on that VM is what this ADR is about.
- **The gateway's host table has no output chain.** `image/gateway/nftables.conf.in` filters
  input and forward. Which local user may open a connection to which address is not stated
  anywhere on the VM, so the broker's address is as reachable to an Envoy's user as to the
  authorizer's. The pool VM's table has had a default-drop output chain with an owner-matched rule
  since [ADR-0029](0029-the-pull-on-a-routeless-segment-and-the-pool-vms-root-rules.md)
  (`image/host-table`); the gateway's never gained one.

So the property the threat model states for the tunnel Envoy (a compartment with no path to a
credential, A-21, R-20, R-27 and the tunnel-Envoy row of TB-17) holds at the authorizer's sockets
and rests, at the broker, on the processes behaving. A compartment that one layer enforces and
the next assumes is not yet a control. The design intended it; this ADR makes the broker and the
kernel enforce it.

A second, related gap is in the same table. ADR-0028 decision 5 has the tunnel Envoy resolve the
`CONNECT` authority itself, and the authorizer admits by name
(`crates/mediatore-gateway/src/lib.rs`). Nothing constrains the address a name resolves to. The
threat model's answer (TB-14, "name resolution poisoned") is the TLS inside the tunnel, which
protects the credential and the workload's request but says nothing about which address the
gateway's own interface dials. The addresses a gateway must never dial on a sandbox's behalf are
known to it already: its own loopback, link-local, the sandbox segment, and the control-plane
upstreams in `/etc/mediatore-gateway/env`. An output chain keyed on the socket's owner states
both rules in one place.

Constraints that shape the decision:

- A SPIRE entry's selectors are a conjunction, so identities are per entry and per user
  (ADR-0028 implementation notes). A user with two entries is handed two SVIDs, and
  `WorkloadApiSource` (`crates/mediatore-tls/src/material.rs`) takes the source's default one.
- The gateway's entries are applied by the platform team, never by the broker (ADR-0028
  decision 2). The admission policy in `deploy/base/admission/clusterstaticentry-mediatore.yaml`
  binds the broker's ServiceAccount alone and admits two shapes, node and claim. Nothing in this
  repository pins the shape of a gateway entry today.
- The gateway is three VMs replaced one at a time, the broker is a Deployment, and the entries
  are a third party's objects. No change here can land on all three at one instant.

## Decision

1. **The authorizer's identity is `spiffe://<td>/gateway/authorizer`; the listeners keep
   `spiffe://<td>/gateway`.** The table of ADR-0004 gains a row:

   | ID | Held by | Created by |
   | --- | --- | --- |
   | `spiffe://<td>/gateway` | the gateway's two listeners, the tunnel Envoy and the inject Envoy, as their server identity | the platform team, `ClusterStaticEntry`, selector `unix:user:envoy` or `unix:user:envoy-inject` |
   | `spiffe://<td>/gateway/authorizer` | `mediatore gateway`, as its client identity to the broker | the platform team, `ClusterStaticEntry`, selector `unix:user:mediatore-gateway` |

   `Naming` (`crates/mediatore-spire/src/lib.rs`) gains `gateway_authorizer_id` and
   `is_gateway_authorizer`, exact matches like `gateway_id` and `is_gateway`: no prefix test
   exists anywhere, and none is added. `is_gateway` keeps refusing everything under `/gateway`,
   the authorizer's ID included, so the two predicates are disjoint by construction. The
   forwarder is untouched and keeps verifying exactly `spiffe://<td>/gateway`
   (`crates/mediatore-guest/src/forward.rs`): a process holding the authorizer's SVID cannot
   stand in for a listener, and a listener cannot stand in for the authorizer. The Envoy
   templates are untouched (`image/gateway/envoy/gateway.yaml.in`, `inject.yaml.in`: the SDS
   secret name stays the gateway ID). `deploy/gateway/clusterstaticentries.yaml` changes each
   VM's second entry: named `gateway-NN-authorizer`, the new ID, the same selector, `hint:
   gateway-authorizer`, and gains the third entry ADR-0040 describes for `unix:user:envoy-inject`
   so the file shows all three. The path sits under `/gateway` because the authorizer is a part
   of the gateway and the scheme's top-level names stay four; the sibling form is open
   question 1.

2. **The authorizer asks for its own SVID by ID and refuses to start on any other.**
   `WorkloadApiSource` gains a way to select the SVID for a stated SPIFFE ID
   (`crates/mediatore-tls/src/material.rs`), and `Broker::connect`
   (`crates/mediatore-gateway/src/broker.rs`) uses it for the path `/gateway/authorizer`: the
   default SVID is never taken. No such SVID within the existing bounded wait is a failed start,
   and a stopped authorizer is a `403` on every tunnel and every inject request
   (`failure_mode_allow: false`), which is the fail-closed shape the gateway already has. This is
   what makes a user that briefly holds two entries during a migration deterministic, and it
   keeps a mistaken entry from quietly giving the authorizer a listener's name. The dev header
   and `--dev-spiffe-id` (`crates/mediatore-gateway/src/serve.rs`) carry the new ID in the dev
   loop and the tests.

   *Amended 2026-11-19 at implementation: the selection is `WorkloadApiSource::connect_as`
   (`crates/mediatore-tls/src/material.rs`), asked for the path `AUTHORIZER_PATH`, and the
   check that the identity in hand is the authorizer's is `ensure_authorizer` (both in
   `crates/mediatore-gateway/src/broker.rs`), which the dev path in `serve.rs` runs too.*

3. **The broker's two gateway routes require the authorizer's ID exactly, and the plain gateway
   ID is no longer a peer of the broker at all.** In `crates/mediatore-api/src/lib.rs`:
   `claim_egress` and `gateway_credential` test `is_gateway_authorizer(peer)`; any other peer,
   `spiffe://<td>/gateway` included, is `403 forbidden` before the claim is looked up, so a
   refusal says nothing about whether a claim exists; and `sandbox_authorizer` admits node
   identities, claim identities and the authorizer's ID, and stops admitting the plain gateway
   ID, which then fails the handshake like any other stranger. Both layers are kept and both
   are tested: the handshake is the outer refusal, the route's own check is what holds under the
   dev header and if the listener's list is ever widened again. The checks after the guard, the
   audit line and the answers are those of ADR-0028 decision 4 and ADR-0040 decision 2,
   unchanged. A listener's identity is from now on a name the sandboxes verify and nothing the
   broker serves.

   *Amended 2026-11-19 at implementation: the guard is one function,
   `require_gateway_authorizer`, called first in `claim_egress` and in `gateway_credential`,
   and the listener's list is `sandbox_authorizer(naming, accept_plain_gateway_identity)`: the
   switch of decision 7 is an argument of both, so there is one place where the plain ID can
   be let in and it is the same for the handshake and the routes.*

4. **An admission policy pins the shape of a gateway entry, for whoever applies one.** The
   existing policy is not widened: its `spiffeID` rule anchors on `/banlieue/(node|claim)/`, so
   the broker's ServiceAccount cannot declare either gateway ID today, and a test pins that it
   still cannot. A second policy,
   `deploy/base/admission/clusterstaticentry-gateway.yaml` (CEL, no webhook, `failurePolicy:
   Fail`, in the base's kustomization), matches a `ClusterStaticEntry` from any principal whose
   `spiffeID` path is `/gateway` or begins with `/gateway/`, and admits two shapes and nothing
   wider:

   | `spiffeID` | selectors | everything else |
   | --- | --- | --- |
   | `spiffe://<td>/gateway` | exactly one, `unix:user:envoy` or `unix:user:envoy-inject` | `parentID` an attested agent ID of the same trust domain; no `admin`, `downstream`, `storeSVID`, `federatesWith` or `dnsNames`; `x509SVIDTTL` at most `4h`; `className` set |
   | `spiffe://<td>/gateway/authorizer` | exactly one, `unix:user:mediatore-gateway` | the same |

   The authorizer's ID with an Envoy's selector, a listener's ID with the authorizer's selector
   (today's second entry), two selectors, and any other path under `/gateway` are refused. That
   last refusal is what a later per-gateway scheme would have to amend on purpose. The policy
   is a guard against a mistaken or copied manifest silently undoing the split; it is not a
   bound on a cluster administrator, who can remove it, nor on SPIRE's own admin API. The
   comment at the head of `deploy/gateway/clusterstaticentries.yaml`, which says no policy
   constrains these entries, is corrected with it.

   *Amended 2026-11-19 at implementation: the policy is
   `mediatore-clusterstaticentry-gateway`, thirteen validations, with its binding in the same
   file. It is in the base, so it is applied with the broker and not as a later step: see the
   amendment of decision 7. It judges `ClusterStaticEntry` objects only: a `ClusterSPIFFEID`
   template that renders a name under `/gateway` is outside it (open question 2).*

5. **The gateway's host table gains an output chain keyed on the socket's owner.**
   `image/gateway/nftables.conf.in` gains `chain output`, rendered from the same env files and
   loaded in the same transaction as the rest, so the existing rule holds: no table, no listener.
   User names are resolved by `nft` when the table loads, from the image's static users; a name
   that does not resolve fails the load. Established and related traffic is accepted first, so
   every rule below is about a **new** connection, and a listener's replies are unaffected.

   | Socket owner (`meta skuid`) | New connections admitted | Refused |
   | --- | --- | --- |
   | `mediatore-gateway` (the authorizer) | `BROKER_ADDRESS` at `BROKER_PORT` | everything else |
   | `envoy-relay` | its four fixed upstreams, each by address and port (`SPIRE_SERVER_*`, `BROKER_*`, `SPIRE_BUNDLE_*`, `REGISTRY_*`) | everything else |
   | `spire` (the agent) | `SPIRE_SERVER_ADDRESS` at `SPIRE_SERVER_PORT` | everything else |
   | `envoy` (the tunnel Envoy) | any IPv4 destination by the egress interface that is not in the refused column; its resolver | loopback and the VM's own addresses (`oif "lo"`), other than the authorizer's check endpoint while that is loopback TCP; link-local (`169.254.0.0/16`); the control-plane addresses of the env file (`SPIRE_SERVER_ADDRESS`, `SPIRE_BUNDLE_ADDRESS`, `REGISTRY_ADDRESS`, `BROKER_ADDRESS`); all IPv6 |
   | `envoy-inject` | as the tunnel Envoy, with no loopback exception (its authorizer endpoint is a unix socket) | the same |
   | every other user, root included | as today | `BROKER_ADDRESS`, on any port |

   Two rules hold for every user. No new connection leaves by the sandbox interface
   (`oifname "@SANDBOX_IF@"`): nothing on a gateway initiates toward the segment, which is
   [ADR-0010](0010-no-inbound-to-sandboxes.md)'s rule stated on the gateway itself. And the
   broker's address is reached by the authorizer's and the relay's users and by nobody else.
   Refusals are logged with a prefix and counted, as the input chain's are. The authorizer's URL
   (`MEDIATORE_URL`) must name `BROKER_ADDRESS`, because the table is rendered from the
   address and the authorizer dials the URL; `image/gateway/check.sh` asserts it for the example
   env and the unit fails to start when they differ (open question 5). The chain's default
   policy stays `accept` in this ADR, for the users the table does not name (root, the
   resolver's, the clock's, the log forwarder's); see open question 4. With the authorizer's ID
   (decision 3) this gives the compartment two independent enforcers: the broker refuses a
   listener's name, and the kernel refuses a listener's packets.

   *Amended 2026-11-19 at implementation: the chain is `chain output` with one sub-chain per
   named user (`output_authorizer`, `output_relay`, `output_agent`, `output_envoy`, and
   `output_listener`, which `envoy-inject` jumps to and the tunnel Envoy falls through to after
   its one exception). Three things differ from the table above.*

   - *The loopback exception is by destination, not by a rule on who may reach the port. The
     tunnel Envoy's user is admitted to `127.0.0.1` at the ports of the set `check_tcp`
     (rendered from an optional key, `CHECK_TCP_ELEMENTS`, default `elements = { 9001 }`; a
     deployment whose check is the unix socket renders it empty). No rule restricts that port to
     the Envoy's user: root and the users the table does not name reach it as they did before
     this ADR. The check answers an allowlist question and never a credential (ADR-0040
     decision 6), so what is left open is what was open; it closes with open question 7.*
   - *A second optional key, `RESOLVER_ELEMENTS`, empty by default, was added beyond this text:
     addresses the two Envoys' users may reach on port 53, tested before the loopback refusal.
     It is the escape hatch of open question 6 for an image that resolves through a loopback
     stub, and it is empty until a booted image says it is needed.*
   - *`MEDIATORE_URL` naming `BROKER_ADDRESS` is enforced as open question 5 recommended: an
     `ExecStartPre` on `image/gateway/systemd/mediatore-gateway.service` refuses the start
     unless the URL is `https://<BROKER_ADDRESS>` with `BROKER_PORT` (the port may be left out
     at 443), and `image/gateway/check.sh` asserts it for the example env.*

   *Optional keys are written in the template as `@NAME:-default@`, which `image/gateway/render`
   fills with the default when the env files do not carry the key.*

   *Amended 2026-11-26 (open question 7, built): the loopback exception is no longer in the
   default table. `image/gateway/env.example` sets
   `AUTHORIZER_ENDPOINT=pipe: { path: /run/mediatore-gateway/check/check.sock }` and
   `CHECK_TCP_ELEMENTS=` (empty), with or without the inject Envoy, and the two templates'
   defaults for an absent key are the same (`AUTHORIZER_ENDPOINT` became optional, and the
   default of `CHECK_TCP_ELEMENTS` went from `elements = { 9001 }` to empty). The tunnel
   Envoy's row therefore reads: loopback refused, no exception. The socket is the CHECK socket
   of ADR-0040 decision 6, as inject deployments already had it: its directory `2750`, setgid,
   owned by `mediatore-gateway` and the group `envoy`, made by an `ExecStartPre=+` that is now
   in the image's unit, the socket `0660`. No other local user can ask the check, which closes
   what the first bullet above left open ("root and the users the table does not name reach it
   as they did"): root still can, as root can do anything on the gateway.*

   *Loopback TCP stays as an explicit setting, for a pod (the kind tier, whose two containers
   share no socket directory: `dev/kind/gateway/envoy.env` says so) and for an operator who
   sets it on purpose: both keys, `AUTHORIZER_ENDPOINT=socket_address: { address: 127.0.0.1,
   port_value: <port> }` and `CHECK_TCP_ELEMENTS=elements = { <port> }`. The exception is then
   the one described above, with what it leaves open. The authorizer's listen argument is no
   longer fixed in the unit: `image/gateway/authorizer-start` reads the two keys through
   `image/gateway/render` (a small template, `image/gateway/authorizer.in`, so an absent key
   or a key written twice means to the authorizer what it means to Envoy's bootstrap and to
   the table) and starts `mediatore gateway` with `--check-socket` and `--socket-dir-mode 2750`
   or with `--listen 127.0.0.1:<port>`. The same script, as an `ExecStartPre`, refuses the
   start with the reason when the two keys disagree (the socket in one and a loopback port in
   the other, either way round, or two different ports) or when the endpoint is neither that
   socket nor `127.0.0.1`: an env file updated by half would otherwise give an Envoy that
   dials where nobody listens, or a table that drops every check, and look like a broker
   outage. One consequence for a gateway deployed before this ADR's chain existed: an env file
   that names the TCP endpoint and has no `CHECK_TCP_ELEMENTS` line used to render the
   exception by default and is now refused until the line is added or the endpoint line is
   removed. `env.inject.example` is down to the one line inject itself adds
   (`INJECT_PORT_ELEMENT`); the binary's own default (`--listen 127.0.0.1:9001`) is unchanged,
   for dev runs. Asserted by `make gateway-render-check` and `image/gateway/check.sh`; not run
   on a booted gateway VM, where the socket's owner and group, the Envoy's connect over the
   pipe and the refusal are still to be observed.*

6. **The same chain bounds the address a resolved name may lead to, and says what it does not
   bound.** The refused column for `envoy` and `envoy-inject` is applied by the kernel at
   connect time, after resolution, so it holds whatever a name resolved to and however often
   it is resolved again. It amends ADR-0028 decision 5: the gateway resolves names, and the
   gateway's table refuses the destinations no name should lead to. What this covers is exactly
   the list above. What it does not cover:
   - an internal address that is not in the env file: the Kubernetes API, the secrets store,
     the identity provider, any other service on the operator's own ranges. A blanket refusal
     of private address space is not right for every environment (an audience may legitimately
     be an on-premises host, as the ADR-0041 run was), so the list is the operator's: a new
     optional env key, `EGRESS_DENY_ELEMENTS`, empty by default and rendered into a set the two
     Envoys' users may not dial, in the manner of `INJECT_PORT_ELEMENT`. Until an operator fills
     it, those addresses remain the datacenter firewall's to refuse on the three egress
     addresses (R-20's second allowlist), as today;
   - the name itself: an allowlisted name that resolves to a public address the operator did
     not intend is still dialled. The TLS inside the tunnel is the control there (TB-14);
   - root on the gateway, which can rewrite the table, and a deployment that renders its own
     copy of the table (the deployment's gateway repository) until that copy is brought in step;
   - unix sockets, which nftables does not see. The agent's socket stays reachable to both
     Envoys, as it must (their SVID), and after decision 3 that SVID opens no route at the
     broker.

   *Amended 2026-11-26 (open question 7, built): the authorizer's check socket is now one of
   those unix sockets by default, so the table is not what keeps a local user away from the
   check: the socket's directory is (`2750`, the group `envoy`, ADR-0040 decision 6). In the
   default table the refusal of loopback for the tunnel Envoy has no exception, so a name that
   resolves to `127.0.0.1` leads nowhere on any port, the former check port included. A
   deployment that sets loopback TCP on purpose (decision 5's amendment of the same date) has
   the one port back, and with it what this decision said of it.*

7. **Migration: the broker is strict by default, with one explicit switch that exists for one
   release.** The three parts cannot change at one instant, and the order matters, so it is
   decided here:
   1. *The broker.* The release that carries decision 3 requires the authorizer's ID. It also
      carries one configuration key, `accept_plain_gateway_identity` (default `false`,
      `crates/mediatore/src/config.rs`). When `true`, the handshake and the two routes accept
      either ID, and every ask under the plain one is a `warn` line naming the peer, the route
      and the claim UID, so the operator can see which gateway has not moved. The key is removed
      in the following release; the configuration refuses unknown fields, so a broker still
      carrying it then refuses to start instead of ignoring it.
   2. *The entries and the image, one gateway VM at a time.* The platform team replaces that
      VM's `gateway-NN-mediatore-gateway` entry with `gateway-NN-authorizer` (a replacement, not
      an addition: the old image takes whichever SVID the agent hands it first, so a user
      holding both is not something the old image handles deterministically) and the VM boots
      the image that carries decisions 2 and 5. A new image whose entry is missing does not
      start its authorizer and serves nothing; an old image whose entry was replaced is refused
      by a broker without the switch, and the authorizer then denies what it has cached
      (`broker_refused`). Both failures are closed and both are loud.

      *Amended 2026-11-19 at implementation: the last clause is not what the code does.
      Decision 3 moved the refusal of the plain ID into the handshake, and over mutual TLS a
      client that is refused there sees a failed connection, which it cannot tell from an
      outage. So the authorizer reports `broker_unreachable`, not `broker_refused`, and a warm
      cache keeps serving the allowlists it holds for up to the stale bound (`--stale-secs`,
      300 seconds), never past a claim's deadline; a claim with nothing cached is denied at
      once. `broker_refused` now occurs only on an HTTP `403`, which an authorizer holding the
      right ID does not get from these routes. The window is the one an outage already had and
      it serves allowlists the broker gave while the authorizer was still a peer; it is recorded
      as an accepted risk in the threat model. Telling the two apart would need the broker to
      complete the handshake and refuse at the route, which is the old behaviour for the plain
      ID and what decision 3 removed on purpose.*
   3. *The admission policy of decision 4*, applied once the last old entry is gone (a
      `ValidatingAdmissionPolicy` does not judge objects that already exist, but it would refuse
      an update to one).

      *Amended 2026-11-19 at implementation: the policy is in `deploy/base`, so it lands with
      the broker at step 1, not here. An old `gateway-NN-mediatore-gateway` entry that already
      exists keeps working until it is replaced (the policy does not judge it), and from step 1
      on it can be deleted and can no longer be updated or applied again. An environment that
      needs to re-apply the old shape during the transition must leave the policy out of its
      overlay until this step, on purpose.*
   4. *The switch set back to `false`*, when no `warn` line has appeared for a full claim
      lifetime, and at the latest before the next release.

   The recommendation is to ship the switch and to leave it off wherever the three parts can be
   changed in one maintenance window: a small environment replaces the entries, the image and
   the broker together and accepts that tunnels are refused for the minutes in between. The
   switch is for an environment where the entries are another team's change on another
   calendar. It is an explicit, logged, short-lived acceptance of today's behaviour, never a
   default, and with it on the compartment of this ADR is not yet in force: the threat model
   says so for as long as the key exists. The alternative, no switch at all, is open
   question 3.

8. **What is not decided here.**
   - *Per-gateway identities.* All three gateways still share each of the two IDs
     (ADR-0028 decision 2: a client verifies "a gateway of this environment"). The broker
     cannot tell one gateway's authorizer from another's.
   - *Binding a credential ask to the gateway that is serving the claim.* The broker still
     answers any authorizer for any live claim; it does not know, and is not told, which
     gateway holds the claim's connection. A compromised authorizer on one gateway therefore
     remains what R-27 says a compromised gateway VM is.
   - *An identity for each listener.* The tunnel Envoy and the inject Envoy keep one server
     ID. Splitting it would change what the forwarder verifies on each port, on every pool VM.
   - *Certificate validation in the Envoy templates*, the per-claim limit of ADR-0040
     decision 5, and how a tunnel is ended before its lifetime. Each has its own item on
     roadmap 10.

### STRIDE, per boundary

Every control below is proposed. None exists yet; each is marked *(not built)* with the file it
will live in, and the threat model is not changed until the pass that follows implementation.

*Amended 2026-11-19 at implementation:* the controls below are built, and the threat model's
TB-3, TB-6, TB-13, TB-14 and TB-17 carry them with their tests since the pass of the same day; the
*(not built)* marks are left as the proposal read. Two rows are not as written. "A refused
authorizer keeps serving what it had cached" is true for up to the stale bound (decision 7's
amendment), and is an accepted risk there, not a control. "The chain cuts something the VM needs"
is still *not proven*: no gateway VM has booted this table. The entries case of the TB-3 table
runs in the kind gateway tier, not the entries tier.

**TB-6, gateway to the broker's sandbox API (the two gateway routes)**

| Threat | STRIDE | Control |
| --- | --- | --- |
| A gateway process other than the authorizer presents the gateway's listener identity to the broker and is answered as the authorizer | S/E | The two routes require `spiffe://<td>/gateway/authorizer` exactly and the handshake no longer admits `spiffe://<td>/gateway`: `is_gateway_authorizer`, `claim_egress`, `gateway_credential`, `sandbox_authorizer` in `crates/mediatore-api/src/lib.rs` and `crates/mediatore-spire/src/lib.rs` *(not built)* |
| The authorizer is handed a listener's SVID (two entries for its user, a mistaken entry) and uses it | S | The authorizer selects its SVID by ID and fails its start without it: `crates/mediatore-tls/src/material.rs`, `crates/mediatore-gateway/src/broker.rs` *(not built)* |
| A credential or an allowlist is disclosed to a peer that is not the authorizer | I | The same guard, placed before the claim lookup, so a refusal carries neither a credential nor the existence of a claim: `crates/mediatore-api/src/lib.rs` *(not built)* |
| The transition switch is left on, and the old acceptance becomes permanent | E | Default `false`, a `warn` line per ask under the plain ID, and removal in the following release where an unknown key refuses the start: `crates/mediatore/src/config.rs` *(not built)* |
| A refused authorizer keeps serving what it had cached | E | Unchanged and existing: a broker that refuses the authorizer's identity denies whatever is cached (`broker_refused`, `crates/mediatore-gateway/src/lib.rs`); to be re-proven with the new ID *(test not built)* |
| Who asked for a credential cannot be told apart afterwards | R | The audit line of ADR-0040 decision 2 gains the peer's SPIFFE ID, which is now informative: `crates/mediatore-api/src/lib.rs` *(not built)* |

**TB-3, registration entries (the gateway's, applied by the platform team)**

| Threat | STRIDE | Control |
| --- | --- | --- |
| An entry gives the authorizer's ID to an Envoy's user, or a listener's ID to the authorizer's user, by mistake or by copy | S/E | `deploy/base/admission/clusterstaticentry-gateway.yaml`: two shapes, one selector each, nothing else under `/gateway` *(not built)* |
| The broker's ServiceAccount declares a gateway identity | E | Existing: `deploy/base/admission/clusterstaticentry-mediatore.yaml` admits `/banlieue/node/` and `/banlieue/claim/` alone; a case for both gateway IDs is added to the entries tier *(test not built)* |
| The policy is absent, or removed by an administrator | T | Not controlled by this repository: the policy is a guard, RBAC on `clusterstaticentries` and on the policy itself is the platform team's. Recorded as an assumption in the threat model at the pass *(not built)* |

**The gateway VM, between its own processes and toward the egress side (R-20, TB-14, TB-17)**

| Threat | STRIDE | Control |
| --- | --- | --- |
| A listener's process opens a connection to the broker's address | E | `chain output` in `image/gateway/nftables.conf.in`: `BROKER_ADDRESS` admitted to the users `mediatore-gateway` and `envoy-relay` alone *(not built)* |
| A name admitted for a claim resolves to the gateway's loopback, a link-local address, the sandbox segment or a control-plane upstream, and the tunnel Envoy dials it | E/S | The same chain, for the users `envoy` and `envoy-inject`, applied at connect time after resolution; `EGRESS_DENY_ELEMENTS` for the operator's own ranges *(not built)* |
| A gateway process initiates a connection into the sandbox segment | E | No new connection by `SANDBOX_IF`, for every user *(not built)* |
| The relay, or the agent, is used to reach an address that is not one of its fixed upstreams | E | Per-user allowlists by address and port in the same chain *(not built)* |
| The table loads without the chain, or with a user name that does not exist | T/D | One `nft -f` transaction, a failed load keeps every unit that requires the table down (existing, `image/gateway/systemd/mediatore-gateway-nft.service`); `make gateway-render-check` and `image/gateway/check.sh` assert the chain and its users in the rendered text *(assertions not built)* |
| The chain cuts something the VM needs (the resolver, the agent's server, the clock) and the gateway serves nothing | D | Fail closed by construction; found only by booting the image, which is why the live run below is a condition of acceptance *(not proven)* |
| Root on the gateway rewrites the table | E | Not controlled: accepted, as R-20 and R-27 already accept root on a gateway VM |

## Consequences

- **The compartment has two enforcers that do not depend on each other.** A listener's process
  that reaches the agent's socket still obtains `spiffe://<td>/gateway`, as it must to serve.
  That name no longer completes a handshake with the broker, and that process's packets no
  longer reach the broker's address. Either control alone would restore what ADR-0040
  decision 6 intended; both are proposed because one is the broker's code and the other is the
  image's, and they fail differently.
- **What does not change.** Root on a gateway VM, or the authorizer's own process, still yields
  what R-27 says: the credentials of live gateway-placed claims for at most 300 seconds, and the
  ability to ask for any live claim's. This ADR narrows R-27 from "any process holding the
  gateway SVID" to "the authorizer's user and root"; it does not close it. A listener's SVID
  still lets its holder impersonate a gateway to a sandbox's forwarder (A-21, unchanged).
- **`/gateway` is no longer a leaf.** ADR-0004's amendment note ("exactly that id, nothing under
  it") is reworded when this is implemented, and `Naming`'s tests pin both IDs as exact. Any
  future code that matched `spiffe://<td>/gateway` by prefix would take in the authorizer; the
  tests of decision 1 exist to make that fail.
- **The platform team's bootstrap grows by nothing and changes one line per VM.** Still one
  entry per user per VM (three with inject), against the agent ID the SPIRE server logs. The
  deploying guide and `deploy/gateway/clusterstaticentries.yaml` carry the new shape.
- **A deployment's own copies must follow.** The deployment's gateway repository renders its
  own templates and table (ADR-0040 decision 10 (g)); its table needs the chain and its entries
  the new ID. Until then that deployment has decision 3 and not decision 5.
- **Operations.** A refused `BROKER_ADDRESS` connection, a refused sandbox-interface connection
  and a refused Envoy destination each have a log prefix; a name that resolves into the refused
  set shows as Envoy's upstream connect failure (`503`) for that tunnel and as a counter on the
  gateway, and the forwarder moves to the next gateway (ADR-0028 decision 7, the `5xx` kind),
  which refuses it the same way.
- **Rollback is not free.** An old image against the new entries presents the authorizer's ID
  to a broker that may not know it. Rolling an image back means rolling its entry back, or the
  switch of decision 7.
- **Documents to change at implementation, not before:** amendment notes on ADR-0004, ADR-0007,
  ADR-0027, ADR-0028 and ADR-0040; CALM (`docs/architecture/calm/architecture.json`: the
  gateway node's identities, the relationship that carries the gateway routes, the host table);
  the deploying guide; roadmap 10's detail doc and its board row. The threat-model pass that
  makes this ADR implemented rewrites A-21 (two identities, and what each can and cannot do at
  the broker), R-20, R-27, the tunnel-Envoy row of TB-17, TB-14's name-resolution row and TB-13's
  loopback row, adds the rows above to TB-3 and TB-6, updates the Mermaid diagram if the
  authorizer becomes a node of its own in it, and bumps the stamp. None of that is done here.
- **The TPM attestation path** (`rules/testing.md`) is not on this change's list as proposed:
  `Naming` gains two functions and `node_id`, `agent_id` and the node entry's shape are
  untouched. If the implementation edits those, or `image/systemd/spire-agent.service`, the
  tier runs.

## Alternatives rejected

- **Keep one ID and rely on the host table alone.** The kernel rule is the image's, and a
  deployment that renders its own table, or a table that loads without the chain, would silently
  have no compartment. The broker should refuse on what it can verify itself.
- **Keep one ID and rely on the two sockets.** That is today's state: the separation holds for a
  process that asks the authorizer and says nothing about one that does not.
- **A new ID for the listeners, the authorizer keeping `/gateway`.** It reads as the smaller
  change at the broker and is the larger one everywhere else: every forwarder on every pool VM
  verifies the listeners' ID, so the pool image, the guest and the gateways would have to move
  together, and a sandbox in flight would refuse its gateways. The process whose peers are one
  broker is the one to rename.
- **The broker tells the processes apart by something other than the SPIFFE ID** (a second
  factor in a header, the source address, a client-certificate extension). The identity scheme
  is the place identities live (ADR-0004); a header is the caller's word, and three gateways
  share nothing by address that an Envoy on the same VM does not share too.
- **Accept both IDs for a release, unconditionally.** The simplest migration and the one most
  likely to outlive its release: nothing would fail if the acceptance were never removed. A
  switch that defaults to strict, logs each use and breaks the start when its release has
  passed cannot be forgotten quietly.
- **Network namespaces or one VM per process instead of `meta skuid`.** Stronger, and a
  different gateway: new interfaces, new units, a new image shape and a new live proof. The
  owner match is the mechanism the pool VM's table already uses for the registry leg
  (ADR-0029) and costs one chain.
- **A fixed refusal of all private and reserved address space for the tunnel Envoy.** Right for
  an environment whose audiences are all public, wrong for one with an on-premises audience.
  The fixed part is what every gateway knows about itself; the rest is the operator's list.
- **Have the authorizer resolve the name and hand Envoy an address.** It would let the
  allowlist be checked against the address, and it moves resolution into the process that
  holds credentials and changes what `CONNECT` carries. Not for this ADR.

## What must be proven

Tests first, red before any implementation (`rules/testing.md`). Names are the proposed ones.

Unit, in the source file:

- `crates/mediatore-spire/src/lib.rs`:
  `the_authorizer_identity_is_exactly_one_id_and_is_not_the_gateway_identity` (both predicates,
  both directions, a trailing slash, a longer path, another trust domain, the broker's ID).
- `crates/mediatore-api/src/lib.rs`:
  `only_the_authorizers_identity_may_ask_and_a_refusal_never_carries_the_credential` (today's
  test with `spiffe://<td>/gateway` moved into the refused list);
  `the_plain_gateway_identity_is_refused_on_both_gateway_routes_before_the_claim_is_looked_up`;
  `the_sandbox_listener_admits_the_authorizer_and_no_longer_the_plain_gateway_identity`;
  `the_transition_switch_is_off_by_default_and_when_on_admits_the_plain_identity_with_a_warning`;
  `the_audit_line_names_the_peer_that_asked`.
- `crates/mediatore-tls/src/material.rs`:
  `a_source_asked_for_one_id_returns_that_svid_among_several_and_fails_without_it`.
- `crates/mediatore-gateway/src/broker.rs`:
  `the_authorizer_asks_as_the_authorizer_identity_and_does_not_start_on_the_listeners`.
- `crates/mediatore-guest/src/forward.rs`:
  `a_server_presenting_the_authorizers_identity_is_not_a_gateway_to_the_forwarder`.
- `crates/mediatore/src/config.rs`:
  `accept_plain_gateway_identity_defaults_to_false`.

End to end, over real listeners:

- `crates/mediatore/tests/e2e_mtls.rs`:
  `the_authorizer_identity_is_a_peer_for_the_gateway_routes_only` (it reaches both gateway
  routes and is `403` on `/v1/me` and `/v1/token`) and
  `the_plain_gateway_identity_does_not_complete_a_handshake_with_the_broker`.
- `crates/mediatore/tests/e2e_gateway.rs`:
  `an_authorizer_holding_the_listeners_identity_is_refused_and_denies_every_tunnel`, and the
  existing tests under the new ID.
- `crates/mediatore/tests/e2e_forward.rs`: a listener under `spiffe://<td>/gateway/authorizer`
  is refused by the forwarder, as a negative case beside the existing ones.

Render and image, on every pull request: `make gateway-render-check` asserts the output chain
in the rendered table with the example env, with and without inject (the five users, the two
all-user rules, the loopback exception present only while the check endpoint is TCP, an empty
and a filled `EGRESS_DENY_ELEMENTS`); `image/gateway/check.sh` asserts the chain in the built
image and that every user the table names exists in it; `make manifests` renders the new entries
and the policy.

The kind gateway tier, `make kind-e2e-gateway` and `make kind-e2e-gateway-policy`
(`dev/kind/gateway/gateway.yaml`, `dev/kind/gateway-e2e.sh`): the pod's two containers get two
identities (two `ClusterSPIFFEID` fixtures told apart by container name, to be shown to work with
the pinned controller manager); the authorizer's log line names
`spiffe://<td>/gateway/authorizer`; a new probe that asks the broker's gateway route with the
Envoy container's identity is refused; the existing probes pass unchanged. The entries tier,
`make kind-e2e-entries`, gains the refused shapes of decision 4, applied as an identity that is
not the broker's, and the broker's own refusal for both gateway IDs.

What kind cannot show, and a live run must: the tier's gateway is a pod, so it has no `unix:user`
selectors, no host table and no systemd units. The gateway image and its entries are proven
only by booting them: three gateway VMs from the built image under the new entries, a pool
member behind them, one claim through a tunnel and one through the inject listener. To observe:
the authorizer attests as the new ID and both Envoys as the old one; the broker's audit line
names the authorizer; as each Envoy's user on a gateway, a connection to `BROKER_ADDRESS` is
dropped and counted, and so is one to loopback, to a link-local address, to the sandbox segment
and to each control-plane address; a name made to resolve to one of those is a `503` for that
tunnel; the agent still reaches its server, the relay its four upstreams and Envoy its
resolver; and the migration of decision 7 is walked once in each direction (switch on, then
off). Until that run has passed, decisions 2 and 5 are not to be called verified, whatever
`make check` and CI say.

## What was proven, and what was not

Proven on 2026-11-19, on the build host:

- **The quality gate** (`make check`): the unit and end-to-end tests named above, with these
  differences. The forwarder's refusal of the authorizer's ID is a negative case in
  `crates/mediatore/tests/e2e_forward.rs` and has no unit test of its own in `forward.rs`.
  Added beyond the list: `a_source_asked_for_one_id_fails_the_connect_within_the_wait_and_names_the_id`
  (`material.rs`), `startup_warns_while_the_plain_gateway_identity_is_accepted_and_says_nothing_otherwise`
  (`config.rs`), and `the_transition_switch_admits_the_plain_gateway_identity_to_the_gateway_routes_only`
  (`e2e_mtls.rs`).
- **The kind gateway tiers** (`make kind-e2e-gateway`, `make kind-e2e-gateway-policy`): the pod's
  two containers hold two identities from two `ClusterSPIFFEID` fixtures told apart by container
  name; the authorizer's log line names `spiffe://<td>/gateway/authorizer`; a client holding the
  listeners' identity is refused by the broker in the handshake; and server-side dry runs of
  gateway entries are judged by the admission policy, three admitted (the two listeners' shapes
  and the authorizer's) and the others refused: as an administrator, swapped selectors, a
  selector of neither kind, two selectors, other paths under `/gateway`, `admin`, a long TTL and
  DNS names; as the broker's ServiceAccount, both gateway IDs.
  The existing probes pass unchanged. The dry runs are in the gateway tier, not the entries tier.
- **The image checks** (`make gateway-image-check`, with `make gateway-render-check`): the built
  gateway image carries the output chain and its five sub-chains, the users the table names, the
  optional sets in their default and filled forms, and the `MEDIATORE_URL` guard.

Not proven: anything on a booted gateway VM. The tier's gateway is a pod, so no `unix:user`
selector, no host table and no systemd unit has run. The kernel's drops per user, the resolver
(open question 6), the agent and the relay still reaching their upstreams under the chain, and
the migration of decision 7 walked in each direction are all still to be observed, and the core
cluster has not run this change. Until then decisions 2, 5 and 6 are built and not verified.
Which certificate validator Envoy runs under the SDS secret is not established by this change
either (the templates name none); it is recorded in the threat model.

## Open questions

1. **`/gateway/authorizer` or a sibling such as `/gateway-authorizer`?** The nested form reads
   as what it is and keeps the top level of the scheme short. The sibling form can never be
   taken in by a prefix match on `/gateway`. *Recommendation:* the nested form, because every
   matcher in the repository is exact and the tests of decision 1 pin it; choose the sibling if
   the maintainer expects an Envoy-side matcher on the gateway ID (a SAN prefix, as the claim
   matcher is) at any point. (Answered 2026-11-19 by the implementation: the nested form,
   pinned exact in both directions by
   `the_authorizer_identity_is_exactly_one_id_and_is_not_the_gateway_identity`.)
2. **Should the admission policy of decision 4 exist at all, given that it binds nobody who can
   delete it?** *Recommendation:* yes. Its job is to stop the one mistake that undoes this ADR
   without any error (the old second entry re-applied from an old manifest), and it documents
   the two shapes in a place the API server enforces. A companion rule for `ClusterSPIFFEID`
   templates under `/gateway` (the kind fixture's kind, and another way to the same name) is
   worth a line in the same file; it is left out of the decision until the maintainer says
   whether that kind is in use outside the tier. (Answered 2026-11-19 by the implementation:
   the policy exists, in the base. The companion rule for `ClusterSPIFFEID` is not built and
   stays open.)
3. **The transition switch, or a hard cut with no dual acceptance?** *Recommendation:* ship the
   switch, default off, removed one release later (decision 7). A hard cut is the purer
   fail-closed choice and is what a single-operator environment should do in practice; without
   the switch, an environment whose entries are changed by another team has an outage of the
   whole egress path for as long as the three changes are apart, and the pressure that creates
   is to delay the fix. If the maintainer prefers no switch, decision 7 loses the key and
   step 4, and the release notes carry the order (entries and image per VM, then the broker)
   with the outage stated. (Answered 2026-11-19 by the implementation: the switch,
   `accept_plain_gateway_identity`, default off, a `warn` at start and at each use. Its removal
   in the following release is still to do.)
4. **Default policy of the output chain: `accept` or `drop`?** The pool VM's table is
   default-drop (ADR-0029). On the gateway that would mean enumerating every system user that
   opens a connection (the resolver, the clock, the log forwarder, the upgrade path), none of
   which this repository has listed. *Recommendation:* `accept` in this ADR with allowlists for
   the five named users, and a follow-up to move to `drop` once the live run has produced the
   list. A wrong guess here is a gateway that boots and serves nothing, found only on a VM. (Answered
   2026-11-19 by the implementation: `accept`. The move to `drop` is not built and waits for the
   live run; what `accept` leaves is an accepted risk in the threat model.)
5. **How is "`MEDIATORE_URL` names `BROKER_ADDRESS`" enforced?** The table is rendered from an
   address and the authorizer dials a URL. *Recommendation:* the image check for the example,
   and the authorizer's unit refusing to start when the URL's host is not the address (a small
   `ExecStartPre`), in preference to deriving one from the other in the template language,
   which `image/gateway/render` deliberately does not have. (Answered 2026-11-19 by the
   implementation: both, as recommended.)
6. **Does the tunnel Envoy's resolver sit on loopback in the image?** If the base image runs a
   local stub resolver, the loopback refusal needs one more exception (the stub's address, port
   53) or Envoy's bootstrap names the egress resolver directly. *Recommendation:* name the
   resolver in the bootstrap from a new env key and keep loopback closed; to be settled by
   reading the booted image, not assumed. (Open. Not settled: no image has booted under the
   chain. `RESOLVER_ELEMENTS` exists, empty, for the case where the answer is a loopback stub.)
7. **Should the tunnel check move to the unix socket by default in the same change?** With the
   check on loopback TCP the table needs a loopback exception for the tunnel Envoy's user and a
   rule that only that user may reach the port. With the unix socket as the default
   (ADR-0040 decision 6 already ships it for inject) there is no loopback rule to get wrong.
   *Recommendation:* yes, in the same image release, as its own small change, so that the
   exception in decision 5 is temporary. (Answered 2026-11-26 by a change of its own, built: the unix
   socket is the default on the gateway image, with or without inject, the default table has no
   loopback exception, and loopback TCP is an explicit setting of two keys that the authorizer's
   unit checks against each other. The amendments of that date at decisions 5 and 6 say what the
   code does. Not yet observed on a booted gateway VM.)
8. **Is `EGRESS_DENY_ELEMENTS` in scope here or a follow-up?** *Recommendation:* in scope, as
   an empty-by-default key, because the chain it extends is new in this ADR and the Kubernetes
   API and the secrets store are the addresses an operator will most want in it; what goes in
   it is the deployment's. (Answered 2026-11-19 by the implementation: in scope, empty by
   default.)
9. **Per-gateway identities and binding an ask to the serving gateway (decision 8).**
   *Recommendation:* a separate ADR, after this one is live. It needs the broker to learn which
   gateway holds a claim's connection, which is a new contract between the gateway and the
   broker, and it is the change that would actually narrow R-27. (Open: no such ADR is
   written. R-27 says what is left.)
