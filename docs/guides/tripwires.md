<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Tripwires

An allowlist bounds where a hijacked workload can go; it does not say whether the workload is
hijacked. A refusal is a log line, and a typo, a tool's probe and an attack produce the same
line. Tripwires separate them: things no honest run has a reason to touch, and a record, or an
end to the sandbox, the first time something touches one.

Two ADRs, two places:

- **On the VM** ([ADR-0069](../adr/0069-tripwires-on-the-vm-a-decoy-the-workload-takes-ends-its-sandbox.md),
  roadmap 17). The guest plants decoys for the jailed workload: loopback ports that answer like
  a service, routes on the egress proxy that are no audience, credentials in their providers'
  shapes. Every trap lives on
  the VM and is decided there, before anything leaves it. Under `enforce` the first use ends the
  sandbox: the network is cut and the jail killed on the VM, then the claim is released.
- **Past the jail** ([ADR-0070](../adr/0070-tripwires-beyond-the-sandbox-a-request-no-honest-build-makes.md),
  roadmap 18). A process that escaped the jail, root on a pool VM, a compromised gateway: their
  peers are mediatore's own code, so the honest requests are a closed set. The broker classifies
  refusals it already makes, and the host tables count drops they already make. No bait, no decoy
  listener, and no answer changes.

mediatore is open source, and this page is public. Nothing here depends on a list being secret:
on the VM the secret is each claim's draw, never the method; past the jail there is no list.

## The kinds

| Kind | The trap | Decided by | Can end a sandbox |
| --- | --- | --- | --- |
| `port` | a drawn loopback port that answers with a plausible first line (an SSH banner, a Redis `-NOAUTH`, an HTTP `401`, ...), or `169.254.169.254:80`; nothing listens on either: the claim's table redirects the sandbox uid's connection to one trap listener, which answers as the decoy reached | the guest | yes, under `enforce` |
| `route` | a drawn host the proxy carries as a route that is no audience, advertised in a variable such as `VAULT_ADDR` | the proxy | yes, under `enforce` |
| `credential` | drawn values in a provider's shape, in the environment and in the files tools read them from, in the sandbox user's home (never `/work`) | the proxy, when a value appears in a request | yes, under `enforce` |
| `denied` | none: the space no honest run reaches, by class (`loopback_port`, `private_range`, `unknown_host`) | the claim's table and the proxy | only for a class switched to `trip` |
| `protocol` | a request no honest build of mediatore makes, by class (below) | the broker | only for a claim-scoped class set to `trip` |
| `segment` | a connection a host table dropped, by class (below) | the gateway's and the pool VM's host tables | never |

A trap trips on **use**, never on discovery: listing the home, reading a bait file, `env`,
`grep -r ~` trip nothing. Completing a handshake on a decoy port, naming a decoy route at the
proxy, or sending a bait value in a request (as the method, in a header's name or value, the
path, the query or the body) does.

## The modes, and the order to roll them out

`policy.traps` is one switch for the whole broker, for ADR-0069:

| Mode | The guest | The broker |
| --- | --- | --- |
| `off` (the default) | arms nothing; the jail, its environment, its home and the claim's table are byte for byte what they were before ADR-0069 | `POST /v1/me/trip` answers `501`, except for a report of `segment` events alone (the pool's host table, ADR-0070), which is recorded as under `shadow`; `GET /v1/me` carries no `traps` |
| `shadow` | arms every trap; a use is reported and ends nothing; nothing is refused that `off` would forward | records each event as `would_trip` (or `reported` for a `denied` class at `report`) and ends nothing |
| `enforce` | a use is refused, the network cut and the jail killed, then reported | records the event, writes `tripped` on the record and releases the claim |

`policy.traps` lives in the `policy` section, which requires `policy.trusted_keys` (notaio's
signing keys): **a deployment with no signed policy cannot turn tripwires on the VM on at all.**
That is how it is built; it changes when the mode moves to a top-level key (ADR-0069 open
question 8). The ADR-0070 section, `tripwires`, is top-level and needs nothing: the pool's
segment classes are recorded whatever `policy.traps` says.

Roll out in this order:

1. **Upgrade the guests first.** A guest from before ADR-0069 ignores `traps` in `GET /v1/me`. Under
   a broker at `enforce` it runs its claims unguarded, and the broker cannot tell.
2. **`off`**, the default: nothing changes.
3. **`shadow`**, for a soak: run ordinary tasks and read the `would_trip` entries. A workload that
   enumerates its environment and fails on an unknown variable shows up here.
4. **`enforce`**, once the soak is quiet.

Never switch the broker to `off` with claims running: their reports are then `501`, and a claim
whose guest has cut and killed ends only at its deadline. A report made under one mode and
received under the other ends its claim if either side says `enforce`.

`enforce` refuses the start under `policy.audience_definitions.mode: bundles`: an audience defined
in a `SandboxAudience` bundle cannot be marked `traps_body: skip` yet, so an agent that quoted a
bait value to its model API would end its own run. `shadow` is allowed there, and shows
`would_trip` on such a route.

### The `denied` switches

`policy.traps_denied` says what each `denied` class does under `enforce`: `report` (the default,
recorded as under `shadow`, nothing ended) or `trip`. Move a class to `trip` only once the soak
shows it silent on honest runs: tools probe localhost for a local service or an IDE, package
managers fall back across mirrors, people mistype hosts. A `denied` event follows the switch the
broker holds when the report arrives.

| Class | What it sees | Limit |
| --- | --- | --- |
| `unknown_host` | a request at the proxy for a host that is no route (still `404 no_route` to the workload, the same bytes as before) | sees every attempt: it is decided at the proxy |
| `loopback_port` | a new TCP connection from the sandbox uid to a loopback port that is neither the proxy nor a decoy, dropped by the claim's table | only on a port Landlock admits: every other connect fails in the syscall and reaches no table |
| `private_range` | the same, to a private or link-local address | the same |

A dropped connection to any other address is refused and logged by the chain and is no class.
A `denied` count is packets (a SYN and its retransmissions).

## What the workload sees

Under `shadow` and `enforce`, and never under `off`:

- **The environment** carries the decoy routes' variables, each pointing at the proxy
  (`VAULT_ADDR=http://127.0.0.1:<proxy port>/<drawn host>/`), and the bait variables
  (`AWS_ACCESS_KEY_ID`, `GITHUB_TOKEN`, `KUBECONFIG`, ...). A variable that the workload's own
  specification or the guest sets is never drawn, nor any variable of the same tool's lookup
  family (`GH_TOKEN` set means no bait `GITHUB_TOKEN`), nor a credential whose provider is one of
  the claim's routes. Every bait value is in the redaction set of the workload's output, so a
  workload that prints its environment ships no bait.
- **The home** is a bind mount of a directory the guest prepared on the claim's tmpfs, `0700`,
  with the bait files `0600` (`~/.aws/credentials`, `~/.git-credentials`, `~/.npmrc`, ...). It
  **persists across the workload's restarts within the claim**: what the workload writes there
  is still there at its next start. Under `off` the home is a fresh tmpfs at every start. Either
  way the mount hides the image's own home, and nothing is planted under `/work`.
- **Decoy routes**: under `shadow` a request naming one gets `404 no_route`, what an unknown host
  gets, and is reported; under `enforce` it is `403 trap`. Either way nothing is resolved,
  dialled or tunnelled.
- **Decoy ports** have nothing listening on them. The claim's table redirects the sandbox
  uid's connection to a decoy port (and to `169.254.169.254:80` when the metadata decoy is
  drawn) to one trap listener on loopback, outside the jail, on a port drawn per claim; the
  listener answers as the decoy the connection was made to. A direct connection to the trap
  listener's port is refused for every uid, and Landlock refuses it to the jail. The jail
  cannot list the decoy ports. In its own `/proc/self/net/tcp` it can see the loopback listeners
  beside the proxy's port: the proxy's pull listener (`MEDIATORE_EGRESS_PULL_PORT`, default
  18129) when the claim's image is pulled through the proxy, and, when traps are armed, the trap
  listener on its drawn port. So it can tell that traps are armed, not where the decoys are.
- **Decoy names.** A generated decoy port is named `dev-server` (the first port of every draw is
  one, and each later port about half the time), so a record or a log reading `trap=dev-server`
  several times for one claim is several generated ports, not one port tripped again.
- **The connect ports.** Landlock admits the decoy ports beside the proxy's (and 80 with the
  metadata decoy). The jail's `confinement applied; exec` line, which reaches the owner with the
  workload's output, then reads `connect_ports=<n> ports`: the number of admitted ports, not
  which.
- **Bodies** on a route whose audience is not marked `traps_body: skip` pass through the
  proxy's matcher, which holds back a few bytes of each body until it is sure they are not part
  of a bait value. A body in an encoding the matcher cannot read is `415 unsupported_encoding`
  under `enforce` and forwarded unscanned under `shadow`.

Under `enforce`, a request that carries bait or names a decoy route is `403 trap`, and so is every
request after a trip. The last line of the workload's output after a trip is
`mediatore: this sandbox was ended by a tripwire (kind <kind>, trap <trap>)` (or `class <class>`),
never the target or a value.

## What a trip does

On the VM, in this order, under `enforce`:

1. the proxy refuses the request and forwards nothing more for the claim, and tells the guest
   over a unix socket in `/run/mediatore-guest/trap`, which the jail cannot reach; for a decoy
   port or a `denied` class the guest decides, and tells the proxy at once, before the cut, so
   that from then on every request is `403 trap` (a request body already streaming keeps
   flowing until the cut lands, about 50 ms);
2. the guest replaces the sandbox uid's table with a drop of everything, in one `nft`
   transaction (the jail and the proxy are cut; the guest's own path to the broker is root's);
3. it kills every process of the sandbox uid;
4. it flushes the workload's output with the final line, within two seconds;
5. it reports `POST /v1/me/trip`, retrying with backoff, and waits at most 120 s for the
   broker's acknowledgement; then it tears down all the same, keeping the cut and the user, and
   a report that never arrives leaves the claim to end at its deadline. Containment never waits
   on the broker.

The first trip is always cut and reported, however many other uses are queued. A workload that
exits while its trip is being cut is still the tripped run: under `enforce`, when the run ends,
the guest waits 600 ms for a use still on its way before it reports an exit, so every armed
`enforce` claim takes 600 ms longer to end.

Measured on the build host, with a debug build in a throwaway network namespace (not a VM), on
the merged tree: 54 ms from the listener's verdict to the end of the cut, every process of the
uid gone 242 ms after the verdict, and 256 ms with the broker unreachable. No release-build
figure exists yet.

At the broker: one audit line per event; `tripped` on the claim's record by compare-and-set; the
release (the SPIRE entry retracted, the record revoked); the event folded into the sandbox's
`status.tripwires`. The reconciler then deletes the `VirtualMachineClaim`, so banlieue destroys
the VM, and marks the sandbox `Failed` with `Tripped=True`. A tripped claim is never restarted,
its token is refused, and the sandbox never gets a second claim.

**A tripped sandbox is not kept forever.** Its record is released, so the retention sweep
deletes the `AgentSandbox` `store.retention_secs` after the release (an hour by default), and its
`status.tripwires` and `Tripped` condition with it. After that only the audit lines in the
broker's log remain: keep them. An exit from the guest never deletes a tripped sandbox, even one
that races the trip. Its owner can: `mediatore sandbox delete` (or `kubectl delete`) is not
refused for a tripped sandbox, and **deleting it deletes the evidence on it**, its
`status.tripwires` and its `Tripped` condition.

The workload's last output still reaches its owner: for 60 s after the trip is recorded the
broker takes the claim's log batches from the node it was bound to, so the final line and what
the workload wrote just before the trip are kept.

## What a requester sees

`mediatore sandbox get <name>` prints the claim as JSON on standard output, now with `tripped` and
`tripwires` when anything happened, and says the same in words on standard error.
`mediatore sandbox create` prints the same words on standard output after its other lines.

```text
ended=tripped	at=2026-11-27T10:01:00Z	recorded_at=2026-11-27T10:01:01Z	kind=credential	trap=aws	target=git.example	source=workload
tripwire	effect=tripped	kind=credential	trap=aws	target=git.example	count=1	first_at=2026-11-27T10:01:00Z	last_at=2026-11-27T10:01:00Z	containment_ms=41
tripwire	effect=would_trip	kind=port	trap=redis	target=6379	count=2	first_at=2026-11-27T09:50:00Z	last_at=2026-11-27T09:51:00Z
tripwire	effect=reported	kind=denied	class=unknown_host	target=mirror.example	count=4	first_at=2026-11-27T09:40:00Z	last_at=2026-11-27T09:41:00Z
tripwires_overflow=5
tripwire counts are a lower bound of what was reported, not a ledger
```

- `ended=tripped` is the trip that ended the claim. When it is there, treat the claim as ended
  whatever `phase` says: outside `dev_mode` the phase can read `Bound` until the reconciler's
  next pass, then `Failed`. `ready` is false from the trip on.
- Each `tripwire` line is one folded entry, latest first, at most 16: what it did (`would_trip`,
  `reported`, `tripped`), the kind, the trap or the class, the target, how many, the first and
  last time, the containment figure where there is one. A `segment` event is never on a claim
  (it is an audit line with no claim). `tripwires_overflow` counts the uses of entries that did not fit. An entry that ended the
  claim is never evicted.
- **The counts are a lower bound, not a ledger.** A retry that lands on another broker replica
  may count twice, and a fold that fails is not retried; the audit line is the record.
- An event's id is never shown. For a `credential` the trap is the catalogue entry's name
  (`aws`, `github`), never the value; the rest of the draw is never shown.

With `kubectl`, as anyone who may `get` the sandbox:

```sh
kubectl -n <namespace> get agentsandbox <name> -o yaml
```

shows `status.phase: Failed`, `status.reason: "tripped: <kind>"`, one condition `type: Tripped`,
`status: "True"`, `reason: <kind>`, `message: trap <trap>, target <target>` (or `class <class>`),
`status.record.tripped`, and `status.tripwires` (`entries`, each with `effect`, `kind`, `trap` or
`class`, `target`, `source`, `count`, `firstAt`, `lastAt`, and `containmentMs` or
`sourceAddress` where present; `overflow`; `updatedAt`). Only the broker's ServiceAccount may
write a sandbox's status, and its RBAC is `patch` on the subresource: nobody marks a sandbox
tripped by hand.

## Past the jail: the twelve classes of ADR-0070

Every class is `report` by default and is set in the `tripwires` section. A class may be set to
`trip` only where it can be scoped to one claim and not on the authorizer's word: three classes,
`foreign_route`, `unknown_route` and `audience_outside_rendered`. `trip` on any other refuses the
start.

| Class | Kind | Scope | May trip | Default | Means | Look at |
| --- | --- | --- | --- | --- | --- | --- |
| `identity_shape` | `protocol` | none | no | `report` | a valid SVID of the trust domain in none of the shapes the sandbox listener admits was presented at the handshake (the listeners' `spiffe://<td>/gateway` included, while `accept_plain_gateway_identity` is off) | the peer's SPIFFE ID in the line; the SPIRE entries that could issue it |
| `foreign_route` | `protocol` | claim, node or authorizer | yes | `report` | an admitted identity called a route of another kind: a claim on a node or gateway route, a node on `POST /v1/token` or a gateway route, the authorizer on anything but its own | the peer and the route template; for a claim, which process holds its SVID |
| `unknown_route` | `protocol` | claim, node or authorizer | yes | `report` | a request on the sandbox listener for a path the router does not serve | first, version skew: a guest newer than the broker |
| `no_record` | `protocol` | none | no | `report` | a claim identity whose uid has no record at all, or a node whose EK hash is not registered, on any route but `POST /v1/nodes` | the runbook below: it has honest sources |
| `audience_outside_rendered` | `protocol` | claim | yes | `report` | `POST /v1/token` for an audience in no route the claim's guest was handed (`status.record.rendered`) | the claim, the audience in the audit line, and who holds the claim SVID |
| `claim_never_issued` | `protocol` | authorizer | no | `report` | the gateway's authorizer asked about a uid the store never held, live or ended | the gateway the batch names; a datastore restore |
| `credential_outside_inject` | `protocol` | authorizer | no | `report` | the authorizer asked for a credential for an audience that is not gateway-placed for that claim | the gateway; its authorizer's integrity |
| `deny_outside_rendered` | `protocol` | claim | no: the claim is named by the authorizer, whose identity every gateway shares | `report` | a gateway reported a deny for an authority in no route or destination of that claim's `rendered` | the claim and the authority; an image pull redirected off the rendered routes |
| `gateway_port` | `segment` | none | no | `report` | a new TCP connection from the sandbox interface to a port the gateway does not serve | the source address (forgeable on a shared segment), the port, other gateways' probes |
| `gateway_output` | `segment` | none | no | `report` | a gateway user's new connection that its output chains drop | the user, where the line names one; the reader's own log for which rule |
| `pool_inbound` | `segment` | none | no | `report` | a new inbound TCP connection to a pool VM | the source address (forgeable) across several pool VMs' reports |
| `pool_output` | `segment` | none | no | `report` | a new TCP connection out of a pool VM that its host table drops | the port; it counts every uid, the workload's included |

A class with no `rendered` to compare with is not judged: `audience_outside_rendered` and
`deny_outside_rendered` look only at a claim under a policy whose bundle the broker holds, so a
deployment with no `policy` section gets neither. Deliberately **not** a class, because honest
runs produce them: a request for a claim released a moment ago; an audience or a route rendered
and since narrowed by a newer bundle; `no_claim` for a node not bound yet; a malformed body; a
wrong method on a known path. Not classified either, because another refusal comes first: a
foreign peer on `POST /v1/me/trip` under `off` or on `POST /v1/me/logs` with logs off (both
`501`), and a body the JSON extractor refuses.

A claim-scoped class at `trip` ends its claim exactly as ADR-0069 does (`tripped` with kind
`protocol` and source `peer`, the release, `Tripped` with reason `protocol`), after the answer
is sent. The answer itself is byte for byte what it would be at `report`. The authorizer's
classes never end anything: every gateway shares that identity, and acting on it would be an
outage any holder could cause. `deny_outside_rendered` records only for the same reason: the
claim it names comes from the authorizer's batch, so at `trip` any holder of that identity could
end any live claim. A node's classes record the node; the claim bound to it, if any,
is ended where the class is at `trip`.

`unknown_route` can be set to `trip`. Then a version-skewed guest that calls a route an older
broker lacks ends its own claim. Keep it at `report` across every upgrade; a scope of its own or
a start-up refusal would change that (ADR-0070 open question 5).

### The runbook, class by class

- **`identity_shape`.** Something holds an SVID of your trust domain that the broker never
  declared. Find which SPIRE entry could issue that SPIFFE ID (the line names it) and who
  created it; the admission policies on `ClusterStaticEntry` are the control.
- **`foreign_route`.** A claim's SVID used on a node route, or a node's on the token route, is not
  something the guest or the proxy does. Read the peer and the route template, then the guest's
  journal on that VM. Under a claim identity this is the class to move to `trip` first, after the
  soak.
- **`unknown_route`.** Almost always a guest and a broker of different releases. Check the
  versions of both before anything else.
- **`no_record`.** Honest sources: a node removed from the register after `store.node_grace_secs`
  (ADR-0039) while its guest still polls `GET /v1/me`; a restore of the datastore, which forgets
  claims and nodes created after the backup; and nothing at all at a low retention, where the
  class is not judged (below). Otherwise an identity minted for a claim or a node the broker
  never had. It is `report` only.
- **`audience_outside_rendered`.** The claim's SVID asked for an audience its guest was never
  handed. The proxy does not do that. Look at who else holds the SVID on that VM (a process of
  the sandbox uid outside the jail, or root).
- **`claim_never_issued`.** A gateway asked about a claim the store never held. After a datastore
  restore it is expected for claims created after the backup; otherwise suspect the gateway.
- **`credential_outside_inject`.** A gateway asked for a credential the broker would never place
  for that claim. Suspect the gateway's authorizer.
- **`deny_outside_rendered`.** A gateway refused an authority the claim was never handed. The
  proxy refuses such a host on the VM, so either the claim's SVID is used elsewhere or an image
  pull was redirected off the rendered routes. Remember the report is the word of whoever holds
  the authorizer identity, which is why the class only records.
- **`gateway_port`, `pool_inbound`.** A dropped SYN proves nothing about its sender, and the source
  address can be forged on a shared segment. Their worth is the pattern: one source reported by
  several machines.
- **`gateway_output`.** A gateway user dialled outside its lane. `gateway_output_refused` and
  `gateway_output_ipv6` can also move for an honest claim whose allowed name resolves to a
  refused or an IPv6 address.
- **`pool_output`.** The host table knows no uid, so the workload's own dropped connections count
  here too. During a claim it proves nothing about anything outside the jail.

## The gateway's and the pool's probes

**On the gateway**, the host table (`image/gateway/nftables.conf.in`) counts by name what it drops:
`gateway_port` on a rule added in front of the input chain's last drop (new TCP connections, with
the source address and port kept in the set `probe_sources`, 4096 elements, five minutes each),
and `gateway_output_{sandbox,imds,wireserver,broker,authorizer,relay,agent,loopback,ipv6,refused}`
on the output chains' dropping rules. The unit `mediatore-gateway-probes.service`, started every
30 s by `mediatore-gateway-probes.timer`, runs `mediatore gateway-probes --dir
/run/mediatore-gateway/probes` as the user `mediatore-probes` with `CAP_NET_ADMIN` alone and no
socket family but netlink. Its directory, `2750` and setgid, the reader's user's and the
authorizer's group's, comes from the image's tmpfiles.d entry
(`/usr/lib/tmpfiles.d/mediatore-gateway.conf`), made at boot before any unit starts: the unit
names it in `ReadWritePaths=`, and systemd sets the unit's mount namespace up before any setup
step, so a directory the unit made itself would not exist in time (the reader of v0.5.0-rc.1
failed every run that way, `226/NAMESPACE`). The unit has no step that runs as root. The reader reads and zeroes the set and the counters
(`nft -j -n reset`) and writes `summary.json` into its own directory. The authorizer
(`mediatore gateway --probes-dir`, that directory by default) opens it without following a link
and without waiting on a FIFO, takes only a regular file of at most 64 KiB, never writes it, and
sends at most 64 probes on its next batch of decisions; a summary already there when the
authorizer starts is taken as read. Off the image the directory is absent and no probe is
reported, silently. At the broker each probe is one `gateway probe` line at `warn`, never stored
and never put on a claim. The decisions route takes at most 20 batches a second for the gateways'
shared identity (`429 too_many_batches` past it) and judges the denies of at most 4 batches at
once.

**On a pool VM with gateways**, the host table (`image/host-table`) counts new TCP connections in
`pool_inbound` (IPv4, with the set `inbound_sources` by source address and port, 4096 elements)
and `pool_output` (with the set `output_ports` by port, 1024 elements), each on a rule added in
front of its chain's last drop. The guest reads them every 60 s and reports what moved as
`segment` events on `POST /v1/me/trip`, which a registered node may send with no claim. The
broker writes each as one audit line with no claim, never on the node's claim even when it has
one, since a source address on the segment can be forged. This holds under `policy.traps: off` too
since the amendment of 2026-11-27: the route takes a report of `segment` events alone in every
mode and answers `501` under `off` to anything else. A pool
with no gateways loads no host table, and the reader then has nothing to read.

Limits: TCP only for `gateway_port` and the pool's classes; a full set still counts but names
nothing, and what it could not name is a count with no port (logged, never reported under an
invented port); the resets of a set and of the counters are separate dumps, so a remainder may
be off by a packet; the source address is never mapped to a node yet (every probe is
unattributed); root on the gateway or the pool VM can silence the reader. No probe ends anything,
whatever the configuration says.

## Configuration reference

| Key | Values | Default | Refused at start |
| --- | --- | --- | --- |
| `policy.traps` | `off`, `shadow`, `enforce` | `off` (and `off` with no `policy` section) | any other value (the YAML parser's `unknown variant`); `enforce` with `policy.audience_definitions.mode: bundles` |
| `policy.traps_denied` | a map of `loopback_port`, `private_range`, `unknown_host` to `report` or `trip` | `report` for each | an unknown class or value (`unknown field`, `unknown variant`) |
| `audiences[].traps_body` | `match`, `skip` | `match` | an unknown value; only for audiences defined in the broker's file |
| `tripwires` | a map of the twelve classes above to `report` or `trip` | `report` for each | an unknown class or value; `trip` on a class that may not trip |
| `store.retention_secs` | seconds | 3600 | nothing: at 900 or less `no_record` is not judged, and the start says so |

The refusals, verbatim:

```text
policy.traps is enforce but policy.audience_definitions.mode is bundles: a bundle-defined audience cannot be marked traps_body: skip yet, so an agent that quoted a bait value to its model API would end its own run; run shadow, or define the audiences in this file (ADR-0069 decision 5)
tripwires.<class>: trip is refused, this class records only: a segment class proves nothing about its sender, a class of the authorizer's or on its word (a reported deny names a claim any holder of the shared authorizer identity could name) must not end one, and a class with no scope has no claim to end (ADR-0070 decisions 5 and 6); set it to report or leave it out
```

Mark a model API `traps_body: skip`, so an agent that read a bait file and quoted it to its model
is not ended for discovering it; its headers, path and query are still matched:

```yaml
audiences:
  - name: anthropic
    via: secret
    traps_body: skip
    # ...
policy:
  trusted_keys:
    - { id: "notaio:v1", public_key: "<base64 of a 32-byte Ed25519 public key>" }
  traps: shadow
  traps_denied: { loopback_port: report, private_range: report, unknown_host: report }
tripwires:
  foreign_route: report
  unknown_route: report
  audience_outside_rendered: report
  deny_outside_rendered: report   # report only
```

`no_record` needs an ended claim's record to outlive its SVID: at a `store.retention_secs` not
above the claim SVID's lifetime (`MAX_CLAIM_SVID_TTL`, 900 s) it is not judged at all, the node
case included, and the broker says so once at start. The kind tiers run with a retention of 0.

The start log says what the broker understood:

```text
tripwires on the VM are off: guests are handed no traps and POST /v1/me/trip answers 501 (policy.traps, ADR-0069)
tripwires on the VM are armed: under enforce a trip ends its claim, under shadow it is recorded and ends nothing (policy.traps, ADR-0069)
a class at trip: an event of this class ends the claim it is scoped to (policy.traps_denied, tripwires)
the no_record class is not judged: store.retention_secs is not above the claim SVID's lifetime, so a claim released a moment ago has no record while its SVID is still valid (ADR-0070 decision 3)
```

## Log lines to search for

No line carries a bait value, a phantom, a request path, a query, a header or a body; the
broker's request span names the method and the matched route template only
(`request{method route}`).

**The broker:**

| Line | Level |
| --- | --- |
| `trip reported` (claim_uid, subject, node, id, mode, effect, kind, trap, class, target, source, source_address, count, containment_ms, at): the audit line of ADR-0069; for a `segment` event `claim_uid` and `subject` are empty, since it is never put on a claim | `warn` when either mode is `enforce` or the kind is `segment`, else `info` |
| `claim ended by a trip: entry retracted, record revoked (ADR-0069 decision 9)` | `warn` |
| `tripped could not be put on the record; the claim is released all the same` | `warn` |
| `release after a trip failed; the claim is not released` | `error` |
| `the trip summary could not be written; the audit lines stand` | `warn` |
| `a trip report was made under another mode than the broker's (policy.traps changed during the claim); enforce is followed where either says it` (never for a report of `segment` events alone) | `warn` |
| `trip report rate-limited (ADR-0069 decision 8)` | `info` |
| `exit for a claim a trap ended: nothing written, nothing deleted (ADR-0069 decision 9)` | `info` |
| `a trap ended the claim while its exit was written: its sandbox is not deleted (ADR-0069 decision 9)` | `info` |
| `the record could not be read again before an exit's release; the sandbox is not deleted` | `warn` |
| `gateway decisions rate-limited: the batch is neither logged nor judged` (gateway, decisions, probes, per_second) | `info` |
| `batches of decisions not judged for deny_outside_rendered: as many were being judged as the broker allows at once; each was answered as always` (batches, max_judging; once a flush) | `warn` |
| `sandbox tripped: its record is released and its claim deleted, never recreated (ADR-0069 decision 9)` (the reconciler, once) | `warn` |
| `a refusal no honest build earns (ADR-0070 decision 8)` (class, scope, action, peer, route, claim_uid, audience, authority, count, first_at, last_at): the audit line of ADR-0070, one a minute per class, peer and claim | `warn` |
| `classified refusals of more peers than the table holds: counted, their peers not kept (ADR-0070 decision 8)` | `warn` |
| `the claim of a node could not be read for a classified refusal; nothing is recorded on it` | `warn` |
| `gateway probe` (kind, class, gateway, count, port, source_address, user, at) | `warn` |

**The guest and the proxy, on the VM** (`journalctl -u mediatore-guest`):

| Line | Level |
| --- | --- |
| `the claim's traps are armed (ADR-0069)` | `info` |
| `the claim's traps could not be armed: under shadow the claim runs unarmed (ADR-0069 decision 5)`, and the same for `the egress proxy could not be armed` | `warn` |
| `... under enforce no jail starts (ADR-0069 decision 5)` (the error of a failed arming) | `error` |
| `the trap listener's drawn port was taken before it could be bound: drawing again` | `warn` |
| `the trap listener accepted a connection that names no decoy: noted as a use, closed unanswered` | `warn` |
| `traps armed: every request is checked before it is forwarded (ADR-0069)` (the proxy) | `info` |
| `a decoy route was named at the proxy: nothing is forwarded, resolved or tunnelled (ADR-0069)` | `warn` |
| `bait in a request's method, path, query or headers at the proxy (ADR-0069)` (its `host` is `invalid` when no route matched) | `warn` |
| `the guest decided a trip: every request is 403 trap from here (ADR-0069 decision 7)` (the proxy) | `error` |
| `the bait matcher stopped on a request body at the proxy (ADR-0069)` | `warn` |
| `a request body in an encoding the bait matcher cannot read: 415 under enforce, forwarded unscanned under shadow (ADR-0069 decision 6)` | `warn` |
| `the proxy could not finish scanning a request body: under enforce it refused the request, nothing unscanned left; nothing is ended and nothing is reported to the broker` | `warn` |
| `a trap was used: the sandbox uid's network is cut and the jail is killed (ADR-0069 decision 7)` (kind, trap, class, containment_ms) | `error` |
| `a trap was used; nothing is ended` (under `shadow`, once per new event) | `warn` |
| `nft refused the cut: the sandbox uid's network is NOT cut; the jail is killed all the same` | `error` |
| `the run was ended by a tripwire and the broker was told (ADR-0069)` | `warn` |
| `the run was ended by a tripwire and the broker did not acknowledge the report in time: ...` (after 120 s; the teardown goes ahead, the cut and the user stay) | `error` |
| `the run ended as a trap was used: it is the tripped run, no exit is reported (ADR-0069 decision 7)` | `warn` |
| `a trap was used and the tripwire's decider is gone: the supervision is signalled without the cut` | `error` |
| `a trap was used again after the trip and the tripwire's queue did not take it: the use is not reported` (at the 1st, 2nd, 4th ... drop) | `warn` |
| `the proxy could not be told of the trip: the cut and the kill stop it` | `warn` |
| `a peer that is not the sandbox uid on the trap socket: refused`, `a peer without a credential on the trap socket: refused`, `a second connection on the trap socket: refused, the draw is handed over once` (each at the 1st, 2nd, 4th ... refusal, with `refusals`) | `warn` |
| `the trap socket is closed: every request is 403 trap from here and the proxy ends, and the claim with it (ADR-0069 decision 7)` | `error` |
| `the broker refused the trip report: it is not sent again` | `error` |
| `no host table is loaded (a pool with no gateways loads none): the segment reader has nothing to read (ADR-0070 decision 4)` | `info` |
| `the host table dropped connections its full set could not name: counted, not reported` | `warn` |

The kernel's log prefix `mediatore-sandbox decoy other uid: ` is a uid other than the sandbox's
opening a connection to a decoy port: dropped and counted, never a trip. The prefix
`mediatore-sandbox trap port direct: ` is a connection made to the trap listener's own port
rather than redirected to it, by any uid: dropped and counted, never a trip.

**The gateway:**

| Line | Level |
| --- | --- |
| `the host table dropped what no honest machine sends (ADR-0070 decision 4)` (the reader; counter, packets) | `warn` |
| `more sources probed the gateway than one summary names; the rest are in its last probe as a count` | `warn` |
| `the probes summary does not read; no probe is reported from it (ADR-0070 decision 4)` (the authorizer) | `warn` |
| `probes not reported to the broker: the summary does not pass the batch's check (ADR-0070)` | `warn` |

## What is built, and what is not

Built and `off` or `report` by default: everything above but the items below.

**Not built:**

- **OpenTelemetry** for either ADR: no exporter exists (roadmap 15). The audit lines and the
  status are the record.
- **The deployment's own catalogue** (the bundle's `traps` section), **`traps.body` in a
  `SandboxAudience` bundle** and the admission code `P017`: the bundle schemas are notaio's. A draw
  is made from the public seeds, generated entries and entries derived from the claim's routes;
  see [the policy bundle](the-policy-bundle.md#traps-not-yet-in-the-bundle).
- **The mapping of a probe's source address to a node**: deferred; every probe is unattributed.
- **Chaff ports** (below): a follow-up ADR.

**Proven, and how:**

| What | How |
| --- | --- |
| The draw, the matcher, containment against a fake `nft`, the proxy's refusals, the route, the record, the summary, every class, the canary scans | hermetic: unit and e2e tests in `make check` |
| Every drawn port trips from a real jail, through the redirect to the trap listener; nothing open under `off`; after a trip nothing of the uid leaves and no jail process remains; containment with the broker unreachable; bait files and `env` trip nothing; a closed port Landlock refuses trips nothing; the jail cannot read its connect ports, and lists no decoy port in any table it can read (the listeners it sees are the trap listener, which Landlock refuses it, and the proxy's); the metadata redirect | live on the build host: nine tests of `crates/mediatore/tests/jail_exec_live.rs` in a throwaway namespace, a debug build ([testing](testing.md#tripwires-by-hand-on-the-build-host)) |
| The host tables' counters move per class and not for honest traffic; the reader holds `CAP_NET_ADMIN` alone | live on the build host's kernel, in fresh network namespaces; the image checks |
| `status.tripwires` in both served versions and a `tripped` record failing its sandbox | kind: `make kind-e2e-sandbox` (the status written by hand, as the broker writes it) |

**Not proven:** anything on a booted VM; the real guest end to end with the real proxy;
`POST /v1/me/trip`, the classifier and the broker's own status write against a real API server
(no kind tier runs with traps on); the gateway's probes and the request span outside the
process; a release-build containment figure; Azure; the shadow soak; `enforce` with Claude Code
on the homelab; the matcher's latency and memory.

## Known limits

- **A workload that knows how mediatore works.** The credential traps mostly catch generic
  attacks; a workload that knows a sandbox never holds a real credential ignores them. The `port`
  traps have a limit of the same kind: such a workload can tell which ports are admitted to it
  without touching a listener, and so which to leave alone. A follow-up ADR adds chaff ports,
  admitted with nothing listening, any use of which trips.
- **The jail can tell that traps are armed.** It cannot list the decoy ports, but it sees in its
  own `/proc/self/net/tcp` a loopback listener on a random port, the trap listener, which exists
  only when traps are armed (beside the proxy's pull listener, default port 18129, when the image
  is pulled through the proxy, which is no trap).
- **A body already streaming** when the guest decides a decoy-port or `denied` trip keeps
  flowing until the cut lands, about 50 ms; a body the proxy itself matched never forwards the
  bait.
- **A header name** that carries a mixed-case bait value leaves lower-cased, a transform the
  matcher does not catch (an all-upper or all-lower value is caught).
- **An exit racing a trip**: an exit never deletes a tripped claim's sandbox, but a trip written
  in the milliseconds between the exit's last read of the record and its delete is not seen.
- **A transformed value** (reversed, split, encrypted, double-encoded, compressed without saying
  so) and a value under eight bytes are not caught. The response is not scanned.
- **A body the matcher cannot finish** (over the expansion bound, or undecodable) never ends a
  sandbox: under `enforce` it is refused (`413 body_expansion`, `400 body_undecodable`) and logged
  on the VM only; under `shadow` it is forwarded. The broker does not hear of it.
- **`loopback_port` and `private_range`** see only the ports Landlock admits. Admitting the decoy
  ports lets the workload attempt them at any address; the claim's table is then their only bound.
- **A process of the sandbox uid outside the jail** can reach the trap socket and end its own
  claim. It cannot take the draw in the proxy's place: within a claim nothing of the uid runs
  before the proxy connects, and none is left from an earlier claim (the guest serves one claim
  per process, its unit kills every process left in its cgroup, pool members are single-use, and
  a uid that still has processes is never freed for reuse).
- **A third party can end a run**: a planted README that steers an agent into a decoy. That is
  the intended outcome.
- **Shadow shows part of a live draw** (one trap per event) to whoever may `get` the sandbox.
- **Attribution**: a report names no claim; the broker uses the node's live claim, else its last.
  A `segment` event is attributed to no claim at all.
- **The fold is per replica**: up to a minute of `protocol` counts is lost at shutdown.
- **Probes and `deny_outside_rendered`** are the word of whoever holds the authorizer identity,
  which is why neither can end anything.
- **Root on a pool VM or a gateway** can skip or silence its reader.

## Read next

[ADR-0069](../adr/0069-tripwires-on-the-vm-a-decoy-the-workload-takes-ends-its-sandbox.md),
[ADR-0070](../adr/0070-tripwires-beyond-the-sandbox-a-request-no-honest-build-makes.md), roadmaps 17
and 18; [the store](the-store.md) (`tripped`, `status.tripwires`, the retention sweep);
[locking down a sandbox VM's network](sandbox-network-lockdown.md) (the claim's table under a
draw); [configuration](../design/configuration.md); the threat model.
