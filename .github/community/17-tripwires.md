<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 17: Tripwires: a decoy the workload takes ends its sandbox

**Status: not started** (opened 2026-11-26). A sandbox carries decoys that no honest run of its
task has a reason to use: a loopback port that looks like a service, a route on the egress proxy
that looks like an internal API, a credential that looks real. Every trap lives on the VM and is
decided there, before anything leaves it: the gateway never sees a decoy, a bait value or the
draw, and its part is unchanged. The first use of one is taken as proof that the workload is no longer
doing what it was asked (a prompt injection, a hijacked agent, a malicious dependency), and the
sandbox is ended: the jail's network is cut and its processes killed on the VM at once, the claim
is released at the broker, and the VM goes back to banlieue. Decided in
[ADR-0069](../../docs/adr/0069-tripwires-on-the-vm-a-decoy-the-workload-takes-ends-its-sandbox.md)
(Proposed): it adds a route to the node surface, a field to the claim's record, a field and a
condition to the `AgentSandbox` status, a section to the policy bundle, and the broker's first
OpenTelemetry signals. Every trip event, and the host or port it reached for, is recorded in the
audit line and on the sandbox's status, and exported as spans and metrics.

Builds on roadmap 06 (the jail and its nftables table, ADR-0020), roadmap 07 (the egress proxy,
ADR-0025), roadmap 08 (the `AgentSandbox` status), and roadmaps 09 and 11 (the signed bundle).
Roadmap 10's gateway is not changed. Uses ADR-0033's ending of a claim from the
guest, ADR-0045's log stream and ADR-0064's status summary. The OpenTelemetry part waits on
roadmap 15's export ADR and phase 1 foundations. Roadmap 16, when it lands, lets a trip name the binary that took
the bait.

## Why

An allowlist bounds where a hijacked workload can go; it does not say whether the workload is
hijacked. Today a refusal is a log line, and a typo, a probe and an attack produce the same line,
so nothing can act on one. A decoy separates them: no legitimate run touches it, so one touch is a
signal strong enough to justify ending the sandbox without a person in the loop.

## Where it is today

- The jail's chain admits a short list of destinations and then logs and drops
  (`crates/mediatore-guest/src/net.rs`, the `mediatore-sandbox drop:` prefix). The drop is a
  kernel log line; nothing reads it.
- The egress proxy (`crates/mediatore-guest/src/egress.rs`) sees every request in the clear:
  the workload calls `http://127.0.0.1:<port>/<host>/<path>`, a `CONNECT` is `405`, and the
  proxy makes the upstream TLS itself. It already refuses a host outside the routes (`404`) and a
  foreign `Authorization` or credential header (`401`), and logs; nothing reacts.
- The gateway refuses an authority outside the claim's allowlist and reports the decision to the
  broker (ADR-0062). That report is lossy by design (a bounded queue, one attempt, decision 4) and
  the broker logs it and keeps nothing (decision 5), so it cannot carry an action.
- A claim can already be ended from the guest: `POST /v1/me/exit` (ADR-0033), under the node's
  SVID, writes the exit to the record and releases the claim (entry retracted first, then the
  record revoked; `release` in `crates/mediatore-claims/src/lib.rs`). A revoked record is refused
  by the gateway on its next ask, up to `fresh_secs` (30 by default) after the release.
- Nothing in the jail's filesystem or environment is planted.

## Invariants (proposed)

1. **A trap trips on use, never on discovery.** Listing a directory, reading a file, `env`,
   `grep -r ~` and a `netstat` do not trip. Completing a connection to a decoy port, requesting a
   decoy route, or sending a decoy credential does. Agents read everything; they should not be
   killed for it.
2. **No trap shares anything with a route the claim may use.** A decoy's port, host and
   credential are never one the claim's policy grants; admission refuses the overlap.
3. **The verdict is the guest's or the proxy's, never the workload's.** The workload has no
   identity to report with. A trip reaches the broker under the node's SVID.
4. **Containment is local and comes first.** The guest cuts the sandbox uid's network and stops
   the jail before it makes any network call of its own. The broker's release is the authoritative
   end, not the first line.
5. **A trip that cannot be reported still ends the jail.** The guest's containment does not wait
   on the broker; the report is retried until it is acknowledged or the VM is gone.
6. **The bait is random, per claim, and useless anywhere else.** Which traps exist, where they
   sit and every bait value are drawn fresh for each claim ([the draw](#the-draw-which-traps-a-sandbox-gets-is-random)).
   A value is valid nowhere (not a phantom token, not a real credential) and is not kept after
   the claim. The draw is held outside the jail.
7. **A tripped claim is never restarted.** ADR-0033's restart policy does not apply, and the
   `AgentSandbox` reconciler does not claim again on its own.
8. **Never log the bait.** A trip logs the claim UID, the trap's kind and id, the port or
   authority; never the canary value, the phantom, or a request body.
9. **Nothing bait-bearing leaves the VM.** A decoy port is a guest listener on loopback. A decoy
   route is answered by the proxy itself and is never tunnelled. A request is checked in full
   (headers, query, and the body up to the bound, question 4) **before** the proxy opens any
   connection upstream, so a request carrying bait is refused on the VM and no byte of it reaches
   a gateway. The gateway is not a trap, holds no part of the draw, and gains no route: a workload
   cannot trick it into anything about traps, because it knows nothing about them. It keeps doing
   what it does today, enforcing the claim's allowlist, and it refuses the claim once the record
   is revoked.
10. **Shadow first.** `policy.traps: off | shadow | enforce`, refused at start when it is anything
   else. In `shadow` a trap logs and reports `would_trip` and ends nothing, as ADR-0030 and
   ADR-0061 rolled out. `off` is the default (ADR-0069 decision 5): arming traps changes every
   workload's environment, which an operator turns on deliberately.

## Assume the attacker has read this

mediatore is open source, so this roadmap, the catalogues and the code that draws from them are
public, and an agent can read them before it acts. A design whose traps work only while their list
is secret is not a design. The real threat is not that an attacker predicts one sandbox's draw
(the CSPRNG prevents that); it is that they **avoid the whole catalogue**: never touch any port on
the list, never send any variable on the list. A short public list would make that easy. So the
design rests on five properties, and the ADR keeps each one:

1. **The secret is the draw, never the method.** Everything above stays public. What an attacker
   cannot have is the draw itself: CSPRNG output made in the guest at boot, which never leaves
   the VM. Reading the source tells them the shape of the space, not their sandbox's position in
   it.
2. **The space is generated, not listed.** The tables below are seeds and weights, not the space.
   Ports are drawn from the whole range (a seed port is just more likely), host names from large
   word lists combined at random, variable names from a stem, a provider and a suffix
   (`PROD_STRIPE_KEY`, `STRIPE_LIVE_SECRET`, `BILLING_STRIPE_TOKEN`). Avoiding the space means
   avoiding most of what a real machine looks like.
3. **Every deployment has a catalogue of its own that is not in this repository.** The bundle
   (question 2) adds names, hosts and shapes from the operator's own world (`acme-billing`,
   `ledger.corp.internal`), signed with the rest of the policy and kept in the organization's
   policy repository. The guest receives it over `GET /v1/me`, outside the jail. An attacker who
   has read mediatore's source has not read that.
4. **Decoys look like the real things beside them.** A decoy route is a host on the same proxy,
   reached the same way (`$MEDIATORE_EGRESS_PROXY/<host>/`), answering the same way until it trips.
   Decoy names are derived from the claim's real routes as well as from the seeds (a claim
   routed to a Git host also gets a decoy that looks like a second Git host). To avoid the decoys
   with certainty, an attacker must avoid things that look exactly like what they were given.
5. **The denied space trips too, so knowing about it does not help.** Under `enforce`, the jail
   chain's drop becomes a trip for the destinations no honest run reaches: any loopback port
   that is neither the proxy nor drawn (closed ports are traps, not only open ones), the
   link-local and private ranges, and a request to the proxy for a host that is no route. These
   do not depend on any list: the only way to avoid them is not to explore. Which of these are
   safe from false positives is what the shadow soak measures, and what it finds decides the
   enforced set (question 11).

What this does not do, and the ADR says so: a workload that touches only what it was given, and
sends data out only to its own allowed routes, trips nothing. Tripwires catch exploration, credential
theft and lateral movement. Bounding what the given routes can carry is the allowlist's job
(roadmaps 07 and 11) and, inside a route, roadmap 16's. The credential traps mostly catch
**generic** attacks (malicious packages and injected prompts that scrape every environment for
`AKIA…`, written for any machine, not for mediatore), which is most of them. A mediatore-aware
attacker who knows a sandbox never holds a real credential ignores them all, and is left with
properties 4 and 5.

## The draw: which traps a sandbox gets is random

No two sandboxes carry the same traps, and nothing outside the VM's guest knows which ones a
given sandbox carries. Each kind below has a **catalogue of possible traps**; at boot the guest
draws from every catalogue with its CSPRNG: how many of each kind, which entries, which ports, and
fresh random values for every credential. Someone who has read this roadmap, the catalogues and
the source knows what *might* be there and still cannot tell which ports are traps and which
variables are bait in the sandbox in front of them.

Rules for the draw:

1. **Fresh per claim, at boot.** Not in the image, not in the bundle, not on the claim's record,
   not in `GET /v1/me`, and not logged at `info`. Two claims from one image and one policy differ.
2. **The count is random too.** Each kind draws between a floor and a ceiling (proposed: two to
   five decoy ports, one to three decoy routes, three to six credentials), so the number of traps
   says nothing either.
3. **Values are random within a real shape.** A credential is the provider's prefix, length and
   alphabet filled from the CSPRNG (with the provider's checksum where it has one, so it passes a
   scanner's offline check). No value is kept after the claim, and none is valid anywhere.
4. **Exclusions are applied after the draw, never instead of it.** A drawn entry that collides
   with something the claim really uses is dropped and redrawn (see the rules under each
   catalogue), so the exclusions do not shrink the space to something predictable.
5. **The draw is held outside the jail.** The guest (root) and the proxy know it; the workload sees
   only the bait.
6. **A deployment can widen a catalogue** in the bundle (question 2): more ports, more host names,
   more variable names with a format from the fixed set of generators. Never a literal value, and
   never a narrowing to a fixed set. The bundle's additions are weighted above the public seeds,
   so most of a sandbox's traps come from the part an outside attacker has not seen.
7. **The tables below are seeds.** Each draw mixes seed entries, generated entries (property 2
   above) and entries derived from the claim's real routes (property 4), in proportions the ADR
   fixes.

## The catalogues of possible traps

### Decoy ports

Listeners the guest (root, outside the jail) opens on loopback; the jail's chain admits the
sandbox uid to the drawn ones. A trip is a completed TCP handshake from the sandbox uid. Each
answers with a plausible first line (an SSH banner, a Redis `-NOAUTH`, an HTTP `401`) so a probe
sees a service, not a closed port.

| Port | Looks like |
| --- | --- |
| 22 | SSH |
| 23 | telnet |
| 25 | SMTP relay |
| 2375, 2376 | the Docker API |
| 3306 | MySQL |
| 5000 | a registry |
| 5432 | PostgreSQL |
| 5672, 15672 | RabbitMQ and its admin page |
| 6379 | Redis |
| 6443 | the Kubernetes API |
| 8080, 8081 | an admin or dev server |
| 8200 | Vault |
| 8500 | Consul |
| 9000 | an object store console |
| 9200 | Elasticsearch |
| 10250 | the kubelet |
| 11211 | memcached |
| 27017 | MongoDB |
| `169.254.169.254:80` | a cloud metadata service (the sandbox uid's packets redirected to a drawn loopback listener; ADR-0068's drop holds for every other uid) |
| any other port in 1024 to 65535 | a forgotten dev server; at least one per draw, answering as an HTTP server |

The seed ports above are only more likely than the rest. Under `enforce`, a connection to a
loopback port that was not drawn at all also trips (property 5), so a scan finds no safe gap.

Excluded after the draw: the proxy's port, the pull listener's port, any port the image's
workload is declared to serve.

### Decoy routes

Hosts the egress proxy carries as routes that are no audience, advertised to the workload by a
variable pointing at the proxy (`VAULT_ADDR=http://127.0.0.1:<proxy>/<host>/`). Any request that
names one trips. The host name is drawn too, from a stem and a suffix, so it is not one fixed name
per service.

| Variable | Stems | Suffixes |
| --- | --- | --- |
| `VAULT_ADDR` | `vault`, `secrets`, `kv` | `.internal`, `.prod.internal`, `.corp.internal`, `.svc.cluster.local` |
| `CONSUL_HTTP_ADDR` | `consul`, `discovery` | as above |
| `ADMIN_API_URL` | `admin`, `backoffice`, `ops` | as above |
| `JENKINS_URL` | `jenkins`, `ci`, `build` | as above |
| `ARTIFACTORY_URL` | `artifactory`, `nexus`, `artifacts` | as above |
| `ELASTICSEARCH_URL` | `es`, `search`, `logs` | as above |
| `GRAFANA_URL` | `grafana`, `metrics`, `dashboards` | as above |
| `METADATA_URL` | `metadata`, `instance-data` | as above |
| `SENTRY_DSN` | `sentry`, `errors` | as above, with a drawn key in the DSN (also a credential trap) |

Excluded after the draw: any host that is one of the claim's routes.

### Credentials

Random values in the shape each provider issues, set in the environment and, where the kind has
one, in the file tools read it from in the sandbox user's home (never under `/work`, where it could
end up in the requester's repository). A trip is the value in a request the proxy is asked to
forward (question 4).

| Variable(s) | File | Shape |
| --- | --- | --- |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | `~/.aws/credentials` | `AKIA` and 16 base32; 40 base64 |
| `GITHUB_TOKEN`, `GH_TOKEN` | `~/.git-credentials` | `ghp_` and 36 base62 with its CRC32 checksum, or `github_pat_…` |
| `GITLAB_TOKEN` | `~/.git-credentials` | `glpat-` and 20 characters |
| `NPM_TOKEN` | `~/.npmrc` | `npm_` and 36 base62 with its checksum |
| `PYPI_TOKEN` | `~/.pypirc` | `pypi-` and a base64 body of plausible length |
| `DOCKER_AUTH_CONFIG` | `~/.docker/config.json` | a base64 `user:password` for a drawn registry host |
| `KUBECONFIG` | `~/.kube/config` | a bearer token and a server that is a drawn decoy route |
| `HF_TOKEN` | | `hf_` and 34 characters |
| `OPENAI_API_KEY` | | `sk-proj-` and a long base64url body |
| `STRIPE_SECRET_KEY` | | `sk_live_` and 99 characters |
| `SLACK_BOT_TOKEN` | | `xoxb-` and three dash-separated parts |
| `GOOGLE_API_KEY` | | `AIza` and 35 characters |
| `AZURE_STORAGE_CONNECTION_STRING` | | `DefaultEndpointsProtocol=https;AccountName=…;AccountKey=…` |
| `DATABASE_URL`, `PROD_DB_PASSWORD` | `~/.pgpass` | `postgres://<user>:<password>@<drawn host>:5432/<db>` |
| `JWT_SIGNING_SECRET` | | 64 hex characters |
| `MACHINE_PASSWORD` | `~/.netrc` | a `machine <drawn host> login <user> password <random>` line |

Excluded after the draw:

- **Any variable a tool would send on an honest run.** Tools read these names on their own (`gh`
  reads `GH_TOKEN` before `GITHUB_TOKEN`; the AWS CLI, `npm`, `huggingface-cli` and the OpenAI
  SDK each read theirs). A tool that sends a bait value to a host the claim cannot reach is
  dropped at the jail's chain and never reaches the proxy, so nothing trips. A tool that sends it
  to a host the claim *does* reach is an honest run tripping. So an entry whose provider is one of
  the claim's routes is dropped, and so is a variable that comes earlier in a routed tool's lookup
  order than the one holding the phantom (a bait `GH_TOKEN` beside a phantom `GITHUB_TOKEN` would
  win and trip `gh`). The catalogue records each entry's provider and lookup order, and unit tests
  pin the check.
- **Any name the guest already sets** (the phantom, the proxy's address, the decoy routes'
  variables).
- **A file the image already has.** The guest does not overwrite a real `~/.npmrc`.

### Rejected: decoys at the gateway

An earlier draft put decoy hosts at the gateway's authorizer, to catch a workload that has left
the jail and holds the claim's SVID. Rejected for three reasons. The bait would have to reach the
gateway to trip, so a decision that can be made on the VM would be made one hop later, on a
component shared by every claim. The gateway would hold trap knowledge, a list an attacker could
probe for across claims, and a second place to keep secret. And it would add a route to the
authorizer's surface for a case the VM already covers: an escape from the jail is still inside the
VM, where the jail's chain, the closed-port traps (property 5) and the claim's allowlist at the
gateway all still apply.

### Rejected: a file trap

Fanotify on a bait file, tripping on read, is rejected by invariant 1: it would fire on every agent
that greps its home directory. The files above are bait; only sending what is in them trips.


## What a trip does

1. **On the VM, at once.** The guest replaces the sandbox uid's chain with a drop of everything,
   in one `nft -f` transaction, and then kills the jail's process tree (or freezes its cgroup;
   question 1). Network first, then processes. The time from the trip to the cut is measured and
   recorded in the ADR. A trip seen by the proxy refuses the tripping request itself, and the
   proxy forwards nothing more for the claim before it tells the guest.
2. **Logs.** What ADR-0045 has collected is flushed with a final line naming the trap, within a
   bounded wait.
3. **Report.** `POST /v1/me/trip` under the node's SVID: the trap's kind and id, the time, the
   port or authority. Retried with backoff until acknowledged (unlike ADR-0062's decisions).
4. **At the broker.** `tripped` is written on the record by compare-and-set (ADR-0057), and the
   claim is released as any other: the entry retracted, the record revoked, the
   `VirtualMachineClaim` deleted, so banlieue destroys the VM. The `AgentSandbox` gets a
   `Tripped` condition with the trap's kind as its reason, and the CLI shows it.
5. **At the gateway, nothing new.** The VM's network is already cut by step 1, so nothing more
   arrives from it. A gateway that is asked about the claim again finds the record revoked and
   refuses, as it does for any released claim.

## The design questions for the ADR

ADR-0069 answers these. Where it differs from a proposal below, the ADR stands: the body is
streamed through a matcher that holds back the longest pattern rather than buffered with a `413`
(decision 6); `off` is the default mode (decision 5); `denied` targets trip per class, `report`
by default (decision 10); the canaries are not kept or hashed after the claim.

1. **Kill or quarantine.** Ending the VM destroys what a responder would want to look at. The
   alternative keeps it frozen and cut off for a bounded time before the release. Proposed: kill
   by default, since a compromised VM kept running is a risk of its own and the log stream holds
   the record; quarantine as an option with a hard upper bound, if at all.
2. **Where the catalogues live.** Built into the guest, with the signed bundle able to widen
   them (more ports, host stems, variable names with a generator) in a new `traps` section, and a
   new `P` code at admission for an entry that overlaps a grant. Or broker configuration only.
   Proposed: built in, widened by the bundle; never narrowed to a fixed set, and never a literal
   value.
3. **Who draws.** The guest at boot, so the draw never leaves the VM and nothing outside it can
   tell which traps a sandbox carries. Only the guest and the proxy hold it (invariant 9).
   Proposed: the guest. Also decided here: the floors and
   ceilings of each count, and whether a sandbox may draw zero of a kind.
4. **How far the proxy looks.** Credential positions always: `Authorization` (including a
   Basic pair, decoded), the headers of `CREDENTIAL_HEADERS`, and query parameters. The body is
   where an exfiltration to an allowed route goes (a gist, an issue comment), but it is also where
   an agent's own context goes. mediatore never runs `env` or reads the bait; an honest agent
   might while debugging its own environment, and Claude Code sends whatever it read to its model
   API in the next request. That is discovery, not use (invariant 1).
   Proposed: the body is matched (up to 64 KiB, in the three encodings) on every route except
   those whose audience is marked as carrying the agent's conversation (a model API), where only
   credential positions count. Whether that mark is the audience's or the bundle's is decided
   here. A value the workload transforms first (reversed, split, encrypted) is not caught; the
   ADR says so, and the decoy ports and routes remain.

   **Hold, check, then forward.** Today the proxy streams a body upstream as it arrives. Under
   `shadow` and `enforce`, on a route whose body is matched, it holds the headers and the body up
   to the bound and checks them before it opens the tunnel, so a tripping request never leaves the
   VM (invariant 9). A body longer than the bound is the open part: proposed, it is refused
   (`413`) on a route that does not declare a larger limit, rather than streamed with its tail
   unchecked, since an unchecked tail is exactly where bait would be put. The memory a held body
   costs, and the latency it adds, are measured and recorded.
5. **The channel from the proxy to the guest.** The proxy runs as the sandbox user outside the
   jail; it tells the guest over a unix socket the jail cannot reach (its own directory, root
   owned, the proxy's uid admitted by the peer credential). Both are already in the trust base.
6. **Readiness.** Under `enforce`, a guest that cannot arm its traps does not report ready
   (ADR-0019), so a sandbox never runs believing it is guarded when it is not.
7. **After a trip.** Whether the `AgentSandbox` may be claimed again: never on its own; on a spec
   change, or on an acknowledgement (an annotation the owner sets). Repeated trips on one
   `AgentSandbox` back off.
8. **A self-inflicted trip.** A workload that wants its sandbox ended can already exit. A third
   party that steers an agent into a decoy (a planted README) ends a run the requester wanted:
   that is the intended outcome, and the ADR states it as the cost.
9. **What the requester sees.** The kind and the port or authority, not the trap's full layout.
   For a credential, the catalogue entry's name (`aws`, `github`), never the value. The rest
   of the draw is never shown, so a requester's account that is itself compromised learns
   nothing about the next sandbox's traps.
10. **Where the bundle's catalogue is readable.** It is signed policy, readable by whoever reads
    the policy repository. Whether trap entries go in a separate file with narrower readers, and
    whether `GET /v1/me` serves the draw's inputs only to the guest (never to the proxy, which
    needs only the drawn result), is decided here.
11. **Which denied destinations trip under `enforce`** (property 5). Candidates: closed loopback
    ports, the link-local and private ranges, an unknown host at the proxy. Known noise to
    measure first: tools that probe localhost for a local service or an IDE, package managers
    falling back across mirrors, a typo in a host. Proposed: each candidate enforced only after
    the shadow soak shows it silent on honest runs.

## Phases

### Phase 0: design

- [ ] ADR-0069 accepted (drafted 2026-11-26, Proposed).
- [x] CALM (2026-11-26): `data-asset-trap-draw`, the guest's, the proxy's and the workload's decoy
      relationships, `POST /v1/me/trip`, the record and status writes, `flow-tripwire`;
      `make calm-validate` and `make calm-diagrams` pass.
- [ ] notaio: the bundle's `traps` section agreed with its schema, if question 2 puts it there.

### Phase 1: containment on the guest

- [ ] A `trip` module in `crates/mediatore-guest`: the drop-all ruleset for the sandbox uid,
      rendered as text and pinned by tests as `net.rs` is; the jail stopped after the cut.
- [ ] Live test in `crates/mediatore/tests/jail_exec_live.rs` on the build host: after a trip a
      connection from the sandbox uid fails, no jail process remains, and the cut takes under the
      bound the ADR sets.
- [ ] A trip the broker cannot hear about still contains the jail (the broker faked down).

### Phase 2: the broker and the status

- [ ] `POST /v1/me/trip` on the node surface: the node's SVID only, the claim bound to it, the
      body validated; `tripped` written by compare-and-set, then the release.
- [ ] A tripped claim is not restarted (ADR-0033) and its token is refused at `POST /v1/token`.
- [ ] The `Tripped` condition on `AgentSandbox`, the reconciler's no-reclaim rule, the
      acknowledgement annotation, the CLI's view.
- [ ] Every event recorded (ADR-0069 decision 9): the audit line; `status.tripwires`, bounded to
      16 entries, written by compare-and-set apart from the record and ignored by the
      controller's watch filter; its CRD schema in both served versions.
- [ ] OpenTelemetry in the broker (ADR-0069 decision 11), once roadmap 15's foundations exist: the
      `mediatore.trip.report` span and its events, the five instruments, the schema additions;
      `drawn` targets exported, `workload` targets as their class only. The cardinality test and
      the bait canary scan over every exported signal.
- [ ] e2e in `crates/mediatore/tests/e2e_dev.rs`: a trip ends the claim; a trip from a
      non-node peer, from another claim's node and for a revoked claim are refused or no-ops; a
      second trip is idempotent.

### Phase 3: decoy ports

- [ ] The draw: a `draw` module in `crates/mediatore-guest`, the catalogues, the counts, the
      redraw on an exclusion. Unit-tested with a seeded RNG for the rules and a statistical test
      that two draws differ; the real draw seeded from the OS only.
- [ ] The guest's listeners for the drawn ports, each with its first line, and the jail chain's
      admission of exactly those; the link-local address.
- [ ] `shadow` and `enforce` behind `policy.traps`, refused at start when anything else.
- [ ] The generators beside the seeds: port anywhere in range, host names from word lists, variable
      names from stem, provider and suffix, decoys derived from the claim's real routes, the
      bundle's additions weighted first.
- [ ] Live test: every drawn port trips from the jail; a closed loopback port trips under
      `enforce` and is logged as `would_trip` under `shadow`; nothing is open under `off`.
- [ ] A red-team check: a script that reads this repository's catalogues and avoids every seed
      entry still trips within a bounded number of probes on a sandbox with a deployment
      catalogue, and its result recorded in the ADR.

### Phase 4: decoy routes and bait credentials at the proxy

- [ ] Drawn decoy routes (stem and suffix) in the proxy's table, refused and reported; the
      advertised variables.
- [ ] A generator per credential shape (prefix, length, alphabet, checksum), unit-tested so every
      value passes the provider's offline check.
- [ ] The credential draw's exclusions: every routed provider, every variable ahead of a phantom
      in a routed tool's lookup order, every name the guest sets itself, every file the image
      already has. Unit-tested against claims with a GitHub, an npm and a model-API route.
- [ ] Planted in the jail's environment and the matching files in the sandbox user's home before
      the jail starts; held by the guest and the proxy only, dropped with the claim.
- [ ] The proxy's matcher, unit-tested on the three encodings, the Basic pair, the body bound, and
      the model-API exemption.
- [ ] The proxy-to-guest socket, peer-credential checked.
- [ ] e2e in `crates/mediatore/tests/e2e_egress.rs`: the canary in a header, in a query and in a
      body each trip; reading the file or running `env` trips nothing; the canary in a request
      body to the model API's route trips nothing, in its `Authorization` it trips; `gh` with a
      routed GitHub phantom never picks up a canary; a legitimate route is unchanged.

### Phase 5: docs, threat model, live proof

- [ ] `docs/guides/tripwires.md`: the kinds, the modes, what a requester sees, and how to read a
      trip.
- [ ] Threat-model pass: the new route on TB-6, the proxy as a reader of
      request bodies for canaries, a trip as a denial of service a third party can cause, the
      transformed-canary gap in §8; stamp bumped.
- [ ] A false-positive soak in `shadow` on the homelab: a run of ordinary Claude Code tasks with no
      `would_trip`.
- [ ] Live on the homelab under `enforce`: a Claude Code sandbox given a planted instruction to
      send `~/.aws/credentials` somewhere is ended, its VM is gone, and its `AgentSandbox` shows
      `Tripped`.
