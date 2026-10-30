<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# The research agent, front to back

One workload, followed from the image a team publishes to the report it pushes: an agent
packaged as `ghcr.io/octocat/research-agent`, run by `octocat` in a sandbox under a policy
that [notaio](https://github.com/firestoned/notaio) certifies, on a VM that mediatore binds
to that login. Every file on this page is a placeholder you replace, and every command is
one the pieces accept today, at mediatore 0.1 and notaio v0.1.0.

> **What is proven and what is designed.** mediatore's side of this page runs in the kind
> tiers (`make kind-e2e-dex`, `make kind-e2e-sandbox`, `make kind-e2e-tpm`,
> [testing](testing.md)) with the guest in a pod; booting the VM image on a libvirt host
> is roadmap 06's live item, not yet done. notaio's side runs as notaio v0.1.0 ships it:
> the lint, the controller, the signed bundle in a ConfigMap. The one seam that is design
> only is notaio's M3: mediatore does not read, verify or relay the bundle yet, and the
> guest does not render the jail from it. Section 5 says what enforces each line of the
> policy today instead.

## The cast

| Who | What they hold | What they do here |
| --- | --- | --- |
| the agent team | the `research-agent` code | publish it as an OCI image, pinned by digest |
| the policy owner | write access to the policy repository | write the `SandboxPolicy` and its `ExposureCeiling`; notaio lints the pull request |
| notaio | its signing key, in OpenBao transit | compile the policy against the `standard` profile, sign the bundle, publish it as a ConfigMap |
| the operator | the broker's config, the pool, the VM image | declare the audience and where it is reached, the registry credential, the group |
| `octocat` | a login at Dex, membership of the group | `mediatore login`, `mediatore sandbox create` |
| mediatore | the issuer's trust, its own STS key | validate the login, create the claim, bind the identity, mint the audience tokens |
| banlieue | the pool of attested members | bind one member to the claim, destroy it at the end |
| the member | its vTPM, the guest | attest, register, pull the image, run the agent in the jail, tear down |
| `git.home.example` | the repositories | the one place the agent reads from and writes to |

## 1. The image the team publishes

The workload image is an ordinary container image: the runtime, the agent, its tools. Not
the VM, and nothing of the sandbox machinery ([what "the workload"
is](running-workloads.md#what-the-workload-is)). Three things make an image fit this
platform, and all three are absences.

- **No credential in it.** The agent never holds one: the jail's environment carries a
  phantom token and the address of the egress proxy on the VM's loopback, and the proxy
  swaps the phantom for the real token on the way out
  ([ADR-0025](../adr/0025-phantom-token-egress-proxy.md)). The image ships no client, no
  token file and nothing at `/usr/bin/mediatore`, where the guest mounts the one binary.
- **No listener.** Nothing inbound ever reaches a sandbox ([ADR-0010](../adr/0010-no-inbound-to-sandboxes.md)). The agent
  takes its question from its arguments and delivers its answer by writing to the audience.
- **No reliance on `/proc`, devices or setuid.** The jail mounts none of them; the rootfs is
  root-owned and read-only, `/work` is the writable directory and `$HOME` a tmpfs
  ([ADR-0021](../adr/0021-sandbox-filesystem-tmpfs-and-rootfs-from-the-registry.md)).

```dockerfile
# research-agent/Dockerfile
FROM python:3.13-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY research_agent.py /usr/local/bin/research-agent
RUN chmod 0755 /usr/local/bin/research-agent
# No ENTRYPOINT: the claim's workload.args is the argv, in full.
```

The agent's loop is short. It reads what it needs from the git host through the egress
proxy, writes its findings, and pushes. It holds no token: every request carries the
phantom from `MEDIATORE_TOKEN`, and the proxy, a process of the same sandbox user outside
the jail, replaces it with a token for `internal-git` that it fetches over the claim's SVID
and keeps to itself. A token lives 15 minutes and the broker refreshes `octocat`'s session
before every one it mints, so a login revoked at Dex ends the agent at its next request
([ADR-0013](../adr/0013-dex-session-delegation.md), [ADR-0025](../adr/0025-phantom-token-egress-proxy.md)).

```python
#!/usr/bin/env python3
# research_agent.py, the shape of it: one audience, the phantom on every call, the answer pushed.
import os, subprocess, sys, datetime

QUESTION = sys.argv[1]
# The jail's only way out: http://127.0.0.1:3128/<host>/<path> goes to https://<host>/<path>.
GIT = f"{os.environ['MEDIATORE_EGRESS_PROXY']}/git.home.example"
PHANTOM = os.environ["MEDIATORE_TOKEN"]   # useless anywhere but at that proxy

def git(*args: str) -> str:
    return subprocess.check_output(
        ["git", "-c", f"http.extraheader=Authorization: Bearer {PHANTOM}", *args],
        text=True, cwd="/work",
    )

git("clone", "--depth", "1", f"{GIT}/platform/services.git", "services")
findings = research(QUESTION, "/work/services")        # the agent's own work
branch = f"research/{datetime.date.today():%Y-%m-%d}"
git("-C", "services", "switch", "-c", branch)
open("/work/services/REPORT.md", "w").write(findings)
git("-C", "services", "add", "REPORT.md")
git("-C", "services", "-c", "user.name=research-agent",
    "-c", "user.email=research-agent@home.example", "commit", "-m", f"research: {QUESTION}")
git("-C", "services", "push", "origin", branch)        # the proxy refreshes the token itself
```

Build for the pool's architecture, push, and record the digest. The digest is what the
claim names: a tag is whatever the registry says at bind time, a digest is the bytes the
guest verified, and the guest logs the manifest digest it pulled with the claim.

```sh
docker build --platform linux/amd64 -t ghcr.io/octocat/research-agent:2026-10-28 research-agent/
docker push ghcr.io/octocat/research-agent:2026-10-28
crane digest ghcr.io/octocat/research-agent:2026-10-28
# sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
```

The guest pulls `tar` and `tar+gzip` layers, which is what `docker build` and `buildx`
produce by default; zstd layers are refused.

## 2. The policy notaio certifies

notaio's unit is the `SandboxPolicy`: a profile, who may claim under it, which audiences
with which access, what else it may reach, which tools. The profile fixes every knob the
policy does not mention, and a lint refuses a policy that asks for more than its profile
allows. The research agent fits `standard` ("everyday engineering work", data scope
`Internal`): one audience (K5.3 at R1), write access to it (K5.2 at R1), tokens of at most
900 seconds (K5.1 at R1). `hardened` would refuse the write (lint L006); `lab` is for
non-production data.

```yaml
# policy/research-agent.yaml, in the policy repository notaio lints on every pull request
apiVersion: sandbox.firestoned.io/v1alpha1
kind: SandboxPolicy
metadata:
  name: research-agent
  namespace: sandboxes
spec:
  profileRef: standard
  subjects:
    # The identity provider's group id, as the login's `groups` claim carries it.
    groups: ["firestoned:research"]
  # standard is K5.3 R1: one audience. K5.2 R1 allows Write; K5.1 R1 caps the token at 900 s.
  audiences:
    - name: internal-git
      access: Write
      scopes: ["repo:read", "repo:write"]
      ttlSeconds: 900
  # No direct egress: the audience's host is reached as the audience, nothing else is.
  egress: []
  tools: []
  lease:
    maxDurationSeconds: 3600
    maxConcurrent: 1
---
# No ceiling, no bundle (notaio ADR-0007): the policy may never exceed this, whoever edits it.
apiVersion: sandbox.firestoned.io/v1alpha1
kind: ExposureCeiling
metadata:
  name: research-agent
  namespace: sandboxes
spec:
  audiences:
    - { name: internal-git, access: Write, maxTtlSeconds: 900 }
  egressHosts: []
  tools: []
  maxLeaseSeconds: 14400
  approvals:
    - { role: Security, reference: https://github.com/octocat/sandbox-policy/pull/12 }
```

Two things the policy does not say, on purpose:

- **Which image.** A `SandboxPolicy` has no image field. What the profile fixes is the
  *Image source* knob, K8.1: `R0` under `fortress` and `hardened`, `R1` under `standard`,
  `R2` under `lab`, with what each step permits defined by the AgentSandbox threat model's
  register (its section 9), which notaio transcribes. The image itself is the claim's,
  named per request by the user, and pinned by digest by convention.
- **Where `internal-git` lives.** The audience is a name. The host it resolves to, and the
  credential that opens it, are the operator's, in the broker's config (next section).

The pull request runs the lint; the merge applies the objects; the controller does the
rest. `notaio lint` exits 1 on an error finding, 2 when a file cannot be read.

```sh
notaio lint policy/                                   # in the policy repository's CI
kubectl apply -f policy/research-agent.yaml           # the GitOps reconciler, on merge
kubectl -n sandboxes get sbpolicy research-agent
# NAME             PROFILE    VERSION   READY   AGE
# research-agent   standard   3         True    41s
kubectl -n sandboxes get configmap research-agent-bundle -o jsonpath='{.data.bundle\.dsse\.json}' | jq .payloadType
# "application/vnd.firestoned.sandboxpolicy.bundle.v2+json"
```

The ConfigMap is named after the policy, carries one key, `bundle.dsse.json`, and the
annotations `sandbox.firestoned.io/bundle-version` and `sandbox.firestoned.io/bundle-digest`.
The envelope is DSSE, signed with notaio's ed25519 key in OpenBao transit (key id
`notaio:v1`); its payload names the policy, the profile and its digest, every knob at its
effective step, the audiences, the egress, the tools, the lease and the budgets, and a
content digest over the canonical form. A consumer verifies the signature against a key it
got from somewhere other than the ConfigMap, then its own version floor, then acts
(notaio's *consume a bundle* guide).

## 3. The operator's side

What the policy names, the broker's config makes concrete
([deploying](deploying.md), [the homelab overlay](https://github.com/firestoned/mediatore/blob/main/deploy/overlays/homelab-example/mediatore.yaml)):

```yaml
# mediatore.yaml, the parts this walkthrough touches
issuers:
  - url: https://dex.home.example
    backend: sts
    client_id: mediatore
    subject_claim: preferred_username
    # The group a login must carry to claim at all. One gate for the broker today; the
    # policy's subjects.groups is the per-policy version, which M3 brings.
    required_group: firestoned:research
    session: { client_id: mediatore }
audiences:
  # The audience the policy names, with its ceiling, and the one host the jail may open
  # for it (ADR-0020). Without egress the agent gets tokens it can spend nowhere.
  - { name: internal-git, via: sts, max_ttl: 900, egress: ["git.home.example:443"] }
registries:
  # The agent image is in a private GHCR package: a read-only token, from a Secret the
  # Deployment mounts, handed to the guest for this one pull (ADR-0022). Never the user's.
  - { host: ghcr.io, username: octocat-pool, password_file: /etc/mediatore-registry/ghcr }
sandboxes:
  namespace: sandboxes
```

```sh
# The pull token: a GitHub fine-grained token or robot account with read:packages only.
kubectl -n banlieue-system create secret generic mediatore-registry --from-file=ghcr=./ghcr-read-token
```

`git.home.example` validates the `sts` tokens against the broker's JWKS
(`https://mediatore.home.example/.well-known/jwks.json`): `aud` is `internal-git`, `sub` is
`octocat`, and the RFC 8693 `act` claim names the sandbox's SPIFFE ID, so the git host can
tell a sandbox acting for `octocat` from `octocat` at a keyboard, and from any other sandbox
([ADR-0003](../adr/0003-token-backends.md)).

The pool is a `VirtualMachinePool` of `GuestReady` members ([requesting a sandbox](requesting-a-sandbox.md#the-pool-must-use-guestready))
booting the VM image of [ADR-0023](../adr/0023-sandbox-vm-image-kairos-derivative.md):
Kairos, the SPIRE agent attesting the member's vTPM, the one `mediatore` binary, `nsjail`
and `nftables`. One VM image serves every workload image.

## 4. The run

`octocat` logs in once, at Dex, as mediatore's own public client (PKCE, loopback
redirect); the CLI keeps the session and, on the claim, delegates its refresh token to the
broker and forgets it.

```sh
mediatore login --issuer https://dex.home.example
# logged in as octocat at https://dex.home.example

mediatore sandbox create --mediatore https://mediatore.home.example \
  --pool research --ttl 3600 \
  --audience internal-git \
  --image ghcr.io/octocat/research-agent@sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 \
  --arg /usr/local/bin/research-agent \
  --arg "which services still call the v1 ledger API?"
# sandbox-7c2e91a4	Pending	ready=false
```

The broker validates the login (issuer, signature, audience, the group), parses the image
reference (one it cannot parse is refused with `400 invalid_workload_image`), checks the
audience is one it serves, seals the delegated refresh token into its store, and creates
the `AgentSandbox` with `spec.subject` `octocat`. From there
([running workloads](running-workloads.md#path-a-a-user-directly) has the sequence
diagram):

1. mediatore creates the `VirtualMachineClaim`; banlieue binds a member that attested its
   vTPM at boot and registered with the broker over mTLS; the claim's SPIFFE entry is
   declared as a `ClusterStaticEntry` with the member as parent and the sandbox user as
   selector ([ADR-0006](../adr/0006-registration-entries-as-clusterstaticentry.md)).
2. The guest on that member fetches the claim over mTLS with its node SVID: the subject,
   the deadline, `workload`, the `egress` of the claim's audiences and the proxy's routes
   for them (the audience, the endpoint, its rules), and the GHCR credential for this pull.
3. It creates `sb-…` for `octocat`, mounts a fresh tmpfs at `/mnt/sandbox`, pulls the image
   into it (every blob checked against its digest, the manifest digest logged), loads the
   nftables ruleset keyed by the sandbox uid (the broker and `git.home.example:443` for the
   proxy's sockets, the proxy's loopback port for the jail's, DNS to the member's
   resolvers, nothing else), starts `mediatore egress-proxy` as that user with the routes
   and a fresh phantom token, and starts the argv under `nsjail` as that user with the
   phantom in its environment; inside, the binary applies Landlock to its own process
   before the argv runs, so writes stay in `/work`, `/tmp` and the home and TCP reaches
   the proxy's port only ([ADR-0024](../adr/0024-landlock-inside-the-jail.md),
   [ADR-0025](../adr/0025-phantom-token-egress-proxy.md)).

   ```
   INFO mediatore_guest::guest: node registered node_id=…
   INFO mediatore_guest::guest: workload image pulled claim_uid=… image=ghcr.io/octocat/research-agent@sha256:9f86… image_digest=sha256:9f86… layers=6 bytes=58213441
   INFO mediatore_guest::guest: sandbox ruleset loaded claim_uid=… user=sb-… uid=… destinations=3 resolvers=1 proxy_port=3128 ruleset_sha256=…
   INFO mediatore_guest::guest: egress proxy ready claim_uid=… pid=… user=sb-… listen=127.0.0.1:3128 routes=1
   INFO mediatore_guest::supervise: jail started pid=… user=sb-…
   ```

4. The agent calls `http://127.0.0.1:3128/git.home.example/platform/services.git` with the
   phantom in `Authorization`. The proxy finds the route (`internal-git`), checks the
   method and path against the audience's rules, and, holding no token yet, fetches one:
   its claim SVID from the Workload API socket (the proxy's, not the jail's), the broker
   refreshes `octocat`'s session at Dex and mints a 15-minute `sts` token for
   `internal-git`, acting for `octocat`. The request goes to `git.home.example` over TLS
   with that token in place of the phantom; the push, minutes later, reuses it, and a
   token near its expiry is replaced before the next request.

   ```
   INFO mediatore_guest::egress: token fetched for the proxy audience=internal-git expires_at=…
   INFO mediatore_guest::egress: forwarded audience=internal-git host=git.home.example:443 method=GET path=/platform/services.git/info/refs?service=git-upload-pack status=200 OK credential=true
   ```
5. The report lands on `research/2026-10-28` at `git.home.example`. The agent exits; the
   guest restarts it until the deadline, since a workload that exits early is restarted
   (the agent is idempotent: a branch that exists is a no-op).

```sh
mediatore sandbox get --mediatore https://mediatore.home.example sandbox-7c2e91a4
# {"name":"sandbox-7c2e91a4","phase":"Bound","ready":true,"addresses":["192.0.2.41"]}
kubectl -n sandboxes get agentsandboxes
# NAME               SUBJECT   POOL       PHASE   READY   AGE
# sandbox-7c2e91a4   octocat   research   Bound   true    2m
```

At the deadline, or on `mediatore sandbox delete`, the entry is retracted, the store record
revoked (tokens stop at once), the jail killed, the ruleset dropped, the tmpfs unmounted, and
banlieue destroys the member. Nothing of the run survives on it.

## 5. What enforces each line today, and what M3 changes

| In the policy | Enforced today by | Under notaio M3 |
| --- | --- | --- |
| `profileRef: standard` | nothing in mediatore: the profile is notaio's, applied at lint and compile | the bundle's knobs, verified by mediatore at every mint and by the guest before it renders the jail |
| `subjects.groups` | the issuer's `required_group`, one for the broker | the policy's groups, per policy, at the claim |
| `audiences[].name` | `audiences[]` in the broker's config; a claim naming one not there is refused before any VM exists | the same, with the policy's set as the ceiling and the version stamped into the token |
| `audiences[].access: Write`, `scopes` | not expressed: a token carries `aud`, `sub` and `act`; what it may do is the git host's authorization of `octocat` | the bundle's access and scopes, carried in the token |
| `ttlSeconds: 900` | the audience's `max_ttl` and the broker's 15-minute cap | the bundle's value |
| `egress: []` and the audience's host | the audience's `egress` in the broker's config, rendered by the guest into nftables keyed by the sandbox uid and into the egress proxy's routes; the audience's `rules` bound the methods and paths the proxy forwards ([ADR-0025](../adr/0025-phantom-token-egress-proxy.md)) | rendered from the bundle, with the direct hosts the policy allows and the endpoint rules it names |
| the image (K8.1) | `workload.image` on the claim, pulled by the guest, verified by digest | the step's meaning, from the register |
| `lease.maxDurationSeconds` | the claim's `ttl_seconds`, the member destroyed at the deadline | the bundle's value as the ceiling |
| the `ExposureCeiling` | notaio: no ceiling, no bundle | unchanged |

The honest summary: today the broker's configuration is the policy, the operator who edits
it is the policy owner, and notaio's bundle is published beside it, signed and checkable,
read by nobody. M3 moves the authority into the bundle and makes the broker and the guest
its verifiers. The bundle's shape, its signature and the ConfigMap are already what they will
be then, which is why the policy on this page is worth writing now.

## Where to go next

- [Running workloads on a claimed VM](running-workloads.md): the other two ways to obtain
  the first token, an agent acting for a user and a service as itself, and the dial-out
  pattern for conversational agents.
- [Deploying on a homelab cluster](deploying.md) and the
  [homelab walkthrough](homelab-walkthrough.md): the cluster, SPIRE, Dex, banlieue, the
  broker and the VM image.
- [Testing tiers](testing.md): the kind tiers that prove the broker's side of this page.
- notaio's *write a policy* and *consume a bundle* guides, and its ROADMAP's M3.
