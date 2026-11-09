<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0033: A one-shot workload: the restart policy, and the claim released when the workload is done

**Status:** Accepted · **Date:** 2026-11-09

Roadmap 06 (the guest). Amends [ADR-0014](0014-one-binary-roles-as-subcommands.md)
decision 3 (what the guest does when the jail exits) and
[ADR-0008](0008-agentsandbox-crd-owned-by-mediatore.md) decision 8 (the shape of `workload`), and adds one
route to the sandbox API beside `POST /v1/me/report`
([ADR-0029](0029-the-pull-on-a-routeless-segment-and-the-pool-vms-root-rules.md) decision
5). Changes no identity, no token, no trust boundary: the node tells the broker one more
thing about its own claim, over the SVID it already holds.

## Context

The guest supervises the jail until the claim's deadline and restarts the workload
whenever it exits, whatever the status; only the confinement refusal (`125`, ADR-0024
decision 4) and the egress proxy's exit end the claim early. That was written for the
agent that runs until it is told to stop. The live run of 2026-11-09 ran the other kind:
the example research agent made one call to Claude, printed the answer and exited `0`,
and the supervisor started it again two seconds later, and again, each time calling Claude,
until the claim was released by hand. A crash loop and a finished agent looked the same.

Two things are wanted. The requester says which kind of workload this is, and a finished
one-shot workload ends its claim: the entry retracted, the tokens cut off, the member
recycled, the exit on record, with no one watching a log to delete the sandbox.

## Decision

1. **`workload.restart`, the systemd shape, defaulting to today's behaviour.**
   `always` (the default): the workload is restarted whatever its status until the
   deadline, as today. `on-failure`: a non-zero exit is restarted, an exit `0` ends the
   claim: the agent that runs once and may be retried. `never`: any exit ends the claim.
   Whatever the policy, the confinement refusal ends the claim (nothing runs unconfined),
   and so does the egress proxy's exit (nothing runs with no way out). The field travels
   as every other part of `workload`: `POST /v1/claims` (`mediatore sandbox create
   --restart`), the `AgentSandbox` (`spec.workload.restart`, frozen with the rest of the
   spec), the claim record, `GET /v1/me`. An old guest ignores the field and behaves as
   `always`; an old broker drops it, which the CLI cannot tell, so the guide says which
   release the field needs.

2. **When the policy ends the claim, the guest says so: `POST /v1/me/exit`.** Over the node
   SVID, like `POST /v1/me/report`, the guest sends what ended the workload: the exit code
   or the signal, how many times it had been restarted, and when. The broker records it on
   the claim (`exit`, kept with the audit row when the claim is swept, shown by
   `GET /v1/claims/{name}` and `mediatore sandbox get`), logs it with the claim and the
   subject, and releases the claim as `DELETE /v1/claims/{name}` does: through the
   `AgentSandbox` where there is a cluster (the reconciler's finalizer retracts the entry
   and the pool recycles the member), directly in `dev_mode`. The request is accepted from
   the node the claim is bound to and from no other identity; a claim already released
   is `204` all the same (the guest may be late). The guest sends it once, bounded, and
   tears down whether or not it was heard: the deadline still bounds the claim, as before.

3. **Nothing else changes.** The supervisor's restart delay, the deadline, the proxy's
   supervision, the teardown and the report are as they were. A workload that keeps
   running to the deadline under `on-failure` or `never` ends as today, with no exit
   recorded. A workload cannot lengthen its claim by any of this; it can only end it
   sooner, which it always could by exiting `125`.

## Consequences

- `RestartPolicy` and `Workload::restart`, `WorkloadExit` and `ClaimResponse::exit`
  (`crates/mediatore-proto`); `ClaimRecord::exit` and the `exit` column with its audit
  twin (`crates/mediatore-store`, migration 6); `SandboxWorkload::restart` and the
  rendered CRD (`crates/mediatore-claims`, `make crds`); `POST /v1/me/exit`
  (`crates/mediatore-api`); `supervise::run` deciding by the policy and returning how the
  round ended, the guest posting it (`crates/mediatore-guest`); `--restart` on
  `mediatore sandbox create` and the exit printed by `sandbox get`
  (`crates/mediatore-client`).
- Proven in the units of the supervisor's decision, the store's round trip and the CRD
  render, and end to end in `e2e_dev.rs`: a claim created `never`, the node posting its
  exit, the claim released and the exit on the response; a foreign node refused; a second
  post after the release `204`.
- The threat model gains one TB-6 row: the exit route lets a node end its own claim and
  nothing else.
- Rejected: the guest deleting the `AgentSandbox` itself (the node has no Kubernetes
  identity and should not get one); a `completed` phase on the claim (the claim's phases
  mirror banlieue's and a released claim is released; the exit is the record's);
  restarting `on-failure` with a cap (the deadline is the cap).
