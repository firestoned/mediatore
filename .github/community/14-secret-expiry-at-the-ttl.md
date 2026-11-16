<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 14: A stored secret expires right on its TTL

**Status: not started** (a spike, opened 2026-11-16). The operator's rule is that a delegated secret is stored no
longer than its claim's TTL, and the intent is that it goes **right on** the TTL. The sealed envelope stays in
Kubernetes as ciphertext (ADR-0034, ADR-0043): the broker must survive a restart, a rollout and a lost leader without
losing a live claim's credential, which a store held only in a process's memory would not do. So the design question
is not where the envelope lives. It is how its removal is driven, so it lands on the expiry and not up to a poll
interval after it.

Depends on roadmap 05 (the store) and ADR-0043 (the envelope's expiry and the sweep).

## Where it is today

- The expiry is persisted with the envelope: `parked_expiry` writes `expires_at` (the least of the credential's own
  expiry and the claim's creation plus its TTL) into the Secret.
- **The credential stops working exactly at the instant.** The credential route refuses an expired delegation at
  every use, so what the TTL means functionally is already exact. Only the *deletion* lags.
- A sweep removes expired envelopes, parked or on a bound record, every 15 seconds (`ENVELOPE_SWEEP_SECS`,
  `Watcher::sweep_envelopes`), so an expired ciphertext can sit in the cluster for up to 15 seconds. It also runs at
  the resync. Both are the Lease holder's work (`watch::run` runs under `run_as_leader`, `crates/mediatore/src/main.rs`),
  so one replica acts at a time, and a lost leader leaves expired envelopes until the next holder's first sweep.
- Release already deletes the Secret object at once (`envelope_write`), so a claim that ends early takes its
  envelope with it.

## What cannot be fixed here

Even a deletion at the exact instant leaves the ciphertext in the API server's storage history and in backups for as long
as those keep it (threat model R-33). Whether storage is encrypted at rest here is not known. A faster delete narrows
the window in the cluster's live view; it does not make the bytes unrecoverable. The key stays in OpenBao and opening
an envelope needs the broker's role, which is what bounds that residual.

## Options to spike

Each keeps the envelope in Kubernetes. What differs is who deletes it, and when.

| | Option | Exactness | Survives a restart | Cost and risk |
| --- | --- | --- | --- | --- |
| A | **A shorter poll**, 1 to 5 seconds, over the existing sweep | Within the interval | Yes, it is the store | A `list` of the labelled Secrets every interval, on the leader only: more API calls, no new moving part. The floor of what "right on" can mean without timers |
| B | **A delay queue in the broker** (`tokio_util::time::DelayQueue` or a `sleep_until` per envelope) fed by a **watch** on the labelled Secrets: on start the watch lists every existing envelope and schedules its deletion, so a restart rebuilds every timer from the persisted `expires_at` | Milliseconds | Yes: the queue is rebuilt from the store at start; the 15 second sweep stays as the backstop for a missed event | A new loop beside the watcher; two replicas must not both delete (the Lease already decides who acts); clock skew between the broker and the API server shifts the instant by the skew |
| C | **A Kubernetes `CronJob`** that sweeps | At best a minute | Yes | The finest cron granularity is a minute, so it is worse than the sweep we already run; a Job also needs its own credentials to delete Secrets, a second identity with that authority. Listed to rule it out |
| D | **A finalizer or owner reference** that makes the API server delete the Secret with its `AgentSandbox` | The sandbox's lifetime, not the envelope's | Yes | Ties deletion to the claim object's end, which comes after the TTL, so it is the backstop for a claim that was deleted, not a timer. Already half in place (the Secret is owned by the sandbox) |
| E | **A per-claim crypto-shred**: destroy the key material at the TTL so any remaining ciphertext is useless | Exact for the bytes, whenever the key is destroyed | Yes, the key is in OpenBao | The transit key is derived per claim from one key, so there is nothing to destroy per claim without a key per claim (a different sealer, many keys in OpenBao). Closes R-33 where the others only narrow it |

## The spike

A short experiment, not a build, to choose between A, B and E:

- [ ] Measure the lag today: create a claim with a 60 second TTL and an unclaimed delegation, and read the Secret's
      deletion against its `expires_at` (expected up to 15 seconds)
- [ ] **B** in a branch: a watch on the labelled Secrets, a `DelayQueue` keyed by name, rebuilt at start; measure the lag
      (expect well under a second) and the cost of the watch
- [ ] Restart the broker with live envelopes and expired ones in the store: every live one still opens, every expired one
      is deleted at start, none twice
- [ ] Two replicas, one leader: kill the leader at the instant of an expiry; the other deletes it within the sweep's
      backstop
- [ ] **A** at 1 second: the number of API calls per minute on a cluster with N parked envelopes, so the cost is known
- [ ] **E**: whether a key per claim is workable in OpenBao (the number of keys, the cost of creating and destroying
      one, the policy for the broker's role), since it is the only option that makes old ciphertext useless
- [ ] Choose, write the ADR (ADR → CALM → TDD), and tick the roadmap

## Acceptance

The envelope's Secret is gone from `kubectl get secret` within the chosen bound of `expires_at`, through a broker
restart, a leader change and a missed watch event; a use at or after the instant is refused (already true); the bound is
written into the threat model beside R-33 and the 15 second figure there is replaced.

## Not in this roadmap

- The issuer's own session (the login's refresh token), which is not bounded by the claim's TTL (ADR-0043 decision 4)
- Making the ciphertext unrecoverable from the API server's history and backups, beyond option E (R-33's own revisit)
