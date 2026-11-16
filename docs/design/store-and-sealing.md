<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# The store and the sealing

Where claim records and secrets live, who may read them, and how long they stay. The code is
`crates/mediatore-store` (the contract and the sealers), `crates/mediatore-claims/src/kubestore.rs` (the shipped
store) and `crates/mediatore-openbao` (the client the transit sealer uses). The guide [The store](../guides/the-store.md)
covers operating it; this page is how it is built.

## The contract

The broker talks to one trait, `ClaimStore` (`crates/mediatore-store/src/lib.rs`). Its methods fall in four groups:

| Group | Methods |
| --- | --- |
| claims | `put_claim`, `get_claim`, `get_claim_by_name`, `get_claim_by_node`, `update_claim`, `revoke_claim`, `list_claims` |
| nodes | `put_node`, `get_node`, `get_node_by_dmi`, `ban_node`, `list_nodes`, `delete_node` |
| sessions (sealed secrets) | `put_session`, `take_session`, `take_delegations`, `delete_session`, `sweep_sessions` |
| policy floors | `get_policy_floor`, `advance_policy_floor` (a compare and set) |

Plus `sweep` (archive claims past retention) and `ping`.

There are two implementations and one rule between them: **what both do is pinned by a conformance suite**
(`crates/mediatore-store/src/conformance.rs`, one `#[tokio::test]` per case, run against each store). `MemoryStore` is
for `dev_mode` and tests. `KubeStore` is the shipped one. A behaviour that matters to the broker is a conformance case,
so the in-memory fake is never more permissive than the real store.

## What lives where (`KubeStore`)

The store is the Kubernetes API (ADR-0034); there is no database.

| Data | Kept as | Notes |
| --- | --- | --- |
| the claim record | `status.record` on the `AgentSandbox` | written in `kubestore.rs` and nowhere else; an ended claim stays for `store.retention_secs` (3600 by default), then the sweep releases it with an audit line |
| the issuer's session (the login's refresh token), sealed | a `Secret` named `mediatore-session-<sandbox uid>` | |
| each delegated credential, sealed | a `Secret` named `mediatore-session-<sandbox uid>-<16 hex of a hash of the audience>` | one per audience |
| an attested pool member | a `SandboxNode` resource named by its EK hash | `kubestore.rs`, `nodegc.rs` |
| a policy's version floor | a `PolicyFloor` resource | moved only upward, by compare and set |

A session Secret holds `key_id`, `nonce` and `ciphertext` (the sealed envelope) beside `subject`, `issuer`, `created_at`
and, when set, `expires_at`. It is labelled `mediatore.io/session` as `parked` (the API wrote it and no record has taken
it yet) or `claimed` (the record has taken it), with the sandbox's UID and, for a delegation, the audience as further
labels. A `claimed` Secret is owned by the sandbox, so the cluster's garbage collector removes it with the sandbox;
ownership is set only within the broker's own namespace, since an owner reference cannot cross one.

## The sealing

No secret enters the store in the clear. `Sealer` (`seal.rs`) turns plaintext into a `Sealed { key_id, nonce,
ciphertext }`, binding it to a UID so an envelope opens for that claim only.

| Sealer | Key | Used for |
| --- | --- | --- |
| `TransitSealer` | a **derived** OpenBao transit key that never leaves OpenBao, the claim's UID as the derivation context; `key_id` is `transit:<mount>/<key>` | the work shape (ADR-0015) |
| `LocalKeySealer` | a 32-byte key read from a mounted file (raw or 64 hex characters) | the homelab shape |

The broker holds only a short-lived OpenBao token, obtained with its projected service-account token at the cluster's
Kubernetes auth mount (`auth_mount`) and renewed by `mediatore-openbao`. It can encrypt and decrypt with that one key
and do nothing else. A refused or unreachable OpenBao fails the request and revokes nothing already issued.

## The life of an envelope

```
POST /v1/claims                          bind                         release / expiry
      │                                    │                                 │
  seal with transit ──► parked ─────────► claimed (on the record) ───► deleted
                           │                  │
                           └── expiry ────────┴────────────────────────► deleted
```

1. **Parked.** `create_sandbox` seals the session and each delegation with the new sandbox's UID and writes one Secret
   each, `parked`, before the caller hears back.
2. **Expiry is set when it is parked.** A delegation's envelope gets `expires_at` = the least of the credential's own
   expiry and the claim's creation plus its TTL (`parked_expiry`, `crates/mediatore-api`). The operator's rule is that
   **no secret is stored longer than its claim's TTL**.
3. **Claimed.** When the reconciler creates the record it takes the parked envelopes (`take_session`,
   `take_delegations`) and relabels them `claimed`.
4. **Swept.** `sweep_sessions` removes an envelope past its `expires_at`, whether still parked or already claimed, and a
   parked one that no record ever took within the grace period (an hour). The watcher runs it every 15 seconds
   (`Watcher::sweep_envelopes`) and at each resync.
5. **Deleted at release.** When a claim ends, `write_envelope` finds the record no longer carries an envelope and the
   Secret exists, so it **deletes the Secret** (`envelope_write`'s `Delete`). It does not blank it or leave a marker:
   that a claim was released is on the `AgentSandbox`'s status record.

`envelope_write(carried, exists)` is the whole decision, a pure function: carried and present is `Replace`, carried and
absent is `Create`, not carried and present is `Delete`, neither is `Nothing`.

A use of a credential at or after its `expires_at` is refused by the credential route whatever the sweep has done, so
the functional expiry is exact and only the removal lags, by at most the sweep interval. Roadmap 14 is the spike to
close that gap. Two things the rule does **not** cover, deliberately: the issuer's own session (the login's refresh
token) is not bounded by the claim's TTL, because it renews the claim's tokens for the claim's whole life, and the
ciphertext of a deleted envelope can remain in the API server's storage history and in backups (threat model R-33).

## Rules this part keeps

- Refresh material and delegated credentials reach the store only as a `Sealed` envelope, bound to one UID.
- A store failure while parking withdraws the `AgentSandbox` so nothing half-made remains.
- Revocation clears the envelopes; release deletes their Secrets.
- A conformance case, not a comment, pins any behaviour the two stores must share.

## Read next

ADR-0012 (the store's shape), ADR-0013 (the session), ADR-0015 (the transit sealer), ADR-0034 (the API as the store),
ADR-0035 and ADR-0041 (delegated credentials), ADR-0043 (the envelope's expiry and deletion). Threat model TB-9 (the
store) and TB-10 (OpenBao), risks R-32 and R-33. Roadmap 14 (expiry right on the TTL).
