<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# The CLI

The person's side of the one binary, in `crates/mediatore-client`: `mediatore login`, `mediatore sandbox ...`,
`mediatore session` and `mediatore logout`. It is only one client of the [Broker API](broker-api.md): everything it does
over the wire a script or a service can do with the same HTTP calls, which matters for requesters that have no CLI.

## `login`: a session, kept locally

`login` runs the OAuth authorization-code flow with **PKCE** (RFC 7636) and a **loopback redirect** (RFC 8252) at the
issuer, as mediatore's own **public client**, and keeps what it gets in a session file (`~/.config/mediatore/session.json`,
mode 0600): the ID token and, when the issuer granted `offline_access`, a refresh token. The flags describe the issuer,
not mediatore: `--issuer`, `--client-id`, `--scope`, `--auth-param` (for a connector or a login hint the issuer wants),
`--ca-file` for an issuer on a private PKI, `--redirect-port`, `--redirect-host`, `--redirect-path`,
`--client-secret-file` (for an issuer whose token endpoint wants a secret even from a public client), `--no-browser`
and `--session` (a session file other than the default).

`mediatore session` says who is logged in, until when, and whether a delegation is left (for example `id token valid,
delegation available`).

## `sandbox`: create, get, delete

| Command | Does |
| --- | --- |
| `sandbox create` | `POST /v1/claims` with the ID token as the bearer; prints the sandbox's name and phase (`--json` for the whole answer) |
| `sandbox get <name>` | `GET /v1/claims/{name}` (`--namespace` adds `?namespace=`, ADR-0046): the phase, readiness, deadline, the guest's report (the image digest, the ruleset's hash) and the workload's exit |
| `sandbox delete <name>` | `DELETE /v1/claims/{name}` (`--namespace` as for `get`) |

`create` takes the request's fields as flags: `--namespace` (the namespace to claim in, ADR-0046; a broker with a
namespace map requires it), `--pool` (one pool by name) or `--pool-selector key=value` (repeatable, all must match;
neither means every pool in the namespace, ADR-0044), `--ttl` (seconds), `--audience` (repeatable), `--image`, `--arg`
(repeatable, the workload's argv; use `--arg=-c` for a value that starts with a dash), `--policy` (a notaio policy by
name), `--restart` (`always`, the default, `on-failure` or `never`), `--strategy` (`longest-ready`, `most-available` or
`spread`, how banlieue ranks the Ready members it may take, ADR-0047; nothing is sent without it), and `--delegate`
(below). `--mediatore` is the broker's URL and
`--ca-file` a CA for a broker behind a private PKI (`MEDIATORE_CA_FILE`).

**One login is good for one claim.** When the issuer requires a session, `create` hands the **refresh token** to the broker
in the claim body and **forgets its own copy**: the issuer rotates refresh tokens, so after the broker's first refresh the
copy here would be dead anyway. A second claim is a second login; a second `create` on the same login is refused by the
broker as `session_required`.

## `--delegate`: a person's own credential

For an audience that is `via: delegated`, the claim must carry a credential of the person's own. `--delegate
<audience>=<source>` reads it **now**, sends it **once** with the claim and keeps it nowhere else (repeatable, one per
audience). The sources, parsed by `Source` (`delegate.rs`):

| Source | Reads |
| --- | --- |
| `claude-code` | Claude Code's own credential store (the macOS Keychain, or its credentials file) |
| `prompt` | asks at the terminal: a user name, then a secret **with echo off** (through `stty`). Terminal only; a script uses `env:` or `file:`. Fails closed: when `stty -echo` fails on a terminal, the secret is neither asked for nor read (`read_unechoed`) |
| `store` | mediatore's own item in the macOS Keychain, saved earlier |
| `env:<NAME>` | the environment variable `NAME`; a bare token, or `user:secret` for a `basic` audience |
| `file:<path>` | the file's contents, the same shapes |

A `basic` credential is a user name and a secret joined `user:secret` (`join_basic`): neither part empty, no control
character, and no colon in the user name (RFC 7617 ends the user name at the first colon). The CLI refuses a malformed
one before sending, and the broker refuses the same at claim time. The secret can be a password or a personal access token;
on a host that refuses passwords for a protocol, it must be a token (ADR-0041, decision 7).

There is **no flag that takes the secret**, so it never lands in shell history or a process listing, and **no source reads
a browser's cookies or another application's store**; any other value of `--delegate` is refused.

### The saved item (`store`)

On macOS, `prompt` then offers to keep the credential: `Keep it in the macOS Keychain for the claim's TTL, <duration>?
[y/N]`, default no. The item (`delegate.rs`, module `store`) is one per audience:

| Part | Value |
| --- | --- |
| service, account | `mediatore`, the audience |
| value | JSON: `saved_at`, `max_age_secs`, and the `user:secret` |

`max_age_secs` is the **least of the claim's TTL and six hours** (`STORE_MAX_AGE_SECS`). On read, an item older than its
own limit, or dated more than a minute in the future, is **deleted and refused**. `mediatore logout --audience <name>`
deletes it (idempotent). Other platforms have no store source and say so. The operating system, not mediatore, decides
which other programs may read the item.

## Rules this part keeps

- The refresh token is handed over once and forgotten; one login is one claim.
- A secret is never a flag, never printed, and never read from a browser or another application's store.
- A saved item never outlives the claim it was saved for, nor six hours.
- The CLI refuses what the broker would refuse, before sending it.

## Read next

ADR-0013 (the session), ADR-0014 (one binary), ADR-0035 (delegated credentials and the `--delegate` sources), ADR-0041
(user name and secret, the Keychain), ADR-0043 (the saved item's claim-TTL limit). Threat model TB-1 and TB-18 (the CLI to
the credential store and terminal), asset A-12 (the session file) and A-25 (the saved item). Guide:
[Requesting a sandbox](../guides/requesting-a-sandbox.md).
