<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Never Commit Real Infrastructure Identifiers

> mediatore is a public OSS repository. Never write a real hostname, IP address,
> username, tenant id, client id or account identifier from the maintainer's (or any
> real) environment into a tracked file — code, tests, docs, ADRs, examples, configs,
> comments, commit messages. A later commit removing it does not un-publish it.

Placeholders to use:

| Kind | Use |
| --- | --- |
| Hostname / domain | `*.home.example`, `bar.foo.io`, `example.com` (RFC 2606) |
| Documentation IPv4 | `192.0.2.x`, `198.51.100.x`, `203.0.113.x` (RFC 5737) |
| Loopback in dev configs | `127.0.0.1` is fine |
| Trust domain | `sandbox.home.example`, `sandbox.test` |
| Entra tenant / client id | `<tenant>`, `<broker app id>` |
| Registry | `registry.internal:5000`, `ghcr.io/firestoned/mediatore` |
| Login | `octocat`, `hexley` |

Real values come from the environment at runtime (config files, env vars), never as
defaults. Before finishing any task, sweep the diff:

```sh
git diff --cached -U0 | rg -i 'jeb\.ca|rbc\.|\b(?:\d{1,3}\.){3}\d{1,3}\b' | rg -v '127\.0\.0\.1|0\.0\.0\.0|192\.0\.2\.|198\.51\.100\.|203\.0\.113\.'
```
