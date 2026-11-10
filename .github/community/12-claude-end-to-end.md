<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# 12: The end-to-end flow to the Anthropic API

**Status: in progress** (started 2026-11-09). Every piece of configuration the path from a
person's login to a Claude answer inside the jail depends on, in one place: Dex, SPIRE,
notaio, the `sandbox-policies` repository, the broker, the gateways, the pool and the
Anthropic side. The hello shape of it is proven live (`docs/guides/testing.md`, runs 5
and 7: one Messages call through the proxy, the operator's key placed by the proxy, the
jail never holding it). The repository shape, GitHub and Claude under one policy, is the
open item. Every name and address below is a placeholder (`rules/no-real-infrastructure.md`);
the real values live in the operator's configuration directory, outside this repository.

Depends on roadmaps 04 (`via: secret`, ADR-0032), 07 (the proxy and `via: none`), 09 and 11
(the bundle verified and enforced), 10 (the gateways), 05 (the store, so a `PolicyFloor`
survives a restart).

## Where the configuration is

The whole of it, Dex to Anthropic with the values that must agree across the six pieces,
is the guide [Claude from the sandbox, end to end](../../docs/guides/claude-end-to-end.md);
the setup, checked step by step, is the skill `.claude/skills/claude-e2e-setup`. This
document tracks what is still open on the path.

## The open items

- [x] Hello shape proven live: `claude-agent`, `via: secret`, the key placed by the proxy,
      Claude's answer printed from the jail (run 5, 2026-11-08); the one-shot version with
      the record on the resource (run 7, 2026-11-09)
- [ ] **Dex groups.** The GitHub connector carries `orgs: [{ name: <org>, teams: [sandbox-users] }]`
      so the ID token's `groups` claim names `<org>:sandbox-users`; the broker's issuer gets
      `required_group` on it. Today the policies' `subjects.groups` name a group no token
      carries, and the broker gates on nothing but the issuer
- [ ] **A policy for the repository shape.** `research-agent` names `github` alone and
      `claude-agent` names `anthropic` alone; the agent's repository mode needs both in one
      claim, and `standard` allows one audience (K5.3 R1, lint `L005`). Decide, in
      `sandbox-policies` under review: a `lab` policy (K5.3 R2) with both audiences
      classified `dataScope: LabOnly` on its ceiling (notaio ADR-0017), which fits a public
      repository and a capped Anthropic workspace, or a custom `SandboxProfile` at K5.3 R2
      with `standard`'s other steps. Then the ceiling widened and signed by Security, the
      bundle admitted, the floor moved
- [ ] **The broker side of that policy.** Both audiences already exist in `mediatore.yaml`
      (`github` `via: none` 480 s, `anthropic` `via: secret` 900 s); the comparison must come
      out `PolicyConformant=True` for a sandbox naming the new policy (`max_ttl` at or below
      the policy's `ttlSeconds`, the same rules and endpoints)
- [ ] **The repository run, live.** `MODE=repo` of the example agent: `GET /repos/<org>/mediatore`
      and the README through the proxy bare, one Messages call with the key placed, the
      report in `/work`, exit 0 ending the claim; recorded as run 8 in
      `docs/guides/testing.md` with the broker's and the proxy's lines
- [ ] **The key's bound.** A workspace of its own at Anthropic with a spend limit, the key
      in `mediatore-audience-secrets`, the rotation rehearsed once (edit, restart, a claim
      minting again within `max_ttl`)
- [ ] **The session's bound.** Document, and if possible lengthen, the window between
      `mediatore login` and a claim that still refreshes: Dex's refresh token outlives the
      GitHub token behind it, so a claim under an `sts` audience fails to mint after about
      eight hours; the Anthropic flow alone does not refresh, so the window only matters when
      `github` moves to `via: sts`
- [ ] **One reference, kept current.** This document is where the four configurations are
      read together; a change to any of them in the guides updates the table here in the
      same commit
