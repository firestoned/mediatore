<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# GitHub Workflows & CI/CD Standards

Same standards as banlieue (`firestoned/banlieue` → `.claude/rules/github-workflows.md`),
restated for this repo:

1. **Composite actions come from `firestoned/github-actions`.** Never replace one with
   a direct action call; version bumps happen in that repo, then the pinned ref here.
2. **Workflows are Makefile-driven.** A workflow installs tools, sets env vars, and
   calls `make <target>`. No multi-line bash in `run:` beyond trivial tool setup; the
   same target must work locally.
3. **Reusable and composable.** New workflows support `workflow_call` (and
   `workflow_dispatch` where useful) alongside their own triggers.
4. **Every third-party action is SHA-pinned** with the version in a trailing comment
   (Scorecard Pinned-Dependencies). Dependabot keeps the pins current.
5. **Top-level `permissions: contents: read`.** Jobs that need more declare it at the
   job level with a comment saying why.
6. **SPDX headers** on every workflow file.

Before adding a workflow: can it be a job in an existing one? Is it reusable? Does it
duplicate logic that belongs in the Makefile?
