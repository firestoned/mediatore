<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Architecture Driven Development (ADD)

> Same methodology as banlieue: architecture is decided, recorded and visualized
> **before** code, and its security posture is re-verified **after**. The order is fixed:
>
> ```
> ADR  →  CALM  →  TDD  →  implement  →  docs  →  threat model
> ```

## The cycle

1. **ADR** — `docs/adr/NNNN-title.md` (lowercase-hyphen, zero-padded sequential).
   `**Status:** … · **Date:** …` line under the title, then Context / Decision /
   Consequences. One decision per ADR; a reversal marks the old one Superseded.
2. **CALM** — update `docs/architecture/calm/architecture.json`;
   `make calm-validate` must pass and `make calm-diagrams` must render before
   implementation starts.
3. **TDD** — failing test first, then the minimum implementation (`rules/testing.md`).
4. **Docs** — README status table, ADR cross-links, examples.
5. **Threat model** — full pass over `docs/security/threat-model.md`, stamp bumped
   (`rules/threat-modeling.md`). **An ADR is not implemented until this pass is done.**

## When ADD applies

Full cycle for anything that changes a **trust boundary, token shape, SPIFFE ID scheme,
storage contract, API surface, deployment topology, or dependency on an external system**
(IdP, SPIRE, banlieue, OpenBao, PostgreSQL). TDD-only for typos, isolated bugfixes and
mechanical refactors. When unsure, write the ADR.

## Checklist

- [ ] ADR written/updated, Status and Date present
- [ ] CALM updated; `make calm-validate` passes; diagrams render
- [ ] Tests written first; quality gate green (`make check`)
- [ ] README / docs updated
- [ ] Threat-model full pass done; header stamp bumped (date + ADR range)
