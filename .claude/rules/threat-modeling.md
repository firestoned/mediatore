<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Threat Modeling

> `docs/security/threat-model.md` is a living document and the **last step of the ADD
> cycle**. After implementing any ADR, walk **every** section — components, assets,
> actors, trust boundaries (including the Mermaid diagram), STRIDE tables, hardening,
> accepted risks — not just the table that obviously changed.

## Requirements for a pass

1. Every new or changed threat maps to a **control that exists** in `crates/` or
   `deploy/`, cited by file — or it is an entry in §8 Accepted risks with an explicit
   *Revisit when*, or a finding to fix before the ADR counts as implemented. Never
   write a control that does not exist yet as though it does.
2. Classify with STRIDE, per trust boundary, in the existing table format.
3. Update the Mermaid trust-boundary diagram when components or boundaries change.
4. **Bump the header stamp** — date *and* ADR range
   (`Last full pass YYYY-MM-DD, against ADR-0001 … ADR-NNNN`). An unchanged stamp
   means the pass did not happen. "No change" is a valid conclusion, but it is still
   a pass: bump the stamp and say so.
5. Never record a specific unremediated vulnerability here — this file is public.
   Findings go through GitHub private vulnerability reporting (see `SECURITY.md`).
6. No real infrastructure identifiers (`rules/no-real-infrastructure.md`).

## Trigger questions

Any **yes** means that section changes: new binary/crate/endpoint? New token type,
credential, or key? New identity (SPIFFE ID, ServiceAccount, app registration)? New
call to an external system? Data crossing a boundary it didn't before? A weakened or
invalidated accepted risk?

## Scope

Full pass for any implemented ADR. Not required for TDD-only changes — but a "trivial"
fix that changes who can reach what was not trivial: write the ADR, then do the pass.
