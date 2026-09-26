<!-- Copyright (c) 2026 Erick Bourgeois, mediatore -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# ADR-0001: Record architecture decisions

**Status:** Accepted · **Date:** 2026-09-26

## Context

mediatore sits between an identity provider, banlieue, SPIRE and every sandbox VM. Decisions
about where trust lives are the product; they must be written down before code.

## Decision

Use ADRs in this directory, numbered, one decision each, following banlieue's
ADR → CALM → TDD flow. A decision is not made until its ADR is Accepted.

## Consequences

Every PR that changes a trust boundary, a token shape, a SPIFFE ID scheme, or a storage
contract links the ADR it implements or amends.
