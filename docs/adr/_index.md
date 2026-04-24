---
title: Architecture Decisions
weight: 120
---

Architecture Decision Records document the non-obvious design choices in Sealcraft -- the ones where a reasonable person might pick differently and deserves to know why we didn't.

- [ADR-0001: Active-DEK uniqueness in app layer](/documentation/sealcraft/v1/adr/0001-active-dek-uniqueness-in-app-layer) -- why the invariant is enforced in `KeyManager` rather than as a DB partial unique index
- [ADR-0002: Per-row requires explicit backfill](/documentation/sealcraft/v1/adr/0002-per-row-requires-explicit-backfill) -- why adopting the per-row strategy throws `InvalidContextException` on legacy rows instead of silently minting UUIDs
