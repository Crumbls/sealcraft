---
title: Architecture Decisions
weight: 120
---

Architecture Decision Records document the non-obvious design choices in Sealcraft -- the ones where a reasonable person might pick differently and deserves to know why we didn't.

- [ADR-0001: Active-DEK uniqueness](/documentation/sealcraft/v1/adr/0001-active-dek-uniqueness-in-app-layer) -- why the invariant uses both `KeyManager` checks and a portable nullable unique hash
- [ADR-0002: Per-row requires explicit backfill](/documentation/sealcraft/v1/adr/0002-per-row-requires-explicit-backfill) -- why adopting the per-row strategy throws `InvalidContextException` on legacy rows instead of silently minting UUIDs
