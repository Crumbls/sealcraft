---
title: "ADR-0001: Active-DEK uniqueness in app layer"
weight: 10
---

# ADR-0001: Enforce active-DEK uniqueness in application code, not as a DB unique index

## Status

Accepted.

## Context

Sealcraft's invariant "at most one active DEK per (context_type, context_id)" is enforced inside `KeyManager::createDek()` via a `SELECT ... FOR UPDATE` inside a transaction. A natural alternative is to push the constraint into the database as a partial unique index on `(context_type, context_id) WHERE retired_at IS NULL AND shredded_at IS NULL`.

## Decision

Keep enforcement in application code.

## Rationale

- **Partial unique indexes are not portably supported.** SQLite supports them with different syntax; MySQL 8 supports functional indexes but not filtered indexes in the usual form; PostgreSQL supports them natively. A package shipping across all three cannot assume partial-unique semantics.
- **NULL handling in composite unique indexes diverges across engines.** MySQL treats NULLs as distinct in unique indexes; PostgreSQL treats them as distinct by default but can be configured otherwise; SQLite follows its own rules. An ordinary unique on `(context_type, context_id)` without a NULL filter would block legitimate inserts of retired-then-reactivated rows.
- **Application-layer enforcement is already transactional.** The `FOR UPDATE` gate inside `KeyManager::createDek()` prevents the only race we care about (two requests trying to create the first active DEK for the same context) and returns a meaningful exception.

## Consequences

- Manual inserts that bypass `KeyManager` could violate the invariant. `sealcraft:audit` detects this.
- Future versions may add an optional migration that layers a partial unique index on engines that support it, without removing the app-layer gate.
