---
title: "ADR-0001: Active-DEK uniqueness"
weight: 10
---

# ADR-0001: Enforce active-DEK uniqueness with app checks and a portable unique key

## Status

Accepted, amended after concurrency review.

## Context

Sealcraft's invariant is "at most one active DEK per (context_type, context_id)." The first implementation enforced this inside `KeyManager::createDek()` via a `SELECT ... FOR UPDATE` inside a transaction. That prevents duplicate active rows when one already exists, but it does not reliably protect the first-create race on every database engine because there may be no row to lock.

## Decision

Keep the application-layer check for clear errors and add a portable database backstop: nullable `active_context_hash` with a unique index. Active rows store a hash of `(context_type, context_id)`. Retired and shredded rows set the column to `null`, so history can contain multiple retired DataKeys for the same context while only one active row can exist.

## Rationale

- **Partial unique indexes are not portably supported.** SQLite supports them with different syntax; MySQL 8 supports functional indexes but not filtered indexes in the usual form; PostgreSQL supports them natively. A package shipping across all three cannot assume partial-unique syntax.
- **Nullable unique columns are portable enough for this invariant.** MySQL, SQLite, and PostgreSQL allow multiple `null` values in a unique column. Active rows get a non-null hash; inactive rows are null.
- **Application-layer checks still matter.** `KeyManager::createDek()` returns a meaningful domain exception before the database backstop fires in the common case.

## Consequences

- Manual inserts that bypass `KeyManager` must set `active_context_hash` correctly or they will not participate in the database invariant.
- Retire, shred, and provider-migration paths must clear the active hash before creating or activating a replacement DataKey.
