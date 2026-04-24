---
title: "ADR-0002: Per-row requires explicit backfill"
weight: 20
---

# ADR-0002: Per-row strategy requires explicit backfill of `sealcraft_key` on existing rows

## Status

Accepted.

## Context

When an existing table adopts the per-row strategy, its rows do not yet have a value in the `sealcraft_key` column. The `HasEncryptedAttributes` trait has a `creating` hook that mints a UUID for NEW rows, but NEVER automatically fills in a UUID for existing ones.

An attempt to read or write an encrypted attribute on an existing row with an empty `sealcraft_key` raises `InvalidContextException` with a message naming the `sealcraft:backfill-row-keys` command.

## Decision

Refuse the operation. Do not mint a throwaway UUID on-read.

## Rationale

- **Silently minting a UUID on first read would break future reads.** The mint would be transient (not persisted unless the row is saved), so a second read would mint a different UUID and fail to unwrap the first read's DEK.
- **Persisting a fresh UUID on first read would corrupt legacy ciphertext.** If the row already contains ciphertext from a previous adoption attempt, writing a new `sealcraft_key` orphans the original DEK and renders the ciphertext unrecoverable.
- **The loud-signal failure forces operators through an auditable migration.** `sealcraft:backfill-row-keys` is idempotent, supports `--dry-run`, and bypasses model events so it is safe to run on tables that contain ciphertext.

## Consequences

- Teams adopting per-row must remember to run the backfill before turning encryption on.
- The error message in the exception points at the exact command — see the `InvalidContextException` raised by `HasEncryptedAttributes::sealcraftContext()`.
- New rows created after adoption are handled automatically by the `creating` hook.
