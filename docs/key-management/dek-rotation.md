---
title: DEK Rotation
weight: 20
---

Rotate the data key itself. Every row encrypted under the old DEK is decrypted and re-encrypted under a new DEK. Much slower than KEK rotation; requires a maintenance window.

## Command

```bash
php artisan sealcraft:rotate-dek \
    "App\\Models\\Patient" \
    patient \
    42
```

The command:

1. Acquires a database advisory lock for the context where the database supports it
2. Creates replacement DEK material in memory
3. Opens one database transaction for the rewrite
4. Decrypts every matching encrypted column under the old DEK
5. Re-encrypts under the new DEK
6. Retires the old DEK and activates the new DataKey row

If a row fails to decrypt or update, the transaction rolls back. Rows already processed in that transaction return to their previous ciphertext and the old DataKey remains active.

## Delegated contexts

By default, `rotate-dek` scans discovered Sealcraft models for rows whose `sealcraftContext()` resolves to the same context. This covers the owner-plus-related-tables pattern from [Delegated context](/documentation/sealcraft/v1/encryption-contexts/delegated-context), where an owner row and dependent tables share one DEK.

For large applications, pass one or more `--scan-path` values to limit discovery:

```bash
php artisan sealcraft:rotate-dek \
    "App\\Models\\OwnedUser" \
    "App\\Models\\OwnedUser" \
    9b92c5a8-7f8f-4c3a-84fb-38df4d90bb9f \
    --scan-path=app/Models
```

The first `App\\Models\\OwnedUser` is the model to scan efficiently. The second is the context type; for per-row models, that is usually the model's morph class.

Use `--without-delegated-discovery` only when you know the context is used by the named model table and nowhere else.

## Pre-requisites

- **No concurrent writes for the affected context.** The command assumes a quiesced state. Put the tenant in maintenance mode before running.
- **Backup first.** DEK rotation rewrites every ciphertext column; a bug in a custom cast could corrupt data. Restore is only possible from a backup.

## When to run

- After a suspected DEK compromise (plaintext DEK leaked in a log, exception dump, or memory snapshot)
- Before declassifying data from a higher tier to a lower tier (where the old DEK's custody chain is no longer acceptable)
- Rarely -- KEK rotation covers most threat models

## Preferred alternative

If you only need to comply with a rotation policy ("keys must rotate annually"), **KEK rotation satisfies that requirement** for most frameworks. Use DEK rotation only when the DEK itself is suspect.

## Dry run

```bash
php artisan sealcraft:rotate-dek \
    "App\\Models\\Patient" \
    patient \
    42 \
    --dry-run
```

Reports how many rows and columns would be rewritten without touching the database.
