---
title: DEK Rotation
weight: 20
---

Rotate the data key itself. Every row encrypted under the old DEK is decrypted and re-encrypted under a new DEK. Much slower than KEK rotation; requires a maintenance window.

## Command

```bash
php artisan sealcraft:rotate-dek \
    "App\\Models\\Patient" \
    --context-type=patient \
    --context-id=42
```

The command:

1. Creates a new DEK for the context
2. Reads every row matching the context
3. Decrypts each encrypted column under the old DEK
4. Re-encrypts under the new DEK
5. Retires the old DEK

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
    --context-type=patient \
    --context-id=42 \
    --dry-run
```

Reports how many rows and columns would be rewritten without touching the database.
