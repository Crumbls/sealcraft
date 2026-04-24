---
title: Per-Row Strategy
weight: 20
---

Each row carries its own `sealcraft_key` column (an auto-populated UUID) and gets its own DEK. Best for vault-style rows where each record is its own security boundary.

## Configure

```php
use Crumbls\Sealcraft\Casts\Encrypted;
use Crumbls\Sealcraft\Concerns\HasEncryptedAttributes;

class VaultEntry extends Model
{
    use HasEncryptedAttributes;

    protected string $sealcraftStrategy = 'per_row';

    protected $casts = ['secret' => Encrypted::class];
}
```

## Migration

Add a row-key column to the table:

```php
$table->string('sealcraft_key', 191)->nullable()->index();
```

## Empty row-keys are a hard error

If a saved row has `NULL` or empty in its row-key column, `sealcraftContext()` throws `InvalidContextException`. Silently minting a fresh UUID would orphan a new DEK on every read and guarantee decryption failure, since the original ciphertext was bound to a different (also throwaway) context.

## Backfill before turning encryption on

When adopting per-row on an existing table, populate row-keys on legacy rows first:

```bash
php artisan sealcraft:backfill-row-keys "App\\Models\\VaultEntry"
```

The command is idempotent, supports `--chunk` and `--dry-run`, and bypasses model events so it is safe to run on tables that already contain ciphertext.

## New rows are handled automatically

A `creating` hook on the trait ensures every newly INSERTed per-row model carries a row-key, even if no encrypted attribute is touched during fill.

## Performance

One KEK unwrap per distinct row you read. The DEK cache keeps steady-state request overhead low, but bulk reads of unique rows are more expensive than per-group.
