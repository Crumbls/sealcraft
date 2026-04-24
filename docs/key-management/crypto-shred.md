---
title: Crypto-Shred
weight: 40
---

Permanent destruction of a context's DEK. Every ciphertext ever wrapped under that context becomes cryptographically unrecoverable. This is the right-to-be-forgotten primitive.

## Programmatic

```php
app(\Crumbls\Sealcraft\Services\KeyManager::class)
    ->shredContext($user->sealcraftContext());
```

## Command

```bash
php artisan sealcraft:shred \
    "App\\Models\\OwnedUser" \
    <sealcraft_key>
```

## What happens

1. The `DataKey` row for the context is deleted from the database
2. The KEK-wrapped DEK is unrecoverable (the DEK plaintext never persisted)
3. Existing row ciphertext remains on disk but cannot be decrypted by anyone, including you
4. The DEK cache is invalidated

The original data row is not deleted -- only the key is. This is what makes crypto-shred faster than cascading `DELETE` across every table and every backup.

## Behavior after shred

- **Reads** of any encrypted column on a shredded context raise `ContextShreddedException` (a separate exception from `DecryptionFailedException`). Render a "record destroyed at user request" page instead of a 500.
- **Writes** to a shredded context also fail with `ContextShreddedException`, preventing accidental resurrection.
- **The `DekShredded` event** fires on success. Wire it to your compliance audit log.

## What it does not do

- **Does not delete data rows.** The columns still exist; they just contain unrecoverable ciphertext. Delete the rows separately if your policy requires it.
- **Does not scrub plaintext elsewhere.** Audit logs, telemetry, data warehouses, CDNs, email archives, and backups all may contain plaintext copies of the same data. Crypto-shred only protects DB columns encrypted through Sealcraft.
- **Does not satisfy GDPR erasure on its own.** You still need to scrub names, emails, IDs, and any other identifying plaintext from non-sealcraft columns.

## Backup implications

Crypto-shred works on backups too -- once the DEK is destroyed, backup copies of the ciphertext are just as unrecoverable. That is the whole point. Make sure your backup of the `sealcraft_data_keys` table is not unconditionally restored, or you will un-shred a user.
