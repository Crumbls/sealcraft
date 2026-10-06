---
title: Crypto-Shred
weight: 40
---

Crypto-shred removes a context's wrapped DEKs from the live DataKey table and blocks future Sealcraft reads and writes. Plan backup and replica retention separately before treating a deletion request as complete.

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

1. Every DataKey row for the context, including retired versions, has its `wrapped_dek` replaced with an unusable marker and is marked shredded
2. The rows remain as tombstones so Sealcraft refuses to create a replacement DEK
3. Existing encrypted data rows remain on disk but cannot be read through Sealcraft
4. The local DEK cache is invalidated

The encrypted data rows are not deleted. Databases may retain old row versions in WAL, replicas, snapshots, and backups, so destroying the live wrapped DEK does not erase those copies.

## Behavior after shred

- **Reads** of any encrypted column on a shredded context raise `ContextShreddedException` (a separate exception from `DecryptionFailedException`). Render a "record destroyed at user request" page instead of a 500.
- **Writes** to a shredded context also fail with `ContextShreddedException`, preventing accidental resurrection.
- **The `DekShredded` event** fires on success. Wire it to your compliance audit log.

## What it does not do

- **Does not delete data rows.** The columns still exist; they just contain unrecoverable ciphertext. Delete the rows separately if your policy requires it.
- **Does not scrub plaintext elsewhere.** Audit logs, telemetry, data warehouses, CDNs, email archives, and backups all may contain plaintext copies of the same data. Crypto-shred only protects DB columns encrypted through Sealcraft.
- **Does not satisfy GDPR erasure on its own.** You still need to scrub names, emails, IDs, and any other identifying plaintext from non-sealcraft columns.

## Backup implications

An older backup of `sealcraft_data_keys` may still contain a usable wrapped DEK. Anyone with that backup, the matching KEK, and the ciphertext can recover the data. Ensure backup retention, restoration controls, and replica handling meet your deletion policy. Never restore an older key row over a shredded tombstone without an explicit review.
