---
title: KEK Rotation
weight: 10
---

Rotate the wrapping key without re-encrypting any row data. Fast. Safe during normal operation.

## Command

```bash
php artisan sealcraft:rotate-kek
```

For each `DataKey` row, Sealcraft unwraps the DEK under the old KEK version, rewraps it under the current KEK version, and updates the stored `kek_version` column.

## Scoping

```bash
# One tenant only
php artisan sealcraft:rotate-kek --context-type=tenant --context-id=42

# One provider only (useful after provider migration)
php artisan sealcraft:rotate-kek --provider=aws_kms

# See what would rotate without touching anything
php artisan sealcraft:rotate-kek --dry-run
```

## Zero-downtime guarantee

During rotation, concurrent reads continue to work because each `DataKey` row stores the KEK version that wrapped it. If a request lands mid-rotation, it unwraps against the old version; after the row is rewrapped, new requests unwrap against the new version. No column ciphertext changes, so reads never fail.

## When to run

- **Scheduled**: quarterly or annually, as a compliance ritual
- **Reactive**: after an access incident, departing staff, or policy change
- **Post-provider-migration**: verify the new provider's KEK is in use for every DEK

Safe to run during peak traffic. The command uses `chunkById` so it scales to 100k+ tenants.

## Event

`DekRotated` fires for each successfully rotated DataKey. Wire it to your audit log.
