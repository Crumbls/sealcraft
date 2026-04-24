---
title: Key Management
weight: 60
---

Sealcraft treats keys as operational artifacts. Rotation, provider migration, and shred are first-class commands with dry-run support.

## Playbook

- [KEK rotation](/documentation/sealcraft/v1/key-management/kek-rotation) -- rewrap every DEK under the current KEK version. Fast, no data re-encrypted, safe during normal operation.
- [DEK rotation](/documentation/sealcraft/v1/key-management/dek-rotation) -- re-encrypt every row under a new DEK. Slower, requires a maintenance window.
- [Provider migration](/documentation/sealcraft/v1/key-management/provider-migration) -- move DEKs between KMS providers (AWS -> GCP, Vault -> Azure, etc.).
- [Crypto-shred](/documentation/sealcraft/v1/key-management/crypto-shred) -- destroy a context's DEK to render ciphertext permanently unrecoverable.

## Dry run

Every destructive command supports `--dry-run`. Use it first, every time.

## Audit

```bash
php artisan sealcraft:audit
```

Reports DEK counts, distribution by context type, distribution by KEK version, and optionally runs a round-trip encrypt/decrypt validation against every DEK to catch corruption or provider drift.
