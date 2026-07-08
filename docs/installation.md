---
title: Installation
weight: 20
---

## Requirements

- PHP 8.2 or later
- `ext-openssl`, `ext-intl`
- `ext-sodium` if you want the XChaCha20-Poly1305 cipher
- Laravel 11, 12, or 13
- A KMS provider for production (AWS KMS, GCP Cloud KMS, Azure Key Vault, or HashiCorp Vault Transit)

## Install the package

```bash
composer require crumbls/sealcraft
```

## Publish config

```bash
php artisan vendor:publish --tag=sealcraft-config
php artisan migrate
```

Sealcraft auto-loads its package migration when no published copy exists. The migration creates the `sealcraft_data_keys` table that stores wrapped DEKs -- one row per `(context_type, context_id)` pair (per-group strategy) or one row per record (per-row strategy).

If your application requires owning every migration file, publish it too:

```bash
php artisan vendor:publish --tag=sealcraft-migrations
php artisan migrate
```

When a published `*_create_sealcraft_data_keys_table.php` migration is present, the package skips auto-loading its internal copy so Laravel does not see two pending migrations for the same table.

## Install provider SDKs

Only install the SDK for the KMS you use:

```bash
composer require aws/aws-sdk-php          # for AWS KMS
composer require google/cloud-kms         # for GCP Cloud KMS
```

Azure Key Vault and HashiCorp Vault Transit use Laravel's built-in HTTP client -- no SDK required.

## Verify

Run `php artisan list sealcraft` to confirm the commands registered:

```
sealcraft:audit
sealcraft:backfill-row-keys
sealcraft:generate-dek
sealcraft:migrate-provider
sealcraft:reencrypt-context
sealcraft:rotate-dek
sealcraft:rotate-kek
sealcraft:shred
```

## What's next

- [Configuration](/documentation/sealcraft/v1/configuration) -- config file reference
- [Getting started](/documentation/sealcraft/v1/getting-started) -- encrypt your first model
- [Providers](/documentation/sealcraft/v1/providers) -- wire up a KMS
