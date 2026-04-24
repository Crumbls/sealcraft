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

## Publish config and migrations

```bash
php artisan vendor:publish --tag=sealcraft-config
php artisan vendor:publish --tag=sealcraft-migrations
php artisan migrate
```

The migration creates the `sealcraft_data_keys` table that stores wrapped DEKs -- one row per `(context_type, context_id)` pair (per-group strategy) or one row per record (per-row strategy).

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
