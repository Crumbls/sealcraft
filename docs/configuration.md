---
title: Configuration
weight: 70
---

The published `config/sealcraft.php` file is the source of truth for Sealcraft's runtime behavior. This page covers the knobs you are most likely to adjust.

## Core knobs

```php
return [
    'default_provider' => env('SEALCRAFT_PROVIDER', 'local'),
    'default_cipher'   => env('SEALCRAFT_CIPHER', 'aes-256-gcm'),
    'dek_strategy'     => env('SEALCRAFT_DEK_STRATEGY', 'per_group'),
    'context_column'   => env('SEALCRAFT_CONTEXT_COLUMN', 'id'),
    'context_type'     => env('SEALCRAFT_CONTEXT_TYPE', null),
    'auto_reencrypt_on_context_change' => env('SEALCRAFT_AUTO_REENCRYPT', true),
    // ...
];
```

| Key | Purpose | Default |
|---|---|---|
| `default_provider` | KEK provider name | `local` |
| `default_cipher` | `aes-256-gcm` or `xchacha20` | `aes-256-gcm` |
| `dek_strategy` | `per_group` or `per_row` | `per_group` |
| `context_column` | Default context column for per-group models | `id` |
| `context_type` | Default context type string | null (uses table name) |
| `auto_reencrypt_on_context_change` | Auto re-encrypt when a context column changes | `true` |

Any of these can be overridden per model by setting the matching property on the model class (e.g. `$sealcraftStrategy`).

## Rate limiting

```php
'rate_limit' => [
    'unwrap_per_minute' => env('SEALCRAFT_UNWRAP_RATE', 0),
],
```

Per-context unwrap throttle. `0` disables. Set this to blunt attacks that try to bulk-enumerate wrapped DEKs through a compromised KMS network path. A legitimate request pattern rarely exceeds a few unwraps per context per minute because of the in-memory DEK cache.

## Providers block

Each provider has its own block. The most relevant keys for production providers:

- **AWS KMS**: `key_id`, `region`
- **GCP Cloud KMS**: `project`, `location`, `key_ring`, `crypto_key`, `token_resolver`
- **Azure Key Vault**: `vault_url`, `key_name`, `aad_strategy`, `token_resolver`, `hmac_key_resolver`
- **Vault Transit**: `addr`, `token`, `key_name`, `mount`, `token_resolver`
- **Local**: `path`, `allow_production`

See each provider's page for full details:

- [AWS KMS](/documentation/sealcraft/v1/providers/aws-kms)
- [GCP Cloud KMS](/documentation/sealcraft/v1/providers/gcp-kms)
- [Azure Key Vault](/documentation/sealcraft/v1/providers/azure-key-vault)
- [HashiCorp Vault Transit](/documentation/sealcraft/v1/providers/vault-transit)
- [Local](/documentation/sealcraft/v1/providers/local)

## Recommended production env

```dotenv
SEALCRAFT_PROVIDER=aws_kms
SEALCRAFT_CIPHER=aes-256-gcm
SEALCRAFT_DEK_STRATEGY=per_group
SEALCRAFT_AUTO_REENCRYPT=true
SEALCRAFT_UNWRAP_RATE=60
SEALCRAFT_AWS_KEY_ID=alias/my-app-kek
SEALCRAFT_AWS_REGION=us-east-1
```
