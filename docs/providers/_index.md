---
title: KEK Providers
weight: 40
---

A KEK provider wraps and unwraps Data Encryption Keys using a backing key store -- almost always a managed KMS. Sealcraft ships six providers; pick one per environment.

## Production providers

| Provider | `SEALCRAFT_PROVIDER` value | Backing store |
|---|---|---|
| [AWS KMS](/documentation/sealcraft/v1/providers/aws-kms) | `aws_kms` | AWS Key Management Service |
| [GCP Cloud KMS](/documentation/sealcraft/v1/providers/gcp-kms) | `gcp_kms` | Google Cloud KMS |
| [Azure Key Vault](/documentation/sealcraft/v1/providers/azure-key-vault) | `azure_kv` | Azure Key Vault |
| [HashiCorp Vault Transit](/documentation/sealcraft/v1/providers/vault-transit) | `vault_transit` | Vault Transit secrets engine |

## Non-production providers

| Provider | `SEALCRAFT_PROVIDER` value | Use |
|---|---|---|
| [Local](/documentation/sealcraft/v1/providers/local) | `local` | Dev / test -- key is a file on disk |
| Null | `null` | Unit tests -- in-memory, ephemeral |

## Selecting a provider

Set `SEALCRAFT_PROVIDER` in `.env`:

```dotenv
SEALCRAFT_PROVIDER=aws_kms
```

Or in `config/sealcraft.php`:

```php
'default_provider' => 'aws_kms',
```

## What the provider does

Every provider implements `Crumbls\Sealcraft\Contracts\KekProvider`:

- `wrap(string $plaintextDek, EncryptionContext $context): WrappedDek`
- `unwrap(WrappedDek $wrapped, EncryptionContext $context): string`

Some providers also implement:

- `SupportsKeyVersioning` -- exposes the KEK version that wrapped a given DEK (required for KEK rotation)
- `SupportsNativeAad` -- the provider binds the context as AAD at the wrap layer (AWS, GCP); when absent, Sealcraft binds at the cipher layer only

## Native AAD vs synthetic AAD

- **AWS KMS, GCP Cloud KMS**: accept arbitrary AAD on `Encrypt`/`Decrypt` API calls. Sealcraft passes the canonical serialized context through.
- **Azure Key Vault, Vault Transit**: `wrapKey`/`unwrapKey` do not accept AAD. Sealcraft defaults to a **synthetic** strategy -- prepending an HMAC-SHA256 of the canonical context over the DEK and verifying on unwrap. Provides defense-in-depth equivalent to native AAD.

The canonical context is NFC-normalized UTF-8 with byte-sorted keys, escaped separators, and a 4KB size cap, so both strategies produce a stable binding.
