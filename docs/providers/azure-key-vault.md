---
title: Azure Key Vault
weight: 30
---

Azure Key Vault uses `wrapKey` / `unwrapKey` which do not accept AAD at the KMS layer. Sealcraft compensates with a synthetic AAD strategy that provides equivalent binding.

## Configure

```dotenv
SEALCRAFT_PROVIDER=azure_kv
SEALCRAFT_AZURE_VAULT_URL=https://my-vault.vault.azure.net
SEALCRAFT_AZURE_KEY_NAME=app-kek
SEALCRAFT_AZURE_AAD_STRATEGY=synthetic
```

## AAD strategies

| Strategy | Behavior | When to use |
|---|---|---|
| `synthetic` (default) | Prepends an HMAC-SHA256 of the canonical context over the DEK before wrapping; verifies on unwrap | Always, unless you have a specific reason not to |
| `cipher_only` | Relies solely on cipher-layer AAD plus Key Vault RBAC | You trust Key Vault access control fully and want lower wrap payload size |

The synthetic strategy catches cross-context replay even if an attacker somehow swaps wrapped DEKs across records -- the HMAC fails to verify against a mismatched context.

## Bind the resolvers

```php
use Illuminate\Support\Facades\Config;

Config::set([
    'sealcraft.providers.azure_kv.token_resolver'     => fn () => Azure::kvToken(),
    'sealcraft.providers.azure_kv.hmac_key_resolver'  => fn () => AzureSecretHelper::hmacKeyBytes(),
]);
```

- `token_resolver` returns a bearer token for `https://vault.azure.net/.default`. Use managed identity if possible.
- `hmac_key_resolver` returns 32+ raw bytes used to derive the synthetic AAD HMAC. Store this as a separate Key Vault secret; rotating it invalidates all existing wrapped DEKs so coordinate with a DEK rotation if you rotate it deliberately.

## Permissions

Grant the managed identity:

- `Key Vault Crypto User` role on the vault (for `wrapKey`/`unwrapKey`)
- `Key Vault Secrets User` role if you store the HMAC key as a secret

## Caveats

- `wrapKey`/`unwrapKey` go over HTTPS; no SDK dependency, but you are responsible for retry and backoff. Laravel's HTTP client defaults are reasonable.
- Key Vault has a per-vault throttle limit (2000 req/10s for `secrets` / `keys`). Heavy backfill jobs should use `--chunk` and a sleep between batches.
