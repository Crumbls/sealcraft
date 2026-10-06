---
title: HashiCorp Vault Transit
weight: 40
---

HashiCorp Vault's Transit secrets engine is a KMS-as-a-service you run yourself. No SDK dependency -- Sealcraft uses Laravel's HTTP client.

## Configure

```dotenv
SEALCRAFT_PROVIDER=vault_transit
SEALCRAFT_VAULT_ADDR=https://vault.internal:8200
SEALCRAFT_VAULT_TOKEN=s.xxxxxxxxxxxxxxxx
SEALCRAFT_VAULT_KEY_NAME=app-kek
SEALCRAFT_VAULT_MOUNT=transit
```

## Token rotation

Do not put a long-lived root token in `SEALCRAFT_VAULT_TOKEN`. Use one of:

- **AppRole** with short-lived tokens; rotate via a sidecar or Vault Agent
- **Kubernetes auth** if you run on K8s
- **AWS IAM auth** if you run on EC2/EKS

Bind a token resolver in a service provider for dynamic tokens:

```php
Config::set(
    'sealcraft.providers.vault_transit.token_resolver',
    fn (): string => VaultAgent::token(),
);
```

## Transit key policy

Your token needs:

```hcl
path "transit/encrypt/app-kek" { capabilities = ["update"] }
path "transit/decrypt/app-kek" { capabilities = ["update"] }
path "transit/keys/app-kek"    { capabilities = ["read"] }
```

The `read` on `transit/keys/app-kek` is required for `sealcraft:rotate-kek` to discover the latest key version.

## AAD

New wraps send canonical context bytes as both Transit `context` (for derived keys) and `associated_data` (AEAD authentication). `context` alone only derives a key when the Transit key has `derived=true`; it does not provide AAD on a regular key. Use an AEAD Transit key such as `aes256-gcm96`.

Wrapped DEKs created by older Sealcraft releases carry no `associated_data` marker. They remain readable through the legacy request path. After upgrading, run `sealcraft:rotate-kek` to rewrap them with authenticated data. Until then, older wraps under a non-derived Transit key do not have wrap-layer context authentication.

## Key rotation

```bash
vault write -f transit/keys/app-kek/rotate
```

Then:

```bash
php artisan sealcraft:rotate-kek
```

Vault retains old key versions indefinitely by default, so rotation is zero-downtime. Configure `min_decryption_version` on the transit key to retire old versions once all DEKs have been rewrapped.
