---
title: Troubleshooting
weight: 110
---

Common errors, what they mean, and the exact fix.

## `SealcraftException: provider [X] is not configured`

The driver factory could not find a config block named `X` under `sealcraft.providers`. The exception message lists every valid name.

**Fix:**
- Set `SEALCRAFT_PROVIDER` in `.env` to one of the listed names, or
- Add a new block to `config/sealcraft.php` under `providers.X`.

Likely culprits:
- Typo: `azure_kv` instead of `azure_key_vault` (renamed in 0.1.5 — see CHANGELOG).
- Missing config publish: run `php artisan sealcraft:install` once.

## `SealcraftException: provider driver [X] is not registered`

The config block's `driver` key names a driver the registry does not know. The message lists the registered drivers.

**Fix:** set the block's `driver` to one of `aws_kms`, `gcp_kms`, `azure_key_vault`, `vault_transit`, `local`, `config`, `null`, or register your own via `ProviderRegistry::extend()`.

## `SealcraftException: cipher [X] is not configured` / `cipher driver [X] is not registered`

Same pattern for ciphers. Valid cipher names live under `sealcraft.ciphers`; valid drivers are `aes-256-gcm` and `xchacha20-poly1305`. Note that XChaCha20 requires `ext-sodium`.

## `InvalidContextException: Per-group Sealcraft strategy requires column [X] to be set`

A per-group model is trying to derive its context but the required column is null or empty on the model instance.

**Fix:**
- Set the column before calling the encrypted attribute: `$model->tenant_id = 42;`
- Or switch to per-row with `protected string $sealcraftStrategy = 'per_row';` (requires a `sealcraft_key` column).
- Or override `sealcraftContext()` entirely to compute the context from a relationship.

## `InvalidContextException: ...has empty row-key column...Backfill via sealcraft:backfill-row-keys`

A per-row model row exists in the database with a null `sealcraft_key`. Reading or writing encrypted attributes on it would mint a throwaway context and guarantee decrypt failure later.

**Fix:** run the command the exception names:

```bash
php artisan sealcraft:backfill-row-keys "App\\Models\\YourModel"
```

It is idempotent and bypasses model events, so it is safe to run on tables that already contain ciphertext.

## `DecryptionFailedException: ...has no recognizable cipher ID prefix`

The column holds a value that does not look like a sealcraft ciphertext envelope. Usually a legacy `APP_KEY`-encrypted value or a plain-string value from before sealcraft was adopted.

**Fix:** do the "migrate from APP_KEY" flow the README describes — read the raw value out-of-band (`DB::table(...)->value(...)` or `$model->getRawOriginal(...)`), assign it back through the `Encrypted` cast, and save. The cast will encrypt it on write.

## `ContextShreddedException` on read/write

Expected — this is right-to-be-forgotten firing. Render a "record destroyed at user request" message in your app. If you got here by accident, the DEK for that context has been retired AND flagged `shredded_at`; it cannot be recovered.

## `KekUnavailableException: ...`

Your KEK provider is unreachable or the provider rejected the call.

**Fix:**
- Network: is the KMS endpoint reachable from the app host?
- Auth: is the IAM role / managed identity / Vault token configured?
- Env: run `php artisan sealcraft:verify` to round-trip a synthetic DEK through the configured provider. It will fail fast with a per-provider hint if a credential is missing.

## Boot-time `SealcraftException: Sealcraft config error: ...`

Fail-fast validation caught a missing or malformed config value. The message names the env var to set. Fix and redeploy.

If you need to boot temporarily with bad config (e.g. during a staged migration), set `SEALCRAFT_VALIDATE_ON_BOOT=false`. Re-enable before production.

## "How do I verify my setup works?"

```bash
php artisan sealcraft:verify
```

It creates a synthetic DEK, unwraps it, encrypts and decrypts a known plaintext through the configured cipher, and shreds the synthetic context. Exit zero = production-ready.
