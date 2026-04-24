---
title: Contracts
weight: 20
---

Interfaces for extending Sealcraft with custom providers or ciphers.

## `KekProvider`

`Crumbls\Sealcraft\Contracts\KekProvider`

Every KEK provider implements:

```php
public function wrap(string $plaintextDek, EncryptionContext $context): WrappedDek;
public function unwrap(WrappedDek $wrapped, EncryptionContext $context): string;
public function name(): string;
public function capabilities(): ProviderCapabilities;
```

## Capability marker interfaces

A provider opts into optional features by also implementing:

- `SupportsKeyVersioning` -- exposes the KEK version that wrapped a given DEK. Required for `sealcraft:rotate-kek`.
- `SupportsNativeAad` -- the provider binds the context as AAD at the wrap layer. When absent, Sealcraft applies cipher-layer AAD only (or synthetic AAD on a case-by-case basis for Azure Key Vault).

## `Cipher`

`Crumbls\Sealcraft\Contracts\Cipher`

```php
public function encrypt(string $plaintext, string $key, string $aad): string;
public function decrypt(string $ciphertext, string $key, string $aad): string;
public function name(): string;
```

The returned ciphertext includes a self-describing header so `CipherRegistry` can route decryption to the right implementation even after the default cipher changes.

## `GeneratesDataKeys`

`Crumbls\Sealcraft\Contracts\GeneratesDataKeys`

An optional interface for providers that can natively generate a DEK-KEK pair in a single API call (e.g. AWS KMS `GenerateDataKey`). If not implemented, Sealcraft generates the DEK locally with `random_bytes(32)` and wraps it via `wrap()`.

## `DekResolver`

`Crumbls\Sealcraft\Contracts\DekResolver`

Internal -- resolves a DEK for a context (cache-aware). Applications do not implement this; they use `KeyManager` instead.

## Registering a custom provider

```php
use Crumbls\Sealcraft\Services\ProviderRegistry;

app(ProviderRegistry::class)->extend('my_custom_kms', function ($app, array $config) {
    return new MyCustomKmsProvider($config);
});
```

Then set `SEALCRAFT_PROVIDER=my_custom_kms`.

## Registering a custom cipher

```php
use Crumbls\Sealcraft\Services\CipherRegistry;

app(CipherRegistry::class)->extend('my-cipher', fn () => new MyCipher);
```

Ciphertext tagged with `my-cipher` decrypts through `MyCipher` forever, even if the default changes.
