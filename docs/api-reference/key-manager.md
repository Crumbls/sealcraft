---
title: KeyManager
weight: 10
---

`Crumbls\Sealcraft\Services\KeyManager` is the main entry point. It is a container singleton; resolve it via DI or `app()`.

## Key methods

```php
/** Encrypt plaintext under the DEK for a given context. */
public function encrypt(string $plaintext, EncryptionContext $context): string;

/** Decrypt ciphertext under the DEK for a given context. */
public function decrypt(string $ciphertext, EncryptionContext $context): string;

/** Force-create a DEK for a context without writing any data. */
public function provisionDek(EncryptionContext $context): DataKey;

/** Rotate the KEK wrapping for one context (or all if $context is null). */
public function rotateKek(?EncryptionContext $context = null, ?string $provider = null): int;

/** Re-encrypt every row under a new DEK. Expects a quiesced context. */
public function rotateDek(string $modelClass, EncryptionContext $context): int;

/** Permanently destroy a context's DEK. */
public function shredContext(EncryptionContext $context): void;
```

The cast layer calls `encrypt()` and `decrypt()` transparently; you rarely call them by hand. The rotation and shred methods are usually called via the Artisan commands, but the programmatic API is available for tests, maintenance scripts, or integrations.

## Typical usage

```php
use Crumbls\Sealcraft\Services\KeyManager;
use Crumbls\Sealcraft\Values\EncryptionContext;

$manager = app(KeyManager::class);

$context = EncryptionContext::for('tenant', 42);

$ciphertext = $manager->encrypt('sensitive-value', $context);
$plaintext  = $manager->decrypt($ciphertext, $context);

$manager->shredContext($context);   // right-to-be-forgotten
```

## Caching

`KeyManager` is backed by `DekCache`, a per-process in-memory cache. The service provider registers a `terminating` callback that flushes the cache at end of request. If you run long-lived workers (Octane, Swoole), the cache persists across requests for as long as the worker lives.

You can bypass the cache for a single call by calling `provisionDek()` and using the returned DataKey directly, but this is rarely needed.

## Thread safety

Not thread-safe. Sealcraft assumes PHP's process-per-request model. Workers that use true threads (ReactPHP, Amp multi-threaded runtimes) need their own synchronization.
