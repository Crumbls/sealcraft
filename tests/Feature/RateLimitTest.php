<?php

declare(strict_types=1);

use Crumbls\Sealcraft\Exceptions\SealcraftException;
use Crumbls\Sealcraft\Services\DekCache;
use Crumbls\Sealcraft\Services\KeyManager;
use Crumbls\Sealcraft\Values\EncryptionContext;
use Illuminate\Support\Facades\RateLimiter;

beforeEach(function (): void {
    config()->set('sealcraft.default_provider', 'null');
    config()->set('sealcraft.default_cipher', 'aes-256-gcm');

    $cache = $this->app->make(DekCache::class);
    $cache->flush();

    RateLimiter::clear('sealcraft:unwrap:' . (new EncryptionContext('tenant', 1))->toCanonicalHash());
});

it('throws once the unwrap rate limit is exceeded for a context', function (): void {
    config()->set('sealcraft.rate_limit.unwrap_per_minute', 2);

    $manager = $this->app->make(KeyManager::class);
    $ctx = new EncryptionContext('tenant', 1);

    // First call creates + caches the DEK.
    $manager->getOrCreateDek($ctx);
    $this->app->make(DekCache::class)->flush();

    // Provider-level unwrap consumes a slot each time the cache is cold.
    $manager->getOrCreateDek($ctx);
    $this->app->make(DekCache::class)->flush();

    $manager->getOrCreateDek($ctx);
    $this->app->make(DekCache::class)->flush();

    expect(fn () => $manager->getOrCreateDek($ctx))
        ->toThrow(SealcraftException::class);
});

it('does not apply the rate limit when disabled (limit = 0)', function (): void {
    config()->set('sealcraft.rate_limit.unwrap_per_minute', 0);

    $manager = $this->app->make(KeyManager::class);
    $ctx = new EncryptionContext('tenant', 1);

    for ($i = 0; $i < 20; $i++) {
        $manager->getOrCreateDek($ctx);
        $this->app->make(DekCache::class)->flush();
    }

    expect(true)->toBeTrue();
});

it('does not consume a rate-limit slot on cache hits', function (): void {
    config()->set('sealcraft.rate_limit.unwrap_per_minute', 2);

    $manager = $this->app->make(KeyManager::class);
    $ctx = new EncryptionContext('tenant', 1);

    // Warm the cache once (consumes 0 attempts).
    $manager->getOrCreateDek($ctx);

    // 20 cache hits should never hit the rate limiter.
    for ($i = 0; $i < 20; $i++) {
        $manager->getOrCreateDek($ctx);
    }

    expect(true)->toBeTrue();
});
