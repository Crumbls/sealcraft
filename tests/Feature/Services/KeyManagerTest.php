<?php

declare(strict_types=1);

use Crumbls\Sealcraft\Events\DekCreated;
use Crumbls\Sealcraft\Events\DekRotated;
use Crumbls\Sealcraft\Events\DekUnwrapped;
use Crumbls\Sealcraft\Exceptions\SealcraftException;
use Crumbls\Sealcraft\Models\DataKey;
use Crumbls\Sealcraft\Providers\NullKekProvider;
use Crumbls\Sealcraft\Services\DekCache;
use Crumbls\Sealcraft\Services\KeyManager;
use Crumbls\Sealcraft\Services\ProviderRegistry;
use Crumbls\Sealcraft\Values\EncryptionContext;
use Illuminate\Support\Facades\Event;

beforeEach(function (): void {
    config()->set('sealcraft.default_provider', 'null');

    /** @var ProviderRegistry $registry */
    $registry = $this->app->make(ProviderRegistry::class);
    $registry->extend('null', fn (): NullKekProvider => new NullKekProvider);
    $registry->forget('null');

    $this->manager = $this->app->make(KeyManager::class);
    $this->cache = $this->app->make(DekCache::class);
    $this->cache->flush();

    $this->ctx = new EncryptionContext('tenant', 42);
});

it('creates a new DEK on first access and caches it', function (): void {
    Event::fake([DekCreated::class]);

    $plaintext = $this->manager->getOrCreateDek($this->ctx);

    expect(strlen($plaintext))->toBe(32);
    expect($this->cache->get($this->ctx))->toBe($plaintext);
    expect(DataKey::query()->forContext('tenant', 42)->active()->count())->toBe(1);

    Event::assertDispatched(DekCreated::class);
});

it('returns cached DEK on subsequent access without hitting provider', function (): void {
    $first = $this->manager->getOrCreateDek($this->ctx);
    Event::fake();

    $second = $this->manager->getOrCreateDek($this->ctx);

    expect($second)->toBe($first);
    Event::assertNotDispatched(DekCreated::class);
});

it('unwraps an existing DataKey when cache is cold', function (): void {
    $this->manager->getOrCreateDek($this->ctx);
    $this->cache->flush();

    Event::fake([DekUnwrapped::class]);

    $restored = $this->manager->getOrCreateDek($this->ctx);

    expect(strlen($restored))->toBe(32);
    Event::assertDispatched(DekUnwrapped::class, fn (DekUnwrapped $e): bool => ! $e->cacheHit);
});

it('refuses to create a second active DEK for the same context', function (): void {
    $this->manager->createDek($this->ctx);

    expect(fn () => $this->manager->createDek($this->ctx))
        ->toThrow(SealcraftException::class);
});

it('rotates a DataKey and keeps plaintext DEK stable', function (): void {
    $before = $this->manager->getOrCreateDek($this->ctx);
    $this->cache->flush();

    Event::fake([DekRotated::class]);

    $rotated = $this->manager->rotateKek($this->ctx);

    expect($rotated)->toBe(1);

    $record = DataKey::query()->forContext('tenant', 42)->active()->first();
    expect($record->rotated_at)->not->toBeNull();

    // Plaintext DEK must stay stable so existing ciphertext remains decryptable.
    $after = $this->manager->getOrCreateDek($this->ctx);
    expect($after)->toBe($before);

    Event::assertDispatched(DekRotated::class);
});

it('retires a DataKey via retireDek', function (): void {
    $dk = $this->manager->createDek($this->ctx);

    $this->manager->retireDek($dk);

    expect(DataKey::query()->forContext('tenant', 42)->active()->count())->toBe(0);
    expect(DataKey::query()->forContext('tenant', 42)->retired()->count())->toBe(1);
});

it('honors cache hit on unwrap after initial creation', function (): void {
    $plaintext = $this->manager->getOrCreateDek($this->ctx);

    Event::fake([DekUnwrapped::class]);

    $again = $this->manager->getOrCreateDek($this->ctx);

    expect($again)->toBe($plaintext);
    // Cache is warm — getOrCreateDek returns early without firing DekUnwrapped
    Event::assertNotDispatched(DekUnwrapped::class);
});
