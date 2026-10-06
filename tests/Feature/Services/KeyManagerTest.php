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
use Crumbls\Sealcraft\Values\WrappedDek;
use Illuminate\Database\QueryException;
use Illuminate\Support\Facades\DB;
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

it('enforces active DEK uniqueness at the database layer too', function (): void {
    $this->manager->createDek($this->ctx);

    expect(fn () => DataKey::query()->create([
        'context_type' => 'tenant',
        'context_id' => '42',
        'active_context_hash' => DataKey::activeContextHash('tenant', '42'),
        'provider_name' => 'null',
        'key_id' => 'manual',
        'key_version' => null,
        'cipher' => 'aes-256-gcm',
        'wrapped_dek' => 'sc1:broken:broken',
    ]))->toThrow(QueryException::class);
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

it('caches DataKey so getActiveDataKey does not repeat queries', function (): void {
    $this->manager->getOrCreateDek($this->ctx);

    DB::flushQueryLog();
    DB::enableQueryLog();

    $first = $this->manager->getActiveDataKey($this->ctx);
    $second = $this->manager->getActiveDataKey($this->ctx);

    $dataKeyQueries = collect(DB::getQueryLog())
        ->filter(fn (array $q): bool => str_contains($q['query'], 'sealcraft_data_keys'))
        ->count();

    expect($dataKeyQueries)->toBe(0);
    expect($first->id)->toBe($second->id);
});

it('honors cache hit on unwrap after initial creation', function (): void {
    $plaintext = $this->manager->getOrCreateDek($this->ctx);

    Event::fake([DekUnwrapped::class]);

    $again = $this->manager->getOrCreateDek($this->ctx);

    expect($again)->toBe($plaintext);
    // Cache is warm — getOrCreateDek returns early without firing DekUnwrapped
    Event::assertNotDispatched(DekUnwrapped::class);
});

it('destroys active and historical wrapped DEKs while retaining a shred tombstone', function (): void {
    $old = $this->manager->createDek($this->ctx);
    $this->manager->retireDek($old);
    $this->manager->createDek($this->ctx);

    $this->manager->shredContext($this->ctx);

    $rows = DataKey::queryForContext('tenant', 42)->get();
    expect($rows)->toHaveCount(2);
    expect($rows->every(fn (DataKey $row): bool => $row->isShredded() && $row->wrapped_dek === 'shredded'))->toBeTrue();
    expect(fn () => WrappedDek::fromStorageString($rows->first()->wrapped_dek))->toThrow(SealcraftException::class);

    $this->manager->shredContext($this->ctx);
    expect(DataKey::queryForContext('tenant', 42)->where('wrapped_dek', '!=', 'shredded')->exists())->toBeFalse();
});

it('shreds retired DEKs even when no active DEK remains', function (): void {
    $old = $this->manager->createDek($this->ctx);
    $this->manager->retireDek($old);

    $this->manager->shredContext($this->ctx);

    $row = DataKey::queryForContext('tenant', 42)->firstOrFail();
    expect($row->wrapped_dek)->toBe('shredded');
    expect($row->isShredded())->toBeTrue();
});

it('does not cache an uncommitted DEK after its outer transaction rolls back', function (): void {
    $rolledBackDek = null;

    try {
        DB::transaction(function () use (&$rolledBackDek): void {
            $rolledBackDek = $this->manager->getOrCreateDek($this->ctx);
            throw new RuntimeException('roll back');
        });
    } catch (RuntimeException) {
    }

    expect(DataKey::queryForContext('tenant', 42)->exists())->toBeFalse();
    expect($this->cache->has($this->ctx))->toBeFalse();

    $replacementDek = $this->manager->getOrCreateDek($this->ctx);
    expect($replacementDek)->not->toBe($rolledBackDek);
    expect(DataKey::queryActiveForContext('tenant', 42)->exists())->toBeTrue();
});
