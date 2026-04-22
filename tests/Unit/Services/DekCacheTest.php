<?php

declare(strict_types=1);

use Crumbls\Sealcraft\Models\DataKey;
use Crumbls\Sealcraft\Services\DekCache;
use Crumbls\Sealcraft\Values\EncryptionContext;

beforeEach(function (): void {
    $this->cache = new DekCache;
    $this->ctx = new EncryptionContext('tenant', 42);
});

it('returns null for an unknown context', function (): void {
    expect($this->cache->has($this->ctx))->toBeFalse();
    expect($this->cache->get($this->ctx))->toBeNull();
});

it('stores and retrieves a DEK keyed by context hash', function (): void {
    $dek = random_bytes(32);

    $this->cache->put($this->ctx, $dek);

    expect($this->cache->has($this->ctx))->toBeTrue();
    expect($this->cache->get($this->ctx))->toBe($dek);
});

it('isolates entries between contexts', function (): void {
    $a = random_bytes(32);
    $b = random_bytes(32);

    $this->cache->put(new EncryptionContext('tenant', 1), $a);
    $this->cache->put(new EncryptionContext('tenant', 2), $b);

    expect($this->cache->get(new EncryptionContext('tenant', 1)))->toBe($a);
    expect($this->cache->get(new EncryptionContext('tenant', 2)))->toBe($b);
    expect($this->cache->count())->toBe(2);
});

it('forgets a single context without touching others', function (): void {
    $this->cache->put(new EncryptionContext('tenant', 1), 'a');
    $this->cache->put(new EncryptionContext('tenant', 2), 'b');

    $this->cache->forget(new EncryptionContext('tenant', 1));

    expect($this->cache->has(new EncryptionContext('tenant', 1)))->toBeFalse();
    expect($this->cache->has(new EncryptionContext('tenant', 2)))->toBeTrue();
});

it('flushes all entries', function (): void {
    $this->cache->put(new EncryptionContext('tenant', 1), 'a');
    $this->cache->put(new EncryptionContext('tenant', 2), 'b');

    $this->cache->flush();

    expect($this->cache->count())->toBe(0);
    expect($this->cache->has(new EncryptionContext('tenant', 1)))->toBeFalse();
});

it('stores and retrieves a DataKey alongside the DEK', function (): void {
    $dek = random_bytes(32);
    $dataKey = new DataKey;
    $dataKey->forceFill(['id' => 1, 'provider_name' => 'null', 'cipher' => 'aes-256-gcm']);

    $this->cache->put($this->ctx, $dek, $dataKey);

    expect($this->cache->getDataKey($this->ctx))->toBe($dataKey);
});

it('returns null DataKey for an unknown context', function (): void {
    expect($this->cache->getDataKey($this->ctx))->toBeNull();
});

it('stores a DataKey independently via putDataKey', function (): void {
    $dataKey = new DataKey;
    $dataKey->forceFill(['id' => 2, 'provider_name' => 'local']);

    $this->cache->putDataKey($this->ctx, $dataKey);

    expect($this->cache->getDataKey($this->ctx))->toBe($dataKey);
    expect($this->cache->get($this->ctx))->toBeNull();
});

it('forgets DataKey when forgetting a context', function (): void {
    $dataKey = new DataKey;
    $dataKey->forceFill(['id' => 3]);

    $this->cache->put($this->ctx, 'dek', $dataKey);
    $this->cache->forget($this->ctx);

    expect($this->cache->getDataKey($this->ctx))->toBeNull();
});

it('flushes DataKeys alongside DEKs', function (): void {
    $dataKey = new DataKey;
    $dataKey->forceFill(['id' => 4]);

    $this->cache->put($this->ctx, 'dek', $dataKey);
    $this->cache->flush();

    expect($this->cache->getDataKey($this->ctx))->toBeNull();
});
