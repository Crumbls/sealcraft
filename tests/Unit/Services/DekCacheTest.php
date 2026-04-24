<?php

declare(strict_types=1);

use Crumbls\Sealcraft\Models\DataKey;
use Crumbls\Sealcraft\Services\DekCache;
use Crumbls\Sealcraft\Values\EncryptionContext;

beforeEach(function (): void {
    $this->cache = new DekCache;
    $this->ctx = new EncryptionContext('tenant', 42);
});

it('evicts least-recently-used entries when max_entries is exceeded', function (): void {
    $cache = new DekCache(maxEntries: 3);

    $a = new EncryptionContext('tenant', 'a');
    $b = new EncryptionContext('tenant', 'b');
    $c = new EncryptionContext('tenant', 'c');
    $d = new EncryptionContext('tenant', 'd');

    $cache->put($a, 'dek-a');
    $cache->put($b, 'dek-b');
    $cache->put($c, 'dek-c');
    expect($cache->count())->toBe(3);

    // Touch $a — this moves it to the MRU position
    $cache->get($a);

    // Add $d — eviction should take the LRU ($b), not $a
    $cache->put($d, 'dek-d');

    expect($cache->count())->toBe(3);
    expect($cache->has($a))->toBeTrue();
    expect($cache->has($b))->toBeFalse();
    expect($cache->has($c))->toBeTrue();
    expect($cache->has($d))->toBeTrue();
});

it('does not evict when max_entries is 0 (unbounded mode)', function (): void {
    $cache = new DekCache(maxEntries: 0);

    for ($i = 0; $i < 10; $i++) {
        $cache->put(new EncryptionContext('tenant', (string) $i), "dek-{$i}");
    }

    expect($cache->count())->toBe(10);
});

it('re-inserting an existing key refreshes its LRU position', function (): void {
    $cache = new DekCache(maxEntries: 2);

    $a = new EncryptionContext('tenant', 'a');
    $b = new EncryptionContext('tenant', 'b');
    $c = new EncryptionContext('tenant', 'c');

    $cache->put($a, 'dek-a');
    $cache->put($b, 'dek-b');
    $cache->put($a, 'dek-a-v2'); // refresh LRU position of a

    $cache->put($c, 'dek-c'); // should evict $b (oldest), not $a

    expect($cache->has($a))->toBeTrue();
    expect($cache->has($b))->toBeFalse();
    expect($cache->has($c))->toBeTrue();
});

it('exposes the configured max_entries value', function (): void {
    expect((new DekCache(maxEntries: 512))->maxEntries())->toBe(512);
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
