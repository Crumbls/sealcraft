<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Services;

use Crumbls\Sealcraft\Models\DataKey;
use Crumbls\Sealcraft\Values\EncryptionContext;

/**
 * Request-scoped in-memory cache for plaintext DEKs.
 *
 * Registered as a singleton in the service provider; the container
 * rebuilds it per request in standard Laravel, per job in queue
 * workers, and needs explicit flush between Octane ticks (wired via
 * an Octane RequestTerminated listener in the service provider).
 *
 * A bounded LRU eviction policy caps the cache at N entries so
 * long-running workers (Horizon, Octane) that touch many tenants over
 * time do not leak an unbounded set of plaintext DEKs. Configure via
 * `sealcraft.dek_cache.max_entries` (default: 1024).
 *
 * Flush overwrites each cached DEK with null bytes before removing
 * the entry. This is best-effort: PHP cannot guarantee the zero bytes
 * reach the underlying memory, and PHP's string copy-on-write and
 * garbage collector may retain unreachable copies. Still worth doing.
 */
final class DekCache
{
    private const DEFAULT_MAX_ENTRIES = 1024;

    /** @var array<string, string> */
    private array $entries = [];

    /** @var array<string, DataKey> */
    private array $dataKeys = [];

    public function __construct(
        private readonly int $maxEntries = self::DEFAULT_MAX_ENTRIES,
    ) {}

    public function has(EncryptionContext $ctx): bool
    {
        return isset($this->entries[$ctx->toCanonicalHash()]);
    }

    public function get(EncryptionContext $ctx): ?string
    {
        $hash = $ctx->toCanonicalHash();

        if (! isset($this->entries[$hash])) {
            return null;
        }

        // Touch: move to the end for LRU recency tracking.
        $value = $this->entries[$hash];
        unset($this->entries[$hash]);
        $this->entries[$hash] = $value;

        return $value;
    }

    public function getDataKey(EncryptionContext $ctx): ?DataKey
    {
        return $this->dataKeys[$ctx->toCanonicalHash()] ?? null;
    }

    public function put(EncryptionContext $ctx, string $plaintextDek, ?DataKey $dataKey = null): void
    {
        $hash = $ctx->toCanonicalHash();

        // If the key already exists, delete it so the re-insert moves it
        // to the end (most-recently-used) of the hash-ordered array.
        if (isset($this->entries[$hash])) {
            $this->entries[$hash] = str_repeat("\0", strlen($this->entries[$hash]));
            unset($this->entries[$hash]);
        }

        $this->entries[$hash] = $plaintextDek;

        if ($dataKey !== null) {
            $this->dataKeys[$hash] = $dataKey;
        }

        $this->evictIfOverCap();
    }

    public function putDataKey(EncryptionContext $ctx, DataKey $dataKey): void
    {
        $this->dataKeys[$ctx->toCanonicalHash()] = $dataKey;
    }

    public function forget(EncryptionContext $ctx): void
    {
        $hash = $ctx->toCanonicalHash();

        if (isset($this->entries[$hash])) {
            $this->entries[$hash] = str_repeat("\0", strlen($this->entries[$hash]));
            unset($this->entries[$hash]);
        }

        unset($this->dataKeys[$hash]);
    }

    public function flush(): void
    {
        foreach ($this->entries as $hash => $value) {
            $this->entries[$hash] = str_repeat("\0", strlen($value));
        }

        $this->entries = [];
        $this->dataKeys = [];
    }

    public function count(): int
    {
        return count($this->entries);
    }

    public function maxEntries(): int
    {
        return $this->maxEntries;
    }

    private function evictIfOverCap(): void
    {
        if ($this->maxEntries <= 0) {
            return;
        }

        while (count($this->entries) > $this->maxEntries) {
            $oldestHash = array_key_first($this->entries);

            if ($oldestHash === null) {
                return;
            }

            $this->entries[$oldestHash] = str_repeat("\0", strlen($this->entries[$oldestHash]));
            unset($this->entries[$oldestHash], $this->dataKeys[$oldestHash]);
        }
    }

    public function __destruct()
    {
        $this->flush();
    }
}
