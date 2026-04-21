<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Services;

use Crumbls\Sealcraft\Values\EncryptionContext;

/**
 * Request-scoped in-memory cache for plaintext DEKs.
 *
 * Registered as a singleton in the service provider; the container
 * rebuilds it per request in standard Laravel, per job in queue
 * workers, and needs explicit flush between Octane ticks (wired via
 * an Octane RequestTerminated listener in the service provider).
 *
 * Flush overwrites each cached DEK with null bytes before removing
 * the entry. This is best-effort: PHP cannot guarantee the zero bytes
 * reach the underlying memory, and PHP's string copy-on-write and
 * garbage collector may retain unreachable copies. Still worth doing.
 */
final class DekCache
{
    /** @var array<string, string> */
    private array $entries = [];

    public function has(EncryptionContext $ctx): bool
    {
        return isset($this->entries[$ctx->toCanonicalHash()]);
    }

    public function get(EncryptionContext $ctx): ?string
    {
        return $this->entries[$ctx->toCanonicalHash()] ?? null;
    }

    public function put(EncryptionContext $ctx, string $plaintextDek): void
    {
        $this->entries[$ctx->toCanonicalHash()] = $plaintextDek;
    }

    public function forget(EncryptionContext $ctx): void
    {
        $hash = $ctx->toCanonicalHash();

        if (isset($this->entries[$hash])) {
            $this->entries[$hash] = str_repeat("\0", strlen($this->entries[$hash]));
            unset($this->entries[$hash]);
        }
    }

    public function flush(): void
    {
        foreach ($this->entries as $hash => $value) {
            $this->entries[$hash] = str_repeat("\0", strlen($value));
        }

        $this->entries = [];
    }

    public function count(): int
    {
        return count($this->entries);
    }

    public function __destruct()
    {
        $this->flush();
    }
}
