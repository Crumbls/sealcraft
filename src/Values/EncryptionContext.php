<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Values;

use Crumbls\Sealcraft\Services\ContextSerializer;

/**
 * Deterministic, canonically-serialized representation of the context a
 * DEK is bound to. Used as AAD at the cipher layer and, where providers
 * support it natively, at the wrap layer as well.
 *
 * Canonical bytes are computed lazily on first access and memoized.
 */
final class EncryptionContext
{
    private ?string $canonicalCache = null;

    /**
     * @param  array<string, scalar|null>  $attributes
     */
    public function __construct(
        public readonly string $contextType,
        public readonly string|int $contextId,
        public readonly array $attributes = [],
    ) {}

    public function toCanonicalBytes(): string
    {
        return $this->canonicalCache ??= ContextSerializer::canonicalize(
            $this->contextType,
            $this->contextId,
            $this->attributes,
        );
    }

    public function toCanonicalHash(): string
    {
        return hash('sha256', $this->toCanonicalBytes());
    }

    /**
     * Structured form for AWS KMS EncryptionContext parameter. Values are
     * coerced to strings; null/empty attributes are stripped.
     *
     * @return array<string, string>
     */
    public function toAwsEncryptionContext(): array
    {
        $out = [
            'ctx_type' => $this->contextType,
            'ctx_id' => (string) $this->contextId,
        ];

        foreach ($this->attributes as $key => $value) {
            if ($value === null || $value === '') {
                continue;
            }

            if (is_bool($value)) {
                $out[$key] = $value ? 'true' : 'false';

                continue;
            }

            $out[$key] = (string) $value;
        }

        return $out;
    }

    public function toGcpAdditionalAuthenticatedData(): string
    {
        return $this->toCanonicalBytes();
    }

    public function toVaultTransitContext(): string
    {
        return base64_encode($this->toCanonicalBytes());
    }

    public function toSyntheticAadHmac(string $hmacKey): string
    {
        return hash_hmac('sha256', $this->toCanonicalBytes(), $hmacKey, true);
    }
}
