<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Values;

/**
 * Plaintext DEK paired with its wrapped form. The plaintext is raw key
 * material and should be treated as radioactive — consumers must not
 * retain it beyond the minimum required window. Sealcraft hands these
 * to KeyManager which pushes plaintext into the request-scoped
 * DekCache and discards this wrapper immediately.
 */
final class DataKeyPair
{
    public function __construct(
        public readonly string $plaintext,
        public readonly WrappedDek $wrapped,
    ) {}
}
