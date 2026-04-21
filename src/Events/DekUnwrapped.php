<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Events;

use Crumbls\Sealcraft\Models\DataKey;
use Crumbls\Sealcraft\Values\EncryptionContext;

final class DekUnwrapped
{
    public function __construct(
        public readonly DataKey $dataKey,
        public readonly EncryptionContext $context,
        public readonly string $providerName,
        public readonly bool $cacheHit,
    ) {}
}
