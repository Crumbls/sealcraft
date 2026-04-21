<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Events;

use Crumbls\Sealcraft\Models\DataKey;

final class DekRotated
{
    public function __construct(
        public readonly DataKey $dataKey,
        public readonly string $providerName,
        public readonly ?string $fromKeyVersion,
        public readonly ?string $toKeyVersion,
    ) {}
}
