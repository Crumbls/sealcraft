<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Events;

use Crumbls\Sealcraft\Values\EncryptionContext;

/**
 * Fired when the unwrap rate limit is tripped for a context. A SIEM rule
 * on this event can detect enumeration attempts before they reach the KMS.
 *
 * Never includes plaintext DEK or PHI.
 */
final class UnwrapRateLimited
{
    public function __construct(
        public readonly EncryptionContext $context,
        public readonly int $limitPerMinute,
    ) {}
}
