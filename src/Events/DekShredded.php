<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Events;

use Crumbls\Sealcraft\Models\DataKey;
use Crumbls\Sealcraft\Values\EncryptionContext;

/**
 * Fired when a context's DEK has been crypto-shredded. Wire to SIEM
 * and any right-to-be-forgotten audit trail: once this event fires,
 * every ciphertext previously encrypted under this context is
 * permanently unrecoverable.
 */
final class DekShredded
{
    public function __construct(
        public readonly DataKey $dataKey,
        public readonly EncryptionContext $context,
        public readonly string $providerName,
    ) {}
}
