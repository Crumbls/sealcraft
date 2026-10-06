<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Events;

use Crumbls\Sealcraft\Models\DataKey;
use Crumbls\Sealcraft\Values\EncryptionContext;

/**
 * Fired when a context's DEK has been crypto-shredded. Wire to SIEM
 * and any deletion audit trail. The live wrapped DEKs were removed;
 * older backups and replicas require separate retention controls.
 */
final class DekShredded
{
    public function __construct(
        public readonly DataKey $dataKey,
        public readonly EncryptionContext $context,
        public readonly string $providerName,
    ) {}
}
