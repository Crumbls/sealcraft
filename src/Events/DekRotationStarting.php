<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Events;

use Crumbls\Sealcraft\Models\DataKey;
use Crumbls\Sealcraft\Values\EncryptionContext;

/**
 * Fired immediately before sealcraft:rotate-dek begins re-encrypting rows.
 *
 * Consumers who need true write-quiescence during rotation should listen
 * for this event and gate writes on the context until DekRotated fires.
 * The advisory DB lock acquired by rotate-dek protects against a second
 * concurrent rotation; it does NOT block normal application writes.
 *
 * Never includes plaintext DEK or PHI.
 */
final class DekRotationStarting
{
    public function __construct(
        public readonly EncryptionContext $context,
        public readonly DataKey $dataKey,
        public readonly string $modelClass,
        public readonly int $rowCount,
    ) {}
}
