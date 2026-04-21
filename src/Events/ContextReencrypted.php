<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Events;

use Crumbls\Sealcraft\Values\EncryptionContext;
use Illuminate\Database\Eloquent\Model;

/**
 * Fired after sealcraft auto-re-encrypts a model's encrypted columns
 * from the old context to the new one. Always fires on successful
 * re-encrypt regardless of config; wire to SIEM for audit logging.
 *
 * @param  array<int, string>  $encryptedAttributes
 */
final class ContextReencrypted
{
    /**
     * @param  array<int, string>  $encryptedAttributes
     */
    public function __construct(
        public readonly Model $model,
        public readonly EncryptionContext $oldContext,
        public readonly EncryptionContext $newContext,
        public readonly array $encryptedAttributes,
    ) {}
}
