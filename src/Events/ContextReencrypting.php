<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Events;

use Crumbls\Sealcraft\Values\EncryptionContext;
use Illuminate\Database\Eloquent\Model;

/**
 * Fired before sealcraft auto-re-encrypts a model whose encryption
 * context has changed. Listeners may return false to cancel the
 * operation; the saving callback then raises InvalidContextException
 * and the save is aborted.
 *
 * @param  array<int, string>  $encryptedAttributes
 */
final class ContextReencrypting
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
