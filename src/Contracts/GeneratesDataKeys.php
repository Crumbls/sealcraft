<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Contracts;

use Crumbls\Sealcraft\Values\DataKeyPair;
use Crumbls\Sealcraft\Values\EncryptionContext;

/**
 * Capability: provider generates the DEK itself and returns both the
 * plaintext and the wrapped form in a single call.
 *
 * AWS KMS's GenerateDataKey operation is the canonical example — one
 * round trip returns plaintext DEK + ciphertext DEK wrapped under the
 * KEK, with EncryptionContext bound as AAD.
 *
 * KeyManager prefers this path when available; it saves a network
 * call compared to locally generating + wrapping separately.
 */
interface GeneratesDataKeys extends KekProvider
{
    public function generateDataKey(EncryptionContext $ctx, int $bytes = 32): DataKeyPair;
}
