<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Events;

use Crumbls\Sealcraft\Values\EncryptionContext;
use Throwable;

/**
 * Fired whenever a decrypt/unwrap operation fails authentication. Apps
 * should subscribe and forward to SIEM; a spike indicates either data
 * corruption or active tampering.
 *
 * Never includes plaintext or ciphertext bodies.
 */
final class DecryptionFailed
{
    public function __construct(
        public readonly string $stage,            // 'cipher' | 'kek_unwrap' | 'synthetic_aad'
        public readonly ?EncryptionContext $context,
        public readonly ?string $providerName,
        public readonly Throwable $exception,
    ) {}
}
