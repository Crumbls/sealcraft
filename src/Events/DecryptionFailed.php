<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Events;

use Crumbls\Sealcraft\Values\EncryptionContext;
use Throwable;

/**
 * Fired whenever a decrypt/unwrap operation fails.
 *
 * `kind` distinguishes failure cause for SIEM consumers:
 *   'auth'      — cipher authentication failed or KMS rejected the ciphertext
 *                 (bad ciphertext, wrong AAD, tampering). A spike warrants alert.
 *   'transient' — KMS was unreachable (network, throttle, timeout). Retryable;
 *                 do not conflate with auth-failure spikes in alerting rules.
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
        public readonly string $kind = 'auth',    // 'auth' | 'transient'
    ) {}
}
