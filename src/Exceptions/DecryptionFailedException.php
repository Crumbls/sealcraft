<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Exceptions;

/**
 * Raised when ciphertext cannot be authenticated or decrypted. Never
 * exposes the underlying cause to callers to avoid oracle leakage;
 * detailed diagnostics are emitted via the DecryptionFailed event instead.
 */
class DecryptionFailedException extends SealcraftException {}
