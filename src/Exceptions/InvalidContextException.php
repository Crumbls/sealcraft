<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Exceptions;

/**
 * Raised when an encryption context is invalid (malformed input, oversized
 * canonical form, unsupported value types) or when a context mismatch is
 * detected at decrypt time with auto-reencrypt disabled.
 */
class InvalidContextException extends SealcraftException {}
