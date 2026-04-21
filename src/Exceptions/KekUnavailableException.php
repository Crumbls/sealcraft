<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Exceptions;

/**
 * Raised when a KEK provider cannot be reached or has rejected a request
 * (transport failure, auth failure, throttling after retries exhausted,
 * or provider misconfiguration).
 */
class KekUnavailableException extends SealcraftException {}
