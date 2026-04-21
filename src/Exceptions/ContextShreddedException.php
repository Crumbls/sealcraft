<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Exceptions;

/**
 * Raised when an encrypted attribute is accessed for a context whose
 * DEK has been crypto-shredded (typically to honor a right-to-be-
 * forgotten request). The underlying ciphertext still exists on disk
 * but is permanently unrecoverable.
 *
 * Applications should catch this and treat the record as destroyed
 * at the UX layer — rendering "this record was deleted at user
 * request" rather than bubbling a 500.
 */
class ContextShreddedException extends SealcraftException {}
