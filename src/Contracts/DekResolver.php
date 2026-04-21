<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Contracts;

use Crumbls\Sealcraft\Values\EncryptionContext;
use Illuminate\Database\Eloquent\Model;

/**
 * Resolves the encryption context for a given model instance. The
 * default implementation lives on HasEncryptedAttributes and reads
 * from the configured context column; apps can bind a custom resolver
 * to the container for centralized multi-tenant or policy-driven
 * context derivation.
 */
interface DekResolver
{
    public function resolve(Model $model): EncryptionContext;
}
