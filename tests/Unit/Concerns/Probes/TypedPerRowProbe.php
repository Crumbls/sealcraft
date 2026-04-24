<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Tests\Unit\Concerns\Probes;

use Crumbls\Sealcraft\Concerns\HasEncryptedAttributes;
use Illuminate\Database\Eloquent\Model;

/**
 * Per-row probe with an explicit context type, used to verify that the
 * sealcraftContextType property overrides both the per-group and per-row
 * fallbacks.
 */
class TypedPerRowProbe extends Model
{
    use HasEncryptedAttributes;
    use ExposesProtectedResolvers;

    public $timestamps = false;

    protected string $sealcraftStrategy = 'per_row';

    protected string $sealcraftContextType = 'patient';
}
