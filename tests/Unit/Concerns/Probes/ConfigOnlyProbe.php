<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Tests\Unit\Concerns\Probes;

use Crumbls\Sealcraft\Concerns\HasEncryptedAttributes;
use Illuminate\Database\Eloquent\Model;

/**
 * Probe with no sealcraft* property overrides — every resolver falls
 * back to config / default values.
 */
class ConfigOnlyProbe extends Model
{
    use HasEncryptedAttributes;
    use ExposesProtectedResolvers;

    public $timestamps = false;
}
