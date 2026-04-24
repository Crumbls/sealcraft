<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Tests\Unit\Concerns\Probes;

use Crumbls\Sealcraft\Concerns\HasEncryptedAttributes;
use Illuminate\Database\Eloquent\Model;

/**
 * Per-row probe with the default sealcraft_key row-key column.
 */
class PerRowProbe extends Model
{
    use HasEncryptedAttributes;
    use ExposesProtectedResolvers;

    public $timestamps = false;

    protected string $sealcraftStrategy = 'per_row';
}
