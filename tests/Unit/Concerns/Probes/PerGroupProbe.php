<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Tests\Unit\Concerns\Probes;

use Crumbls\Sealcraft\Concerns\HasEncryptedAttributes;
use Illuminate\Database\Eloquent\Model;

/**
 * Per-group probe with an explicit tenant_id context column.
 */
class PerGroupProbe extends Model
{
    use HasEncryptedAttributes;
    use ExposesProtectedResolvers;

    public $timestamps = false;

    protected string $sealcraftStrategy = 'per_group';

    protected string $sealcraftContextType = 'tenant';

    protected string $sealcraftContextColumn = 'tenant_id';
}
