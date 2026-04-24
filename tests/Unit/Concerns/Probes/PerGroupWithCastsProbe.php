<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Tests\Unit\Concerns\Probes;

use Crumbls\Sealcraft\Casts\Encrypted;
use Crumbls\Sealcraft\Casts\EncryptedJson;
use Crumbls\Sealcraft\Concerns\HasEncryptedAttributes;
use Illuminate\Database\Eloquent\Model;

/**
 * Per-group probe with mixed encrypted / non-encrypted casts, used to
 * exercise sealcraftEncryptedAttributes() introspection.
 */
class PerGroupWithCastsProbe extends Model
{
    use HasEncryptedAttributes;
    use ExposesProtectedResolvers;

    public $timestamps = false;

    protected string $sealcraftStrategy = 'per_group';

    protected string $sealcraftContextColumn = 'tenant_id';

    protected $casts = [
        'ssn' => Encrypted::class,
        'history' => EncryptedJson::class,
        'name' => 'string',
        'active' => 'boolean',
    ];
}
