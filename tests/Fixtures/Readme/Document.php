<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Tests\Fixtures\Readme;

use Crumbls\Sealcraft\Casts\Encrypted;
use Crumbls\Sealcraft\Concerns\HasEncryptedAttributes;
use Illuminate\Database\Eloquent\Model;

/**
 * Fixture backing the README "Per-group" example — tenant-scoped DEK.
 */
class Document extends Model
{
    use HasEncryptedAttributes;

    protected $table = 'readme_documents';

    protected $guarded = [];

    public $timestamps = false;

    protected string $sealcraftContextColumn = 'tenant_id';

    protected string $sealcraftContextType = 'tenant';

    protected $casts = [
        'body' => Encrypted::class,
    ];
}
