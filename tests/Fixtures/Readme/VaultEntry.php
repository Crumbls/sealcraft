<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Tests\Fixtures\Readme;

use Crumbls\Sealcraft\Casts\Encrypted;
use Crumbls\Sealcraft\Concerns\HasEncryptedAttributes;
use Illuminate\Database\Eloquent\Model;

/**
 * Fixture backing the README "Per-row" example — each row has its own DEK.
 */
class VaultEntry extends Model
{
    use HasEncryptedAttributes;

    protected $table = 'readme_vault_entries';

    protected $guarded = [];

    public $timestamps = false;

    protected string $sealcraftStrategy = 'per_row';

    protected $casts = [
        'secret' => Encrypted::class,
    ];
}
