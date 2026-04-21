<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Tests\Fixtures;

use Crumbls\Sealcraft\Casts\Encrypted;
use Crumbls\Sealcraft\Concerns\HasEncryptedAttributes;
use Illuminate\Database\Eloquent\Model;

class EncryptedVaultEntry extends Model
{
    use HasEncryptedAttributes;

    protected $table = 'encrypted_vault_entries';

    protected $guarded = [];

    public $timestamps = false;

    protected string $sealcraftStrategy = 'per_row';

    protected $casts = [
        'payload' => Encrypted::class,
    ];
}
