<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Tests\Fixtures;

use Crumbls\Sealcraft\Casts\Encrypted;
use Crumbls\Sealcraft\Concerns\HasEncryptedAttributes;
use Illuminate\Database\Eloquent\Model;

class EncryptedDocument extends Model
{
    use HasEncryptedAttributes;

    protected $table = 'encrypted_documents';

    protected $guarded = [];

    public $timestamps = false;

    /** @var array<string, string> */
    protected $casts = [
        'secret' => Encrypted::class,
        'note' => Encrypted::class,
    ];
}
