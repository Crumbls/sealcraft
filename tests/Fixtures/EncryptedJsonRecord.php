<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Tests\Fixtures;

use Crumbls\Sealcraft\Casts\Encrypted;
use Crumbls\Sealcraft\Casts\EncryptedJson;
use Crumbls\Sealcraft\Concerns\HasEncryptedAttributes;
use Illuminate\Database\Eloquent\Model;

/**
 * Per-row model that exercises the EncryptedJson cast alongside a
 * scalar Encrypted column. Mirrors the "patient chart with structured
 * medical history" shape that drove the cast's requirements.
 */
class EncryptedJsonRecord extends Model
{
    use HasEncryptedAttributes;

    protected $table = 'encrypted_json_records';

    protected $guarded = [];

    public $timestamps = false;

    protected string $sealcraftStrategy = 'per_row';

    protected $casts = [
        'name' => Encrypted::class,
        'history' => EncryptedJson::class,
    ];
}
