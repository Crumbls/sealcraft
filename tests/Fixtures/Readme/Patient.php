<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Tests\Fixtures\Readme;

use Crumbls\Sealcraft\Casts\Encrypted;
use Crumbls\Sealcraft\Casts\EncryptedJson;
use Crumbls\Sealcraft\Concerns\HasEncryptedAttributes;
use Illuminate\Database\Eloquent\Model;

/**
 * Fixture backing the README's "Quick start" and EncryptedJson examples.
 *
 * The README shows `class Patient extends Model` with no context-column
 * guidance. This fixture fills in the implicit default: per-group
 * strategy against a `tenant_id` column — which is what a reader who
 * follows the README with the stock `config/sealcraft.php` actually
 * gets. If that implicit default trips readers up, workstream I
 * addresses it in docs.
 */
class Patient extends Model
{
    use HasEncryptedAttributes;

    protected $table = 'readme_patients';

    protected $guarded = [];

    public $timestamps = false;

    protected $casts = [
        'ssn' => Encrypted::class,
        'dob' => Encrypted::class,
        'diagnosis' => Encrypted::class,
        'history' => EncryptedJson::class,
    ];
}
