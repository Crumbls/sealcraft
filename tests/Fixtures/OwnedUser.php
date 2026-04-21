<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Tests\Fixtures;

use Crumbls\Sealcraft\Casts\Encrypted;
use Crumbls\Sealcraft\Concerns\HasEncryptedAttributes;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

/**
 * A user-like owner whose row carries its own `sealcraft_key` column
 * (auto-populated by the per-row strategy). Every one of this user's
 * encrypted fields — and every encrypted field on related models
 * that delegate via the relationship — lives under a single DEK
 * keyed by this row's `sealcraft_key`.
 *
 * Crypto-shredding that DEK destroys all of this user's data in one
 * operation, which is the right-to-be-forgotten primitive for HIPAA.
 */
class OwnedUser extends Model
{
    use HasEncryptedAttributes;

    protected $table = 'owned_users';

    protected $guarded = [];

    public $timestamps = false;

    protected string $sealcraftStrategy = 'per_row';

    protected $casts = [
        'ssn' => Encrypted::class,
        'dob' => Encrypted::class,
    ];

    public function records(): HasMany
    {
        return $this->hasMany(OwnedRecord::class, 'owned_user_id');
    }
}
