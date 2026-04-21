<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Tests\Fixtures;

use Crumbls\Sealcraft\Casts\Encrypted;
use Crumbls\Sealcraft\Concerns\HasEncryptedAttributes;
use Crumbls\Sealcraft\Exceptions\InvalidContextException;
use Crumbls\Sealcraft\Values\EncryptionContext;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * A related row that delegates its encryption context to its owning
 * OwnedUser. Demonstrates the HIPAA pattern where a user's data
 * across multiple tables shares one user-scoped DEK.
 */
class OwnedRecord extends Model
{
    use HasEncryptedAttributes;

    protected $table = 'owned_records';

    protected $guarded = [];

    public $timestamps = false;

    protected $casts = [
        'body' => Encrypted::class,
    ];

    public function owner(): BelongsTo
    {
        return $this->belongsTo(OwnedUser::class, 'owned_user_id');
    }

    public function sealcraftContext(): EncryptionContext
    {
        $owner = $this->owner ?? $this->owner()->first();

        if (! $owner instanceof OwnedUser) {
            throw new InvalidContextException(
                'OwnedRecord cannot derive its encryption context without a loaded owner.'
            );
        }

        return $owner->sealcraftContext();
    }
}
