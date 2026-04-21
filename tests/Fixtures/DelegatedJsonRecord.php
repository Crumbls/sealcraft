<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Tests\Fixtures;

use Crumbls\Sealcraft\Casts\EncryptedJson;
use Crumbls\Sealcraft\Concerns\HasEncryptedAttributes;
use Crumbls\Sealcraft\Exceptions\InvalidContextException;
use Crumbls\Sealcraft\Values\EncryptionContext;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

/**
 * A record whose JSON-encrypted column lives under its owning user's
 * DEK via delegated context — the HIPAA "all of a patient's PHI under
 * one key" pattern, applied to structured JSON data.
 */
class DelegatedJsonRecord extends Model
{
    use HasEncryptedAttributes;

    protected $table = 'delegated_json_records';

    protected $guarded = [];

    public $timestamps = false;

    protected $casts = [
        'payload' => EncryptedJson::class,
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
                'DelegatedJsonRecord cannot derive its encryption context without a loaded owner.'
            );
        }

        return $owner->sealcraftContext();
    }
}
