<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Tests\Fixtures\Unified;

use Crumbls\Sealcraft\Casts\Encrypted;
use Crumbls\Sealcraft\Casts\EncryptedJson;
use Crumbls\Sealcraft\Concerns\HasEncryptedAttributes;
use Illuminate\Database\Eloquent\Model;

/**
 * Exercises the new unified context API:
 *   - Model-level context via $sealcraft array
 *   - Per-column override via cast parameters
 */
class UnifiedPatient extends Model
{
    use HasEncryptedAttributes;

    protected $table = 'unified_patients';

    protected $guarded = [];

    public $timestamps = false;

    protected array $sealcraft = [
        'strategy' => 'per_group',
        'type' => 'patient',
        'column' => 'patient_id',
    ];

    protected $casts = [
        // Uses model defaults: (type=patient, column=patient_id)
        'ssn' => Encrypted::class,
        'history' => EncryptedJson::class,

        // Per-column override: context becomes (type=employer, column=employer_id)
        'work_notes' => Encrypted::class . ':type=employer,column=employer_id',
    ];
}
