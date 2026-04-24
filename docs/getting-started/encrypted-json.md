---
title: Encrypted JSON
weight: 20
---

`Crumbls\Sealcraft\Casts\EncryptedJson` encrypts string leaves inside a JSON column while preserving the tree shape. Useful when admin tools, analytics, or schema validators need to inspect keys and structure, but the values themselves are sensitive.

```php
use Crumbls\Sealcraft\Casts\Encrypted;
use Crumbls\Sealcraft\Casts\EncryptedJson;
use Crumbls\Sealcraft\Concerns\HasEncryptedAttributes;

class Patient extends Model
{
    use HasEncryptedAttributes;

    protected $casts = [
        'ssn'     => Encrypted::class,
        'history' => EncryptedJson::class,
    ];
}

$patient->history = [
    'conditions' => ['asthma', 'hypertension'],
    'allergies'  => [
        ['substance' => 'penicillin', 'severity' => 'severe'],
    ],
    'notes'      => 'no recent flares',
];
```

## What gets encrypted

On disk the column is still valid JSON. Every **string leaf** is individually encrypted under the same DEK as the row's scalar `Encrypted` columns. Keys, nesting, and non-string scalars (ints, floats, bools, nulls) stay readable.

On read, leaves that carry a cipher prefix are decrypted. Strings without a prefix pass through unchanged, so a column can safely mix plaintext shape data with encrypted leaves -- useful during migration.

## When to use it

- You need PHI values protected but your tooling queries the JSON by key (Postgres `->>`, MySQL `JSON_EXTRACT`)
- You have a legacy column that already contains JSON and you want to opt individual values into encryption without restructuring the column
- You want per-value crypto-shred granularity within a larger record

## When not to use it

- The entire column is sensitive -- use scalar `Encrypted` and serialize yourself; it is simpler and has less overhead
- You need to query on the encrypted values -- the plaintext is never in the column, so indexes on leaf values see only ciphertext
