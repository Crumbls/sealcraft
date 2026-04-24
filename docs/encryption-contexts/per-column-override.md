---
title: Per-Column Override
weight: 40
---

A per-column override routes **one attribute** on a model to a different encryption context than the rest. It's an escape hatch, not a strategy — use it when a single column legitimately belongs to a different party than the model's primary context holder.

## Syntax

Pass `type=X,column=Y` as cast parameters:

```php
use Crumbls\Sealcraft\Casts\Encrypted;
use Crumbls\Sealcraft\Casts\EncryptedJson;

protected $casts = [
    'work_notes' => Encrypted::class . ':type=employer,column=employer_id',
    'audit_log'  => EncryptedJson::class . ':type=compliance,column=audit_org_id',
];
```

- `type=` — the context type string to bind the DEK to
- `column=` — the model attribute whose value becomes the context id

Both are required together. Passing only one raises `SealcraftException` at cast-construction time with an actionable message.

## Complete example

A patient record where most columns belong to the patient, but one belongs to the employer who issued a work-related clearance:

```php
use Crumbls\Sealcraft\Casts\Encrypted;
use Crumbls\Sealcraft\Casts\EncryptedJson;
use Crumbls\Sealcraft\Concerns\HasEncryptedAttributes;

class Patient extends Model
{
    use HasEncryptedAttributes;

    protected array $sealcraft = [
        'type'   => 'patient',
        'column' => 'patient_id',
    ];

    protected $casts = [
        // Bound to ('patient', $model->patient_id) — model-level context
        'ssn'        => Encrypted::class,
        'history'    => EncryptedJson::class,

        // Bound to ('employer', $model->employer_id) — per-column override
        'work_notes' => Encrypted::class . ':type=employer,column=employer_id',
    ];
}
```

Writing `$patient->ssn = '...'` creates a DEK under `('patient', 42)`. Writing `$patient->work_notes = '...'` creates a separate DEK under `('employer', 1007)`. Both live in the `sealcraft_data_keys` table as independent rows.

## Resolution precedence

When both are present on a model, order matters:

1. **Cast parameter override** (highest) — if the cast has `type=` and `column=`, use them for that attribute and ignore everything else.
2. **`sealcraftContext()` method** — if the model overrides this method, it applies to every non-overridden attribute.
3. **`$sealcraft` array** — the model-level default for non-overridden attributes.
4. **Legacy individual properties** (`$sealcraftStrategy`, etc.) — for back-compat.
5. **`sealcraft.*` config defaults**.

## Shred semantics

Each context has its own DEK. This means:

- Shredding the **model-level** context (e.g. `('patient', 42)`) destroys `ssn` and `history` but **not** `work_notes`.
- Shredding the **override** context (e.g. `('employer', 1007)`) destroys `work_notes` on every patient whose `employer_id = 1007`, but leaves their `ssn` and `history` readable.

If that's not the shred model you want, don't use per-column override — put the column on a related table with a shared parent and use [delegated context](/documentation/sealcraft/v1/encryption-contexts/delegated-context) instead.

## When to use

- A column on one model legitimately belongs to a different stakeholder (employer, insurer, partner tenant).
- You need columnar isolation where one column's KMS audit trail is separate from the others.
- Regulatory scope differs per column — one field is PHI, another is contract data that lives under a different retention policy.

## When to pick something else

- You just want "most of my columns in this model under context X, this other one under context Y" for organizational reasons, not stakeholder reasons → use [delegated context](/documentation/sealcraft/v1/encryption-contexts/delegated-context) with a join table.
- Every row is an independent boundary → use [per-row](/documentation/sealcraft/v1/encryption-contexts/per-row).
- You're trying to get `WHERE column = ?` to work on an encrypted column by switching contexts → it still won't work; the ciphertext is still ciphertext.

## Gotchas

- The override `column` must be set on the model when you read or write the overridden attribute. If it's `null`, the cast raises `InvalidContextException` with a message naming the column.
- Context changes on the override column fire the same `ContextReencrypting` / `ContextReencrypted` events as model-level context changes — they're handled identically by the save hook.
- The `sealcraftEncryptedAttributes()` introspector correctly identifies parameterized casts (it strips the `:...` tail when matching the cast class), so `sealcraft:models`, `sealcraft:rotate-dek`, and friends include overridden columns in their operations.
