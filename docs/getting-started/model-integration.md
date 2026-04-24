---
title: Model Integration
weight: 10
---

Add encryption to a model by pulling in the `HasEncryptedAttributes` trait and casting columns with `Crumbls\Sealcraft\Casts\Encrypted`.

```php
use Crumbls\Sealcraft\Casts\Encrypted;
use Crumbls\Sealcraft\Concerns\HasEncryptedAttributes;

class Patient extends Model
{
    use HasEncryptedAttributes;

    protected $casts = [
        'ssn'       => Encrypted::class,
        'dob'       => Encrypted::class,
        'diagnosis' => Encrypted::class,
    ];
}
```

That is the complete integration. Reads and writes transparently encrypt. Null values stay null.

## How it works

On write, `Encrypted::set` asks `KeyManager` for the DEK that matches the model's encryption context, encrypts the value with the configured cipher, and stores the envelope string in the column. On read, `Encrypted::get` resolves the same DEK (cached for the request) and decrypts in place.

The "encryption context" is what binds a DEK to a row. A context is a `(type, id)` pair -- `('tenant', 42)`, `('patient', '0f2e...-uuid')`, `('vault-entry', 'row-key-uuid')`. Two rows with the same context share a DEK; two rows with different contexts do not. The context also gets bound to each ciphertext as AAD, so swapping ciphertext from one context onto another row fails authentication.

## The `$sealcraft` configuration array

The recommended way to customize context derivation is a single `$sealcraft` array property on the model:

```php
class Patient extends Model
{
    use HasEncryptedAttributes;

    protected array $sealcraft = [
        'strategy' => 'per_row',        // 'per_group' (default) | 'per_row'
        'type'     => 'patient',        // context type name
        'column'   => 'patient_id',     // per_group: context id column
                                        // per_row:   row-key column (default: sealcraft_key)
    ];

    protected $casts = [
        'ssn' => Encrypted::class,
    ];
}
```

| Key | Meaning | Default |
|---|---|---|
| `strategy` | `per_group` (one DEK per context value) or `per_row` (one DEK per row) | `config('sealcraft.dek_strategy')` -> `per_group` |
| `type` | Context type string. Becomes the `ctx_type` in canonical AAD bytes and in the KMS encryption-context field for providers that support it | per_group: `config('sealcraft.context_type')` -> `tenant`. per_row: the model's morph class |
| `column` | per_group: the model column that holds the context id. per_row: the UUID row-key column | per_group: `config('sealcraft.context_column')` -> `tenant_id`. per_row: `sealcraft_key` |

The same `column` key does double duty depending on strategy. Pick the name that reads naturally in your table.

## Custom context type names

The type string appears in two places a security reviewer will see:

1. The `context_type` column on `sealcraft_data_keys` (one row per distinct context)
2. The `ctx_type` key inside the AWS KMS `EncryptionContext` (visible in CloudTrail logs)

Pick a type that is human-readable at a glance:

```php
protected array $sealcraft = [
    'type' => 'patient',   // not 'App\\Models\\Patient'
];
```

If you omit `type` on a **per-group** model, the package falls back to the value in `config('sealcraft.context_type')`, which defaults to `'tenant'`. That is intentional: the common case is multi-tenant SaaS where every model shares the tenant context.

If you omit `type` on a **per-row** model, the fallback is the model's `getMorphClass()` — usually the fully-qualified class name unless you have a morph map. That is fine for internal uniqueness but less pretty in logs. Setting `type` explicitly is recommended for per-row.

## Custom column names

### per-group: context id column

Every row shares one DEK per value of this column. The column must be populated before the first encrypted attribute is read or written, otherwise Sealcraft throws `InvalidContextException`.

```php
class Document extends Model
{
    use HasEncryptedAttributes;

    protected array $sealcraft = [
        'type'   => 'tenant',
        'column' => 'tenant_id',   // or 'organization_id', 'workspace_id', 'owner_id' ...
    ];

    protected $casts = ['body' => Encrypted::class];
}
```

### per-row: row-key column

Each row gets its own UUID row-key. Default column name is `sealcraft_key`; override it if that name clashes with something in your schema or you prefer a different convention:

```php
class VaultEntry extends Model
{
    use HasEncryptedAttributes;

    protected array $sealcraft = [
        'strategy' => 'per_row',
        'type'     => 'vault-entry',
        'column'   => 'row_key',    // instead of the default 'sealcraft_key'
    ];

    protected $casts = ['secret' => Encrypted::class];
}
```

Required migration:

```php
$table->string('row_key', 191)->nullable()->index();
```

New rows get a UUID automatically via the trait's `creating` hook. Existing rows are a hard error on read/write until you run `php artisan sealcraft:backfill-row-keys "App\\Models\\VaultEntry"` — see [per-row strategy](/documentation/sealcraft/v1/encryption-contexts/per-row).

## Custom context resolution (delegated, relationship-based)

Override `sealcraftContext()` directly for anything the `$sealcraft` array cannot express -- delegating to a parent, reading from a custom accessor, or combining multiple columns:

```php
use Crumbls\Sealcraft\Values\EncryptionContext;

class MedicalRecord extends Model
{
    use HasEncryptedAttributes;

    protected $casts = ['notes' => Encrypted::class];

    public function patient()
    {
        return $this->belongsTo(Patient::class);
    }

    public function sealcraftContext(): EncryptionContext
    {
        // Share the patient's DEK so a patient shred destroys all their
        // records in one move.
        return $this->patient->sealcraftContext();
    }
}
```

Eager-load the relationship when reading many rows to avoid lazy-load storms. See [Delegated context](/documentation/sealcraft/v1/encryption-contexts/delegated-context) for the full pattern.

## Extra context attributes (fine-grained AAD binding)

`EncryptionContext` accepts a third parameter -- an array of scalar attributes -- that gets baked into the canonical AAD bytes and (on AWS KMS) into the per-call `EncryptionContext` map. Use this to bind ciphertext to additional dimensions beyond `(type, id)`, for example an environment tag or a data-classification level:

```php
use Crumbls\Sealcraft\Values\EncryptionContext;

class Document extends Model
{
    use HasEncryptedAttributes;

    protected $casts = ['body' => Encrypted::class];

    public function sealcraftContext(): EncryptionContext
    {
        return new EncryptionContext(
            contextType: 'tenant',
            contextId: (int) $this->tenant_id,
            attributes: [
                'env'            => config('app.env'),
                'classification' => $this->classification,  // 'public' | 'internal' | 'secret'
            ],
        );
    }
}
```

Every ciphertext written is bound to these attributes. Attempting to decrypt the same row under a different `classification` value fails authentication at the cipher layer. This is useful for hard-guaranteeing that ciphertext written in production cannot be decrypted in a staging process that happened to share a KEK.

## Remote key names (which KMS key wraps your DEKs)

The KMS key that wraps your DEKs is set at the **provider** level, not on the model.

### Single KMS key (common case)

`.env`:

```dotenv
SEALCRAFT_PROVIDER=aws_kms
SEALCRAFT_AWS_KEY_ID=alias/my-app-kek
SEALCRAFT_AWS_REGION=us-east-1
```

Every context encrypted through the default provider uses that key. Rotating it is a one-command operation; see [KEK rotation](/documentation/sealcraft/v1/key-management/kek-rotation).

Each provider has its own key-name env var: `SEALCRAFT_AWS_KEY_ID`, `SEALCRAFT_GCP_CRYPTO_KEY`, `SEALCRAFT_AZURE_KEY_NAME`, `SEALCRAFT_VAULT_KEY_NAME`. Details on each are on the individual provider pages under [KEK Providers](/documentation/sealcraft/v1/providers).

### Multiple KMS keys on one app

Define additional provider blocks in `config/sealcraft.php` that reuse the same driver against different KMS keys. For example, a stricter key for HIPAA-covered columns:

```php
'providers' => [
    'aws_kms' => [
        'driver' => 'aws_kms',
        'key_id' => env('SEALCRAFT_AWS_KEY_ID'),         // alias/app-default-kek
        'region' => env('SEALCRAFT_AWS_REGION'),
    ],

    'aws_kms_hipaa' => [
        'driver' => 'aws_kms',
        'key_id' => env('SEALCRAFT_AWS_HIPAA_KEY_ID'),   // alias/app-hipaa-kek
        'region' => env('SEALCRAFT_AWS_REGION'),
    ],
],
```

The two providers share a driver but point at different KMS keys with different IAM scopes. You can now route specific contexts at DEK creation time by explicitly provisioning against the stricter provider **before** the first encrypted read/write touches that context:

```php
use Crumbls\Sealcraft\Services\KeyManager;

$manager = app(KeyManager::class);

$manager->createDek($patient->sealcraftContext(), 'aws_kms_hipaa');
```

Once a context's DataKey row exists under a given provider, subsequent unwraps route to that provider automatically — the row stores its `provider_name`. Anything you forget to pre-provision falls through to `sealcraft.default_provider`.

To move a context from one provider to another later, use [provider migration](/documentation/sealcraft/v1/key-management/provider-migration).

## Legacy property syntax

Before the unified `$sealcraft` array existed, customization lived on four individual properties. They are still supported and not deprecated:

```php
class Patient extends Model
{
    use HasEncryptedAttributes;

    protected string $sealcraftStrategy      = 'per_row';
    protected string $sealcraftContextType   = 'patient';
    protected string $sealcraftRowKeyColumn  = 'row_key';  // per_row only

    // per_group only — set this when strategy is per_group:
    // protected string $sealcraftContextColumn = 'tenant_id';

    protected $casts = ['ssn' => Encrypted::class];
}
```

The unified array is preferred for new code -- it keeps all four knobs in one place. If both forms are present on the same model, the array wins for any key it defines.

## See also

- [Encryption contexts](/documentation/sealcraft/v1/encryption-contexts) -- per-group vs per-row, delegated context, changing context
- [Encrypted JSON](/documentation/sealcraft/v1/getting-started/encrypted-json) -- shape-preserving JSON encryption
- [KEK Providers](/documentation/sealcraft/v1/providers) -- per-provider `key_id` / `key_name` configuration
- [Provider migration](/documentation/sealcraft/v1/key-management/provider-migration) -- move a context between KMS providers
