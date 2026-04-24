---
title: Per-Group Strategy
weight: 10
---

Every row sharing a context value uses one DEK. KEK rotation rewraps one DB row per context. Best for multi-tenant SaaS.

## Configure

```php
use Crumbls\Sealcraft\Casts\Encrypted;
use Crumbls\Sealcraft\Concerns\HasEncryptedAttributes;

class Document extends Model
{
    use HasEncryptedAttributes;

    protected array $sealcraft = [
        'type'   => 'tenant',
        'column' => 'tenant_id',
    ];

    protected $casts = ['body' => Encrypted::class];
}
```

Per-group is the default strategy, so `'strategy' => 'per_group'` is implied and can be omitted. If your app's context column is literally `tenant_id` and your context type name is `tenant` (the shipped defaults), you can drop the `$sealcraft` array entirely.

## How it works

Sealcraft looks up (or mints) one `DataKey` row per `(context_type, context_id)` pair. Every `Document` where `tenant_id = 42` shares the DEK at `('tenant', 42)`.

Read workload:

- **First read per request for tenant 42**: one `sealcraft_data_keys` lookup + one KEK unwrap call
- **Every subsequent read for tenant 42** in the same request: zero network calls (DEK cached in memory)

## When to use

- Multi-tenant SaaS where each tenant is the unit of trust
- Apps with a natural aggregate (user, patient, organization) that owns many rows
- Any time "one tenant = one compliance scope"

## When to pick something else

- Each row is an independent security boundary -- use [per-row](/documentation/sealcraft/v1/encryption-contexts/per-row)
- A user's data spans multiple root-owned tables and you want one shred to destroy it all -- use [delegated context](/documentation/sealcraft/v1/encryption-contexts/delegated-context)
- One column on this model needs a different context than the rest -- use [per-column override](/documentation/sealcraft/v1/encryption-contexts/per-column-override)

## Legacy form

The individual properties still resolve identically — no migration required on models already using them:

```php
protected string $sealcraftContextType   = 'tenant';
protected string $sealcraftContextColumn = 'tenant_id';
```

The `$sealcraft` array is the recommended form for new models.
