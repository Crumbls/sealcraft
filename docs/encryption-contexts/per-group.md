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

    protected string $sealcraftContextType   = 'tenant';
    protected string $sealcraftContextColumn = 'tenant_id';

    protected $casts = ['body' => Encrypted::class];
}
```

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
