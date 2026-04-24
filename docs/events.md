---
title: Events
weight: 80
---

Every significant key-lifecycle event fires a Laravel event. Subscribe in a service provider and forward to your SIEM, audit log, or compliance pipeline.

## Event catalog

| Event | Class | Fired when |
|---|---|---|
| DEK created | `Crumbls\Sealcraft\Events\DekCreated` | A new DataKey row is inserted |
| DEK unwrapped | `Crumbls\Sealcraft\Events\DekUnwrapped` | Plaintext DEK is produced; carries a `cacheHit` flag |
| DEK rotated | `Crumbls\Sealcraft\Events\DekRotated` | A DataKey's KEK version changed (KEK rotation or provider migration) |
| DEK shredded | `Crumbls\Sealcraft\Events\DekShredded` | A context has been crypto-shredded |
| Decryption failed | `Crumbls\Sealcraft\Events\DecryptionFailed` | Any unwrap or cipher auth failure. Never includes plaintext. |
| Context re-encrypting | `Crumbls\Sealcraft\Events\ContextReencrypting` | Before auto-reencrypt; listeners may cancel by returning `false` |
| Context re-encrypted | `Crumbls\Sealcraft\Events\ContextReencrypted` | After auto-reencrypt; audit-logging hook |

## Wiring to a SIEM

```php
use Crumbls\Sealcraft\Events\DekShredded;
use Crumbls\Sealcraft\Events\DekRotated;
use Crumbls\Sealcraft\Events\DecryptionFailed;
use Illuminate\Support\Facades\Event;

public function boot(): void
{
    Event::listen(DekShredded::class, AuditShredListener::class);
    Event::listen(DekRotated::class, AuditRotationListener::class);
    Event::listen(DecryptionFailed::class, AlertOnDecryptFailure::class);
}
```

## Safety guarantees

- **No plaintext in any event payload.** `DecryptionFailed` carries the context, exception class, and provider, but never the attempted plaintext or the DEK.
- **Events fire after the write is durable** for `DekCreated`, `DekRotated`, `DekShredded`. A listener that dispatches an async job can trust the state.
- **Cancelling `ContextReencrypting`** causes the save to throw `InvalidContextException`, not silently skip. Use this to enforce approval workflows on context changes.

## Recommended minimum wiring

For HIPAA / SOC 2 audit purposes, at minimum log:

- `DekCreated` -- new tenant / user onboarded
- `DekRotated` -- rotation events for compliance attestation
- `DekShredded` -- right-to-be-forgotten fulfillment
- `DecryptionFailed` -- potential tampering or misconfiguration
- `ContextReencrypted` -- record moved between contexts (tenant merge, record re-owned)
