---
title: Exceptions
weight: 30
---

Sealcraft's exception hierarchy is intentionally granular so applications can render meaningful error pages without a generic 500.

## Hierarchy

All Sealcraft exceptions extend `Crumbls\Sealcraft\Exceptions\SealcraftException`.

| Exception | Thrown when | Typical handling |
|---|---|---|
| `ContextShreddedException` | Read or write against a context whose DEK has been shredded | Render "record destroyed at user request" (410 Gone) |
| `DecryptionFailedException` | Ciphertext fails authentication, or unwrap fails at the cipher layer | Treat as data corruption / tampering; alert security; do not retry |
| `InvalidContextException` | Context change on a model when `auto_reencrypt_on_context_change=false`, OR per-row model with an empty row-key column | Application bug / incomplete backfill; fix and redeploy |
| `KekUnavailableException` | KMS provider is unreachable, throttled, or the KEK is disabled | Retry with exponential backoff; page oncall if persistent |

## Distinguishing shred from corruption

`ContextShreddedException` and `DecryptionFailedException` are siblings, not parent/child. This lets you render completely different UX:

```php
try {
    $patient = Patient::findOrFail($id);
    return view('patient.show', compact('patient'));
} catch (ContextShreddedException $e) {
    return response()->view('patient.shredded', [], 410);
} catch (DecryptionFailedException $e) {
    Log::alert('Decryption failed', ['patient_id' => $id]);
    abort(500);
}
```

## Do not catch broadly

`catch (\Exception $e)` around a Sealcraft call swallows `KekUnavailableException` (transient -- should retry) and `DecryptionFailedException` (not transient -- should alert). Catch the specific subclasses.

## Logging

No Sealcraft exception message or context includes plaintext data. It is safe to log the full message, exception class, and stack trace. The `context` property on `SealcraftException` subclasses is the canonical context bytes -- suitable for correlation but not sensitive.
