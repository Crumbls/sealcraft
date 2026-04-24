---
title: Encryption Contexts
weight: 50
---

Every DEK is bound to an **encryption context** -- a `(type, id)` pair plus optional scalar attributes. The context controls which DEK decrypts which row, and gets cryptographically bound to the ciphertext as AAD.

## What canonicalization guarantees

The context is serialized to stable UTF-8 bytes:

- NFC-normalized strings
- Byte-sorted keys
- Escaped separators
- 4KB size cap

This means the same logical context always produces the same bytes, regardless of array ordering or subtle Unicode variants. A cross-context decrypt attempt -- intentional or accidental -- fails authentication.

## Strategies

Sealcraft supports three context strategies. Pick per model.

- [Per-group](/documentation/sealcraft/v1/encryption-contexts/per-group) -- one DEK per tenant / user / patient. Default. Best for multi-tenant SaaS.
- [Per-row](/documentation/sealcraft/v1/encryption-contexts/per-row) -- one DEK per record. Best for vault-style rows where each row is an independent security boundary.
- [Delegated context](/documentation/sealcraft/v1/encryption-contexts/delegated-context) -- child records share a parent's DEK. The HIPAA primitive for one-shot crypto-shred.

## Changing context

Changing the context column on an existing row is a security-sensitive event. Sealcraft's default behavior is to **auto-reencrypt on save**:

```php
$patient->user_id = $newOwner->id;
$patient->save();  // auto-decrypts with old DEK, re-encrypts with new DEK
```

Two events fire:

- `ContextReencrypting` (pre, cancellable by returning `false`)
- `ContextReencrypted` (post, for audit log)

To require an explicit migration command instead, set:

```dotenv
SEALCRAFT_AUTO_REENCRYPT=false
```

Then any uncoordinated context change throws `InvalidContextException`. Run `sealcraft:reencrypt-context` when you mean to move a row between contexts. Wire the events to your SIEM regardless.
