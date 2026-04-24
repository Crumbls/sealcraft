---
title: Architecture
weight: 5
---

Envelope encryption with a two-layer key hierarchy: a **KEK** (Key Encryption Key) inside your KMS wraps a **DEK** (Data Encryption Key); the DEK actually encrypts your column data.

```
+--------------------+           wrap            +--------------------+
|   KEK in KMS       |  <----------------------  |   Plaintext DEK    |
|  (aws/gcp/azure/   |                           |   32 random bytes  |
|   vault/local)     |  ---------------------->  |   cached per-req   |
+--------------------+          unwrap           +---------+----------+
                                                           |
                                     encrypt / decrypt     |
                                       field column        v
                                                 +--------------------+
                                                 |  Ciphertext bytes  |
                                                 |  stored in the DB  |
                                                 |  row (ag1:v1:...)  |
                                                 +--------------------+
```

## Lifecycle of a field write

1. Eloquent calls the `Encrypted` cast's `set()`.
2. Cast calls `KeyManager::getOrCreateDek($ctx)`.
3. Manager checks `DekCache` (request-scoped). If miss:
   - Query `DataKey::forContext(type,id)->active()->first()`.
   - If no row: `createDek()` → provider generates or wraps DEK → insert row.
   - If row exists: `unwrapInto()` → provider unwraps → cache plaintext.
4. Cast asks `CipherRegistry` for the configured cipher.
5. Cipher encrypts plaintext with the DEK, using `$ctx->toCanonicalBytes()` as AAD.
6. Eloquent writes the resulting envelope string to the column.

## Lifecycle of a field read

1. Eloquent calls the `Encrypted` cast's `get()`.
2. Same DEK resolution path (cache hit on subsequent reads in the same request).
3. Cast extracts the 3-char cipher id from the envelope via `CipherRegistry::peekId()`.
4. Cipher decrypts using the DEK and the same AAD. Mismatch = `DecryptionFailedException`.

## Request termination

`SealcraftServiceProvider::registerTerminatingFlush()` wires `DekCache::flush()` into `app()->terminating()`. Every plaintext DEK in memory is overwritten with null bytes and dropped before the process releases the request.

## DEK cache bounds

The plaintext DEK cache is bounded by `sealcraft.dek_cache.max_entries` (default `1024`). When the cap is exceeded the least-recently-used entry is overwritten with null bytes and dropped. This prevents long-running workers (Horizon, Octane) that touch many tenants over time from accumulating an unbounded number of plaintext DEKs. Set `SEALCRAFT_DEK_CACHE_MAX_ENTRIES=0` to disable the cap if your workload is strictly per-request.

## Per-group vs per-row

| Dimension | per_group | per_row |
|---|---|---|
| DEKs per tenant | 1 | N (one per row) |
| KMS calls per request (cold cache) | 1 per tenant you read | 1 per row you read |
| Blast radius of DEK compromise | one tenant | one row |
| Shred granularity | tenant | row |
| Good for | multi-tenant SaaS | vault / per-patient data |

Choose per_group by default. Reach for per_row when one DEK per row is a compliance requirement (e.g. HIPAA "destroy this specific patient's data without touching anyone else").

## Why active-DEK uniqueness is enforced in app code, not via a DB unique index

See [ADR-0001](/documentation/sealcraft/v1/adr/0001-active-dek-uniqueness-in-app-layer).

## Why per-row requires explicit backfill

See [ADR-0002](/documentation/sealcraft/v1/adr/0002-per-row-requires-explicit-backfill).
