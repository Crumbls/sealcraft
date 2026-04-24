---
title: Performance
weight: 30
---

Sealcraft trades a few milliseconds on DEK cache misses for ironclad key management. Steady-state overhead is near zero.

## Request-lifetime cost

| Event | Cost |
|---|---|
| DEK cache hit | O(1) array lookup in process memory, zero network calls |
| DEK cache miss | One DB query to find the DataKey row + one KEK provider unwrap (roughly 10-100ms network) |

The DEK cache is per-process, keyed by canonical context bytes, and flushed on terminate (`app()->terminating()` hook in the service provider).

## Per-strategy steady state

| Strategy | Reads per request | KEK unwrap calls |
|---|---|---|
| per-group | All rows for one tenant | 1 (per context) |
| per-row | N distinct rows | N |
| delegated | All rows across tables for one user | 1 (on the root's context) |

If you serve many distinct tenants in one long-running worker (Octane, Swoole, Horizon), the cache amortizes quickly.

## Batch operations

`sealcraft:rotate-kek`, `sealcraft:rotate-dek`, `sealcraft:migrate-provider`, and `sealcraft:backfill-row-keys` all use `chunkById` so they scale to 100k+ contexts without OOM.

KMS rate limits matter here. AWS KMS per-region limits are 10k req/s on `Encrypt`/`Decrypt`; GCP and Azure are lower. Use `--chunk` and schedule batches during off-peak.

## What to measure

- P99 latency on endpoints that read encrypted columns (should be < 5ms overhead once cached)
- KEK unwrap rate (dashboards on the KMS provider)
- `DekUnwrapped` events with `cacheHit=false` as a proxy for cache efficiency

## Anti-patterns

- **Creating a fresh context per request.** Burns the cache and hits the KMS on every read.
- **Per-row strategy with frequent bulk reads of unique rows.** Consider delegated context or a different design.
- **Reading encrypted columns for analytics without decrypt batching.** Build an offline re-encryption pipeline into a warehouse instead.
