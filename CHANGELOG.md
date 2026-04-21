# Changelog

All notable changes to `crumbls/sealcraft` are tracked here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/);
this package is pre-1.0 so breaking changes can land without a major
bump until the 1.0 release.

## [Unreleased]

### Added
- `EncryptedJson` cast — encrypts every leaf scalar of a JSON
  structure while preserving keys and nesting, so admin tools and
  analytics can still see shape without decrypting. Mirrors the
  scalar `Encrypted` cast on context resolution, null handling,
  cipher-ID dispatch, AAD binding, and `DecryptionFailed` event
  emission. Non-string scalars, empty strings, and nulls pass
  through on write. String leaves lacking a cipher prefix pass
  through on read (supports mixed-content columns); prefix-bearing
  leaves that fail authentication raise `DecryptionFailedException`
  rather than silently returning tampered data. Fixtures +
  regression suite in `tests/Feature/Casts/EncryptedJsonTest.php`.
  Limitation: auto re-encrypt on context column change currently
  only walks scalar `Encrypted` columns; per-group models with
  `EncryptedJson` columns must migrate context via an explicit
  maintenance path.
- `ConfigKekProvider` — reads KEK bytes from config (pipeline-driven
  env workflows). Multi-version support for non-destructive rotation.
  Registered as driver `config` in `ProviderRegistry`.

### Fixed
- `Encrypted` cast now persists attributes whose value was **mutated**
  during context resolution, not just keys that were newly added. This
  closes a bug where `sealcraft_key` generated lazily on an
  already-persisted row (loaded with `sealcraft_key = NULL`) was never
  written back to the DB, so the next read generated a new UUID,
  created a new DEK, and failed to decrypt the prior ciphertext with
  `AES-GCM authentication failed`. Regression test in
  `tests/Feature/Casts/EncryptedTest.php`.

## [0.1.0] — initial release (pre-tagged)

### Package foundation
- Laravel 11 / 12 / 13 compatibility. PHP 8.2+. Pest 3 test suite,
  Laravel Pint, Rector, PHPStan configured.
- Autodiscovered `SealcraftServiceProvider` with publishable config
  and migrations (`sealcraft-config`, `sealcraft-migrations` tags).
- `sealcraft_data_keys` table: polymorphic `context_type` + `context_id`,
  versioned provider metadata, `retired_at` + `shredded_at` lifecycle
  columns.

### Contracts + value objects
- Capability-based `KekProvider` contract hierarchy:
  `GeneratesDataKeys`, `SupportsNativeAad`, `SupportsKeyVersioning`.
- `Cipher` contract with 3-char cipher ID dispatch (`ag1`, `xc1`).
- `EncryptionContext` value object + `ContextSerializer` with locked
  canonical rules (NFC normalization, byte-sort keys, scalar coercion,
  escape rules, 4096-byte cap). AWS / GCP / Vault Transit / synthetic
  HMAC adapters on the value object itself.
- `WrappedDek` with versioned `sc1:` storage format for forward
  compatibility.

### KEK providers
- `AwsKmsKekProvider` — `GenerateDataKey` + `Decrypt` with native
  `EncryptionContext` AAD; retry + exponential backoff on
  throttling/internal errors.
- `GcpCloudKmsKekProvider` — REST API via Laravel HTTP client;
  `additionalAuthenticatedData` bound to canonical context; closure-
  based token resolver.
- `AzureKeyVaultKekProvider` — `wrapKey` / `unwrapKey` with **synthetic
  AAD** strategy (HMAC-SHA256 prepended to DEK, verified on unwrap)
  as default, `cipher_only` strategy as opt-out.
- `VaultTransitKekProvider` — Transit engine with native `context`
  parameter; parses `vault:vN:` version prefix from ciphertext.
- `LocalKekProvider` — file-backed, versioned rotation, refuses
  `production` env without explicit opt-in.
- `NullKekProvider` — test passthrough.
- `ConfigKekProvider` — see Unreleased.

### Ciphers
- `AesGcmCipher` (default) — AES-256-GCM, 12-byte IV, 16-byte tag,
  emits `ag1:v1:<iv>:<tag>:<ct>`.
- `XChaCha20Cipher` — libsodium-backed, graceful fallback when
  `ext-sodium` is absent.

### Eloquent integration
- `Encrypted` cast — transparent encrypt/decrypt, null passthrough,
  cipher-ID dispatch on read, AAD binding, `DecryptionFailed` events.
- `HasEncryptedAttributes` trait — `sealcraftContext()` default
  resolver for both `per_group` and `per_row` strategies; auto-
  generated `sealcraft_key` UUID for per-row models; auto-reencrypt
  on context column change (config-gated, event-wired, cancellable).

### HIPAA primitives
- Relationship-delegated context pattern (related models override
  `sealcraftContext()` to walk to an owning user). Fixtures +
  regression suite in `tests/Feature/HipaaPatternsTest.php`.
- Crypto-shred: `KeyManager::shredContext()`, `sealcraft:shred`
  command. `ContextShreddedException` distinct from
  `DecryptionFailedException` so apps can render
  "destroyed at user request" cleanly. Shred-aware reads AND writes.

### Services
- `KeyManager` — DEK lifecycle orchestration with capability-based
  branching and cache-first reads.
- `DekCache` — request-scoped plaintext DEK store, zero-on-flush
  best-effort.
- `ProviderRegistry` / `CipherRegistry` — driver-based resolution
  with `extend()` for custom implementations.

### Events (audit surface)
- `DekCreated`, `DekUnwrapped` (with `cacheHit` flag), `DekRotated`,
  `DekShredded`, `DecryptionFailed`, `ContextReencrypting` (pre,
  cancellable), `ContextReencrypted` (post).

### Artisan commands
- `sealcraft:generate-dek {type} {id}` — manual DEK provisioning
- `sealcraft:rotate-kek [--context-type] [--context-id] [--provider] [--chunk] [--dry-run]`
- `sealcraft:rotate-dek {model} --context-type --context-id [--chunk] [--dry-run]`
- `sealcraft:migrate-provider --from --to [...scope]`
- `sealcraft:reencrypt-context {model} {id} {new_value} [--column]`
- `sealcraft:shred {type} {id} [--force]`
- `sealcraft:audit [--provider] [--context-type] [--roundtrip]`

### Hardening
- Per-context unwrap rate-limit guard (`rate_limit.unwrap_per_minute`
  config; 0 disables). Cache hits don't consume slots.
- `hash_equals` used for all MAC comparisons.
- Request-terminating `DekCache::flush()` overwrites plaintext bytes
  with nulls (best-effort).

### Docs
- Comprehensive `README.md` with quick starts for every provider,
  per-group + per-row + delegated context patterns, rotation
  playbook, threat model, HIPAA/PCI compliance notes.
- `SECURITY.md` with disclosure policy.

### Known limitations
- Searchable encryption (`WHERE encrypted_col = ?`) intentionally
  out of scope for v1; planned for v2 via CipherSweet-style blind
  indexing.
- Level 3 multi-provider (dual-wrap redundancy) deferred to v1.1.
- `sealcraft:rotate-dek` assumes no concurrent writes during
  execution (run in a maintenance window).
- Cloud provider token resolvers are the app's responsibility
  (no built-in Managed Identity / ADC helpers yet).

### Test coverage at release
- 164 tests, 332 assertions. Covers cipher round-trips, provider
  capabilities, key management lifecycle, Eloquent integration,
  HIPAA delegation + shred patterns, rate limiting, and every
  artisan command.
