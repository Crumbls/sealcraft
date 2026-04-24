# Changelog

All notable changes to `crumbls/sealcraft` are tracked here.
Format loosely follows [Keep a Changelog](https://keepachangelog.com/);
this package is pre-1.0 so breaking changes can land without a major
bump until the 1.0 release.

## [Unreleased]

### Fixed
- **`Model::replicate()` on per-row models no longer shares a DEK with the
  original.** Previously, `replicate()` copied the `sealcraft_key`
  column, which meant the clone shared the original's DEK — shredding
  one would also destroy the other's data. The trait now hooks the
  `replicating` event, decrypts the original's encrypted attributes on
  the replica, nulls the row-key so `creating` mints a fresh UUID, and
  lets the cast re-encrypt under the new DEK on save.
- **Cloud KEK provider error classification is now wired up.** The
  Vault / GCP / Azure providers now call `->throw()` on their HTTP
  chains, so `RequestException` actually propagates and the provider's
  `isAuthError()` branch can classify 400s as `DecryptionFailedException`
  (context mismatch / AAD mismatch) while 403/5xx become
  `KekUnavailableException`. Previously the auth-error branch was
  unreachable — every non-2xx response fell through to "response
  missing plaintext" via body parsing.
- **`HasEncryptedAttributes` resolvers no longer return `""` when
  config is explicitly `null` or `""`.** The `(string) config(...)` cast
  yielded an empty string (bypassing the intended default), which
  surfaced as `'' !== 'per_group'` logic bugs in downstream code. All
  three resolvers (`resolveSealcraftStrategy`,
  `resolveSealcraftContextType`, `resolveSealcraftContextColumn`) now
  fall through empty strings to the intended default.
- **`sealcraft:install --force` now forwards `--force` to `migrate`**
  so production-install workflows can bypass the migration confirmation
  prompt without a separate step.

### Added
- **Unified `$sealcraft` array for model context configuration.** Replaces
  the four separate `$sealcraftStrategy`, `$sealcraftContextType`,
  `$sealcraftContextColumn`, and `$sealcraftRowKeyColumn` properties with
  one array that reads like `$casts` or `$fillable`:
  ```php
  protected array $sealcraft = [
      'strategy' => 'per_row',     // 'per_group' (default) | 'per_row'
      'type'     => 'patient',     // context type
      'column'   => 'patient_id',  // per_group: id column; per_row: row-key column
  ];
  ```
  The legacy individual properties still work — no migration required.
- **Per-column context override via cast parameters.** `Encrypted` and
  `EncryptedJson` now accept `type=X,column=Y` pairs in the cast string
  to route one attribute to a different encryption context than the
  rest of the model:
  ```php
  protected $casts = [
      'ssn'        => Encrypted::class,
      'work_notes' => Encrypted::class . ':type=employer,column=employer_id',
  ];
  ```
  Only `type=` and `column=` together are supported; passing one without
  the other raises `SealcraftException` at construction time.
- **`sealcraft:doctor`** end-to-end diagnostic that combines config
  validation, a provider+cipher round-trip, and the model inventory
  scan in one command. Exits non-zero if any check fails — suitable
  for deploy-gate CI. Supports `--skip-roundtrip` and `--skip-models`
  for environments that can't run every step.
- **`sealcraft:models`** scans the app for models using
  `HasEncryptedAttributes` and prints a table with strategy, context,
  encrypted columns, and active DEK count per model. Supports
  `--path=<dir>` to scope and `--json` for machine-readable output.
- **`sealcraft:install` is now idempotent at the filesystem layer.**
  Detects existing `config/sealcraft.php` and existing
  `*_create_sealcraft_data_keys_table.php` migration files and skips
  re-publishing to prevent duplicate timestamped migration files.
  `--force` overrides the skip.
- **Bounded DEK cache with LRU eviction.** `DekCache` now caps at
  `sealcraft.dek_cache.max_entries` (default `1024`) and evicts the
  least-recently-used entry when full. Prevents unbounded plaintext-DEK
  retention in long-running workers (Horizon / Octane) that touch many
  tenants over time. Set `SEALCRAFT_DEK_CACHE_MAX_ENTRIES=0` to disable
  the cap.
- **`sealcraft:install`** one-shot onboarding command. Publishes config,
  publishes the migration, and runs `migrate` — idempotent and safe to
  re-run. Replaces the three-step `vendor:publish` / `migrate` dance.
- **`sealcraft:verify`** end-to-end smoke test. Round-trips a synthetic
  DEK through the configured provider and cipher, then shreds the
  context. Exits non-zero with an actionable message on failure.
- **Fail-fast config validation at boot**. A new `ConfigValidator`
  service validates the entire `sealcraft.*` block during
  `SealcraftServiceProvider::boot()` when
  `sealcraft.validate_on_boot=true` (the default). Missing env vars,
  typo'd provider names, and out-of-range values now fail at deploy
  time with messages that name the exact env var to set. Disable per
  app with `SEALCRAFT_VALIDATE_ON_BOOT=false` when testing bad config.
- **`.env.example`** ships in the package root with every env var the
  config honors, grouped by provider.
- **Upgraded error messages** across `ProviderRegistry`, `CipherRegistry`,
  and the `Encrypted` cast. Unknown-provider errors now list the valid
  provider names; unknown-cipher errors list the valid cipher names;
  the cast's "no recognizable cipher ID prefix" message now points at
  the legacy-plaintext migration path from the README.

### Changed
- **BREAKING:** `sealcraft:rotate-dek` context arguments are now
  positional instead of options, matching `sealcraft:generate-dek` and
  `sealcraft:shred`.
  - Before: `sealcraft:rotate-dek "App\\Models\\Patient" --context-type=patient --context-id=42`
  - After:  `sealcraft:rotate-dek "App\\Models\\Patient" patient 42`
  - For `Artisan::call` callers, rename keys `--context-type` /
    `--context-id` to `context_type` / `context_id`.
- **BREAKING:** `sealcraft.providers.azure_kv` renamed to
  `sealcraft.providers.azure_key_vault`. The config key now matches the
  driver name for consistency with `aws_kms`, `gcp_kms`, and
  `vault_transit`.
  - **Env**: change `SEALCRAFT_PROVIDER=azure_kv` to
    `SEALCRAFT_PROVIDER=azure_key_vault`.
  - **Code**: change any
    `config(['sealcraft.providers.azure_kv.*' => ...])` bindings to
    `config(['sealcraft.providers.azure_key_vault.*' => ...])`.
  - One-liner migration:
    `sed -i '' 's/azure_kv/azure_key_vault/g' .env config/sealcraft.php app/Providers/*.php`

## [0.1.4]

### Fixed
- **`CipherRegistry::peekId()` no longer returns false positives for
  non-ciphertext values whose first 8 characters contain a colon.**
  Previously, any `<word>:<anything>` payload — data URIs
  (`data:image/png;base64,...`), URLs (`http://...`, `mailto:...`),
  JSON-wrapped strings (`"{"foo":"bar"}"`) — was reported as ciphertext
  and the prefix returned as a "cipher ID." The method now validates
  the full sealcraft envelope shape (`<id>:v<n>:<b64>:<b64>[:<b64>...]`)
  AND that the prefix matches a registered cipher driver. This unblocks
  legacy-plaintext-backfill commands that used `peekId !== null` as the
  "already encrypted, skip" gate — they will now correctly identify
  colon-prefixed plaintext as plaintext and re-encrypt it. It also
  replaces the opaque `cipherById('data')` failure deep in the
  `Encrypted` cast with the clearer "no recognizable cipher ID prefix"
  `DecryptionFailedException` from the cast itself.

### Changed
- **`CipherRegistry::peekId()` is now an instance method.** The new
  validation requires access to the registry's cipher index, which is
  not available statically. Internal callers (`Casts\Encrypted`,
  `Casts\EncryptedJson`) have been updated to use the instance method
  via the registry they already resolve from the container. Consumers
  who call the method statically must either resolve the registry
  (`app(CipherRegistry::class)->peekId(...)`) or switch to the
  deprecated `peekIdUnsafe()` shim documented below.

### Deprecated
- **`CipherRegistry::peekIdUnsafe()`** (static) preserves the legacy
  prefix-only behavior for one release as a transitional escape hatch.
  Scheduled for removal in 0.2.0. Do not introduce new call sites; this
  method has the same false-positive bug that the new `peekId()` fixes.

### Migration notes
- No database or ciphertext format changes. Existing ciphertext is
  unchanged and remains readable.
- If you extend `Encrypted` or `EncryptedJson` and override `get()` /
  any tree-walking helper, replace `CipherRegistry::peekId($value)`
  with `$ciphers->peekId($value)` where `$ciphers` is your resolved
  `CipherRegistry` instance.
- Consumers running legacy-plaintext detection should re-run their
  reencrypt command after upgrading; rows that were silently skipped
  on v0.1.3 (because their plaintext happened to contain a `:` in the
  first 8 chars) will now be detected and re-encrypted.

## [0.1.3]

### Fixed
- **`HasEncryptedAttributes::sealcraftContext()` no longer silently mints a
  throwaway row-key UUID on an already-persisted row.** Previously, when a
  per-row model was loaded with an empty `sealcraft_key` (or the configured
  row-key column), every read minted a fresh UUID into in-memory attributes
  and returned it as the encryption context. The UUID was never persisted,
  so each subsequent read produced another UUID, and `KeyManager::getOrCreateDek()`
  inserted a fresh `sealcraft_data_keys` row every time. The original
  ciphertext was bound to a different (also discarded) context, so
  decryption always failed — while the orphan-DEK table grew unbounded.
  `sealcraftContext()` now throws `InvalidContextException` when the row
  exists and the row-key column is empty, pointing the operator at the new
  backfill command. Lazy mint behavior is preserved on unsaved models so
  the existing fill-then-save flow still works.

### Added
- **`creating` event hook** on `HasEncryptedAttributes` mints the per-row
  row-key before INSERT, so newly-created rows always carry a row-key
  even when no encrypted attribute is touched during fill (covers the
  `Model::create([...])` → encrypt-later pattern).
- **`sealcraft:backfill-row-keys {model} [--chunk=500] [--dry-run]`**
  command — backfills the per-row row-key column with fresh UUIDs on
  rows where it is `NULL` or empty. Bypasses model events and casts so
  it is safe to run on tables that already contain ciphertext under a
  legacy/missing context. Idempotent.

## [0.1.2]

### Fixed
- **`KeyManager::getActiveDataKey()` no longer queries the database on
  every encrypted column read/write.** `DekCache` now stores the
  `DataKey` model alongside the plaintext DEK, sharing one cache and
  one invalidation path. `getActiveDataKey()` checks the cache first;
  `getOrCreateDek()`, `createDek()`, and `unwrapInto()` populate both
  slots on first access. Existing `forget()` and `flush()` clear both
  stores, so Octane/queue lifecycle is unchanged.

## [0.1.1]

### Fixed
- **Stack overflow during `Model::fill()` with encrypted attributes.**
  Both `Encrypted` and `EncryptedJson` casts now cache the resolved
  `EncryptionContext` per model instance via a static `WeakMap`. When a
  model has N encrypted attributes, `sealcraftContext()` is called once
  instead of N times, eliminating redundant relationship loads and deep
  autoload chains that could exhaust `zend.max_allowed_stack_size`.
  Cache entries are automatically cleaned up on garbage collection.
  A public `forgetContext(Model)` static method is available on both
  cast classes for explicit invalidation.
- `HasEncryptedAttributes::handleSealcraftContextChange()` now clears
  both cast context caches when the context column is dirty, preventing
  stale context from surviving a re-encryption pass.
- `HasEncryptedAttributes::sealcraftEncryptedAttributes()` now detects
  `EncryptedJson` columns in addition to `Encrypted` columns, so
  per-group models with JSON-encrypted attributes are included in the
  auto re-encryption logic during context column changes.

## [0.1.0]

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
