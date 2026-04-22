# Agent notes: sealcraft

Context for AI agents (and humans) picking up work on this package or
integrating it into a new Laravel app. Read `README.md` for the
user-facing story; this file is about *why* the code looks the way
it does and *what's easy to get wrong*.

## What this package actually is

Envelope encryption for Laravel. Two moving parts:

1. **DEK** (Data Encryption Key): a short-lived symmetric key that
   actually encrypts column data. Never persisted as plaintext.
2. **KEK** (Key Encryption Key): a long-lived key, typically in a
   KMS (AWS KMS, Azure Key Vault, GCP KMS, HashiCorp Vault), that
   wraps the DEK so the wrapped DEK can safely sit in the DB.

Every DEK is bound to an `EncryptionContext` — a (type, id) pair —
which is used as AAD at the cipher layer and (where the provider
supports it) at the wrap layer too. This is what makes cross-context
ciphertext swap attacks fail authentication.

## Decisions locked in (do not re-litigate without reason)

| Decision | Chosen | Why |
|---|---|---|
| Cipher identification | 3-char ID embedded in ciphertext (`ag1`, `xc1`) | Read path dispatches to correct cipher without consulting DataKey row; lets cipher migration happen without re-encryption |
| DEK rotation semantics | Synchronous re-encryption before retiring old DEK | Matches HIPAA/PCI expectations; simple read path (no retired-DEK reads); tradeoff is operational heaviness |
| KEK rotation scope | Both scoped and unscoped, with chunked iteration | Supports multi-tenant installs with 10k+ tenants |
| DataKey shape | Polymorphic `context_type` + `context_id` (string) | Allows tenant-scoped AND patient-scoped DEKs side-by-side; integrity enforced at app layer via AAD |
| Context change policy | Auto-reencrypt on save by default, config-gated | Smooth DX for multi-tenant apps; disable for installs that require explicit audited migrations |
| Azure AAD strategy | Synthetic HMAC default, `cipher_only` opt-out | Azure `wrapKey` has no native AAD; synthetic recovers defense-in-depth |
| Context canonical form | Pipe-delimited, NFC-normalized, byte-sort keys, 4KB cap | Avoids JSON edge cases (key ordering, number repr); trivial to hand-verify |
| Per-row identifier | Auto-generated `sealcraft_key` UUID column | Primary keys don't exist at insert time; UUID solves chicken-and-egg and persists independently of row PK changes |
| Laravel version range | 11 / 12 / 13 | User-confirmed |
| DEK strategies | `per_group` (default) + `per_row` opt-in | Covers multi-tenant SaaS (per_group) and vault-style apps (per_row) |

## The provider selection flowchart

```
Does your infra allow runtime HTTPS to a KMS from app servers?
├── No  → ConfigKekProvider (pipeline pulls KEK bytes into env)
└── Yes → Do you already run on a cloud?
         ├── AWS         → AwsKmsKekProvider   (native AAD)
         ├── Azure       → AzureKeyVaultKekProvider  (synthetic AAD strategy)
         ├── GCP         → GcpCloudKmsKekProvider    (native AAD)
         └── Self-hosted → VaultTransitKekProvider   (native AAD)

Dev / local testing → LocalKekProvider (refuses production w/o opt-in)
Unit tests          → NullKekProvider
```

## The strategy selection flowchart

```
Is every row in this model an independent security boundary (e.g.
each row is a vault / a user's private record)?
├── Yes → per_row strategy
│         Each row carries a sealcraft_key UUID; each row gets its
│         own DEK. Crypto-shredding one row destroys just that row.
│
└── No → Is the data scoped to a tenant / patient / organization?
         ├── Yes → per_group strategy (default)
         │         All rows sharing the context column share one DEK.
         │         Low KMS call volume; rotation rewraps one row per group.
         │
         └── Do many tables belong to one "owner" (e.g. user with
             medical records, prescriptions, notes)?
             └── Yes → per_row on the owner + delegated context on related models
                       Related models override sealcraftContext() to return
                       $this->owner->sealcraftContext(). One DEK protects
                       everything the owner touches across every table.
                       This is the HIPAA right-to-be-forgotten pattern.
```

## Integration playbook: adding sealcraft to a new Laravel app

1. **Composer install**
   ```bash
   composer require crumbls/sealcraft
   php artisan vendor:publish --tag=sealcraft-config
   ```
2. **Pick a provider** per the flowchart above. Set the matching
   `SEALCRAFT_*` env vars. For providers that need a token resolver
   (`azure_kv`, `gcp_kms`, `vault_transit`), bind the closure in a
   service provider — see `README.md` for examples.
3. **Run migrations** — the package auto-loads
   `create_sealcraft_data_keys_table` via `loadMigrationsFrom`. Do
   **not** also publish migrations; if you do, delete the published
   copy to avoid a duplicate-migration collision (only one will
   succeed, the other errors "table already exists"). See known
   gotcha below.
4. **Pick a strategy** per the flowchart. For per_row, add a
   `sealcraft_key string(191) nullable` column + index to the model's
   migration.
5. **Wire up the model**:
   ```php
   use Crumbls\Sealcraft\Casts\Encrypted;
   use Crumbls\Sealcraft\Concerns\HasEncryptedAttributes;

   class User extends Authenticatable {
       use HasEncryptedAttributes;
       protected string $sealcraftStrategy = 'per_row';
       protected $casts = ['ssn' => Encrypted::class];
       // Put sealcraft_key in $hidden.
   }
   ```
6. **For related tables, delegate context**:
   ```php
   public function sealcraftContext(): EncryptionContext {
       return $this->owner->sealcraftContext();
   }
   ```
7. **Smoke test**: create a row with the encrypted column, confirm
   the DB row has `ag1:v1:...` ciphertext (not plaintext), fresh
   fetch returns plaintext, `KeyManager::shredContext()` makes
   further reads throw `ContextShreddedException`.

## Gotchas that bit us during development

These are real bugs that shipped, got caught in test or in the live
app, and got fixed. If you change the relevant code, re-read these.

### 1. Laravel `array_replace`s the cast's return value onto `$this->attributes`

The `Encrypted` cast's `set()` method has to return an **array** of
all attributes it wants to persist, not just the encrypted value.
Laravel snapshots `$this->attributes` before calling the cast and
`array_replace`s the cast's return value onto it after — so any
mutations the cast makes to `$this->attributes` directly (e.g., the
context resolver lazily generating `sealcraft_key`) get wiped.

The cast captures `$priorAttrs = $model->getAttributes()` *before*
resolving context, then after resolving, iterates current attributes
and includes any whose value changed or key is new. If you simplify
this to "just return the ciphertext," you will break per-row for
rows that didn't already have a `sealcraft_key`.

### 2. `Event::fake()` doesn't retroactively fake captured dispatchers

If you inject `Dispatcher` into a singleton's constructor and then
call `Event::fake()` in a test, the singleton still holds the real
dispatcher — `Event::fake()` only swaps the container binding and
the facade accessor. `KeyManager` therefore uses the `Event` facade
directly (`Event::dispatch(...)`) rather than a captured Dispatcher
ref. Don't "refactor to DI" this back; tests will break silently
(assertions pass against an empty fake while dispatches go elsewhere).

### 3. Unique-active-DataKey can't be enforced by SQL

MySQL, SQLite, and Postgres ≤ 14 treat `NULL` as distinct in unique
indexes, so `UNIQUE(context_type, context_id, retired_at)` does not
prevent multiple rows with `retired_at = NULL` for the same context.
Enforcement happens in `KeyManager::createDek()` via a transaction +
`lockForUpdate()`. Don't add back a `UNIQUE` constraint thinking it
will help; it won't.

### 4. Primary key is not available before save

Per-row strategy can't use `$this->getKey()` as context because
`Encrypted::set()` runs during `fill()`, before the row is inserted.
That's why per-row generates a `sealcraft_key` UUID lazily in
`sealcraftContext()` and injects it into `$this->attributes`. See
gotcha #1 for how it gets persisted.

### 5. `setRawAttributes(sync: true)` silences `save()`

In `RotateDekCommand` we re-encrypt row ciphertext. Using
`setRawAttributes($attributes, sync: true)` updates original to match
new, so `save()` sees nothing dirty and silently no-ops. The command
now uses direct `DB::update()` instead of going through the model,
both to bypass dirty tracking and to skip the auto-reencrypt
observer that would otherwise try to do something smart mid-rotation.

### 6. Context type regex must allow backslashes

Per-row context uses `$model->getMorphClass()` as the context type,
which is a FQN with `\` separators. `ContextSerializer` has a
separate `CONTEXT_TYPE_REGEX` (allows `\`) distinct from
`ATTR_KEY_REGEX` (doesn't). Don't merge them.

### 7. Published migration + auto-loaded migration collide

`SealcraftServiceProvider::registerMigrations()` calls
`loadMigrationsFrom()` AND `registerPublishing()` registers a
publish tag for the same migration. Publishing creates a timestamped
copy; the package auto-load also references the untimestamped
original. Both are "pending." Running migrate tries both → second
one fails with "table already exists."

**Workaround in app**: after publishing, delete the published copy.
**Fix candidate (not yet shipped)**: remove auto-load, require
publish. Standard Spatie pattern. Would break existing installs.

## Testing conventions

- **Pest 3, not PHPUnit.** All tests as `it('...')` functions.
- **Structure**: `tests/Unit/<folder matching src/>/<Class>Test.php`
  for pure unit tests; `tests/Feature/<Feature>Test.php` for tests
  that need the Laravel container / DB.
- **DB**: SQLite `:memory:` via Orchestra Testbench. See
  `tests/TestCase.php`.
- **Fixtures**: `tests/Fixtures/` holds test models and their
  migrations. `TestCase::defineDatabaseMigrations` loads both the
  package's and the fixtures' migrations.
- **HIPAA patterns** live in `tests/Feature/HipaaPatternsTest.php` —
  if you change delegation, shred, or the per-row UUID mechanics,
  update that file.
- **Full suite should stay green** — there's no "acceptable failures"
  list. If you break something, fix it before committing.

## Coding conventions

- `declare(strict_types=1);` at the top of every file.
- `final` on concrete classes unless there's a real extension
  point. Contracts (`interface`) for extension points.
- Constructor property promotion wherever all properties qualify.
- PSR-12 + Laravel Pint config (`pint.json`). Run `vendor/bin/pint`
  before committing.
- No comments that describe what the code does. Comments are for
  non-obvious *why* — constraints, gotchas, references to upstream
  quirks. See the cipher IDs, the context canonical rules, the
  array_replace gotcha for examples.
- Events are simple `final` value objects with public readonly
  properties. No behavior.
- Exceptions: `SealcraftException` is the root. Specific subclasses
  for distinct failure modes. `ContextShreddedException` is
  intentionally distinct from `DecryptionFailedException` — apps
  handle them differently.

## Known limitations + deferred features

- **No searchable encryption** (`WHERE encrypted = ?`). Planned for
  v2 via blind indexing (CipherSweet pattern).
- **No Level-3 multi-provider** (simultaneous dual-wrap under two
  KMSes for DR). Planned for v1.1.
- **No built-in Managed Identity / ADC helpers.** Apps bind their
  own token resolver closure.
- **`rotate-dek` assumes no concurrent writes** during execution.
  Production use should be inside a maintenance window.
- **No IBM Key Protect or other minor KMS providers.** Extension
  point is `ProviderRegistry::extend()`.

## When in doubt

- **Security posture question** (is X safe, should we allow Y) —
  err toward the conservative choice. Default behavior should be
  the HIPAA-defensible one; weaker options exist only as explicit
  opt-ins with loud documentation (e.g. `cipher_only` AAD,
  `allow_production` on local).
- **Performance concern** (this feels slow) — check if `DekCache`
  is being flushed too aggressively. One unwrap per context per
  request is the target. If you're seeing more, that's a cache
  miss bug, not "encryption is slow."
- **Compliance question** — sealcraft handles the *cryptographic*
  primitives. Everything else (BAAs, access control, backup
  handling, PHI logging hygiene) is the app's responsibility. The
  threat model section in `README.md` is the canonical statement
  of what the package does and does not cover.

## Files worth knowing

| File | What it does |
|---|---|
| `src/SealcraftServiceProvider.php` | Container bindings, command registration, terminating-flush hook |
| `src/Services/KeyManager.php` | DEK lifecycle orchestration; the heart of the package |
| `src/Services/ContextSerializer.php` | Canonical context serialization rules |
| `src/Casts/Encrypted.php` | Eloquent integration entry point |
| `src/Concerns/HasEncryptedAttributes.php` | Trait with default context resolver + auto-reencrypt observer |
| `src/Providers/*` | One file per KMS provider; read `AwsKmsKekProvider.php` as the canonical shape |
| `tests/Feature/HipaaPatternsTest.php` | Regression guard for delegation + shred semantics |

## Handoff checklist

If you're picking this up to integrate into a PHI app:

- [ ] Read `README.md` end-to-end.
- [ ] Read the threat model section specifically.
- [ ] Decide on provider per the flowchart above.
- [ ] Decide on strategy (almost certainly per_row on User + delegated
      on related PHI tables).
- [ ] Enumerate every table that holds PHI. They all get
      `HasEncryptedAttributes` + `Encrypted` casts.
- [ ] Plan a backfill migration for existing plaintext rows.
- [ ] Wire listeners for `DekShredded`, `ContextReencrypted`,
      `DecryptionFailed` → SIEM / audit log.
- [ ] Document your key management SOP (rotation schedule, HMAC key
      custody if Azure synthetic AAD, what an incident looks like).
- [ ] Confirm BAA coverage with your KMS vendor.
- [ ] Run `vendor/bin/pest` inside the package at least once to
      confirm the environment works.
