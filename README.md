# Sealcraft

KMS-backed, field-level encryption for Laravel. Runs alongside Laravel's
built-in `Crypt` -- it does not replace it.

- **Laravel**: 11, 12, 13
- **PHP**: 8.2+
- **Providers**: AWS KMS, GCP Cloud KMS, Azure Key Vault, HashiCorp Vault Transit, Local (dev/test), Null (testing)
- **Ciphers**: AES-256-GCM (default), XChaCha20-Poly1305 (via libsodium)
- **One-command onboarding**: `php artisan sealcraft:install && php artisan sealcraft:verify`
- **Full documentation**: <https://www.crumbls.com/documentation/sealcraft>

## What this is

Sealcraft encrypts specific database columns with short-lived Data Encryption
Keys (DEKs) that are wrapped by a long-lived Key Encryption Key (KEK) inside
a cloud KMS. Use it when a particular column needs KMS-backed key custody,
documented rotation, per-tenant isolation, or cryptographic destruction on
demand.

Sealcraft does not replace Laravel's `Crypt` facade or `encrypted` cast.
Those keep doing what they do best -- sessions, cookies, signed URLs, queue
payloads, and casual field encryption where `APP_KEY` custody is acceptable.
Most apps that adopt Sealcraft still use `Crypt` everywhere else.

## Use cases

- **Healthcare (HIPAA-adjacent):** patient SSN/DOB/diagnosis, telehealth
  notes, insurance IDs -- including right-to-be-forgotten via one-shot
  crypto-shred of the patient's DEK.
- **Financial services:** bank account numbers, ABA routing, tax IDs,
  payout destination details on a marketplace.
- **Multi-tenant SaaS:** one DEK per tenant so a stolen DB dump means
  one-per-tenant unwrap attempts, not a single `APP_KEY` unlocking every
  customer. Per-tenant crypto-shred on cancellation.
- **Identity / auth:** stored OAuth refresh tokens, third-party API keys,
  MFA backup codes, KYC documents (passport / DL / national ID).
- **Legal / compliance:** privileged communications, protected-identity
  fields, GDPR Article 17 fulfillment across warehouses and backups via
  crypto-shred.
- **Consumer apps:** encrypted notes, journals, personal vaults where
  users expect that an internal DB reader alone cannot see content.
- **B2B SaaS:** CRM PII in strict-privacy jurisdictions, HR data
  (salaries, DOB, home addresses), sensitive contract metadata.

How it works: a plaintext DEK is unwrapped on demand, cached in memory for
the request, and overwritten with null bytes at request termination.
Rotating the KEK rewraps one DB row per tenant; column ciphertext never
changes.

## When NOT to use this

- **Sessions, cookies, signed URLs, queue payloads.** Those are Laravel
  `Crypt`'s job; Sealcraft is not designed for them.
- **You need `WHERE encrypted_col = ?` queries.** Searchable / blind-indexed
  encryption is out of scope for v1. Plan is to integrate CipherSweet-style
  blind indexing in v2.
- **Single-tenant app with no compliance story.** Laravel's built-in
  `encrypted` cast is fine -- you won't get your money's worth out of the
  extra operational surface.
- **You can't run a KMS and don't want to.** Sealcraft's local file
  provider is for development only and refuses to run in production
  without an explicit opt-in flag.

## Install

```bash
composer require crumbls/sealcraft
php artisan sealcraft:install
php artisan sealcraft:verify
```

`sealcraft:install` publishes config, publishes the migration, and runs `migrate`. `sealcraft:verify` round-trips a synthetic DEK through your configured provider and cipher so you know the deploy is actually wired up. Both commands are idempotent.

If you need to run the steps manually (for example in a CI pipeline that runs migrations separately), the low-level form still works:

```bash
php artisan vendor:publish --tag=sealcraft-config
php artisan vendor:publish --tag=sealcraft-migrations
php artisan migrate
```

Provider SDKs are optional — install only what you use:

```bash
composer require aws/aws-sdk-php          # for AWS KMS
composer require google/cloud-kms         # for GCP Cloud KMS
# Azure Key Vault and Vault Transit use Laravel's Http client; no SDK required
```

## Quick start

### Model integration

```php
use Crumbls\Sealcraft\Casts\Encrypted;
use Crumbls\Sealcraft\Concerns\HasEncryptedAttributes;

class Patient extends Model
{
    use HasEncryptedAttributes;

    protected $casts = [
        'ssn'       => Encrypted::class,
        'dob'       => Encrypted::class,
        'diagnosis' => Encrypted::class,
    ];
}
```

That's it. Reads and writes transparently encrypt. Null values stay null.

### Structured columns — encrypt JSON leaves while preserving shape

Need to keep a column queryable as a JSON tree (so admin tools, analytics,
or schema validators can see keys and structure) while protecting the
inner values? Use the `EncryptedJson` cast.

```php
use Crumbls\Sealcraft\Casts\Encrypted;
use Crumbls\Sealcraft\Casts\EncryptedJson;
use Crumbls\Sealcraft\Concerns\HasEncryptedAttributes;

class Patient extends Model
{
    use HasEncryptedAttributes;

    protected $casts = [
        'ssn'     => Encrypted::class,
        'history' => EncryptedJson::class,
    ];
}

$patient->history = [
    'conditions' => ['asthma', 'hypertension'],
    'allergies'  => [
        ['substance' => 'penicillin', 'severity' => 'severe'],
    ],
    'notes'      => 'no recent flares',
];
```

On disk, the column stays valid JSON — every leaf string is individually
encrypted under the same DEK as the row's scalar encrypted columns, while
keys, nesting, and non-string scalars (ints, floats, bools, nulls) remain
readable. On read, leaves that carry a cipher prefix are decrypted;
strings without a prefix pass through unchanged so columns can mix
plaintext shape data with encrypted leaves.

### AWS KMS

`.env`:

```dotenv
SEALCRAFT_PROVIDER=aws_kms
SEALCRAFT_AWS_KEY_ID=alias/my-app-kek
SEALCRAFT_AWS_REGION=us-east-1
# Uses standard AWS credential chain (env, profile, IRSA, IAM role)
```

### GCP Cloud KMS

```dotenv
SEALCRAFT_PROVIDER=gcp_kms
SEALCRAFT_GCP_PROJECT=my-project
SEALCRAFT_GCP_LOCATION=us-east1
SEALCRAFT_GCP_KEY_RING=my-ring
SEALCRAFT_GCP_CRYPTO_KEY=app-kek
```

Bind your token resolver in a service provider (ADC, workload identity, etc.):

```php
config(['sealcraft.providers.gcp_kms.token_resolver' => fn (): string => GcpAuth::freshAccessToken()]);
```

### Azure Key Vault

```dotenv
SEALCRAFT_PROVIDER=azure_key_vault
SEALCRAFT_AZURE_VAULT_URL=https://my-vault.vault.azure.net
SEALCRAFT_AZURE_KEY_NAME=app-kek
SEALCRAFT_AZURE_AAD_STRATEGY=synthetic
```

Azure's `wrapKey`/`unwrapKey` don't accept AAD natively. The default
`synthetic` strategy prepends an HMAC-SHA256 of the canonical context
over the DEK and verifies it on unwrap — defense-in-depth equivalent to
AWS/GCP. Switch to `cipher_only` if you can accept relying solely on
cipher-layer AAD plus Key Vault RBAC.

Bind the token resolver and (for synthetic AAD) an HMAC key resolver:

```php
config([
    'sealcraft.providers.azure_key_vault.token_resolver' => fn () => Azure::kvToken(),
    'sealcraft.providers.azure_key_vault.hmac_key_resolver' => fn () => AzureSecretHelper::hmacKeyBytes(),
]);
```

### HashiCorp Vault Transit

```dotenv
SEALCRAFT_PROVIDER=vault_transit
SEALCRAFT_VAULT_ADDR=https://vault.internal:8200
SEALCRAFT_VAULT_TOKEN=s.xxxxxxxxxxxxxxxx
SEALCRAFT_VAULT_KEY_NAME=app-kek
SEALCRAFT_VAULT_MOUNT=transit
```

### Local (dev/test only)

```dotenv
SEALCRAFT_PROVIDER=local
SEALCRAFT_LOCAL_KEY_PATH=/path/to/storage/sealcraft/kek.key
```

Refuses to load in `production` unless `SEALCRAFT_LOCAL_ALLOW_PRODUCTION=true`.

## Encryption contexts

Every DEK is bound to an **encryption context** — a (type, id) pair plus
optional scalar attributes. The context canonicalizes to stable UTF-8
bytes (NFC-normalized, byte-sorted keys, escaped separators, 4KB cap)
and is used as AAD at the cipher layer, and, where the provider
supports it, at the wrap layer too. A cross-context decrypt attempt
fails authentication.

Configure a model's context with a single `$sealcraft` array:

```php
protected array $sealcraft = [
    'strategy' => 'per_group',   // 'per_group' (default) | 'per_row'
    'type'     => 'tenant',      // context type name
    'column'   => 'tenant_id',   // per_group: context id column
                                 // per_row:   row-key column (default: sealcraft_key)
];
```

Only the keys that differ from defaults need to be set.

### Per-group (default) — one DEK per tenant / user / patient

Every row sharing a context value uses one DEK. KEK rotation rewraps
one row per context. Best for multi-tenant SaaS.

```php
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

### Per-row — one DEK per record

Each row carries its own `sealcraft_key` column (auto-populated UUID)
and gets its own DEK. Best for vault-style rows where each row is an
independent security boundary.

```php
class VaultEntry extends Model
{
    use HasEncryptedAttributes;

    protected array $sealcraft = ['strategy' => 'per_row'];

    protected $casts = ['secret' => Encrypted::class];
}
```

Add `sealcraft_key string(191) nullable index` to your model's
migration.

### Delegated context — user "passes" their key to related models

A record delegates its context to a parent so all of a user's data
across multiple tables shares one DEK. This is the HIPAA primitive
for one-shot crypto-shred.

```php
class OwnedUser extends Model
{
    use HasEncryptedAttributes;

    protected array $sealcraft = ['strategy' => 'per_row'];

    protected $casts = ['ssn' => Encrypted::class, 'dob' => Encrypted::class];
}

class OwnedRecord extends Model
{
    use HasEncryptedAttributes;

    protected $casts = ['body' => Encrypted::class];

    public function owner() { return $this->belongsTo(OwnedUser::class); }

    public function sealcraftContext(): \Crumbls\Sealcraft\Values\EncryptionContext
    {
        return $this->owner->sealcraftContext();
    }
}
```

### Per-column override — one model, multiple contexts

Most models use one context for all encrypted columns. When you need
to split — for example, a patient record where most fields belong to
the patient but one field belongs to the employer who issued it —
pass `type=` and `column=` as cast parameters:

```php
class Patient extends Model
{
    use HasEncryptedAttributes;

    protected array $sealcraft = [
        'type'   => 'patient',
        'column' => 'patient_id',
    ];

    protected $casts = [
        // Uses model-level context (patient, patient_id)
        'ssn'        => Encrypted::class,
        'history'    => EncryptedJson::class,

        // Per-column override: DEK under (employer, employer_id)
        'work_notes' => Encrypted::class . ':type=employer,column=employer_id',
    ];
}
```

The two context bindings are independent — shredding the patient
destroys `ssn` and `history` but leaves `work_notes` readable until
the employer context is shredded separately.

> The legacy form — four separate properties (`$sealcraftStrategy`,
> `$sealcraftContextType`, `$sealcraftContextColumn`,
> `$sealcraftRowKeyColumn`) — still works. The `$sealcraft` array is
> the recommended form going forward.

## Changing context (tenant moves, record re-owned)

Changing the context column on an existing row is a security-sensitive
event. Sealcraft's default is to **auto-reencrypt on save**:

```php
$patient->user_id = $newOwner->id;
$patient->save();  // auto-decrypts with old DEK, re-encrypts with new DEK
```

Two events fire:

- `ContextReencrypting` (pre, cancellable via `return false`)
- `ContextReencrypted` (post, for audit log)

Set `SEALCRAFT_AUTO_REENCRYPT=false` to require explicit migration via
`sealcraft:reencrypt-context` instead — the trait throws
`InvalidContextException` on any uncoordinated context change. Wire
the events to your SIEM regardless.

## Right-to-be-forgotten: crypto-shred

Permanent destruction of a user's data without `DELETE`-ing anything:

```php
app(\Crumbls\Sealcraft\Services\KeyManager::class)
    ->shredContext($user->sealcraftContext());
```

Or:

```bash
php artisan sealcraft:shred Crumbls\\Sealcraft\\Tests\\Fixtures\\OwnedUser <sealcraft_key>
```

After shred, every ciphertext ever wrapped under that context becomes
cryptographically unrecoverable. Reads raise `ContextShreddedException`
(a separate exception from `DecryptionFailedException`, so apps can
render a "record destroyed at user request" message instead of a 500).
Writes to a shredded context also fail with `ContextShreddedException`,
preventing accidental resurrection.

The `DekShredded` event fires on success — wire it to your compliance
audit log.

## Key rotation playbook

### KEK rotation (rotate the wrapping key)

Fast. No data is re-encrypted. Just rewraps each DataKey under the
current KEK version.

```bash
# All tenants
php artisan sealcraft:rotate-kek

# Scoped to one tenant
php artisan sealcraft:rotate-kek --context-type=tenant --context-id=42

# Scoped to a provider (useful after provider migration)
php artisan sealcraft:rotate-kek --provider=aws_kms

# See what would rotate without touching anything
php artisan sealcraft:rotate-kek --dry-run
```

Run during normal operation — the existing DataKey's stored KEK version
keeps older data decryptable during the rotation window.

### DEK rotation (rotate the data key itself)

Slower. Synchronously decrypts every row under the old DEK, re-encrypts
under a new DEK, then retires the old DEK. Run during a maintenance
window (the command assumes no concurrent writes for the affected
context).

```bash
php artisan sealcraft:rotate-dek "App\\Models\\Patient" patient 42
```

### Provider migration (move from one KMS to another)

```bash
php artisan sealcraft:migrate-provider --from=aws_kms --to=gcp_kms --dry-run
php artisan sealcraft:migrate-provider --from=aws_kms --to=gcp_kms
```

## Operational commands

| Command | Purpose |
|---|---|
| `sealcraft:generate-dek {type} {id}` | Manually provision a DEK |
| `sealcraft:rotate-kek` | KEK rotation (all or scoped) |
| `sealcraft:rotate-dek {model}` | DEK rotation (synchronous re-encryption) |
| `sealcraft:migrate-provider --from --to` | Move DataKeys between providers |
| `sealcraft:reencrypt-context {model} {id} {new}` | Per-row context migration |
| `sealcraft:backfill-row-keys {model}` | Fill empty per-row row-key columns on existing rows |
| `sealcraft:shred {type} {id}` | Crypto-shred (right to be forgotten) |
| `sealcraft:audit` | Report DEK counts, distribution, optional round-trip validation |

All destructive commands support `--dry-run`.

### Operational caveats

- **Per-row strategy: empty row-keys are a hard error.** If a saved row has
  `NULL` or empty in its row-key column (default `sealcraft_key`),
  `sealcraftContext()` throws `InvalidContextException` instead of minting a
  throwaway UUID. Silently minting would orphan a fresh DEK on every read
  and guarantee decryption failure, since the original ciphertext was bound
  to a different (also throwaway) context.
- **Backfill before turning encryption on.** When adopting the per-row
  strategy on an existing table, run
  `php artisan sealcraft:backfill-row-keys "App\\Models\\Patient"` to
  populate row-keys on legacy rows. The command is idempotent, supports
  `--chunk` and `--dry-run`, and bypasses model events so it is safe to
  run on tables that may already contain ciphertext.
- **New rows are handled automatically.** A `creating` hook on the trait
  ensures every newly INSERTed per-row model carries a row-key, even if
  no encrypted attribute is touched during fill.

## Configuration reference

See `config/sealcraft.php` after publishing. Key knobs:

- `default_provider` — KEK provider name
- `default_cipher` — `aes-256-gcm` (default) or `xchacha20`
- `dek_strategy` — `per_group` (default) or `per_row`
- `context_column`, `context_type` — defaults for per-group models
- `auto_reencrypt_on_context_change` — `true` (default) or `false`
- `rate_limit.unwrap_per_minute` — per-context unwrap throttle (0 = disabled)

## Events

Subscribe in a service provider to send to your SIEM / audit pipeline:

| Event | Fired when |
|---|---|
| `DekCreated` | A new DataKey row is inserted |
| `DekUnwrapped` | Plaintext DEK is produced (carries `cacheHit` flag) |
| `DekRotated` | A DataKey's KEK version changed (KEK rotation) |
| `DekShredded` | A context has been crypto-shredded |
| `DecryptionFailed` | Any unwrap or cipher auth failure; never includes plaintext |
| `ContextReencrypting` | Before auto-reencrypt; listeners may cancel by returning `false` |
| `ContextReencrypted` | After auto-reencrypt; audit-logging hook |

## Performance

- **Cache hit**: O(1) array lookup in process memory, zero network calls
- **Cache miss**: one KEK provider unwrap (~10-100ms network) + one DB
  query to find the DataKey row
- **Per-group strategy**: one unwrap per tenant per request regardless
  of how many rows or columns you read for that tenant
- **Per-row strategy**: one unwrap per distinct row you read

Shred, rotation, and audit commands iterate with `chunkById` so they
scale to 10k+ tenants.

## Threat model

**What Sealcraft protects against:**

- **Database-at-rest theft.** Attackers with a stolen DB dump (or
  backup tape, or replica snapshot) see only ciphertext. The KEK is in
  the KMS, not the DB; the DEK is never persisted in plaintext.
- **Cross-context ciphertext replay.** An attacker who swaps ciphertext
  from one tenant onto another tenant's row gets an authentication
  failure at decrypt time — the AAD binding catches it.
- **KMS enumeration.** The per-context unwrap rate limit blunts
  attacks that try to bulk-enumerate wrapped DEKs through a compromised
  KMS network path.
- **Right-to-be-forgotten requests.** Crypto-shred instantly makes a
  user's data unrecoverable without requiring row-level deletion
  across every table (backups, audit logs, warehouses, replicas).

**What Sealcraft does NOT protect against:**

- **Live application compromise.** If an attacker executes code inside
  your Laravel process, they can call `KeyManager` just like any other
  service. Plaintext DEKs live in request memory by design; there is no
  TEE or HSM-fronted plaintext boundary.
- **KMS compromise combined with DB access.** If an attacker both
  steals the DB and owns your KMS credentials, they can unwrap DEKs.
  AAD binding narrows the blast radius (they still need the matching
  context), but it's not a complete mitigation.
- **Plaintext in logs, cache, queues, or error reports.** Sealcraft
  only encrypts DB columns. Anything you pass through `dd()`,
  `Log::info()`, queue payloads, or a stack trace is your
  responsibility. Don't log PHI.
- **Key custody policy.** Sealcraft manages wrapping/unwrapping; it
  doesn't decide who can access the KEK in your KMS. Lock that down
  with IAM, managed identities, least-privilege policies, and approval
  workflows.

## Compliance notes

HIPAA and PCI-DSS expect encryption-at-rest with defensible key
management — which is what envelope encryption plus a KMS gives you.
Sealcraft is the key-management and cipher machinery; you still own
the rest:

- Authorization and access control (who can read a row)
- PHI scrubbing in logs, stack traces, error reports, and
  non-sealcraft columns
- Business associate agreements (BAAs) with your KMS vendor
- Backup encryption and backup-site key management
- Incident response and breach notification procedures

Crypto-shred is necessary but not sufficient for GDPR erasure — you
may still need to scrub names/emails/IDs from audit logs, telemetry,
and data warehouses.

## Migrating from `APP_KEY` / `encrypted` cast

The short version: back up the DB, write a one-off migration that
reads each encrypted column via `Crypt::decrypt`, re-assigns via the
`Encrypted` cast, and saves. Do it during a maintenance window. Keep
`APP_KEY` around for at least one full backup cycle in case of
rollback.

## Testing

```bash
composer test
composer test-coverage
composer analyse    # PHPStan
composer format     # Pint
```

Integration tests for AWS KMS use mocked `KmsClient`; GCP, Azure, and
Vault Transit use `Http::fake`. No live cloud credentials required.

## Documentation

Full reference documentation — installation, configuration, every provider, every encryption-context strategy, every artisan command, troubleshooting, and ADRs — is published at:

<https://www.crumbls.com/documentation/sealcraft>

The Markdown sources live under `docs/` in this repository and are versioned per release.

## Contributing

Issues and PRs welcome. Run `composer format` and `composer test`
before submitting.

## License

MIT — see [LICENSE.md](LICENSE.md).

## Security disclosures

See [SECURITY.md](SECURITY.md).
