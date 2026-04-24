---
title: Testing
weight: 90
---

# Testing apps that use Sealcraft

This guide covers writing tests against application code that stores encrypted columns — factories, assertions, mocking providers, and the patterns that keep the test suite fast and deterministic.

## Pick a test provider

Every test run needs a KEK provider. The choices:

| Provider | When to use |
|---|---|
| `null` | Default for unit/feature tests. No external I/O, no keyfile, instant. |
| `local` | When you explicitly want to exercise file-backed KEK versioning / rotation in a test. |
| `aws_kms` / `gcp_kms` / `azure_key_vault` / `vault_transit` | Only in dedicated integration tests, typically behind a feature flag or CI-only suite. Mock them in unit/feature tests. |

A sane default for `phpunit.xml`:

```xml
<php>
    <env name="SEALCRAFT_PROVIDER" value="null"/>
    <env name="SEALCRAFT_CIPHER" value="aes-256-gcm"/>
</php>
```

Or set it per test with `config()->set('sealcraft.default_provider', 'null')` in a `beforeEach`.

## Flush the DEK cache between tests

Sealcraft caches plaintext DEKs in memory (`DekCache`). Between tests that touch different tenants (or the same tenant across schema resets), flush the cache so cached DEKs don't refer to rows that no longer exist:

```php
beforeEach(function (): void {
    config()->set('sealcraft.default_provider', 'null');
    config()->set('sealcraft.default_cipher', 'aes-256-gcm');

    $this->app->make(\Crumbls\Sealcraft\Services\DekCache::class)->flush();
});
```

If you use `RefreshDatabase`, this is especially important — the `sealcraft_data_keys` table is reset between tests but the in-memory cache singleton survives if you are not using Testbench.

## Factories work out of the box

```php
class PatientFactory extends Factory
{
    protected $model = Patient::class;

    public function definition(): array
    {
        return [
            'tenant_id' => 1,
            'ssn' => fake()->numerify('###-##-####'),
            'dob' => fake()->date(),
            'diagnosis' => fake()->sentence(),
        ];
    }
}

$patient = Patient::factory()->create();
$patient->ssn; // decrypted plaintext
```

The cast encrypts on write and decrypts on read — factories don't need to know about Sealcraft at all. For per-row models, each factory-created row gets its own `sealcraft_key` (auto-minted by the `creating` hook).

## Assert the column is actually encrypted on disk

Use `getRawOriginal()` to see the stored ciphertext and `peekId()` to confirm it's a sealcraft envelope:

```php
use Crumbls\Sealcraft\Services\CipherRegistry;

it('ssn is stored encrypted', function (): void {
    $patient = Patient::factory()->create(['ssn' => '123-45-6789']);

    $ciphertext = $patient->getRawOriginal('ssn');

    expect($ciphertext)->not->toBe('123-45-6789');
    expect(app(CipherRegistry::class)->peekId($ciphertext))->toBe('ag1');
});
```

Pest custom expectation for readability:

```php
// tests/Pest.php
expect()->extend('toBeEncryptedOnDisk', function (): \Pest\Expectation {
    $ciphertext = (string) $this->value;
    $id = app(\Crumbls\Sealcraft\Services\CipherRegistry::class)->peekId($ciphertext);

    expect($id)->not->toBeNull("Column value is not a sealcraft envelope: {$ciphertext}");

    return $this;
});

// In a test:
expect($patient->getRawOriginal('ssn'))->toBeEncryptedOnDisk();
```

## Assert a cross-tenant read throws DecryptionFailed

```php
use Crumbls\Sealcraft\Exceptions\DecryptionFailedException;
use Illuminate\Support\Facades\DB;

it('swapping ciphertext across tenants fails authentication', function (): void {
    $a = Patient::factory()->create(['tenant_id' => 1, 'ssn' => 'a-ssn']);
    $b = Patient::factory()->create(['tenant_id' => 2, 'ssn' => 'b-ssn']);

    DB::table('patients')->where('id', $b->id)->update([
        'ssn' => $a->getRawOriginal('ssn'),
    ]);

    app(\Crumbls\Sealcraft\Services\DekCache::class)->flush();

    expect(fn () => Patient::find($b->id)->ssn)->toThrow(DecryptionFailedException::class);
});
```

## Shredding in tests

Shredding is permanent — after a test shreds a context, any later test trying to read the same context will raise `ContextShreddedException`. If you use `RefreshDatabase` the `sealcraft_data_keys` table resets between tests, so each test starts with a clean slate.

```php
use Crumbls\Sealcraft\Services\KeyManager;

it('crypto-shreds a patient', function (): void {
    $patient = Patient::factory()->create(['ssn' => 'destroy-me']);

    app(KeyManager::class)->shredContext($patient->sealcraftContext());
    app(\Crumbls\Sealcraft\Services\DekCache::class)->flush();

    expect(fn () => $patient->fresh()->ssn)
        ->toThrow(\Crumbls\Sealcraft\Exceptions\ContextShreddedException::class);
});
```

## Faking the KEK provider

For unit tests that don't need a real wrap/unwrap round-trip, register a custom driver via `ProviderRegistry::extend()` and point your test config at it:

```php
use Crumbls\Sealcraft\Services\ProviderRegistry;
use Crumbls\Sealcraft\Providers\NullKekProvider;

beforeEach(function (): void {
    config()->set('sealcraft.providers.test_null', ['driver' => 'test_null']);
    config()->set('sealcraft.default_provider', 'test_null');

    app(ProviderRegistry::class)->extend('test_null', fn () => new NullKekProvider);
});
```

For cloud providers, use Laravel's `Http::fake()`:

```php
use Illuminate\Support\Facades\Http;

it('mocks GCP KMS', function (): void {
    Http::fake([
        'cloudkms.googleapis.com/*:encrypt' => Http::response([
            'ciphertext' => base64_encode('fake-wrapped-dek'),
            'name' => 'projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1',
        ]),
        'cloudkms.googleapis.com/*:decrypt' => Http::response([
            'plaintext' => base64_encode('fake-plaintext-dek'),
        ]),
    ]);

    // ... exercise your code ...
});
```

## Listening for events in tests

```php
use Crumbls\Sealcraft\Events\DekCreated;
use Illuminate\Support\Facades\Event;

it('fires DekCreated on first write for a new tenant', function (): void {
    Event::fake([DekCreated::class]);

    Patient::factory()->create(['tenant_id' => 99, 'ssn' => '111-22-3333']);

    Event::assertDispatched(DekCreated::class, fn ($e) => $e->context->contextId === 99);
});
```

## Hiding encrypted columns from `toArray()` in API tests

Eloquent's `toArray()` runs through casts, so encrypted columns come out as plaintext. If your API should not leak them, add the columns to `$hidden` on the model or project them through an API Resource. In tests, assert the response:

```php
it('api response does not expose ssn', function (): void {
    $patient = Patient::factory()->create();

    $this->getJson("/api/patients/{$patient->id}")
        ->assertJsonMissing(['ssn' => $patient->ssn]);
});
```

## Running `sealcraft:doctor` in CI

Treat `sealcraft:doctor --skip-roundtrip` as a deploy-gate check in staging/CI:

```yaml
# .github/workflows/deploy.yml
- run: php artisan sealcraft:doctor --skip-roundtrip --skip-models
```

Skip `--skip-roundtrip` on a staging pipeline that can reach your KMS to get the full end-to-end check.

## Parallel test runners

Pest's parallel mode and PHPUnit's paratest both run tests in separate processes, each with its own `DekCache` singleton. No cross-process leakage to worry about. If a test uses `RefreshDatabase` the `sealcraft_data_keys` table is scoped per worker as well.
