<?php

declare(strict_types=1);

/*
 * README-as-spec walkthrough.
 *
 * Every `it(...)` below corresponds to a concrete claim made in
 * packages/sealcraft/README.md. When the README changes, this file MUST
 * change with it (or vice versa). A failure here means the documentation
 * and the code disagree.
 *
 * Line references in comments point at the README sections being
 * exercised.
 */

use Crumbls\Sealcraft\Events\ContextReencrypted;
use Crumbls\Sealcraft\Events\ContextReencrypting;
use Crumbls\Sealcraft\Events\DecryptionFailed;
use Crumbls\Sealcraft\Events\DekCreated;
use Crumbls\Sealcraft\Events\DekRotated;
use Crumbls\Sealcraft\Events\DekShredded;
use Crumbls\Sealcraft\Events\DekUnwrapped;
use Crumbls\Sealcraft\Exceptions\ContextShreddedException;
use Crumbls\Sealcraft\Exceptions\InvalidContextException;
use Crumbls\Sealcraft\Models\DataKey;
use Crumbls\Sealcraft\Providers\AwsKmsKekProvider;
use Crumbls\Sealcraft\Providers\AzureKeyVaultKekProvider;
use Crumbls\Sealcraft\Providers\GcpCloudKmsKekProvider;
use Crumbls\Sealcraft\Providers\LocalKekProvider;
use Crumbls\Sealcraft\Providers\NullKekProvider;
use Crumbls\Sealcraft\Providers\VaultTransitKekProvider;
use Crumbls\Sealcraft\Services\DekCache;
use Crumbls\Sealcraft\Services\KeyManager;
use Crumbls\Sealcraft\Services\ProviderRegistry;
use Crumbls\Sealcraft\Tests\Fixtures\OwnedRecord;
use Crumbls\Sealcraft\Tests\Fixtures\OwnedUser;
use Crumbls\Sealcraft\Tests\Fixtures\Readme\Document;
use Crumbls\Sealcraft\Tests\Fixtures\Readme\Patient;
use Crumbls\Sealcraft\Tests\Fixtures\Readme\VaultEntry;
use Crumbls\Sealcraft\Values\EncryptionContext;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Event;

beforeEach(function (): void {
    config()->set('sealcraft.default_provider', 'null');
    config()->set('sealcraft.default_cipher', 'aes-256-gcm');
    config()->set('sealcraft.dek_strategy', 'per_group');
    config()->set('sealcraft.context_type', 'tenant');
    config()->set('sealcraft.context_column', 'tenant_id');
    config()->set('sealcraft.auto_reencrypt_on_context_change', true);

    $this->app->make(DekCache::class)->flush();
});

// -----------------------------------------------------------------------
// README: Install (lines 41-45)
// -----------------------------------------------------------------------

it('onboards via sealcraft:install + sealcraft:verify in the documented order', function (): void {
    $installCode = Artisan::call('sealcraft:install', ['--no-migrate' => true]);
    expect($installCode)->toBe(0);
    expect(Artisan::output())->toContain('Sealcraft is ready');

    $verifyCode = Artisan::call('sealcraft:verify');
    expect($verifyCode)->toBe(0);
    expect(Artisan::output())->toContain('Sealcraft verified');
});

it('publishes config and migrations under the documented tags', function (): void {
    $configGroups = \Illuminate\Support\ServiceProvider::$publishGroups['sealcraft-config'] ?? [];
    $migrationGroups = \Illuminate\Support\ServiceProvider::$publishGroups['sealcraft-migrations'] ?? [];

    expect($configGroups)->not->toBeEmpty()
        ->and(array_values($configGroups))->toContain(config_path('sealcraft.php'));
    expect($migrationGroups)->not->toBeEmpty();

    // The migration file shipped is the one the README's `php artisan migrate` runs.
    $migrationSources = array_keys($migrationGroups);
    $matched = array_filter(
        $migrationSources,
        fn (string $src): bool => str_ends_with($src, '/create_sealcraft_data_keys_table.php'),
    );
    expect($matched)->not->toBeEmpty();
});

it('runs the create_sealcraft_data_keys_table migration', function (): void {
    expect(\Illuminate\Support\Facades\Schema::hasTable('sealcraft_data_keys'))->toBeTrue();

    foreach ([
        'context_type', 'context_id', 'provider_name',
        'key_id', 'key_version', 'cipher', 'wrapped_dek',
        'created_at', 'rotated_at', 'retired_at', 'shredded_at',
    ] as $column) {
        expect(\Illuminate\Support\Facades\Schema::hasColumn('sealcraft_data_keys', $column))
            ->toBeTrue("migration missing column: {$column}");
    }
});

// -----------------------------------------------------------------------
// README: Quick start -> Model integration (lines 60-73)
// -----------------------------------------------------------------------

it('round-trips encrypted columns on a Patient declared as the README shows', function (): void {
    $patient = Patient::query()->create([
        'tenant_id' => 1,
        'ssn' => '123-45-6789',
        'dob' => '1980-04-23',
        'diagnosis' => 'asthma',
    ]);

    $raw = $patient->getRawOriginal('ssn');
    expect($raw)->toStartWith('ag1:v1:')
        ->and($raw)->not->toContain('123-45-6789');

    $this->app->make(DekCache::class)->flush();

    $fresh = Patient::query()->find($patient->id);
    expect($fresh->ssn)->toBe('123-45-6789');
    expect($fresh->dob)->toBe('1980-04-23');
    expect($fresh->diagnosis)->toBe('asthma');
});

it('treats null values as null (README line 76)', function (): void {
    $patient = Patient::query()->create([
        'tenant_id' => 1,
        'ssn' => null,
    ]);

    expect($patient->getRawOriginal('ssn'))->toBeNull();
    expect($patient->fresh()->ssn)->toBeNull();
});

// -----------------------------------------------------------------------
// README: Structured columns (EncryptedJson, lines 84-113)
// -----------------------------------------------------------------------

it('round-trips a nested EncryptedJson column preserving structure', function (): void {
    $history = [
        'conditions' => ['asthma', 'hypertension'],
        'allergies' => [
            ['substance' => 'penicillin', 'severity' => 'severe'],
        ],
        'notes' => 'no recent flares',
    ];

    $patient = Patient::query()->create([
        'tenant_id' => 2,
        'history' => $history,
    ]);

    $raw = json_decode((string) $patient->getRawOriginal('history'), true);
    expect($raw)->toBeArray();
    expect(array_keys($raw))->toEqual(['conditions', 'allergies', 'notes']);
    expect($raw['conditions'][0])->toStartWith('ag1:v1:');
    expect($raw['notes'])->toStartWith('ag1:v1:');

    $this->app->make(DekCache::class)->flush();

    $fresh = Patient::query()->find($patient->id);
    expect($fresh->history)->toEqual($history);
});

it('passes unprefixed string leaves through unchanged on read', function (): void {
    $tenantId = 3;
    $patient = Patient::query()->create([
        'tenant_id' => $tenantId,
        'history' => ['notes' => 'encrypted'],
    ]);

    $raw = json_decode((string) $patient->getRawOriginal('history'), true);
    $raw['plain_note'] = 'plain text leaf';

    Patient::query()->where('id', $patient->id)->update([
        'history' => json_encode($raw),
    ]);

    $this->app->make(DekCache::class)->flush();

    $fresh = Patient::query()->find($patient->id);
    expect($fresh->history['notes'])->toBe('encrypted');
    expect($fresh->history['plain_note'])->toBe('plain text leaf');
});

// -----------------------------------------------------------------------
// README: AWS KMS (lines 115-124)
// -----------------------------------------------------------------------

it('resolves the aws_kms provider from the README env snippet', function (): void {
    config()->set('sealcraft.providers.aws_kms', [
        'driver' => 'aws_kms',
        'key_id' => 'alias/my-app-kek',
        'region' => 'us-east-1',
    ]);

    $provider = $this->app->make(ProviderRegistry::class)->provider('aws_kms');

    expect($provider)->toBeInstanceOf(AwsKmsKekProvider::class);
    expect($provider->currentKeyId())->toBe('alias/my-app-kek');
});

// -----------------------------------------------------------------------
// README: GCP Cloud KMS (lines 128-140)
// -----------------------------------------------------------------------

it('resolves the gcp_kms provider and accepts a bound token resolver', function (): void {
    config()->set('sealcraft.providers.gcp_kms', [
        'driver' => 'gcp_kms',
        'project' => 'my-project',
        'location' => 'us-east1',
        'key_ring' => 'my-ring',
        'crypto_key' => 'app-kek',
        'token_resolver' => fn (): string => 'fake-oauth-token',
    ]);

    $provider = $this->app->make(ProviderRegistry::class)->provider('gcp_kms');

    expect($provider)->toBeInstanceOf(GcpCloudKmsKekProvider::class);
});

// -----------------------------------------------------------------------
// README: Azure Key Vault (lines 144-164)
// -----------------------------------------------------------------------

it('resolves the azure_key_vault provider with synthetic AAD strategy', function (): void {
    config()->set('sealcraft.providers.azure_key_vault', [
        'driver' => 'azure_key_vault',
        'vault_url' => 'https://my-vault.vault.azure.net',
        'key_name' => 'app-kek',
        'aad_strategy' => 'synthetic',
        'token_resolver' => fn (): string => 'fake-azure-token',
        'hmac_key_resolver' => fn (): string => random_bytes(32),
    ]);

    $provider = $this->app->make(ProviderRegistry::class)->provider('azure_key_vault');

    expect($provider)->toBeInstanceOf(AzureKeyVaultKekProvider::class);
});

// -----------------------------------------------------------------------
// README: Vault Transit (lines 168-173)
// -----------------------------------------------------------------------

it('resolves the vault_transit provider from the README env snippet', function (): void {
    config()->set('sealcraft.providers.vault_transit', [
        'driver' => 'vault_transit',
        'address' => 'https://vault.internal:8200',
        'token' => 's.xxxxxxxxxxxxxxxx',
        'key_name' => 'app-kek',
        'mount' => 'transit',
    ]);

    $provider = $this->app->make(ProviderRegistry::class)->provider('vault_transit');

    expect($provider)->toBeInstanceOf(VaultTransitKekProvider::class);
});

// -----------------------------------------------------------------------
// README: Local dev provider (lines 178-183)
// -----------------------------------------------------------------------

it('round-trips through the local file-backed provider', function (): void {
    $keyPath = sys_get_temp_dir() . '/sealcraft-readme-' . bin2hex(random_bytes(6)) . '/kek.key';

    config()->set('sealcraft.default_provider', 'local');
    config()->set('sealcraft.providers.local', [
        'driver' => 'local',
        'key_path' => $keyPath,
        'allow_production' => false,
    ]);

    $registry = $this->app->make(ProviderRegistry::class);
    $registry->forget('local');

    $provider = $registry->provider('local');
    expect($provider)->toBeInstanceOf(LocalKekProvider::class);

    $ctx = new EncryptionContext('tenant', 'readme-local');
    $manager = $this->app->make(KeyManager::class);
    $manager->createDek($ctx, 'local');

    expect(DataKey::query()->forContext('tenant', 'readme-local')->active()->count())->toBe(1);

    @unlink($keyPath);
    foreach (glob($keyPath . '.*') ?: [] as $f) {
        @unlink($f);
    }
    @rmdir(dirname($keyPath));
});

// -----------------------------------------------------------------------
// README: Per-group encryption context (lines 194-209)
// -----------------------------------------------------------------------

it('shares one DEK across all rows of a tenant in the per-group strategy', function (): void {
    $a = Document::query()->create(['tenant_id' => 10, 'body' => 'row A']);
    $b = Document::query()->create(['tenant_id' => 10, 'body' => 'row B']);
    $c = Document::query()->create(['tenant_id' => 20, 'body' => 'row C']);

    expect(DataKey::query()->forContext('tenant', '10')->active()->count())->toBe(1);
    expect(DataKey::query()->forContext('tenant', '20')->active()->count())->toBe(1);

    $this->app->make(DekCache::class)->flush();

    expect(Document::query()->find($a->id)->body)->toBe('row A');
    expect(Document::query()->find($b->id)->body)->toBe('row B');
    expect(Document::query()->find($c->id)->body)->toBe('row C');
});

// -----------------------------------------------------------------------
// README: Per-row encryption context (lines 211-229)
// -----------------------------------------------------------------------

it('mints one DEK per row in the per-row strategy', function (): void {
    $a = VaultEntry::query()->create(['secret' => 'alpha']);
    $b = VaultEntry::query()->create(['secret' => 'beta']);

    expect($a->sealcraft_key)->not->toBeEmpty();
    expect($b->sealcraft_key)->not->toBeEmpty();
    expect($a->sealcraft_key)->not->toBe($b->sealcraft_key);

    $morph = (new VaultEntry)->getMorphClass();
    expect(DataKey::query()->forContext($morph, $a->sealcraft_key)->active()->count())->toBe(1);
    expect(DataKey::query()->forContext($morph, $b->sealcraft_key)->active()->count())->toBe(1);
});

// -----------------------------------------------------------------------
// README: Delegated context (lines 231-260)
// -----------------------------------------------------------------------

it('delegates child record context to the owning user', function (): void {
    $user = OwnedUser::query()->create(['email' => 'a@x', 'ssn' => '111-22-3333']);
    $record = OwnedRecord::query()->create([
        'owned_user_id' => $user->id,
        'body' => 'medical note',
    ]);

    $morph = (new OwnedUser)->getMorphClass();

    expect(DataKey::query()->forContext($morph, $user->sealcraft_key)->active()->count())->toBe(1);
    expect(DataKey::query()->count())->toBe(1);

    $this->app->make(DekCache::class)->flush();

    $record->setRelation('owner', $user);
    expect($record->body)->toBe('medical note');
});

// -----------------------------------------------------------------------
// README: Changing context / auto-reencrypt (lines 262-270)
// -----------------------------------------------------------------------

it('auto-reencrypts when the per-group context column changes', function (): void {
    Event::fake([ContextReencrypting::class, ContextReencrypted::class]);

    $doc = Document::query()->create(['tenant_id' => 30, 'body' => 'payload']);

    $before = $doc->getRawOriginal('body');
    $doc->tenant_id = 31;
    $doc->save();

    $after = $doc->getRawOriginal('body');
    expect($after)->not->toBe($before);

    $this->app->make(DekCache::class)->flush();
    expect(Document::query()->find($doc->id)->body)->toBe('payload');

    Event::assertDispatched(ContextReencrypting::class, fn ($e): bool => $e->model->is($doc));
    Event::assertDispatched(ContextReencrypted::class, fn ($e): bool => $e->model->is($doc));
});

it('throws InvalidContextException when auto-reencrypt is disabled and context changes', function (): void {
    config()->set('sealcraft.auto_reencrypt_on_context_change', false);

    $doc = Document::query()->create(['tenant_id' => 40, 'body' => 'payload']);
    $doc->tenant_id = 41;

    expect(fn () => $doc->save())->toThrow(InvalidContextException::class);
});

// -----------------------------------------------------------------------
// README: Crypto-shred (lines 282-305)
// -----------------------------------------------------------------------

it('shreds a context via KeyManager::shredContext', function (): void {
    Event::fake([DekShredded::class]);

    $user = OwnedUser::query()->create(['email' => 'shred@x', 'ssn' => '444-55-6666']);

    $this->app->make(KeyManager::class)->shredContext($user->sealcraftContext());

    $morph = (new OwnedUser)->getMorphClass();
    expect(DataKey::query()->forContext($morph, $user->sealcraft_key)->shredded()->count())->toBe(1);

    Event::assertDispatched(DekShredded::class);
});

it('shreds a context via the sealcraft:shred artisan command', function (): void {
    $this->app->make(KeyManager::class)->createDek(new EncryptionContext('tenant', 'cli-shred'));

    $code = Artisan::call('sealcraft:shred', [
        'context_type' => 'tenant',
        'context_id' => 'cli-shred',
        '--force' => true,
    ]);

    expect($code)->toBe(0);
    expect(DataKey::query()->forContext('tenant', 'cli-shred')->shredded()->count())->toBe(1);
});

it('throws ContextShreddedException on post-shred read', function (): void {
    $user = OwnedUser::query()->create(['email' => 's@x', 'ssn' => '888-88-8888']);
    $this->app->make(KeyManager::class)->shredContext($user->sealcraftContext());
    $this->app->make(DekCache::class)->flush();

    $fresh = OwnedUser::query()->find($user->id);

    expect(fn () => $fresh->ssn)->toThrow(ContextShreddedException::class);
});

it('throws ContextShreddedException on post-shred write, preventing resurrection', function (): void {
    $user = OwnedUser::query()->create(['email' => 'w@x', 'ssn' => '777-77-7777']);
    $this->app->make(KeyManager::class)->shredContext($user->sealcraftContext());
    $this->app->make(DekCache::class)->flush();

    $fresh = OwnedUser::query()->find($user->id);

    expect(function () use ($fresh): void {
        $fresh->ssn = 'new-value';
        $fresh->save();
    })->toThrow(ContextShreddedException::class);
});

// -----------------------------------------------------------------------
// README: Key rotation playbook (lines 307-350)
// -----------------------------------------------------------------------

it('rotates KEK for every active DataKey when called with no filters', function (): void {
    $manager = $this->app->make(KeyManager::class);
    $manager->createDek(new EncryptionContext('tenant', 'rot-a'));
    $manager->createDek(new EncryptionContext('tenant', 'rot-b'));

    $code = Artisan::call('sealcraft:rotate-kek');

    expect($code)->toBe(0);
    expect(DataKey::query()->whereNotNull('rotated_at')->count())->toBe(2);
});

it('scopes rotate-kek to a single tenant with --context-type and --context-id', function (): void {
    $manager = $this->app->make(KeyManager::class);
    $manager->createDek(new EncryptionContext('tenant', '42'));
    $manager->createDek(new EncryptionContext('tenant', '99'));

    $code = Artisan::call('sealcraft:rotate-kek', [
        '--context-type' => 'tenant',
        '--context-id' => '42',
    ]);

    expect($code)->toBe(0);
    expect(DataKey::query()->forContext('tenant', '42')->whereNotNull('rotated_at')->count())->toBe(1);
    expect(DataKey::query()->forContext('tenant', '99')->whereNotNull('rotated_at')->count())->toBe(0);
});

it('scopes rotate-kek to a single provider with --provider', function (): void {
    $this->app->make(KeyManager::class)->createDek(new EncryptionContext('tenant', 'provider-rot'), 'null');

    $code = Artisan::call('sealcraft:rotate-kek', ['--provider' => 'null']);

    expect($code)->toBe(0);
    expect(DataKey::query()->forContext('tenant', 'provider-rot')->whereNotNull('rotated_at')->count())->toBe(1);
});

it('dry-runs rotate-kek without touching DataKeys', function (): void {
    $this->app->make(KeyManager::class)->createDek(new EncryptionContext('tenant', 'dry'));

    Artisan::call('sealcraft:rotate-kek', ['--dry-run' => true]);

    expect(DataKey::query()->forContext('tenant', 'dry')->whereNotNull('rotated_at')->count())->toBe(0);
});

it('rotates the DEK itself and re-encrypts all model rows (README line 339-343)', function (): void {
    $user = OwnedUser::query()->create(['email' => 'dek-rot@x', 'ssn' => '555-44-3333']);
    $morph = (new OwnedUser)->getMorphClass();
    $originalDataKeyId = DataKey::query()->forContext($morph, $user->sealcraft_key)->active()->value('id');

    $code = Artisan::call('sealcraft:rotate-dek', [
        'model' => OwnedUser::class,
        'context_type' => $morph,
        'context_id' => $user->sealcraft_key,
    ]);

    expect($code)->toBe(0);
    $newDataKeyId = DataKey::query()->forContext($morph, $user->sealcraft_key)->active()->value('id');
    expect($newDataKeyId)->not->toBe($originalDataKeyId);

    $this->app->make(DekCache::class)->flush();
    expect(OwnedUser::query()->find($user->id)->ssn)->toBe('555-44-3333');
});

it('migrates DataKeys between providers with sealcraft:migrate-provider', function (): void {
    config()->set('sealcraft.providers.null_b', ['driver' => 'null']);
    $registry = $this->app->make(ProviderRegistry::class);
    $registry->extend('null', fn (): NullKekProvider => new NullKekProvider);

    $this->app->make(KeyManager::class)
        ->createDek(new EncryptionContext('tenant', 'migrate'), 'null');

    Artisan::call('sealcraft:migrate-provider', ['--from' => 'null', '--to' => 'null_b', '--dry-run' => true]);
    expect(DataKey::query()->forContext('tenant', 'migrate')->forProvider('null_b')->count())->toBe(0);

    $code = Artisan::call('sealcraft:migrate-provider', ['--from' => 'null', '--to' => 'null_b']);

    expect($code)->toBe(0);
    expect(DataKey::query()->forContext('tenant', 'migrate')->forProvider('null')->retired()->count())->toBe(1);
    expect(DataKey::query()->forContext('tenant', 'migrate')->forProvider('null_b')->active()->count())->toBe(1);
});

// -----------------------------------------------------------------------
// README: Operational commands (lines 352-380)
// -----------------------------------------------------------------------

it('generate-dek provisions a DataKey for a context', function (): void {
    $code = Artisan::call('sealcraft:generate-dek', [
        'context_type' => 'tenant',
        'context_id' => 'new-dek',
    ]);

    expect($code)->toBe(0);
    expect(DataKey::query()->forContext('tenant', 'new-dek')->active()->count())->toBe(1);
});

it('backfill-row-keys fills empty row-key columns on legacy rows', function (): void {
    \Illuminate\Support\Facades\DB::table('owned_users')->insert([
        'email' => 'legacy@x',
        'sealcraft_key' => null,
    ]);

    $code = Artisan::call('sealcraft:backfill-row-keys', ['model' => OwnedUser::class]);

    expect($code)->toBe(0);
    $user = OwnedUser::query()->where('email', 'legacy@x')->first();
    expect($user->sealcraft_key)->not->toBeEmpty();
});

it('audit prints a DEK count report', function (): void {
    $manager = $this->app->make(KeyManager::class);
    $manager->createDek(new EncryptionContext('tenant', 'audit-a'));
    $manager->createDek(new EncryptionContext('tenant', 'audit-b'));
    $manager->shredContext(new EncryptionContext('tenant', 'audit-b'));

    $code = Artisan::call('sealcraft:audit');
    $output = Artisan::output();

    expect($code)->toBe(0);
    expect($output)->toContain('Active DEKs');
    expect($output)->toContain('Shredded DEKs');
});

it('reencrypt-context moves a single row to a new context (README command table)', function (): void {
    $doc = Document::query()->create(['tenant_id' => 50, 'body' => 'relocate']);

    $code = Artisan::call('sealcraft:reencrypt-context', [
        'model' => Document::class,
        'id' => (string) $doc->id,
        'new_value' => '60',
    ]);

    expect($code)->toBe(0);

    $this->app->make(DekCache::class)->flush();
    $fresh = Document::query()->find($doc->id);
    expect($fresh->tenant_id)->toBe(60);
    expect($fresh->body)->toBe('relocate');
});

// -----------------------------------------------------------------------
// README: Events table (lines 396-408)
// -----------------------------------------------------------------------

it('fires DekCreated, DekUnwrapped, DekRotated, ContextReencrypting, ContextReencrypted, DekShredded in order', function (): void {
    Event::fake([
        DekCreated::class,
        DekUnwrapped::class,
        DekRotated::class,
        DekShredded::class,
        ContextReencrypting::class,
        ContextReencrypted::class,
    ]);

    $doc = Document::query()->create(['tenant_id' => 70, 'body' => 'event-test']);
    Event::assertDispatched(DekCreated::class);

    $this->app->make(DekCache::class)->flush();
    Document::query()->find($doc->id)->body;
    Event::assertDispatched(DekUnwrapped::class);

    Artisan::call('sealcraft:rotate-kek', ['--context-type' => 'tenant', '--context-id' => '70']);
    Event::assertDispatched(DekRotated::class);

    $doc->tenant_id = 71;
    $doc->save();
    Event::assertDispatched(ContextReencrypting::class);
    Event::assertDispatched(ContextReencrypted::class);

    $this->app->make(KeyManager::class)->shredContext(new EncryptionContext('tenant', 71));
    Event::assertDispatched(DekShredded::class);
});

it('fires DecryptionFailed on a cross-tenant ciphertext swap', function (): void {
    Event::fake([DecryptionFailed::class]);

    $a = Document::query()->create(['tenant_id' => 90, 'body' => 'a-body']);
    $b = Document::query()->create(['tenant_id' => 91, 'body' => 'b-body']);

    $aCiphertext = $a->getRawOriginal('body');

    \Illuminate\Support\Facades\DB::table('readme_documents')
        ->where('id', $b->id)
        ->update(['body' => $aCiphertext]);

    $this->app->make(DekCache::class)->flush();

    try {
        Document::query()->find($b->id)->body;
    } catch (\Throwable) {
        // expected — AAD mismatch
    }

    Event::assertDispatched(DecryptionFailed::class);
});
