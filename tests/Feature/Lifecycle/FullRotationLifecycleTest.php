<?php

declare(strict_types=1);

/*
 * Full cradle-to-grave lifecycle: a tenant's data is encrypted, its KEK
 * is rotated twice, its DEK is rotated in between, its provider is
 * migrated, and finally the tenant is crypto-shredded. Every step is
 * asserted against both row state and DataKey state.
 *
 * No existing test spans this arc — individual steps are covered in
 * CommandsTest and KeyManagerTest, but nothing exercises all of them
 * together. This test catches transition bugs between steps.
 */

use Crumbls\Sealcraft\Exceptions\ContextShreddedException;
use Crumbls\Sealcraft\Models\DataKey;
use Crumbls\Sealcraft\Providers\LocalKekProvider;
use Crumbls\Sealcraft\Services\DekCache;
use Crumbls\Sealcraft\Services\KeyManager;
use Crumbls\Sealcraft\Services\ProviderRegistry;
use Crumbls\Sealcraft\Tests\Fixtures\EncryptedDocument;
use Crumbls\Sealcraft\Values\EncryptionContext;
use Illuminate\Support\Facades\Artisan;

beforeEach(function (): void {
    $this->keyPath = sys_get_temp_dir() . '/sealcraft-lifecycle-' . bin2hex(random_bytes(6)) . '/kek.key';

    config()->set('sealcraft.default_provider', 'local');
    config()->set('sealcraft.default_cipher', 'aes-256-gcm');
    config()->set('sealcraft.context_type', 'tenant');
    config()->set('sealcraft.context_column', 'tenant_id');
    config()->set('sealcraft.providers.local', [
        'driver' => 'local',
        'key_path' => $this->keyPath,
        'allow_production' => false,
    ]);
    config()->set('sealcraft.providers.null', ['driver' => 'null']);

    $this->app->make(DekCache::class)->flush();
});

afterEach(function (): void {
    if (! isset($this->keyPath)) {
        return;
    }

    $dir = dirname($this->keyPath);
    foreach (glob($this->keyPath . '*') ?: [] as $f) {
        @unlink($f);
    }
    @rmdir($dir);
});

it('survives a full encrypt -> rotate KEK -> rotate DEK -> rotate KEK -> migrate provider -> shred cycle', function (): void {
    $tenantId = 1001;
    $ctx = new EncryptionContext('tenant', $tenantId);

    // Step 1: write rows under DEK v1, KEK v1
    $row1 = EncryptedDocument::query()->create(['tenant_id' => $tenantId, 'secret' => 'row-1']);
    $row2 = EncryptedDocument::query()->create(['tenant_id' => $tenantId, 'secret' => 'row-2']);
    $initialDataKeyId = DataKey::query()->forContext('tenant', (string) $tenantId)->active()->value('id');

    expect($initialDataKeyId)->not->toBeNull();
    expect(DataKey::query()->forContext('tenant', (string) $tenantId)->active()->value('key_version'))->toBe('v1');

    // Step 2: rotate KEK from v1 -> v2 at the provider layer, then run sealcraft:rotate-kek
    $provider = $this->app->make(ProviderRegistry::class)->provider('local');
    expect($provider)->toBeInstanceOf(LocalKekProvider::class);
    $provider->rotate();
    expect($provider->listKeyVersions())->toBe(['v1', 'v2']);

    $code = Artisan::call('sealcraft:rotate-kek', ['--context-type' => 'tenant', '--context-id' => (string) $tenantId]);
    expect($code)->toBe(0);

    $sameDekRow = DataKey::query()->forContext('tenant', (string) $tenantId)->active()->first();
    expect($sameDekRow->id)->toBe($initialDataKeyId);
    expect($sameDekRow->key_version)->toBe('v2');
    expect($sameDekRow->rotated_at)->not->toBeNull();

    $this->app->make(DekCache::class)->flush();
    expect(EncryptedDocument::query()->find($row1->id)->secret)->toBe('row-1');
    expect(EncryptedDocument::query()->find($row2->id)->secret)->toBe('row-2');

    // Step 3: rotate DEK itself — brand-new DEK, old rows re-encrypted under it, old DEK retired
    $oldCiphertext = $row1->fresh()->getRawOriginal('secret');
    $code = Artisan::call('sealcraft:rotate-dek', [
        'model' => EncryptedDocument::class,
        'context_type' => 'tenant',
        'context_id' => (string) $tenantId,
    ]);
    expect($code)->toBe(0);

    $newDataKey = DataKey::query()->forContext('tenant', (string) $tenantId)->active()->first();
    expect($newDataKey->id)->not->toBe($initialDataKeyId);
    expect(DataKey::query()->forContext('tenant', (string) $tenantId)->retired()->where('id', $initialDataKeyId)->count())->toBe(1);

    $this->app->make(DekCache::class)->flush();
    $freshRow1 = EncryptedDocument::query()->find($row1->id);
    expect($freshRow1->secret)->toBe('row-1');
    expect($freshRow1->getRawOriginal('secret'))->not->toBe($oldCiphertext);

    // Step 4: rotate KEK again v2 -> v3, confirm everything still readable
    $provider->rotate();
    expect($provider->listKeyVersions())->toBe(['v1', 'v2', 'v3']);

    Artisan::call('sealcraft:rotate-kek', ['--context-type' => 'tenant', '--context-id' => (string) $tenantId]);

    $finalActive = DataKey::query()->forContext('tenant', (string) $tenantId)->active()->first();
    expect($finalActive->key_version)->toBe('v3');

    $this->app->make(DekCache::class)->flush();
    expect(EncryptedDocument::query()->find($row1->id)->secret)->toBe('row-1');

    // Step 5: migrate provider from local -> null
    $code = Artisan::call('sealcraft:migrate-provider', [
        '--from' => 'local',
        '--to' => 'null',
        '--context-type' => 'tenant',
        '--context-id' => (string) $tenantId,
    ]);
    expect($code)->toBe(0);

    // After step 3's DEK rotation and step 5's provider migration, two
    // local-provider DEKs are retired (the original DEK + the migrated one).
    expect(DataKey::query()->forContext('tenant', (string) $tenantId)->forProvider('local')->retired()->count())->toBe(2);
    expect(DataKey::query()->forContext('tenant', (string) $tenantId)->forProvider('null')->active()->count())->toBe(1);

    $this->app->make(DekCache::class)->flush();
    expect(EncryptedDocument::query()->find($row1->id)->secret)->toBe('row-1');
    expect(EncryptedDocument::query()->find($row2->id)->secret)->toBe('row-2');

    // Step 6: shred the context — reads of any row must now throw ContextShreddedException
    $this->app->make(KeyManager::class)->shredContext($ctx);
    $this->app->make(DekCache::class)->flush();

    $shreddedRow = EncryptedDocument::query()->find($row1->id);
    expect(fn () => $shreddedRow->secret)->toThrow(ContextShreddedException::class);
});
