<?php

declare(strict_types=1);

use Crumbls\Sealcraft\Events\DekShredded;
use Crumbls\Sealcraft\Models\DataKey;
use Crumbls\Sealcraft\Providers\NullKekProvider;
use Crumbls\Sealcraft\Services\DekCache;
use Crumbls\Sealcraft\Services\KeyManager;
use Crumbls\Sealcraft\Services\ProviderRegistry;
use Crumbls\Sealcraft\Tests\Fixtures\EncryptedDocument;
use Crumbls\Sealcraft\Tests\Fixtures\OwnedUser;
use Crumbls\Sealcraft\Values\EncryptionContext;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Event;

beforeEach(function (): void {
    config()->set('sealcraft.default_provider', 'null');
    config()->set('sealcraft.default_cipher', 'aes-256-gcm');
    config()->set('sealcraft.context_type', 'tenant');
    config()->set('sealcraft.context_column', 'tenant_id');

    $this->app->make(DekCache::class)->flush();
});

it('generate-dek creates a new DataKey for a context', function (): void {
    $code = Artisan::call('sealcraft:generate-dek', [
        'context_type' => 'tenant',
        'context_id' => '42',
    ]);

    expect($code)->toBe(0);
    expect(DataKey::query()->forContext('tenant', '42')->active()->count())->toBe(1);
});

it('generate-dek fails if a DataKey already exists', function (): void {
    $this->app->make(KeyManager::class)->createDek(new EncryptionContext('tenant', 77));

    $code = Artisan::call('sealcraft:generate-dek', [
        'context_type' => 'tenant',
        'context_id' => '77',
    ]);

    expect($code)->toBe(1);
});

it('shred retires the DEK and emits the DekShredded event', function (): void {
    $this->app->make(KeyManager::class)->createDek(new EncryptionContext('tenant', 9));

    Event::fake([DekShredded::class]);

    $code = Artisan::call('sealcraft:shred', [
        'context_type' => 'tenant',
        'context_id' => '9',
        '--force' => true,
    ]);

    expect($code)->toBe(0);
    expect(DataKey::query()->forContext('tenant', '9')->shredded()->count())->toBe(1);
    Event::assertDispatched(DekShredded::class);
});

it('rotate-kek rewraps every scoped active DataKey', function (): void {
    $manager = $this->app->make(KeyManager::class);
    $manager->createDek(new EncryptionContext('tenant', 1));
    $manager->createDek(new EncryptionContext('tenant', 2));

    $code = Artisan::call('sealcraft:rotate-kek', [
        '--context-type' => 'tenant',
    ]);

    expect($code)->toBe(0);
    expect(DataKey::query()->forContext('tenant', '1')->active()->whereNotNull('rotated_at')->count())->toBe(1);
    expect(DataKey::query()->forContext('tenant', '2')->active()->whereNotNull('rotated_at')->count())->toBe(1);
});

it('rotate-kek --dry-run touches no DataKeys', function (): void {
    $manager = $this->app->make(KeyManager::class);
    $manager->createDek(new EncryptionContext('tenant', 3));

    Artisan::call('sealcraft:rotate-kek', ['--dry-run' => true]);

    expect(DataKey::query()->forContext('tenant', '3')->active()->whereNotNull('rotated_at')->count())->toBe(0);
});

it('audit reports DEK counts', function (): void {
    $manager = $this->app->make(KeyManager::class);
    $manager->createDek(new EncryptionContext('tenant', 10));
    $manager->createDek(new EncryptionContext('tenant', 11));
    $manager->shredContext(new EncryptionContext('tenant', 11));

    $code = Artisan::call('sealcraft:audit');
    $output = Artisan::output();

    expect($code)->toBe(0);
    expect($output)->toContain('Active DEKs');
    expect($output)->toContain('Shredded DEKs');
    expect($output)->toContain(': 1'); // one active (context 10), one shredded (context 11)
});

it('reencrypt-context moves a model row to a new context', function (): void {
    $doc = EncryptedDocument::query()->create([
        'tenant_id' => 42,
        'secret' => 'migration-payload',
    ]);

    $code = Artisan::call('sealcraft:reencrypt-context', [
        'model' => EncryptedDocument::class,
        'id' => (string) $doc->id,
        'new_value' => '99',
    ]);

    expect($code)->toBe(0);

    $this->app->make(DekCache::class)->flush();

    $fresh = EncryptedDocument::query()->find($doc->id);
    expect($fresh->tenant_id)->toBe(99);
    expect($fresh->secret)->toBe('migration-payload');
});

it('rotate-dek re-encrypts model rows under a fresh DEK', function (): void {
    $user = OwnedUser::query()->create(['email' => 'e@x', 'ssn' => '111-22-3333']);

    $originalCiphertext = $user->getRawOriginal('ssn');
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
    expect(DataKey::query()->forContext($morph, $user->sealcraft_key)->retired()->count())->toBe(1);

    $this->app->make(DekCache::class)->flush();

    $fresh = OwnedUser::query()->find($user->id);
    expect($fresh->getRawOriginal('ssn'))->not->toBe($originalCiphertext);
    expect($fresh->ssn)->toBe('111-22-3333');
});

it('migrate-provider relocates DataKeys between providers', function (): void {
    config()->set('sealcraft.providers.null_b', ['driver' => 'null']);
    $registry = $this->app->make(ProviderRegistry::class);
    $registry->extend('null', fn () => new NullKekProvider);

    $this->app->make(KeyManager::class)->createDek(new EncryptionContext('tenant', 55), 'null');

    $code = Artisan::call('sealcraft:migrate-provider', [
        '--from' => 'null',
        '--to' => 'null_b',
    ]);

    expect($code)->toBe(0);
    expect(DataKey::query()->forContext('tenant', '55')->forProvider('null')->retired()->count())->toBe(1);
    expect(DataKey::query()->forContext('tenant', '55')->active()->count())->toBe(1);
});
