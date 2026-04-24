<?php

declare(strict_types=1);

/*
 * Pins the behavior of `sealcraft:audit --roundtrip`: the command
 * exercises every active DataKey through the configured KEK provider
 * and reports a success/failure count. Previously untested.
 */

use Crumbls\Sealcraft\Models\DataKey;
use Crumbls\Sealcraft\Services\DekCache;
use Crumbls\Sealcraft\Services\KeyManager;
use Crumbls\Sealcraft\Values\EncryptionContext;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;

beforeEach(function (): void {
    config()->set('sealcraft.default_provider', 'null');
    config()->set('sealcraft.default_cipher', 'aes-256-gcm');
    $this->app->make(DekCache::class)->flush();
});

it('audit --roundtrip succeeds when every active DataKey unwraps cleanly', function (): void {
    $manager = $this->app->make(KeyManager::class);
    $manager->createDek(new EncryptionContext('tenant', 'rt-1'));
    $manager->createDek(new EncryptionContext('tenant', 'rt-2'));

    $code = Artisan::call('sealcraft:audit', ['--roundtrip' => true]);
    $output = Artisan::output();

    expect($code)->toBe(0);
    expect($output)->toContain('Round-trip validation');
    expect($output)->toContain('All active DataKeys unwrapped successfully');
});

it('audit --roundtrip reports failure when a DataKey is corrupted', function (): void {
    $manager = $this->app->make(KeyManager::class);
    $manager->createDek(new EncryptionContext('tenant', 'rt-corrupt'));

    // Corrupt the wrapped_dek so provider unwrap fails
    DB::table('sealcraft_data_keys')
        ->where('context_id', 'rt-corrupt')
        ->update(['wrapped_dek' => 'clearly-not-a-valid-envelope']);

    $this->app->make(DekCache::class)->flush();

    $code = Artisan::call('sealcraft:audit', ['--roundtrip' => true]);
    $output = Artisan::output();

    expect($code)->toBe(1);
    expect($output)->toContain('failed round-trip validation');
});

it('audit without --roundtrip does not touch the KEK provider', function (): void {
    $manager = $this->app->make(KeyManager::class);
    $manager->createDek(new EncryptionContext('tenant', 'no-rt'));

    $code = Artisan::call('sealcraft:audit');
    $output = Artisan::output();

    expect($code)->toBe(0);
    expect($output)->not->toContain('Round-trip validation');
});

it('audit --provider filters the report scope', function (): void {
    $manager = $this->app->make(KeyManager::class);
    $manager->createDek(new EncryptionContext('tenant', 'filter-null'), 'null');

    $code = Artisan::call('sealcraft:audit', ['--provider' => 'null']);

    expect($code)->toBe(0);
    expect(Artisan::output())->toContain('null');
});

it('audit --context-type filters rows to the named context type', function (): void {
    $manager = $this->app->make(KeyManager::class);
    $manager->createDek(new EncryptionContext('tenant', 'ct-1'));
    $manager->createDek(new EncryptionContext('patient', 'ct-2'));

    $code = Artisan::call('sealcraft:audit', ['--context-type' => 'patient']);
    $output = Artisan::output();

    expect($code)->toBe(0);
    expect($output)->toMatch('/Active DEKs\s+: 1/');

    expect(DataKey::query()->where('context_type', 'tenant')->count())->toBe(1);
    expect(DataKey::query()->where('context_type', 'patient')->count())->toBe(1);
});
