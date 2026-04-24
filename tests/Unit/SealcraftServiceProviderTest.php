<?php

declare(strict_types=1);

use Crumbls\Sealcraft\Commands\AuditCommand;
use Crumbls\Sealcraft\Commands\BackfillRowKeysCommand;
use Crumbls\Sealcraft\Commands\DoctorCommand;
use Crumbls\Sealcraft\Commands\GenerateDekCommand;
use Crumbls\Sealcraft\Commands\InstallCommand;
use Crumbls\Sealcraft\Commands\MigrateProviderCommand;
use Crumbls\Sealcraft\Commands\ModelsCommand;
use Crumbls\Sealcraft\Commands\ReencryptContextCommand;
use Crumbls\Sealcraft\Commands\RotateDekCommand;
use Crumbls\Sealcraft\Commands\RotateKekCommand;
use Crumbls\Sealcraft\Commands\ShredCommand;
use Crumbls\Sealcraft\Commands\VerifyCommand;
use Crumbls\Sealcraft\Services\CipherRegistry;
use Crumbls\Sealcraft\Services\DekCache;
use Crumbls\Sealcraft\Services\KeyManager;
use Crumbls\Sealcraft\Services\ProviderRegistry;
use Crumbls\Sealcraft\Values\EncryptionContext;
use Illuminate\Support\Facades\Artisan;

it('registers ProviderRegistry as a singleton', function (): void {
    $a = $this->app->make(ProviderRegistry::class);
    $b = $this->app->make(ProviderRegistry::class);

    expect($a)->toBeInstanceOf(ProviderRegistry::class);
    expect($a)->toBe($b);
});

it('registers CipherRegistry as a singleton', function (): void {
    $a = $this->app->make(CipherRegistry::class);
    $b = $this->app->make(CipherRegistry::class);

    expect($a)->toBe($b);
});

it('registers DekCache as a singleton', function (): void {
    $a = $this->app->make(DekCache::class);
    $b = $this->app->make(DekCache::class);

    expect($a)->toBe($b);
});

it('registers KeyManager as a singleton', function (): void {
    $a = $this->app->make(KeyManager::class);
    $b = $this->app->make(KeyManager::class);

    expect($a)->toBe($b);
});

it('merges the shipped config so sealcraft.* keys have defaults', function (): void {
    expect(config('sealcraft.default_provider'))->not->toBeNull();
    expect(config('sealcraft.default_cipher'))->toBeString();
    expect(config('sealcraft.dek_strategy'))->toBeIn(['per_group', 'per_row']);
    expect(config('sealcraft.providers'))->toBeArray();
    expect(config('sealcraft.ciphers'))->toBeArray();
});

it('registers every artisan command in the suite', function (): void {
    $registered = collect(Artisan::all())->keys()->all();

    expect($registered)->toContain(
        'sealcraft:audit',
        'sealcraft:backfill-row-keys',
        'sealcraft:doctor',
        'sealcraft:generate-dek',
        'sealcraft:install',
        'sealcraft:migrate-provider',
        'sealcraft:models',
        'sealcraft:reencrypt-context',
        'sealcraft:rotate-dek',
        'sealcraft:rotate-kek',
        'sealcraft:shred',
        'sealcraft:verify',
    );
});

it('registers commands as their documented classes', function (): void {
    $commands = Artisan::all();

    expect($commands['sealcraft:audit'])->toBeInstanceOf(AuditCommand::class);
    expect($commands['sealcraft:backfill-row-keys'])->toBeInstanceOf(BackfillRowKeysCommand::class);
    expect($commands['sealcraft:doctor'])->toBeInstanceOf(DoctorCommand::class);
    expect($commands['sealcraft:generate-dek'])->toBeInstanceOf(GenerateDekCommand::class);
    expect($commands['sealcraft:install'])->toBeInstanceOf(InstallCommand::class);
    expect($commands['sealcraft:migrate-provider'])->toBeInstanceOf(MigrateProviderCommand::class);
    expect($commands['sealcraft:models'])->toBeInstanceOf(ModelsCommand::class);
    expect($commands['sealcraft:reencrypt-context'])->toBeInstanceOf(ReencryptContextCommand::class);
    expect($commands['sealcraft:rotate-dek'])->toBeInstanceOf(RotateDekCommand::class);
    expect($commands['sealcraft:rotate-kek'])->toBeInstanceOf(RotateKekCommand::class);
    expect($commands['sealcraft:shred'])->toBeInstanceOf(ShredCommand::class);
    expect($commands['sealcraft:verify'])->toBeInstanceOf(VerifyCommand::class);
});

it('exposes sealcraft-config and sealcraft-migrations publish groups', function (): void {
    $groups = \Illuminate\Support\ServiceProvider::$publishGroups;

    expect($groups)->toHaveKey('sealcraft-config');
    expect($groups)->toHaveKey('sealcraft-migrations');
});

it('flushes DekCache when the app terminates', function (): void {
    config()->set('sealcraft.default_provider', 'null');
    config()->set('sealcraft.default_cipher', 'aes-256-gcm');

    $manager = $this->app->make(KeyManager::class);
    $cache = $this->app->make(DekCache::class);

    $manager->createDek(new EncryptionContext('tenant', 'termination'));
    expect($cache->has(new EncryptionContext('tenant', 'termination')))->toBeTrue();

    $this->app->terminate();

    expect($cache->has(new EncryptionContext('tenant', 'termination')))->toBeFalse();
});
