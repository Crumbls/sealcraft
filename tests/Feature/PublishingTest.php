<?php

declare(strict_types=1);

/*
 * End-to-end smoke test for `vendor:publish --tag=...`. Previous tests
 * only checked the publish-group registration existed; this test
 * actually invokes the command and verifies the files land at the
 * expected destinations with the expected content. Publishes go to the
 * Testbench laravel/ scratch directory, which this test cleans up.
 */

use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\ServiceProvider;

beforeEach(function (): void {
    $publishMap = ServiceProvider::$publishes[\Crumbls\Sealcraft\SealcraftServiceProvider::class] ?? [];

    $this->configDest = null;
    $this->migrationDest = null;

    foreach ($publishMap as $src => $dest) {
        if (str_ends_with($src, 'config/sealcraft.php')) {
            $this->configDest = $dest;
        } elseif (str_contains($src, 'create_sealcraft_data_keys_table')) {
            $this->migrationDest = $dest;
        }
    }

    // Remove any stale leftovers before the test runs
    if ($this->configDest && file_exists($this->configDest)) {
        @unlink($this->configDest);
    }
    if ($this->migrationDest && file_exists($this->migrationDest)) {
        @unlink($this->migrationDest);
    }
});

afterEach(function (): void {
    if ($this->configDest && file_exists($this->configDest)) {
        @unlink($this->configDest);
    }
    if ($this->migrationDest && file_exists($this->migrationDest)) {
        @unlink($this->migrationDest);
    }
});

it('resolves both publish destinations from the service provider registry', function (): void {
    expect($this->configDest)->not->toBeNull('sealcraft-config publish target missing');
    expect($this->migrationDest)->not->toBeNull('sealcraft-migrations publish target missing');
});

it('publishes config/sealcraft.php when sealcraft-config tag is invoked', function (): void {
    Artisan::call('vendor:publish', [
        '--tag' => 'sealcraft-config',
        '--force' => true,
    ]);

    expect(file_exists($this->configDest))->toBeTrue();

    $config = require $this->configDest;
    expect($config)->toBeArray();
    expect($config)->toHaveKey('default_provider');
    expect($config)->toHaveKey('default_cipher');
    expect($config)->toHaveKey('providers');
    expect($config['providers'])->toHaveKey('azure_key_vault');
    expect($config['providers'])->toHaveKey('aws_kms');
    expect($config['providers'])->toHaveKey('gcp_kms');
    expect($config['providers'])->toHaveKey('vault_transit');
    expect($config['providers'])->toHaveKey('local');
});

it('publishes the migration with a timestamped filename', function (): void {
    Artisan::call('vendor:publish', [
        '--tag' => 'sealcraft-migrations',
        '--force' => true,
    ]);

    expect(file_exists($this->migrationDest))->toBeTrue();
    expect(basename($this->migrationDest))->toMatch('/^\d{4}_\d{2}_\d{2}_\d{6}_create_sealcraft_data_keys_table\.php$/');
});

it('produces a published migration whose bytes match the shipped source exactly', function (): void {
    Artisan::call('vendor:publish', [
        '--tag' => 'sealcraft-migrations',
        '--force' => true,
    ]);

    $source = __DIR__ . '/../../database/migrations/create_sealcraft_data_keys_table.php';

    expect(file_get_contents($this->migrationDest))->toBe(file_get_contents($source));
});

it('published migration is a valid anonymous-class Migration with an up() method', function (): void {
    Artisan::call('vendor:publish', [
        '--tag' => 'sealcraft-migrations',
        '--force' => true,
    ]);

    $migration = require $this->migrationDest;
    expect($migration)->toBeInstanceOf(\Illuminate\Database\Migrations\Migration::class);
    expect(method_exists($migration, 'up'))->toBeTrue();
});

it('sealcraft:install drives both publishes end-to-end', function (): void {
    $code = Artisan::call('sealcraft:install', [
        '--force' => true,
        '--no-migrate' => true,
    ]);

    expect($code)->toBe(0);
    expect(file_exists($this->configDest))->toBeTrue();
    expect(file_exists($this->migrationDest))->toBeTrue();
});

it('sealcraft:install run twice does not duplicate the migration file (idempotence)', function (): void {
    Artisan::call('sealcraft:install', ['--no-migrate' => true]);
    $firstMigrationCount = count(glob(dirname($this->migrationDest) . '/*_create_sealcraft_data_keys_table.php'));

    Artisan::call('sealcraft:install', ['--no-migrate' => true]);
    $secondMigrationCount = count(glob(dirname($this->migrationDest) . '/*_create_sealcraft_data_keys_table.php'));
    $output = Artisan::output();

    expect($secondMigrationCount)->toBe($firstMigrationCount);
    expect($output)->toContain('already exists');
});

it('sealcraft:install --force re-publishes even when a migration already exists', function (): void {
    Artisan::call('sealcraft:install', ['--no-migrate' => true]);

    $code = Artisan::call('sealcraft:install', ['--no-migrate' => true, '--force' => true]);
    $output = Artisan::output();

    expect($code)->toBe(0);
    expect($output)->not->toContain('already exists');
});
