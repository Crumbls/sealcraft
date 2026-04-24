<?php

declare(strict_types=1);

use Crumbls\Sealcraft\Services\DekCache;
use Crumbls\Sealcraft\Services\KeyManager;
use Crumbls\Sealcraft\Tests\Fixtures\EncryptedDocument;
use Crumbls\Sealcraft\Tests\Fixtures\EncryptedVaultEntry;
use Crumbls\Sealcraft\Tests\Fixtures\OwnedUser;
use Crumbls\Sealcraft\Values\EncryptionContext;
use Illuminate\Support\Facades\Artisan;

beforeEach(function (): void {
    config()->set('sealcraft.default_provider', 'null');
    config()->set('sealcraft.default_cipher', 'aes-256-gcm');
    $this->app->make(DekCache::class)->flush();
});

it('discovers Sealcraft-using models under the scanned path and prints a table', function (): void {
    $code = Artisan::call('sealcraft:models', [
        '--path' => [__DIR__ . '/../../Fixtures'],
    ]);
    $output = Artisan::output();

    expect($code)->toBe(0);
    expect($output)->toContain('EncryptedDocument');
    expect($output)->toContain('EncryptedVaultEntry');
    expect($output)->toContain('OwnedUser');
    // Per-row and per-group should both appear as strategies
    expect($output)->toContain('per_group');
    expect($output)->toContain('per_row');
});

it('emits JSON when --json is passed', function (): void {
    $code = Artisan::call('sealcraft:models', [
        '--path' => [__DIR__ . '/../../Fixtures'],
        '--json' => true,
    ]);
    $output = trim(Artisan::output());

    expect($code)->toBe(0);

    $decoded = json_decode($output, true);
    expect($decoded)->toBeArray();
    expect($decoded)->not->toBeEmpty();

    $modelClasses = array_column($decoded, 'model');
    expect($modelClasses)->toContain(EncryptedDocument::class);
    expect($modelClasses)->toContain(OwnedUser::class);

    $edRow = collect($decoded)->firstWhere('model', EncryptedDocument::class);
    expect($edRow['strategy'])->toBe('per_group');
    expect($edRow['encrypted_attributes'])->toContain('secret');
    expect($edRow['encrypted_attributes'])->toContain('note');
});

it('reports active DEK counts for each model', function (): void {
    EncryptedDocument::query()->create(['tenant_id' => 1, 'secret' => 'a']);
    EncryptedDocument::query()->create(['tenant_id' => 2, 'secret' => 'b']);

    $this->app->make(KeyManager::class)->createDek(new EncryptionContext('tenant', 3));

    $code = Artisan::call('sealcraft:models', [
        '--path' => [__DIR__ . '/../../Fixtures'],
        '--json' => true,
    ]);

    $decoded = json_decode(trim(Artisan::output()), true);
    $edRow = collect($decoded)->firstWhere('model', EncryptedDocument::class);

    // EncryptedDocument is per_group with context_type 'tenant' — all 3 DEKs count
    expect($edRow['active_deks'])->toBe(3);
});

it('warns when no models are found in the scanned paths', function (): void {
    $empty = sys_get_temp_dir() . '/sealcraft-empty-' . bin2hex(random_bytes(4));
    mkdir($empty);

    $code = Artisan::call('sealcraft:models', ['--path' => [$empty]]);
    $output = Artisan::output();

    rmdir($empty);

    expect($code)->toBe(0);
    expect($output)->toContain('No models using HasEncryptedAttributes');
});

it('per-row model rows show their morph class in the context column', function (): void {
    OwnedUser::query()->create(['email' => 'morph@x', 'ssn' => '333-33-3333']);

    Artisan::call('sealcraft:models', [
        '--path' => [__DIR__ . '/../../Fixtures'],
        '--json' => true,
    ]);

    $decoded = json_decode(trim(Artisan::output()), true);
    $ownedRow = collect($decoded)->firstWhere('model', OwnedUser::class);

    expect($ownedRow['strategy'])->toBe('per_row');
    expect($ownedRow['context'])->toContain('sealcraft_key');

    // One DEK should exist for the single OwnedUser row we created
    expect($ownedRow['active_deks'])->toBeGreaterThanOrEqual(1);
});

it('gracefully handles paths that do not exist', function (): void {
    $code = Artisan::call('sealcraft:models', ['--path' => ['/nonexistent/path']]);

    expect($code)->toBe(0);
});
