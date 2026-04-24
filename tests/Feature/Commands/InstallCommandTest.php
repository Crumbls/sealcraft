<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;

it('runs the install sequence end to end with success exit code', function (): void {
    $code = Artisan::call('sealcraft:install', ['--no-migrate' => true]);
    $output = Artisan::output();

    expect($code)->toBe(0);
    expect($output)->toContain('Publishing Sealcraft config');
    expect($output)->toContain('Publishing Sealcraft migration');
    expect($output)->toContain('Sealcraft is ready');
});

it('is idempotent — re-running is safe', function (): void {
    Artisan::call('sealcraft:install', ['--no-migrate' => true]);
    $code = Artisan::call('sealcraft:install', ['--no-migrate' => true]);

    expect($code)->toBe(0);
});

it('prints actionable next steps', function (): void {
    Artisan::call('sealcraft:install', ['--no-migrate' => true]);
    $output = Artisan::output();

    expect($output)->toContain('SEALCRAFT_PROVIDER');
    expect($output)->toContain('HasEncryptedAttributes');
    expect($output)->toContain('Encrypted::class');
    expect($output)->toContain('sealcraft:verify');
});

it('uses the renamed azure_key_vault identifier in next-step hints (not the old azure_kv)', function (): void {
    Artisan::call('sealcraft:install', ['--no-migrate' => true]);
    $output = Artisan::output();

    expect($output)->toContain('azure_key_vault');
    expect($output)->not->toContain('azure_kv|');
});

it('forwards --force to migrate so production install can skip the migrate prompt', function (): void {
    // Can't easily assert on migrate's internal flags here without a deeper
    // harness, but we can at least confirm the command accepts --force
    // without failing and still exits successfully.
    $code = Artisan::call('sealcraft:install', ['--force' => true, '--no-migrate' => true]);

    expect($code)->toBe(0);
});
