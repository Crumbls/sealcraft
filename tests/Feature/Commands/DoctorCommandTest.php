<?php

declare(strict_types=1);

use Crumbls\Sealcraft\Services\DekCache;
use Illuminate\Support\Facades\Artisan;

beforeEach(function (): void {
    config()->set('sealcraft.default_provider', 'null');
    config()->set('sealcraft.default_cipher', 'aes-256-gcm');
    $this->app->make(DekCache::class)->flush();
});

it('passes every step on a healthy configuration', function (): void {
    $code = Artisan::call('sealcraft:doctor', ['--skip-models' => true]);
    $output = Artisan::output();

    expect($code)->toBe(0);
    expect($output)->toContain('[1/3] Config validation');
    expect($output)->toContain('[2/3] Provider round-trip');
    expect($output)->toContain('All Sealcraft checks passed');
});

it('fails when config validation fails and reports the specific error', function (): void {
    // Make the config invalid: point default_provider at a non-existent block
    config()->set('sealcraft.default_provider', 'ghost_provider_block');

    $code = Artisan::call('sealcraft:doctor', ['--skip-roundtrip' => true, '--skip-models' => true]);
    $output = Artisan::output();

    expect($code)->toBe(1);
    expect($output)->toContain('FAIL');
    expect($output)->toContain('ghost_provider_block');
});

it('skips the round-trip when --skip-roundtrip is passed', function (): void {
    $code = Artisan::call('sealcraft:doctor', [
        '--skip-roundtrip' => true,
        '--skip-models' => true,
    ]);
    $output = Artisan::output();

    expect($code)->toBe(0);
    expect($output)->toContain('SKIP');
});

it('runs the models scan by default', function (): void {
    Artisan::call('sealcraft:doctor', ['--skip-roundtrip' => true]);
    $output = Artisan::output();

    expect($output)->toContain('Model inventory');
});
