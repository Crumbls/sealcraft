<?php

declare(strict_types=1);

use Crumbls\Sealcraft\Models\DataKey;
use Crumbls\Sealcraft\Services\DekCache;
use Illuminate\Support\Facades\Artisan;

beforeEach(function (): void {
    config()->set('sealcraft.default_provider', 'null');
    config()->set('sealcraft.default_cipher', 'aes-256-gcm');
    $this->app->make(DekCache::class)->flush();
});

it('round-trips a synthetic DEK through the configured provider and cipher', function (): void {
    $code = Artisan::call('sealcraft:verify');
    $output = Artisan::output();

    expect($code)->toBe(0);
    expect($output)->toContain('Provider:');
    expect($output)->toContain('Cipher:');
    expect($output)->toContain('DEK created:');
    expect($output)->toContain('Sealcraft verified');
});

it('cleans up the synthetic context via shred so no residue is left', function (): void {
    $before = DataKey::query()->count();
    Artisan::call('sealcraft:verify');

    $activeAfter = DataKey::query()->where('context_type', 'sealcraft_verify')->active()->count();
    $shreddedAfter = DataKey::query()->where('context_type', 'sealcraft_verify')->shredded()->count();

    expect($activeAfter)->toBe(0);
    expect($shreddedAfter)->toBe(1);
    expect(DataKey::query()->count() - $before)->toBe(1);
});

it('returns failure and a readable message when provider resolution fails', function (): void {
    $code = Artisan::call('sealcraft:verify', ['--provider' => 'definitely-not-a-real-provider']);
    $output = Artisan::output();

    expect($code)->toBe(1);
    expect($output)->toContain('Provider resolution failed');
});

it('reports elapsed time in milliseconds on success', function (): void {
    Artisan::call('sealcraft:verify');
    $output = Artisan::output();

    expect($output)->toMatch('/Sealcraft verified: \d+ms/');
});

it('accepts --provider to verify a non-default provider', function (): void {
    config()->set('sealcraft.providers.null_alt', ['driver' => 'null']);

    $code = Artisan::call('sealcraft:verify', ['--provider' => 'null_alt']);

    expect($code)->toBe(0);
    expect(Artisan::output())->toContain('Sealcraft verified');
});
