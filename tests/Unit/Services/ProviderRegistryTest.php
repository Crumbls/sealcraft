<?php

declare(strict_types=1);

use Crumbls\Sealcraft\Exceptions\SealcraftException;
use Crumbls\Sealcraft\Providers\LocalKekProvider;
use Crumbls\Sealcraft\Providers\NullKekProvider;
use Crumbls\Sealcraft\Services\ProviderRegistry;

beforeEach(function (): void {
    $this->registry = $this->app->make(ProviderRegistry::class);
});

it('resolves the null driver', function (): void {
    $provider = $this->registry->provider('null');

    expect($provider)->toBeInstanceOf(NullKekProvider::class);
});

it('resolves the local driver against storage path fallback', function (): void {
    config()->set('sealcraft.providers.local.key_path', null);

    $provider = $this->registry->provider('local');

    expect($provider)->toBeInstanceOf(LocalKekProvider::class);
});

it('memoizes resolved providers', function (): void {
    $a = $this->registry->provider('null');
    $b = $this->registry->provider('null');

    expect($a)->toBe($b);
});

it('throws for an unknown configured provider', function (): void {
    expect(fn () => $this->registry->provider('does_not_exist'))
        ->toThrow(SealcraftException::class);
});

it('allows custom drivers via extend', function (): void {
    config()->set('sealcraft.providers.custom', ['driver' => 'custom_driver']);
    $this->registry->extend('custom_driver', fn (): NullKekProvider => new NullKekProvider);

    $provider = $this->registry->provider('custom');

    expect($provider)->toBeInstanceOf(NullKekProvider::class);
});
