<?php

declare(strict_types=1);

use Crumbls\Sealcraft\Exceptions\DecryptionFailedException;
use Crumbls\Sealcraft\Exceptions\KekUnavailableException;
use Crumbls\Sealcraft\Exceptions\SealcraftException;
use Crumbls\Sealcraft\Providers\ConfigKekProvider;
use Crumbls\Sealcraft\Services\ProviderRegistry;
use Crumbls\Sealcraft\Values\EncryptionContext;

beforeEach(function (): void {
    $this->ctx = new EncryptionContext('tenant', 42);
    $this->v1 = random_bytes(32);
    $this->v2 = random_bytes(32);
});

it('reports expected name and capabilities', function (): void {
    $provider = new ConfigKekProvider(['v1' => $this->v1], 'v1');
    $caps = $provider->capabilities();

    expect($provider->name())->toBe('config');
    expect($provider->currentKeyId())->toBe('v1');
    expect($caps->generatesDataKeys)->toBeTrue();
    expect($caps->hasNativeAad)->toBeTrue();
    expect($caps->supportsKeyVersioning)->toBeTrue();
    expect($caps->aadStrategy)->toBe('native');
});

it('round-trips a DEK through wrap/unwrap with matching context', function (): void {
    $provider = new ConfigKekProvider(['v1' => $this->v1], 'v1');
    $dek = random_bytes(32);

    $wrapped = $provider->wrap($dek, $this->ctx);
    expect($provider->unwrap($wrapped, $this->ctx))->toBe($dek);
});

it('fails unwrap on context mismatch (native AAD)', function (): void {
    $provider = new ConfigKekProvider(['v1' => $this->v1], 'v1');
    $dek = random_bytes(32);
    $wrapped = $provider->wrap($dek, $this->ctx);

    expect(fn () => $provider->unwrap($wrapped, new EncryptionContext('tenant', 99)))
        ->toThrow(DecryptionFailedException::class);
});

it('supports multiple KEK versions side by side', function (): void {
    $provider = new ConfigKekProvider(['v1' => $this->v1, 'v2' => $this->v2], 'v2');

    $dek = random_bytes(32);

    $wrappedV1 = $provider->wrapWithVersion($dek, $this->ctx, 'v1');
    $wrappedV2 = $provider->wrap($dek, $this->ctx);  // uses current = v2

    expect($wrappedV1->keyVersion)->toBe('v1');
    expect($wrappedV2->keyVersion)->toBe('v2');
    expect($provider->unwrap($wrappedV1, $this->ctx))->toBe($dek);
    expect($provider->unwrap($wrappedV2, $this->ctx))->toBe($dek);
});

it('refuses unwrap when the stored version is no longer configured', function (): void {
    $writer = new ConfigKekProvider(['v1' => $this->v1, 'v2' => $this->v2], 'v2');
    $dek = random_bytes(32);
    $wrapped = $writer->wrapWithVersion($dek, $this->ctx, 'v1');

    // Simulate a redeploy where v1 has been removed from env.
    $readerWithoutV1 = new ConfigKekProvider(['v2' => $this->v2], 'v2');

    expect(fn () => $readerWithoutV1->unwrap($wrapped, $this->ctx))
        ->toThrow(KekUnavailableException::class);
});

it('rejects construction with no versions', function (): void {
    expect(fn () => new ConfigKekProvider([], 'v1'))
        ->toThrow(SealcraftException::class);
});

it('rejects construction when current version is missing', function (): void {
    expect(fn () => new ConfigKekProvider(['v1' => $this->v1], 'v9'))
        ->toThrow(SealcraftException::class);
});

it('rejects construction with wrong-length key bytes', function (): void {
    expect(fn () => new ConfigKekProvider(['v1' => random_bytes(16)], 'v1'))
        ->toThrow(SealcraftException::class);
});

it('lists versions in sorted order', function (): void {
    $provider = new ConfigKekProvider([
        'v2' => $this->v2,
        'v1' => $this->v1,
        'v10' => random_bytes(32),
    ], 'v10');

    expect($provider->listKeyVersions())->toBe(['v1', 'v2', 'v10']);
});

it('generates a DataKeyPair that round-trips', function (): void {
    $provider = new ConfigKekProvider(['v1' => $this->v1], 'v1');
    $pair = $provider->generateDataKey($this->ctx);

    expect(strlen($pair->plaintext))->toBe(32);
    expect($provider->unwrap($pair->wrapped, $this->ctx))->toBe($pair->plaintext);
});

it('is resolvable via the ProviderRegistry config driver', function (): void {
    config()->set('sealcraft.providers.config', [
        'driver' => 'config',
        'current_version' => 'v1',
        'versions' => [
            'v1' => base64_encode($this->v1),
        ],
    ]);

    $provider = $this->app->make(ProviderRegistry::class)->provider('config');

    expect($provider)->toBeInstanceOf(ConfigKekProvider::class);

    $dek = random_bytes(32);
    $wrapped = $provider->wrap($dek, $this->ctx);
    expect($provider->unwrap($wrapped, $this->ctx))->toBe($dek);
});

it('rejects invalid base64 via the registry factory', function (): void {
    config()->set('sealcraft.providers.config', [
        'driver' => 'config',
        'current_version' => 'v1',
        'versions' => ['v1' => 'not-valid-base64!!!'],
    ]);

    expect(fn () => $this->app->make(ProviderRegistry::class)->provider('config'))
        ->toThrow(SealcraftException::class);
});

it('rejects wrong-length bytes via the registry factory', function (): void {
    config()->set('sealcraft.providers.config', [
        'driver' => 'config',
        'current_version' => 'v1',
        'versions' => ['v1' => base64_encode(random_bytes(16))],
    ]);

    expect(fn () => $this->app->make(ProviderRegistry::class)->provider('config'))
        ->toThrow(SealcraftException::class);
});

it('uses the first defined version when no current_version is provided', function (): void {
    $wrappedRawV1 = base64_encode($this->v1);

    config()->set('sealcraft.providers.config', [
        'driver' => 'config',
        'versions' => ['v1' => $wrappedRawV1],
    ]);

    $provider = $this->app->make(ProviderRegistry::class)->provider('config');

    expect($provider->currentKeyId())->toBe('v1');
});

it('silently skips empty version slots so unused env vars do not blow up', function (): void {
    config()->set('sealcraft.providers.config', [
        'driver' => 'config',
        'current_version' => 'v1',
        'versions' => [
            'v1' => base64_encode($this->v1),
            'v2' => '',       // unset env var — skipped
            'v3' => null,     // null too
        ],
    ]);

    $provider = $this->app->make(ProviderRegistry::class)->provider('config');

    expect($provider->listKeyVersions())->toBe(['v1']);
});
