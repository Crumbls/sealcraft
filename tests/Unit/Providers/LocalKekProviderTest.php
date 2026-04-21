<?php

declare(strict_types=1);

use Crumbls\Sealcraft\Exceptions\DecryptionFailedException;
use Crumbls\Sealcraft\Exceptions\SealcraftException;
use Crumbls\Sealcraft\Providers\LocalKekProvider;
use Crumbls\Sealcraft\Values\EncryptionContext;
use Illuminate\Contracts\Foundation\Application;

beforeEach(function (): void {
    $this->keyPath = sys_get_temp_dir() . '/sealcraft-test-' . bin2hex(random_bytes(6)) . '/kek.key';
    $this->provider = new LocalKekProvider($this->keyPath, $this->app, allowProduction: false);
    $this->ctx = new EncryptionContext('tenant', 42);
});

afterEach(function (): void {
    $directory = dirname($this->keyPath);

    if (is_dir($directory)) {
        foreach (scandir($directory) ?: [] as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }

            @unlink($directory . '/' . $entry);
        }

        @rmdir($directory);
    }
});

it('creates an initial KEK version on first wrap', function (): void {
    $dek = random_bytes(32);
    $wrapped = $this->provider->wrap($dek, $this->ctx);

    expect($wrapped->keyVersion)->toBe('v1');
    expect(file_exists($this->keyPath))->toBeTrue();
    expect(file_exists($this->keyPath . '.v1'))->toBeTrue();
});

it('round-trips a DEK through wrap/unwrap with matching context', function (): void {
    $dek = random_bytes(32);
    $wrapped = $this->provider->wrap($dek, $this->ctx);

    expect($this->provider->unwrap($wrapped, $this->ctx))->toBe($dek);
});

it('fails unwrap when context changes (native AAD)', function (): void {
    $dek = random_bytes(32);
    $wrapped = $this->provider->wrap($dek, $this->ctx);

    expect(fn () => $this->provider->unwrap($wrapped, new EncryptionContext('tenant', 99)))
        ->toThrow(DecryptionFailedException::class);
});

it('rotates to a new KEK version and still unwraps older-version wrapped DEKs', function (): void {
    $dekA = random_bytes(32);
    $wrappedA = $this->provider->wrap($dekA, $this->ctx);

    $this->provider->rotate();

    $dekB = random_bytes(32);
    $wrappedB = $this->provider->wrap($dekB, $this->ctx);

    expect($wrappedA->keyVersion)->toBe('v1');
    expect($wrappedB->keyVersion)->toBe('v2');
    expect($this->provider->unwrap($wrappedA, $this->ctx))->toBe($dekA);
    expect($this->provider->unwrap($wrappedB, $this->ctx))->toBe($dekB);
});

it('can wrap with a pinned version', function (): void {
    $dek = random_bytes(32);
    $this->provider->wrap($dek, $this->ctx);  // creates v1
    $this->provider->rotate();                  // creates v2

    $wrapped = $this->provider->wrapWithVersion($dek, $this->ctx, 'v1');

    expect($wrapped->keyVersion)->toBe('v1');
    expect($this->provider->unwrap($wrapped, $this->ctx))->toBe($dek);
});

it('lists KEK versions in ascending order', function (): void {
    $this->provider->wrap(random_bytes(32), $this->ctx);
    $this->provider->rotate();
    $this->provider->rotate();

    expect($this->provider->listKeyVersions())->toBe(['v1', 'v2', 'v3']);
});

it('refuses to load in production without opt-in', function (): void {
    $prodApp = Mockery::mock(Application::class);
    $prodApp->shouldReceive('environment')->with('production')->andReturnTrue();

    expect(fn () => new LocalKekProvider($this->keyPath, $prodApp, allowProduction: false))
        ->toThrow(SealcraftException::class);

    $prodAppOptIn = Mockery::mock(Application::class);
    $prodAppOptIn->shouldNotReceive('environment');
    $provider = new LocalKekProvider($this->keyPath, $prodAppOptIn, allowProduction: true);

    expect($provider->name())->toBe('local');
});

it('generates a DataKeyPair that unwraps back to plaintext', function (): void {
    $pair = $this->provider->generateDataKey($this->ctx);

    expect(strlen($pair->plaintext))->toBe(32);
    expect($this->provider->unwrap($pair->wrapped, $this->ctx))->toBe($pair->plaintext);
});
