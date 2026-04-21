<?php

declare(strict_types=1);

use Crumbls\Sealcraft\Exceptions\DecryptionFailedException;
use Crumbls\Sealcraft\Providers\NullKekProvider;
use Crumbls\Sealcraft\Values\EncryptionContext;

beforeEach(function (): void {
    $this->provider = new NullKekProvider;
    $this->ctx = new EncryptionContext('tenant', 42);
});

it('exposes the expected name and capabilities', function (): void {
    $caps = $this->provider->capabilities();

    expect($this->provider->name())->toBe('null');
    expect($caps->generatesDataKeys)->toBeTrue();
    expect($caps->hasNativeAad)->toBeTrue();
    expect($caps->supportsKeyVersioning)->toBeFalse();
});

it('round-trips a DEK through wrap/unwrap with matching context', function (): void {
    $dek = random_bytes(32);
    $wrapped = $this->provider->wrap($dek, $this->ctx);

    expect($this->provider->unwrap($wrapped, $this->ctx))->toBe($dek);
});

it('fails unwrap on context mismatch', function (): void {
    $dek = random_bytes(32);
    $wrapped = $this->provider->wrap($dek, $this->ctx);

    expect(fn () => $this->provider->unwrap($wrapped, new EncryptionContext('tenant', 99)))
        ->toThrow(DecryptionFailedException::class);
});

it('generates a DataKeyPair with wrapped DEK under matching context', function (): void {
    $pair = $this->provider->generateDataKey($this->ctx);

    expect(strlen($pair->plaintext))->toBe(32);
    expect($this->provider->unwrap($pair->wrapped, $this->ctx))->toBe($pair->plaintext);
});
