<?php

declare(strict_types=1);

use Crumbls\Sealcraft\Exceptions\SealcraftException;
use Crumbls\Sealcraft\Values\WrappedDek;

it('round-trips through storage string form', function (): void {
    $original = new WrappedDek(
        ciphertext: random_bytes(64),
        providerName: 'aws_kms',
        keyId: 'arn:aws:kms:us-east-1:000000000000:key/abc',
        keyVersion: 'v4',
        aadStrategy: 'native',
        metadata: ['foo' => 'bar'],
    );

    $restored = WrappedDek::fromStorageString($original->toStorageString());

    expect($restored->ciphertext)->toBe($original->ciphertext);
    expect($restored->providerName)->toBe($original->providerName);
    expect($restored->keyId)->toBe($original->keyId);
    expect($restored->keyVersion)->toBe($original->keyVersion);
    expect($restored->aadStrategy)->toBe($original->aadStrategy);
    expect($restored->metadata)->toBe($original->metadata);
});

it('handles null keyVersion and empty metadata', function (): void {
    $original = new WrappedDek(
        ciphertext: 'abc',
        providerName: 'null',
        keyId: 'null-kek',
        keyVersion: null,
        aadStrategy: 'native',
    );

    $restored = WrappedDek::fromStorageString($original->toStorageString());

    expect($restored->keyVersion)->toBeNull();
    expect($restored->metadata)->toBe([]);
});

it('produces a storage string beginning with sc1:', function (): void {
    $wrapped = new WrappedDek('x', 'null', 'null-kek', null, 'native');

    expect($wrapped->toStorageString())->toStartWith('sc1:');
});

it('rejects malformed storage strings', function (): void {
    expect(fn () => WrappedDek::fromStorageString('not-a-valid-string'))
        ->toThrow(SealcraftException::class);
});

it('rejects unsupported storage version prefixes', function (): void {
    expect(fn () => WrappedDek::fromStorageString('sc9:header:body'))
        ->toThrow(SealcraftException::class);
});

it('rejects headers missing required fields', function (): void {
    $bad = 'sc1:' . rtrim(strtr(base64_encode('{"provider":"x"}'), '+/', '-_'), '=') . ':' . base64_encode('body');

    expect(fn () => WrappedDek::fromStorageString($bad))->toThrow(SealcraftException::class);
});
