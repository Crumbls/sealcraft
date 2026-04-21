<?php

declare(strict_types=1);

use Crumbls\Sealcraft\Exceptions\DecryptionFailedException;
use Crumbls\Sealcraft\Exceptions\InvalidContextException;
use Crumbls\Sealcraft\Exceptions\KekUnavailableException;
use Crumbls\Sealcraft\Exceptions\SealcraftException;

it('roots every package exception at SealcraftException', function (): void {
    expect(is_subclass_of(KekUnavailableException::class, SealcraftException::class))->toBeTrue();
    expect(is_subclass_of(InvalidContextException::class, SealcraftException::class))->toBeTrue();
    expect(is_subclass_of(DecryptionFailedException::class, SealcraftException::class))->toBeTrue();
});

it('extends RuntimeException for framework compatibility', function (): void {
    expect(is_subclass_of(SealcraftException::class, RuntimeException::class))->toBeTrue();
});
