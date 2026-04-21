<?php

declare(strict_types=1);

use Crumbls\Sealcraft\Values\ProviderCapabilities;

it('accepts all three valid AAD strategies', function (string $strategy): void {
    $caps = new ProviderCapabilities(false, false, false, $strategy);

    expect($caps->aadStrategy)->toBe($strategy);
})->with([
    ProviderCapabilities::AAD_NATIVE,
    ProviderCapabilities::AAD_SYNTHETIC,
    ProviderCapabilities::AAD_NONE,
]);

it('rejects unknown AAD strategies', function (): void {
    expect(fn () => new ProviderCapabilities(false, false, false, 'bogus'))
        ->toThrow(InvalidArgumentException::class);
});
