<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Providers;

use Crumbls\Sealcraft\Contracts\GeneratesDataKeys;
use Crumbls\Sealcraft\Contracts\SupportsNativeAad;
use Crumbls\Sealcraft\Exceptions\DecryptionFailedException;
use Crumbls\Sealcraft\Values\DataKeyPair;
use Crumbls\Sealcraft\Values\EncryptionContext;
use Crumbls\Sealcraft\Values\ProviderCapabilities;
use Crumbls\Sealcraft\Values\WrappedDek;

/**
 * Passthrough KEK provider for unit tests. Wraps a DEK by storing it
 * verbatim (base64) and AAD-binds via a stored hash so mismatches are
 * detectable by tests.
 *
 * Not for any real use. Must never be configured outside automated
 * testing.
 */
final class NullKekProvider implements GeneratesDataKeys, SupportsNativeAad
{
    public const NAME = 'null';

    private const KEY_ID = 'null-kek';

    public function name(): string
    {
        return self::NAME;
    }

    public function currentKeyId(): string
    {
        return self::KEY_ID;
    }

    public function capabilities(): ProviderCapabilities
    {
        return new ProviderCapabilities(
            generatesDataKeys: true,
            hasNativeAad: true,
            supportsKeyVersioning: false,
            aadStrategy: ProviderCapabilities::AAD_NATIVE,
        );
    }

    public function wrap(string $plaintextDek, EncryptionContext $ctx): WrappedDek
    {
        return new WrappedDek(
            ciphertext: $plaintextDek,
            providerName: self::NAME,
            keyId: self::KEY_ID,
            keyVersion: null,
            aadStrategy: ProviderCapabilities::AAD_NATIVE,
            metadata: ['aad_hash' => $ctx->toCanonicalHash()],
        );
    }

    public function unwrap(WrappedDek $wrapped, EncryptionContext $ctx): string
    {
        $expected = $wrapped->metadata['aad_hash'] ?? null;

        if (! is_string($expected) || ! hash_equals($expected, $ctx->toCanonicalHash())) {
            throw new DecryptionFailedException(
                'NullKekProvider AAD mismatch.'
            );
        }

        return $wrapped->ciphertext;
    }

    public function generateDataKey(EncryptionContext $ctx, int $bytes = 32): DataKeyPair
    {
        $plaintext = random_bytes($bytes);

        return new DataKeyPair($plaintext, $this->wrap($plaintext, $ctx));
    }
}
