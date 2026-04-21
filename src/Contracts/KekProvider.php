<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Contracts;

use Crumbls\Sealcraft\Values\EncryptionContext;
use Crumbls\Sealcraft\Values\ProviderCapabilities;
use Crumbls\Sealcraft\Values\WrappedDek;

/**
 * Base KEK provider contract. Every Sealcraft provider implements this
 * interface. Capability interfaces (GeneratesDataKeys, SupportsNativeAad,
 * SupportsKeyVersioning) extend it to declare additional features the
 * KeyManager can take advantage of.
 */
interface KekProvider
{
    /**
     * Wrap a plaintext DEK with the provider's current KEK, binding the
     * encryption context as AAD where the provider supports native AAD.
     * Providers without native AAD may synthesize it at the wrap layer
     * (see Azure Key Vault's synthetic strategy).
     *
     * Must throw KekUnavailableException on transport/auth/throttling
     * failures after retry exhaustion.
     */
    public function wrap(string $plaintextDek, EncryptionContext $ctx): WrappedDek;

    /**
     * Unwrap a previously wrapped DEK. The same encryption context used at
     * wrap time must be provided; a mismatch must result in decryption
     * failure (either because the provider enforces AAD natively or
     * because the synthetic AAD HMAC fails verification).
     */
    public function unwrap(WrappedDek $wrapped, EncryptionContext $ctx): string;

    /**
     * Identifier of the KEK the provider will use for new wrap operations.
     * Format is provider-specific (ARN, resource URI, alias, file hash).
     */
    public function currentKeyId(): string;

    /**
     * Stable identifier for the provider (e.g. 'aws_kms', 'azure_kv').
     * Recorded in the sealcraft_data_keys.provider_name column.
     */
    public function name(): string;

    public function capabilities(): ProviderCapabilities;
}
