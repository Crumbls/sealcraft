<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Providers;

use Aws\Exception\AwsException;
use Aws\Kms\KmsClient;
use Crumbls\Sealcraft\Contracts\GeneratesDataKeys;
use Crumbls\Sealcraft\Contracts\SupportsKeyVersioning;
use Crumbls\Sealcraft\Contracts\SupportsNativeAad;
use Crumbls\Sealcraft\Exceptions\DecryptionFailedException;
use Crumbls\Sealcraft\Exceptions\KekUnavailableException;
use Crumbls\Sealcraft\Values\DataKeyPair;
use Crumbls\Sealcraft\Values\EncryptionContext;
use Crumbls\Sealcraft\Values\ProviderCapabilities;
use Crumbls\Sealcraft\Values\WrappedDek;
use Throwable;

/**
 * AWS KMS backed KEK provider.
 *
 * Uses GenerateDataKey for single-round-trip DEK creation (the AWS-
 * native pattern), and Decrypt for unwrapping. The EncryptionContext
 * produced by sealcraft's EncryptionContext::toAwsEncryptionContext()
 * is passed as AWS's native EncryptionContext parameter, so AAD is
 * enforced by KMS itself — a cross-context unwrap fails at the
 * service layer, not just at our cipher.
 *
 * Supports key aliases ("alias/my-kek"), key IDs ("abc-123..."), or
 * full ARNs. KEK versions rotate via AWS's built-in key rotation; the
 * KMS Decrypt call transparently handles older key versions without
 * needing an explicit version parameter.
 */
final class AwsKmsKekProvider implements GeneratesDataKeys, SupportsKeyVersioning, SupportsNativeAad
{
    public const NAME = 'aws_kms';

    private const MAX_ATTEMPTS = 3;

    public function __construct(
        private readonly KmsClient $client,
        private readonly string $keyId,
    ) {}

    public function name(): string
    {
        return self::NAME;
    }

    public function currentKeyId(): string
    {
        return $this->keyId;
    }

    public function capabilities(): ProviderCapabilities
    {
        return new ProviderCapabilities(
            generatesDataKeys: true,
            hasNativeAad: true,
            supportsKeyVersioning: true,
            aadStrategy: ProviderCapabilities::AAD_NATIVE,
        );
    }

    public function generateDataKey(EncryptionContext $ctx, int $bytes = 32): DataKeyPair
    {
        $result = $this->retrying(fn () => $this->client->generateDataKey([
            'KeyId' => $this->keyId,
            'NumberOfBytes' => $bytes,
            'EncryptionContext' => $ctx->toAwsEncryptionContext(),
        ]));

        /** @var string $plaintext */
        $plaintext = (string) $result['Plaintext'];
        /** @var string $ciphertext */
        $ciphertext = (string) $result['CiphertextBlob'];
        /** @var string $resolvedKeyId */
        $resolvedKeyId = (string) ($result['KeyId'] ?? $this->keyId);

        return new DataKeyPair(
            plaintext: $plaintext,
            wrapped: new WrappedDek(
                ciphertext: $ciphertext,
                providerName: self::NAME,
                keyId: $resolvedKeyId,
                keyVersion: null,
                aadStrategy: ProviderCapabilities::AAD_NATIVE,
            ),
        );
    }

    public function wrap(string $plaintextDek, EncryptionContext $ctx): WrappedDek
    {
        $result = $this->retrying(fn () => $this->client->encrypt([
            'KeyId' => $this->keyId,
            'Plaintext' => $plaintextDek,
            'EncryptionContext' => $ctx->toAwsEncryptionContext(),
        ]));

        return new WrappedDek(
            ciphertext: (string) $result['CiphertextBlob'],
            providerName: self::NAME,
            keyId: (string) ($result['KeyId'] ?? $this->keyId),
            keyVersion: null,
            aadStrategy: ProviderCapabilities::AAD_NATIVE,
        );
    }

    public function unwrap(WrappedDek $wrapped, EncryptionContext $ctx): string
    {
        try {
            $result = $this->retrying(fn () => $this->client->decrypt([
                'CiphertextBlob' => $wrapped->ciphertext,
                'EncryptionContext' => $ctx->toAwsEncryptionContext(),
            ]));
        } catch (AwsException $e) {
            if ($this->isAuthenticationError($e)) {
                throw new DecryptionFailedException('AWS KMS refused to unwrap DEK: context mismatch or tampering.');
            }

            throw new KekUnavailableException('AWS KMS unwrap failed: ' . $e->getAwsErrorMessage(), 0, $e);
        }

        return (string) $result['Plaintext'];
    }

    /**
     * @return array<int, string>
     */
    public function listKeyVersions(): array
    {
        // AWS KMS does not expose a direct version list through a
        // stable public API; operators rotate KEKs by calling
        // EnableKeyRotation on the CMK, after which Decrypt transparently
        // picks the right backing key. We return an empty array to
        // indicate no caller-visible versions.
        return [];
    }

    public function wrapWithVersion(string $plaintextDek, EncryptionContext $ctx, string $version): WrappedDek
    {
        // AWS KMS cannot pin to a specific backing key version for new
        // wrap operations; this is a service-side rotation detail.
        // Fall through to normal wrap.
        return $this->wrap($plaintextDek, $ctx);
    }

    /**
     * @template T
     *
     * @param  callable(): T  $operation
     * @return T
     */
    private function retrying(callable $operation): mixed
    {
        $attempt = 0;

        while (true) {
            $attempt++;

            try {
                return $operation();
            } catch (AwsException $e) {
                if ($attempt >= self::MAX_ATTEMPTS || ! $this->isRetryable($e)) {
                    throw $e;
                }

                usleep((int) (random_int(50, 150) * 1000 * (2 ** ($attempt - 1))));
            } catch (Throwable $e) {
                throw new KekUnavailableException('AWS KMS client error: ' . $e->getMessage(), 0, $e);
            }
        }
    }

    private function isRetryable(AwsException $e): bool
    {
        $code = (string) $e->getAwsErrorCode();

        return in_array($code, [
            'ThrottlingException',
            'RequestLimitExceeded',
            'KMSInternalException',
            'DependencyTimeoutException',
            'InternalFailure',
        ], true);
    }

    private function isAuthenticationError(AwsException $e): bool
    {
        $code = (string) $e->getAwsErrorCode();

        return in_array($code, [
            'InvalidCiphertextException',
            'IncorrectKeyException',
        ], true);
    }
}
