<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Providers;

use Crumbls\Sealcraft\Contracts\GeneratesDataKeys;
use Crumbls\Sealcraft\Contracts\SupportsKeyVersioning;
use Crumbls\Sealcraft\Contracts\SupportsNativeAad;
use Crumbls\Sealcraft\Exceptions\DecryptionFailedException;
use Crumbls\Sealcraft\Exceptions\KekUnavailableException;
use Crumbls\Sealcraft\Exceptions\SealcraftException;
use Crumbls\Sealcraft\Values\DataKeyPair;
use Crumbls\Sealcraft\Values\EncryptionContext;
use Crumbls\Sealcraft\Values\ProviderCapabilities;
use Crumbls\Sealcraft\Values\WrappedDek;

/**
 * KEK provider that reads its wrapping-key bytes directly from config
 * (typically populated by a CI/CD pipeline that extracted the secret
 * from a vault, wrote it to env, and loaded it into config at boot).
 *
 * Semantically equivalent to LocalKekProvider but without the file
 * dependency. Supports multiple KEK versions side-by-side for
 * non-destructive rotation: add a new version to config, flip the
 * current pointer, run `sealcraft:rotate-kek` to rewrap DataKeys
 * under the new version, then remove the old version from config on
 * the next deploy.
 *
 * Security posture note: the KEK plaintext lives in your application
 * process memory, env file, and wherever your pipeline cached it. A
 * compromise of any of those vectors exfiltrates the KEK. Prefer a
 * runtime KMS provider (aws_kms, azure_kv, gcp_kms, vault_transit)
 * when the infrastructure supports it.
 */
final class ConfigKekProvider implements GeneratesDataKeys, SupportsKeyVersioning, SupportsNativeAad
{
    public const NAME = 'config';

    public const KEY_BYTES = 32;

    private const IV_BYTES = 12;

    private const TAG_BYTES = 16;

    private const CIPHER = 'aes-256-gcm';

    /**
     * @param  array<string, string>  $versionBytes  Map of version label => raw 32-byte KEK
     */
    public function __construct(
        private readonly array $versionBytes,
        private readonly string $currentVersion,
    ) {
        if ($this->versionBytes === []) {
            throw new SealcraftException('ConfigKekProvider requires at least one version.');
        }

        if (! isset($this->versionBytes[$this->currentVersion])) {
            throw new SealcraftException(
                "ConfigKekProvider current_version [{$this->currentVersion}] is not present in configured versions."
            );
        }

        foreach ($this->versionBytes as $version => $bytes) {
            if (strlen($bytes) !== self::KEY_BYTES) {
                throw new SealcraftException(
                    "ConfigKekProvider version [{$version}] has wrong key length (" . strlen($bytes) . ' bytes; need ' . self::KEY_BYTES . ').'
                );
            }
        }
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function currentKeyId(): string
    {
        return $this->currentVersion;
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

    public function wrap(string $plaintextDek, EncryptionContext $ctx): WrappedDek
    {
        return $this->wrapWithVersion($plaintextDek, $ctx, $this->currentVersion);
    }

    public function wrapWithVersion(string $plaintextDek, EncryptionContext $ctx, string $version): WrappedDek
    {
        $kek = $this->versionBytes[$version] ?? null;

        if ($kek === null) {
            throw new KekUnavailableException("ConfigKekProvider version [{$version}] is not configured.");
        }

        $iv = random_bytes(self::IV_BYTES);
        $tag = '';

        $ciphertext = openssl_encrypt(
            $plaintextDek,
            self::CIPHER,
            $kek,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $ctx->toCanonicalBytes(),
            self::TAG_BYTES,
        );

        if ($ciphertext === false || strlen($tag) !== self::TAG_BYTES) {
            throw new SealcraftException('ConfigKekProvider wrap failed.');
        }

        return new WrappedDek(
            ciphertext: $iv . $tag . $ciphertext,
            providerName: self::NAME,
            keyId: 'config-kek',
            keyVersion: $version,
            aadStrategy: ProviderCapabilities::AAD_NATIVE,
        );
    }

    public function unwrap(WrappedDek $wrapped, EncryptionContext $ctx): string
    {
        $version = $wrapped->keyVersion ?? $this->currentVersion;
        $kek = $this->versionBytes[$version] ?? null;

        if ($kek === null) {
            throw new KekUnavailableException(
                "ConfigKekProvider cannot unwrap: version [{$version}] is not configured (removed during rotation?)."
            );
        }

        $blob = $wrapped->ciphertext;
        $minLength = self::IV_BYTES + self::TAG_BYTES;

        if (strlen($blob) < $minLength + 1) {
            throw new DecryptionFailedException('ConfigKekProvider wrapped DEK is too short.');
        }

        $iv = substr($blob, 0, self::IV_BYTES);
        $tag = substr($blob, self::IV_BYTES, self::TAG_BYTES);
        $body = substr($blob, $minLength);

        $plaintext = openssl_decrypt(
            $body,
            self::CIPHER,
            $kek,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $ctx->toCanonicalBytes(),
        );

        if ($plaintext === false) {
            throw new DecryptionFailedException('ConfigKekProvider authentication failed.');
        }

        return $plaintext;
    }

    public function generateDataKey(EncryptionContext $ctx, int $bytes = 32): DataKeyPair
    {
        $plaintext = random_bytes($bytes);

        return new DataKeyPair($plaintext, $this->wrap($plaintext, $ctx));
    }

    /**
     * @return array<int, string>
     */
    public function listKeyVersions(): array
    {
        $versions = array_keys($this->versionBytes);
        sort($versions, SORT_NATURAL);

        return $versions;
    }
}
