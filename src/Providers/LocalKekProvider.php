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
use Illuminate\Contracts\Foundation\Application;

/**
 * File-backed KEK provider for dev/test parity with cloud providers.
 *
 * Implements every capability interface so tests exercise the same
 * KeyManager branches as AWS/GCP/Azure. The KEK is stored as raw 32
 * bytes at the configured key_path; versions are named "v1", "v2",
 * "v3" and live at <key_path>.<version>. The base file is a symlink
 * (or copy) of the current active version.
 *
 * Refuses to load in production unless allow_production is true.
 */
final class LocalKekProvider implements GeneratesDataKeys, SupportsKeyVersioning, SupportsNativeAad
{
    public const NAME = 'local';

    private const KEY_BYTES = 32;

    private const IV_BYTES = 12;

    private const TAG_BYTES = 16;

    private const CIPHER = 'aes-256-gcm';

    public function __construct(
        private readonly string $keyPath,
        private readonly Application $app,
        private readonly bool $allowProduction = false,
    ) {
        $this->guardProduction();
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function currentKeyId(): string
    {
        return $this->currentVersion();
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
        return $this->wrapWithVersion($plaintextDek, $ctx, $this->currentVersion());
    }

    public function wrapWithVersion(string $plaintextDek, EncryptionContext $ctx, string $version): WrappedDek
    {
        $kek = $this->loadKekVersion($version);

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
            throw new SealcraftException('LocalKekProvider wrap failed.');
        }

        return new WrappedDek(
            ciphertext: $iv . $tag . $ciphertext,
            providerName: self::NAME,
            keyId: 'local-kek',
            keyVersion: $version,
            aadStrategy: ProviderCapabilities::AAD_NATIVE,
            metadata: [],
        );
    }

    public function unwrap(WrappedDek $wrapped, EncryptionContext $ctx): string
    {
        $version = $wrapped->keyVersion ?? $this->currentVersion();
        $kek = $this->loadKekVersion($version);

        $blob = $wrapped->ciphertext;
        $minLength = self::IV_BYTES + self::TAG_BYTES;

        if (strlen($blob) < $minLength + 1) {
            throw new DecryptionFailedException('LocalKekProvider wrapped DEK is too short.');
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
            throw new DecryptionFailedException('LocalKekProvider authentication failed.');
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
        $directory = dirname($this->keyPath);
        $basename = basename($this->keyPath);

        if (! is_dir($directory)) {
            return [];
        }

        $entries = scandir($directory);

        if ($entries === false) {
            return [];
        }

        $versions = [];

        foreach ($entries as $entry) {
            if (preg_match('/^' . preg_quote($basename, '/') . '\.(v\d+)$/', $entry, $m) === 1) {
                $versions[] = $m[1];
            }
        }

        usort($versions, function (string $a, string $b): int {
            return (int) substr($a, 1) <=> (int) substr($b, 1);
        });

        return $versions;
    }

    public function rotate(): string
    {
        $versions = $this->listKeyVersions();
        $next = 'v' . (count($versions) === 0 ? 1 : ((int) substr(end($versions), 1)) + 1);

        $key = random_bytes(self::KEY_BYTES);
        $versionPath = $this->keyPath . '.' . $next;

        $this->ensureDirectory();

        if (file_put_contents($versionPath, $key, LOCK_EX) === false) {
            throw new KekUnavailableException("Unable to write KEK version to {$versionPath}");
        }

        chmod($versionPath, 0600);

        if (@file_put_contents($this->keyPath, $next, LOCK_EX) === false) {
            throw new KekUnavailableException("Unable to update KEK pointer at {$this->keyPath}");
        }

        chmod($this->keyPath, 0600);

        return $next;
    }

    private function currentVersion(): string
    {
        $this->ensureDirectory();

        if (! file_exists($this->keyPath)) {
            return $this->rotate();
        }

        $pointer = file_get_contents($this->keyPath);

        if ($pointer === false || $pointer === '') {
            throw new KekUnavailableException("Empty KEK pointer at {$this->keyPath}");
        }

        return trim($pointer);
    }

    private function loadKekVersion(string $version): string
    {
        $path = $this->keyPath . '.' . $version;

        if (! file_exists($path)) {
            throw new KekUnavailableException("KEK version {$version} not found at {$path}");
        }

        $bytes = file_get_contents($path);

        if ($bytes === false || strlen($bytes) !== self::KEY_BYTES) {
            throw new KekUnavailableException("KEK version {$version} is corrupt or wrong size.");
        }

        return $bytes;
    }

    private function ensureDirectory(): void
    {
        $directory = dirname($this->keyPath);

        if (! is_dir($directory) && ! @mkdir($directory, 0700, true) && ! is_dir($directory)) {
            throw new KekUnavailableException("Cannot create KEK directory: {$directory}");
        }
    }

    private function guardProduction(): void
    {
        if ($this->allowProduction) {
            return;
        }

        if ($this->app->environment('production')) {
            throw new SealcraftException(
                'LocalKekProvider is disabled in production. Set providers.local.allow_production to true only for narrow, audited scenarios.'
            );
        }
    }
}
