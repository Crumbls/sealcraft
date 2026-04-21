<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Ciphers;

use Crumbls\Sealcraft\Contracts\Cipher;
use Crumbls\Sealcraft\Exceptions\DecryptionFailedException;
use Crumbls\Sealcraft\Exceptions\SealcraftException;

/**
 * AES-256-GCM field cipher.
 *
 * Output format (UTF-8 ASCII string):
 *     ag1:v1:<b64 iv>:<b64 tag>:<b64 ciphertext>
 *
 * "ag1" identifies this cipher so the reader can dispatch without
 * consulting the DataKey row. "v1" is this cipher's internal format
 * version, independent of the ID — lets us evolve the on-disk shape
 * (e.g. different IV/tag sizes) without changing the dispatch key.
 */
final class AesGcmCipher implements Cipher
{
    public const ID = 'ag1';

    public const FORMAT_VERSION = 'v1';

    private const KEY_BYTES = 32;

    private const IV_BYTES = 12;

    private const TAG_BYTES = 16;

    private const OPENSSL_CIPHER = 'aes-256-gcm';

    public function name(): string
    {
        return 'aes-256-gcm';
    }

    public function id(): string
    {
        return self::ID;
    }

    public function keyBytes(): int
    {
        return self::KEY_BYTES;
    }

    public function encrypt(string $plaintext, string $dek, string $aad): string
    {
        $this->assertKeyLength($dek);

        $iv = random_bytes(self::IV_BYTES);
        $tag = '';

        $ciphertext = openssl_encrypt(
            $plaintext,
            self::OPENSSL_CIPHER,
            $dek,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $aad,
            self::TAG_BYTES,
        );

        if ($ciphertext === false || strlen($tag) !== self::TAG_BYTES) {
            throw new SealcraftException('AES-GCM encryption failed.');
        }

        return self::ID
            . ':' . self::FORMAT_VERSION
            . ':' . base64_encode($iv)
            . ':' . base64_encode($tag)
            . ':' . base64_encode($ciphertext);
    }

    public function decrypt(string $ciphertext, string $dek, string $aad): string
    {
        $this->assertKeyLength($dek);

        $parts = explode(':', $ciphertext, 5);

        if (count($parts) !== 5) {
            throw new DecryptionFailedException('Ciphertext is not in the expected sealcraft format.');
        }

        [$id, $version, $b64Iv, $b64Tag, $b64Body] = $parts;

        if ($id !== self::ID) {
            throw new DecryptionFailedException(
                "Ciphertext cipher id [{$id}] does not match this cipher's id [" . self::ID . '].'
            );
        }

        if ($version !== self::FORMAT_VERSION) {
            throw new DecryptionFailedException("Unsupported ciphertext format version: {$version}");
        }

        $iv = base64_decode($b64Iv, true);
        $tag = base64_decode($b64Tag, true);
        $body = base64_decode($b64Body, true);

        if ($iv === false || $tag === false || $body === false) {
            throw new DecryptionFailedException('Ciphertext base64 segments are invalid.');
        }

        if (strlen($iv) !== self::IV_BYTES || strlen($tag) !== self::TAG_BYTES) {
            throw new DecryptionFailedException('Ciphertext IV or tag has unexpected length.');
        }

        $plaintext = openssl_decrypt(
            $body,
            self::OPENSSL_CIPHER,
            $dek,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            $aad,
        );

        if ($plaintext === false) {
            throw new DecryptionFailedException('AES-GCM authentication failed.');
        }

        return $plaintext;
    }

    private function assertKeyLength(string $dek): void
    {
        if (strlen($dek) !== self::KEY_BYTES) {
            throw new SealcraftException('AES-GCM requires a 32-byte DEK.');
        }
    }
}
