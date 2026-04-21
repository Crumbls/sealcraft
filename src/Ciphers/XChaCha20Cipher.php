<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Ciphers;

use Crumbls\Sealcraft\Contracts\Cipher;
use Crumbls\Sealcraft\Exceptions\DecryptionFailedException;
use Crumbls\Sealcraft\Exceptions\SealcraftException;

/**
 * XChaCha20-Poly1305 field cipher, backed by libsodium.
 *
 * Output format (UTF-8 ASCII string):
 *     xc1:v1:<b64 nonce>:<b64 ciphertext_with_tag>
 *
 * libsodium concatenates the 16-byte Poly1305 tag onto the end of the
 * ciphertext; we store them as one blob to match the library's API.
 *
 * Requires ext-sodium. Apps that don't ship libsodium should stick
 * with the default AesGcmCipher — this class registers itself only
 * when the extension is available.
 */
final class XChaCha20Cipher implements Cipher
{
    public const ID = 'xc1';

    public const FORMAT_VERSION = 'v1';

    public function name(): string
    {
        return 'xchacha20-poly1305';
    }

    public function id(): string
    {
        return self::ID;
    }

    public function keyBytes(): int
    {
        return SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES;
    }

    public function encrypt(string $plaintext, string $dek, string $aad): string
    {
        $this->assertKeyLength($dek);

        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);

        $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
            $plaintext,
            $aad,
            $nonce,
            $dek,
        );

        return self::ID
            . ':' . self::FORMAT_VERSION
            . ':' . base64_encode($nonce)
            . ':' . base64_encode($ciphertext);
    }

    public function decrypt(string $ciphertext, string $dek, string $aad): string
    {
        $this->assertKeyLength($dek);

        $parts = explode(':', $ciphertext, 4);

        if (count($parts) !== 4) {
            throw new DecryptionFailedException('Ciphertext is not in the expected sealcraft format.');
        }

        [$id, $version, $b64Nonce, $b64Body] = $parts;

        if ($id !== self::ID) {
            throw new DecryptionFailedException(
                "Ciphertext cipher id [{$id}] does not match this cipher's id [" . self::ID . '].'
            );
        }

        if ($version !== self::FORMAT_VERSION) {
            throw new DecryptionFailedException("Unsupported ciphertext format version: {$version}");
        }

        $nonce = base64_decode($b64Nonce, true);
        $body = base64_decode($b64Body, true);

        if ($nonce === false || $body === false) {
            throw new DecryptionFailedException('Ciphertext base64 segments are invalid.');
        }

        if (strlen($nonce) !== SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES) {
            throw new DecryptionFailedException('Ciphertext nonce has unexpected length.');
        }

        $plaintext = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
            $body,
            $aad,
            $nonce,
            $dek,
        );

        if ($plaintext === false) {
            throw new DecryptionFailedException('XChaCha20-Poly1305 authentication failed.');
        }

        return $plaintext;
    }

    private function assertKeyLength(string $dek): void
    {
        if (strlen($dek) !== SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES) {
            throw new SealcraftException(
                'XChaCha20-Poly1305 requires a ' . SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES . '-byte DEK.'
            );
        }
    }
}
