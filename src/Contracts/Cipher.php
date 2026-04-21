<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Contracts;

/**
 * Symmetric AEAD cipher used at the field layer. The DEK passed in is
 * the plaintext 32-byte key produced by KeyManager; the AAD bytes are
 * the canonical form of the EncryptionContext.
 *
 * Implementations must produce a self-describing ciphertext string
 * beginning with a version prefix (e.g. "v1:") so ciphers can evolve
 * without breaking stored data.
 */
interface Cipher
{
    /**
     * Stable identifier (e.g. 'aes-256-gcm', 'xchacha20-poly1305').
     */
    public function name(): string;

    /**
     * Short (3-char) cipher identifier embedded in every ciphertext
     * this cipher produces, so the reader can dispatch to the correct
     * cipher implementation without consulting the DataKey row.
     *
     * Reserved IDs:
     *   'ag1' -> AES-256-GCM
     *   'xc1' -> XChaCha20-Poly1305
     *
     * Custom cipher drivers must pick an ID that doesn't collide.
     */
    public function id(): string;

    /**
     * Required DEK length in bytes.
     */
    public function keyBytes(): int;

    /**
     * Encrypt plaintext with DEK + AAD. AAD binding is mandatory — a
     * mismatch at decrypt time must fail authentication.
     */
    public function encrypt(string $plaintext, string $dek, string $aad): string;

    /**
     * Decrypt ciphertext with DEK + AAD. Must throw
     * DecryptionFailedException on any authentication failure.
     */
    public function decrypt(string $ciphertext, string $dek, string $aad): string;
}
