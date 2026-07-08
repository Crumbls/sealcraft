<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Services;

use Crumbls\Sealcraft\Casts\Encrypted;
use Crumbls\Sealcraft\Casts\EncryptedJson;
use Crumbls\Sealcraft\Contracts\Cipher;
use Crumbls\Sealcraft\Exceptions\DecryptionFailedException;
use Crumbls\Sealcraft\Exceptions\SealcraftException;

final class EncryptedPayloadRewriter
{
    public function __construct(
        private readonly CipherRegistry $ciphers,
    ) {}

    public function reencrypt(
        string $castDriver,
        mixed $stored,
        string $oldDek,
        string $oldAad,
        Cipher $newCipher,
        string $newDek,
        string $newAad,
        bool $preferNewContext = false,
    ): mixed {
        if ($stored === null) {
            return null;
        }

        if ($castDriver === Encrypted::class) {
            return $this->reencryptScalar(
                stored: (string) $stored,
                oldDek: $oldDek,
                oldAad: $oldAad,
                newCipher: $newCipher,
                newDek: $newDek,
                newAad: $newAad,
                preferNewContext: $preferNewContext,
            );
        }

        if ($castDriver === EncryptedJson::class) {
            return $this->reencryptJson(
                stored: (string) $stored,
                oldDek: $oldDek,
                oldAad: $oldAad,
                newCipher: $newCipher,
                newDek: $newDek,
                newAad: $newAad,
                preferNewContext: $preferNewContext,
            );
        }

        throw new SealcraftException("Unsupported Sealcraft cast driver [{$castDriver}].");
    }

    private function reencryptScalar(
        string $stored,
        string $oldDek,
        string $oldAad,
        Cipher $newCipher,
        string $newDek,
        string $newAad,
        bool $preferNewContext,
    ): string {
        $plaintext = $this->decryptEnvelope(
            stored: $stored,
            oldDek: $oldDek,
            oldAad: $oldAad,
            newDek: $newDek,
            newAad: $newAad,
            preferNewContext: $preferNewContext,
        );

        return $newCipher->encrypt($plaintext, $newDek, $newAad);
    }

    private function reencryptJson(
        string $stored,
        string $oldDek,
        string $oldAad,
        Cipher $newCipher,
        string $newDek,
        string $newAad,
        bool $preferNewContext,
    ): string {
        $decoded = json_decode($stored, associative: true);

        if (! is_array($decoded)) {
            throw new SealcraftException('EncryptedJson column does not contain valid JSON.');
        }

        $rewritten = $this->walkJson(
            tree: $decoded,
            oldDek: $oldDek,
            oldAad: $oldAad,
            newCipher: $newCipher,
            newDek: $newDek,
            newAad: $newAad,
            preferNewContext: $preferNewContext,
        );

        return (string) json_encode($rewritten);
    }

    /**
     * @param  array<int|string, mixed>  $tree
     * @return array<int|string, mixed>
     */
    private function walkJson(
        array $tree,
        string $oldDek,
        string $oldAad,
        Cipher $newCipher,
        string $newDek,
        string $newAad,
        bool $preferNewContext,
    ): array {
        $out = [];

        foreach ($tree as $key => $value) {
            if (is_array($value)) {
                $out[$key] = $this->walkJson(
                    tree: $value,
                    oldDek: $oldDek,
                    oldAad: $oldAad,
                    newCipher: $newCipher,
                    newDek: $newDek,
                    newAad: $newAad,
                    preferNewContext: $preferNewContext,
                );

                continue;
            }

            if (! is_string($value) || $value === '' || $this->ciphers->peekId($value) === null) {
                $out[$key] = $value;

                continue;
            }

            $plaintext = $this->decryptEnvelope(
                stored: $value,
                oldDek: $oldDek,
                oldAad: $oldAad,
                newDek: $newDek,
                newAad: $newAad,
                preferNewContext: $preferNewContext,
            );

            $out[$key] = $newCipher->encrypt($plaintext, $newDek, $newAad);
        }

        return $out;
    }

    private function decryptEnvelope(
        string $stored,
        string $oldDek,
        string $oldAad,
        string $newDek,
        string $newAad,
        bool $preferNewContext,
    ): string {
        $cipherId = $this->ciphers->peekId($stored);

        if ($cipherId === null) {
            throw new DecryptionFailedException('Stored value has no recognizable Sealcraft cipher ID prefix.');
        }

        $cipher = $this->ciphers->cipherById($cipherId);

        if ($preferNewContext) {
            try {
                return $cipher->decrypt($stored, $newDek, $newAad);
            } catch (DecryptionFailedException) {
                // The value may have been assigned before the cast context
                // cache was busted, so fall back to the original context.
            }
        }

        return $cipher->decrypt($stored, $oldDek, $oldAad);
    }
}
