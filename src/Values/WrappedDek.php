<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Values;

use Crumbls\Sealcraft\Exceptions\SealcraftException;

/**
 * Rich container for a wrapped DEK and its provenance. Serialized to a
 * versioned string for storage in sealcraft_data_keys.wrapped_dek:
 *
 *     sc1:<b64url(json header)>:<b64(ciphertext)>
 *
 * The "sc1" prefix is forward-compatible for future format changes.
 */
final class WrappedDek
{
    public const STORAGE_VERSION = 'sc1';

    /**
     * @param  array<string, scalar|array<mixed>|null>  $metadata
     */
    public function __construct(
        public readonly string $ciphertext,
        public readonly string $providerName,
        public readonly string $keyId,
        public readonly ?string $keyVersion,
        public readonly string $aadStrategy,
        public readonly array $metadata = [],
    ) {}

    public function toStorageString(): string
    {
        $header = [
            'provider' => $this->providerName,
            'key_id' => $this->keyId,
            'key_version' => $this->keyVersion,
            'aad' => $this->aadStrategy,
            'metadata' => $this->metadata,
        ];

        $headerBytes = json_encode($header, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        return self::STORAGE_VERSION
            . ':' . self::base64UrlEncode($headerBytes)
            . ':' . base64_encode($this->ciphertext);
    }

    public static function fromStorageString(string $stored): self
    {
        $parts = explode(':', $stored, 3);

        if (count($parts) !== 3) {
            throw new SealcraftException('Malformed WrappedDek storage string.');
        }

        [$version, $encodedHeader, $encodedCiphertext] = $parts;

        if ($version !== self::STORAGE_VERSION) {
            throw new SealcraftException("Unsupported WrappedDek storage version: {$version}");
        }

        $headerBytes = self::base64UrlDecode($encodedHeader);
        $ciphertext = base64_decode($encodedCiphertext, true);

        if ($headerBytes === false || $ciphertext === false) {
            throw new SealcraftException('Malformed WrappedDek base64 payload.');
        }

        /** @var array{provider?: string, key_id?: string, key_version?: string|null, aad?: string, metadata?: array<mixed>} $header */
        $header = json_decode($headerBytes, true, flags: JSON_THROW_ON_ERROR);

        foreach (['provider', 'key_id', 'aad'] as $required) {
            if (! isset($header[$required]) || ! is_string($header[$required])) {
                throw new SealcraftException("WrappedDek header missing required field: {$required}");
            }
        }

        return new self(
            ciphertext: $ciphertext,
            providerName: $header['provider'],
            keyId: $header['key_id'],
            keyVersion: isset($header['key_version']) ? (string) $header['key_version'] : null,
            aadStrategy: $header['aad'],
            metadata: is_array($header['metadata'] ?? null) ? $header['metadata'] : [],
        );
    }

    private static function base64UrlEncode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    private static function base64UrlDecode(string $encoded): string|false
    {
        $padding = strlen($encoded) % 4;

        if ($padding > 0) {
            $encoded .= str_repeat('=', 4 - $padding);
        }

        return base64_decode(strtr($encoded, '-_', '+/'), true);
    }
}
