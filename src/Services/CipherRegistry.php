<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Services;

use Closure;
use Crumbls\Sealcraft\Ciphers\AesGcmCipher;
use Crumbls\Sealcraft\Ciphers\XChaCha20Cipher;
use Crumbls\Sealcraft\Contracts\Cipher;
use Crumbls\Sealcraft\Exceptions\SealcraftException;
use Illuminate\Contracts\Config\Repository;

/**
 * Resolves ciphers by configured name and by the 3-char ID embedded in
 * stored ciphertext. Apps can register custom cipher drivers via
 * extend(); those drivers' Cipher::id() is indexed automatically on
 * first use, so cipher-by-id dispatch works without further setup.
 */
final class CipherRegistry
{
    /** @var array<string, Closure(array<string, mixed>): Cipher> */
    private array $drivers = [];

    /** @var array<string, Cipher> indexed by configured name */
    private array $resolved = [];

    /** @var array<string, string> cipher-id -> configured-name */
    private array $idIndex = [];

    public function __construct(
        private readonly Repository $config,
    ) {
        $this->registerBuiltInDrivers();
    }

    /**
     * @param  Closure(array<string, mixed>): Cipher  $factory
     */
    public function extend(string $driver, Closure $factory): void
    {
        $this->drivers[$driver] = $factory;
        unset($this->resolved[$driver]);
        $this->idIndex = [];
    }

    public function cipher(?string $name = null): Cipher
    {
        $name ??= (string) $this->config->get('sealcraft.default_cipher', 'aes-256-gcm');

        if (isset($this->resolved[$name])) {
            return $this->resolved[$name];
        }

        $config = $this->config->get("sealcraft.ciphers.{$name}");

        if (! is_array($config)) {
            throw new SealcraftException("Sealcraft cipher [{$name}] is not configured.");
        }

        $driver = (string) ($config['driver'] ?? $name);

        if (! isset($this->drivers[$driver])) {
            throw new SealcraftException("Sealcraft cipher driver [{$driver}] is not registered.");
        }

        $cipher = ($this->drivers[$driver])($config);
        $this->resolved[$name] = $cipher;
        $this->idIndex[$cipher->id()] = $name;

        return $cipher;
    }

    /**
     * Resolve a cipher by the 3-char ID embedded in ciphertext. Ensures
     * every configured cipher is instantiated so the ID index is
     * complete, then looks up by id.
     */
    public function cipherById(string $id): Cipher
    {
        if (! isset($this->idIndex[$id])) {
            $this->hydrateIdIndex();
        }

        if (! isset($this->idIndex[$id])) {
            throw new SealcraftException(
                "No Sealcraft cipher registered for id [{$id}]. Is the cipher configured and loaded?"
            );
        }

        return $this->cipher($this->idIndex[$id]);
    }

    /**
     * Extract the 3-char cipher ID from a ciphertext string without
     * decrypting. Returns null if the string doesn't begin with a
     * cipher-id-like prefix.
     */
    public static function peekId(string $ciphertext): ?string
    {
        $colon = strpos($ciphertext, ':');

        if ($colon === false || $colon === 0 || $colon > 8) {
            return null;
        }

        return substr($ciphertext, 0, $colon);
    }

    private function hydrateIdIndex(): void
    {
        /** @var array<string, array<string, mixed>> $ciphers */
        $ciphers = (array) $this->config->get('sealcraft.ciphers', []);

        foreach (array_keys($ciphers) as $name) {
            try {
                // Instantiating each cipher populates $this->idIndex via cipher().
                $this->cipher($name);
            } catch (SealcraftException) {
                // Configured cipher references a driver that isn't installed
                // in this environment (e.g. XChaCha20 without ext-sodium).
                // Skip it — apps that don't use that cipher shouldn't fail.
            }
        }
    }

    private function registerBuiltInDrivers(): void
    {
        $this->drivers['aes-256-gcm'] = fn (): Cipher => new AesGcmCipher;

        $this->drivers['xchacha20-poly1305'] = function (): Cipher {
            if (! function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_encrypt')) {
                throw new SealcraftException(
                    'ext-sodium is required for the XChaCha20-Poly1305 cipher driver.'
                );
            }

            return new XChaCha20Cipher;
        };
    }
}
