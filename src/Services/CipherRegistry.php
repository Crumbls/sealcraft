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

    private function listConfiguredCiphers(): string
    {
        $ciphers = (array) $this->config->get('sealcraft.ciphers', []);
        $names = array_keys($ciphers);

        return $names === [] ? '(none configured)' : implode(', ', $names);
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
            throw new SealcraftException(
                "Sealcraft cipher [{$name}] is not configured. Valid ciphers: "
                . $this->listConfiguredCiphers()
                . '. Set SEALCRAFT_CIPHER in your .env or edit config/sealcraft.php.'
            );
        }

        $driver = (string) ($config['driver'] ?? $name);

        if (! isset($this->drivers[$driver])) {
            throw new SealcraftException(
                "Sealcraft cipher driver [{$driver}] is not registered. Valid drivers: "
                . implode(', ', array_keys($this->drivers))
                . '.'
            );
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
                "No Sealcraft cipher registered for id [{$id}]. Registered cipher ids: "
                . (array_keys($this->idIndex) === [] ? '(none)' : implode(', ', array_keys($this->idIndex)))
                . '. Ensure the cipher is configured in sealcraft.ciphers and that required extensions (e.g. ext-sodium for XChaCha20) are installed.'
            );
        }

        return $this->cipher($this->idIndex[$id]);
    }

    /**
     * Extract a registered cipher ID from a sealcraft ciphertext envelope.
     *
     * Returns null if the value does not match the sealcraft envelope shape
     * (`<id>:v<n>:<b64>:<b64>[:<b64>...]`) OR the prefix is not a registered
     * cipher. A "looks like ciphertext" check based purely on the presence
     * of a colon prefix is insufficient: data URIs, JSON-wrapped strings,
     * URLs, and other `<word>:` payloads all have short colon prefixes that
     * the previous implementation falsely reported as cipher IDs.
     */
    public function peekId(string $ciphertext): ?string
    {
        if (! preg_match(
            '/^([a-z0-9-]{1,8}):v\d+(?::[A-Za-z0-9+\/]+=*){2,}$/',
            $ciphertext,
            $matches
        )) {
            return null;
        }

        $id = $matches[1];

        if (! isset($this->idIndex[$id])) {
            $this->hydrateIdIndex();
        }

        return isset($this->idIndex[$id]) ? $id : null;
    }

    /**
     * Legacy prefix-only peek that returns whatever appears before the first
     * colon in the first 8 characters, with no validation against registered
     * ciphers and no envelope-shape check. Returns false positives for any
     * `<word>:<anything>` input — the source of v0.1.3 bugs where data URIs
     * and JSON-wrapped strings were mis-detected as ciphertext.
     *
     * @deprecated 0.1.4 Use the instance method `peekId()` on a resolved
     *             CipherRegistry instead. Scheduled for removal in 0.2.0.
     */
    public static function peekIdUnsafe(string $ciphertext): ?string
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
