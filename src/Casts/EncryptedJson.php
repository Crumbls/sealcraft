<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Casts;

use Crumbls\Sealcraft\Contracts\Cipher;
use Crumbls\Sealcraft\Events\DecryptionFailed;
use Crumbls\Sealcraft\Exceptions\ContextShreddedException;
use Crumbls\Sealcraft\Exceptions\DecryptionFailedException;
use Crumbls\Sealcraft\Exceptions\InvalidContextException;
use Crumbls\Sealcraft\Exceptions\SealcraftException;
use Crumbls\Sealcraft\Models\DataKey;
use Crumbls\Sealcraft\Services\CipherRegistry;
use Crumbls\Sealcraft\Services\KeyManager;
use Crumbls\Sealcraft\Values\EncryptionContext;
use Illuminate\Contracts\Database\Eloquent\CastsAttributes;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Event;
use Throwable;

/**
 * Eloquent attribute cast that encrypts every leaf scalar of a JSON
 * structure while preserving keys and nesting. Useful for columns
 * whose shape needs to stay visible to admin tooling or analytics
 * while the inner values remain protected.
 *
 * Semantics:
 *
 *   - set(): accepts null, array, object (JSON-serializable), or a
 *     JSON-encoded string. Recursively walks the structure; every
 *     non-empty string leaf is encrypted with the model's DEK.
 *     Non-string scalars (int/float/bool), empty strings, and nulls
 *     are preserved as-is so structural cues and metadata keys are
 *     not obfuscated.
 *
 *   - get(): returns null for null; otherwise json-decodes and walks
 *     the tree. String leaves carrying a recognizable cipher prefix
 *     are decrypted; strings without the prefix pass through as-is
 *     (supports mixed plaintext/ciphertext during migrations). A
 *     prefix-bearing leaf that fails authentication raises
 *     DecryptionFailedException — we never silently return tampered
 *     ciphertext as plaintext.
 *
 * The host model must expose sealcraftContext(): EncryptionContext
 * (typically via the HasEncryptedAttributes trait).
 *
 * @implements CastsAttributes<array<int|string, mixed>|null, mixed>
 */
final class EncryptedJson implements CastsAttributes
{
    /** @var \WeakMap<Model, EncryptionContext>|null */
    private static ?\WeakMap $contextCache = null;

    public static function forgetContext(Model $model): void
    {
        if (self::$contextCache !== null) {
            unset(self::$contextCache[$model]);
        }
    }

    public function get(Model $model, string $key, mixed $value, array $attributes): ?array
    {
        if ($value === null) {
            return null;
        }

        if (! is_string($value)) {
            throw new SealcraftException("EncryptedJson column [{$key}] must be stored as a string.");
        }

        $decoded = json_decode($value, associative: true);

        if (! is_array($decoded)) {
            throw new SealcraftException("EncryptedJson column [{$key}] does not contain valid JSON.");
        }

        $context = $this->contextFor($model);
        $manager = app(KeyManager::class);
        $ciphers = app(CipherRegistry::class);

        try {
            $dek = $manager->getOrCreateDek($context);
            $dataKey = $manager->getActiveDataKey($context);
        } catch (ContextShreddedException $e) {
            throw $e;
        } catch (Throwable $e) {
            Event::dispatch(new DecryptionFailed('kek_unwrap', $context, null, $e));

            throw $e;
        }

        return $this->walkDecrypt($decoded, $key, $context, $dataKey, $ciphers, $dek);
    }

    /**
     * @return array<string, string|null>
     */
    public function set(Model $model, string $key, mixed $value, array $attributes): array
    {
        if ($value === null) {
            return [$key => null];
        }

        $tree = $this->normalizeInput($value, $key);

        // Empty structures round-trip as empty JSON without invoking the
        // KEK. No DEK needs to materialize if there is nothing to encrypt.
        if ($tree === []) {
            return [$key => json_encode($tree)];
        }

        // $attributes is $model->attributes at call time; use it as the
        // prior-state snapshot to avoid re-entering getAttributes() (which
        // would recursively invoke this cast via mergeAttributesFromCachedCasts).
        $priorAttrs = $attributes;

        $context = $this->contextFor($model);
        $manager = app(KeyManager::class);
        $dek = $manager->getOrCreateDek($context);
        $dataKey = $manager->getActiveDataKey($context);

        $cipher = $this->cipherFor($dataKey);
        $aad = $context->toCanonicalBytes();

        $encryptedTree = $this->walkEncrypt($tree, $cipher, $dek, $aad);

        $merged = [$key => json_encode($encryptedTree)];

        $currentAttrs = self::readRawAttributes($model);

        foreach ($currentAttrs as $attr => $attrValue) {
            if ($attr === $key) {
                continue;
            }

            $wasPresent = array_key_exists($attr, $priorAttrs);

            if (! $wasPresent || $priorAttrs[$attr] !== $attrValue) {
                $merged[$attr] = $attrValue;
            }
        }

        return $merged;
    }

    /**
     * @return array<int|string, mixed>
     */
    private function normalizeInput(mixed $value, string $key): array
    {
        if (is_array($value)) {
            return $value;
        }

        if (is_string($value)) {
            $decoded = json_decode($value, associative: true);

            if (is_array($decoded)) {
                return $decoded;
            }

            throw new SealcraftException(
                "EncryptedJson column [{$key}] received a string that is not valid JSON."
            );
        }

        if (is_object($value)) {
            $encoded = json_encode($value);

            if ($encoded !== false) {
                $decoded = json_decode($encoded, associative: true);

                if (is_array($decoded)) {
                    return $decoded;
                }
            }
        }

        throw new SealcraftException(
            "EncryptedJson column [{$key}] received an unsupported value of type " . get_debug_type($value) . '.'
        );
    }

    /**
     * @param  array<int|string, mixed>  $tree
     * @return array<int|string, mixed>
     */
    private function walkEncrypt(array $tree, Cipher $cipher, string $dek, string $aad): array
    {
        $out = [];

        foreach ($tree as $k => $v) {
            if (is_array($v)) {
                $out[$k] = $this->walkEncrypt($v, $cipher, $dek, $aad);

                continue;
            }

            if (is_string($v) && $v !== '') {
                $out[$k] = $cipher->encrypt($v, $dek, $aad);

                continue;
            }

            // Non-string scalars, empty strings, and nulls pass through
            // to preserve the structural contract of the column.
            $out[$k] = $v;
        }

        return $out;
    }

    /**
     * @param  array<int|string, mixed>  $tree
     * @return array<int|string, mixed>
     */
    private function walkDecrypt(
        array $tree,
        string $column,
        EncryptionContext $context,
        DataKey $dataKey,
        CipherRegistry $ciphers,
        string $dek,
    ): array {
        $out = [];

        foreach ($tree as $k => $v) {
            if (is_array($v)) {
                $out[$k] = $this->walkDecrypt($v, $column, $context, $dataKey, $ciphers, $dek);

                continue;
            }

            if (! is_string($v) || $v === '') {
                $out[$k] = $v;

                continue;
            }

            $cipherId = $ciphers->peekId($v);

            if ($cipherId === null) {
                // No ciphertext prefix — treat as plaintext (or
                // unrelated data) and pass through unchanged. This
                // supports mixed-content columns and graceful
                // handling of pre-encryption seeds.
                $out[$k] = $v;

                continue;
            }

            try {
                $cipher = $ciphers->cipherById($cipherId);
            } catch (SealcraftException $e) {
                Event::dispatch(new DecryptionFailed('cipher', $context, $dataKey->provider_name, $e));

                throw $e;
            }

            try {
                $out[$k] = $cipher->decrypt($v, $dek, $context->toCanonicalBytes());
            } catch (DecryptionFailedException $e) {
                Event::dispatch(new DecryptionFailed('cipher', $context, $dataKey->provider_name, $e));

                throw $e;
            }
        }

        return $out;
    }

    private function contextFor(Model $model): EncryptionContext
    {
        self::$contextCache ??= new \WeakMap;

        if (isset(self::$contextCache[$model])) {
            return self::$contextCache[$model];
        }

        if (! method_exists($model, 'sealcraftContext')) {
            throw new InvalidContextException(
                get_class($model) . ' must use HasEncryptedAttributes or expose sealcraftContext(): EncryptionContext to use the EncryptedJson cast.'
            );
        }

        /** @var EncryptionContext $ctx */
        $ctx = $model->sealcraftContext();
        self::$contextCache[$model] = $ctx;

        return $ctx;
    }

    private function cipherFor(DataKey $dataKey): Cipher
    {
        return app(CipherRegistry::class)->cipher($dataKey->cipher);
    }

    /**
     * Read $model->attributes directly, bypassing getAttributes() (which
     * would trigger mergeAttributesFromCachedCasts and recurse into this
     * cast's set() for every cached cast column).
     *
     * @return array<string, mixed>
     */
    private static function readRawAttributes(Model $model): array
    {
        static $reader = null;

        $reader ??= \Closure::bind(
            static fn (Model $m): array => $m->attributes,
            null,
            Model::class,
        );

        return $reader($model);
    }
}
