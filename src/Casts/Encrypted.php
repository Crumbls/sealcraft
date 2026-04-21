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
 * Eloquent attribute cast that transparently encrypts and decrypts a
 * column using the DEK derived from the model's encryption context.
 *
 * Null values pass through unchanged so NULL-aware SQL (IS NULL, etc.)
 * still works for rows that simply have no value. Non-null values are
 * bound to the context at the cipher layer via AAD; an attempted
 * cross-context decrypt fails authentication and raises
 * DecryptionFailedException.
 *
 * The host model must use the HasEncryptedAttributes trait (or
 * otherwise expose a public sealcraftContext() method returning an
 * EncryptionContext).
 *
 * @implements CastsAttributes<string|null, string|null>
 */
final class Encrypted implements CastsAttributes
{
    public function get(Model $model, string $key, mixed $value, array $attributes): ?string
    {
        if ($value === null) {
            return null;
        }

        if (! is_string($value)) {
            throw new SealcraftException("Encrypted column [{$key}] must be stored as a string.");
        }

        $context = $this->contextFor($model);
        $manager = app(KeyManager::class);
        $ciphers = app(CipherRegistry::class);

        try {
            $dek = $manager->getOrCreateDek($context);
            $dataKey = $manager->getActiveDataKey($context);
        } catch (ContextShreddedException $e) {
            // Shred is an intentional, auditable destruction — not a
            // decryption failure. Propagate without firing the
            // DecryptionFailed event so SIEM dashboards aren't spammed
            // by right-to-be-forgotten reads.
            throw $e;
        } catch (Throwable $e) {
            Event::dispatch(new DecryptionFailed('kek_unwrap', $context, null, $e));

            throw $e;
        }

        $cipherId = CipherRegistry::peekId($value);

        if ($cipherId === null) {
            $ex = new DecryptionFailedException(
                "Encrypted column [{$key}] has no recognizable cipher ID prefix."
            );
            Event::dispatch(new DecryptionFailed('cipher', $context, $dataKey->provider_name, $ex));

            throw $ex;
        }

        try {
            $cipher = $ciphers->cipherById($cipherId);
        } catch (SealcraftException $e) {
            Event::dispatch(new DecryptionFailed('cipher', $context, $dataKey->provider_name, $e));

            throw $e;
        }

        try {
            return $cipher->decrypt($value, $dek, $context->toCanonicalBytes());
        } catch (DecryptionFailedException $e) {
            Event::dispatch(new DecryptionFailed('cipher', $context, $dataKey->provider_name, $e));

            throw $e;
        }
    }

    public function set(Model $model, string $key, mixed $value, array $attributes): array
    {
        if ($value === null) {
            return [$key => null];
        }

        if (! is_scalar($value) && ! (is_object($value) && method_exists($value, '__toString'))) {
            throw new SealcraftException(
                "Encrypted column [{$key}] received a non-stringable value of type " . get_debug_type($value) . '.'
            );
        }

        // Capture pre-existing attribute state so we can detect any changes
        // the context resolver injects during this call (e.g. a generated
        // sealcraft_key for per-row strategy, which may either be newly
        // added OR overwrite an existing NULL on an already-persisted row).
        //
        // Laravel snapshots $this->attributes before invoking the cast and
        // then array_replaces the cast's return value back onto it, so
        // mutations the resolver makes to $model->attributes directly would
        // otherwise be lost.
        $priorAttrs = $model->getAttributes();

        $context = $this->contextFor($model);
        $manager = app(KeyManager::class);
        $dek = $manager->getOrCreateDek($context);
        $dataKey = $manager->getActiveDataKey($context);

        $ciphertext = $this->cipherFor($dataKey)->encrypt((string) $value, $dek, $context->toCanonicalBytes());

        $merged = [$key => $ciphertext];

        foreach ($model->getAttributes() as $attr => $attrValue) {
            if ($attr === $key) {
                continue;
            }

            $wasPresent = array_key_exists($attr, $priorAttrs);

            // Include newly-added attributes AND attributes whose value was
            // mutated by the context resolver (e.g. sealcraft_key going from
            // NULL to a freshly-generated UUID on an existing row).
            if (! $wasPresent || $priorAttrs[$attr] !== $attrValue) {
                $merged[$attr] = $attrValue;
            }
        }

        return $merged;
    }

    private function contextFor(Model $model): EncryptionContext
    {
        if (! method_exists($model, 'sealcraftContext')) {
            throw new InvalidContextException(
                get_class($model) . ' must use HasEncryptedAttributes or expose sealcraftContext(): EncryptionContext to use the Encrypted cast.'
            );
        }

        /** @var EncryptionContext $ctx */
        $ctx = $model->sealcraftContext();

        return $ctx;
    }

    private function cipherFor(DataKey $dataKey): Cipher
    {
        return app(CipherRegistry::class)->cipher($dataKey->cipher);
    }
}
