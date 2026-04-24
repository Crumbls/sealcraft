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
    /** @var \WeakMap<Model, EncryptionContext>|null */
    private static ?\WeakMap $contextCache = null;

    /** @var array<string, string> Per-cast context overrides parsed from cast parameters. */
    private array $overrides = [];

    /**
     * Cast parameters accepted from `$casts`:
     *
     *   'col' => Encrypted::class . ':type=employer,column=employer_id'
     *
     * Both `type` and `column` must be provided together when overriding —
     * the cast will derive context `(type, $model->{column})` for this
     * attribute only, independent of the model-level `$sealcraft` config.
     */
    public function __construct(string ...$params)
    {
        foreach ($params as $param) {
            if (! str_contains($param, '=')) {
                continue;
            }

            [$key, $value] = explode('=', $param, 2);
            $key = trim($key);
            $value = trim($value);

            if ($value === '') {
                continue;
            }

            $this->overrides[$key] = $value;
        }

        if ($this->overrides !== []) {
            $haveType = isset($this->overrides['type']);
            $haveColumn = isset($this->overrides['column']);

            if ($haveType xor $haveColumn) {
                throw new SealcraftException(
                    'Encrypted cast parameters require BOTH `type` and `column` together (got only one). '
                    . 'Example: Encrypted::class . \':type=employer,column=employer_id\''
                );
            }
        }
    }

    public static function forgetContext(Model $model): void
    {
        if (self::$contextCache !== null) {
            unset(self::$contextCache[$model]);
        }
    }

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

        $cipherId = $ciphers->peekId($value);

        if ($cipherId === null) {
            $modelClass = $model::class;
            $ex = new DecryptionFailedException(
                "Encrypted column [{$key}] on {$modelClass} has no recognizable cipher ID prefix. "
                . 'If this row holds a legacy plaintext value, read it out-of-band (e.g. via DB facade or getRawOriginal()), '
                . 'reassign through the Encrypted cast, and save to upgrade it. See README "Migrating from APP_KEY".'
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

        // The $attributes parameter is the snapshot of $model->attributes
        // at the moment Laravel invoked this cast (see HasAttributes::
        // setAttribute and ::mergeAttributesFromClassCasts). Use it as
        // the pre-call state instead of $model->getAttributes(), which
        // would trigger mergeAttributesFromCachedCasts and recursively
        // re-enter this cast's set() for any column already in the
        // class cast cache.
        $priorAttrs = $attributes;

        $context = $this->contextFor($model);
        $manager = app(KeyManager::class);
        $dek = $manager->getOrCreateDek($context);
        $dataKey = $manager->getActiveDataKey($context);

        $ciphertext = $this->cipherFor($dataKey)->encrypt((string) $value, $dek, $context->toCanonicalBytes());

        $merged = [$key => $ciphertext];

        // Read $model->attributes WITHOUT going through getAttributes(),
        // to avoid the cache-merge recursion described above. Closure::bind
        // with Model scope lets us read the protected property directly.
        $currentAttrs = self::readRawAttributes($model);

        foreach ($currentAttrs as $attr => $attrValue) {
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

    private function contextFor(Model $model): EncryptionContext
    {
        if ($this->overrides !== []) {
            return $this->contextFromOverrides($model);
        }

        self::$contextCache ??= new \WeakMap;

        if (isset(self::$contextCache[$model])) {
            return self::$contextCache[$model];
        }

        if (! method_exists($model, 'sealcraftContext')) {
            throw new InvalidContextException(
                get_class($model) . ' must use HasEncryptedAttributes or expose sealcraftContext(): EncryptionContext to use the Encrypted cast.'
            );
        }

        /** @var EncryptionContext $ctx */
        $ctx = $model->sealcraftContext();
        self::$contextCache[$model] = $ctx;

        return $ctx;
    }

    private function contextFromOverrides(Model $model): EncryptionContext
    {
        $type = $this->overrides['type'];
        $column = $this->overrides['column'];
        $value = $model->getAttribute($column);

        if ($value === null || $value === '') {
            throw new InvalidContextException(sprintf(
                'Encrypted cast with per-column override on %s requires column [%s] to be set (resolving context type [%s]).',
                get_class($model),
                $column,
                $type,
            ));
        }

        return new EncryptionContext(
            contextType: $type,
            contextId: is_int($value) ? $value : (string) $value,
        );
    }

    private function cipherFor(DataKey $dataKey): Cipher
    {
        return app(CipherRegistry::class)->cipher($dataKey->cipher);
    }
}
