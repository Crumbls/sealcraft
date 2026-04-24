<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Concerns;

use Crumbls\Sealcraft\Casts\Encrypted;
use Crumbls\Sealcraft\Casts\EncryptedJson;
use Crumbls\Sealcraft\Events\ContextReencrypted;
use Crumbls\Sealcraft\Events\ContextReencrypting;
use Crumbls\Sealcraft\Exceptions\InvalidContextException;
use Crumbls\Sealcraft\Services\CipherRegistry;
use Crumbls\Sealcraft\Services\KeyManager;
use Crumbls\Sealcraft\Values\EncryptionContext;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;

/**
 * Marks a model's attributes as sealcraft-encrypted. Provides default
 * context derivation and hooks the saving event to handle context
 * changes according to the configured policy.
 *
 * RECOMMENDED: customize with a single `$sealcraft` array property:
 *
 *     protected array $sealcraft = [
 *         'strategy' => 'per_row',        // 'per_group' (default) | 'per_row'
 *         'type'     => 'patient',        // context type name
 *         'column'   => 'patient_id',     // per_group: context id column;
 *                                         // per_row:   row-key column (default: sealcraft_key)
 *     ];
 *
 * For full custom resolution (delegated context, relationship-based, etc.)
 * override the public sealcraftContext() method.
 *
 * Legacy separate properties — still supported, not deprecated:
 *
 *     protected string $sealcraftStrategy        = 'per_row';
 *     protected string $sealcraftContextType     = 'patient';
 *     protected string $sealcraftContextColumn   = 'patient_id';
 *     protected string $sealcraftRowKeyColumn    = 'row_key';
 */
trait HasEncryptedAttributes
{
    public static function bootHasEncryptedAttributes(): void
    {
        static::creating(static function (Model $model): void {
            /** @var self $model */
            $model->ensureSealcraftRowKeyMinted();
        });

        static::saving(static function (Model $model): void {
            if (! $model->exists) {
                return;
            }

            /** @var self $model */
            $model->handleSealcraftContextChange();
        });

        // Model::replicate() copies all attributes including sealcraft_key,
        // which would make the clone share the original's DEK — shredding
        // one would destroy the other's data. For per-row models we:
        //   1. Decrypt every encrypted attribute using the (still-shared)
        //      sealcraft_key so plaintext lives on the replica.
        //   2. Null the sealcraft_key so the `creating` hook mints a fresh
        //      UUID on save.
        //   3. The cast's set() will re-encrypt under the new DEK when the
        //      plaintext is re-assigned below.
        static::replicating(static function (Model $model): void {
            /** @var self $model */
            if ($model->resolveSealcraftStrategy() !== 'per_row') {
                return;
            }

            $encryptedAttributes = $model->sealcraftEncryptedAttributes();
            $decrypted = [];

            foreach ($encryptedAttributes as $attribute) {
                if (($model->attributes[$attribute] ?? null) !== null) {
                    $decrypted[$attribute] = $model->getAttribute($attribute);
                }
            }

            Encrypted::forgetContext($model);
            EncryptedJson::forgetContext($model);

            $rowKey = $model->resolveSealcraftRowKeyColumn();
            $model->attributes[$rowKey] = null;

            foreach ($decrypted as $attribute => $plaintext) {
                $model->attributes[$attribute] = null;
                unset($model->classCastCache[$attribute]);
                $model->setAttribute($attribute, $plaintext);
            }
        });
    }

    public function sealcraftContext(): EncryptionContext
    {
        $strategy = $this->resolveSealcraftStrategy();

        if ($strategy === 'per_row') {
            $column = $this->resolveSealcraftRowKeyColumn();

            // Read raw attributes to avoid triggering casts/accessors.
            $value = $this->attributes[$column] ?? null;

            if ($value === null || $value === '') {
                if ($this->exists) {
                    throw new InvalidContextException(sprintf(
                        '%s#%s has empty row-key column [%s]; refusing to mint a throwaway context. '
                        . 'Backfill via `php artisan sealcraft:backfill-row-keys "%s"` before reading or writing encrypted attributes.',
                        static::class,
                        (string) $this->getKey(),
                        $column,
                        static::class,
                    ));
                }

                $value = (string) Str::uuid();
                $this->attributes[$column] = $value;
            }

            return new EncryptionContext(
                contextType: $this->resolveSealcraftRowContextType(),
                contextId: (string) $value,
            );
        }

        $column = $this->resolveSealcraftContextColumn();
        $value = $this->getAttributeValue($column);

        if ($value === null || $value === '') {
            throw new InvalidContextException(
                "Per-group Sealcraft strategy requires column [{$column}] to be set on " . static::class . '.'
            );
        }

        return new EncryptionContext(
            contextType: $this->resolveSealcraftContextType(),
            contextId: is_int($value) ? $value : (string) $value,
        );
    }

    /**
     * Mint and persist the per-row row-key column on a not-yet-saved model
     * so the row never reaches the database with an empty key. Skipped for
     * non-per-row strategies.
     */
    protected function ensureSealcraftRowKeyMinted(): void
    {
        if ($this->resolveSealcraftStrategy() !== 'per_row') {
            return;
        }

        $column = $this->resolveSealcraftRowKeyColumn();

        if (empty($this->attributes[$column])) {
            $this->attributes[$column] = (string) Str::uuid();
        }
    }

    /**
     * Read a key from the model's `$sealcraft` array, or null if absent.
     * Primary entry point for the unified context configuration.
     */
    protected function sealcraftOption(string $key): ?string
    {
        if (! property_exists($this, 'sealcraft')) {
            return null;
        }

        /** @var mixed $config */
        $config = $this->sealcraft;

        if (! is_array($config) || ! array_key_exists($key, $config)) {
            return null;
        }

        $value = $config[$key];

        return is_string($value) && $value !== '' ? $value : null;
    }

    protected function resolveSealcraftStrategy(): string
    {
        if ($value = $this->sealcraftOption('strategy')) {
            return $value;
        }

        if (property_exists($this, 'sealcraftStrategy') && is_string($this->sealcraftStrategy) && $this->sealcraftStrategy !== '') {
            return $this->sealcraftStrategy;
        }

        $configured = config('sealcraft.dek_strategy');

        return is_string($configured) && $configured !== '' ? $configured : 'per_group';
    }

    protected function resolveSealcraftContextType(): string
    {
        if ($value = $this->sealcraftOption('type')) {
            return $value;
        }

        if (property_exists($this, 'sealcraftContextType') && is_string($this->sealcraftContextType) && $this->sealcraftContextType !== '') {
            return $this->sealcraftContextType;
        }

        $configured = config('sealcraft.context_type');

        return is_string($configured) && $configured !== '' ? $configured : 'tenant';
    }

    protected function resolveSealcraftContextColumn(): string
    {
        if ($value = $this->sealcraftOption('column')) {
            return $value;
        }

        if (property_exists($this, 'sealcraftContextColumn') && is_string($this->sealcraftContextColumn) && $this->sealcraftContextColumn !== '') {
            return $this->sealcraftContextColumn;
        }

        $configured = config('sealcraft.context_column');

        return is_string($configured) && $configured !== '' ? $configured : 'tenant_id';
    }

    protected function resolveSealcraftRowContextType(): string
    {
        if ($value = $this->sealcraftOption('type')) {
            return $value;
        }

        if (property_exists($this, 'sealcraftContextType') && is_string($this->sealcraftContextType)) {
            return $this->sealcraftContextType;
        }

        return $this->getMorphClass();
    }

    protected function resolveSealcraftRowKeyColumn(): string
    {
        if ($value = $this->sealcraftOption('column')) {
            return $value;
        }

        if (property_exists($this, 'sealcraftRowKeyColumn') && is_string($this->sealcraftRowKeyColumn)) {
            return $this->sealcraftRowKeyColumn;
        }

        return 'sealcraft_key';
    }

    /**
     * @return array<int, string>
     */
    protected function sealcraftEncryptedAttributes(): array
    {
        $encrypted = [];

        foreach ($this->getCasts() as $attribute => $cast) {
            if (! is_string($cast)) {
                continue;
            }

            $driver = strtok($cast, ':');

            if ($driver === Encrypted::class || $driver === EncryptedJson::class) {
                $encrypted[] = $attribute;
            }
        }

        return $encrypted;
    }

    protected function handleSealcraftContextChange(): void
    {
        $strategy = $this->resolveSealcraftStrategy();

        if ($strategy !== 'per_group') {
            // Per-row context is derived from an immutable sealcraft_key
            // column populated on first cast invocation; the row's
            // encryption context cannot change via attribute mutation.
            return;
        }

        $column = $this->resolveSealcraftContextColumn();

        if (! $this->isDirty($column)) {
            return;
        }

        Encrypted::forgetContext($this);
        EncryptedJson::forgetContext($this);

        $originalValue = $this->getOriginal($column);

        if ($originalValue === null || $originalValue === '') {
            // Row was saved without a context previously; nothing to
            // re-encrypt. The upcoming save will simply encrypt under
            // the new context.
            return;
        }

        $autoEnabled = (bool) config('sealcraft.auto_reencrypt_on_context_change', true);

        if (! $autoEnabled) {
            throw new InvalidContextException(
                static::class . " attempted to change its Sealcraft context column [{$column}]; auto_reencrypt_on_context_change is disabled. Use sealcraft:reencrypt-context to migrate the row explicitly."
            );
        }

        $type = $this->resolveSealcraftContextType();

        $oldContext = new EncryptionContext(
            contextType: $type,
            contextId: is_int($originalValue) ? $originalValue : (string) $originalValue,
        );

        $newContext = $this->sealcraftContext();

        $encryptedAttributes = $this->sealcraftEncryptedAttributes();

        if ($encryptedAttributes === []) {
            return;
        }

        $proceed = Event::until(new ContextReencrypting(
            model: $this,
            oldContext: $oldContext,
            newContext: $newContext,
            encryptedAttributes: $encryptedAttributes,
        ));

        if ($proceed === false) {
            throw new InvalidContextException(
                'ContextReencrypting listener cancelled the context change on ' . static::class . '.'
            );
        }

        $manager = app(KeyManager::class);
        $ciphers = app(CipherRegistry::class);

        $oldDek = $manager->getOrCreateDek($oldContext);
        $oldDataKey = $manager->getActiveDataKey($oldContext);
        $newDek = $manager->getOrCreateDek($newContext);
        $newDataKey = $manager->getActiveDataKey($newContext);

        $oldAad = $oldContext->toCanonicalBytes();
        $newAad = $newContext->toCanonicalBytes();

        $oldCipher = $ciphers->cipher($oldDataKey->cipher);
        $newCipher = $ciphers->cipher($newDataKey->cipher);

        foreach ($encryptedAttributes as $attribute) {
            $ciphertext = $this->getRawOriginal($attribute);

            if ($ciphertext === null) {
                continue;
            }

            $plaintext = $oldCipher->decrypt((string) $ciphertext, $oldDek, $oldAad);
            $newCiphertext = $newCipher->encrypt($plaintext, $newDek, $newAad);

            $this->attributes[$attribute] = $newCiphertext;

            // Bust any cached decrypted value the cast may have stored.
            unset($this->classCastCache[$attribute]);
        }

        Event::dispatch(new ContextReencrypted(
            model: $this,
            oldContext: $oldContext,
            newContext: $newContext,
            encryptedAttributes: $encryptedAttributes,
        ));
    }
}
