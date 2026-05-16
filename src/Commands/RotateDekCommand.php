<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Commands;

use Crumbls\Sealcraft\Commands\Concerns\ResolvesEncryptionContext;
use Crumbls\Sealcraft\Concerns\HasEncryptedAttributes;
use Crumbls\Sealcraft\Contracts\GeneratesDataKeys;
use Crumbls\Sealcraft\Events\DekCreated;
use Crumbls\Sealcraft\Events\DekRotated;
use Crumbls\Sealcraft\Events\DekRotationStarting;
use Crumbls\Sealcraft\Models\DataKey;
use Crumbls\Sealcraft\Services\CipherRegistry;
use Crumbls\Sealcraft\Services\DekCache;
use Crumbls\Sealcraft\Services\KeyManager;
use Crumbls\Sealcraft\Services\ProviderRegistry;
use Crumbls\Sealcraft\Values\DataKeyPair;
use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use RuntimeException;

/**
 * Rotate the DEK for a context by synchronously re-encrypting every
 * encrypted column on every row of the given model, then retiring
 * the old DEK and activating the new one.
 *
 * This is the HIPAA-grade DEK rotation path (decision recorded in
 * the plan: "Require full synchronous re-encryption before retiring
 * DEK"). It requires no concurrent writes during execution — run
 * during a maintenance window.
 */
final class RotateDekCommand extends Command
{
    use ResolvesEncryptionContext;

    protected $signature = 'sealcraft:rotate-dek
        {model : Fully-qualified model class using HasEncryptedAttributes (e.g. "App\\Models\\Patient")}
        {context_type : Context type (e.g. "tenant", "patient", or a model FQN)}
        {context_id : Context identifier}
        {--chunk=500 : Re-encrypt rows in chunks of this size}
        {--dry-run : Report the affected row count without re-encrypting}';

    protected $description = 'Synchronously re-encrypt a model\'s rows under a fresh DEK for a context, then retire the old DEK. Example: php artisan sealcraft:rotate-dek "App\\Models\\Patient" patient 42';

    public function handle(
        KeyManager $manager,
        ProviderRegistry $providers,
        CipherRegistry $ciphers,
        DekCache $cache,
    ): int {
        $modelClass = (string) $this->argument('model');

        if (! class_exists($modelClass) || ! is_subclass_of($modelClass, Model::class)) {
            $this->error("[{$modelClass}] is not a valid Eloquent model class.");

            return self::FAILURE;
        }

        if (! in_array(HasEncryptedAttributes::class, class_uses_recursive($modelClass), true)) {
            $this->error("[{$modelClass}] does not use HasEncryptedAttributes.");

            return self::FAILURE;
        }

        $ctx = $this->buildContext(
            (string) $this->argument('context_type'),
            (string) $this->argument('context_id'),
        );

        // --- pre-flight checks (no lock held yet) ---

        $oldDataKey = DataKey::query()
            ->forContext($ctx->contextType, $ctx->contextId)
            ->active()
            ->first();

        if (! $oldDataKey instanceof DataKey) {
            $this->error("No active DataKey for context [{$ctx->contextType}:{$ctx->contextId}].");

            return self::FAILURE;
        }

        $provider = $providers->provider($oldDataKey->provider_name);
        $cipherName = $oldDataKey->cipher;
        $cipher = $ciphers->cipher($cipherName);

        /** @var Model $probe */
        $probe = new $modelClass;
        $encryptedAttrs = $this->encryptedAttributesOf($probe);

        if ($encryptedAttrs === []) {
            $this->error("Model [{$modelClass}] declares no Encrypted casts.");

            return self::FAILURE;
        }

        $modelContextColumn = $this->resolveFilterColumn($probe);
        $baseQuery = $modelClass::query()->where($modelContextColumn, $ctx->contextId);
        $total = (clone $baseQuery)->count();

        $this->info("Rotating DEK for context [{$ctx->contextType}:{$ctx->contextId}] on {$modelClass}.");
        $this->info("Rows to re-encrypt: {$total}");

        if ($this->option('dry-run')) {
            $this->line('(dry-run) no changes made.');

            return self::SUCCESS;
        }

        if ($total === 0) {
            return self::SUCCESS;
        }

        // --- acquire lock and run rotation ---
        // Lock acquired after all pre-flight validation so it is never held
        // across an early-return. Released unconditionally in finally.

        $lockKey = 'sealcraft_rotate_' . $ctx->toCanonicalHash();
        $this->acquireAdvisoryLock($lockKey);

        $rewritten = 0;

        try {
            $cache->flush();

            Event::dispatch(new DekRotationStarting($ctx, $oldDataKey, $modelClass, $total));

            // Unwrap the current DEK so we can decrypt existing rows.
            $oldPlaintext = $manager->getOrCreateDek($ctx);

            // Mint a replacement DEK but keep it in memory until all rows succeed.
            if ($provider instanceof GeneratesDataKeys) {
                $replacement = $provider->generateDataKey($ctx, $cipher->keyBytes());
            } else {
                $newPlaintext = random_bytes($cipher->keyBytes());
                $replacement = new DataKeyPair($newPlaintext, $provider->wrap($newPlaintext, $ctx));
            }

            $aad = $ctx->toCanonicalBytes();

            $baseQuery->chunkById((int) max(1, (int) $this->option('chunk')), function ($rows) use ($modelClass, $encryptedAttrs, $cipher, $oldPlaintext, $replacement, $aad, &$rewritten): void {
                foreach ($rows as $row) {
                    /** @var Model $row */
                    $attributes = $row->getAttributes();
                    $updates = [];

                    foreach ($encryptedAttrs as $attr) {
                        $ciphertext = $attributes[$attr] ?? null;

                        if ($ciphertext === null) {
                            continue;
                        }

                        $plaintext = $cipher->decrypt((string) $ciphertext, $oldPlaintext, $aad);
                        $updates[$attr] = $cipher->encrypt($plaintext, $replacement->plaintext, $aad);
                    }

                    if ($updates !== []) {
                        // Bypass Eloquent's dirty-tracking + observer so the
                        // per-row update lands even when raw attributes match
                        // after save, and so the HasEncryptedAttributes
                        // saving hook doesn't try to re-cast/re-encrypt.
                        (new $modelClass)->newQuery()
                            ->whereKey($row->getKey())
                            ->update($updates);
                        $rewritten++;
                    }
                }
            });

            // Finalize: retire old, activate new, atomically.
            DB::transaction(function () use ($oldDataKey, $replacement, $ctx, $cipherName): DataKey {
                $oldDataKey->fill(['retired_at' => now()])->save();

                $fresh = DataKey::query()->create([
                    'context_type' => $ctx->contextType,
                    'context_id' => (string) $ctx->contextId,
                    'provider_name' => $replacement->wrapped->providerName,
                    'key_id' => $replacement->wrapped->keyId,
                    'key_version' => $replacement->wrapped->keyVersion,
                    'cipher' => $cipherName,
                    'wrapped_dek' => $replacement->wrapped->toStorageString(),
                ]);

                Event::dispatch(new DekCreated($fresh, $ctx, $replacement->wrapped->providerName));
                Event::dispatch(new DekRotated($fresh, $replacement->wrapped->providerName, $oldDataKey->key_version, $fresh->key_version));

                return $fresh;
            });

            $cache->flush();
        } catch (\Throwable $e) {
            $this->error('Row re-encryption failed; no DataKeys were touched. Error: ' . $e->getMessage());

            return self::FAILURE;
        } finally {
            $this->releaseAdvisoryLock($lockKey);
        }

        $this->info("Re-encrypted {$rewritten} row(s); DEK rotated.");

        return self::SUCCESS;
    }

    /**
     * @return array<int, string>
     */
    private function encryptedAttributesOf(Model $model): array
    {
        $ref = new \ReflectionMethod($model, 'sealcraftEncryptedAttributes');
        $ref->setAccessible(true);

        /** @var array<int, string> $attrs */
        $attrs = $ref->invoke($model);

        return $attrs;
    }

    private function acquireAdvisoryLock(string $key): void
    {
        $driver = DB::connection()->getDriverName();

        if ($driver === 'pgsql') {
            $intKey = abs(crc32($key));
            $result = DB::selectOne('SELECT pg_try_advisory_lock(?) AS acquired', [$intKey]);

            if (! $result?->acquired) {
                throw new RuntimeException(
                    "Could not acquire advisory lock for this context. Another rotate-dek may be in progress."
                );
            }

            return;
        }

        if (in_array($driver, ['mysql', 'mariadb'], true)) {
            $mysqlKey = substr($key, 0, 64);
            $result = DB::selectOne('SELECT GET_LOCK(?, 0) AS acquired', [$mysqlKey]);

            if ((int) ($result?->acquired ?? 0) !== 1) {
                throw new RuntimeException(
                    "Could not acquire advisory lock for this context. Another rotate-dek may be in progress."
                );
            }

            return;
        }

        // SQLite and other drivers do not support advisory locks. The operator
        // must ensure no concurrent writes, as documented.
        $this->warn("Advisory locks are not supported for driver [{$driver}]; relying on operator quiescence.");
    }

    private function releaseAdvisoryLock(string $key): void
    {
        $driver = DB::connection()->getDriverName();

        if ($driver === 'pgsql') {
            DB::selectOne('SELECT pg_advisory_unlock(?)', [abs(crc32($key))]);

            return;
        }

        if (in_array($driver, ['mysql', 'mariadb'], true)) {
            DB::selectOne('SELECT RELEASE_LOCK(?)', [substr($key, 0, 64)]);
        }
    }

    private function resolveFilterColumn(Model $probe): string
    {
        $strategyRef = new \ReflectionMethod($probe, 'resolveSealcraftStrategy');
        $strategyRef->setAccessible(true);
        $strategy = (string) $strategyRef->invoke($probe);

        if ($strategy === 'per_row') {
            $ref = new \ReflectionMethod($probe, 'resolveSealcraftRowKeyColumn');
            $ref->setAccessible(true);

            return (string) $ref->invoke($probe);
        }

        $ref = new \ReflectionMethod($probe, 'resolveSealcraftContextColumn');
        $ref->setAccessible(true);

        return (string) $ref->invoke($probe);
    }
}
