<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Commands;

use Crumbls\Sealcraft\Commands\Concerns\ResolvesEncryptionContext;
use Crumbls\Sealcraft\Concerns\HasEncryptedAttributes;
use Crumbls\Sealcraft\Contracts\Cipher;
use Crumbls\Sealcraft\Contracts\GeneratesDataKeys;
use Crumbls\Sealcraft\Events\DekCreated;
use Crumbls\Sealcraft\Events\DekRotated;
use Crumbls\Sealcraft\Events\DekRotationStarting;
use Crumbls\Sealcraft\Models\DataKey;
use Crumbls\Sealcraft\Services\CipherRegistry;
use Crumbls\Sealcraft\Services\DekCache;
use Crumbls\Sealcraft\Services\EncryptedPayloadRewriter;
use Crumbls\Sealcraft\Services\KeyManager;
use Crumbls\Sealcraft\Services\ProviderRegistry;
use Crumbls\Sealcraft\Values\DataKeyPair;
use Crumbls\Sealcraft\Values\EncryptionContext;
use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use ReflectionClass;
use RuntimeException;
use Symfony\Component\Finder\Finder;

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
        {--scan-path=* : Directories to scan for delegated models (defaults to app/, or the project root when app/ is absent)}
        {--without-delegated-discovery : Only rotate rows from the explicitly provided model}
        {--dry-run : Report the affected row count without re-encrypting}';

    protected $description = 'Synchronously re-encrypt a model\'s rows under a fresh DEK for a context, then retire the old DEK. Example: php artisan sealcraft:rotate-dek "App\\Models\\Patient" patient 42';

    public function handle(
        KeyManager $manager,
        ProviderRegistry $providers,
        CipherRegistry $ciphers,
        DekCache $cache,
        EncryptedPayloadRewriter $rewriter,
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

        $oldDataKey = DataKey::queryActiveForContext($ctx->contextType, $ctx->contextId)
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

        $targets = $this->rotationTargets($modelClass, $ctx);
        $total = $this->countTargetRows($targets, $ctx, (int) max(1, (int) $this->option('chunk')));

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
            $chunk = (int) max(1, (int) $this->option('chunk'));

            DB::transaction(function () use ($targets, $ctx, $oldDataKey, $replacement, $cipherName, $cipher, $oldPlaintext, $aad, $rewriter, $chunk, &$rewritten): void {
                $lockedOld = DataKey::query()
                    ->whereKey($oldDataKey->getKey())
                    ->lockForUpdate()
                    ->first();

                if (! $lockedOld instanceof DataKey || $lockedOld->isRetired()) {
                    throw new RuntimeException('The source DataKey changed before rotation could start.');
                }

                foreach ($targets as $target) {
                    /** @var class-string<Model> $targetModel */
                    $targetModel = $target['model'];
                    $target['query']()->chunkById($chunk, function ($rows) use ($target, $targetModel, $ctx, $cipher, $oldPlaintext, $replacement, $aad, $rewriter, &$rewritten): void {
                        foreach ($rows as $row) {
                            /** @var Model $row */
                            if (! $this->rowMatchesContext($row, $ctx)) {
                                continue;
                            }

                            $updates = $this->reencryptRow(
                                row: $row,
                                encryptedAttrs: $target['encrypted_attrs'],
                                oldPlaintext: $oldPlaintext,
                                newPlaintext: $replacement->plaintext,
                                aad: $aad,
                                newCipher: $cipher,
                                rewriter: $rewriter,
                            );

                            if ($updates === []) {
                                continue;
                            }

                            // Bypass Eloquent's dirty-tracking + observer so the
                            // per-row update lands even when raw attributes match
                            // after save, and so the HasEncryptedAttributes
                            // saving hook doesn't try to re-cast/re-encrypt.
                            (new $targetModel)->newQuery()
                                ->whereKey($row->getKey())
                                ->update($updates);
                            $rewritten++;
                        }
                    });
                }

                $lockedOld->markRetired();
                $lockedOld->save();

                $fresh = DataKey::query()->create([
                    'context_type' => $ctx->contextType,
                    'context_id' => (string) $ctx->contextId,
                    'active_context_hash' => DataKey::activeContextHash($ctx->contextType, $ctx->contextId),
                    'provider_name' => $replacement->wrapped->providerName,
                    'key_id' => $replacement->wrapped->keyId,
                    'key_version' => $replacement->wrapped->keyVersion,
                    'cipher' => $cipherName,
                    'wrapped_dek' => $replacement->wrapped->toStorageString(),
                ]);

                Event::dispatch(new DekCreated($fresh, $ctx, $replacement->wrapped->providerName));
                Event::dispatch(new DekRotated($fresh, $replacement->wrapped->providerName, $oldDataKey->key_version, $fresh->key_version));
            });

            $cache->flush();
        } catch (\Throwable $e) {
            $this->error('Row re-encryption failed; database changes were rolled back. Error: ' . $e->getMessage());

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

    /**
     * @param  array<int, string>  $encryptedAttrs
     * @return array<string, mixed>
     */
    private function reencryptRow(
        Model $row,
        array $encryptedAttrs,
        string $oldPlaintext,
        string $newPlaintext,
        string $aad,
        Cipher $newCipher,
        EncryptedPayloadRewriter $rewriter,
    ): array {
        $attributes = $row->getAttributes();
        $updates = [];

        foreach ($encryptedAttrs as $attr) {
            $stored = $attributes[$attr] ?? null;

            if ($stored === null) {
                continue;
            }

            $driver = $this->castDriverOf($row, $attr);

            if ($driver === null) {
                continue;
            }

            $updates[$attr] = $rewriter->reencrypt(
                castDriver: $driver,
                stored: $stored,
                oldDek: $oldPlaintext,
                oldAad: $aad,
                newCipher: $newCipher,
                newDek: $newPlaintext,
                newAad: $aad,
            );
        }

        return $updates;
    }

    private function castDriverOf(Model $model, string $attribute): ?string
    {
        $ref = new \ReflectionMethod($model, 'sealcraftCastDriverFor');
        $ref->setAccessible(true);

        $driver = $ref->invoke($model, $attribute);

        return is_string($driver) ? $driver : null;
    }

    /**
     * @return array<int, array{model: class-string<Model>, encrypted_attrs: array<int, string>, query: \Closure(): Builder<Model>}>
     */
    private function rotationTargets(string $modelClass, EncryptionContext $ctx): array
    {
        /** @var Model $probe */
        $probe = new $modelClass;
        $modelContextColumn = $this->resolveFilterColumn($probe);

        $targets = [[
            'model' => $modelClass,
            'encrypted_attrs' => $this->encryptedAttributesOf($probe),
            'query' => static fn () => $modelClass::query()->where($modelContextColumn, $ctx->contextId),
        ]];

        if ($this->option('without-delegated-discovery')) {
            return $targets;
        }

        foreach ($this->discoverDelegatedModelClasses($modelClass) as $class) {
            /** @var Model $candidate */
            $candidate = new $class;
            $encryptedAttrs = $this->encryptedAttributesOf($candidate);

            if ($encryptedAttrs === []) {
                continue;
            }

            $targets[] = [
                'model' => $class,
                'encrypted_attrs' => $encryptedAttrs,
                'query' => static fn () => $class::query(),
            ];
        }

        return $targets;
    }

    /**
     * @param  array<int, array{model: class-string<Model>, encrypted_attrs: array<int, string>, query: \Closure(): Builder<Model>}>  $targets
     */
    private function countTargetRows(array $targets, EncryptionContext $ctx, int $chunk): int
    {
        $count = 0;

        foreach ($targets as $target) {
            $target['query']()->chunkById($chunk, function ($rows) use ($ctx, &$count): void {
                foreach ($rows as $row) {
                    /** @var Model $row */
                    if ($this->rowMatchesContext($row, $ctx)) {
                        $count++;
                    }
                }
            });
        }

        return $count;
    }

    private function rowMatchesContext(Model $row, EncryptionContext $ctx): bool
    {
        if (! method_exists($row, 'sealcraftContext')) {
            return false;
        }

        try {
            /** @var EncryptionContext $rowContext */
            $rowContext = $row->sealcraftContext();
        } catch (\Throwable) {
            return false;
        }

        return hash_equals($ctx->toCanonicalHash(), $rowContext->toCanonicalHash());
    }

    /**
     * @param  class-string<Model>  $explicitModel
     * @return iterable<int, class-string<Model>>
     */
    private function discoverDelegatedModelClasses(string $explicitModel): iterable
    {
        $paths = $this->resolveScanPaths();
        $existingPaths = array_filter($paths, static fn (string $path): bool => is_dir($path));

        if ($existingPaths === []) {
            return;
        }

        $finder = Finder::create()
            ->files()
            ->in($existingPaths)
            ->name('*.php');

        foreach ($finder as $file) {
            $class = $this->classFromFile($file->getRealPath() ?: $file->getPathname());

            if ($class === null || $class === $explicitModel || ! class_exists($class)) {
                continue;
            }

            $reflection = new ReflectionClass($class);

            if ($reflection->isAbstract() || ! $reflection->isSubclassOf(Model::class)) {
                continue;
            }

            if (! in_array(HasEncryptedAttributes::class, class_uses_recursive($class), true)) {
                continue;
            }

            yield $class;
        }
    }

    /**
     * @return array<int, string>
     */
    private function resolveScanPaths(): array
    {
        /** @var array<int, string> $explicit */
        $explicit = (array) $this->option('scan-path');

        if ($explicit !== []) {
            return array_values(array_filter($explicit, static fn (string $path): bool => $path !== ''));
        }

        $default = base_path('app');

        if (is_dir($default)) {
            return [$default];
        }

        $fallbacks = array_filter([
            base_path('tests/Fixtures'),
            base_path('src'),
        ], static fn (string $path): bool => is_dir($path));

        return $fallbacks === [] ? [base_path()] : array_values($fallbacks);
    }

    /**
     * @return class-string|null
     */
    private function classFromFile(string $path): ?string
    {
        $contents = @file_get_contents($path);

        if ($contents === false) {
            return null;
        }

        if (preg_match('/^namespace\s+([^;]+);/m', $contents, $ns) !== 1) {
            return null;
        }

        if (preg_match('/^(?:final\s+|abstract\s+)?class\s+([A-Za-z_][A-Za-z0-9_]*)/m', $contents, $cls) !== 1) {
            return null;
        }

        return trim($ns[1]) . '\\' . trim($cls[1]);
    }

    private function acquireAdvisoryLock(string $key): void
    {
        $driver = DB::connection()->getDriverName();

        if ($driver === 'pgsql') {
            $intKey = abs(crc32($key));
            $result = DB::selectOne('SELECT pg_try_advisory_lock(?) AS acquired', [$intKey]);

            if ($result === null || ! $result->acquired) {
                throw new RuntimeException(
                    'Could not acquire advisory lock for this context. Another rotate-dek may be in progress.'
                );
            }

            return;
        }

        if (in_array($driver, ['mysql', 'mariadb'], true)) {
            $mysqlKey = substr($key, 0, 64);
            $result = DB::selectOne('SELECT GET_LOCK(?, 0) AS acquired', [$mysqlKey]);

            if ($result === null || (int) $result->acquired !== 1) {
                throw new RuntimeException(
                    'Could not acquire advisory lock for this context. Another rotate-dek may be in progress.'
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
