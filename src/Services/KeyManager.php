<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Services;

use Crumbls\Sealcraft\Contracts\GeneratesDataKeys;
use Crumbls\Sealcraft\Events\DecryptionFailed;
use Crumbls\Sealcraft\Events\DekCreated;
use Crumbls\Sealcraft\Events\DekRotated;
use Crumbls\Sealcraft\Events\DekShredded;
use Crumbls\Sealcraft\Events\DekUnwrapped;
use Crumbls\Sealcraft\Exceptions\ContextShreddedException;
use Crumbls\Sealcraft\Exceptions\SealcraftException;
use Crumbls\Sealcraft\Models\DataKey;
use Crumbls\Sealcraft\Values\EncryptionContext;
use Crumbls\Sealcraft\Values\WrappedDek;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\RateLimiter;
use Throwable;

/**
 * Orchestrates the DEK lifecycle. Applications should not call providers
 * directly; they should go through this class so caching, capability
 * branching, audit events, and active-DEK uniqueness are enforced in one
 * place.
 */
final class KeyManager
{
    public function __construct(
        private readonly ProviderRegistry $providers,
        private readonly CipherRegistry $ciphers,
        private readonly DekCache $cache,
        private readonly Repository $config,
        private readonly ConnectionResolverInterface $db,
    ) {}

    /**
     * Get or create the active plaintext DEK for a context. Cached in
     * the request-scoped DekCache on first access.
     */
    public function getOrCreateDek(EncryptionContext $ctx, ?string $providerName = null): string
    {
        $cached = $this->cache->get($ctx);

        if ($cached !== null) {
            return $cached;
        }

        $dataKey = DataKey::query()
            ->forContext($ctx->contextType, $ctx->contextId)
            ->active()
            ->first();

        if ($dataKey instanceof DataKey) {
            return $this->unwrapInto($dataKey, $ctx);
        }

        $this->guardShredded($ctx);

        $created = $this->createDek($ctx, $providerName);

        return $this->unwrapInto($created, $ctx, fireUnwrap: false);
    }

    /**
     * Create a new active DEK for a context. Throws if one already
     * exists (use rotateDek to cycle instead).
     */
    public function createDek(EncryptionContext $ctx, ?string $providerName = null): DataKey
    {
        $providerName ??= (string) $this->config->get('sealcraft.default_provider', 'local');
        $provider = $this->providers->provider($providerName);
        $cipherName = (string) $this->config->get('sealcraft.default_cipher', 'aes-256-gcm');
        $cipher = $this->ciphers->cipher($cipherName);

        $connection = $this->db->connection();

        return $connection->transaction(function () use ($ctx, $provider, $providerName, $cipher, $cipherName): DataKey {
            $existing = DataKey::query()
                ->forContext($ctx->contextType, $ctx->contextId)
                ->active()
                ->lockForUpdate()
                ->first();

            if ($existing instanceof DataKey) {
                throw new SealcraftException(
                    "An active DEK already exists for context [{$ctx->contextType}:{$ctx->contextId}]."
                );
            }

            if ($provider instanceof GeneratesDataKeys) {
                $pair = $provider->generateDataKey($ctx, $cipher->keyBytes());
                $plaintext = $pair->plaintext;
                $wrapped = $pair->wrapped;
            } else {
                $plaintext = random_bytes($cipher->keyBytes());
                $wrapped = $provider->wrap($plaintext, $ctx);
            }

            $dataKey = DataKey::query()->create([
                'context_type' => $ctx->contextType,
                'context_id' => (string) $ctx->contextId,
                'provider_name' => $providerName,
                'key_id' => $wrapped->keyId,
                'key_version' => $wrapped->keyVersion,
                'cipher' => $cipherName,
                'wrapped_dek' => $wrapped->toStorageString(),
            ]);

            $this->cache->put($ctx, $plaintext, $dataKey);

            Event::dispatch(new DekCreated($dataKey, $ctx, $providerName));

            return $dataKey;
        });
    }

    /**
     * Unwrap a stored DataKey using the provider that wrapped it and
     * re-wrap under the current KEK version (KEK rotation). Returns
     * the number of DataKeys rewrapped.
     */
    public function rotateKek(EncryptionContext $ctx): int
    {
        $connection = $this->db->connection();

        return $connection->transaction(function () use ($ctx): int {
            $query = DataKey::query()
                ->forContext($ctx->contextType, $ctx->contextId)
                ->active()
                ->lockForUpdate();

            $count = 0;

            $query->each(function (DataKey $dataKey) use ($ctx, &$count): void {
                $provider = $this->providers->provider($dataKey->provider_name);
                $wrapped = WrappedDek::fromStorageString($dataKey->wrapped_dek);

                $plaintext = $provider->unwrap($wrapped, $ctx);

                $rewrapped = $provider->wrap($plaintext, $ctx);

                $fromVersion = $dataKey->key_version;

                $dataKey->fill([
                    'key_id' => $rewrapped->keyId,
                    'key_version' => $rewrapped->keyVersion,
                    'wrapped_dek' => $rewrapped->toStorageString(),
                    'rotated_at' => now(),
                ])->save();

                Event::dispatch(new DekRotated(
                    $dataKey,
                    $dataKey->provider_name,
                    $fromVersion,
                    $rewrapped->keyVersion,
                ));

                $count++;
            });

            $this->cache->forget($ctx);

            return $count;
        });
    }

    public function retireDek(DataKey $dataKey): void
    {
        $dataKey->fill(['retired_at' => now()])->save();
    }

    /**
     * Fetch the live DataKey row for a context, creating one if none
     * exists. Useful to casts that need provenance metadata (cipher
     * name, provider, key version) alongside the plaintext DEK.
     */
    public function getActiveDataKey(EncryptionContext $ctx, ?string $providerName = null): DataKey
    {
        $cached = $this->cache->getDataKey($ctx);

        if ($cached !== null) {
            return $cached;
        }

        $existing = DataKey::query()
            ->forContext($ctx->contextType, $ctx->contextId)
            ->active()
            ->first();

        if ($existing instanceof DataKey) {
            $this->cache->putDataKey($ctx, $existing);

            return $existing;
        }

        $this->guardShredded($ctx);

        return $this->createDek($ctx, $providerName);
    }

    /**
     * Crypto-shred a context's DEK. The active DataKey row is marked
     * retired AND shredded; no replacement is created. All ciphertext
     * previously encrypted under this context becomes permanently
     * unrecoverable.
     *
     * This is the mechanism for honoring right-to-be-forgotten /
     * data-erasure requests without having to delete every field in
     * every related row (which is impossible in the presence of
     * backups, replicas, audit logs, and data warehouses).
     *
     * Idempotent: repeated calls for an already-shredded context
     * are no-ops.
     */
    public function shredContext(EncryptionContext $ctx): void
    {
        $connection = $this->db->connection();

        $connection->transaction(function () use ($ctx): void {
            $active = DataKey::query()
                ->forContext($ctx->contextType, $ctx->contextId)
                ->active()
                ->lockForUpdate()
                ->first();

            if (! $active instanceof DataKey) {
                // Nothing active to shred. If a previously-shredded row
                // exists we're already done; otherwise the context simply
                // never had a DEK and there's nothing to destroy.
                return;
            }

            $now = now();

            $active->fill([
                'retired_at' => $now,
                'shredded_at' => $now,
            ])->save();

            $this->cache->forget($ctx);

            Event::dispatch(new DekShredded(
                dataKey: $active,
                context: $ctx,
                providerName: $active->provider_name,
            ));
        });
    }

    public function isContextShredded(EncryptionContext $ctx): bool
    {
        $active = DataKey::query()
            ->forContext($ctx->contextType, $ctx->contextId)
            ->active()
            ->exists();

        if ($active) {
            return false;
        }

        return DataKey::query()
            ->forContext($ctx->contextType, $ctx->contextId)
            ->shredded()
            ->exists();
    }

    private function guardShredded(EncryptionContext $ctx): void
    {
        if (! $this->isContextShredded($ctx)) {
            return;
        }

        throw new ContextShreddedException(
            "Context [{$ctx->contextType}:{$ctx->contextId}] has been crypto-shredded; data encrypted under it is permanently unrecoverable."
        );
    }

    /**
     * Migrate a context's active DEK from one provider to another by
     * unwrapping with the source, rewrapping with the target, and
     * retiring the old DataKey.
     */
    public function migrateProvider(
        EncryptionContext $ctx,
        string $fromProvider,
        string $toProvider,
    ): DataKey {
        $connection = $this->db->connection();

        return $connection->transaction(function () use ($ctx, $fromProvider, $toProvider): DataKey {
            $current = DataKey::query()
                ->forContext($ctx->contextType, $ctx->contextId)
                ->forProvider($fromProvider)
                ->active()
                ->lockForUpdate()
                ->first();

            if (! $current instanceof DataKey) {
                throw new SealcraftException(
                    "No active DEK under provider [{$fromProvider}] for context [{$ctx->contextType}:{$ctx->contextId}]."
                );
            }

            $source = $this->providers->provider($fromProvider);
            $target = $this->providers->provider($toProvider);

            $wrapped = WrappedDek::fromStorageString($current->wrapped_dek);
            $plaintext = $source->unwrap($wrapped, $ctx);

            $rewrapped = $target->wrap($plaintext, $ctx);

            $current->fill(['retired_at' => now()])->save();

            $fresh = DataKey::query()->create([
                'context_type' => $ctx->contextType,
                'context_id' => (string) $ctx->contextId,
                'provider_name' => $toProvider,
                'key_id' => $rewrapped->keyId,
                'key_version' => $rewrapped->keyVersion,
                'cipher' => $current->cipher,
                'wrapped_dek' => $rewrapped->toStorageString(),
            ]);

            $this->cache->forget($ctx);

            Event::dispatch(new DekCreated($fresh, $ctx, $toProvider));

            return $fresh;
        });
    }

    private function unwrapInto(DataKey $dataKey, EncryptionContext $ctx, bool $fireUnwrap = true): string
    {
        if (($plaintext = $this->cache->get($ctx)) !== null) {
            $this->cache->putDataKey($ctx, $dataKey);

            if ($fireUnwrap) {
                Event::dispatch(new DekUnwrapped($dataKey, $ctx, $dataKey->provider_name, cacheHit: true));
            }

            return $plaintext;
        }

        $this->enforceUnwrapRateLimit($ctx);

        $provider = $this->providers->provider($dataKey->provider_name);
        $wrapped = WrappedDek::fromStorageString($dataKey->wrapped_dek);

        try {
            $plaintext = $provider->unwrap($wrapped, $ctx);
        } catch (Throwable $e) {
            Event::dispatch(new DecryptionFailed('kek_unwrap', $ctx, $dataKey->provider_name, $e));

            throw $e;
        }

        $this->cache->put($ctx, $plaintext, $dataKey);

        if ($fireUnwrap) {
            Event::dispatch(new DekUnwrapped($dataKey, $ctx, $dataKey->provider_name, cacheHit: false));
        }

        return $plaintext;
    }

    /**
     * Guard provider-level unwrap calls against enumeration/abuse. Cache
     * hits bypass this check since they don't touch the KEK provider.
     */
    private function enforceUnwrapRateLimit(EncryptionContext $ctx): void
    {
        $limit = (int) $this->config->get('sealcraft.rate_limit.unwrap_per_minute', 0);

        if ($limit <= 0) {
            return;
        }

        $key = 'sealcraft:unwrap:' . $ctx->toCanonicalHash();

        if (RateLimiter::tooManyAttempts($key, $limit)) {
            throw new SealcraftException(
                "Sealcraft unwrap rate limit exceeded for context [{$ctx->contextType}:{$ctx->contextId}]."
            );
        }

        RateLimiter::hit($key, 60);
    }
}
