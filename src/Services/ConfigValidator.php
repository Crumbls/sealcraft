<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Services;

use Crumbls\Sealcraft\Exceptions\SealcraftException;

/**
 * Fail-fast validator for the sealcraft.* config block. Runs in
 * SealcraftServiceProvider::boot() so production deployments discover
 * misconfiguration at boot rather than on first unwrap (potentially
 * hours into a release window).
 *
 * Each validation failure produces a message that names the exact
 * config key (or env var) the operator should fix.
 */
final class ConfigValidator
{
    /** @var array<string, array{required: array<int, string>, env_prefix: string}> */
    private const PROVIDER_REQUIREMENTS = [
        'aws_kms' => [
            'required' => ['key_id', 'region'],
            'env_prefix' => 'SEALCRAFT_AWS_',
        ],
        'gcp_kms' => [
            'required' => ['project', 'location', 'key_ring', 'crypto_key'],
            'env_prefix' => 'SEALCRAFT_GCP_',
        ],
        'azure_key_vault' => [
            'required' => ['vault_url', 'key_name'],
            'env_prefix' => 'SEALCRAFT_AZURE_',
        ],
        'vault_transit' => [
            'required' => ['address', 'key_name'],
            'env_prefix' => 'SEALCRAFT_VAULT_',
        ],
    ];

    /**
     * @param  array<string, mixed>  $config  The sealcraft config block (typically $app['config']['sealcraft'])
     *
     * @throws SealcraftException on any validation failure
     */
    public static function validate(array $config): void
    {
        self::validateDefaultProvider($config);
        self::validateDefaultCipher($config);
        self::validateDekStrategy($config);
        self::validateContextColumn($config);
        self::validateRateLimit($config);
        self::validateResolvedProviderBlock($config);
    }

    private static function validateDefaultProvider(array $config): void
    {
        $default = $config['default_provider'] ?? null;

        if (! is_string($default) || $default === '') {
            throw new SealcraftException(
                'Sealcraft config error: `default_provider` must be a non-empty string. '
                . 'Set SEALCRAFT_PROVIDER in your .env to one of: '
                . self::listKnownProviders($config)
            );
        }

        $providers = is_array($config['providers'] ?? null) ? $config['providers'] : [];

        if (! isset($providers[$default])) {
            throw new SealcraftException(
                "Sealcraft config error: `default_provider` is set to [{$default}] but no provider block with that name exists under `sealcraft.providers`. "
                . 'Valid names are: ' . self::listKnownProviders($config)
            );
        }
    }

    private static function validateDefaultCipher(array $config): void
    {
        $default = $config['default_cipher'] ?? null;

        if (! is_string($default) || $default === '') {
            throw new SealcraftException(
                'Sealcraft config error: `default_cipher` must be a non-empty string. '
                . 'Set SEALCRAFT_CIPHER in your .env to one of: ' . self::listKnownCiphers($config)
            );
        }

        $ciphers = is_array($config['ciphers'] ?? null) ? $config['ciphers'] : [];

        if (! isset($ciphers[$default])) {
            throw new SealcraftException(
                "Sealcraft config error: `default_cipher` is set to [{$default}] but no cipher block with that name exists under `sealcraft.ciphers`. "
                . 'Valid names are: ' . self::listKnownCiphers($config)
            );
        }
    }

    private static function validateDekStrategy(array $config): void
    {
        $strategy = $config['dek_strategy'] ?? 'per_group';

        if (! in_array($strategy, ['per_group', 'per_row'], true)) {
            throw new SealcraftException(
                "Sealcraft config error: `dek_strategy` must be either 'per_group' or 'per_row', got [" . var_export($strategy, true) . ']. '
                . 'Set SEALCRAFT_DEK_STRATEGY in your .env.'
            );
        }
    }

    private static function validateContextColumn(array $config): void
    {
        $strategy = $config['dek_strategy'] ?? 'per_group';

        if ($strategy !== 'per_group') {
            return;
        }

        $column = $config['context_column'] ?? null;
        $type = $config['context_type'] ?? null;

        if (! is_string($column) || $column === '') {
            throw new SealcraftException(
                'Sealcraft config error: per_group strategy requires `context_column` (env: SEALCRAFT_CONTEXT_COLUMN). '
                . 'Example: tenant_id'
            );
        }

        if (! is_string($type) || $type === '') {
            throw new SealcraftException(
                'Sealcraft config error: per_group strategy requires `context_type` (env: SEALCRAFT_CONTEXT_TYPE). '
                . 'Example: tenant'
            );
        }
    }

    private static function validateRateLimit(array $config): void
    {
        $rate = $config['rate_limit']['unwrap_per_minute'] ?? 0;

        if (! is_int($rate) || $rate < 0) {
            throw new SealcraftException(
                'Sealcraft config error: `rate_limit.unwrap_per_minute` must be a non-negative integer (env: SEALCRAFT_UNWRAP_RPM). '
                . 'Use 0 to disable rate limiting.'
            );
        }
    }

    private static function validateResolvedProviderBlock(array $config): void
    {
        $default = $config['default_provider'] ?? null;

        if (! is_string($default)) {
            return;
        }

        $block = $config['providers'][$default] ?? null;

        if (! is_array($block)) {
            return;
        }

        $driver = $block['driver'] ?? $default;

        if (! is_string($driver) || $driver === '') {
            throw new SealcraftException(
                "Sealcraft config error: provider [{$default}] is missing a `driver` key."
            );
        }

        $requirements = self::PROVIDER_REQUIREMENTS[$driver] ?? null;

        if ($requirements === null) {
            // local, config, null — no external credentials to validate
            return;
        }

        foreach ($requirements['required'] as $key) {
            $value = $block[$key] ?? null;

            if ($value === null || $value === '') {
                $envVar = $requirements['env_prefix'] . strtoupper($key);

                throw new SealcraftException(
                    "Sealcraft config error: provider [{$default}] (driver: {$driver}) requires `{$key}`. "
                    . "Set {$envVar} in your .env."
                );
            }
        }
    }

    private static function listKnownProviders(array $config): string
    {
        $providers = is_array($config['providers'] ?? null) ? array_keys($config['providers']) : [];

        return $providers === [] ? '(none configured)' : implode(', ', $providers);
    }

    private static function listKnownCiphers(array $config): string
    {
        $ciphers = is_array($config['ciphers'] ?? null) ? array_keys($config['ciphers']) : [];

        return $ciphers === [] ? '(none configured)' : implode(', ', $ciphers);
    }
}
