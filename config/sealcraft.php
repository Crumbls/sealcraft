<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | Default KEK provider
    |--------------------------------------------------------------------------
    |
    | The provider used to wrap and unwrap data encryption keys (DEKs). The
    | provider must be defined in the `providers` array below.
    |
    | Built-in drivers: aws_kms, gcp_kms, azure_key_vault, vault_transit,
    | local, null.
    |
    */
    'default_provider' => env('SEALCRAFT_PROVIDER', 'local'),

    /*
    |--------------------------------------------------------------------------
    | Default cipher
    |--------------------------------------------------------------------------
    |
    | The cipher used to encrypt field data. DEKs are generated at the size
    | required by this cipher.
    |
    | Built-in ciphers: aes-256-gcm, xchacha20.
    |
    */
    'default_cipher' => env('SEALCRAFT_CIPHER', 'aes-256-gcm'),

    /*
    |--------------------------------------------------------------------------
    | DEK strategy (global default)
    |--------------------------------------------------------------------------
    |
    | per_group: one DEK per context group (tenant/owner/patient). All rows
    |            sharing a context share the DEK. Best for multi-tenant apps.
    | per_row:   each row gets its own DEK. Highest isolation, highest KMS
    |            call volume. Best for true vault-style models.
    |
    | Models may override via: protected string $sealcraftStrategy = '...';
    |
    */
    'dek_strategy' => env('SEALCRAFT_DEK_STRATEGY', 'per_group'),

    /*
    |--------------------------------------------------------------------------
    | Context column + type (per-group default)
    |--------------------------------------------------------------------------
    |
    | The column read from the model to derive the encryption context, and
    | the context type string recorded with each DataKey row. Models may
    | override by implementing sealcraftContext().
    |
    */
    'context_column' => env('SEALCRAFT_CONTEXT_COLUMN', 'tenant_id'),

    'context_type' => env('SEALCRAFT_CONTEXT_TYPE', 'tenant'),

    /*
    |--------------------------------------------------------------------------
    | Auto re-encrypt on context change
    |--------------------------------------------------------------------------
    |
    | When true, changing a model's context column triggers automatic
    | decryption with the old DEK and re-encryption with the new DEK at
    | save time. The ContextReencrypting (pre, cancellable) and
    | ContextReencrypted (post) events fire regardless of this flag so
    | audit pipelines can subscribe.
    |
    | When false, a context column change raises InvalidContextException
    | instead. Use false for compliance postures that require explicit,
    | audited context migrations via sealcraft:reencrypt-context.
    |
    */
    'auto_reencrypt_on_context_change' => env('SEALCRAFT_AUTO_REENCRYPT', true),

    /*
    |--------------------------------------------------------------------------
    | Storage
    |--------------------------------------------------------------------------
    */
    'table_name' => 'sealcraft_data_keys',

    /*
    |--------------------------------------------------------------------------
    | DEK cache bounds
    |--------------------------------------------------------------------------
    |
    | The plaintext DEK cache is per-singleton (per request in HTTP, per job
    | in queue workers, per tick in Octane). Long-running workers that touch
    | many distinct tenants would otherwise accumulate an unbounded number
    | of plaintext DEKs. The cap evicts least-recently-used entries when
    | exceeded. Set to 0 to disable the cap (unbounded — not recommended
    | for Horizon / Octane).
    |
    */
    'dek_cache' => [
        'max_entries' => (int) env('SEALCRAFT_DEK_CACHE_MAX_ENTRIES', 1024),
    ],

    /*
    |--------------------------------------------------------------------------
    | Fail-fast config validation at boot
    |--------------------------------------------------------------------------
    |
    | When true, SealcraftServiceProvider validates the entire sealcraft
    | config block during boot() and throws SealcraftException on the first
    | problem — so missing env vars, typo'd provider names, and out-of-range
    | values fail at deploy time instead of on first unwrap.
    |
    | Disable only when intentionally testing bad config or bootstrapping a
    | partially-configured environment.
    |
    */
    'validate_on_boot' => (bool) env('SEALCRAFT_VALIDATE_ON_BOOT', true),

    /*
    |--------------------------------------------------------------------------
    | Rate limiting
    |--------------------------------------------------------------------------
    |
    | Guards against enumeration attacks that exercise the KEK provider's
    | unwrap endpoint. Scoped per context.
    |
    */
    'rate_limit' => [
        'unwrap_per_minute' => (int) env('SEALCRAFT_UNWRAP_RPM', 1000),
    ],

    /*
    |--------------------------------------------------------------------------
    | KEK providers
    |--------------------------------------------------------------------------
    */
    'providers' => [

        'aws_kms' => [
            'driver' => 'aws_kms',
            'key_id' => env('SEALCRAFT_AWS_KEY_ID'),
            'region' => env('SEALCRAFT_AWS_REGION', env('AWS_DEFAULT_REGION')),
        ],

        'gcp_kms' => [
            'driver' => 'gcp_kms',
            'project' => env('SEALCRAFT_GCP_PROJECT'),
            'location' => env('SEALCRAFT_GCP_LOCATION'),
            'key_ring' => env('SEALCRAFT_GCP_KEY_RING'),
            'crypto_key' => env('SEALCRAFT_GCP_CRYPTO_KEY'),
        ],

        'azure_key_vault' => [
            'driver' => 'azure_key_vault',
            'vault_url' => env('SEALCRAFT_AZURE_VAULT_URL'),
            'key_name' => env('SEALCRAFT_AZURE_KEY_NAME'),
            'aad_strategy' => env('SEALCRAFT_AZURE_AAD_STRATEGY', 'synthetic'),
            'aad_hmac_key_name' => env('SEALCRAFT_AZURE_AAD_HMAC_KEY_NAME'),
        ],

        'vault_transit' => [
            'driver' => 'vault_transit',
            'address' => env('SEALCRAFT_VAULT_ADDR'),
            'token' => env('SEALCRAFT_VAULT_TOKEN'),
            'key_name' => env('SEALCRAFT_VAULT_KEY_NAME'),
            'mount' => env('SEALCRAFT_VAULT_MOUNT', 'transit'),
        ],

        'local' => [
            'driver' => 'local',
            'key_path' => env('SEALCRAFT_LOCAL_KEY_PATH'),
            'allow_production' => (bool) env('SEALCRAFT_LOCAL_ALLOW_PRODUCTION', false),
        ],

        /*
         * Config-backed KEK: the wrapping key bytes live in env (usually
         * populated by a CI/CD pipeline that pulled them from a vault
         * at deploy time). No runtime KMS dependency.
         *
         * Security posture: weaker than a live KMS provider (KEK
         * plaintext lives in app process memory + env). Prefer
         * aws_kms / azure_key_vault / gcp_kms / vault_transit when your
         * infrastructure allows runtime KMS calls.
         *
         * Rotation is non-destructive: add a new version, flip
         * current_version, run `sealcraft:rotate-kek` to rewrap
         * existing DataKeys under it, then drop the old version on
         * the next deploy.
         */
        'config' => [
            'driver' => 'config',
            'current_version' => env('SEALCRAFT_CONFIG_KEK_VERSION', 'v1'),
            'versions' => array_filter([
                'v1' => env('SEALCRAFT_CONFIG_KEK_V1_B64'),
                'v2' => env('SEALCRAFT_CONFIG_KEK_V2_B64'),
                'v3' => env('SEALCRAFT_CONFIG_KEK_V3_B64'),
            ], static fn ($v): bool => is_string($v) && $v !== ''),
        ],

        'null' => [
            'driver' => 'null',
        ],

    ],

    /*
    |--------------------------------------------------------------------------
    | Ciphers
    |--------------------------------------------------------------------------
    */
    'ciphers' => [

        'aes-256-gcm' => [
            'driver' => 'aes-256-gcm',
        ],

        'xchacha20' => [
            'driver' => 'xchacha20-poly1305',
        ],

    ],

];
