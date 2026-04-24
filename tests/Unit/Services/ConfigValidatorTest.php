<?php

declare(strict_types=1);

use Crumbls\Sealcraft\Exceptions\SealcraftException;
use Crumbls\Sealcraft\Services\ConfigValidator;

function validConfig(array $overrides = []): array
{
    return array_replace_recursive([
        'default_provider' => 'local',
        'default_cipher' => 'aes-256-gcm',
        'dek_strategy' => 'per_group',
        'context_column' => 'tenant_id',
        'context_type' => 'tenant',
        'rate_limit' => ['unwrap_per_minute' => 1000],
        'providers' => [
            'local' => ['driver' => 'local', 'key_path' => '/tmp/kek'],
            'null' => ['driver' => 'null'],
            'aws_kms' => ['driver' => 'aws_kms', 'key_id' => 'alias/x', 'region' => 'us-east-1'],
            'gcp_kms' => ['driver' => 'gcp_kms', 'project' => 'p', 'location' => 'l', 'key_ring' => 'r', 'crypto_key' => 'k'],
            'azure_key_vault' => ['driver' => 'azure_key_vault', 'vault_url' => 'https://v', 'key_name' => 'k'],
            'vault_transit' => ['driver' => 'vault_transit', 'address' => 'https://v', 'key_name' => 'k'],
        ],
        'ciphers' => [
            'aes-256-gcm' => ['driver' => 'aes-256-gcm'],
            'xchacha20' => ['driver' => 'xchacha20-poly1305'],
        ],
    ], $overrides);
}

it('passes on the shipped defaults', function (): void {
    ConfigValidator::validate(validConfig());
    expect(true)->toBeTrue();
});

it('rejects an empty default_provider', function (): void {
    expect(fn () => ConfigValidator::validate(validConfig(['default_provider' => ''])))
        ->toThrow(SealcraftException::class, 'SEALCRAFT_PROVIDER');
});

it('rejects a default_provider that is not in the providers block', function (): void {
    expect(fn () => ConfigValidator::validate(validConfig(['default_provider' => 'nope'])))
        ->toThrow(SealcraftException::class, 'no provider block with that name');
});

it('lists valid provider names in the error when one is misconfigured', function (): void {
    try {
        ConfigValidator::validate(validConfig(['default_provider' => 'nope']));
    } catch (SealcraftException $e) {
        expect($e->getMessage())->toContain('local');
        expect($e->getMessage())->toContain('aws_kms');

        return;
    }

    throw new RuntimeException('expected validation to throw');
});

it('rejects an empty default_cipher', function (): void {
    expect(fn () => ConfigValidator::validate(validConfig(['default_cipher' => ''])))
        ->toThrow(SealcraftException::class, 'SEALCRAFT_CIPHER');
});

it('rejects a default_cipher that is not in the ciphers block', function (): void {
    expect(fn () => ConfigValidator::validate(validConfig(['default_cipher' => 'rot13'])))
        ->toThrow(SealcraftException::class, 'no cipher block with that name');
});

it('rejects a dek_strategy that is not per_group or per_row', function (): void {
    expect(fn () => ConfigValidator::validate(validConfig(['dek_strategy' => 'weird'])))
        ->toThrow(SealcraftException::class, 'SEALCRAFT_DEK_STRATEGY');
});

it('requires context_column and context_type for per_group strategy', function (): void {
    expect(fn () => ConfigValidator::validate(validConfig(['context_column' => ''])))
        ->toThrow(SealcraftException::class, 'SEALCRAFT_CONTEXT_COLUMN');
    expect(fn () => ConfigValidator::validate(validConfig(['context_type' => ''])))
        ->toThrow(SealcraftException::class, 'SEALCRAFT_CONTEXT_TYPE');
});

it('does not require context_column or context_type for per_row strategy', function (): void {
    ConfigValidator::validate(validConfig([
        'dek_strategy' => 'per_row',
        'context_column' => '',
        'context_type' => '',
    ]));

    expect(true)->toBeTrue();
});

it('rejects a negative rate limit', function (): void {
    expect(fn () => ConfigValidator::validate(validConfig(['rate_limit' => ['unwrap_per_minute' => -5]])))
        ->toThrow(SealcraftException::class, 'non-negative integer');
});

it('rejects a non-integer rate limit', function (): void {
    expect(fn () => ConfigValidator::validate(validConfig(['rate_limit' => ['unwrap_per_minute' => 'many']])))
        ->toThrow(SealcraftException::class, 'non-negative integer');
});

it('names the exact env var to set when a cloud provider key is missing', function (): void {
    $cfg = validConfig([
        'default_provider' => 'aws_kms',
        'providers' => ['aws_kms' => ['driver' => 'aws_kms', 'key_id' => null, 'region' => 'us-east-1']],
    ]);

    try {
        ConfigValidator::validate($cfg);
    } catch (SealcraftException $e) {
        expect($e->getMessage())->toContain('SEALCRAFT_AWS_KEY_ID');

        return;
    }

    throw new RuntimeException('expected validation to throw');
});

it('points at GCP env vars when GCP is missing required fields', function (): void {
    $cfg = validConfig([
        'default_provider' => 'gcp_kms',
        'providers' => ['gcp_kms' => ['driver' => 'gcp_kms', 'project' => '']],
    ]);

    expect(fn () => ConfigValidator::validate($cfg))
        ->toThrow(SealcraftException::class, 'SEALCRAFT_GCP_PROJECT');
});

it('points at Azure env vars when Azure is missing required fields', function (): void {
    $cfg = validConfig([
        'default_provider' => 'azure_key_vault',
        'providers' => ['azure_key_vault' => ['driver' => 'azure_key_vault', 'vault_url' => '', 'key_name' => '']],
    ]);

    expect(fn () => ConfigValidator::validate($cfg))
        ->toThrow(SealcraftException::class, 'SEALCRAFT_AZURE_VAULT_URL');
});

it('points at Vault env vars when Vault Transit is missing required fields', function (): void {
    $cfg = validConfig([
        'default_provider' => 'vault_transit',
        'providers' => ['vault_transit' => ['driver' => 'vault_transit', 'address' => '']],
    ]);

    expect(fn () => ConfigValidator::validate($cfg))
        ->toThrow(SealcraftException::class, 'SEALCRAFT_VAULT_ADDRESS');
});

it('skips credential validation for local/null/config drivers', function (): void {
    ConfigValidator::validate(validConfig(['default_provider' => 'local']));
    ConfigValidator::validate(validConfig(['default_provider' => 'null']));

    expect(true)->toBeTrue();
});
