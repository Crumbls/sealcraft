<?php

declare(strict_types=1);

/*
 * Error-path parity for the three HTTP-backed cloud providers (GCP,
 * Azure, Vault). AwsKmsKekProviderTest already covers its errors via
 * the AWS SDK exception hierarchy. These tests close the gap so every
 * cloud provider has loud, well-classified failures.
 *
 * Categories covered per provider:
 *   - Malformed response body         -> KekUnavailableException
 *   - HTTP 403 (auth failure)         -> KekUnavailableException or DecryptionFailedException
 *   - HTTP 500 (transient failure)    -> KekUnavailableException
 *   - Response with invalid base64    -> KekUnavailableException
 */

use Crumbls\Sealcraft\Exceptions\DecryptionFailedException;
use Crumbls\Sealcraft\Exceptions\KekUnavailableException;
use Crumbls\Sealcraft\Providers\AzureKeyVaultKekProvider;
use Crumbls\Sealcraft\Providers\GcpCloudKmsKekProvider;
use Crumbls\Sealcraft\Providers\VaultTransitKekProvider;
use Crumbls\Sealcraft\Values\EncryptionContext;
use Crumbls\Sealcraft\Values\WrappedDek;
use Illuminate\Http\Client\Factory as HttpFactory;

function fakeVault(HttpFactory $http): VaultTransitKekProvider
{
    return new VaultTransitKekProvider(
        http: $http,
        address: 'https://vault.example.test',
        keyName: 'sealcraft',
        tokenResolver: fn (): string => 'test-token',
        mount: 'transit',
    );
}

function fakeGcp(HttpFactory $http): GcpCloudKmsKekProvider
{
    return new GcpCloudKmsKekProvider(
        http: $http,
        project: 'p',
        location: 'l',
        keyRing: 'r',
        cryptoKey: 'k',
        tokenResolver: fn (): string => 'test-token',
    );
}

function fakeAzure(HttpFactory $http): AzureKeyVaultKekProvider
{
    return new AzureKeyVaultKekProvider(
        http: $http,
        vaultUrl: 'https://vault.example.test',
        keyName: 'sealcraft',
        tokenResolver: fn (): string => 'test-token',
        aadStrategy: AzureKeyVaultKekProvider::STRATEGY_CIPHER_ONLY,
    );
}

// --- Vault ------------------------------------------------------------

it('vault wrap raises KekUnavailableException on malformed response', function (): void {
    $http = new HttpFactory;
    $http->fake(['vault.example.test/v1/transit/encrypt/sealcraft' => $http->response(['data' => []])]);

    expect(fn () => fakeVault($http)->wrap('dek', new EncryptionContext('tenant', 1)))
        ->toThrow(KekUnavailableException::class, 'missing ciphertext');
});

it('vault unwrap raises DecryptionFailed on 400 (context mismatch / invalid ciphertext)', function (): void {
    $http = new HttpFactory;
    $http->fake(['vault.example.test/v1/transit/decrypt/sealcraft' => $http->response(['errors' => ['context invalid']], 400)]);

    $wrapped = new WrappedDek('vault:v1:xx', 'vault_transit', 'kid', '1', 'native');

    expect(fn () => fakeVault($http)->unwrap($wrapped, new EncryptionContext('tenant', 1)))
        ->toThrow(DecryptionFailedException::class, 'context mismatch or tampering');
});

it('vault unwrap raises KekUnavailable on 403 (policy denial is an operational issue, not auth error)', function (): void {
    $http = new HttpFactory;
    $http->fake(['vault.example.test/v1/transit/decrypt/sealcraft' => $http->response(['errors' => ['denied']], 403)]);

    $wrapped = new WrappedDek('vault:v1:xx', 'vault_transit', 'kid', '1', 'native');

    expect(fn () => fakeVault($http)->unwrap($wrapped, new EncryptionContext('tenant', 1)))
        ->toThrow(KekUnavailableException::class, 'decrypt failed');
});

it('vault unwrap raises KekUnavailable on 500 (transient failure)', function (): void {
    $http = new HttpFactory;
    $http->fake(['vault.example.test/v1/transit/decrypt/sealcraft' => $http->response(['errors' => ['oops']], 500)]);

    $wrapped = new WrappedDek('vault:v1:xx', 'vault_transit', 'kid', '1', 'native');

    expect(fn () => fakeVault($http)->unwrap($wrapped, new EncryptionContext('tenant', 1)))
        ->toThrow(KekUnavailableException::class);
});

// --- GCP --------------------------------------------------------------

it('gcp wrap raises KekUnavailableException on malformed response', function (): void {
    $http = new HttpFactory;
    $http->fake([
        'cloudkms.googleapis.com/v1/projects/p/locations/l/keyRings/r/cryptoKeys/k:encrypt' => $http->response(['name' => 'x']),
    ]);

    expect(fn () => fakeGcp($http)->wrap('dek', new EncryptionContext('tenant', 1)))
        ->toThrow(KekUnavailableException::class, 'missing required fields');
});

it('gcp unwrap raises DecryptionFailed on 400 (AAD mismatch)', function (): void {
    $http = new HttpFactory;
    $http->fake([
        'cloudkms.googleapis.com/v1/projects/p/locations/l/keyRings/r/cryptoKeys/k:decrypt' => $http->response(['error' => 'INVALID_ARGUMENT'], 400),
    ]);

    $wrapped = new WrappedDek('ct', 'gcp_kms', 'kid', '1', 'native');

    expect(fn () => fakeGcp($http)->unwrap($wrapped, new EncryptionContext('tenant', 1)))
        ->toThrow(DecryptionFailedException::class, 'AAD mismatch or corruption');
});

it('gcp unwrap raises KekUnavailable on 403 (policy denial)', function (): void {
    $http = new HttpFactory;
    $http->fake([
        'cloudkms.googleapis.com/v1/projects/p/locations/l/keyRings/r/cryptoKeys/k:decrypt' => $http->response(['error' => 'PERMISSION_DENIED'], 403),
    ]);

    $wrapped = new WrappedDek('ct', 'gcp_kms', 'kid', '1', 'native');

    expect(fn () => fakeGcp($http)->unwrap($wrapped, new EncryptionContext('tenant', 1)))
        ->toThrow(KekUnavailableException::class, 'decrypt failed');
});

// --- Azure ------------------------------------------------------------

it('azure wrap raises KekUnavailableException on missing value field', function (): void {
    $http = new HttpFactory;
    $http->fake([
        'vault.example.test/keys/sealcraft/wrapkey*' => $http->response(['kid' => 'k']),
    ]);

    expect(fn () => fakeAzure($http)->wrap(random_bytes(32), new EncryptionContext('tenant', 1)))
        ->toThrow(KekUnavailableException::class, 'missing value field');
});

it('azure unwrap raises KekUnavailableException on invalid base64 response', function (): void {
    $http = new HttpFactory;
    $http->fake([
        'vault.example.test/keys/sealcraft/unwrapkey*' => $http->response(['value' => '!!not-base64url!!']),
    ]);

    $wrapped = new WrappedDek('ct', 'azure_key_vault', 'k', '1', 'none');

    expect(fn () => fakeAzure($http)->unwrap($wrapped, new EncryptionContext('tenant', 1)))
        ->toThrow(KekUnavailableException::class, 'invalid base64url');
});
