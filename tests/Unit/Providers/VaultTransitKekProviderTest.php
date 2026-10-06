<?php

declare(strict_types=1);

use Crumbls\Sealcraft\Providers\VaultTransitKekProvider;
use Crumbls\Sealcraft\Values\EncryptionContext;
use Crumbls\Sealcraft\Values\WrappedDek;
use Illuminate\Http\Client\Factory as HttpFactory;
use Illuminate\Http\Client\Request;

beforeEach(function (): void {
    $this->ctx = new EncryptionContext('tenant', 42);
});

function makeVaultProvider(HttpFactory $http): VaultTransitKekProvider
{
    return new VaultTransitKekProvider(
        http: $http,
        address: 'https://vault.example.test',
        keyName: 'sealcraft',
        tokenResolver: fn (): string => 'test-token',
        mount: 'transit',
    );
}

it('wraps a DEK and extracts the vault version from ciphertext', function (): void {
    $http = new HttpFactory;
    $http->fake([
        'vault.example.test/v1/transit/encrypt/sealcraft' => $http->response([
            'data' => ['ciphertext' => 'vault:v3:abc123xyz'],
        ]),
    ]);

    $provider = makeVaultProvider($http);

    $wrapped = $provider->wrap('plain-dek', $this->ctx);

    expect($provider->name())->toBe('vault_transit');
    expect($provider->capabilities()->hasNativeAad)->toBeTrue();
    expect($wrapped->ciphertext)->toBe('vault:v3:abc123xyz');
    expect($wrapped->keyVersion)->toBe('3');
    expect($wrapped->aadStrategy)->toBe('native');
    expect($wrapped->metadata['vault_aad'])->toBe('associated_data');
});

it('sends canonical bytes as both derivation context and authenticated data', function (): void {
    $http = new HttpFactory;
    $http->fake([
        'vault.example.test/v1/transit/encrypt/sealcraft' => $http->response([
            'data' => ['ciphertext' => 'vault:v1:xx'],
        ]),
    ]);

    makeVaultProvider($http)->wrap('d', $this->ctx);

    $http->assertSent(function (Request $request): bool {
        $body = json_decode($request->body(), true);
        expect(base64_decode($body['context']))->toBe('tenant|42');
        expect(base64_decode($body['associated_data']))->toBe('tenant|42');

        return true;
    });
});

it('unwraps and returns the decoded plaintext', function (): void {
    $dek = random_bytes(32);

    $http = new HttpFactory;
    $http->fake([
        'vault.example.test/v1/transit/decrypt/sealcraft' => $http->response([
            'data' => ['plaintext' => base64_encode($dek)],
        ]),
    ]);

    $wrapped = new WrappedDek('vault:v1:xx', 'vault_transit', 'kid', '1', 'native');

    expect(makeVaultProvider($http)->unwrap($wrapped, $this->ctx))->toBe($dek);

    $http->assertSent(function (Request $request): bool {
        $body = json_decode($request->body(), true);

        return ! isset($body['associated_data']);
    });
});

it('authenticates new wrapped DEKs with Vault associated data on unwrap', function (): void {
    $http = new HttpFactory;
    $http->fake([
        'vault.example.test/v1/transit/decrypt/sealcraft' => $http->response([
            'data' => ['plaintext' => base64_encode('dek')],
        ]),
    ]);

    $wrapped = new WrappedDek('vault:v1:xx', 'vault_transit', 'kid', '1', 'native', [
        'vault_aad' => 'associated_data',
    ]);

    expect(makeVaultProvider($http)->unwrap($wrapped, $this->ctx))->toBe('dek');

    $http->assertSent(function (Request $request): bool {
        $body = json_decode($request->body(), true);

        return base64_decode($body['associated_data'] ?? '') === 'tenant|42';
    });
});
