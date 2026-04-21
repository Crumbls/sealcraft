<?php

declare(strict_types=1);

use Crumbls\Sealcraft\Exceptions\DecryptionFailedException;
use Crumbls\Sealcraft\Providers\AzureKeyVaultKekProvider;
use Crumbls\Sealcraft\Values\EncryptionContext;
use Crumbls\Sealcraft\Values\WrappedDek;
use Illuminate\Http\Client\Factory as HttpFactory;

beforeEach(function (): void {
    $this->ctx = new EncryptionContext('tenant', 42);
    $this->hmacKey = random_bytes(32);
});

function makeAzureProvider(HttpFactory $http, string $strategy, ?string $hmacKey = null): AzureKeyVaultKekProvider
{
    return new AzureKeyVaultKekProvider(
        http: $http,
        vaultUrl: 'https://vault.example.test',
        keyName: 'sealcraft-kek',
        tokenResolver: fn (): string => 'test-token',
        aadStrategy: $strategy,
        hmacKeyResolver: $hmacKey === null ? null : fn (): string => $hmacKey,
    );
}

function azureBase64UrlEncode(string $bytes): string
{
    return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
}

function azureBase64UrlDecode(string $encoded): string
{
    $pad = strlen($encoded) % 4;

    if ($pad > 0) {
        $encoded .= str_repeat('=', 4 - $pad);
    }

    return base64_decode(strtr($encoded, '-_', '+/'), true) ?: '';
}

it('reports synthetic AAD capabilities by default', function (): void {
    $http = new HttpFactory;
    $provider = makeAzureProvider($http, AzureKeyVaultKekProvider::STRATEGY_SYNTHETIC, $this->hmacKey);

    $caps = $provider->capabilities();

    expect($provider->name())->toBe('azure_kv');
    expect($caps->aadStrategy)->toBe('synthetic');
    expect($caps->hasNativeAad)->toBeTrue();
});

it('prepends HMAC to the DEK before wrap and strips on unwrap', function (): void {
    $dek = random_bytes(32);
    $capturedWrapBlob = null;

    $http = new HttpFactory;
    $http->fake([
        'vault.example.test/keys/sealcraft-kek/wrapkey*' => function ($request) use ($http, &$capturedWrapBlob) {
            $body = json_decode($request->body(), true);
            $capturedWrapBlob = azureBase64UrlDecode($body['value']);

            return $http->response([
                'value' => azureBase64UrlEncode('wrap-key-output'),
                'kid' => 'https://vault.example.test/keys/sealcraft-kek/abc123',
            ]);
        },
    ]);

    $provider = makeAzureProvider($http, AzureKeyVaultKekProvider::STRATEGY_SYNTHETIC, $this->hmacKey);

    $wrapped = $provider->wrap($dek, $this->ctx);

    expect(strlen($capturedWrapBlob))->toBe(strlen($dek) + 32);
    expect(substr($capturedWrapBlob, 0, 32))
        ->toBe(hash_hmac('sha256', $this->ctx->toCanonicalBytes(), $this->hmacKey, true));
    expect(substr($capturedWrapBlob, 32))->toBe($dek);

    expect($wrapped->aadStrategy)->toBe('synthetic');
    expect($wrapped->keyVersion)->toBe('abc123');

    // Round-trip the unwrap path.
    $unwrapPayload = hash_hmac('sha256', $this->ctx->toCanonicalBytes(), $this->hmacKey, true) . $dek;
    $http->fake([
        'vault.example.test/keys/sealcraft-kek/unwrapkey*' => $http->response([
            'value' => azureBase64UrlEncode($unwrapPayload),
        ]),
    ]);

    $stored = new WrappedDek('azure-ct', 'azure_kv', 'kid', 'abc123', 'synthetic');

    expect($provider->unwrap($stored, $this->ctx))->toBe($dek);
});

it('raises DecryptionFailedException on synthetic AAD mismatch', function (): void {
    $dek = random_bytes(32);
    $wrongPayload = hash_hmac('sha256', 'tenant|99', $this->hmacKey, true) . $dek;

    $http = new HttpFactory;
    $http->fake([
        'vault.example.test/keys/sealcraft-kek/unwrapkey*' => $http->response([
            'value' => azureBase64UrlEncode($wrongPayload),
        ]),
    ]);

    $provider = makeAzureProvider($http, AzureKeyVaultKekProvider::STRATEGY_SYNTHETIC, $this->hmacKey);

    $stored = new WrappedDek('ct', 'azure_kv', 'kid', null, 'synthetic');

    expect(fn () => $provider->unwrap($stored, $this->ctx))
        ->toThrow(DecryptionFailedException::class);
});

it('bypasses synthetic AAD under cipher_only strategy', function (): void {
    $dek = random_bytes(32);
    $capturedWrapBlob = null;

    $http = new HttpFactory;
    $http->fake([
        'vault.example.test/keys/sealcraft-kek/wrapkey*' => function ($request) use ($http, &$capturedWrapBlob) {
            $body = json_decode($request->body(), true);
            $capturedWrapBlob = azureBase64UrlDecode($body['value']);

            return $http->response([
                'value' => azureBase64UrlEncode('wrap-output'),
            ]);
        },
        'vault.example.test/keys/sealcraft-kek/unwrapkey*' => $http->response([
            'value' => azureBase64UrlEncode($dek),
        ]),
    ]);

    $provider = makeAzureProvider($http, AzureKeyVaultKekProvider::STRATEGY_CIPHER_ONLY);

    $wrapped = $provider->wrap($dek, $this->ctx);

    expect($capturedWrapBlob)->toBe($dek);
    expect($wrapped->aadStrategy)->toBe('none');

    $stored = new WrappedDek('ct', 'azure_kv', 'kid', null, 'none');
    expect($provider->unwrap($stored, $this->ctx))->toBe($dek);
});
