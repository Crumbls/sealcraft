<?php

declare(strict_types=1);

use Crumbls\Sealcraft\Providers\GcpCloudKmsKekProvider;
use Crumbls\Sealcraft\Values\EncryptionContext;
use Crumbls\Sealcraft\Values\WrappedDek;
use Illuminate\Http\Client\Factory as HttpFactory;
use Illuminate\Http\Client\Request;

beforeEach(function (): void {
    $this->ctx = new EncryptionContext('tenant', 42);
});

function makeGcpProvider(HttpFactory $http): GcpCloudKmsKekProvider
{
    return new GcpCloudKmsKekProvider(
        http: $http,
        project: 'sealcraft-test',
        location: 'us-east1',
        keyRing: 'ring',
        cryptoKey: 'kek',
        tokenResolver: fn (): string => 'test-token',
        baseUrl: 'https://cloudkms.example.test',
    );
}

it('wraps and reports the expected capabilities', function (): void {
    $http = new HttpFactory;
    $http->fake([
        'cloudkms.example.test/*:encrypt' => $http->response([
            'name' => 'projects/sealcraft-test/locations/us-east1/keyRings/ring/cryptoKeys/kek/cryptoKeyVersions/7',
            'ciphertext' => base64_encode('wrapped-bytes'),
        ]),
    ]);

    $provider = makeGcpProvider($http);

    expect($provider->name())->toBe('gcp_kms');
    expect($provider->capabilities()->generatesDataKeys)->toBeFalse();
    expect($provider->capabilities()->hasNativeAad)->toBeTrue();
    expect($provider->capabilities()->aadStrategy)->toBe('native');

    $wrapped = $provider->wrap('plain-dek-bytes-32-bytes-padding!', $this->ctx);

    expect($wrapped->ciphertext)->toBe('wrapped-bytes');
    expect($wrapped->providerName)->toBe('gcp_kms');
    expect($wrapped->keyVersion)->toBe('7');
    expect($wrapped->aadStrategy)->toBe('native');
});

it('sends the canonical context as additionalAuthenticatedData', function (): void {
    $http = new HttpFactory;
    $http->fake([
        'cloudkms.example.test/*' => $http->response([
            'name' => 'projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1',
            'ciphertext' => base64_encode('ct'),
        ]),
    ]);

    makeGcpProvider($http)->wrap('d', $this->ctx);

    $http->assertSent(function (Request $request): bool {
        $body = json_decode($request->body(), true);
        expect(base64_decode($body['additionalAuthenticatedData']))->toBe('tenant|42');

        return true;
    });
});

it('unwraps and returns the decoded plaintext', function (): void {
    $dek = random_bytes(32);

    $http = new HttpFactory;
    $http->fake([
        'cloudkms.example.test/*:decrypt' => $http->response([
            'plaintext' => base64_encode($dek),
        ]),
    ]);

    $wrapped = new WrappedDek('wrapped', 'gcp_kms', 'key', null, 'native');

    expect(makeGcpProvider($http)->unwrap($wrapped, $this->ctx))->toBe($dek);
});
