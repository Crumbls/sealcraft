<?php

declare(strict_types=1);

use Aws\Command;
use Aws\Exception\AwsException;
use Aws\Kms\KmsClient;
use Aws\Result;
use Crumbls\Sealcraft\Exceptions\DecryptionFailedException;
use Crumbls\Sealcraft\Exceptions\KekUnavailableException;
use Crumbls\Sealcraft\Providers\AwsKmsKekProvider;
use Crumbls\Sealcraft\Values\EncryptionContext;
use Crumbls\Sealcraft\Values\WrappedDek;
use Mockery\MockInterface;

function mockKmsClient(): KmsClient&MockInterface
{
    return Mockery::mock(KmsClient::class);
}

beforeEach(function (): void {
    $this->ctx = new EncryptionContext('tenant', 42);
    $this->keyId = 'alias/sealcraft-test';
});

it('reports the expected name and capabilities', function (): void {
    $provider = new AwsKmsKekProvider(mockKmsClient(), $this->keyId);

    $caps = $provider->capabilities();

    expect($provider->name())->toBe('aws_kms');
    expect($provider->currentKeyId())->toBe($this->keyId);
    expect($caps->generatesDataKeys)->toBeTrue();
    expect($caps->hasNativeAad)->toBeTrue();
    expect($caps->supportsKeyVersioning)->toBeTrue();
    expect($caps->aadStrategy)->toBe('native');
});

it('generates a DataKeyPair via GenerateDataKey with encryption context', function (): void {
    $plaintextDek = random_bytes(32);
    $ciphertext = 'aws-wrapped-bytes';

    $client = mockKmsClient();
    $client->shouldReceive('generateDataKey')
        ->once()
        ->with(Mockery::on(function (array $args): bool {
            expect($args['KeyId'])->toBe('alias/sealcraft-test');
            expect($args['NumberOfBytes'])->toBe(32);
            expect($args['EncryptionContext'])->toBe(['ctx_type' => 'tenant', 'ctx_id' => '42']);

            return true;
        }))
        ->andReturn(new Result([
            'Plaintext' => $plaintextDek,
            'CiphertextBlob' => $ciphertext,
            'KeyId' => 'arn:aws:kms:us-east-1:000:key/abcd',
        ]));

    $provider = new AwsKmsKekProvider($client, $this->keyId);

    $pair = $provider->generateDataKey($this->ctx);

    expect($pair->plaintext)->toBe($plaintextDek);
    expect($pair->wrapped->ciphertext)->toBe($ciphertext);
    expect($pair->wrapped->providerName)->toBe('aws_kms');
    expect($pair->wrapped->keyId)->toBe('arn:aws:kms:us-east-1:000:key/abcd');
    expect($pair->wrapped->aadStrategy)->toBe('native');
});

it('unwraps via Decrypt with encryption context', function (): void {
    $plaintextDek = random_bytes(32);

    $client = mockKmsClient();
    $client->shouldReceive('decrypt')
        ->once()
        ->with(Mockery::on(function (array $args): bool {
            expect($args['CiphertextBlob'])->toBe('wrapped-bytes');
            expect($args['EncryptionContext'])->toBe(['ctx_type' => 'tenant', 'ctx_id' => '42']);

            return true;
        }))
        ->andReturn(new Result(['Plaintext' => $plaintextDek]));

    $provider = new AwsKmsKekProvider($client, $this->keyId);

    $wrapped = new WrappedDek(
        ciphertext: 'wrapped-bytes',
        providerName: 'aws_kms',
        keyId: $this->keyId,
        keyVersion: null,
        aadStrategy: 'native',
    );

    expect($provider->unwrap($wrapped, $this->ctx))->toBe($plaintextDek);
});

it('raises DecryptionFailedException on InvalidCiphertextException', function (): void {
    $client = mockKmsClient();
    $client->shouldReceive('decrypt')
        ->andThrow(new AwsException(
            'bad ciphertext',
            new Command('Decrypt'),
            ['code' => 'InvalidCiphertextException'],
        ));

    $provider = new AwsKmsKekProvider($client, $this->keyId);

    $wrapped = new WrappedDek(
        ciphertext: 'bad',
        providerName: 'aws_kms',
        keyId: $this->keyId,
        keyVersion: null,
        aadStrategy: 'native',
    );

    expect(fn () => $provider->unwrap($wrapped, $this->ctx))
        ->toThrow(DecryptionFailedException::class);
});

it('raises KekUnavailableException on non-auth errors', function (): void {
    $client = mockKmsClient();
    $client->shouldReceive('decrypt')
        ->andThrow(new AwsException(
            'access denied',
            new Command('Decrypt'),
            ['code' => 'AccessDeniedException'],
        ));

    $provider = new AwsKmsKekProvider($client, $this->keyId);

    $wrapped = new WrappedDek(
        ciphertext: 'bytes',
        providerName: 'aws_kms',
        keyId: $this->keyId,
        keyVersion: null,
        aadStrategy: 'native',
    );

    expect(fn () => $provider->unwrap($wrapped, $this->ctx))
        ->toThrow(KekUnavailableException::class);
});

it('retries up to three times on ThrottlingException then succeeds', function (): void {
    $plaintextDek = random_bytes(32);

    $client = mockKmsClient();
    $client->shouldReceive('decrypt')
        ->twice()
        ->andThrow(new AwsException(
            'throttled',
            new Command('Decrypt'),
            ['code' => 'ThrottlingException'],
        ));

    $client->shouldReceive('decrypt')
        ->once()
        ->andReturn(new Result(['Plaintext' => $plaintextDek]));

    $provider = new AwsKmsKekProvider($client, $this->keyId);

    $wrapped = new WrappedDek(
        ciphertext: 'bytes',
        providerName: 'aws_kms',
        keyId: $this->keyId,
        keyVersion: null,
        aadStrategy: 'native',
    );

    expect($provider->unwrap($wrapped, $this->ctx))->toBe($plaintextDek);
});
