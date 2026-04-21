<?php

declare(strict_types=1);

use Crumbls\Sealcraft\Exceptions\InvalidContextException;
use Crumbls\Sealcraft\Values\EncryptionContext;

it('canonicalizes a simple context with no attributes', function (): void {
    $ctx = new EncryptionContext('tenant', 42);

    expect($ctx->toCanonicalBytes())->toBe('tenant|42');
});

it('sorts attribute keys by UTF-8 byte order', function (): void {
    $ctx = new EncryptionContext(
        contextType: 'tenant',
        contextId: 42,
        attributes: [
            'region' => 'us-east-1',
            'locale' => 'en_US',
            'app' => 'sealcraft',
        ],
    );

    expect($ctx->toCanonicalBytes())->toBe('tenant|42|app=sealcraft|locale=en_US|region=us-east-1');
});

it('produces identical bytes for attributes provided in different orders', function (): void {
    $a = new EncryptionContext('tenant', 42, ['b' => '1', 'a' => '2']);
    $b = new EncryptionContext('tenant', 42, ['a' => '2', 'b' => '1']);

    expect($a->toCanonicalBytes())->toBe($b->toCanonicalBytes());
});

it('strips null and empty-string attributes', function (): void {
    $a = new EncryptionContext('tenant', 42, ['a' => '1', 'b' => null, 'c' => '']);
    $b = new EncryptionContext('tenant', 42, ['a' => '1']);

    expect($a->toCanonicalBytes())->toBe($b->toCanonicalBytes());
});

it('coerces int contextId to decimal string', function (): void {
    $fromInt = new EncryptionContext('tenant', 42);
    $fromString = new EncryptionContext('tenant', '42');

    expect($fromInt->toCanonicalBytes())->toBe($fromString->toCanonicalBytes());
});

it('coerces bool attributes to lowercase true/false', function (): void {
    $ctx = new EncryptionContext('tenant', 1, ['active' => true, 'archived' => false]);

    expect($ctx->toCanonicalBytes())->toBe('tenant|1|active=true|archived=false');
});

it('normalizes Unicode inputs to NFC', function (): void {
    // e + combining acute accent (NFD) vs precomposed e-acute (NFC)
    $nfd = new EncryptionContext('tenant', 1, ['name' => "caf\u{0065}\u{0301}"]);
    $nfc = new EncryptionContext('tenant', 1, ['name' => "caf\u{00E9}"]);

    expect($nfd->toCanonicalBytes())->toBe($nfc->toCanonicalBytes());
});

it('escapes backslash and pipe characters in values', function (): void {
    $ctx = new EncryptionContext('tenant', 1, ['note' => 'a|b\\c']);

    expect($ctx->toCanonicalBytes())->toBe('tenant|1|note=a\\|b\\\\c');
});

it('enforces strict byte order between close keys', function (): void {
    $ctx = new EncryptionContext('tenant', 1, [
        'b' => 'x',
        'aa' => 'x',
        'a' => 'x',
    ]);

    expect($ctx->toCanonicalBytes())->toBe('tenant|1|a=x|aa=x|b=x');
});

it('produces a stable SHA-256 hash', function (): void {
    $ctx = new EncryptionContext('tenant', 42, ['k' => 'v']);

    expect($ctx->toCanonicalHash())->toBe(hash('sha256', 'tenant|42|k=v'));
});

it('rejects float values at construction', function (): void {
    expect(fn () => (new EncryptionContext('tenant', 1, ['x' => 1.5]))->toCanonicalBytes())
        ->toThrow(InvalidContextException::class);
});

it('rejects nested array attributes', function (): void {
    /** @phpstan-ignore-next-line */
    expect(fn () => (new EncryptionContext('tenant', 1, ['x' => ['nested' => 'value']]))->toCanonicalBytes())
        ->toThrow(InvalidContextException::class);
});

it('rejects object attributes', function (): void {
    /** @phpstan-ignore-next-line */
    expect(fn () => (new EncryptionContext('tenant', 1, ['x' => new stdClass]))->toCanonicalBytes())
        ->toThrow(InvalidContextException::class);
});

it('rejects invalid attribute key characters', function (): void {
    expect(fn () => (new EncryptionContext('tenant', 1, ['bad|key' => 'x']))->toCanonicalBytes())
        ->toThrow(InvalidContextException::class);

    expect(fn () => (new EncryptionContext('tenant', 1, ['bad=key' => 'x']))->toCanonicalBytes())
        ->toThrow(InvalidContextException::class);

    expect(fn () => (new EncryptionContext('tenant', 1, ['' => 'x']))->toCanonicalBytes())
        ->toThrow(InvalidContextException::class);
});

it('rejects invalid contextType', function (): void {
    expect(fn () => (new EncryptionContext('bad|type', 1))->toCanonicalBytes())
        ->toThrow(InvalidContextException::class);

    expect(fn () => (new EncryptionContext('', 1))->toCanonicalBytes())
        ->toThrow(InvalidContextException::class);
});

it('rejects empty contextId', function (): void {
    expect(fn () => (new EncryptionContext('tenant', ''))->toCanonicalBytes())
        ->toThrow(InvalidContextException::class);
});

it('rejects canonical output larger than 4096 bytes', function (): void {
    $big = str_repeat('a', 5000);

    expect(fn () => (new EncryptionContext('tenant', 1, ['big' => $big]))->toCanonicalBytes())
        ->toThrow(InvalidContextException::class);
});

it('exposes an AWS-shaped encryption context map', function (): void {
    $ctx = new EncryptionContext('tenant', 42, ['region' => 'us-east-1', 'active' => true]);

    expect($ctx->toAwsEncryptionContext())->toBe([
        'ctx_type' => 'tenant',
        'ctx_id' => '42',
        'region' => 'us-east-1',
        'active' => 'true',
    ]);
});

it('exposes raw canonical bytes to GCP and base64 to Vault Transit', function (): void {
    $ctx = new EncryptionContext('tenant', 42);

    expect($ctx->toGcpAdditionalAuthenticatedData())->toBe('tenant|42');
    expect($ctx->toVaultTransitContext())->toBe(base64_encode('tenant|42'));
});

it('computes a stable synthetic AAD HMAC for a given key', function (): void {
    $ctx = new EncryptionContext('tenant', 42);
    $key = 'hmac-key-bytes';

    expect($ctx->toSyntheticAadHmac($key))
        ->toBe(hash_hmac('sha256', 'tenant|42', $key, true));
});
