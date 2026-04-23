<?php

declare(strict_types=1);

use Crumbls\Sealcraft\Ciphers\AesGcmCipher;
use Crumbls\Sealcraft\Contracts\Cipher;
use Crumbls\Sealcraft\Exceptions\SealcraftException;
use Crumbls\Sealcraft\Services\CipherRegistry;

beforeEach(function (): void {
    $this->registry = $this->app->make(CipherRegistry::class);
});

it('resolves the configured default cipher', function (): void {
    $cipher = $this->registry->cipher();

    expect($cipher)->toBeInstanceOf(AesGcmCipher::class);
});

it('resolves ciphers by 3-char ID', function (): void {
    $cipher = $this->registry->cipherById('ag1');

    expect($cipher)->toBeInstanceOf(AesGcmCipher::class);
});

it('throws when no cipher is registered for an unknown ID', function (): void {
    expect(fn () => $this->registry->cipherById('zz9'))
        ->toThrow(SealcraftException::class);
});

it('memoizes resolved ciphers', function (): void {
    $a = $this->registry->cipher('aes-256-gcm');
    $b = $this->registry->cipher('aes-256-gcm');

    expect($a)->toBe($b);
});

it('extracts cipher ID via peekId for valid envelopes with registered ciphers', function (): void {
    expect($this->registry->peekId('ag1:v1:AAAA:BBBB:CCCC'))->toBe('ag1');
});

it('returns null from peekId for non-envelope inputs', function (): void {
    expect($this->registry->peekId(''))->toBeNull();
    expect($this->registry->peekId('no-colon'))->toBeNull();
    expect($this->registry->peekId(':leading-empty'))->toBeNull();
    expect($this->registry->peekId('way-too-long-prefix:v1'))->toBeNull();
});

it('returns null from peekId for non-ciphertext values that have a colon prefix', function (): void {
    // The bug fixed in v0.1.4: any string with a short colon prefix used to
    // be misreported as ciphertext. These are all real-world examples that
    // tripped the legacy-plaintext-backfill flow at consumers.
    expect($this->registry->peekId('data:image/png;base64,iVBORw0KGgo'))->toBeNull();
    expect($this->registry->peekId('http://example.com'))->toBeNull();
    expect($this->registry->peekId('https://example.com/path'))->toBeNull();
    expect($this->registry->peekId('"{"foo":"bar"}"'))->toBeNull();
    expect($this->registry->peekId('mailto:alice@example.com'))->toBeNull();
});

it('returns null from peekId for envelope-shaped strings whose prefix is not a registered cipher', function (): void {
    expect($this->registry->peekId('xyz:v1:AAAA:BBBB:CCCC'))->toBeNull();
});

it('returns null from peekId when prefix is registered but envelope is malformed', function (): void {
    expect($this->registry->peekId('ag1:not-a-real-envelope'))->toBeNull();
    expect($this->registry->peekId('ag1:v1:only-one-segment'))->toBeNull();
    expect($this->registry->peekId('ag1:vX:AAAA:BBBB:CCCC'))->toBeNull();
});

it('extracts cipher ID via peekId for xchacha envelopes when sodium is loaded', function (): void {
    if (! extension_loaded('sodium')) {
        $this->markTestSkipped('ext-sodium not installed; xc1 driver is unavailable.');
    }

    // xc1 emits 4-segment envelopes (id:v:nonce:body) — peekId allows 2+ trailing chunks.
    expect($this->registry->peekId('xc1:v1:AAAAAAAAAAAAAAAAAAAAAAAA:BBBB'))->toBe('xc1');
});

it('peekIdUnsafe preserves the legacy prefix-only behavior for BC', function (): void {
    // Deprecated shim — keeps the v0.1.3 behavior so consumers that relied on
    // the static call can opt into it explicitly during their migration.
    expect(CipherRegistry::peekIdUnsafe('ag1:v1:iv:tag:ct'))->toBe('ag1');
    expect(CipherRegistry::peekIdUnsafe('data:image/png'))->toBe('data');
    expect(CipherRegistry::peekIdUnsafe('no-colon'))->toBeNull();
    expect(CipherRegistry::peekIdUnsafe(''))->toBeNull();
});

it('allows registering custom cipher drivers via extend', function (): void {
    $fake = new class implements Cipher
    {
        public function name(): string
        {
            return 'fake';
        }

        public function id(): string
        {
            return 'fk1';
        }

        public function keyBytes(): int
        {
            return 32;
        }

        public function encrypt(string $plaintext, string $dek, string $aad): string
        {
            return 'fk1:v1:' . base64_encode($plaintext);
        }

        public function decrypt(string $ciphertext, string $dek, string $aad): string
        {
            return base64_decode(substr($ciphertext, 7)) ?: '';
        }
    };

    config()->set('sealcraft.ciphers.fake', ['driver' => 'fake_driver']);
    $this->registry->extend('fake_driver', fn (): Cipher => $fake);

    expect($this->registry->cipher('fake'))->toBe($fake);
    expect($this->registry->cipherById('fk1'))->toBe($fake);
});
