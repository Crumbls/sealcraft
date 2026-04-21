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

it('extracts cipher ID via peekId', function (): void {
    expect(CipherRegistry::peekId('ag1:v1:iv:tag:ct'))->toBe('ag1');
    expect(CipherRegistry::peekId('xc1:v1:iv:tag:ct'))->toBe('xc1');
    expect(CipherRegistry::peekId(''))->toBeNull();
    expect(CipherRegistry::peekId('no-colon'))->toBeNull();
    expect(CipherRegistry::peekId(':leading-empty'))->toBeNull();
    expect(CipherRegistry::peekId('way-too-long-prefix:v1'))->toBeNull();
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
