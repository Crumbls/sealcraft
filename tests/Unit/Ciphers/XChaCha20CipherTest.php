<?php

declare(strict_types=1);

use Crumbls\Sealcraft\Ciphers\XChaCha20Cipher;
use Crumbls\Sealcraft\Exceptions\DecryptionFailedException;
use Crumbls\Sealcraft\Exceptions\SealcraftException;

beforeEach(function (): void {
    if (! function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_encrypt')) {
        $this->markTestSkipped('ext-sodium is not available.');
    }

    $this->cipher = new XChaCha20Cipher;
    $this->dek = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES);
    $this->aad = 'tenant|42';
});

it('round-trips plaintext through encrypt/decrypt', function (string $plaintext): void {
    $ciphertext = $this->cipher->encrypt($plaintext, $this->dek, $this->aad);
    $restored = $this->cipher->decrypt($ciphertext, $this->dek, $this->aad);

    expect($restored)->toBe($plaintext);
})->with([
    'empty' => '',
    'single char' => 'a',
    'short ascii' => 'hello world',
    'utf-8' => "caf\u{00E9} rendered fine",
    'binary-ish' => "\x00\x01\x02\x03\xFF\xFE",
    'medium 1 KB' => str_repeat('x', 1024),
    'large 256 KB' => str_repeat('y', 256 * 1024),
]);

it('fails decryption on AAD mismatch', function (): void {
    $ciphertext = $this->cipher->encrypt('secret', $this->dek, $this->aad);

    expect(fn () => $this->cipher->decrypt($ciphertext, $this->dek, 'tenant|99'))
        ->toThrow(DecryptionFailedException::class);
});

it('fails decryption on DEK mismatch', function (): void {
    $ciphertext = $this->cipher->encrypt('secret', $this->dek, $this->aad);

    expect(fn () => $this->cipher->decrypt($ciphertext, random_bytes(32), $this->aad))
        ->toThrow(DecryptionFailedException::class);
});

it('rejects ciphertext with a foreign cipher id prefix', function (): void {
    expect(fn () => $this->cipher->decrypt('ag1:v1:abc:def', $this->dek, $this->aad))
        ->toThrow(DecryptionFailedException::class);
});

it('rejects DEKs of the wrong length', function (): void {
    expect(fn () => $this->cipher->encrypt('x', random_bytes(16), $this->aad))
        ->toThrow(SealcraftException::class);
});

it('emits ciphertext with the xc1 id prefix', function (): void {
    $ciphertext = $this->cipher->encrypt('x', $this->dek, $this->aad);

    expect($ciphertext)->toStartWith('xc1:v1:');
});

it('reports stable name, id, and key size', function (): void {
    expect($this->cipher->name())->toBe('xchacha20-poly1305');
    expect($this->cipher->id())->toBe('xc1');
    expect($this->cipher->keyBytes())->toBe(32);
});
