<?php

declare(strict_types=1);

use Crumbls\Sealcraft\Ciphers\AesGcmCipher;
use Crumbls\Sealcraft\Exceptions\DecryptionFailedException;
use Crumbls\Sealcraft\Exceptions\SealcraftException;

beforeEach(function (): void {
    $this->cipher = new AesGcmCipher;
    $this->dek = random_bytes(32);
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
    'large 1 MB' => str_repeat('y', 1024 * 1024),
]);

it('produces different ciphertexts for identical inputs (random IV)', function (): void {
    $a = $this->cipher->encrypt('same', $this->dek, $this->aad);
    $b = $this->cipher->encrypt('same', $this->dek, $this->aad);

    expect($a)->not->toBe($b);
});

it('fails decryption with a mismatched AAD', function (): void {
    $ciphertext = $this->cipher->encrypt('secret', $this->dek, $this->aad);

    expect(fn () => $this->cipher->decrypt($ciphertext, $this->dek, 'tenant|99'))
        ->toThrow(DecryptionFailedException::class);
});

it('fails decryption with a mismatched DEK', function (): void {
    $ciphertext = $this->cipher->encrypt('secret', $this->dek, $this->aad);

    expect(fn () => $this->cipher->decrypt($ciphertext, random_bytes(32), $this->aad))
        ->toThrow(DecryptionFailedException::class);
});

it('rejects ciphertext with a tampered body', function (): void {
    $ciphertext = $this->cipher->encrypt('secret', $this->dek, $this->aad);
    $parts = explode(':', $ciphertext);
    $body = base64_decode($parts[4], true);
    $tampered = substr_replace($body, chr(ord($body[0]) ^ 0x01), 0, 1);
    $parts[4] = base64_encode($tampered);

    expect(fn () => $this->cipher->decrypt(implode(':', $parts), $this->dek, $this->aad))
        ->toThrow(DecryptionFailedException::class);
});

it('rejects ciphertext with a tampered auth tag', function (): void {
    $ciphertext = $this->cipher->encrypt('secret', $this->dek, $this->aad);
    $parts = explode(':', $ciphertext);
    $tag = base64_decode($parts[3], true);
    $tampered = substr_replace($tag, chr(ord($tag[0]) ^ 0x01), 0, 1);
    $parts[3] = base64_encode($tampered);

    expect(fn () => $this->cipher->decrypt(implode(':', $parts), $this->dek, $this->aad))
        ->toThrow(DecryptionFailedException::class);
});

it('rejects ciphertext with a foreign cipher ID prefix', function (): void {
    expect(fn () => $this->cipher->decrypt('xc1:v1:abc:def:ghi', $this->dek, $this->aad))
        ->toThrow(DecryptionFailedException::class);
});

it('rejects ciphertext with an unsupported format version', function (): void {
    expect(fn () => $this->cipher->decrypt('ag1:v9:abc:def:ghi', $this->dek, $this->aad))
        ->toThrow(DecryptionFailedException::class);
});

it('rejects DEKs of the wrong length', function (): void {
    expect(fn () => $this->cipher->encrypt('x', random_bytes(16), $this->aad))
        ->toThrow(SealcraftException::class);
});

it('reports stable cipher name, id, and key size', function (): void {
    expect($this->cipher->name())->toBe('aes-256-gcm');
    expect($this->cipher->id())->toBe('ag1');
    expect($this->cipher->keyBytes())->toBe(32);
});

it('emits ciphertext with the ag1 id prefix', function (): void {
    $ciphertext = $this->cipher->encrypt('x', $this->dek, $this->aad);

    expect($ciphertext)->toStartWith('ag1:v1:');
});
