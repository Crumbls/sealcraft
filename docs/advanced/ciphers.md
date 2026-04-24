---
title: Ciphers
weight: 10
---

Sealcraft ships two cipher drivers. Both are authenticated (AEAD) and bind the encryption context as AAD.

## AES-256-GCM (default)

`Crumbls\Sealcraft\Ciphers\AesGcmCipher`

- 256-bit key, 96-bit nonce, 128-bit auth tag
- Implemented via PHP's built-in `openssl_encrypt` with `aes-256-gcm`
- Hardware-accelerated on every modern CPU (AES-NI)
- FIPS 140-2 validated implementations are widely available

Default because it is universally available and the fastest option on common hardware.

## XChaCha20-Poly1305

`Crumbls\Sealcraft\Ciphers\XChaCha20Cipher`

- 256-bit key, 192-bit nonce, 128-bit auth tag
- Requires `ext-sodium`
- Extended nonce makes random nonces collision-resistant beyond practical attack

Choose this over AES-GCM if:

- You need large nonce space (random-nonce designs at billions+ of operations per key)
- You are worried about timing side channels in non-AES-NI environments
- Your compliance framework specifically calls out ChaCha-family ciphers

## Switching

```dotenv
SEALCRAFT_CIPHER=xchacha20
```

**Switching is not a migration.** Ciphertext already written with one cipher is tagged and stays readable by that cipher regardless of the current default. Only newly-written ciphertext uses the new default. Run a DEK rotation if you want to re-encrypt legacy data under a new cipher.

## AAD binding

Both ciphers call the same canonical context serializer, so the AAD bytes are identical regardless of cipher. Swapping ciphers does not change which contexts can decrypt which ciphertext -- only the cipher identity in the stored header.
