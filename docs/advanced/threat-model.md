---
title: Threat Model
weight: 20
---

What Sealcraft protects against, and what it does not. Read this before your security review reads it.

## What Sealcraft protects against

### Database-at-rest theft

Attackers with a stolen DB dump, backup tape, or replica snapshot see only ciphertext. The KEK lives in the KMS, not the DB; the DEK is never persisted in plaintext. Reconstruction requires the KMS, which is a separate compromise.

### Cross-context ciphertext replay

An attacker who swaps ciphertext from one tenant onto another tenant's row gets an authentication failure at decrypt time. The AAD binding catches it because the row's context is cryptographically tied to the ciphertext.

### KMS enumeration

The per-context unwrap rate limit (`sealcraft.rate_limit.unwrap_per_minute`) blunts attacks that try to bulk-enumerate wrapped DEKs through a compromised KMS network path. Legitimate traffic sits well under the limit because of the DEK cache.

### Right-to-be-forgotten requests

Crypto-shred instantly makes a user's data unrecoverable without requiring row-level deletion across every table, backup, audit log, warehouse, and replica. See [Crypto-shred](/documentation/sealcraft/v1/key-management/crypto-shred).

## What Sealcraft does NOT protect against

### Live application compromise

If an attacker executes code inside your Laravel process, they can call `KeyManager` like any other service. Plaintext DEKs live in request memory by design; there is no TEE or HSM-fronted plaintext boundary. Mitigate with defense-in-depth at the application layer (CSP, input validation, dependency scanning).

### KMS compromise combined with DB access

If an attacker steals both the DB and your KMS credentials, they can unwrap DEKs. AAD binding narrows the blast radius -- they still need the matching context -- but it is not a complete mitigation. Treat KMS credential compromise as a full data breach.

### Plaintext in logs, cache, queues, or error reports

Sealcraft only encrypts DB columns. Anything you pass through `dd()`, `Log::info()`, queue payloads, a stack trace, or a bug report is your responsibility. Do not log PHI. Scrub exception handlers.

### Key custody policy

Sealcraft manages wrapping and unwrapping. It does not decide who can access the KEK in your KMS. Lock that down with IAM, managed identities, least-privilege policies, and approval workflows.

## Minimum secure deployment

- Production provider is a cloud KMS (AWS / GCP / Azure / Vault), not `local`
- Rate limit set (`SEALCRAFT_UNWRAP_RATE=60` or similar)
- Events wired to an audit log (at minimum: `DekShredded`, `DecryptionFailed`, `ContextReencrypted`)
- Backup of `sealcraft_data_keys` is not automatically restored without a human-in-the-loop review (otherwise you un-shred deleted users)
- Log scrubbing in place for Sealcraft-encrypted columns
