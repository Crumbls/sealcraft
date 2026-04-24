---
title: Introduction
weight: 10
---

Sealcraft is a Laravel library for encrypting specific database columns with keys wrapped by a cloud KMS  for compliance reasons. 
It runs **alongside** Laravel's built-in Crypt facade and encrypted cast.

Reach for Sealcraft when a particular column holds data that needs KMS-backed keys, documented rotation, per-tenant isolation, or cryptographic destruction on demand.

## Sealcraft vs. Laravel Crypt

Both exist. You will probably use both in the same app. The split:

| Concern | Laravel Crypt / encrypted cast | Sealcraft |
|---|---|---|
| Where the key lives | `APP_KEY` in `.env` | A KEK inside a KMS you control |
| Typical targets | Sessions, cookies, signed URLs, small casual fields | Regulated / sensitive DB columns |
| Rotation | Re-encrypt every ciphertext after `APP_KEY` rotation | Rewrap one DB row per tenant; row ciphertext untouched |
| Multi-tenant isolation | One key protects everything | One DEK per tenant (or per row); one compromise, one tenant |
| Right-to-be-forgotten | Delete rows from every table and every backup | Destroy the tenant's DEK once; ciphertext everywhere becomes permanently unrecoverable |
| Compliance story | Fine for ordinary web apps | Designed to pass HIPAA, SOC 2, PCI-adjacent reviews |

## Use cases

Concrete scenarios where teams reach for Sealcraft.

### Healthcare (HIPAA-adjacent)

- Patient SSN, date of birth, diagnosis codes, insurance IDs
- Telehealth session notes, referral letters
- Right-to-be-forgotten when a patient closes their account -- one crypto-shred call, every backup and replica goes dark for that patient

### Financial services

- Bank account numbers, ABA routing numbers, tax IDs stored for ACH operations
- Payout destination details on a marketplace
- Audit-trail fields that must remain reconstructable internally but never leave the app boundary in plaintext

### Multi-tenant SaaS

- One DEK per tenant so a stolen DB dump yields one-per-tenant unwrap attempts instead of a single `APP_KEY` unlocking every customer's data
- Per-tenant crypto-shred on cancellation or contract termination -- no more "find every row in every table for customer X"
- Isolated compliance scope: you can hand one tenant's auditor proof of their key's custody without touching any other tenant

### Identity and authentication

- Stored OAuth refresh tokens and third-party API keys
- MFA backup / recovery codes
- Passport, driver's license, national ID numbers collected for KYC
- Service-account credentials stored for scheduled integrations

### Legal and compliance platforms

- Privileged attorney-client communications
- Witness names and protected-identity fields in case-management systems
- GDPR Article 17 (right to erasure) fulfillment at scale -- crypto-shred a user's DEK and their data is cryptographically erased from warehouses, replicas, and backup tapes in one move

### Consumer apps with user-level privacy expectations

- Encrypted notes, journals, or diaries where users expect that an internal DB reader alone cannot see content
- Personal vaults (password managers, secret storage) where each vault is its own security boundary (`per_row` strategy)
- Draft messages or unsent content the user may want wiped on account deletion

### B2B SaaS with sensitive business data

- CRM contact PII (email, phone, address) in countries with strict data laws
- HR tools: salaries, DOB, home addresses, performance-review text
- Contract metadata that is sensitive even if the contract PDF itself lives elsewhere

### DevOps / platform tooling

- Webhook signing secrets, third-party API credentials stored per-tenant in an integrations table
- Encrypted columns in config stores or audit logs where key custody is owned by the platform team, not application developers

## When Laravel Crypt is enough

Sealcraft is MIT-licensed and free to use, but it does add operational surface -- a KMS to run, a rotation playbook to own, audit commands to wire into your ops rhythm, and its own concepts (context, DEK, KEK) to learn. 

Skip it when:

- The app is single-tenant and has no regulated-data story
- You don't run a KMS and have no plan to
- The field is low-sensitivity and `APP_KEY` custody is already acceptable
- You need `WHERE encrypted_col = ?` queries
- You're encrypting sessions, cookies, signed URLs, or queue payloads -- those are Crypt's job and always will be

## How it works

Envelope encryption with two layers:

- A short-lived **Data Encryption Key (DEK)** encrypts your column data
- A long-lived **Key Encryption Key (KEK)** inside your KMS wraps the DEK

The plaintext DEK is unwrapped on demand, cached in memory for the request, and overwritten with null bytes at request termination. Rotating the KEK rewraps one DB row per tenant; no column ciphertext changes. For a full walk-through, see [Architecture](/documentation/sealcraft/v1/advanced/architecture).

## Supported infrastructure

- **KMS providers**: AWS KMS, GCP Cloud KMS, Azure Key Vault, HashiCorp Vault Transit
- **Dev/test**: local file provider (refuses production without an explicit flag), null provider
- **Ciphers**: AES-256-GCM (default), XChaCha20-Poly1305 (requires `ext-sodium`)
- **Laravel**: 11, 12, 13
- **PHP**: 8.2+

## What's next

- [Installation](/documentation/sealcraft/v1/installation)
- [Getting started](/documentation/sealcraft/v1/getting-started)
- [Threat model](/documentation/sealcraft/v1/advanced/threat-model)
