---
title: v1
slogan: Production-grade envelope encryption for Laravel -- KMS-backed DEK/KEK, field-level, context-bound.
githubUrl: https://github.com/crumbls/sealcraft
branch: main
---

Sealcraft implements envelope encryption for Laravel applications that need a defensible story for encryption-at-rest, key rotation, KMS integration, and right-to-be-forgotten. Built for HIPAA-adjacent apps, multi-tenant SaaS, and regulated industries.

A short-lived Data Encryption Key (DEK) encrypts your field data; a long-lived Key Encryption Key (KEK) inside a KMS wraps the DEK. Plaintext DEKs never touch disk.
