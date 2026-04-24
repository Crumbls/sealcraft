---
title: AWS KMS
weight: 10
---

AWS Key Management Service is the most mature and most commonly deployed production provider. Native AAD support, built-in key versioning, IAM-scoped access.

## Install the SDK

```bash
composer require aws/aws-sdk-php
```

## Configure

```dotenv
SEALCRAFT_PROVIDER=aws_kms
SEALCRAFT_AWS_KEY_ID=alias/my-app-kek
SEALCRAFT_AWS_REGION=us-east-1
```

The provider uses the standard AWS credential chain (environment variables, shared profile, IRSA on EKS, or an EC2/ECS instance role). No separate credential config is needed in Sealcraft.

## IAM permissions

The IAM identity Sealcraft runs under needs:

- `kms:Encrypt`
- `kms:Decrypt`
- `kms:GenerateDataKey` (only if you use `sealcraft:generate-dek`)
- `kms:DescribeKey` (for `sealcraft:rotate-kek`, to read `KeyMetadata.KeyId` version)

Scope the policy to the specific key alias or ARN. Do not grant `kms:*`.

## KEK rotation

AWS KMS supports automatic annual key rotation (`EnableKeyRotation`). When enabled, AWS rotates the backing key material every year, and `DescribeKey` surfaces the new backing key ID. Sealcraft's `sealcraft:rotate-kek` picks up the new version and rewraps each DEK.

You can also run `sealcraft:rotate-kek` on demand after an access incident or staff change.

## Notes

- Cross-region replication of the KEK is your responsibility. Sealcraft binds a DEK to one KEK at a time; if you need multi-region reads, use the same KEK alias in each region and rely on AWS multi-region keys.
- KMS request quotas are per-region (default 10000 req/s for `Encrypt`/`Decrypt`). Sealcraft's in-memory DEK cache keeps steady-state requests far below this, but batch backfills should throttle.
