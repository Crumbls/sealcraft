---
title: Provider Migration
weight: 30
---

Move DEKs between KMS providers -- for example, migrating from AWS KMS to GCP Cloud KMS during a cloud provider switch, or from Vault Transit to Azure Key Vault.

## Command

```bash
# Dry run first
php artisan sealcraft:migrate-provider --from=aws_kms --to=gcp_kms --dry-run

# Execute
php artisan sealcraft:migrate-provider --from=aws_kms --to=gcp_kms
```

For each `DataKey` wrapped under the source provider, Sealcraft:

1. Unwraps the DEK using the source provider
2. Rewraps it using the destination provider
3. Updates the `provider` column on the `DataKey` row

No row ciphertext changes. Reads continue to work before, during, and after migration.

## Prerequisites

- Both providers are configured and credentialed on the running host
- The destination KEK already exists and has the right IAM / RBAC
- Enough runtime for both providers' SDKs / HTTP clients to operate concurrently

## Two-phase migration

For a clean cutover:

1. Configure both providers. Set the new one as `default_provider`.
2. Run `sealcraft:migrate-provider --from=old --to=new`.
3. Run `sealcraft:audit` to confirm every DataKey is on the new provider.
4. Decommission the old provider's KEK access.

## Partial / paused migration

If the command is interrupted, rerun it. It is idempotent -- already-migrated DEKs are skipped.

## Event

`DekRotated` fires for each DataKey that changed providers. If your audit log needs to distinguish provider migration from KEK rotation, inspect the event's `from` and `to` fields.
