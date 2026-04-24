---
title: GCP Cloud KMS
weight: 20
---

Google Cloud KMS supports native AAD and automatic key versioning. Credentials come from a bound token resolver so you can plug in ADC, workload identity, or a short-lived impersonation token.

## Install the SDK

```bash
composer require google/cloud-kms
```

## Configure

```dotenv
SEALCRAFT_PROVIDER=gcp_kms
SEALCRAFT_GCP_PROJECT=my-project
SEALCRAFT_GCP_LOCATION=us-east1
SEALCRAFT_GCP_KEY_RING=my-ring
SEALCRAFT_GCP_CRYPTO_KEY=app-kek
```

## Token resolver

Bind a callable that returns a fresh OAuth 2.0 access token for the KMS scope:

```php
use Illuminate\Support\Facades\Config;

Config::set(
    'sealcraft.providers.gcp_kms.token_resolver',
    fn (): string => GcpAuth::freshAccessToken(),
);
```

The resolver runs on every unwrap that misses the DEK cache, so cache the token yourself for the duration of its lifetime. Google's ADC library handles this automatically if you use `Google\Auth\ApplicationDefaultCredentials::getCredentials()`.

## IAM permissions

Grant the service account running your app:

- `roles/cloudkms.cryptoKeyEncrypterDecrypter` on the specific crypto key

Do not grant `roles/cloudkms.admin` or project-level KMS roles in production.

## KEK rotation

GCP Cloud KMS supports automatic rotation via `--rotation-period`. New primary versions are created on schedule; `sealcraft:rotate-kek` rewraps each DEK under the current primary.

Legacy versions remain decryptable until explicitly disabled, so rotation is zero-downtime.
