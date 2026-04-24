---
title: Local Provider
weight: 50
---

The `local` provider stores the KEK in a file on disk. It exists for development and test environments -- it is **not** a valid choice for production.

## Configure

```dotenv
SEALCRAFT_PROVIDER=local
SEALCRAFT_LOCAL_KEY_PATH=/path/to/storage/sealcraft/kek.key
```

If the file does not exist, the provider generates a 32-byte random key on first use.

## Production refuses to load

If `APP_ENV=production`, the provider throws unless you also set:

```dotenv
SEALCRAFT_LOCAL_ALLOW_PRODUCTION=true
```

This is a deliberate guardrail. A file-based KEK means anyone with shell access to the server can decrypt every wrapped DEK. It is not defensible under HIPAA, PCI, SOC 2, or any serious compliance review.

## Legitimate uses

- **Local development.** Developers do not need AWS credentials to run the app.
- **CI pipelines.** Integration tests can spin up a throwaway KEK.
- **Air-gapped testing.** Environments where connecting to a cloud KMS is not possible and the data is synthetic.

## Do not

- Share the key file across developers via git or Slack
- Back it up unencrypted
- Use it on a staging environment that contains real PHI or regulated data -- staging is production from a compliance standpoint if the data is real
