# Security Policy

## Supported versions

Sealcraft is pre-1.0. Security fixes are applied to the `main` branch
and released immediately. Once a stable 1.x line ships, this document
will be updated with a concrete support window.

## Reporting a vulnerability

Please do **not** open a public GitHub issue for security reports.

Email: security@crumbls.com

Include:

- The version(s) of Sealcraft affected
- A description of the issue and its impact
- Reproduction steps or a proof of concept
- Your preferred disclosure timeline, if any

You will receive an acknowledgement within 72 hours. We aim to issue
a fix (or a documented mitigation) within 14 days for severe issues
and 30 days for moderate ones, and to coordinate public disclosure
with the reporter.

## Scope

In scope:

- Cipher, AAD, or context canonicalization bugs that could weaken
  confidentiality or authentication
- KEK provider integrations that could leak plaintext DEKs or mis-
  authenticate unwrap requests
- Crypto-shred correctness (data that should be unrecoverable becoming
  recoverable, or vice versa)
- Eloquent cast and trait behavior that could silently drop AAD
  binding or write plaintext to the database
- Rate-limit / event wiring that could mask or suppress security-
  relevant signals

Out of scope:

- Bugs in third-party dependencies (report those upstream)
- Side-channel attacks on libsodium or the host PHP runtime
- Attacks that require live code execution inside the application
  process (see the threat model in `README.md`)
- Denial of service via forced KMS calls — use your KMS provider's
  rate limits and the `rate_limit.unwrap_per_minute` config knob

## Acknowledgements

We credit reporters in release notes unless they request otherwise.
