---
name: Bug report
about: Report a reproducible problem in DSM
title: "[bug] "
labels: bug
assignees: ""
---

<!--
SECURITY ISSUES DO NOT BELONG HERE. If this is a vulnerability, stop and
follow the private process in SECURITY.md — do not open a public issue.

Never paste secrets or PII into this issue:
    - private keys, passphrases, or sealed/wrapped key blobs
    - configs containing real IPs, certificates, CA roots, or SPKI pins
    - TPM attestation blobs or device certificates
    Redact everything. Use placeholder values. When in doubt, leave it out.
-->

## Summary

A clear, one-or-two-sentence description of the bug.

## Environment

- DSM version / commit:
- Role: server / client
- OS + version (e.g. Debian 12, Ubuntu 22.04):
- Arch (`uname -m`):
- Build flavor: TPM (`tpm-attest`) / eval (`dev-soft-attest`)
- TPM present: yes / no (swtpm / hardware / none)

## Steps to reproduce

1.
2.
3.

## Expected behavior

What you expected to happen.

## Actual behavior

What actually happened.

## Logs / output

<!-- Paste RELEVANT, REDACTED log lines only. Strip keys, certs, CNs, real
     IPs, and any attest blobs before pasting. -->

```
(redacted logs here)
```

## Additional context

Anything else that might help — config diffs (redacted), network topology,
recent changes, etc.
