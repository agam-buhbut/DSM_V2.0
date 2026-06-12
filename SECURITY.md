# Security Policy

DSM is security-sensitive software: it is a VPN / network-anonymity tool, and
people may rely on it to protect traffic from a passive observer, an active
on-path adversary, and even a compromised server. We take vulnerability reports
seriously and appreciate responsible disclosure.

## Supported Versions

DSM has not yet had a stable release. Security fixes are provided only for the
current pre-release line.

| Version            | Supported          |
|--------------------|--------------------|
| `v0.1.0` (pre-release) | :white_check_mark: |
| anything older     | :x:                |

Because there is no stable release yet, all users should track the latest
`v0.1.x` pre-release.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report privately through one of the following channels:

<!-- TODO(maintainer): set a real security contact before public release.
     Recommended: enable GitHub Security Advisories ("Report a vulnerability"
     under the repository Security tab) AND publish a dedicated contact address
     such as security@<project-domain>. Replace the placeholder below with the
     real address and remove this comment. -->

- Preferred: GitHub Security Advisories — use the repository's **Security →
  Report a vulnerability** workflow (private to maintainers).
- Email: `SECURITY-CONTACT-PLACEHOLDER` (maintainer must configure a real
  address before public release).

Please include:

- A description of the issue and the impact you believe it has.
- Steps to reproduce, a proof of concept, or the affected code path.
- The version / commit you tested against and your environment.
- Any suggested remediation, if you have one.

If possible, encrypt sensitive details; a contact key will be published
alongside the real security address.

## Response Expectations

This is a small, best-effort project. As a target:

- **Acknowledgement:** within 7 days of your report.
- **Initial assessment / triage:** within 14 days.
- **Fix or mitigation plan:** communicated as soon as the severity and scope
  are understood; timelines depend on complexity.

We will keep you informed of progress and coordinate a disclosure timeline with
you. Please give us a reasonable window to ship a fix before any public
disclosure.

## Scope

In scope are weaknesses that undermine DSM's intended security and anonymity
properties, including (non-exhaustively):

- Cryptographic correctness: handshake, key derivation, key lifecycle,
  zeroization, rekeying.
- Authentication and identity binding (certificate handling, pinning, the
  Noise static-key binding).
- Confidentiality / integrity of tunneled traffic.
- Anonymity and traffic-analysis resistance beyond the documented accepted
  risks below.
- Memory-safety or denial-of-service issues in the data path, including the
  native `tuncore` extension.
- Network-integration safety (kill switch, nftables rules, DNS handling,
  `resolv.conf` and sysctl restoration).

## Known and Accepted v1 Risks (not vulnerabilities)

The following are **documented, accepted limitations** of the current design,
not vulnerabilities. Reports describing only these will be acknowledged but
closed as known:

- **Boot / handshake fingerprint.** The connection-establishment phase emits a
  recognizable traffic pattern before cover traffic is active, allowing an
  observer to identify that DSM is in use. Masking pre-key traffic is
  post-v1 research.
- **TCP traffic-analysis caveat.** DSM's adaptive-envelope shaping bounds, but
  does not perfectly eliminate, traffic-analysis signal during active periods.
  The anonymity claim is scoped accordingly; perfect indistinguishability under
  a global passive adversary is not promised.

These are described in the project's threat-model documentation. If you believe
a property is materially worse than documented — or that one of these can be
escalated into a stronger attack — that **is** in scope; please report it.

## Out of Scope

- Attacks requiring a pre-compromised local host or stolen device (not part of
  the v1 threat model).
- Issues in third-party dependencies that do not affect DSM as deployed
  (please report those upstream).
- Social-engineering, physical attacks, and operator misconfiguration outside
  the documented deployment guide.
