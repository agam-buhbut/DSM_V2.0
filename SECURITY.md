# Security Policy

DSM is a VPN and network-anonymity tool. The server terminates the tunnel and is
assumed operator-owned: it sees the client's source IP and the decrypted traffic,
so DSM promises no confidentiality against the server operator. The device
attestation and certificate binding still hold against a misbehaving server; see
the README threat model for the full split.

## Supported Versions

DSM has not yet had a stable release. Security fixes are provided only for the
current pre-release line.

Only the current pre-release line, `v0.1.0`, receives security fixes.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report privately through one of the following channels:

- Preferred: GitHub Security Advisories — use the repository's **Security →
  Report a vulnerability** workflow (private to maintainers).
- Email: `252506444+agam-buhbut@users.noreply.github.com`

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
- **Traffic-analysis limits.** DSM's tier shaper sends packets at a steady
  rate that only changes in a few fixed steps, so a watcher sees which step
  you are on, not your real traffic. It does not hide everything: the step
  itself shows roughly how much you send; the packet counter at the start of
  every packet is not encrypted and links your traffic across port changes;
  someone who watches both your connection and your server's internet side
  can line up your real busy periods; and in TCP mode the TCP connection
  itself stays visible. Perfect hiding from someone who can watch the whole
  internet is not promised.
- **Slow-link auto cap.** Anyone who can congest the path for a few
  seconds, so that 5% or more of your packets are lost, can lower your top
  tier for minutes. They need no place on the path: flooding a link on the
  way, for example your access link, is enough. Junk sent to the DSM host
  itself no longer counts as loss. It only costs speed: never below tier 1,
  at most an hour per step, fresh with each connection, logged (`auto cap:`
  lines), and `shaper_auto_cap = false` turns it off. A quick step down a
  few seconds after a climb also shows a watcher when your link fills up.
  A small, steady trickle of junk (about 2 packets a second) at an end's
  DSM port turns auto cap off for the packets sent to that end for as long
  as it lasts; that only brings back the behaviour from before auto cap
  (no cap), so it costs speed on slow links, not privacy.

These are described in the project's threat-model documentation. If you believe
a property is materially worse than documented — or that one of these can be
escalated into a stronger attack — that is in scope; please report it.

## Out of Scope

- Attacks requiring a pre-compromised local host or stolen device (not part of
  the v1 threat model).
- Issues in third-party dependencies that do not affect DSM as deployed
  (please report those upstream).
- Social-engineering, physical attacks, and operator misconfiguration outside
  the documented deployment guide.
