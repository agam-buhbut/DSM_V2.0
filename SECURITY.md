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
  itself shows roughly how much you send; someone who watches both your
  connection and your server's internet side can line up your real busy
  periods; and in TCP mode the TCP connection itself stays visible. Perfect
  hiding from someone who can watch the whole internet is not promised.
- **The handshake gate is a filter, not a lock (wire v2).** The server
  answers a first handshake message only if it carries a short code (called
  mac1) that shows the sender knows the CA certificate and the server's name.
  When the server is busy it also sends the sender a cookie, a code tied to
  the sender's address, and the sender must send it back to prove it can
  receive there. Anyone with the CA certificate and the server's name can
  make a valid mac1, and a captured first message stays valid for up to 15
  minutes. Such a sender gets the server's answer (its certificate), can
  take the one handshake slot an idle server gives without a cookie, or can
  use up the cookie-reply budget (20 a second) so a real client waits for
  its cookie. When the server is busy, a captured first message works only
  from its own address and port, for 2 to 4 minutes. Who gets in is
  unchanged: the certificates, the name allowlist and the CRL decide.
- **Start limits (handshakes).** Someone who has the CA certificate and
  the server's name can make new devices wait. Over UDP they can do it
  even from faked source addresses, by keeping the cookie budget empty
  while the server is busy. Over TCP it takes real addresses: about 4, or
  about 31 with the 30 s penalty.
  Over TCP, someone with nothing at all can make new devices wait too,
  but needs many addresses (about 22, or about 170 once a failed start
  costs its address 30 s).

  Right after the server starts or restarts, no device is "known" yet,
  so every device counts as new until it connects once. While such an
  attack runs then, it does not just slow devices down: it can keep every
  device out, until the attack stops and one device gets in. Over UDP
  that takes about 16 addresses (about 125 with the 30 s penalty), or no
  real address at all by keeping the cookie budget empty. Over TCP it
  takes about 22 addresses (about 170) with nothing at all, or the UDP
  numbers with the certificate and the name.

  Once a device has connected in this run, these limits no longer hold
  it back when it comes back from the same public address. Nobody can
  keep such a known device out through them unless they are behind that
  same public address, or they know that address, have the CA
  certificate and the server's name, and fake it while the server is
  busy. Even then only the devices behind that one address are hurt, and
  the replies it draws are capped.

  When all slots are busy, a stalled handshake attempt can lose its slot
  to a new one; this is called being pushed out.

  The 30 s penalty has two exceptions, by design. A start whose
  final handshake message (msg3) does not open costs its address nothing, because a faked packet slipped into a real device's handshake
  looks the same. And a start pushed out less than 1.29 s after the
  server's reply left costs nothing, because it was waiting on the
  server's TPM, not stalling. So someone who can send a valid first
  message (the CA certificate and the server's name) and ends every start
  with a bad msg3 never pays the penalty: for them the smaller numbers
  above hold, not the ones "with the 30 s penalty". Over TCP the 1.29 s
  also covers a client that held its first frame back, since the server
  signs only once that frame arrives. A faked packet that lands just
  after a real device's msg3 still costs that address 30 s; the device
  sends its next frame right behind msg3, so that gap is tiny.

  (A flood of raw packets that fills the kernel's socket buffer is a
  separate risk; see "Several clients on one server".)
- **Several clients on one server.** One Python event loop serves every
  client, so a busy or hostile client slows every client (the live tests
  measure how much). The kernel's connection table (conntrack, used for
  NAT) and the server's socket buffer are shared, with no per-client cap
  on either yet. What one enrolled device (a valid certificate on the
  allowlist, for example a stolen one) can and cannot do:
  - It **can**:
    - hold one session, for its own CN, at any tier, and retake it within
      its takeover allowance;
    - reach the internet, the server's own services on 10.8.0.1 and the
      server's LAN, as before, and through a server service also other
      clients, because traffic from the server to clients is allowed (DNS
      needs it; a known gap);
    - send valid packets as fast as its link allows, each costing the
      server about twice what junk costs (an estimate);
    - keep sending from a new port it never validates (its packets still
      arrive, at a small extra cost per session);
    - use its own DNS caps in full and fill its own buffers and queues;
    - load the server's one event loop through DNS lookups as well as
      packets (each lookup the cache cannot answer opens a new TLS
      connection upstream);
    - open many NAT flows and fill the kernel's connection table, which
      stops new flows for every client;
    - flood the shared socket, which can cost other clients packets there.
    - It **cannot**:
    - hold a second session, or one for another CN;
    - reach another client through the tunnel, or send with another
      client's tunnel address;
    - read another client's DNS answers, cache or timing;
    - take another CN's address or session (that needs the other client's
      Noise key and TPM attest key);
    - use up the DNS proxy's shared limits, or fill another session's
      queues;
    - grow server memory beyond its own session's bounds, or hold the
      handshake slots.

  A watcher of the server's traffic can count the connected clients, and
  a client at the top tier adds a little timing jitter to every other
  client's packets.
- **Many devices coming back at once.** The server's TPM signs one
  handshake at a time, about 5 a second. Devices it already knows skip the
  shared start limits, so after an outage longer than the clients' liveness
  timeout they may all come back together. Up to about 30 within a few
  seconds get in as fast as the TPM signs. Beyond that, some attempts lose
  their slot to a newer one right after the server signed for them: that
  signature is wasted, and the device tries again later (about 18 s, plus
  its own reconnect wait of up to 30 s). In a model with 8 handshake slots,
  100 devices were all back after about 33 s and 200 after about 5 minutes,
  where 10-40 s would be the TPM's own limit. Nobody is barred for it. There
  is no cap for this yet. If one server serves more than about 30 devices,
  expect a slow return after a long outage and watch how long the last
  devices take to reconnect.
- **Allowlist changes move addresses.** When the allowlist file changes,
  the names below the change get new tunnel addresses at the next restart.
  Their old flows are cut by the flow tags; a new flow that reuses an old
  flow's exact addresses and ports fails until that old entry expires.
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
- **DNS blocklist bypass.** The server's DNS blocklist sees only the
  queries sent to DSM's DNS proxy. An app that uses its own encrypted DNS
  (DNS over HTTPS or over TLS) through the tunnel skips it. DSM answers "no
  such name" for `use-application-dns.net`, which tells Firefox not to
  switch to its own encrypted DNS, but a Firefox set to always use it, and
  other apps, still skip the list. Pi-hole has the same limit. The
  blocklist cuts ads and trackers; it is not a wall. A list can only make
  names fail, never send them somewhere else, so a bad or hostile list can
  break sites but cannot redirect you.

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
