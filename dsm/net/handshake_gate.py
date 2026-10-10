"""Checks in front of new server handshake attempts.

Two parts, both used by the acceptor (``dsm.net.handshake_acceptor``):

* The gate (wire v2, T10 part 2). msg1 carries mac1 at bytes 32-47 and mac2
  at bytes 48-63, inside its random padding. mac1 shows the sender knows the
  CA certificate and the server's name; a msg1 without it is dropped
  silently, so the server no longer answers random probes. Under load, mac2
  must also show the sender can receive at its address: it is made from a
  cookie the server hands out in a cookie reply. mac1 and cookies are a
  filter and an address proof, not authentication. The client's side
  (stamping msg1, reading a cookie reply) lives here too, so both ends share
  one copy of the formulas.
* Limits (``SourceLimiter``): per address and overall, on starting attempts.
  They change nothing on the wire.

Each admitted msg1 costs the server an attest-key signature (a TPM call on
TPM builds) and holds one of ``max_inflight_handshakes`` slots for up to
12 s.

Limits and cookies are keyed by source IPv4 address (cookies also by port):
a client gets a new port each time it restarts. The server binds IPv4 only;
an IPv6 listener would need to key by /64.
"""

from __future__ import annotations

import enum
import hashlib
import hmac
import ipaddress
import logging
import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from cryptography.hazmat.primitives.serialization import Encoding

import tuncore
from dsm.core.log import RepeatLog
from dsm.crypto.cert import CertError, DeviceCert

if TYPE_CHECKING:
    from cryptography import x509

    from dsm.crypto.auth_loader import CertAuthMaterials

log = logging.getLogger(__name__)

# One client needs one attempt at a time. The second covers a client that
# restarts while its old attempt still holds a slot.
PER_SOURCE_INFLIGHT = 2
# New attempts per address: one every 4 s, up to 3 saved up. A client that
# systemd restarts every 10 s stays well inside this.
PER_SOURCE_RATE = 0.25  # tokens per second
PER_SOURCE_BURST = 3.0
# New attempts from all addresses together: a safety net for signing time.
# Measured on the server box's TPM (2026-10-09): about 0.21 s a signature.
# Keeping the parent key loaded saves only about 40 ms of that; the real win
# is that signing no longer blocks the event loop (its longest stall went
# from 219 ms to 6 ms).
GLOBAL_START_RATE = 4.0  # tokens per second
GLOBAL_START_BURST = 8.0
# New attempts from all addresses together while a session runs, on top of
# the limits above (owner decision 2026-10-09). Each admitted attempt costs
# a TPM signature; this caps that work while a session is live.
IN_SESSION_START_RATE = 1.0  # tokens per second
IN_SESSION_START_BURST = 1.0
# Addresses remembered at once. When full, the idle address that started an
# attempt longest ago is forgotten; one with an attempt running never is.
MAX_TRACKED_SOURCES = 4096


class TokenBucket:
    """``rate`` tokens a second, holding at most ``burst``; starts full."""

    def __init__(self, rate: float, burst: float, now: float) -> None:
        self._rate = rate
        self._burst = burst
        self._tokens = burst
        self._stamp = now

    def ready(self, now: float) -> bool:
        """Refill up to ``now``; True if a whole token can be taken."""
        # A clock that steps back adds nothing and is not counted twice.
        if now > self._stamp:
            self._tokens = min(
                self._burst, self._tokens + (now - self._stamp) * self._rate
            )
            self._stamp = now
        return self._tokens >= 1.0

    def take(self) -> None:
        """Spend one token. Call only after ``ready`` returned True."""
        self._tokens -= 1.0


@dataclass
class _Source:
    inflight: int
    bucket: TokenBucket


class SourceLimiter:
    """Per-address and overall limits on new handshake attempts.

    ``run_server`` makes one per run and hands it to every accept cycle, so
    the limits hold across cycles. ``try_start`` and ``finish`` never await:
    a check and the slot it admits happen in one step on the event loop.
    Refusals are logged at INFO, at most one line per 10 s per reason, never
    with the address.
    """

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        max_sources: int = MAX_TRACKED_SOURCES,
    ) -> None:
        self._clock = clock
        self._max_sources = max_sources
        # Oldest start first: try_start moves an address to the end.
        self._sources: dict[str, _Source] = {}
        now = clock()
        self._overall = TokenBucket(GLOBAL_START_RATE, GLOBAL_START_BURST, now)
        self._in_session = TokenBucket(
            IN_SESSION_START_RATE, IN_SESSION_START_BURST, now
        )
        self._busy_log = RepeatLog(log, logging.INFO, clock=clock)
        self._rate_log = RepeatLog(log, logging.INFO, clock=clock)
        self._overall_log = RepeatLog(log, logging.INFO, clock=clock)
        self._in_session_log = RepeatLog(log, logging.INFO, clock=clock)

    def __len__(self) -> int:
        """How many addresses are remembered now."""
        return len(self._sources)

    def try_start(self, ip: str, *, in_session: bool = False) -> bool:
        """Admit a new attempt from ``ip`` if every limit allows it.

        All or nothing: a refusal spends no token and remembers nothing.
        Pair every True with exactly one ``finish(ip)``. ``in_session`` is
        True for the accept that runs while a session is live: such a start
        also needs the in-session budget (one a second).
        """
        now = self._clock()
        src = self._sources.get(ip)
        if src is not None and src.inflight >= PER_SOURCE_INFLIGHT:
            self._busy_log.log(
                "new handshake refused: that address already has %d running",
                PER_SOURCE_INFLIGHT,
            )
            return False
        if src is not None and not src.bucket.ready(now):
            self._rate_log.log(
                "new handshake refused: that address started too many lately"
            )
            return False
        if not self._overall.ready(now):
            self._overall_log.log(
                "new handshake refused: too many new handshakes overall"
            )
            return False
        if in_session and not self._in_session.ready(now):
            self._in_session_log.log(
                "new handshake refused: too many new handshakes while a session runs"
            )
            return False
        if src is None:
            if len(self._sources) >= self._max_sources and not self._forget_one_idle():
                self._overall_log.log(
                    "new handshake refused: too many new handshakes overall"
                )
                return False
            src = _Source(
                inflight=0,
                bucket=TokenBucket(PER_SOURCE_RATE, PER_SOURCE_BURST, now),
            )
        else:
            del self._sources[ip]  # added back below, as the newest
        src.bucket.take()
        self._overall.take()
        if in_session:
            self._in_session.take()
        src.inflight += 1
        self._sources[ip] = src
        return True

    def finish(self, ip: str) -> None:
        """End one attempt that ``try_start(ip)`` admitted.

        Callers must pair each True from ``try_start`` with exactly one
        ``finish``; a missed ``finish`` is the caller's to prevent.

        Raises:
            RuntimeError: ``ip`` has no running attempt to end. Nothing
                changes, so one extra call cannot let an address run more
                than its share.
        """
        src = self._sources.get(ip)
        if src is None or src.inflight <= 0:
            raise RuntimeError("finish without a matching try_start")
        src.inflight -= 1

    def _forget_one_idle(self) -> bool:
        """Forget the idle address that started longest ago, if there is one."""
        idle = next(
            (ip for ip, src in self._sources.items() if src.inflight == 0), None
        )
        if idle is None:
            return False
        del self._sources[idle]
        return True


# --- The gate (wire v2, T10 part 2) -----------------------------------------

# Every handshake frame is this many bytes: dsm.crypto.handshake's
# HANDSHAKE_FRAME_SIZE. Not imported from there, because client_handshake
# imports this module; test_handshake_gate_mac.py pins that the two agree.
FRAME_SIZE = 1400
# msg1 (spec §7.1): [0:32] the Noise ephemeral e, [32:48] mac1, [48:64] mac2,
# then random bytes. Noise reads only e.
EPHEMERAL_SIZE = 32
MAC_SIZE = 16
MAC1_AT = 32
MAC2_AT = 48
# mac1 covers w = floor(unix time / 300). The server accepts w-1, w and w+1,
# so clocks less than 5 minutes apart always pass.
MAC1_WINDOW_S = 300
# R, the secret that makes cookies, is replaced this often; the one before
# still counts, so a cookie lasts 120 to 240 s.
COOKIE_SECRET_LIFETIME_S = 120.0
# Cookie replies from all addresses together: 20 a second, up to 40 saved up.
# This caps reflection (a reply is as big as the request) and the work.
COOKIE_REPLY_RATE = 20.0
COOKIE_REPLY_BURST = 40.0
# Under load: a handshake is running, or there was trouble this recently.
LOAD_HOLD_S = 30.0
# The bad-mac1 INFO line: at most once a minute, with a count.
BAD_MAC1_LOG_INTERVAL_S = 60.0
# Cookie reply (spec §7.3): [0:24] nonce, [24:56] the sealed cookie (16 bytes
# and a 16-byte tag), then random bytes.
COOKIE_NONCE_SIZE = 24
COOKIE_SEALED_SIZE = MAC_SIZE + 16

BAD_MAC1_LINE = (
    "dropped a handshake start with a bad mac1 (wrong CA or CN, a clock more "
    "than 5 minutes off, a DSM client older than wire v2, or not a DSM client)"
)

# The "-v1" is T10's own version of the gate scheme, kept as approved.
_MAC1_LABEL = b"DSM-mac1-v1\x00"
_COOKIE_LABEL = b"DSM-cookie-v1\x00"
_SECRET_SIZE = 32
_U64 = 0xFFFF_FFFF_FFFF_FFFF


class GateKeyError(ValueError):
    """The gate keys cannot be made: the server's name is missing or empty."""


@dataclass(frozen=True, slots=True)
class GateKeys:
    """The two gate keys both ends make from the CA certificate and the
    server's CN (spec §7.2).

    Low value: anyone with the CA certificate and the name can make them.
    Never logged or written.
    """

    mac1_key: bytes = field(repr=False)
    cookie_key: bytes = field(repr=False)

    @classmethod
    def from_ca_der(cls, ca_der: bytes, server_cn: str) -> GateKeys:
        """Make the keys from the CA certificate's DER bytes.

        Raises:
            GateKeyError: ``server_cn`` is empty or too long.
        """
        if not server_cn:
            raise GateKeyError("the server CN is empty")
        cn = server_cn.encode("utf-8")
        if len(cn) > 0xFFFF:
            raise GateKeyError("the server CN is too long")
        tail = hashlib.sha256(ca_der).digest() + len(cn).to_bytes(2, "big") + cn
        return cls(
            mac1_key=hashlib.blake2s(_MAC1_LABEL + tail).digest(),
            cookie_key=hashlib.blake2s(_COOKIE_LABEL + tail).digest(),
        )

    @classmethod
    def derive(cls, ca_root: x509.Certificate, server_cn: str) -> GateKeys:
        """Make the keys from the CA certificate itself. Its DER bytes, not
        its PEM file or the ``ca_root_sha256`` pin: two copies of one
        certificate can differ in PEM line endings.

        Raises:
            GateKeyError: ``server_cn`` is empty or too long.
        """
        return cls.from_ca_der(ca_root.public_bytes(Encoding.DER), server_cn)


def server_gate_keys(materials: CertAuthMaterials) -> GateKeys:
    """The server's gate keys: the CA certificate and its own certificate's CN.

    Raises:
        GateKeyError: the server certificate has no single, non-empty CN.
    """
    try:
        cn = DeviceCert.from_der(materials.cert_der).subject_cn
    except CertError as e:
        raise GateKeyError(f"the server certificate has no usable CN: {e}") from e
    return GateKeys.derive(materials.ca_root, cn)


def _mac(key: bytes, data: bytes) -> bytes:
    return hashlib.blake2s(data, digest_size=MAC_SIZE, key=key).digest()


def _window(now: float) -> int:
    return int(now // MAC1_WINDOW_S)


def _mac1_for(keys: GateKeys, window: int, e: bytes) -> bytes:
    # u64 big-endian; a clock before 1970 wraps instead of raising.
    return _mac(keys.mac1_key, (window & _U64).to_bytes(8, "big") + e)


def compute_mac1(e: bytes, keys: GateKeys, now: float) -> bytes:
    """mac1 for the Noise ephemeral ``e`` at unix time ``now``."""
    return _mac1_for(keys, _window(now), e)


def make_cookie(secret: bytes, src: tuple[str, int]) -> bytes | None:
    """The cookie for ``src`` under the secret R; None for a source that is
    not an IPv4 address with a valid port (the server binds IPv4 only)."""
    try:
        ip = ipaddress.IPv4Address(src[0]).packed
    except ValueError:
        return None
    if not 0 <= src[1] <= 0xFFFF:
        return None
    return _mac(secret, ip + src[1].to_bytes(2, "big"))


def compute_mac2(head: bytes, cookie: bytes) -> bytes:
    """mac2 over msg1[0:48] (e and mac1), keyed by the cookie."""
    return _mac(cookie, head)


def stamp_msg1(
    msg1: bytearray, mac1: bytes, *, rand: Callable[[int], bytes] = os.urandom
) -> None:
    """Write mac1, and 16 random bytes (never all zero) where mac2 goes."""
    msg1[MAC1_AT:MAC2_AT] = mac1
    filler = rand(MAC_SIZE)
    while filler == bytes(MAC_SIZE):
        filler = rand(MAC_SIZE)
    msg1[MAC2_AT : MAC2_AT + MAC_SIZE] = filler


def stamp_mac2(msg1: bytearray, cookie: bytes) -> None:
    """Write mac2 for ``cookie``; e and mac1 stay as they are."""
    msg1[MAC2_AT : MAC2_AT + MAC_SIZE] = compute_mac2(bytes(msg1[:MAC2_AT]), cookie)


def open_cookie_reply(frame: bytes, keys: GateKeys, sent_mac1: bytes) -> bytes | None:
    """The cookie in ``frame`` if it is a cookie reply to the msg1 that
    carried ``sent_mac1``; None for anything else, msg2 included (a msg2
    opens by chance once in 2^128). Never raises on peer bytes."""
    if len(frame) != FRAME_SIZE:
        return None
    sealed_end = COOKIE_NONCE_SIZE + COOKIE_SEALED_SIZE
    cookie = tuncore.xchacha_open(
        keys.cookie_key,
        bytes(frame[:COOKIE_NONCE_SIZE]),
        bytes(frame[COOKIE_NONCE_SIZE:sealed_end]),
        sent_mac1,
    )
    if cookie is None or len(cookie) != MAC_SIZE:
        return None
    return bytes(cookie)


class LoadTracker:
    """Whether the server is under load (spec §7.4, T10 §3.5): a handshake is
    running, or there was trouble in the last 30 s.

    Trouble is an attempt that failed, timed out or was refused, or a msg1
    dropped for a full pool, the inbox cap or a limiter refusal. A wrong
    size, a bad mac1 and a missing cookie are not trouble: scanner noise must
    not turn cookies on. One per run, inside the run's ``HandshakeGate``.
    """

    def __init__(
        self,
        *,
        clock: Callable[[], float] = time.monotonic,
        hold_s: float = LOAD_HOLD_S,
    ) -> None:
        self._clock = clock
        self._hold_s = hold_s
        self._last_trouble: float | None = None

    def note_trouble(self) -> None:
        self._last_trouble = self._clock()

    def under_load(self, inflight: int) -> bool:
        """``inflight``: handshakes running in the current accept."""
        if inflight > 0:
            return True
        last = self._last_trouble
        # A clock that steps back reads as recent trouble: the safe side.
        return last is not None and self._clock() - last < self._hold_s


class Msg1Verdict(enum.Enum):
    """What the UDP demux does with a new source's first frame."""

    DROP = enum.auto()  # wrong size or bad mac1: silence
    NEED_COOKIE = enum.auto()  # under load, mac2 missing or wrong: cookie reply
    ADMIT = enum.auto()  # on to the limits and the pool


class HandshakeGate:
    """The server's gate in front of new handshake attempts (spec §7.3, §7.4).

    ``run_server`` makes one per run and hands it to every accept, idle or in
    session, so the cookie secret, the reply budget and the load state hold
    across accepts. Nothing here awaits, and nothing raises on peer bytes.
    ``clock`` (monotonic) drives the intervals, ``wall_clock`` (unix time)
    the mac1 window.
    """

    def __init__(
        self,
        keys: GateKeys,
        *,
        clock: Callable[[], float] = time.monotonic,
        wall_clock: Callable[[], float] = time.time,
        rand: Callable[[int], bytes] = os.urandom,
    ) -> None:
        self._keys = keys
        self._clock = clock
        self._wall_clock = wall_clock
        self._rand = rand
        now = clock()
        self.load = LoadTracker(clock=clock)
        self._secret = rand(_SECRET_SIZE)
        self._previous_secret: bytes | None = None
        self._secret_born = now
        self._replies = TokenBucket(COOKIE_REPLY_RATE, COOKIE_REPLY_BURST, now)
        self._bad_mac1_log = RepeatLog(
            log, logging.INFO, interval_s=BAD_MAC1_LOG_INTERVAL_S, clock=clock
        )
        self._budget_log = RepeatLog(log, logging.DEBUG, clock=clock)

    def mac1_ok(self, frame: bytes) -> bool:
        """True for a 1400-byte msg1 whose mac1 fits w-1, w or w+1. A bad one
        counts toward the INFO line. TCP uses this alone (no cookies)."""
        if len(frame) != FRAME_SIZE:
            return False
        e = bytes(frame[:EPHEMERAL_SIZE])
        got = bytes(frame[MAC1_AT:MAC2_AT])
        w = _window(self._wall_clock())
        for window in (w, w - 1, w + 1):
            if hmac.compare_digest(_mac1_for(self._keys, window, e), got):
                return True
        self._bad_mac1_log.log(BAD_MAC1_LINE)
        return False

    def check_msg1(
        self, frame: bytes, src: tuple[str, int], *, under_load: bool
    ) -> Msg1Verdict:
        """Steps 2 and 3 of spec §7.4 for a new UDP source's frame."""
        if not self.mac1_ok(frame):
            return Msg1Verdict.DROP
        if not under_load or self._mac2_ok(frame, src):
            return Msg1Verdict.ADMIT
        return Msg1Verdict.NEED_COOKIE

    def cookie_reply(self, frame: bytes, src: tuple[str, int]) -> bytes | None:
        """A 1400-byte cookie reply to ``frame`` from ``src``; None when the
        reply budget is spent or ``src`` is not IPv4 (the msg1 is then just
        dropped)."""
        if not self._replies.ready(self._clock()):
            self._budget_log.log("cookie reply budget spent; dropped a handshake start")
            return None
        secret, _ = self._secrets()
        cookie = make_cookie(secret, src)
        if cookie is None:
            return None
        self._replies.take()
        nonce = self._rand(COOKIE_NONCE_SIZE)
        sealed = tuncore.xchacha_seal(
            self._keys.cookie_key, nonce, cookie, bytes(frame[MAC1_AT:MAC2_AT])
        )
        padding = FRAME_SIZE - COOKIE_NONCE_SIZE - COOKIE_SEALED_SIZE
        return nonce + bytes(sealed) + self._rand(padding)

    def _mac2_ok(self, frame: bytes, src: tuple[str, int]) -> bool:
        head = bytes(frame[:MAC2_AT])
        got = bytes(frame[MAC2_AT : MAC2_AT + MAC_SIZE])
        for secret in self._secrets():
            if secret is None:
                continue
            cookie = make_cookie(secret, src)
            if cookie is not None and hmac.compare_digest(
                compute_mac2(head, cookie), got
            ):
                return True
        return False

    def _secrets(self) -> tuple[bytes, bytes | None]:
        """R and the R before it; R is replaced once it is 120 s old."""
        now = self._clock()
        age = now - self._secret_born
        if age >= 2 * COOKIE_SECRET_LIFETIME_S:
            self._previous_secret = None
            self._secret = self._rand(_SECRET_SIZE)
            self._secret_born = now
        elif age >= COOKIE_SECRET_LIFETIME_S:
            self._previous_secret = self._secret
            self._secret = self._rand(_SECRET_SIZE)
            self._secret_born = now
        return self._secret, self._previous_secret
