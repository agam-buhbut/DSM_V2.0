"""Shared session data path: encrypt/send, decrypt/dispatch, TUN forwarding.

Extracted from client.py and server.py to eliminate duplication.
"""

# This module concentrates the whole encrypt/send + decrypt/dispatch + TUN
# forwarding + liveness + rekey + auto-MTU data path in one place by design
# (the loops share a DataPathContext and tight ordering guarantees), so it
# exceeds pylint's 1000-line module ceiling. Like the too-many-* metrics
# disabled in pyproject.toml, this is a refactorer-territory size metric
# inherent to the data path, not a bug.
# pylint: disable=too-many-lines

from __future__ import annotations

import asyncio
import logging
import os
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from dsm.core import netaudit
from dsm.core.config import MIN_TUN_MTU, Config
from dsm.core.fsm import SessionFSM, State
from dsm.core.protocol import (
    GCM_TAG_SIZE,
    OUTER_HEADER_SIZE,
    PATH_TOKEN_SIZE,
    SEQ_STRUCT,
    SIZE_CLASSES,
    Fragment,
    InnerPacket,
    OuterPacket,
    PacketType,
    ReassemblyBuffer,
    fragment_ip_packet,
)
from dsm.net.transport.tcp import TCPTransport
from dsm.net.transport.udp import UDPTransport
from dsm.net.tunnel import TunDevice
from dsm.rekey import (
    MAX_REKEY_RETRIES,
    REKEY_ACK_TIMEOUT,
    SendFn,
    handle_rekey_ack,
    handle_rekey_init,
    initiate_rekey,
    resend_rekey_init,
)
from dsm.traffic.scheduler import SendScheduler
from dsm.traffic.shaper import TrafficShaper

if TYPE_CHECKING:
    import tuncore

log = logging.getLogger(__name__)

# Liveness parameters (seconds)
KEEPALIVE_SEND_INTERVAL = 15.0  # emit KEEPALIVE if send-idle for this long
DEAD_PEER_TIMEOUT = 60.0  # tear down if recv-idle for this long
LIVENESS_CHECK_INTERVAL = 5.0  # cadence at which liveness_loop wakes

# Wire overhead per outer packet — IP(20) + UDP(8) + outer header(20) +
# GCM tag(16) + inner header(4) = 68 bytes. Subtracted from the kernel-
# discovered path MTU to size the inner TUN MTU.
WIRE_OVERHEAD = 68

# Outer header layout: seq(SEQ_STRUCT.size=8) ‖ nonce(12) ‖ ciphertext, with
# the nonce occupying the bytes between the sequence number and the start of
# the ciphertext (OUTER_HEADER_SIZE=20). Derived from the imported protocol
# constants so it tracks any future header change; the assert pins today's
# 12-byte AES-GCM nonce.
NONCE_OFFSET = (
    SEQ_STRUCT.size
)  # pylint: disable=invalid-name  # intentional/false positive (see report)
NONCE_SIZE = OUTER_HEADER_SIZE - SEQ_STRUCT.size
assert NONCE_SIZE == 12

# auto-MTU adapter: how many consecutive same-or-higher path-MTU
# observations are required before raising the TUN MTU back toward
# config.mtu. Guards against transient PMTU bumps causing flap.
AUTO_MTU_HYSTERESIS_RISES = 3


@dataclass
class LivenessState:
    """Tracks peer liveness via most-recent send/recv timestamps.

    Seeded with ``time.monotonic()`` so a freshly-established session is
    not flagged dead before the first packet arrives.

    M-BUG-15: ``last_real_send_time`` separates from ``last_send_time``
    so the KEEPALIVE-trigger doesn't get bumped by chaff. With the
    Poisson-rate chaff model always firing, the previous "any-send
    idle > 15s" check meant KEEPALIVE was effectively never sent —
    silently making the typed-keepalive path dead code rather than the
    intended fixed-cadence ping. ``last_send_time`` stays for any
    callers that care about absolute wire-presence; the keepalive loop
    now consults ``last_real_send_time``.
    """

    last_recv_time: float = field(default_factory=time.monotonic)
    last_send_time: float = field(default_factory=time.monotonic)
    last_real_send_time: float = field(default_factory=time.monotonic)


def setup_signal_handlers(shutdown: asyncio.Event) -> None:
    """Register termination signals to set the shutdown event.

    SIGHUP and SIGQUIT are included so that ``systemctl reload`` (sends
    SIGHUP) and Ctrl-\\ (SIGQUIT) trigger graceful AsyncExitStack
    unwind rather than killing the process and leaving nftables, TUN,
    resolv.conf, and sysctl state on the host. We do not support config
    reload — SIGHUP is treated as shutdown.
    """
    import signal

    def _on_signal(sig_name: str) -> None:
        netaudit.emit("shutdown_signal", source=sig_name)
        shutdown.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
        loop.add_signal_handler(
            sig, _on_signal, sig.name
        )  # pylint: disable=no-member  # enum .name false positive


# Outer sequence number is wire-encoded as `!Q` (uint64 big-endian), so
# wraparound at 2**64 must trigger session rekey rather than silently roll
# back to 0 (a nonce reuse risk).
_SEQ_MAX = 2**64


@dataclass
class SequenceCounter:
    """Monotonic 64-bit outer-packet sequence counter.

    Kept as a dataclass so every caller mutates the same instance — a plain
    ``int`` closed over by ``send_packet`` cannot be incremented in place.
    """

    value: int = 0

    def next(self) -> int:
        self.value += 1
        if self.value >= _SEQ_MAX:
            raise RuntimeError("sequence number overflow — session must be rekeyed")
        return self.value


@dataclass
class FragmentIdCounter:
    """16-bit rolling counter for Fragment.fragment_id.

    Each oversized TUN packet gets a fresh id so the receiver's
    ReassemblyBuffer can distinguish concurrent bursts. The window is
    larger than REASSEMBLY_MAX_PENDING (256), so id collisions only
    happen after thousands of oversized packets — and even then the
    stale entry has either completed or expired by 5s.
    """

    value: int = 0

    def next(self) -> int:
        self.value = (self.value + 1) & 0xFFFF
        return self.value


def make_send_fn(
    session_keys: tuncore.SessionKeyManager,
    transport: UDPTransport | TCPTransport,
    dest_addr: Callable[[], tuple[str, int] | None],
    seq: SequenceCounter,
    liveness: LivenessState | None = None,
    shutdown: asyncio.Event | None = None,
) -> SendFn:
    """Create a send_packet closure.

    ``shutdown`` (when supplied) is set if the send path hits an unrecoverable
    encryption-side condition — sequence-number overflow or nonce-counter
    exhaustion. Both indicate the session has produced 2^64 packets or has
    fallen too far behind on rekey; either way, propagating the RuntimeError
    out would kill the asyncio.gather without cleanup. Setting shutdown lets
    the existing teardown path unwind nftables/TUN/resolv.conf cleanly.
    """

    # For TCP, always use max size class so the length-prefix is constant,
    # preventing passive traffic analysis via frame sizes.
    tcp_fixed_size = SIZE_CLASSES[-1] if isinstance(transport, TCPTransport) else 0
    # The plaintext we hand to AEAD must be sized so that the final wire
    # packet (OUTER_HEADER_SIZE + ciphertext_with_GCM_tag) equals
    # tcp_fixed_size. The plaintext slot is therefore
    # tcp_fixed_size - OUTER_HEADER_SIZE - GCM_TAG_SIZE.
    tcp_inner_target = (
        tcp_fixed_size - OUTER_HEADER_SIZE - GCM_TAG_SIZE if tcp_fixed_size else 0
    )

    async def send_packet(data: bytes, target_size: int) -> None:
        try:
            n = seq.next()
        except RuntimeError as e:
            log.error("sequence counter exhausted: %s — triggering shutdown", e)
            if shutdown is not None:
                shutdown.set()
            return
        # H-BUG-1: epoch_id is baked into the InnerPacket header at
        # build (queue) time, but encryption happens here at send time.
        # If a rekey completes between queue and send, the header says
        # OLD epoch_id, the AEAD key is NEW, and the receiver drops the
        # packet at the `inner.epoch_id != expected_eid` check. Patch
        # byte 1 of the header (top 4 bits = epoch_id, bottom 4
        # reserved/zero — audit M3 widening) with the live
        # session_keys.epoch right before encryption. CHAFF packets are
        # exempt from the receiver's check, but patching them is
        # harmless.
        #
        # M-PERF: the shaper already stamped the queue-time epoch nibble
        # into byte 1 (shaper._serialize_padded). When NO rekey happened
        # between queue and send — the overwhelmingly common case — that
        # nibble already equals the live epoch, so we can hand the
        # immutable `data` straight to AEAD with ZERO copies. Only when a
        # rekey actually changed the live epoch do we allocate a fresh
        # bytearray to patch it (measured: 2 allocs / ~2890 B per packet
        # eliminated on the common path). We still never mutate the
        # scheduler's buffer: the patch path allocates a NEW bytearray
        # (bytearray(data) copies), exactly as before.
        if len(data) >= 2:
            want_byte1 = (data[1] & 0x0F) | ((session_keys.epoch & 0x0F) << 4)
            if data[1] != want_byte1:
                buf = bytearray(data)
                buf[1] = want_byte1
                data = bytes(buf)
        if tcp_fixed_size and len(data) < tcp_inner_target:
            # Fixed-size TCP framing: extend the inner plaintext to
            # tcp_inner_target so that after AEAD (+GCM_TAG_SIZE) and
            # OuterPacket framing (+OUTER_HEADER_SIZE) the wire packet
            # is exactly tcp_fixed_size. Random pad bytes go INSIDE the
            # AEAD envelope and are therefore authenticated.
            pad_len = tcp_inner_target - len(data)
            buf = bytearray(tcp_inner_target)
            buf[: len(data)] = data
            buf[len(data) :] = os.urandom(pad_len)
            data = bytes(buf)
            target_size = tcp_fixed_size
        aad = SEQ_STRUCT.pack(n)
        try:
            nonce, ct, _epoch = session_keys.encrypt(data, aad)
        except RuntimeError as e:
            log.error("AEAD nonce exhausted: %s — triggering shutdown", e)
            if shutdown is not None:
                shutdown.set()
            return
        outer = OuterPacket(seq=n, nonce=nonce, ciphertext=ct)
        wire = outer.serialize(target_size)
        if isinstance(transport, UDPTransport):
            addr = dest_addr()
            if addr is None:
                # DSM-002: destination addr not yet known (the server has no
                # peer addr until the first authenticated client packet sets
                # it via post_authenticate). Raising here escapes the detached
                # SendScheduler task and silently kills it — stopping ALL
                # egress incl. chaff with no shutdown signal. Mirror the
                # seq/nonce-exhaustion paths: log, trigger shutdown, drop.
                log.error(
                    "UDP send before destination addr known — "
                    "dropping packet and triggering shutdown"
                )
                if shutdown is not None:
                    shutdown.set()
                return
            await transport.send(wire, addr)
        else:
            await transport.send(wire)
        if liveness is not None:
            liveness.last_send_time = time.monotonic()

    return send_packet


def make_addr_send_fn(
    session_keys: tuncore.SessionKeyManager,
    transport: UDPTransport | TCPTransport,
    seq: SequenceCounter,
) -> Callable[[bytes, int, tuple[str, int]], Awaitable[None]]:
    """Build an encrypt-and-send closure that targets an EXPLICIT addr.

    Unlike ``make_send_fn`` — whose destination is whatever the committed
    egress closure returns — this resolves the destination from the
    ``addr`` argument passed at call time. It exists solely for the
    return-routability PATH_CHALLENGE: that probe must go to the UNCOMMITTED
    pending candidate WITHOUT routing through the scheduler (which always
    targets the committed egress) and WITHOUT mutating the committed egress.

    The AEAD/seq/nonce framing is byte-identical to ``make_send_fn`` — only
    the destination resolution differs — so the probe is indistinguishable on
    the wire from any other size-128 control packet. TCP has a single
    connection (no per-packet addr), so the ``addr`` argument is ignored and
    ``transport.send`` is used directly; in practice path validation is a
    UDP-roaming concern.
    """

    async def send_to(data: bytes, target_size: int, addr: tuple[str, int]) -> None:
        n = seq.next()
        if len(data) >= 2:
            want_byte1 = (data[1] & 0x0F) | ((session_keys.epoch & 0x0F) << 4)
            if data[1] != want_byte1:
                buf = bytearray(data)
                buf[1] = want_byte1
                data = bytes(buf)
        aad = SEQ_STRUCT.pack(n)
        nonce, ct, _epoch = session_keys.encrypt(data, aad)
        outer = OuterPacket(seq=n, nonce=nonce, ciphertext=ct)
        wire = outer.serialize(target_size)
        if isinstance(transport, UDPTransport):
            await transport.send(wire, addr)
        else:
            await transport.send(wire)

    return send_to


# Minimum interval between PATH_CHALLENGE emissions (seconds). A single
# pending slot bounds memory; this bounds the challenge SEND rate so the
# return-routability probe cannot be abused as a reflection/amplification
# vector (each AEAD-valid packet from a new source would otherwise emit a
# challenge). Replies are size-class-padded control packets, so even a
# saturated challenge cadence emits at most one small packet per interval to
# any given candidate.
PATH_CHALLENGE_MIN_INTERVAL = 1.0

# How long a pending candidate may sit unvalidated before it is discarded.
# A stale pending must never wedge a future legitimate roam: once it times
# out the slot is free for the next candidate. Must comfortably exceed a
# real RTT plus the challenge cadence so a genuine NAT-rebind round-trip
# completes; 5s mirrors other recovery windows in the data path.
PATH_PENDING_TIMEOUT = 5.0


@dataclass
class PathValidationState:
    """Single-slot return-routability state for server egress roaming.

    The server commits its egress address only to a peer that PROVES it can
    receive at that address (it echoes a fresh 16-byte token in a
    PATH_RESPONSE). Until then a candidate from a new source addr is held
    here as ``pending_addr`` and probed with a PATH_CHALLENGE.

    One slot only: a newer candidate REPLACES any existing pending (with a
    fresh token), so an attacker cannot exhaust memory and cannot pin the
    slot against a genuine later roam. ``clock`` is injectable so timeout /
    rate-limit behaviour is deterministic in tests (default time.monotonic).

    Fields:
      * ``pending_addr``: the unvalidated candidate egress, or None.
      * ``token``: the 16-byte token the candidate must echo. None iff no
        pending.
      * ``challenge_sent_at``: monotonic time the current pending's first
        challenge went out — drives the pending timeout.
      * ``last_challenge_at``: monotonic time of the most recent challenge
        emission (any candidate) — drives the send rate limit.
    """

    clock: Callable[[], float] = time.monotonic
    pending_addr: tuple[str, int] | None = None
    token: bytes | None = None
    challenge_sent_at: float | None = None
    last_challenge_at: float | None = None

    def _expired(self, now: float) -> bool:
        return (
            self.challenge_sent_at is not None
            and now - self.challenge_sent_at > PATH_PENDING_TIMEOUT
        )

    def clear(self) -> None:
        self.pending_addr = None
        self.token = None
        self.challenge_sent_at = None

    def should_challenge(self, candidate: tuple[str, int]) -> bytes | None:
        """Decide whether to (re)challenge ``candidate``; return a fresh token
        to send, or None to stay silent.

        Issues a token when there is no live pending, when the pending has
        timed out, or when the candidate differs from the current pending —
        each case (re)arms the slot with a fresh token bound to ``candidate``.
        A repeat of the SAME live, un-timed-out pending is suppressed (no new
        token) UNLESS the rate-limit interval has elapsed, in which case the
        existing token is re-sent (a retransmit, not a new probe).

        All emissions are gated by ``PATH_CHALLENGE_MIN_INTERVAL`` so the
        probe cannot be abused as an amplifier.
        """
        now = self.clock()
        if self.last_challenge_at is not None and (
            now - self.last_challenge_at < PATH_CHALLENGE_MIN_INTERVAL
        ):
            return None

        same_live_pending = (
            self.pending_addr == candidate
            and self.token is not None
            and not self._expired(now)
        )
        if same_live_pending:
            # Rate-limit interval has elapsed (checked above): retransmit the
            # existing token rather than minting a new one, so an in-flight
            # legitimate response still matches.
            assert self.token is not None
            token = self.token
        else:
            # New candidate, or the slot is empty/expired: arm a fresh token.
            token = os.urandom(PATH_TOKEN_SIZE)
            self.pending_addr = candidate
            self.token = token
            self.challenge_sent_at = now
        self.last_challenge_at = now
        return token

    def validate(self, recv_addr: tuple[str, int], token: bytes) -> bool:
        """Return True iff ``token`` matches the live pending for ``recv_addr``.

        On success the caller commits egress to ``recv_addr`` and calls
        ``clear()``. A mismatched token, a response from a non-pending addr,
        or a response after the pending timed out all return False — egress
        stays on the committed real client.
        """
        if self.pending_addr is None or self.token is None:
            return False
        if recv_addr != self.pending_addr:
            return False
        if self._expired(self.clock()):
            return False
        # Constant-time compare: the token is a secret the attacker is trying
        # to guess; a timing oracle on the echo path would leak it.
        import hmac

        return hmac.compare_digest(token, self.token)


def _decrypt_with_fallback(
    session_keys: tuncore.SessionKeyManager,
    nonce: bytes,
    ciphertext: bytes,
    aad: bytes,
    seq: int,
) -> tuple[bytes, bool] | None:
    """Try current-epoch decrypt, then previous-epoch if in grace period.

    Returns (plaintext, used_prev_epoch) or None on failure.

    M-PERF-5: prefer the Rust-side `try_decrypt_with_fallback` which
    returns `None` on auth failure instead of raising. Constructing a
    Python exception + traceback on every dropped packet costs ~30µs
    of CPU each; at any meaningful forgery-flood rate this dominates
    the recv-side cost. The fallback to the exception-driven path
    handles older `tuncore` builds that don't yet have the new method
    (e.g. an in-place upgrade without a rebuild).
    """
    try_fn = getattr(session_keys, "try_decrypt_with_fallback", None)
    if try_fn is not None:
        result = try_fn(nonce, ciphertext, aad, seq)
        if result is None:
            log.debug("decrypt failed, dropping packet")
            return None
        return result  # (plaintext, used_prev)

    # Legacy fallback for tuncore builds without M-PERF-5 method.
    try:
        return session_keys.decrypt(nonce, ciphertext, aad, seq, False), False
    except RuntimeError:
        pass
    if session_keys.has_grace_period:
        try:
            return session_keys.decrypt(nonce, ciphertext, aad, seq, True), True
        except RuntimeError:
            pass
    log.debug("decrypt failed, dropping packet")
    return None


def decrypt_packet(
    data: bytes,
    session_keys: tuncore.SessionKeyManager,
    replay: tuncore.ReplayWindow,
) -> tuple[InnerPacket, bool] | None:
    """Parse, replay-check, decrypt, and validate an incoming packet.

    Returns (inner_packet, decrypted_prev_epoch) or None if the packet
    should be dropped (too short, replay, auth failure, malformed, epoch mismatch).

    M-BUG-14 DESIGN NOTE: there are TWO replay windows — this
    Python-side ``replay`` ARG (checked here BEFORE AEAD work) and the
    Rust-side window INSIDE ``session_keys.decrypt``. The Python check
    saves the AEAD cost on replays; the Rust check is the authoritative
    replay window (it's per-epoch and cleared on rotation, where the
    Python window is monotonic across rotations). Both are kept on
    purpose: removing the Python pre-check would burn AEAD on every
    forgery; removing the Rust window would break per-epoch isolation
    after rotation. Sequence numbers are monotonic across rotations
    (one SequenceCounter for the session) so the two windows agree on
    what's a replay.
    """
    if len(data) < OUTER_HEADER_SIZE:
        log.debug("packet too short, dropping")
        return None

    seq = SEQ_STRUCT.unpack_from(data)[0]
    if not replay.check(seq):
        log.debug("replay detected, dropping seq=%d", seq)
        return None

    # nonce sits between the 8-byte seq and the ciphertext; see NONCE_OFFSET
    # / NONCE_SIZE. Byte-identical to the former data[8:20].
    nonce_bytes = data[NONCE_OFFSET : NONCE_OFFSET + NONCE_SIZE]
    ciphertext = data[OUTER_HEADER_SIZE:]
    aad = SEQ_STRUCT.pack(seq)

    result = _decrypt_with_fallback(session_keys, nonce_bytes, ciphertext, aad, seq)
    if result is None:
        return None
    plaintext, decrypted_prev_epoch = result

    replay.update(seq)

    try:
        inner = InnerPacket.deserialize(plaintext)
    except ValueError:
        log.debug("malformed inner packet, dropping")
        return None

    # Verify epoch_id matches the key epoch used for decryption.
    # Audit M3: epoch_id widened to 4 bits (0x0F mask).
    #
    # Phase 1.1: REKEY_ACK is ALSO exempt. A re-sent cached ACK is stamped
    # with the responder's NEW epoch nibble, but a retransmitted INIT means
    # the initiator is still at the OLD epoch, so the nibble check would drop
    # the very ACK that completes recovery. REKEY_ACK self-validates via its
    # own 4-byte epoch field (handle_rekey_ack checks it against
    # pending_epoch) plus AEAD, so the outer nibble check is redundant for it.
    # PATH_CHALLENGE / PATH_RESPONSE are control packets (like CHAFF /
    # REKEY_ACK). They can be built under one epoch and re-stamped by
    # make_send_fn at send time, or arrive during a rekey grace window, so
    # exempt them from the outer epoch-nibble check. They self-authenticate
    # via AEAD plus the 16-byte token echo; the nibble adds nothing.
    if inner.ptype not in (
        PacketType.CHAFF,
        PacketType.REKEY_ACK,
        PacketType.PATH_CHALLENGE,
        PacketType.PATH_RESPONSE,
    ):
        if decrypted_prev_epoch:
            expected_eid = (session_keys.epoch - 1) & 0x0F
        else:
            expected_eid = session_keys.epoch & 0x0F
        if inner.epoch_id != expected_eid:
            log.debug(
                "epoch_id mismatch: got %d, expected %d", inner.epoch_id, expected_eid
            )
            return None

    return inner, decrypted_prev_epoch


@dataclass
class RekeyState:
    """Mutable rekey state shared between recv and send loops.

    Tracks:
      * ``in_progress``: True between INIT send and ACK receive on the
        initiator side (client). Never set on the responder (server).
      * ``last_time``: monotonic timestamp of last SUCCESSFULLY completed
        rekey — used by the rate limiter to enforce MIN_REKEY_INTERVAL.
      * ``pending_epoch``: the epoch requested in the in-flight INIT;
        cross-checked against the ACK so a stale/replayed ACK can't
        complete rotation to the wrong epoch.
      * ``last_init_payload``: raw payload bytes of the in-flight INIT
        (``struct + ephemeral_pub``). Stored so the send loop can
        rebuild + retransmit an identical INIT on ACK timeout without
        re-deriving the rotation.
      * ``last_init_sent_at``: monotonic time of the last INIT send
        (original or retry). Used by the retry scheduler.
      * ``retries_used``: count of retransmits attempted for the
        current INIT; capped at ``MAX_REKEY_RETRIES``.
    """

    in_progress: bool = False
    last_time: float | None = None
    pending_epoch: int | None = None
    last_init_payload: bytes | None = None
    last_init_sent_at: float | None = None
    retries_used: int = 0
    # Server-side only: the payload of the most recently sent REKEY_ACK,
    # plus the epoch it applied. Consulted by ``handle_rekey_init`` when a
    # duplicate REKEY_INIT arrives (client's ACK was lost) so we re-send
    # the same ACK bytes under the current keys instead of trying to
    # re-rotate (which would fail the epoch precondition).
    cached_ack_payload: bytes | None = None
    cached_ack_epoch: int | None = None

    def reset_retry(self) -> None:
        self.last_init_payload = None
        self.last_init_sent_at = None
        self.retries_used = 0


@dataclass
class DataPathContext:
    """State shared across the per-connection data-path loops.

    Bundles the long-lived objects that ``dispatch_inner``, ``tun_send_loop``
    and ``liveness_loop`` all need. Built once after the handshake
    completes, then passed around instead of being threaded as 8+ args.
    """

    tun: TunDevice
    session_keys: tuncore.SessionKeyManager
    fsm: SessionFSM
    shaper: TrafficShaper
    send_fn: SendFn
    scheduler: SendScheduler
    rekey: RekeyState
    liveness: LivenessState
    shutdown: asyncio.Event
    reassembly: ReassemblyBuffer | None = None
    fragment_ids: FragmentIdCounter = field(default_factory=FragmentIdCounter)
    # H-ANON-4: optional UDPTransport reference for the client to call
    # `rebind_to_fresh_port()` on rekey completion, breaking the
    # stable-src-port session fingerprint. None on server / TCP.
    udp_transport: UDPTransport | None = None
    # Audit H1 / M-BUG-1: our and peer's 32-byte Noise static pubs.
    # Consumed by ``_handle_rekey_init`` for the mutual-init tie-break.
    # Optional fields here (None when unset) so older test fixtures
    # don't have to populate them; the tie-break degrades to its
    # pre-fix behavior (silent drop) when either is None.
    local_static_pub: bytes | None = None
    remote_static_pub: bytes | None = None


async def _handle_data(ctx: DataPathContext, inner: InnerPacket) -> None:
    await ctx.tun.awrite(inner.payload)


async def _handle_fragment(ctx: DataPathContext, inner: InnerPacket) -> None:
    if ctx.reassembly is None:
        log.warning("received fragment but no reassembly buffer configured")
        return
    try:
        frag = Fragment.deserialize(inner.payload)
    except ValueError:
        log.debug("malformed fragment, dropping")
        return
    payload = ctx.reassembly.add_fragment(frag)
    if payload is not None:
        await ctx.tun.awrite(payload)


async def _handle_rekey_init(ctx: DataPathContext, inner: InnerPacket) -> None:
    # Audit H1: plumb rekey_state + static pubs into handle_rekey_init so
    # the M-BUG-1 mutual-init tie-break actually fires. Without these
    # kwargs the tie-break guard fails closed and a simultaneous-rekey
    # collision tears down both sides.
    (
        ctx.rekey.last_time,
        ctx.rekey.cached_ack_epoch,
        ctx.rekey.cached_ack_payload,
    ) = await handle_rekey_init(
        inner.payload,
        ctx.session_keys,
        ctx.fsm,
        ctx.shaper,
        ctx.send_fn,
        ctx.rekey.last_time,
        cached_ack_epoch=ctx.rekey.cached_ack_epoch,
        cached_ack_payload=ctx.rekey.cached_ack_payload,
        rekey_state=ctx.rekey,
        local_static_pub=ctx.local_static_pub,
        remote_static_pub=ctx.remote_static_pub,
        # Task 2.6: route the (normal) REKEY_ACK through the paced envelope so
        # its wire timing matches the steady stream. The duplicate-INIT
        # cached-ACK replay inside handle_rekey_init keeps the bounded direct
        # send_fn (lost-ACK recovery must stay observable within 5 s).
        paced_send=ctx.scheduler.enqueue,
    )


async def _handle_rekey_ack(ctx: DataPathContext, inner: InnerPacket) -> None:
    ts = handle_rekey_ack(
        inner.payload,
        ctx.session_keys,
        ctx.fsm,
        ctx.rekey.pending_epoch,
    )
    if ts is not None:
        ctx.rekey.last_time = ts
    # Clear pending rotation state on BOTH success and failure. On failure
    # (malformed ACK, low-order peer ephemeral, etc.) the Rust-side
    # pending_rotation has already been consumed by complete_rotation_initiator,
    # so leaving stale Python-side payload/epoch/retry counters would block the
    # next needs_rotation() trigger from starting a clean cycle.
    ctx.rekey.pending_epoch = None
    ctx.rekey.reset_retry()
    ctx.rekey.in_progress = False

    # H-ANON-4: client rebinds UDP socket to fresh ephemeral port on
    # successful rekey, so the (src_ip, src_port, dst_ip, dst_port)
    # quadruple changes per rekey. Without this the src_port is stable
    # for the session lifetime and an ISP-side passive observer can
    # correlate all of the user's outer packets as one persistent
    # session — defeating rekey's anonymity property.
    if ts is not None and ctx.udp_transport is not None:
        try:
            await ctx.udp_transport.rebind_to_fresh_port()
            netaudit.emit("udp_rebound", reason="rekey")
        except OSError as e:
            log.warning("UDP rebind on rekey failed: %s", e)


async def _handle_session_close(ctx: DataPathContext, inner: InnerPacket) -> None:
    # pylint: disable=unused-argument  # signature fixed by the _DISPATCH table
    ctx.shutdown.set()


def _build_control_packet(
    ctx: DataPathContext, ptype: PacketType, payload: bytes = b""
) -> tuple[bytes, int]:
    """Build a control packet (KEEPALIVE / SESSION_CLOSE / PATH_*).

    They share the same shape: a small payload (empty for KEEPALIVE /
    SESSION_CLOSE, the 16-byte token for PATH_CHALLENGE / PATH_RESPONSE),
    current epoch_id, run through the shaper for size-class padding.
    Centralised so future control-packet types pick up the right
    epoch/padding wiring automatically.
    """
    inner = InnerPacket(
        ptype=ptype,
        epoch_id=ctx.session_keys.epoch & 0x0F,
        payload=payload,
    )
    return ctx.shaper.pad_packet(inner)


async def _handle_path_challenge(ctx: DataPathContext, inner: InnerPacket) -> None:
    """Client side: answer a PATH_CHALLENGE with a PATH_RESPONSE.

    The server emits a PATH_CHALLENGE to a candidate egress addr to confirm
    return-routability before it roams its egress there. A legitimate client
    that has just moved (NAT rebind / network change) IS at that new addr,
    receives the challenge, and echoes the 16-byte token straight back via
    the normal paced send path — so the legitimate roam completes. The
    response rides the scheduler (same envelope as any control packet); the
    server matches the echoed token against its pending slot.

    An off-path attacker who spoofed a victim's source addr never receives
    the challenge (it is sent to the victim, who cannot decrypt or
    meaningfully answer it), so it never produces a valid response — the
    server's egress stays on the real client.
    """
    token = inner.payload
    if len(token) != PATH_TOKEN_SIZE:
        log.debug("PATH_CHALLENGE with bad token length %d, dropping", len(token))
        return
    padded, target_size = _build_control_packet(
        ctx, PacketType.PATH_RESPONSE, payload=token
    )
    ctx.scheduler.enqueue(padded, target_size)


async def send_session_close(ctx: DataPathContext) -> None:
    """Send a single SESSION_CLOSE packet to notify the peer of graceful exit.

    Bypasses the scheduler (direct send_fn call) so the packet leaves
    immediately; otherwise shutdown could tear down the scheduler before
    the queued close packet flushed. Best-effort: errors are logged, not
    raised — shutdown must continue regardless.
    """
    try:
        padded, target_size = _build_control_packet(ctx, PacketType.SESSION_CLOSE)
        # DSM-024: bound the send so a wedged peer or TCP backpressure cannot
        # pin the teardown. send_session_close runs in run_data_loops' finally,
        # BEFORE the caller unwinds nft/tun/resolv; an unbounded drain here
        # would delay the whole leak-safe teardown. Mirrors the rekey sends.
        await asyncio.wait_for(ctx.send_fn(padded, target_size), timeout=5.0)
    except Exception as e:  # noqa: BLE001  # see linter report
        # Debug-level: the peer being gone at shutdown is the common case
        # (we may be shutting down BECAUSE the peer disappeared). Warning
        # would be noise on every disconnect.
        log.debug("SESSION_CLOSE send failed (continuing shutdown): %s", e)


async def _handle_noop(ctx: DataPathContext, inner: InnerPacket) -> None:
    # pylint: disable=unused-argument  # signature fixed by the _DISPATCH table
    """No-op for CHAFF and KEEPALIVE — liveness is accounted in recv_loop."""


_DISPATCH: dict[
    PacketType, Callable[[DataPathContext, InnerPacket], Awaitable[None]]
] = {
    PacketType.CHAFF: _handle_noop,
    PacketType.KEEPALIVE: _handle_noop,
    PacketType.DATA: _handle_data,
    PacketType.FRAGMENT: _handle_fragment,
    PacketType.REKEY_INIT: _handle_rekey_init,
    PacketType.REKEY_ACK: _handle_rekey_ack,
    PacketType.SESSION_CLOSE: _handle_session_close,
    # Client answers a server's PATH_CHALLENGE with a PATH_RESPONSE.
    PacketType.PATH_CHALLENGE: _handle_path_challenge,
    # PATH_RESPONSE: the server validates+commits in post_authenticate (it has
    # recv_addr there); reaching dispatch it is a no-op (client never gets one).
    PacketType.PATH_RESPONSE: _handle_noop,
}


async def dispatch_inner(ctx: DataPathContext, inner: InnerPacket) -> None:
    """Dispatch a decrypted inner packet to the appropriate handler."""
    handler = _DISPATCH.get(inner.ptype)
    if handler is None:
        return
    await handler(ctx, inner)


async def liveness_loop(ctx: DataPathContext) -> None:
    """Emit KEEPALIVE while send-idle; shut down on dead-peer timeout.

    The check cadence is ``LIVENESS_CHECK_INTERVAL`` — well below both
    ``KEEPALIVE_SEND_INTERVAL`` and ``DEAD_PEER_TIMEOUT`` so there is slack
    for the scheduler's jitter and for a single missed keepalive round.
    """
    while not ctx.shutdown.is_set():
        try:
            await asyncio.wait_for(ctx.shutdown.wait(), timeout=LIVENESS_CHECK_INTERVAL)
            return
        except TimeoutError:
            pass

        now = time.monotonic()
        recv_idle = now - ctx.liveness.last_recv_time
        if recv_idle > DEAD_PEER_TIMEOUT:
            log.warning(
                "dead peer: no packets received for %.1fs, tearing down session",
                recv_idle,
            )
            netaudit.emit(
                "liveness_fire",
                reason="dead_peer_timeout",
                recv_idle_s=round(recv_idle, 2),
                threshold_s=DEAD_PEER_TIMEOUT,
            )
            ctx.shutdown.set()
            return

        # M-BUG-15: trigger on real-data idleness, not all-send idleness.
        # With Poisson-rate chaff always firing, last_send_time would
        # never go stale and KEEPALIVE would never fire. Tracking
        # last_real_send_time separately gives KEEPALIVE its intended
        # fixed-cadence diagnostic value.
        if now - ctx.liveness.last_real_send_time > KEEPALIVE_SEND_INTERVAL:
            padded, target_size = _build_control_packet(ctx, PacketType.KEEPALIVE)
            ctx.scheduler.enqueue(padded, target_size)
            ctx.liveness.last_real_send_time = now


async def _tcp_recv_raced(
    transport: TCPTransport, shutdown_wait: asyncio.Task[bool]
) -> bytes | None:
    """Await one framed TCP read, racing it against shutdown.

    Returns the frame bytes, or ``None`` if shutdown won the race (the caller
    must then stop the recv loop). Re-raises ``ConnectionError`` on peer close.

    The framed ``transport.recv()`` has no internal timeout: a short
    cancellable timeout would cancel-then-RETRY mid-frame (after the 4-byte
    length prefix, before the payload) and desync the stream. But a bare,
    untimed read on a silent peer blocks forever, and a local-initiated
    shutdown (signal, dead-peer timeout, sibling-loop crash — all of which only
    *set* the event) could then never interrupt it, hanging ``gather()`` and
    deadlocking the AsyncExitStack kill-switch/TUN/resolv teardown. Racing the
    read against a long-lived shutdown waiter fixes both: on shutdown we cancel
    the in-flight read ENTIRELY (the session is tearing down, so abandoning the
    partial frame is correct and never resumed — no desync).
    """
    recv_task = asyncio.ensure_future(transport.recv())
    await asyncio.wait({recv_task, shutdown_wait}, return_when=asyncio.FIRST_COMPLETED)
    if not recv_task.done():
        recv_task.cancel()
        try:
            await recv_task
        except (asyncio.CancelledError, ConnectionError):
            pass
        return None
    return recv_task.result()  # may re-raise ConnectionError


async def run_data_loops(
    ctx: DataPathContext,
    transport: UDPTransport | TCPTransport,
    session_keys: tuncore.SessionKeyManager,
    replay: tuncore.ReplayWindow,
    fsm: SessionFSM,
    *,
    extra_loops: tuple[Awaitable[None], ...] = (),
    udp_addr_filter: Callable[[tuple[str, int]], bool] | None = None,
    post_authenticate: (
        Callable[[tuple[str, int], InnerPacket], Awaitable[None]] | None
    ) = None,
    shutdown_log: str = "shutting down",
) -> None:
    """Drive the steady-state recv/tun_send/liveness loops to completion.

    On exit — clean shutdown OR ``CancelledError`` from the surrounding
    AsyncExitStack — emits SESSION_CLOSE (best-effort) and transitions
    the FSM through TEARDOWN → IDLE so the caller's stack unwinds
    cleanly.

    Role-specific differences are parameterised:

    * ``udp_addr_filter`` (client): drop UDP datagrams whose source addr
      is not the expected server. ``None`` on the server, which has no
      single expected peer addr until the first authenticated packet.
    * ``post_authenticate`` (server): handle the source addr of an
      authenticated packet (the server learns the peer's UDP ephemeral port
      from the first valid frame, and gates any later egress roam behind a
      return-routability PATH_CHALLENGE/PATH_RESPONSE check). Receives the
      decrypted ``inner`` too so it can act on a PATH_RESPONSE; called BEFORE
      ``dispatch_inner`` so the egress decision is made before the payload is
      delivered.
    * ``extra_loops``: client passes ``auto_mtu_loop(...)`` here; server
      passes nothing.
    * ``shutdown_log``: caller-supplied label so the log line still
      distinguishes "shutting down" (client) vs "server shutting
      down".

    The caller owns scheduler.start() / .stop registration on the
    AsyncExitStack — this helper deliberately does NOT pull the stack
    inside itself, because the role module's stack registrations are
    unwind-order-sensitive (kill switch must outlast TUN teardown).
    """

    async def recv_loop() -> None:
        # Phase 1.6: for TCP, race each framed read against shutdown via a
        # single long-lived waiter (_tcp_recv_raced). See that helper for why.
        is_tcp = not isinstance(transport, UDPTransport)
        shutdown_wait: asyncio.Task[bool] | None = (
            asyncio.ensure_future(ctx.shutdown.wait()) if is_tcp else None
        )
        try:
            while not ctx.shutdown.is_set():
                recv_addr: tuple[str, int] | None = None
                try:
                    if isinstance(transport, UDPTransport):
                        data, recv_addr = await asyncio.wait_for(
                            transport.recv(),
                            timeout=0.1,
                        )
                        if udp_addr_filter is not None and not udp_addr_filter(
                            recv_addr
                        ):
                            log.debug(
                                "packet from unexpected source %s, dropping",
                                recv_addr,
                            )
                            continue
                    else:
                        assert shutdown_wait is not None
                        framed = await _tcp_recv_raced(transport, shutdown_wait)
                        if framed is None:
                            return  # shutdown won the race
                        data = framed
                except TimeoutError:
                    session_keys.tick()
                    continue
                except ConnectionError as e:
                    log.info("transport closed by peer: %s", e)
                    ctx.shutdown.set()
                    return

                result = decrypt_packet(data, session_keys, replay)
                if result is None:
                    continue

                ctx.liveness.last_recv_time = time.monotonic()

                inner, _prev_epoch = result

                # Server-side only: gate the egress-address roam. The first
                # addr commits; a DIFFERENT authenticated source is held as a
                # pending candidate and probed with a PATH_CHALLENGE (it does
                # NOT switch egress until it echoes the token in a
                # PATH_RESPONSE — return-routability). Runs BEFORE dispatch so
                # a PATH_RESPONSE is validated against recv_addr here; the
                # packet's payload still delivers to TUN via dispatch_inner.
                if post_authenticate is not None and recv_addr is not None:
                    await post_authenticate(recv_addr, inner)

                await dispatch_inner(ctx, inner)
        finally:
            if shutdown_wait is not None and not shutdown_wait.done():
                shutdown_wait.cancel()
                try:
                    await shutdown_wait
                except asyncio.CancelledError:
                    pass

    async def _tcp_idle_tick_loop() -> None:
        # Phase 1.6: drive session_keys.tick() (grace-period cleanup) on a
        # fixed cadence independent of the blocking framed recv. UDP gets its
        # tick from the recv_loop's 0.1s timeout; TCP's recv blocks, so it
        # needs its own ticker. Exits promptly on shutdown.
        if isinstance(transport, UDPTransport):
            return
        while not ctx.shutdown.is_set():
            try:
                await asyncio.wait_for(ctx.shutdown.wait(), timeout=0.1)
                return
            except TimeoutError:
                session_keys.tick()

    async def _supervised(coro: Awaitable[None], name: str) -> None:
        # DSM-001: contain each loop so one loop's terminal exception cannot
        # orphan its siblings. asyncio.gather() does NOT cancel the other
        # awaitables when one raises a non-CancelledError — it surfaces the
        # first exception while the rest keep running as detached tasks. For
        # the data loops that means recv/liveness/auto_mtu would keep
        # decrypting and writing the TUN while the caller's AsyncExitStack
        # tears down the fd/route/kill-switch — a use-after-teardown leak
        # window. Containing each loop here means any terminal error sets
        # ctx.shutdown (siblings then exit on their next ~0.1s poll) and is
        # swallowed AFTER logging, so gather() returns only once every loop
        # has actually stopped. CancelledError is NOT an Exception, so an
        # external AsyncExitStack cancel still propagates and unwinds gather.
        try:
            await coro
        except Exception:
            log.error(
                "data loop %r terminated unexpectedly — shutting down session",
                name,
                exc_info=True,
            )
            ctx.shutdown.set()

    try:
        await asyncio.gather(
            _supervised(recv_loop(), "recv"),
            _supervised(tun_send_loop(ctx), "tun_send"),
            _supervised(liveness_loop(ctx), "liveness"),
            _supervised(_tcp_idle_tick_loop(), "tcp_tick"),
            *(_supervised(c, f"extra[{i}]") for i, c in enumerate(extra_loops)),
        )
    except asyncio.CancelledError:
        pass
    finally:
        log.info("%s", shutdown_log)
        # Notify peer first (best-effort) so it sees a fast graceful
        # close rather than DEAD_PEER_TIMEOUT. Must fire BEFORE the
        # caller's AsyncExitStack unwinds — once scheduler/transport
        # are gone the send_fn is useless.
        await send_session_close(ctx)
        fsm.transition(State.TEARDOWN)
        fsm.transition(State.IDLE)


async def auto_mtu_loop(
    ctx: DataPathContext,
    transport: UDPTransport | TCPTransport,
    config: Config,
) -> None:
    """Track kernel-discovered path MTU; adjust the TUN MTU to match.

    Lower-on-drop is immediate; raise-toward ``config.mtu`` is gated on
    ``AUTO_MTU_HYSTERESIS_RISES`` consecutive observations of a stable
    larger usable MTU to avoid flap on transient PMTU bumps. Bounded
    below by ``MIN_TUN_MTU`` and above by ``config.mtu``.

    No-ops when:
      * ``config.auto_mtu`` is False
      * transport is non-UDP — kernel ``IP_MTU`` is meaningful only on
        UDP sockets with PMTU discovery enabled
    """
    if not config.auto_mtu:
        return
    if not isinstance(transport, UDPTransport):
        return

    current = config.mtu
    rises_observed = 0

    while not ctx.shutdown.is_set():
        try:
            await asyncio.wait_for(
                ctx.shutdown.wait(),
                timeout=config.pmtu_check_interval_s,
            )
            return  # shutdown
        except TimeoutError:
            pass

        path_mtu = transport.get_path_mtu()
        if path_mtu is None:
            continue

        usable = max(MIN_TUN_MTU, min(config.mtu, path_mtu - WIRE_OVERHEAD))

        if usable < current:
            try:
                ctx.tun.set_mtu(usable)
            except Exception as e:  # noqa: BLE001  # see linter report
                log.warning("auto_mtu: set_mtu(%d) failed: %s", usable, e)
                continue
            # Phase 1.7: also clamp the shaper's size-class ceiling so padded
            # / chaff outer packets fit the constrained path. The outer DSM
            # packet rides inside IP(20)+UDP(8), so the size-class ceiling is
            # path_mtu - 28.
            ctx.shaper.set_size_class_ceiling(path_mtu - 28)
            log.info(
                "auto_mtu: lowered tun mtu %d -> %d (kernel pmtu=%d)",
                current,
                usable,
                path_mtu,
            )
            netaudit.emit(
                "auto_mtu_change",
                direction="lower",
                old_mtu=current,
                new_mtu=usable,
                kernel_pmtu=path_mtu,
            )
            current = usable
            rises_observed = 0
        elif usable > current:
            rises_observed += 1
            if rises_observed >= AUTO_MTU_HYSTERESIS_RISES:
                try:
                    ctx.tun.set_mtu(usable)
                except Exception as e:  # noqa: BLE001  # see linter report
                    log.warning("auto_mtu: set_mtu(%d) failed: %s", usable, e)
                    rises_observed = 0
                    continue
                # Phase 1.7: track the recovered path on the shaper too. The
                # ceiling is bounded above by padding_max, so this restores the
                # size-class set toward the full budget as the path heals.
                ctx.shaper.set_size_class_ceiling(path_mtu - 28)
                log.info(
                    "auto_mtu: raised tun mtu %d -> %d after %d stable "
                    "observations (kernel pmtu=%d)",
                    current,
                    usable,
                    rises_observed,
                    path_mtu,
                )
                netaudit.emit(
                    "auto_mtu_change",
                    direction="raise",
                    old_mtu=current,
                    new_mtu=usable,
                    kernel_pmtu=path_mtu,
                    stable_observations=rises_observed,
                )
                current = usable
                rises_observed = 0
        else:
            rises_observed = 0


async def tun_send_loop(ctx: DataPathContext) -> None:
    """Read from TUN, fragment if needed, pad, enqueue for sending.

    Initiates rekey when the key manager signals rotation. Packets larger
    than ``MAX_INNER_PAYLOAD`` are split into FRAGMENT inner packets
    (receiver reassembles via ``ReassemblyBuffer``); packets beyond the
    16-fragment cap are dropped with a warning rather than crashing the
    send loop.
    """
    while not ctx.shutdown.is_set():
        if ctx.session_keys.needs_rotation() and not ctx.rekey.in_progress:
            # NOTE: do NOT set in_progress=True before calling initiate_rekey.
            # initiate_rekey can short-circuit (rate-limit, wrong FSM state)
            # and return (last_time, None, None) without sending an INIT.
            # If we set in_progress first, the flag would stick at True
            # forever (no payload → retry scheduler never fires → no
            # rotation completion → flag never cleared) and all future
            # rekey attempts would be blocked by ``not ctx.rekey.in_progress``.
            try:
                (
                    new_last_time,
                    new_pending_epoch,
                    init_payload,
                ) = await initiate_rekey(
                    ctx.session_keys,
                    ctx.fsm,
                    ctx.shaper,
                    ctx.send_fn,
                    ctx.rekey.last_time,
                    # Task 2.6: pace the REKEY_INIT onto the envelope. The
                    # retransmit budget is gated on REKEY_ACK_TIMEOUT (ACK
                    # receipt), not send completion, so fire-and-forget enqueue
                    # is safe — a paced INIT leaves within one latency budget.
                    paced_send=ctx.scheduler.enqueue,
                )
            except Exception:
                # An exception out of initiate_rekey must not leave the
                # rekey state half-initialized.
                ctx.rekey.in_progress = False
                raise
            ctx.rekey.last_time = new_last_time
            ctx.rekey.pending_epoch = new_pending_epoch
            # Only commit to in_progress=True if a real INIT went out.
            # Without payload there's nothing to retry against.
            if init_payload is not None:
                ctx.rekey.in_progress = True
                ctx.rekey.last_init_payload = init_payload
                ctx.rekey.last_init_sent_at = time.monotonic()
                ctx.rekey.retries_used = 0

        # Rekey retry scheduler: if we're still waiting on REKEY_ACK after
        # REKEY_ACK_TIMEOUT, retransmit the same INIT. After MAX_REKEY_RETRIES
        # exhausted, tear down — the session is dead in a way we can't recover
        # from (either network partition or peer is gone).
        if (
            ctx.rekey.in_progress
            and ctx.rekey.last_init_payload is not None
            and ctx.rekey.last_init_sent_at is not None
        ):
            since_sent = time.monotonic() - ctx.rekey.last_init_sent_at
            if since_sent >= REKEY_ACK_TIMEOUT:
                if ctx.rekey.retries_used >= MAX_REKEY_RETRIES:
                    log.error(
                        "rekey giving up after %d retries — tearing down",
                        ctx.rekey.retries_used,
                    )
                    ctx.shutdown.set()
                    return
                ctx.rekey.retries_used += 1
                log.warning(
                    "rekey ACK timeout — retransmitting INIT (attempt %d/%d)",
                    ctx.rekey.retries_used,
                    MAX_REKEY_RETRIES,
                )
                await resend_rekey_init(
                    ctx.rekey.last_init_payload,
                    ctx.session_keys,
                    ctx.shaper,
                    ctx.send_fn,
                    # Task 2.6: pace the retransmitted INIT (same envelope path
                    # as the original; the next ACK timeout is the recovery
                    # mechanism, so fire-and-forget is correct).
                    paced_send=ctx.scheduler.enqueue,
                )
                ctx.rekey.last_init_sent_at = time.monotonic()

        try:
            pkt = await asyncio.wait_for(ctx.tun.read(), timeout=0.1)
        except TimeoutError:
            continue

        epoch_id = ctx.session_keys.epoch & 0x0F
        try:
            inners = fragment_ip_packet(pkt, epoch_id, ctx.fragment_ids.next())
        except ValueError as e:
            # Packet exceeds the 16-fragment cap. Drop rather than crash;
            # the kernel will retransmit if this is TCP, and UDP senders
            # that exceed path MTU are already non-compliant.
            log.warning("dropping oversized TUN packet (%d bytes): %s", len(pkt), e)
            continue

        # Phase 2: the adaptive envelope (TrafficShaper.update_envelope /
        # release_budget, driven by the scheduler) smooths burst onset by
        # PACING the queue — real packets enter the same paced queue and the
        # envelope governs when they leave (within the latency budget).
        # H-ANON-1: spread out fragments across multiple jitter windows
        # so an oversized TUN packet doesn't produce a recognizable
        # "1 → N tightly-spaced packets" wire signature. Per-fragment
        # extra delay is uniformly distributed in [0, FRAG_SPREAD_S);
        # FRAG_SPREAD_S = 0.05 (50 ms) is comfortably larger than the
        # scheduler's max jitter (50 ms by default) so the fragments
        # are temporally interleaved with other queued packets rather
        # than emerging back-to-back. Total worst-case spread for 16
        # fragments is ~16 * 50 = 800 ms — meaningful but acceptable
        # for the rare oversized packet path; bulk transfers that
        # routinely fragment should configure a larger inner MTU.
        from dsm.core.rand import csprng_float

        # M-BUG-15: mark a real-data send so the keepalive loop's
        # 15s-idle check doesn't get bumped by chaff.
        ctx.liveness.last_real_send_time = time.monotonic()
        for i, inner in enumerate(inners):
            padded, target_size = ctx.shaper.pad_packet(inner)
            # H-ANON (size-feedback fix): real-packet sizes are no longer fed
            # back into any distribution. pad_packet draws the target class
            # from the FIXED published prior (the same one chaff uses) and
            # bumps up to fit the payload, so the real-traffic size histogram
            # cannot collapse onto one dominant class. The former
            # observe_real_packet feedback (the Polya-urn loop) is removed.
            # i=0 gets no extra delay; later fragments shuffle within
            # the per-position window.
            extra = (i + csprng_float()) * 0.05 if i > 0 else 0.0
            ctx.scheduler.enqueue(padded, target_size, extra_delay=extra)
