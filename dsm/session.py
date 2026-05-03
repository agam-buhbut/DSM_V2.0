"""Shared session data path: encrypt/send, decrypt/dispatch, TUN forwarding.

Extracted from client.py and server.py to eliminate duplication.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from collections.abc import Awaitable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable

from dsm.core.config import Config, MIN_TUN_MTU
from dsm.core.fsm import SessionFSM
from dsm.core.protocol import (
    Fragment, InnerPacket, OuterPacket, PacketType, ReassemblyBuffer,
    OUTER_HEADER_SIZE, SEQ_STRUCT, SIZE_CLASSES, fragment_ip_packet,
)
from dsm.net.transport.udp import UDPTransport
from dsm.net.transport.tcp import TCPTransport
from dsm.net.tunnel import TunDevice
from dsm.traffic.shaper import TrafficShaper
from dsm.traffic.scheduler import SendScheduler
from dsm.rekey import (
    MAX_REKEY_RETRIES, REKEY_ACK_TIMEOUT, SendFn, initiate_rekey,
    handle_rekey_ack, handle_rekey_init, resend_rekey_init,
)

if TYPE_CHECKING:
    import tuncore

log = logging.getLogger(__name__)

# Liveness parameters (seconds)
KEEPALIVE_SEND_INTERVAL = 15.0   # emit KEEPALIVE if send-idle for this long
DEAD_PEER_TIMEOUT = 60.0         # tear down if recv-idle for this long
LIVENESS_CHECK_INTERVAL = 5.0    # cadence at which liveness_loop wakes

# Wire overhead per outer packet — IP(20) + UDP(8) + outer header(20) +
# GCM tag(16) + inner header(4) = 68 bytes. Subtracted from the kernel-
# discovered path MTU to size the inner TUN MTU.
WIRE_OVERHEAD = 68

# auto-MTU adapter: how many consecutive same-or-higher path-MTU
# observations are required before raising the TUN MTU back toward
# config.mtu. Guards against transient PMTU bumps causing flap.
AUTO_MTU_HYSTERESIS_RISES = 3


@dataclass
class LivenessState:
    """Tracks peer liveness via most-recent send/recv timestamps.

    Seeded with ``time.monotonic()`` so a freshly-established session is
    not flagged dead before the first packet arrives.
    """
    last_recv_time: float = field(default_factory=time.monotonic)
    last_send_time: float = field(default_factory=time.monotonic)


def setup_signal_handlers(shutdown: asyncio.Event) -> None:
    """Register termination signals to set the shutdown event.

    SIGHUP and SIGQUIT are included so that ``systemctl reload`` (sends
    SIGHUP) and Ctrl-\\ (SIGQUIT) trigger graceful AsyncExitStack
    unwind rather than killing the process and leaving nftables, TUN,
    resolv.conf, and sysctl state on the host. We do not support config
    reload — SIGHUP is treated as shutdown.
    """
    import signal

    from dsm.core import netaudit

    def _on_signal(sig_name: str) -> None:
        netaudit.emit("shutdown_signal", source=sig_name)
        shutdown.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
        loop.add_signal_handler(sig, _on_signal, sig.name)


@dataclass
class SequenceCounter:
    """Monotonic 64-bit outer-packet sequence counter.

    Kept as a dataclass so every caller mutates the same instance — a plain
    ``int`` closed over by ``send_packet`` cannot be incremented in place.
    """
    value: int = 0

    def next(self) -> int:
        self.value += 1
        if self.value >= 2**64:
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
) -> SendFn:
    """Create a send_packet closure."""

    # For TCP, always use max size class so the length-prefix is constant,
    # preventing passive traffic analysis via frame sizes.
    tcp_fixed_size = SIZE_CLASSES[-1] if isinstance(transport, TCPTransport) else 0

    async def send_packet(data: bytes, target_size: int) -> None:
        n = seq.next()
        if tcp_fixed_size and tcp_fixed_size > target_size:
            # Fixed-size TCP framing: extend in place to avoid the
            # intermediate concat buffer on the send hot path. Entropy
            # source is still `os.urandom`, unchanged.
            pad_len = tcp_fixed_size - target_size
            buf = bytearray(tcp_fixed_size)
            buf[:target_size] = data
            buf[target_size:] = os.urandom(pad_len)
            data = bytes(buf)
            target_size = tcp_fixed_size
        aad = SEQ_STRUCT.pack(n)
        nonce, ct, _epoch = session_keys.encrypt(data, aad)
        outer = OuterPacket(seq=n, nonce=nonce, ciphertext=ct)
        wire = outer.serialize(target_size)
        if isinstance(transport, UDPTransport):
            addr = dest_addr()
            if addr is None:
                raise RuntimeError("UDP send requires destination address")
            await transport.send(wire, addr)
        else:
            await transport.send(wire)
        if liveness is not None:
            liveness.last_send_time = time.monotonic()

    return send_packet


def _decrypt_with_fallback(
    session_keys: tuncore.SessionKeyManager,
    nonce: bytes,
    ciphertext: bytes,
    aad: bytes,
    seq: int,
) -> tuple[bytes, bool] | None:
    """Try current-epoch decrypt, then previous-epoch if in grace period.

    Returns (plaintext, used_prev_epoch) or None on failure. The PyO3
    bridge returns ``list[int]`` for ``Vec<u8>``; we coerce to ``bytes``
    here so downstream ``struct.unpack_from`` calls on the plaintext work.
    """
    try:
        return bytes(session_keys.decrypt(nonce, ciphertext, aad, seq, False)), False
    except RuntimeError:
        pass
    if session_keys.has_grace_period:
        try:
            return bytes(session_keys.decrypt(nonce, ciphertext, aad, seq, True)), True
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
    """
    if len(data) < OUTER_HEADER_SIZE:
        log.debug("packet too short, dropping")
        return None

    seq = SEQ_STRUCT.unpack_from(data)[0]
    if not replay.check(seq):
        log.debug("replay detected, dropping seq=%d", seq)
        return None

    nonce_bytes = data[8:20]
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

    # Verify epoch_id matches the key epoch used for decryption
    if inner.ptype != PacketType.CHAFF:
        if decrypted_prev_epoch:
            expected_eid = (session_keys.epoch - 1) & 0x03
        else:
            expected_eid = session_keys.epoch & 0x03
        if inner.epoch_id != expected_eid:
            log.debug("epoch_id mismatch: got %d, expected %d", inner.epoch_id, expected_eid)
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
    (
        ctx.rekey.last_time,
        ctx.rekey.cached_ack_epoch,
        ctx.rekey.cached_ack_payload,
    ) = await handle_rekey_init(
        inner.payload, ctx.session_keys, ctx.fsm, ctx.shaper, ctx.send_fn,
        ctx.rekey.last_time,
        cached_ack_epoch=ctx.rekey.cached_ack_epoch,
        cached_ack_payload=ctx.rekey.cached_ack_payload,
    )


async def _handle_rekey_ack(ctx: DataPathContext, inner: InnerPacket) -> None:
    ts = handle_rekey_ack(
        inner.payload, ctx.session_keys, ctx.fsm, ctx.rekey.pending_epoch,
    )
    if ts is not None:
        ctx.rekey.last_time = ts
        ctx.rekey.pending_epoch = None
        # Successful ACK — clear retry scheduler state.
        ctx.rekey.reset_retry()
    ctx.rekey.in_progress = False


async def _handle_session_close(ctx: DataPathContext, inner: InnerPacket) -> None:
    ctx.shutdown.set()


async def send_session_close(ctx: DataPathContext) -> None:
    """Send a single SESSION_CLOSE packet to notify the peer of graceful exit.

    Bypasses the scheduler (direct send_fn call) so the packet leaves
    immediately; otherwise shutdown could tear down the scheduler before
    the queued close packet flushed. Best-effort: errors are logged, not
    raised — shutdown must continue regardless.
    """
    inner = InnerPacket(
        ptype=PacketType.SESSION_CLOSE,
        epoch_id=ctx.session_keys.epoch & 0x03,
        payload=b"",
    )
    try:
        padded, target_size = ctx.shaper.pad_packet(inner)
        await ctx.send_fn(padded, target_size)
    except Exception as e:
        # Debug-level: the peer being gone at shutdown is the common case
        # (we may be shutting down BECAUSE the peer disappeared). Warning
        # would be noise on every disconnect.
        log.debug("SESSION_CLOSE send failed (continuing shutdown): %s", e)


async def _handle_noop(ctx: DataPathContext, inner: InnerPacket) -> None:
    """No-op for CHAFF and KEEPALIVE — liveness is accounted in recv_loop."""


_DISPATCH: dict[PacketType, Callable[[DataPathContext, InnerPacket], Awaitable[None]]] = {
    PacketType.CHAFF: _handle_noop,
    PacketType.KEEPALIVE: _handle_noop,
    PacketType.DATA: _handle_data,
    PacketType.FRAGMENT: _handle_fragment,
    PacketType.REKEY_INIT: _handle_rekey_init,
    PacketType.REKEY_ACK: _handle_rekey_ack,
    PacketType.SESSION_CLOSE: _handle_session_close,
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
        except asyncio.TimeoutError:
            pass

        now = time.monotonic()
        recv_idle = now - ctx.liveness.last_recv_time
        if recv_idle > DEAD_PEER_TIMEOUT:
            log.warning(
                "dead peer: no packets received for %.1fs, tearing down session",
                recv_idle,
            )
            from dsm.core import netaudit
            netaudit.emit(
                "liveness_fire",
                reason="dead_peer_timeout",
                recv_idle_s=round(recv_idle, 2),
                threshold_s=DEAD_PEER_TIMEOUT,
            )
            ctx.shutdown.set()
            return

        if now - ctx.liveness.last_send_time > KEEPALIVE_SEND_INTERVAL:
            inner = InnerPacket(
                ptype=PacketType.KEEPALIVE,
                epoch_id=ctx.session_keys.epoch & 0x03,
                payload=b"",
            )
            padded, target_size = ctx.shaper.pad_packet(inner)
            ctx.scheduler.enqueue(padded, target_size)


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
                ctx.shutdown.wait(), timeout=config.pmtu_check_interval_s,
            )
            return  # shutdown
        except asyncio.TimeoutError:
            pass

        path_mtu = transport.get_path_mtu()
        if path_mtu is None:
            continue

        usable = max(MIN_TUN_MTU, min(config.mtu, path_mtu - WIRE_OVERHEAD))

        if usable < current:
            try:
                ctx.tun.set_mtu(usable)
            except Exception as e:
                log.warning("auto_mtu: set_mtu(%d) failed: %s", usable, e)
                continue
            log.info(
                "auto_mtu: lowered tun mtu %d -> %d (kernel pmtu=%d)",
                current, usable, path_mtu,
            )
            from dsm.core import netaudit
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
                except Exception as e:
                    log.warning("auto_mtu: set_mtu(%d) failed: %s", usable, e)
                    rises_observed = 0
                    continue
                log.info(
                    "auto_mtu: raised tun mtu %d -> %d after %d stable observations (kernel pmtu=%d)",
                    current, usable, rises_observed, path_mtu,
                )
                from dsm.core import netaudit
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
            ctx.rekey.in_progress = True
            (
                ctx.rekey.last_time,
                ctx.rekey.pending_epoch,
                init_payload,
            ) = await initiate_rekey(
                ctx.session_keys, ctx.fsm, ctx.shaper, ctx.send_fn, ctx.rekey.last_time,
            )
            # Record the INIT payload + send time so the retry scheduler
            # below can retransmit on ACK timeout.
            if init_payload is not None:
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
                    ctx.rekey.retries_used, MAX_REKEY_RETRIES,
                )
                await resend_rekey_init(
                    ctx.rekey.last_init_payload, ctx.session_keys,
                    ctx.shaper, ctx.send_fn,
                )
                ctx.rekey.last_init_sent_at = time.monotonic()

        try:
            pkt = await asyncio.wait_for(ctx.tun.read(), timeout=0.1)
        except asyncio.TimeoutError:
            continue

        epoch_id = ctx.session_keys.epoch & 0x03
        try:
            inners = fragment_ip_packet(pkt, epoch_id, ctx.fragment_ids.next())
        except ValueError as e:
            # Packet exceeds the 16-fragment cap. Drop rather than crash;
            # the kernel will retransmit if this is TCP, and UDP senders
            # that exceed path MTU are already non-compliant.
            log.warning("dropping oversized TUN packet (%d bytes): %s", len(pkt), e)
            continue

        smoothing_delay = ctx.shaper.burst_smoothing_delay()
        if smoothing_delay is not None:
            await asyncio.sleep(smoothing_delay)
        for inner in inners:
            padded, target_size = ctx.shaper.pad_packet(inner)
            ctx.shaper.observe_real_packet(target_size)
            ctx.scheduler.enqueue(padded, target_size)
