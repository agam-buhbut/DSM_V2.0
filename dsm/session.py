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

from dsm.core.fsm import SessionFSM
from dsm.core.protocol import (
    Fragment, InnerPacket, OuterPacket, PacketType, ReassemblyBuffer,
    OUTER_HEADER_SIZE, SEQ_STRUCT, SIZE_CLASSES,
)
from dsm.net.transport.udp import UDPTransport
from dsm.net.transport.tcp import TCPTransport
from dsm.net.tunnel import TunDevice
from dsm.traffic.shaper import TrafficShaper
from dsm.traffic.scheduler import SendScheduler
from dsm.rekey import SendFn, initiate_rekey, handle_rekey_init, handle_rekey_ack

if TYPE_CHECKING:
    import tuncore

log = logging.getLogger(__name__)

# Liveness parameters (seconds)
KEEPALIVE_SEND_INTERVAL = 15.0   # emit KEEPALIVE if send-idle for this long
DEAD_PEER_TIMEOUT = 60.0         # tear down if recv-idle for this long
LIVENESS_CHECK_INTERVAL = 5.0    # cadence at which liveness_loop wakes


@dataclass
class LivenessState:
    """Tracks peer liveness via most-recent send/recv timestamps.

    Seeded with ``time.monotonic()`` so a freshly-established session is
    not flagged dead before the first packet arrives.
    """
    last_recv_time: float = field(default_factory=time.monotonic)
    last_send_time: float = field(default_factory=time.monotonic)


def setup_signal_handlers(shutdown: asyncio.Event) -> None:
    """Register SIGINT/SIGTERM to set the shutdown event."""
    import signal

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shutdown.set)


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

    Returns (plaintext, used_prev_epoch) or None on failure.
    """
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
    """Mutable rekey state shared between recv and send loops."""
    in_progress: bool = False
    last_time: float | None = None
    pending_epoch: int | None = None


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
    ctx.rekey.last_time = await handle_rekey_init(
        inner.payload, ctx.session_keys, ctx.fsm, ctx.shaper, ctx.send_fn,
        ctx.rekey.last_time,
    )


async def _handle_rekey_ack(ctx: DataPathContext, inner: InnerPacket) -> None:
    ts = handle_rekey_ack(
        inner.payload, ctx.session_keys, ctx.fsm, ctx.rekey.pending_epoch,
    )
    if ts is not None:
        ctx.rekey.last_time = ts
        ctx.rekey.pending_epoch = None
    ctx.rekey.in_progress = False


async def _handle_session_close(ctx: DataPathContext, inner: InnerPacket) -> None:
    ctx.shutdown.set()


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


async def tun_send_loop(ctx: DataPathContext) -> None:
    """Read from TUN, pad, enqueue for sending. Initiates rekey when needed."""
    while not ctx.shutdown.is_set():
        if ctx.session_keys.needs_rotation() and not ctx.rekey.in_progress:
            ctx.rekey.in_progress = True
            ctx.rekey.last_time, ctx.rekey.pending_epoch = await initiate_rekey(
                ctx.session_keys, ctx.fsm, ctx.shaper, ctx.send_fn, ctx.rekey.last_time,
            )

        try:
            pkt = await asyncio.wait_for(ctx.tun.read(), timeout=0.1)
        except asyncio.TimeoutError:
            continue

        inner = InnerPacket(
            ptype=PacketType.DATA,
            epoch_id=ctx.session_keys.epoch & 0x03,
            payload=pkt,
        )
        smoothing_delay = ctx.shaper.burst_smoothing_delay()
        if smoothing_delay is not None:
            await asyncio.sleep(smoothing_delay)
        padded, target_size = ctx.shaper.pad_packet(inner)
        ctx.shaper.observe_real_packet(target_size)
        ctx.scheduler.enqueue(padded, target_size)
