"""A lost REKEY_ACK is fixed by the initiator's resent REKEY_INIT.

Runs the real rekey handlers, send path and receive path on a pair of
real tuncore key managers. The responder applies the rotation when the
first INIT arrives, but that ACK is lost. The responder must keep its old
keys until the initiator sends under the new ones, so the resent INIT is
still read, the cached ACK goes back under the old send key, and both
sides end up on the new keys.

The Rust side holds the time-based part (old keys kept past the 5 s grace,
110 s limit) in its own unit tests: Rust's clock cannot be moved from here.
"""

from __future__ import annotations

import asyncio

import tuncore
from dsm.core.config import MAX_SHAPER_LATENCY_BUDGET_MS
from dsm.core.fsm import SessionFSM, State
from dsm.core.protocol import InnerPacket, PacketType
from dsm.rekey import (
    MAX_REKEY_RETRIES,
    MIN_REKEY_INTERVAL,
    REKEY_RETRY_BUDGET,
    handle_rekey_ack,
    handle_rekey_init,
    initiate_rekey,
    resend_rekey_init,
)
from dsm.session import SequenceCounter, decrypt_packet, make_send_fn
from dsm.traffic.shaper import TrafficShaper


class _Wire:
    """Stands in for the transport: keeps what was sent."""

    def __init__(self) -> None:
        self.sent: list[bytes] = []

    async def send(self, wire: bytes) -> None:
        self.sent.append(wire)


class _Peer:
    def __init__(self, keys: tuncore.SessionKeyManager) -> None:
        self.keys = keys
        self.fsm = SessionFSM()
        self.fsm.transition(State.CONNECTING)
        self.fsm.transition(State.HANDSHAKING)
        self.fsm.transition(State.ESTABLISHED)
        self.wire = _Wire()
        self.send_fn = make_send_fn(
            keys, self.wire, lambda: None, SequenceCounter()  # type: ignore[arg-type]
        )
        self.replay = tuncore.ReplayWindow()
        self.queued: list[tuple[bytes, int]] = []

    def paced_send(self, data: bytes, target_size: int) -> None:
        self.queued.append((data, target_size))

    async def flush(self) -> list[bytes]:
        """Send everything queued; return the wire packets."""
        for data, size in self.queued:
            await self.send_fn(data, size)
        self.queued.clear()
        out = list(self.wire.sent)
        self.wire.sent.clear()
        return out

    def receive(self, wire: bytes) -> tuple[InnerPacket, bool]:
        result = decrypt_packet(wire, self.keys, self.replay)
        assert result is not None, "packet must decrypt"
        return result


async def _unused_send(data: bytes, size: int) -> None:
    raise AssertionError("rekey packets must go through paced_send")


def _pair() -> tuple[_Peer, _Peer]:
    a = tuncore.BootstrapEphemeral.generate()
    b = tuncore.BootstrapEphemeral.generate()
    initiator = tuncore.complete_bootstrap(a, b.public_key_bytes, True)
    responder = tuncore.complete_bootstrap(b, a.public_key_bytes, False)
    return _Peer(initiator), _Peer(responder)


async def test_lost_ack_recovers_with_resent_init() -> None:
    init, resp = _pair()
    shaper = TrafficShaper(padding_min=128, padding_max=1400)
    old_epoch = resp.keys.epoch

    _t, new_epoch, payload = await initiate_rekey(
        init.keys, init.fsm, shaper, _unused_send, None, paced_send=init.paced_send
    )
    assert new_epoch is not None and payload is not None
    assert new_epoch == old_epoch + 1
    (wire,) = await init.flush()
    inner, _prev = resp.receive(wire)
    last_time, ack_epoch, ack_payload = await handle_rekey_init(
        inner.payload,
        resp.keys,
        resp.fsm,
        shaper,
        _unused_send,
        paced_send=resp.paced_send,
    )
    assert resp.keys.epoch == new_epoch

    # The ACK is lost on the way.
    assert len(await resp.flush()) == 1

    # The responder still sends under the old key and still reads it.
    assert resp.keys.send_epoch == old_epoch
    assert resp.keys.has_grace_period

    # The resent INIT (old key) is read and gets the cached ACK back.
    await resend_rekey_init(
        payload, init.keys, shaper, _unused_send, paced_send=init.paced_send
    )
    (wire,) = await init.flush()
    inner, used_prev = resp.receive(wire)
    assert inner.ptype == PacketType.REKEY_INIT and used_prev
    await handle_rekey_init(
        inner.payload,
        resp.keys,
        resp.fsm,
        shaper,
        _unused_send,
        last_time,
        ack_epoch,
        ack_payload,
        paced_send=resp.paced_send,
    )
    (wire,) = await resp.flush()
    inner, used_prev = init.receive(wire)
    assert inner.ptype == PacketType.REKEY_ACK and not used_prev
    assert handle_rekey_ack(inner.payload, init.keys, init.fsm, new_epoch) is not None
    assert init.keys.epoch == new_epoch

    # The first packet under the new keys switches the responder's send key.
    data = InnerPacket(ptype=PacketType.DATA, epoch_id=new_epoch & 0x0F, payload=b"hi")
    await init.send_fn(*shaper.pad_packet(data))
    (wire,) = await init.flush()
    inner, used_prev = resp.receive(wire)
    assert inner.payload == b"hi" and not used_prev
    assert resp.keys.send_epoch == new_epoch

    reply = InnerPacket(ptype=PacketType.DATA, epoch_id=new_epoch & 0x0F, payload=b"yo")
    await resp.send_fn(*shaper.pad_packet(reply))
    (wire,) = await resp.flush()
    inner, used_prev = init.receive(wire)
    assert inner.payload == b"yo" and not used_prev


def test_responder_waits_longer_than_the_retry_plan() -> None:
    # Rust and Python constants live in two languages; keep them in step.
    assert REKEY_RETRY_BUDGET > MIN_REKEY_INTERVAL
    # Each resend also waits for a send slot. At the slowest allowed setting a
    # first-tier gap is under half the largest latency budget (config.py's
    # first-tier rule), so the last resend reaches the responder by about
    # REKEY_RETRY_BUDGET + (MAX_REKEY_RETRIES + 1) * 2.5 s.
    longest_slot_wait = 0.5 * MAX_SHAPER_LATENCY_BUDGET_MS / 1000.0
    worst_last_resend = REKEY_RETRY_BUDGET + (MAX_REKEY_RETRIES + 1) * longest_slot_wait
    assert tuncore.REKEY_PEER_CONFIRM_LIMIT_SECS > worst_last_resend + 10


if __name__ == "__main__":
    asyncio.run(test_lost_ack_recovers_with_resent_init())
