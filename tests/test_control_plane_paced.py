"""Task 2.6 (Fork 7 = YES): control-plane packets ride the paced envelope.

Rekey REKEY_INIT / REKEY_ACK during normal operation are routed through the
SAME paced scheduler.enqueue path that real data/chaff packets use, so their
wire timing matches the steady enveloped stream (no control-plane timing
fingerprint). Two carve-outs are preserved:

  * the DUPLICATE-INIT cached-ACK replay keeps the bounded DIRECT ``send_fn``
    (it must be observable within 5 s — the lost-ACK recovery, Task 1.1);
  * the TEARDOWN SESSION_CLOSE keeps the bounded DIRECT ``send_fn`` (the
    scheduler is about to be stopped, so a paced enqueue might never flush).

Backward compat: when no ``paced_send`` is supplied the helpers fall back to
the legacy direct ``send_fn`` (the pre-existing integration tests rely on it).

The scheduler/transport is faked at the I/O boundary. The pure-Python routing
assertions (INIT, resend, fallback, teardown) need no tuncore; the responder
ACK paths need a real ``SessionKeyManager`` for the rotation and are gated.
"""

from __future__ import annotations

import asyncio
import struct
import unittest

try:
    import tuncore

    _HAS_TUNCORE = True
except ImportError:
    tuncore = None  # type: ignore[assignment]
    _HAS_TUNCORE = False

from dsm.core.fsm import SessionFSM, State
from dsm.core.protocol import PacketType
from dsm.rekey import (
    handle_rekey_init,
    initiate_rekey,
    resend_rekey_init,
)
from dsm.session import (
    DataPathContext,
    LivenessState,
    RekeyState,
    send_session_close,
)
from dsm.traffic.shaper import TrafficShaper


class _RecordingScheduler:
    """Captures paced enqueues at the scheduler boundary (sync, fire-and-forget)."""

    def __init__(self) -> None:
        self.enqueued: list[tuple[bytes, int]] = []

    def enqueue(
        self, data: bytes, target_size: int, *, extra_delay: float = 0.0
    ) -> None:
        self.enqueued.append((data, target_size))


def _established_fsm() -> SessionFSM:
    fsm = SessionFSM()
    fsm.transition(State.CONNECTING)
    fsm.transition(State.HANDSHAKING)
    fsm.transition(State.ESTABLISHED)
    return fsm


class _FakeRotatingKeys:
    """Minimal SessionKeyManager stand-in for the INIT routing assertions.

    Only ``epoch`` and ``initiate_rotation`` are exercised on this path
    (initiate_rekey never touches the responder/decrypt machinery).
    """

    epoch = 0

    def initiate_rotation(self) -> tuple[int, bytes]:
        return 1, b"\x11" * 32


class InitRoutingThroughEnvelope(unittest.IsolatedAsyncioTestCase):
    """REKEY_INIT goes through paced_send when provided, direct send_fn when not."""

    def setUp(self) -> None:
        self.shaper = TrafficShaper(128, 1400)
        self.direct_sends: list[tuple[bytes, int]] = []

    async def _direct(self, data: bytes, target_size: int) -> None:
        self.direct_sends.append((data, target_size))

    async def test_init_routes_through_paced_send(self) -> None:
        sched = _RecordingScheduler()
        fsm = _established_fsm()
        keys = _FakeRotatingKeys()

        ts, new_epoch, payload = await initiate_rekey(
            keys,  # type: ignore[arg-type]
            fsm,
            self.shaper,
            self._direct,
            paced_send=sched.enqueue,
        )

        self.assertIsNotNone(payload)
        self.assertEqual(new_epoch, 1)
        self.assertIsNotNone(ts)
        # INIT enqueued through the paced scheduler, NOT the direct send_fn.
        self.assertEqual(len(sched.enqueued), 1, "INIT must be paced via enqueue")
        self.assertEqual(self.direct_sends, [], "INIT must NOT use direct send_fn")

    async def test_init_falls_back_to_direct_send_without_paced(self) -> None:
        fsm = _established_fsm()
        keys = _FakeRotatingKeys()

        _ts, _epoch, payload = await initiate_rekey(
            keys,  # type: ignore[arg-type]
            fsm,
            self.shaper,
            self._direct,
        )

        self.assertIsNotNone(payload)
        # No paced_send: legacy direct path (pre-existing tests rely on this).
        self.assertEqual(len(self.direct_sends), 1)

    async def test_resend_init_routes_through_paced_send(self) -> None:
        sched = _RecordingScheduler()
        keys = _FakeRotatingKeys()
        payload = struct.pack("!I", 1) + b"\x22" * 32

        await resend_rekey_init(
            payload,
            keys,  # type: ignore[arg-type]
            self.shaper,
            self._direct,
            paced_send=sched.enqueue,
        )

        self.assertEqual(len(sched.enqueued), 1, "resend INIT must be paced")
        self.assertEqual(self.direct_sends, [])


def _responder() -> tuncore.SessionKeyManager:
    ours = tuncore.BootstrapEphemeral.generate()
    peer = tuncore.BootstrapEphemeral.generate()
    return tuncore.complete_bootstrap(ours, peer.public_key_bytes, False)


@unittest.skipUnless(_HAS_TUNCORE, "tuncore extension not built")
class AckRoutingThroughEnvelope(unittest.IsolatedAsyncioTestCase):
    """Normal REKEY_ACK is paced; the duplicate-INIT cached-ACK replay is direct."""

    async def test_normal_ack_routes_through_paced_send(self) -> None:
        keys = _responder()
        fsm = _established_fsm()
        shaper = TrafficShaper(128, 1400)
        sched = _RecordingScheduler()
        direct: list[tuple[bytes, int]] = []

        async def _direct(data: bytes, size: int) -> None:
            direct.append((data, size))

        new_epoch = keys.epoch + 1
        eph = tuncore.BootstrapEphemeral.generate()
        payload = struct.pack("!I", new_epoch) + eph.public_key_bytes

        _ts, cached_epoch, cached_payload = await handle_rekey_init(
            payload,
            keys,
            fsm,
            shaper,
            _direct,
            last_rekey_time=None,
            paced_send=sched.enqueue,
        )

        # Responder completed the rotation and cached the ACK.
        self.assertEqual(cached_epoch, new_epoch)
        self.assertIsNotNone(cached_payload)
        self.assertEqual(keys.epoch, new_epoch)
        # The ACK left via the paced scheduler, not the direct bounded send.
        self.assertEqual(len(sched.enqueued), 1, "normal ACK must be paced")
        self.assertEqual(direct, [], "normal ACK must NOT use direct send_fn")

    async def test_duplicate_init_cached_ack_replay_uses_direct_send(self) -> None:
        keys = _responder()
        fsm = _established_fsm()
        shaper = TrafficShaper(128, 1400)
        sched = _RecordingScheduler()
        direct: list[tuple[bytes, int]] = []

        async def _direct(data: bytes, size: int) -> None:
            direct.append((data, size))

        new_epoch = keys.epoch + 1
        eph = tuncore.BootstrapEphemeral.generate()
        payload = struct.pack("!I", new_epoch) + eph.public_key_bytes

        # First INIT: completes rotation, caches the ACK (paced).
        _ts, cached_epoch, cached_payload = await handle_rekey_init(
            payload,
            keys,
            fsm,
            shaper,
            _direct,
            last_rekey_time=None,
            paced_send=sched.enqueue,
        )
        paced_after_first = len(sched.enqueued)
        self.assertEqual(paced_after_first, 1)
        self.assertEqual(direct, [])

        # Duplicate INIT (the client's first ACK was lost) → cached-ACK replay.
        # This MUST take the bounded DIRECT path so it is observable within 5 s
        # (Task 1.1 lost-ACK recovery), NOT the paced enqueue.
        await handle_rekey_init(
            payload,
            keys,
            fsm,
            shaper,
            _direct,
            last_rekey_time=None,
            cached_ack_epoch=cached_epoch,
            cached_ack_payload=cached_payload,
            paced_send=sched.enqueue,
        )

        self.assertEqual(
            len(sched.enqueued),
            paced_after_first,
            "cached-ACK replay must NOT be paced (bounded direct send only)",
        )
        self.assertEqual(len(direct), 1, "cached-ACK replay must use direct send_fn")


class TeardownSessionCloseStaysDirect(unittest.IsolatedAsyncioTestCase):
    """The teardown SESSION_CLOSE keeps the bounded DIRECT send (carve-out)."""

    async def test_session_close_uses_direct_send_not_scheduler(self) -> None:
        sched = _RecordingScheduler()
        direct: list[tuple[bytes, int]] = []

        async def _direct(data: bytes, size: int) -> None:
            direct.append((data, size))

        class _FakeKeys:
            epoch = 0

        ctx = DataPathContext(
            tun=None,  # type: ignore[arg-type]
            session_keys=_FakeKeys(),  # type: ignore[arg-type]
            fsm=_established_fsm(),
            shaper=TrafficShaper(128, 1400),
            send_fn=_direct,
            scheduler=sched,  # type: ignore[arg-type]
            rekey=RekeyState(),
            liveness=LivenessState(),
            shutdown=asyncio.Event(),
        )

        await send_session_close(ctx)

        # Teardown close goes out directly; the scheduler is untouched.
        self.assertEqual(len(direct), 1, "teardown SESSION_CLOSE must be direct")
        self.assertEqual(sched.enqueued, [], "teardown SESSION_CLOSE must NOT be paced")
        self.assertEqual(PacketType.SESSION_CLOSE, 0x06)


if __name__ == "__main__":
    unittest.main()
