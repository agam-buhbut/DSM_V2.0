"""Regression tests for the data-loop driver's fail-closed containment.

Covers DSM-001 (a loop's terminal exception must not orphan its siblings —
it sets shutdown and the whole session tears down cleanly) and DSM-002 part A
(a UDP send with no destination addr must trigger shutdown, not raise into the
detached scheduler task).

All collaborators are faked at the I/O boundary so the tests are deterministic
and need neither the Rust ``tuncore`` extension nor real sockets.
"""

from __future__ import annotations

import asyncio
import unittest

from dsm.core.fsm import SessionFSM, State
from dsm.core.protocol import OUTER_HEADER_SIZE
from dsm.net.transport.udp import UDPTransport
from dsm.session import (
    DataPathContext,
    LivenessState,
    RekeyState,
    SequenceCounter,
    make_send_fn,
    run_data_loops,
)


class _IdleTun:
    """TUN fake whose read() never returns; wait_for(0.1) cancels it each cycle."""

    def __init__(self) -> None:
        self.writes: list[bytes] = []

    async def read(self, bufsize: int = 2048) -> bytes:
        await asyncio.sleep(3600)
        return b""

    async def awrite(self, data: bytes) -> int:
        self.writes.append(data)
        return len(data)


class _FakeSessionKeys:
    epoch = 0

    def needs_rotation(self) -> bool:
        return False

    def tick(self) -> None:
        pass

    def encrypt(self, data: bytes, aad: bytes) -> tuple[bytes, bytes, int]:
        # Echo the plaintext as ciphertext so the caller can size target_size
        # as OUTER_HEADER_SIZE + len(data) and pass OuterPacket.serialize's
        # exact-size check.
        return (b"\x00" * 12, data, 0)


class _FakeShaper:
    def burst_smoothing_delay(self) -> float | None:
        return None

    def pad_packet(self, inner: object) -> tuple[bytes, int]:
        return (b"\x00" * 16, 128)

    def observe_real_packet(self, size: int) -> None:
        pass

    def should_send_chaff(self) -> bool:
        return False


class _RecordingScheduler:
    def __init__(self) -> None:
        self.enqueued: list[tuple[bytes, int]] = []

    def enqueue(
        self, data: bytes, target_size: int, *, extra_delay: float = 0.0
    ) -> None:
        self.enqueued.append((data, target_size))


class _IdleTransport:
    """Non-UDP transport fake; recv() never returns so recv_loop stays idle."""

    async def recv(self, timeout: float | None = None) -> bytes:
        await asyncio.sleep(3600)
        return b""


def _established_fsm() -> SessionFSM:
    fsm = SessionFSM()
    fsm.transition(State.CONNECTING)
    fsm.transition(State.HANDSHAKING)
    fsm.transition(State.ESTABLISHED)
    return fsm


def _make_ctx() -> tuple[DataPathContext, list[tuple[bytes, int]], SessionFSM]:
    fsm = _established_fsm()
    sent: list[tuple[bytes, int]] = []

    async def send_fn(data: bytes, target_size: int) -> None:
        sent.append((data, target_size))

    ctx = DataPathContext(
        tun=_IdleTun(),  # type: ignore[arg-type]
        session_keys=_FakeSessionKeys(),  # type: ignore[arg-type]
        fsm=fsm,
        shaper=_FakeShaper(),  # type: ignore[arg-type]
        send_fn=send_fn,
        scheduler=_RecordingScheduler(),  # type: ignore[arg-type]
        rekey=RekeyState(),
        liveness=LivenessState(),
        shutdown=asyncio.Event(),
        reassembly=None,
    )
    return ctx, sent, fsm


class DataLoopContainment(unittest.IsolatedAsyncioTestCase):
    async def test_loop_exception_sets_shutdown_and_tears_down_cleanly(self) -> None:
        """DSM-001: a non-cancel exception in one loop must not orphan siblings.

        It sets ctx.shutdown, every sibling exits, SESSION_CLOSE is sent once,
        and the FSM ends in IDLE — run_data_loops returns normally (no raise).
        """
        ctx, sent, fsm = _make_ctx()

        async def boom() -> None:
            raise RuntimeError("loop boom")

        await asyncio.wait_for(
            run_data_loops(
                ctx,
                _IdleTransport(),  # type: ignore[arg-type]
                ctx.session_keys,
                None,  # type: ignore[arg-type]  # replay unused (recv stays idle)
                fsm,
                extra_loops=(boom(),),
            ),
            timeout=5,
        )

        self.assertTrue(ctx.shutdown.is_set())
        self.assertEqual(fsm.state, State.IDLE)
        self.assertEqual(len(sent), 1)  # exactly one SESSION_CLOSE

    async def test_external_cancel_drains_to_idle(self) -> None:
        """DSM-001: an external AsyncExitStack cancel still unwinds to IDLE.

        Locks the subtlety that the supervisor swallows ``Exception`` but NOT
        ``CancelledError`` — so a cancel propagates through gather, the
        ``except CancelledError`` runs the teardown finally, and the FSM
        reaches IDLE.
        """
        ctx, sent, fsm = _make_ctx()

        task = asyncio.create_task(
            run_data_loops(
                ctx,
                _IdleTransport(),  # type: ignore[arg-type]
                ctx.session_keys,
                None,  # type: ignore[arg-type]
                fsm,
            )
        )
        # Let the loops enter their await points before cancelling.
        await asyncio.sleep(0.05)
        task.cancel()
        await asyncio.wait_for(task, timeout=5)  # swallows cancel, runs finally

        self.assertEqual(fsm.state, State.IDLE)
        self.assertEqual(len(sent), 1)  # SESSION_CLOSE attempted during teardown


class UdpSendNoAddr(unittest.IsolatedAsyncioTestCase):
    async def test_udp_send_without_addr_triggers_shutdown_not_raise(self) -> None:
        """DSM-002 part A: addr=None must shut down, not raise into the loop."""
        shutdown = asyncio.Event()
        transport = UDPTransport()  # unbound; we never reach the actual send
        send_fn = make_send_fn(
            _FakeSessionKeys(),  # type: ignore[arg-type]
            transport,
            lambda: None,  # destination addr never known
            SequenceCounter(),
            shutdown=shutdown,
        )

        # Must NOT raise (raising would kill the detached scheduler task).
        # target_size matches the framed wire size so the sizing check passes
        # and we reach the addr=None branch under test.
        payload = b"hello"
        await send_fn(payload, OUTER_HEADER_SIZE + len(payload))

        self.assertTrue(shutdown.is_set())


if __name__ == "__main__":
    unittest.main()
