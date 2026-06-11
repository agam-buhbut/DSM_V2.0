"""Phase 1.6: a TCP frame split across reads with a >100ms inter-segment gap
must NOT desync the length prefix. Drives the real TCPTransport over a
loopback socket pair.
"""

from __future__ import annotations

import asyncio
import struct
import unittest
from unittest.mock import patch

from dsm.net.transport.tcp import TCPTransport

try:
    import tuncore

    _HAS_TUNCORE = True
except ImportError:
    tuncore = None  # type: ignore[assignment]
    _HAS_TUNCORE = False


class TcpFramingSplitRead(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self._p = patch("dsm.net.transport.tcp.apply_so_mark", lambda sock: None)
        self._p.start()
        self.addCleanup(self._p.stop)

    async def test_frame_split_with_gap_does_not_desync(self) -> None:
        # Wire two TCPTransports back-to-back over loopback.
        server = TCPTransport()

        async def run_server() -> int:
            return await server.listen("127.0.0.1", 0)

        listen_task = asyncio.ensure_future(run_server())
        await asyncio.sleep(0.05)
        # Pull the port the server bound.
        port = server._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]

        client = TCPTransport()
        await client.connect("127.0.0.1", port)
        await listen_task
        self.addCleanup(client.close)
        self.addCleanup(server.close)

        payload = b"DSM-FRAME-PAYLOAD-32-bytes-long!"
        frame = struct.pack("!I", len(payload)) + payload

        # Send the prefix, wait >100ms, then send the payload — simulating the
        # degraded-path inter-segment gap that the old wait_for(0.1) cancelled
        # mid-frame.
        writer = client._writer
        assert writer is not None
        writer.write(frame[:4])
        await writer.drain()

        async def delayed_tail() -> None:
            await asyncio.sleep(0.2)  # > 100ms gap
            writer.write(frame[4:])
            await writer.drain()

        tail_task = asyncio.ensure_future(delayed_tail())
        # recv() must return the full payload despite the gap.
        got = await asyncio.wait_for(server.recv(), timeout=2.0)
        await tail_task
        self.assertEqual(got, payload)

        # And a SECOND frame must still frame correctly (no desync).
        payload2 = b"second-frame-ok"
        frame2 = struct.pack("!I", len(payload2)) + payload2
        writer.write(frame2)
        await writer.drain()
        got2 = await asyncio.wait_for(server.recv(), timeout=2.0)
        self.assertEqual(got2, payload2)


class RecvLoopDesyncRegression(unittest.IsolatedAsyncioTestCase):
    """Reproduce the recv-loop-level desync the fix targets.

    The bug lives in ``recv_loop``'s EXTERNAL ``wait_for(0.1)`` around the
    framed TCP read, not in ``TCPTransport.recv()`` itself (which is correct
    in isolation). This test replicates BOTH recv-loop read patterns over a
    real loopback ``TCPTransport`` and asserts they diverge:

      * OLD pattern: ``await wait_for(transport.recv(), 0.1)`` — cancels the
        in-progress read after the 4-byte prefix is consumed but before the
        payload arrives, losing the length. The next read then mis-frames the
        payload bytes as a new prefix -> ``ValueError`` (frame length exceeds
        max) or a wrong-length read -> permanent desync.
      * NEW pattern: bare ``await transport.recv()`` — blocks until the whole
        frame arrives, returning it intact, and the next frame still frames.

    This fails against the old wrapped-wait_for behavior and passes against
    the fix's bare read.
    """

    async def asyncSetUp(self) -> None:
        self._p = patch("dsm.net.transport.tcp.apply_so_mark", lambda sock: None)
        self._p.start()
        self.addCleanup(self._p.stop)

    async def _wire_pair(self) -> tuple[TCPTransport, TCPTransport]:
        server = TCPTransport()

        async def run_server() -> int:
            return await server.listen("127.0.0.1", 0)

        listen_task = asyncio.ensure_future(run_server())
        await asyncio.sleep(0.05)
        port = server._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]
        client = TCPTransport()
        await client.connect("127.0.0.1", port)
        await listen_task
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        return server, client

    async def test_old_wrapped_wait_for_desyncs(self) -> None:
        """The OLD recv-loop read pattern desyncs across a >100ms gap."""
        server, client = await self._wire_pair()
        writer = client._writer
        assert writer is not None

        payload = b"DSM-FRAME-PAYLOAD-32-bytes-long!"
        frame = struct.pack("!I", len(payload)) + payload
        payload2 = b"second-frame-ok"
        frame2 = struct.pack("!I", len(payload2)) + payload2

        writer.write(frame[:4])
        await writer.drain()

        async def feeder() -> None:
            await asyncio.sleep(0.2)  # > the 0.1s bound: cancels mid-frame
            writer.write(frame[4:])
            await writer.drain()
            writer.write(frame2)
            await writer.drain()

        feeder_task = asyncio.ensure_future(feeder())

        # Emulate recv_loop's OLD behavior: read under a 0.1s wait_for. The
        # first call times out AFTER the prefix is consumed. The loop swallows
        # TimeoutError and retries; subsequent reads are now off by the lost
        # 4-byte prefix -> desync (ValueError or wrong payload).
        desynced = False
        results: list[bytes] = []
        for _ in range(6):
            try:
                got = await asyncio.wait_for(server.recv(), timeout=0.1)
                results.append(got)
            except TimeoutError:
                continue
            except (ValueError, ConnectionError):
                desynced = True
                break
        await feeder_task

        # Either an explicit frame error fired, OR we never recovered the two
        # clean frames in order — both are desync symptoms.
        clean = results == [payload, payload2]
        self.assertTrue(
            desynced or not clean,
            f"expected desync under old wrapped wait_for, got {results!r}",
        )

    async def test_new_bare_recv_does_not_desync(self) -> None:
        """The NEW recv-loop read pattern (bare recv) frames both intact."""
        server, client = await self._wire_pair()
        writer = client._writer
        assert writer is not None

        payload = b"DSM-FRAME-PAYLOAD-32-bytes-long!"
        frame = struct.pack("!I", len(payload)) + payload
        payload2 = b"second-frame-ok"
        frame2 = struct.pack("!I", len(payload2)) + payload2

        writer.write(frame[:4])
        await writer.drain()

        async def feeder() -> None:
            await asyncio.sleep(0.2)  # > 100ms gap
            writer.write(frame[4:])
            await writer.drain()
            writer.write(frame2)
            await writer.drain()

        feeder_task = asyncio.ensure_future(feeder())

        # Emulate recv_loop's NEW behavior: bare await, no short wait_for.
        got1 = await asyncio.wait_for(server.recv(), timeout=2.0)
        got2 = await asyncio.wait_for(server.recv(), timeout=2.0)
        await feeder_task

        self.assertEqual([got1, got2], [payload, payload2])


class _SilentMockTun:
    """Duck-typed `TunDevice` whose `read()` blocks forever.

    `tun_send_loop` reads from this under a 0.1s `wait_for`, so a blocking
    `read()` just makes the loop idle-spin without emitting traffic — which
    is what we want: the test exercises the recv-side shutdown interrupt,
    not the send path. Mirrors `_MockTun` in test_data_path_integration.py.
    """

    def __init__(self, name: str = "silent0") -> None:
        self.name = name
        self._block: asyncio.Event = asyncio.Event()  # never set → read blocks

    async def read(self, bufsize: int = 2048) -> bytes:
        await self._block.wait()  # blocks until cancelled
        return b""

    def write(self, data: bytes) -> int:
        return len(data)

    async def awrite(self, data: bytes) -> int:
        return len(data)

    def configure(self, *args: object, **kwargs: object) -> None:
        pass

    def deconfigure(self) -> None:
        pass

    def set_mtu(self, mtu: int) -> None:
        pass

    def open(self) -> None:
        pass

    def close(self) -> None:
        pass


@unittest.skipUnless(
    _HAS_TUNCORE,
    "tuncore (Rust crypto core) not built; run `maturin develop` in rust/tuncore/",
)
class RecvLoopShutdownInterrupt(unittest.IsolatedAsyncioTestCase):
    """Phase 1.6 second-fix: ``run_data_loops`` recv_loop must interrupt a
    TCP recv blocked on a SILENT peer when ``ctx.shutdown`` is set.

    The first Phase-1.6 fix removed a ``wait_for(0.1)`` that desynced the
    length prefix (covered by the tests above), but a bare
    ``await transport.recv()`` on a silent peer blocks forever. A local-
    initiated shutdown (signal / dead-peer timeout / sibling-loop crash)
    only *sets* ``ctx.shutdown``; without the race-fix nothing wakes the
    blocked recv, ``asyncio.gather`` never returns, and the caller's
    AsyncExitStack (kill-switch / TUN / resolv teardown) deadlocks.

    The fix races ``transport.recv()`` against a long-lived
    ``ctx.shutdown.wait()`` via ``asyncio.wait(FIRST_COMPLETED)`` and, on
    shutdown, cancels the in-flight recv and returns.

    This test wires a real loopback ``TCPTransport`` pair where the client
    peer NEVER sends, drives ``run_data_loops`` on the server side, sets
    ``ctx.shutdown`` after ~0.2s, and asserts ``run_data_loops`` returns
    well within a 3s bound.

    Non-vacuity: without the race-fix the recv_loop's ``await
    transport.recv()`` would be parked forever on the silent peer (the
    socket is open but no bytes ever arrive), and merely setting
    ``ctx.shutdown`` could not unblock it — the ``while not
    ctx.shutdown.is_set()`` guard is only re-checked between reads, never
    mid-read. ``gather`` would hang and ``asyncio.wait_for(..., 3.0)``
    would raise ``TimeoutError``, failing the assertion.
    """

    async def asyncSetUp(self) -> None:
        self._p = patch("dsm.net.transport.tcp.apply_so_mark", lambda sock: None)
        self._p.start()
        self.addCleanup(self._p.stop)

    async def _wire_pair(self) -> tuple[TCPTransport, TCPTransport]:
        server = TCPTransport()

        async def run_server() -> int:
            return await server.listen("127.0.0.1", 0)

        listen_task = asyncio.ensure_future(run_server())
        await asyncio.sleep(0.05)
        port = server._server.sockets[0].getsockname()[1]  # type: ignore[union-attr]
        client = TCPTransport()
        await client.connect("127.0.0.1", port)
        await listen_task
        self.addCleanup(client.close)
        self.addCleanup(server.close)
        return server, client

    def _build_ctx(
        self,
        transport: TCPTransport,
        keys: tuncore.SessionKeyManager,
    ) -> tuple[object, asyncio.Event]:
        """Minimal DataPathContext for a TCP server side, no handshake.

        Mirrors the minimal-context construction in
        test_data_path_integration.py::test_rekey_retry_scheduler_fires_on_timeout
        (a capturing-or-real send_fn, a SilentMockTun, an ESTABLISHED FSM,
        and zero-jitter no-chaff scheduler).
        """
        from dsm.core.fsm import SessionFSM, State
        from dsm.core.protocol import ReassemblyBuffer
        from dsm.session import (
            DataPathContext,
            LivenessState,
            RekeyState,
            SequenceCounter,
            make_send_fn,
        )
        from dsm.traffic.scheduler import SendScheduler
        from dsm.traffic.shaper import TrafficShaper, make_chaff_packet

        fsm = SessionFSM()
        fsm.transition(State.CONNECTING)
        fsm.transition(State.HANDSHAKING)
        fsm.transition(State.ESTABLISHED)

        shaper = TrafficShaper(padding_min=128, padding_max=1400)
        seq = SequenceCounter()
        liveness = LivenessState()
        shutdown = asyncio.Event()
        # TCP: dest_addr is unused inside make_send_fn (the TCP branch sends
        # without an addr), so a None-returning closure is fine.
        send_fn = make_send_fn(keys, transport, lambda: None, seq, liveness=liveness)
        scheduler = SendScheduler(
            send_fn=send_fn,
            chaff_fn=lambda: make_chaff_packet(shaper, keys.epoch & 0x0F),
            should_chaff_fn=lambda: False,
            jitter_ms_min=0,
            jitter_ms_max=0,
        )
        ctx = DataPathContext(
            tun=_SilentMockTun("server"),  # type: ignore[arg-type]
            session_keys=keys,
            fsm=fsm,
            shaper=shaper,
            send_fn=send_fn,
            scheduler=scheduler,
            rekey=RekeyState(),
            liveness=liveness,
            shutdown=shutdown,
            reassembly=ReassemblyBuffer(),
        )
        return ctx, shutdown

    async def test_shutdown_interrupts_blocked_tcp_recv(self) -> None:
        from dsm.core.fsm import SessionFSM, State
        from dsm.session import run_data_loops

        server_transport, _client_transport = await self._wire_pair()

        # Paired bootstrap so the SessionKeyManager is a real tuncore object;
        # the client never sends, so the keys are only exercised by the
        # teardown SESSION_CLOSE encrypt (which must not block the assertion).
        our_eph = tuncore.BootstrapEphemeral.generate()
        peer_eph = tuncore.BootstrapEphemeral.generate()
        keys = tuncore.complete_bootstrap(
            our_eph, bytes(peer_eph.public_key_bytes), is_initiator=False
        )

        ctx, shutdown = self._build_ctx(server_transport, keys)

        replay = tuncore.ReplayWindow()
        # A fresh FSM threaded as run_data_loops' `fsm` arg (it drives the
        # TEARDOWN/IDLE transitions on exit). Keep it distinct from ctx.fsm
        # to avoid double-transition asserts.
        loop_fsm = SessionFSM()
        loop_fsm.transition(State.CONNECTING)
        loop_fsm.transition(State.HANDSHAKING)
        loop_fsm.transition(State.ESTABLISHED)

        await ctx.scheduler.start()  # type: ignore[attr-defined]
        self.addAsyncCleanup(ctx.scheduler.stop)  # type: ignore[attr-defined]

        async def _drive() -> None:
            run_task = asyncio.ensure_future(
                run_data_loops(
                    ctx,  # type: ignore[arg-type]
                    server_transport,
                    keys,
                    replay,
                    loop_fsm,
                )
            )
            # Let the recv_loop park on the silent peer's TCP recv, THEN set
            # shutdown (simulating a signal / dead-peer timeout). Setting it
            # first proves we exercise the shutdown-interrupt path, not the
            # dead-peer path (DEAD_PEER_TIMEOUT is 60s — far beyond this test).
            await asyncio.sleep(0.2)
            self.assertFalse(
                run_task.done(),
                "run_data_loops returned before shutdown was set — "
                "recv was not actually blocking on the silent peer",
            )
            shutdown.set()
            await run_task

        # The load-bearing assertion: with the race-fix this returns promptly;
        # without it the blocked TCP recv hangs gather() forever and this
        # raises TimeoutError.
        await asyncio.wait_for(_drive(), timeout=3.0)

        self.assertTrue(shutdown.is_set())


if __name__ == "__main__":
    unittest.main()
