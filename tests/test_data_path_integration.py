"""End-to-end data path integration test.

Spins up two peers on loopback UDP with real `UDPTransport`, completes the
full Noise XX + bootstrap handshake, then drives both ends' `tun_send_loop`
and recv loops against *mock* TUN devices — the kernel is not involved.

Verifies:
  * Small payload (no fragmentation) roundtrips byte-exact both directions.
  * Large payload (>MAX_INNER_PAYLOAD, fragmented) roundtrips intact via
    the send-side fragmenter + `ReassemblyBuffer`.
  * Graceful `SESSION_CLOSE` triggers the other side's shutdown event.

If any piece of the glue between components is broken (list-vs-bytes
coercion, nonce framing, epoch_id, scheduler drops, etc.) this test will
find it.
"""

from __future__ import annotations

import asyncio
import time
import unittest
from unittest.mock import patch

try:
    import tuncore

    _HAS_TUNCORE = True
except ImportError:
    tuncore = None  # type: ignore[assignment]
    _HAS_TUNCORE = False


class _MockTun:
    """Duck-typed stand-in for `dsm.net.tunnel.TunDevice`.

    Attributes/methods match what `tun_send_loop`, `_handle_data`,
    `_handle_fragment`, and the teardown paths touch.
    """

    def __init__(self, name: str = "mock0") -> None:
        self.name = name
        self._to_send: asyncio.Queue[bytes] = asyncio.Queue()
        self.received: list[bytes] = []

    async def read(self, bufsize: int = 2048) -> bytes:
        # Wait for a payload to be pushed in by the test.
        return await self._to_send.get()

    def write(self, data: bytes) -> int:
        self.received.append(bytes(data))
        return len(data)

    async def awrite(self, data: bytes) -> int:
        self.received.append(bytes(data))
        return len(data)

    def configure(self, *args: object, **kwargs: object) -> None:
        pass

    def deconfigure(self) -> None:
        pass

    def open(self) -> None:
        pass

    def close(self) -> None:
        pass

    def push_payload(self, data: bytes) -> None:
        self._to_send.put_nowait(data)


@unittest.skipUnless(
    _HAS_TUNCORE,
    "tuncore (Rust crypto core) not built; run `maturin develop` in rust/tuncore/",
)
class TestDataPathRoundtrip(unittest.IsolatedAsyncioTestCase):
    """Full round-trip: peer A's TUN read → ... → peer B's TUN write."""

    async def asyncSetUp(self) -> None:
        # apply_so_mark needs CAP_NET_ADMIN; patch out for unprivileged runs.
        self._so_mark_patch = patch(
            "dsm.net.transport.udp.apply_so_mark",
            lambda sock: None,
        )
        self._so_mark_patch.start()

    async def asyncTearDown(self) -> None:
        self._so_mark_patch.stop()

    async def _build_peers(self) -> tuple[dict, dict]:
        """Construct a client↔server pair with completed handshake and
        DataPathContexts on both sides using MockTuns. Returns (client, server)
        dicts with the resources we need in the test.
        """
        from dsm.core.fsm import SessionFSM, State
        from dsm.core.protocol import ReassemblyBuffer
        from dsm.crypto.cert_allowlist import CNAllowlist
        from dsm.crypto.handshake import client_handshake, server_handshake
        from dsm.net.transport.udp import UDPTransport
        from dsm.session import (
            DataPathContext,
            LivenessState,
            RekeyState,
            SequenceCounter,
            make_send_fn,
        )
        from dsm.traffic.scheduler import SendScheduler
        from dsm.traffic.shaper import TrafficShaper, make_chaff_packet
        from tests.cert_helpers import (
            CLIENT_AUTH_OID,
            SERVER_AUTH_OID,
            make_enrolled_device,
            make_test_ca,
        )

        server_transport = UDPTransport()
        server_port = await server_transport.bind("127.0.0.1", 0)
        self.addAsyncCleanup(server_transport.aclose)

        client_transport = UDPTransport()
        await client_transport.bind("127.0.0.1", 0)
        self.addAsyncCleanup(client_transport.aclose)

        ca = make_test_ca()
        client = make_enrolled_device(
            ca, subject_cn="dsm-data-client", eku=CLIENT_AUTH_OID
        )
        server = make_enrolled_device(
            ca, subject_cn="dsm-data-server", eku=SERVER_AUTH_OID
        )
        server_addr = ("127.0.0.1", server_port)

        (c_keys, _c_hash, _s_static_pub), (s_keys, _c_pub) = await asyncio.wait_for(
            asyncio.gather(
                client_handshake(
                    client_transport,
                    client.identity,
                    server_addr,
                    attest_key=client.attest_key,
                    cert_der=client.cert_der,
                    ca_root=ca.certificate,
                    expected_server_cn="dsm-data-server",
                ),
                server_handshake(
                    server_transport,
                    server.identity,
                    attest_key=server.attest_key,
                    cert_der=server.cert_der,
                    ca_root=ca.certificate,
                    cn_allowlist=CNAllowlist(cns=frozenset({"dsm-data-client"})),
                ),
            ),
            timeout=30.0,
        )

        # Build DataPathContexts using MockTuns. No scheduler chaff/jitter —
        # we want deterministic test latency. Use minimum jitter 0,0 via a
        # constrained shaper config.

        def _make_ctx(
            keys: tuncore.SessionKeyManager,
            transport: UDPTransport,
            dest_holder: list,
            tun: _MockTun,
        ) -> tuple[DataPathContext, SendScheduler]:
            fsm = SessionFSM()
            fsm.transition(State.CONNECTING)
            fsm.transition(State.HANDSHAKING)
            fsm.transition(State.ESTABLISHED)
            shaper = TrafficShaper(padding_min=128, padding_max=1400)
            seq = SequenceCounter()
            liveness = LivenessState()

            def _dest() -> tuple[str, int] | None:
                return dest_holder[0]

            send_fn = make_send_fn(keys, transport, _dest, seq, liveness=liveness)
            scheduler = SendScheduler(
                send_fn=send_fn,
                chaff_fn=lambda: make_chaff_packet(shaper, keys.epoch & 0x0F),
                should_chaff_fn=lambda: False,  # no chaff interference
                jitter_ms_min=0,
                jitter_ms_max=0,
            )
            shutdown = asyncio.Event()
            ctx = DataPathContext(
                tun=tun,  # type: ignore[arg-type]
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
            return ctx, scheduler

        client_tun = _MockTun("client")
        server_tun = _MockTun("server")

        # Shared mutable dest holders so the recv_loop can populate the
        # server's dest (the client's ephemeral UDP source addr) on the
        # fly without needing to rebuild the scheduler's captured send_fn.
        client_dest_holder: list = [server_addr]
        server_dest_holder: list = [None]

        client_ctx, client_scheduler = _make_ctx(
            c_keys,
            client_transport,
            client_dest_holder,
            client_tun,
        )
        server_ctx, server_scheduler = _make_ctx(
            s_keys,
            server_transport,
            server_dest_holder,
            server_tun,
        )

        client = {
            "transport": client_transport,
            "keys": c_keys,
            "ctx": client_ctx,
            "scheduler": client_scheduler,
            "tun": client_tun,
            "dest_holder": client_dest_holder,
        }
        server = {
            "transport": server_transport,
            "keys": s_keys,
            "ctx": server_ctx,
            "scheduler": server_scheduler,
            "tun": server_tun,
            "dest_holder": server_dest_holder,
        }
        return client, server

    @staticmethod
    async def _recv_loop(
        transport,
        session_keys,
        replay,
        ctx,
        *,
        dest_holder: list | None = None,
    ) -> None:
        """Generic recv_loop adapted from client.py/server.py.

        When `dest_holder` is given (server side), the first authenticated
        packet's source address is written into it so the paired send_fn's
        `_dest()` closure can resolve.
        """
        from dsm.session import decrypt_packet, dispatch_inner

        while not ctx.shutdown.is_set():
            try:
                data, recv_addr = await asyncio.wait_for(
                    transport.recv(),
                    timeout=0.1,
                )
            except TimeoutError:
                session_keys.tick()
                continue

            result = decrypt_packet(data, session_keys, replay)
            if result is None:
                continue

            ctx.liveness.last_recv_time = time.monotonic()
            if dest_holder is not None and dest_holder[0] is None:
                dest_holder[0] = recv_addr

            inner, _prev_epoch = result
            await dispatch_inner(ctx, inner)

    async def _run_both(
        self,
        client: dict,
        server: dict,
        action,
        timeout: float = 5.0,
    ) -> None:
        """Start both peers' loops, run `action`, then shut down."""
        from dsm.session import tun_send_loop

        c_replay = tuncore.ReplayWindow()
        s_replay = tuncore.ReplayWindow()

        async def _server_recv() -> None:
            await self._recv_loop(
                server["transport"],
                server["keys"],
                s_replay,
                server["ctx"],
                dest_holder=server["dest_holder"],
            )

        async def _client_recv() -> None:
            await self._recv_loop(
                client["transport"],
                client["keys"],
                c_replay,
                client["ctx"],
            )

        await client["scheduler"].start()
        await server["scheduler"].start()

        try:
            tasks = [
                asyncio.create_task(_server_recv()),
                asyncio.create_task(_client_recv()),
                asyncio.create_task(tun_send_loop(client["ctx"])),
                asyncio.create_task(tun_send_loop(server["ctx"])),
            ]
            try:
                await asyncio.wait_for(action(), timeout=timeout)
            finally:
                client["ctx"].shutdown.set()
                server["ctx"].shutdown.set()
                for t in tasks:
                    t.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            await client["scheduler"].stop()
            await server["scheduler"].stop()

    async def test_small_payload_roundtrip(self) -> None:
        client, server = await self._build_peers()

        async def _action() -> None:
            payload = b"hello through the tunnel"
            client["tun"].push_payload(payload)
            # Wait up to 2s for the packet to appear on the server's TUN.
            for _ in range(200):
                if server["tun"].received:
                    break
                await asyncio.sleep(0.01)

        await self._run_both(client, server, _action, timeout=5.0)
        self.assertTrue(
            server["tun"].received,
            "server TUN never received the client's payload",
        )
        self.assertEqual(server["tun"].received[0], b"hello through the tunnel")

    async def test_large_payload_fragments_and_reassembles(self) -> None:
        client, server = await self._build_peers()

        # 2500 bytes > MAX_INNER_PAYLOAD (1500) → must be fragmented
        payload = bytes((i * 17 + 3) & 0xFF for i in range(2500))

        async def _action() -> None:
            client["tun"].push_payload(payload)
            for _ in range(400):
                if server["tun"].received:
                    break
                await asyncio.sleep(0.01)

        await self._run_both(client, server, _action, timeout=10.0)
        self.assertTrue(
            server["tun"].received,
            "server TUN never received the reassembled payload",
        )
        self.assertEqual(
            server["tun"].received[0],
            payload,
            "reassembled payload bytes differ from original",
        )

    async def test_bidirectional_roundtrip(self) -> None:
        client, server = await self._build_peers()

        async def _action() -> None:
            # Client must send first so the server learns the client's
            # ephemeral source address (UDP is connectionless — the server
            # can't send back before discovering where to send).
            client["tun"].push_payload(b"client-to-server")
            for _ in range(200):
                if server["tun"].received:
                    break
                await asyncio.sleep(0.01)
            server["tun"].push_payload(b"server-to-client")
            for _ in range(200):
                if client["tun"].received:
                    break
                await asyncio.sleep(0.01)

        await self._run_both(client, server, _action, timeout=5.0)
        self.assertEqual(server["tun"].received, [b"client-to-server"])
        self.assertEqual(client["tun"].received, [b"server-to-client"])

    async def test_rekey_roundtrip(self) -> None:
        """Trigger rekey on the client; verify both sides rotate epoch and
        a post-rekey data packet still roundtrips."""
        from dsm.core.fsm import State
        from dsm.rekey import initiate_rekey

        client, server = await self._build_peers()

        initial_epoch = client["keys"].epoch
        self.assertEqual(server["keys"].epoch, initial_epoch)

        async def _action() -> None:
            # Warm up: client sends a packet so server learns the addr.
            client["tun"].push_payload(b"warmup")
            for _ in range(200):
                if server["tun"].received:
                    break
                await asyncio.sleep(0.01)

            # Initiate rekey from client side.
            ts, new_epoch, _init_payload = await initiate_rekey(
                client["keys"],
                client["ctx"].fsm,
                client["ctx"].shaper,
                client["ctx"].send_fn,
            )
            client["ctx"].rekey.last_time = ts
            client["ctx"].rekey.pending_epoch = new_epoch

            # Give both sides a few event-loop ticks for REKEY_ACK to land.
            for _ in range(200):
                if (
                    server["ctx"].fsm.state == State.ESTABLISHED
                    and client["ctx"].fsm.state == State.ESTABLISHED
                    and server["keys"].epoch == new_epoch
                    and client["keys"].epoch == new_epoch
                ):
                    break
                await asyncio.sleep(0.01)

            # Send a post-rekey payload from client → server to prove new
            # keys work.
            client["tun"].push_payload(b"post-rekey hello")
            for _ in range(200):
                if len(server["tun"].received) >= 2:
                    break
                await asyncio.sleep(0.01)

        await self._run_both(client, server, _action, timeout=10.0)

        self.assertNotEqual(
            client["keys"].epoch,
            initial_epoch,
            "client did not advance epoch after rekey",
        )
        self.assertEqual(
            client["keys"].epoch,
            server["keys"].epoch,
            "both sides must agree on new epoch after rekey",
        )
        self.assertEqual(client["ctx"].fsm.state, State.ESTABLISHED)
        self.assertEqual(server["ctx"].fsm.state, State.ESTABLISHED)
        self.assertEqual(server["tun"].received[-1], b"post-rekey hello")

    async def test_rekey_duplicate_init_resends_cached_ack(self) -> None:
        """Simulate a lost REKEY_ACK: the client retransmits the same INIT,
        and the server re-sends its cached ACK rather than trying to
        re-rotate (which would fail the epoch precondition)."""
        from dsm.core.fsm import State
        from dsm.rekey import handle_rekey_init, initiate_rekey

        client, server = await self._build_peers()

        async def _action() -> None:
            client["tun"].push_payload(b"warmup")
            for _ in range(200):
                if server["tun"].received:
                    break
                await asyncio.sleep(0.01)

            ts, new_epoch, init_payload = await initiate_rekey(
                client["keys"],
                client["ctx"].fsm,
                client["ctx"].shaper,
                client["ctx"].send_fn,
            )
            client["ctx"].rekey.last_time = ts
            client["ctx"].rekey.pending_epoch = new_epoch

            for _ in range(200):
                if server["keys"].epoch == new_epoch:
                    break
                await asyncio.sleep(0.01)
            self.assertEqual(server["keys"].epoch, new_epoch)
            self.assertIsNotNone(server["ctx"].rekey.cached_ack_epoch)

            # Manually invoke the server's handler again with the SAME
            # INIT payload — mimics a retransmit from the client after a
            # lost ACK. Captures outbound bytes to confirm an ACK was
            # re-sent rather than a fresh rotation being attempted.
            sent_before = server["ctx"].rekey.cached_ack_payload
            (
                server["ctx"].rekey.last_time,
                server["ctx"].rekey.cached_ack_epoch,
                server["ctx"].rekey.cached_ack_payload,
            ) = await handle_rekey_init(
                init_payload,  # same INIT as the first one
                server["keys"],
                server["ctx"].fsm,
                server["ctx"].shaper,
                server["ctx"].send_fn,
                server["ctx"].rekey.last_time,
                cached_ack_epoch=server["ctx"].rekey.cached_ack_epoch,
                cached_ack_payload=server["ctx"].rekey.cached_ack_payload,
            )

            # Server must NOT have advanced past new_epoch (no double-rotate).
            self.assertEqual(server["keys"].epoch, new_epoch)
            # Cached ACK payload is unchanged (same ACK was replayed).
            self.assertEqual(server["ctx"].rekey.cached_ack_payload, sent_before)
            self.assertEqual(server["ctx"].fsm.state, State.ESTABLISHED)

        await self._run_both(client, server, _action, timeout=10.0)

    async def test_rekey_retry_scheduler_fires_on_timeout(self) -> None:
        """Unit-level proof that the tun_send_loop retry scheduler
        actually retransmits REKEY_INIT when the ACK is missing.

        Bypasses the handshake entirely — builds a minimal DataPathContext
        with a capturing send_fn, primes RekeyState to look like "we sent
        an INIT a long time ago and no ACK arrived", then runs a single
        iteration of tun_send_loop. Asserts a retransmit was emitted.
        """
        import dsm.session as session_mod
        from dsm.core.fsm import SessionFSM, State
        from dsm.core.protocol import ReassemblyBuffer
        from dsm.session import (
            DataPathContext,
            LivenessState,
            RekeyState,
            tun_send_loop,
        )
        from dsm.traffic.scheduler import SendScheduler
        from dsm.traffic.shaper import TrafficShaper, make_chaff_packet

        orig_timeout = session_mod.REKEY_ACK_TIMEOUT
        session_mod.REKEY_ACK_TIMEOUT = 0.05
        self.addCleanup(
            lambda: setattr(session_mod, "REKEY_ACK_TIMEOUT", orig_timeout),
        )

        tun = _MockTun("retry-client")
        # Construct a SessionKeyManager via a real bootstrap DH (the
        # from_handshake_hash Python binding was dropped — audit M2).
        # Audit M4 then dropped the raw-bytes variants too, leaving only the
        # mlock'd BootstrapEphemeral path.
        our_eph = tuncore.BootstrapEphemeral.generate()
        peer_eph = tuncore.BootstrapEphemeral.generate()
        keys = tuncore.complete_bootstrap(
            our_eph, bytes(peer_eph.public_key_bytes), is_initiator=True
        )
        fsm = SessionFSM()
        fsm.transition(State.CONNECTING)
        fsm.transition(State.HANDSHAKING)
        fsm.transition(State.ESTABLISHED)
        fsm.transition(State.REKEYING)  # simulate mid-rekey

        shaper = TrafficShaper(padding_min=128, padding_max=1400)
        wire_sends: list[tuple[bytes, int]] = []

        async def capture_send(data: bytes, target_size: int) -> None:
            wire_sends.append((data, target_size))

        scheduler = SendScheduler(
            send_fn=capture_send,
            chaff_fn=lambda: make_chaff_packet(shaper, keys.epoch & 0x0F),
            should_chaff_fn=lambda: False,
            jitter_ms_min=0,
            jitter_ms_max=0,
        )
        shutdown = asyncio.Event()
        rekey = RekeyState()
        rekey.in_progress = True
        rekey.last_init_payload = b"\x00" * 4 + b"\x01" * 32  # fake payload
        rekey.last_init_sent_at = time.monotonic() - 1.0  # well past timeout
        rekey.retries_used = 0

        ctx = DataPathContext(
            tun=tun,  # type: ignore[arg-type]
            session_keys=keys,
            fsm=fsm,
            shaper=shaper,
            send_fn=capture_send,
            scheduler=scheduler,
            rekey=rekey,
            liveness=LivenessState(),
            shutdown=shutdown,
            reassembly=ReassemblyBuffer(),
        )

        # Phase 2.6: control-plane (REKEY_INIT retransmits) is now PACED
        # through the scheduler, so each retry hands the packet to
        # scheduler.enqueue rather than calling send_fn directly. Spy on
        # enqueue to observe the retransmits (the scheduler is not started
        # here, so paced packets stay queued and never reach send_fn).
        enqueued: list[tuple[bytes, int]] = []
        orig_enqueue = scheduler.enqueue

        def _spy_enqueue(data: bytes, target_size: int) -> None:
            enqueued.append((data, target_size))
            orig_enqueue(data, target_size)

        scheduler.enqueue = _spy_enqueue  # type: ignore[method-assign]

        # Let the loop run for a few iterations. The retry scheduler
        # should fire at least once per iteration until MAX_REKEY_RETRIES
        # is hit, then shutdown.set().
        task = asyncio.create_task(tun_send_loop(ctx))
        try:
            for _ in range(100):
                if shutdown.is_set():
                    break
                await asyncio.sleep(0.02)
        finally:
            shutdown.set()
            await asyncio.gather(task, return_exceptions=True)

        # At least MAX_REKEY_RETRIES retransmits must have fired, and each
        # must have been handed to the paced scheduler (enqueue); after
        # that the loop sets shutdown and exits.
        from dsm.rekey import MAX_REKEY_RETRIES

        self.assertGreaterEqual(
            rekey.retries_used,
            MAX_REKEY_RETRIES,
            f"expected >= {MAX_REKEY_RETRIES} retries, got {rekey.retries_used}",
        )
        self.assertGreaterEqual(
            len(enqueued),
            MAX_REKEY_RETRIES,
            "each REKEY_INIT retransmit should have been enqueued (paced)",
        )

    async def test_session_close_triggers_peer_shutdown(self) -> None:
        from dsm.session import send_session_close

        client, server = await self._build_peers()

        async def _action() -> None:
            # Send a normal payload first so the server learns the client addr
            # (required for server→client direction).
            client["tun"].push_payload(b"hello")
            for _ in range(200):
                if server["tun"].received:
                    break
                await asyncio.sleep(0.01)
            await send_session_close(client["ctx"])
            for _ in range(200):
                if server["ctx"].shutdown.is_set():
                    break
                await asyncio.sleep(0.01)

        await self._run_both(client, server, _action, timeout=5.0)
        self.assertTrue(
            server["ctx"].shutdown.is_set(),
            "server never received or acted on SESSION_CLOSE",
        )


@unittest.skipUnless(
    _HAS_TUNCORE,
    "tuncore (Rust crypto core) not built; run `maturin develop` in rust/tuncore/",
)
class TestTCPFixedSizePadding(unittest.IsolatedAsyncioTestCase):
    """Regression: ``make_send_fn`` over TCP MUST pad the inner plaintext
    to ``tcp_fixed_size - OUTER_HEADER_SIZE - GCM_TAG_SIZE`` (1364), NOT
    to ``tcp_fixed_size`` (1400). The latter caused
    ``OuterPacket.serialize(target_size=1400)`` to fail with a wire-size
    mismatch on every send below the max class — silently dropped by the
    scheduler's broad ``except Exception``.
    """

    async def test_small_target_size_produces_1400_byte_wire(self) -> None:
        import tuncore
        from dsm.core.protocol import GCM_TAG_SIZE, OUTER_HEADER_SIZE, SIZE_CLASSES
        from dsm.net.transport.tcp import TCPTransport
        from dsm.session import SequenceCounter, make_send_fn

        local = tuncore.BootstrapEphemeral.generate()
        peer = tuncore.BootstrapEphemeral.generate()
        peer_pub = bytes(peer.public_key_bytes)
        sk = tuncore.complete_bootstrap(local, peer_pub, is_initiator=True)

        sent: list[bytes] = []

        class _StubTCP(TCPTransport):
            def __init__(self) -> None:
                pass  # skip real socket setup

            async def send(self, data: bytes) -> None:  # type: ignore[override]
                sent.append(data)

        transport = _StubTCP()
        seq = SequenceCounter()
        send = make_send_fn(sk, transport, lambda: None, seq)

        # Smallest class — would fail before the fix because plaintext
        # was padded to 1400 then encrypted to 1416, mismatching target=1400.
        smallest = SIZE_CLASSES[0]  # 128
        inner_for_smallest = smallest - OUTER_HEADER_SIZE - GCM_TAG_SIZE
        await send(b"x" * inner_for_smallest, smallest)

        mid = 512
        inner_for_mid = mid - OUTER_HEADER_SIZE - GCM_TAG_SIZE
        await send(b"y" * inner_for_mid, mid)

        # Max class — branch should NOT trigger; wire size still 1400.
        largest = SIZE_CLASSES[-1]  # 1400
        inner_for_largest = largest - OUTER_HEADER_SIZE - GCM_TAG_SIZE
        await send(b"z" * inner_for_largest, largest)

        self.assertEqual(len(sent), 3, "all three sends must succeed")
        for i, frame in enumerate(sent):
            self.assertEqual(
                len(frame),
                SIZE_CLASSES[-1],
                f"send #{i}: wire size {len(frame)} != {SIZE_CLASSES[-1]}",
            )


class TestRotationThresholdOverride(unittest.TestCase):
    """Regression: ``config.rotation_packets`` and ``rotation_seconds``
    were dead config fields for one milestone — validated but never
    plumbed to the Rust SessionKeyManager. This pins down that the
    operator override actually changes the threshold.
    """

    def test_packet_threshold_override_takes_effect(self) -> None:
        import tuncore

        OVERRIDE = 200
        # Sample 20 sessions; with proportional ±20% jitter, every threshold
        # should land in [160, 240]. Default base of 5000 lands in [4000, 6000].
        for _ in range(20):
            local = tuncore.BootstrapEphemeral.generate()
            peer = tuncore.BootstrapEphemeral.generate()
            peer_pub = bytes(peer.public_key_bytes)
            sk = tuncore.complete_bootstrap(
                local,
                peer_pub,
                is_initiator=True,
                rotation_packets=OVERRIDE,
                rotation_seconds=30,
            )
            n = 0
            while not sk.needs_rotation() and n < OVERRIDE * 2:
                sk.encrypt(b"x", b"\x00" * 8)  # encrypt requires an 8-byte AAD
                n += 1
            self.assertGreaterEqual(
                n,
                int(OVERRIDE * 0.8),
                f"override threshold rotated too early: {n} < 160",
            )
            self.assertLessEqual(
                n,
                int(OVERRIDE * 1.2),
                f"override threshold rotated too late: {n} > 240",
            )

    def test_default_threshold_when_no_override(self) -> None:
        import tuncore

        for _ in range(5):
            local = tuncore.BootstrapEphemeral.generate()
            peer = tuncore.BootstrapEphemeral.generate()
            peer_pub = bytes(peer.public_key_bytes)
            sk = tuncore.complete_bootstrap(
                local,
                peer_pub,
                is_initiator=True,
            )
            n = 0
            while not sk.needs_rotation() and n < 7000:
                sk.encrypt(b"x", b"\x00" * 8)  # encrypt requires an 8-byte AAD
                n += 1
            # Default base 5000 ± 20% → [4000, 6000]
            self.assertGreaterEqual(n, 4000)
            self.assertLessEqual(n, 6000)


@unittest.skipUnless(
    _HAS_TUNCORE,
    "tuncore (Rust crypto core) not built; run `maturin develop` in rust/tuncore/",
)
class TestDataPathReplayRejection(unittest.TestCase):
    """DSM-009: the Python data-path drops replayed and rotated-out
    packets at ``dsm.session.decrypt_packet``.

    These exercise ``decrypt_packet`` directly with a real
    ``tuncore.SessionKeyManager`` + ``tuncore.ReplayWindow`` (no sockets,
    no event loop) so the replay/epoch logic is locked deterministically.
    Framing mirrors ``make_send_fn``: seq ‖ nonce ‖ AEAD(inner, aad=seq).
    """

    @staticmethod
    def _bootstrap_pair():
        a = tuncore.BootstrapEphemeral.generate()
        b = tuncore.BootstrapEphemeral.generate()
        a_pub = bytes(a.public_key_bytes)
        b_pub = bytes(b.public_key_bytes)
        a_keys = tuncore.complete_bootstrap(a, b_pub, is_initiator=True)
        b_keys = tuncore.complete_bootstrap(b, a_pub, is_initiator=False)
        return a_keys, b_keys

    @staticmethod
    def _frame(keys, seq_counter, payload, ptype=None):
        """Build a wire packet the way ``make_send_fn`` does."""
        from dsm.core.protocol import (
            SEQ_STRUCT,
            InnerPacket,
            OuterPacket,
            PacketType,
        )

        if ptype is None:
            ptype = PacketType.DATA
        n = seq_counter.next()
        inner = InnerPacket(ptype=ptype, epoch_id=keys.epoch & 0x0F, payload=payload)
        buf = bytearray(inner.serialize())
        # Mirror make_send_fn: stamp the live epoch nibble into byte 1.
        if len(buf) >= 2:
            buf[1] = (buf[1] & 0x0F) | ((keys.epoch & 0x0F) << 4)
        nonce, ct, _epoch = keys.encrypt(bytes(buf), SEQ_STRUCT.pack(n))
        wire = OuterPacket(seq=n, nonce=nonce, ciphertext=ct).serialize()
        return wire, n

    @staticmethod
    def _rotate(initiator, responder) -> None:
        """Drive one full rekey at the SessionKeyManager level (the same
        two-phase API ``initiate_rekey`` / ``handle_rekey_init`` /
        ``handle_rekey_ack`` use), advancing both peers one epoch."""
        new_epoch, init_eph = initiator.initiate_rotation()
        resp_eph, _prepared = responder.prepare_rotation_responder(
            bytes(init_eph), new_epoch
        )
        responder.apply_rotation_responder()
        initiator.complete_rotation_initiator(bytes(resp_eph))

    def test_duplicate_packet_dropped_window_still_advances(self) -> None:
        from dsm.core.protocol import InnerPacket
        from dsm.session import SequenceCounter, decrypt_packet

        a_keys, b_keys = self._bootstrap_pair()
        seq = SequenceCounter()
        replay = tuncore.ReplayWindow()

        wire, n1 = self._frame(a_keys, seq, b"first packet")

        first = decrypt_packet(wire, b_keys, replay)
        self.assertIsNotNone(first)
        inner, prev = first  # type: ignore[misc]
        self.assertIsInstance(inner, InnerPacket)
        self.assertEqual(inner.payload, b"first packet")
        self.assertFalse(prev)

        self.assertFalse(replay.check(n1))

        # Same bytes again → dropped (None), not a second decode.
        second = decrypt_packet(wire, b_keys, replay)
        self.assertIsNone(second)

        # A fresh higher-seq packet still decodes — proving the window
        # advanced rather than blanket-dropping everything after a replay.
        wire2, _n2 = self._frame(a_keys, seq, b"second packet")
        third = decrypt_packet(wire2, b_keys, replay)
        self.assertIsNotNone(third)
        assert third is not None  # narrow for the index access below
        self.assertEqual(third[0].payload, b"second packet")

    def test_pre_rekey_packet_rejected_after_epoch_advances(self) -> None:
        from dsm.session import SequenceCounter, decrypt_packet

        a_keys, b_keys = self._bootstrap_pair()
        seq = SequenceCounter()

        # Capture a packet's wire bytes under the CURRENT epoch.
        old_wire, _n = self._frame(a_keys, seq, b"pre-rekey payload")
        start_epoch = a_keys.epoch

        # Drive TWO full rekeys. One rekey is not enough: the
        # SessionKeyManager keeps a one-epoch grace window
        # (decrypt-with-fallback / has_grace_period), so a packet from the
        # immediately-previous epoch still decrypts by design. After two
        # rotations the captured packet is two epochs behind — outside the
        # grace window — and must be dropped.
        self._rotate(a_keys, b_keys)
        self._rotate(a_keys, b_keys)
        self.assertEqual(a_keys.epoch, b_keys.epoch)
        self.assertEqual(a_keys.epoch - start_epoch, 2)

        # Feed the OLD captured packet to a fresh replay window so the drop
        # is attributable to the epoch advance, not to the replay check.
        replay = tuncore.ReplayWindow()
        self.assertIsNone(decrypt_packet(old_wire, b_keys, replay))

        # Sanity: a freshly-framed packet under the NEW epoch still decodes.
        fresh_wire, _n2 = self._frame(a_keys, seq, b"post-rekey payload")
        result = decrypt_packet(fresh_wire, b_keys, replay)
        self.assertIsNotNone(result)
        assert result is not None  # narrow for the index access below
        self.assertEqual(result[0].payload, b"post-rekey payload")


if __name__ == "__main__":
    unittest.main()
