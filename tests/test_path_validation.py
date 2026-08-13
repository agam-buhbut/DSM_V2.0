"""QUIC-style PATH VALIDATION for server egress roaming.

Proves the return-routability gate that closes the on-path roam-redirect
vuln. The server used to roam its egress to the source addr of ANY
AEAD-valid packet with no return-routability check. An on-path attacker
could suppress a genuine client->server packet and reinject it with a
SPOOFED UDP source = victim IP; the packet is AEAD-valid, so the server
roamed egress to the victim (a redirect / off-path DoS primitive).

The fix: the server commits its egress only to a peer that PROVES it can
receive at the candidate address by echoing a fresh 16-byte token in a
PATH_RESPONSE (``dsm.session.PathValidationState`` +
``make_addr_send_fn``, wired in ``dsm/server.py::_run_one_session``). The
genuine packet's payload still delivers to TUN; only the egress-addr
SWITCH is gated.

These tests drive the REAL ``run_data_loops`` recv path with a faithful
copy of the server's ``post_authenticate`` gating callback (mirrored from
``dsm/server.py``), a REAL ``tuncore.SessionKeyManager`` bootstrap pair
(so the AEAD authenticated-vs-forged distinction is real, not stubbed),
and a scripted in-memory transport. The PathValidationState clock is
injected so the pending timeout is deterministic — no sleeps, no network.

Cases:
  (a) An AEAD-valid packet from a SPOOFED source does NOT redirect egress:
      the server emits a PATH_CHALLENGE to the spoofed addr, gets no valid
      response, and egress STAYS on the committed addr.
  (b) A client that has roamed to a NEW addr and ANSWERS the challenge
      (valid PATH_RESPONSE echoing the token) DOES get committed.
  (c) A PATH_RESPONSE with a wrong/mismatched token does NOT commit.
  (d) A stale pending times out (cannot wedge a future roam) and is
      replaceable by a newer candidate.
"""

from __future__ import annotations

import asyncio
import unittest

from dsm.core.fsm import SessionFSM, State
from dsm.core.protocol import (
    PATH_TOKEN_SIZE,
    SEQ_STRUCT,
    InnerPacket,
    OuterPacket,
    PacketType,
)
from dsm.net.transport.udp import UDPTransport
from dsm.session import (
    DataPathContext,
    LivenessState,
    PathValidationState,
    RekeyState,
    SequenceCounter,
    _build_control_packet,
    decrypt_packet,
    make_addr_send_fn,
    make_send_fn,
    run_data_loops,
)

try:
    import tuncore

    _HAS_TUNCORE = True
except ImportError:
    tuncore = None  # type: ignore[assignment]
    _HAS_TUNCORE = False


# The committed real client, the spoofed victim addr an on-path attacker
# would inject, and the addr a genuine client roams to after a NAT rebind.
_COMMITTED_ADDR: tuple[str, int] = ("198.51.100.7", 51820)
_SPOOFED_VICTIM_ADDR: tuple[str, int] = ("203.0.113.66", 4444)
_ROAMED_ADDR: tuple[str, int] = ("192.0.2.99", 33333)


class _FakeClock:
    """Manually advanced monotonic clock for deterministic timeouts."""

    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class _RecordingTun:
    """TUN fake: read() blocks (tun_send_loop idle); writes are captured."""

    def __init__(self) -> None:
        self.received: list[bytes] = []

    async def read(self, bufsize: int = 2048) -> bytes:
        await asyncio.sleep(3600)
        return b""

    async def awrite(self, data: bytes) -> int:
        self.received.append(bytes(data))
        return len(data)


class _ScriptedUDPTransport(UDPTransport):
    """``UDPTransport`` whose recv() replays scripted ``(wire, src_addr)``
    datagrams then blocks; send() records ``(wire, dest_addr)``.

    Subclasses ``UDPTransport`` because both ``make_send_fn`` and
    ``make_addr_send_fn`` branch on ``isinstance(transport, UDPTransport)``.
    """

    def __init__(self, inbound: list[tuple[bytes, tuple[str, int]]]) -> None:
        # Intentionally skip UDPTransport.__init__ (no real socket).
        self._inbound = list(inbound)
        self._idx = 0
        self.sent: list[tuple[bytes, tuple[str, int]]] = []

    async def recv(  # type: ignore[override]
        self, timeout: float | None = None
    ) -> tuple[bytes, tuple[str, int]]:
        if self._idx < len(self._inbound):
            item = self._inbound[self._idx]
            self._idx += 1
            return item
        await asyncio.sleep(3600)
        raise AssertionError("unreachable")

    async def send(  # type: ignore[override]
        self, data: bytes, addr: tuple[str, int]
    ) -> None:
        self.sent.append((bytes(data), addr))


class _NoopScheduler:
    """Records enqueued packets (the client PATH_RESPONSE path uses enqueue);
    here we only need to observe that nothing odd is enqueued server-side."""

    def __init__(self) -> None:
        self.enqueued: list[tuple[bytes, int]] = []

    def enqueue(
        self, data: bytes, target_size: int, *, extra_delay: float = 0.0
    ) -> None:
        self.enqueued.append((bytes(data), target_size))


def _established_fsm() -> SessionFSM:
    fsm = SessionFSM()
    fsm.transition(State.CONNECTING)
    fsm.transition(State.HANDSHAKING)
    fsm.transition(State.ESTABLISHED)
    return fsm


def _bootstrap_pair() -> tuple[tuncore.SessionKeyManager, tuncore.SessionKeyManager]:
    a = tuncore.BootstrapEphemeral.generate()
    b = tuncore.BootstrapEphemeral.generate()
    a_pub = bytes(a.public_key_bytes)
    b_pub = bytes(b.public_key_bytes)
    client_keys = tuncore.complete_bootstrap(a, b_pub, is_initiator=True)
    server_keys = tuncore.complete_bootstrap(b, a_pub, is_initiator=False)
    return client_keys, server_keys


def _frame(
    keys: tuncore.SessionKeyManager,
    seq_counter: SequenceCounter,
    ptype: PacketType,
    payload: bytes,
) -> bytes:
    """Build a genuine authenticated wire packet of ``ptype``, the way
    ``make_send_fn`` does: seq ‖ nonce ‖ AEAD(inner, aad=seq), with the
    live epoch nibble stamped into inner-header byte 1."""
    n = seq_counter.next()
    inner = InnerPacket(ptype=ptype, epoch_id=keys.epoch & 0x0F, payload=payload)
    buf = bytearray(inner.serialize())
    if len(buf) >= 2:
        buf[1] = (buf[1] & 0x0F) | ((keys.epoch & 0x0F) << 4)
    nonce, ct, _epoch = keys.encrypt(bytes(buf), SEQ_STRUCT.pack(n))
    return OuterPacket(seq=n, nonce=nonce, ciphertext=ct).serialize()


def _extract_token(wire: bytes, client_keys: tuncore.SessionKeyManager) -> bytes:
    """Decrypt a server-emitted PATH_CHALLENGE wire packet and return its
    16-byte token.

    AEAD is directional: the SERVER encrypts with its send key, so the CLIENT
    (its receive key = server's send key) is the party that decrypts. The
    on-path attacker who spoofed the source addr does NOT hold these keys —
    that is exactly why it cannot answer the challenge. Uses a fresh replay
    window so it never collides with the driver's own window."""
    replay = tuncore.ReplayWindow()
    result = decrypt_packet(wire, client_keys, replay)
    assert result is not None, "server challenge did not authenticate"
    inner, _prev = result
    assert inner.ptype == PacketType.PATH_CHALLENGE
    assert len(inner.payload) == PATH_TOKEN_SIZE
    return inner.payload


@unittest.skipUnless(
    _HAS_TUNCORE,
    "tuncore (Rust crypto core) not built; run `maturin develop` in rust/tuncore/",
)
class PathValidationDriver(unittest.IsolatedAsyncioTestCase):
    """Drives the real recv path with a faithful copy of server.py's
    return-routability gating callback."""

    async def _drive(
        self,
        inbound: list[tuple[bytes, tuple[str, int]]],
        server_keys: tuncore.SessionKeyManager,
        clock: _FakeClock,
        *,
        committed_seed: tuple[str, int] | None = None,
        stop_when,
    ) -> tuple[dict[str, tuple[str, int] | None], list[bytes], _ScriptedUDPTransport]:
        """Run ``run_data_loops`` server-side against scripted inbound, with the
        path-validation gating callback wired exactly like ``dsm/server.py``.

        ``committed_seed`` pre-commits the egress addr (skipping the "first
        addr commits" branch) so a test can start already-established with a
        known committed peer. ``stop_when()`` is polled to decide when to set
        shutdown.

        Returns the committed-addr cell, the TUN writes, and the transport.
        """
        fsm = _established_fsm()
        transport = _ScriptedUDPTransport(inbound)
        tun = _RecordingTun()
        replay = tuncore.ReplayWindow()

        client_addr: dict[str, tuple[str, int] | None] = {"addr": committed_seed}

        def _dest() -> tuple[str, int] | None:
            return client_addr["addr"]

        seq = SequenceCounter()
        liveness = LivenessState()
        shutdown = asyncio.Event()
        send_fn = make_send_fn(
            server_keys, transport, _dest, seq, liveness=liveness, shutdown=shutdown
        )
        scheduler = _NoopScheduler()

        class _NoopShaper:
            def pad_packet(self, inner: InnerPacket) -> tuple[bytes, int]:
                # Build a REAL padded control packet so the token survives the
                # round-trip — _build_control_packet calls pad_packet, and the
                # server's challenge must carry the actual 16-byte token. Pad to
                # a fixed 128-byte size class (inner len <= token + header).
                wire_inner = inner.serialize()
                target = 128
                # plaintext slot = target - OUTER_HEADER - GCM_TAG
                from dsm.core.protocol import GCM_TAG_SIZE, OUTER_HEADER_SIZE

                slot = target - OUTER_HEADER_SIZE - GCM_TAG_SIZE
                buf = bytearray(slot)
                buf[: len(wire_inner)] = wire_inner
                return bytes(buf), target

        ctx = DataPathContext(
            tun=tun,  # type: ignore[arg-type]
            session_keys=server_keys,
            fsm=fsm,
            shaper=_NoopShaper(),  # type: ignore[arg-type]
            send_fn=send_fn,
            scheduler=scheduler,  # type: ignore[arg-type]
            rekey=RekeyState(),
            liveness=liveness,
            shutdown=shutdown,
            reassembly=None,
        )

        # Mirror dsm/server.py::_run_one_session path-validation wiring.
        path_validation = PathValidationState(clock=clock)
        path_send = make_addr_send_fn(server_keys, transport, seq)

        async def _send_challenge(candidate: tuple[str, int], token: bytes) -> None:
            padded, target_size = _build_control_packet(
                ctx,
                PacketType.PATH_CHALLENGE,
                payload=token,  # pyright: ignore[reportCallIssue]
            )
            try:
                await asyncio.wait_for(
                    path_send(padded, target_size, candidate), timeout=5.0
                )
            except (TimeoutError, OSError):
                pass

        async def _post_authenticate(addr: tuple[str, int], inner: object) -> None:
            assert isinstance(inner, InnerPacket)
            committed = client_addr["addr"]
            if committed is None:
                client_addr["addr"] = addr
                return
            if inner.ptype == PacketType.PATH_RESPONSE:
                if path_validation.validate(addr, inner.payload):
                    client_addr["addr"] = addr
                    path_validation.clear()
                return
            if addr == committed:
                return
            token = path_validation.should_challenge(addr)
            if token is not None:
                await _send_challenge(addr, token)

        async def _run() -> None:
            await run_data_loops(
                ctx,
                transport,
                server_keys,
                replay,
                fsm,
                post_authenticate=_post_authenticate,
                shutdown_log="server shutting down",
            )

        task = asyncio.create_task(_run())
        for _ in range(400):
            if stop_when(client_addr, transport, tun):
                break
            await asyncio.sleep(0.01)
        shutdown.set()
        await asyncio.wait_for(task, timeout=5.0)
        return client_addr, tun.received, transport

    async def test_spoofed_source_does_not_redirect_egress(self) -> None:
        """(a) An AEAD-valid packet from a SPOOFED source must NOT switch
        egress. The server emits a PATH_CHALLENGE to the spoofed addr; with no
        valid PATH_RESPONSE, egress STAYS committed to the real client. The
        spoofed packet's payload still delivers to TUN (only the egress switch
        is gated)."""
        client_keys, server_keys = _bootstrap_pair()
        cseq = SequenceCounter()
        # On-path attacker reinjects a genuine-looking DATA packet (AEAD-valid)
        # but with a SPOOFED victim source addr.
        spoofed = _frame(client_keys, cseq, PacketType.DATA, b"reinjected-data")

        clock = _FakeClock()

        def _stop(addr_cell, transport, tun) -> bool:
            # Stop once the challenge has been emitted AND the payload delivered.
            challenged = any(d == _SPOOFED_VICTIM_ADDR for _w, d in transport.sent)
            return challenged and bool(tun.received)

        addr_cell, tun_writes, transport = await self._drive(
            [(spoofed, _SPOOFED_VICTIM_ADDR)],
            server_keys,
            clock,
            committed_seed=_COMMITTED_ADDR,
            stop_when=_stop,
        )

        self.assertEqual(
            addr_cell["addr"],
            _COMMITTED_ADDR,
            "spoofed AEAD-valid source redirected egress — vuln NOT fixed",
        )
        # Exactly ONE packet went to the spoofed addr — the return-routability
        # PATH_CHALLENGE probe — and nothing else. (Any other traffic, incl. the
        # teardown SESSION_CLOSE, goes to the COMMITTED egress, confirming egress
        # never moved.)
        to_spoofed = [(w, d) for w, d in transport.sent if d == _SPOOFED_VICTIM_ADDR]
        self.assertEqual(
            len(to_spoofed),
            1,
            "exactly one challenge to the spoofed candidate expected",
        )
        self.assertTrue(
            all(
                d == _COMMITTED_ADDR
                for w, d in transport.sent
                if d != _SPOOFED_VICTIM_ADDR
            ),
            "non-challenge egress must stay on the committed real client",
        )
        # The probe was a real PATH_CHALLENGE (decryptable by the client's
        # keys, NOT producible/answerable by the off-path spoofer).
        self.assertEqual(
            len(_extract_token(to_spoofed[0][0], client_keys)),
            PATH_TOKEN_SIZE,
        )
        self.assertEqual(tun_writes, [b"reinjected-data"])

    async def test_roamed_client_answering_challenge_commits(self) -> None:
        """(b) A client that has roamed to a NEW addr, receives the challenge
        there, and echoes the token in a PATH_RESPONSE DOES get committed.

        The token is freshly random per run, so the response can only be built
        AFTER observing the challenge — ``_drive_roam_then_respond`` captures
        the live token from the server's emitted PATH_CHALLENGE and feeds back
        a matching PATH_RESPONSE from the roamed addr."""
        client_keys, server_keys = _bootstrap_pair()
        committed = await self._drive_roam_then_respond(
            client_keys, server_keys, _ROAMED_ADDR
        )
        self.assertEqual(
            committed,
            _ROAMED_ADDR,
            "a roamed client that answered the challenge must be committed",
        )

    async def _drive_roam_then_respond(
        self,
        client_keys: tuncore.SessionKeyManager,
        server_keys: tuncore.SessionKeyManager,
        roamed_addr: tuple[str, int],
        *,
        tamper_token: bool = False,
    ) -> tuple[str, int] | None:
        """Single-session driver: an authenticated DATA from ``roamed_addr``
        arms a challenge; the test captures the live token from the transport
        and feeds a matching (or tampered) PATH_RESPONSE back, then asserts on
        the committed addr. Returns the committed addr.

        Because the token is freshly random per run, the response packet can
        only be built AFTER observing the challenge — so this driver injects
        the response into the scripted transport at runtime.
        """
        cseq = SequenceCounter()
        roam_trigger = _frame(client_keys, cseq, PacketType.DATA, b"roam-hello")

        fsm = _established_fsm()
        tun = _RecordingTun()
        replay = tuncore.ReplayWindow()
        client_addr: dict[str, tuple[str, int] | None] = {"addr": _COMMITTED_ADDR}
        clock = _FakeClock()

        # A mutable inbound list the recv loop drains; we append the response
        # once we have observed the challenge token.
        inbound: list[tuple[bytes, tuple[str, int]]] = [(roam_trigger, roamed_addr)]
        transport = _ScriptedUDPTransport(inbound)

        def _dest() -> tuple[str, int] | None:
            return client_addr["addr"]

        seq = SequenceCounter()
        liveness = LivenessState()
        shutdown = asyncio.Event()
        send_fn = make_send_fn(
            server_keys, transport, _dest, seq, liveness=liveness, shutdown=shutdown
        )
        scheduler = _NoopScheduler()

        class _Shaper:
            def pad_packet(self, inner: InnerPacket) -> tuple[bytes, int]:
                from dsm.core.protocol import GCM_TAG_SIZE, OUTER_HEADER_SIZE

                wire_inner = inner.serialize()
                slot = 128 - OUTER_HEADER_SIZE - GCM_TAG_SIZE
                buf = bytearray(slot)
                buf[: len(wire_inner)] = wire_inner
                return bytes(buf), 128

        ctx = DataPathContext(
            tun=tun,  # type: ignore[arg-type]
            session_keys=server_keys,
            fsm=fsm,
            shaper=_Shaper(),  # type: ignore[arg-type]
            send_fn=send_fn,
            scheduler=scheduler,  # type: ignore[arg-type]
            rekey=RekeyState(),
            liveness=liveness,
            shutdown=shutdown,
            reassembly=None,
        )
        path_validation = PathValidationState(clock=clock)
        path_send = make_addr_send_fn(server_keys, transport, seq)

        async def _send_challenge(candidate: tuple[str, int], token: bytes) -> None:
            padded, target_size = _build_control_packet(
                ctx,
                PacketType.PATH_CHALLENGE,
                payload=token,  # pyright: ignore[reportCallIssue]
            )
            await path_send(padded, target_size, candidate)

        async def _post_authenticate(addr: tuple[str, int], inner: object) -> None:
            assert isinstance(inner, InnerPacket)
            committed = client_addr["addr"]
            if committed is None:
                client_addr["addr"] = addr
                return
            if inner.ptype == PacketType.PATH_RESPONSE:
                if path_validation.validate(addr, inner.payload):
                    client_addr["addr"] = addr
                    path_validation.clear()
                return
            if addr == committed:
                return
            token = path_validation.should_challenge(addr)
            if token is not None:
                await _send_challenge(addr, token)

        async def _run() -> None:
            await run_data_loops(
                ctx,
                transport,
                server_keys,
                replay,
                fsm,
                post_authenticate=_post_authenticate,
                shutdown_log="server shutting down",
            )

        task = asyncio.create_task(_run())
        # Wait for the challenge to be emitted to the roamed addr.
        for _ in range(400):
            if any(d == roamed_addr for _w, d in transport.sent):
                break
            await asyncio.sleep(0.01)
        # Capture the live token and craft the matching PATH_RESPONSE from the
        # client (it is AT the roamed addr and holds the keys to decrypt the
        # challenge — the spoofer does not).
        token = _extract_token(transport.sent[0][0], client_keys)
        if tamper_token:
            token = bytes((token[0] ^ 0xFF,)) + token[1:]
        response = _frame(client_keys, cseq, PacketType.PATH_RESPONSE, token)
        transport._inbound.append((response, roamed_addr))
        # Wait for commit (or, in the tamper case, give it time to NOT commit).
        for _ in range(400):
            if client_addr["addr"] == roamed_addr:
                break
            await asyncio.sleep(0.01)
        await asyncio.sleep(0.05)
        shutdown.set()
        await asyncio.wait_for(task, timeout=5.0)
        return client_addr["addr"]

    async def test_wrong_token_does_not_commit(self) -> None:
        """(c) A PATH_RESPONSE from the pending addr carrying a WRONG token
        must NOT commit — egress stays on the committed real client."""
        client_keys, server_keys = _bootstrap_pair()
        committed = await self._drive_roam_then_respond(
            client_keys, server_keys, _ROAMED_ADDR, tamper_token=True
        )
        self.assertEqual(
            committed,
            _COMMITTED_ADDR,
            "a mismatched token must not commit the roam",
        )

    async def test_pending_times_out_and_is_replaceable(self) -> None:
        """(d) State-machine unit: a stale pending TIMES OUT (so a late, valid
        response can no longer commit it) and a NEWER candidate REPLACES the
        pending slot (so a stale pending cannot wedge future roams)."""
        clock = _FakeClock()
        state = PathValidationState(clock=clock)

        # First candidate gets a token.
        t1 = state.should_challenge(_SPOOFED_VICTIM_ADDR)
        self.assertIsNotNone(t1)
        assert t1 is not None
        self.assertEqual(state.pending_addr, _SPOOFED_VICTIM_ADDR)

        # Within the rate-limit interval, the SAME candidate is suppressed
        # (no new probe).
        self.assertIsNone(state.should_challenge(_SPOOFED_VICTIM_ADDR))

        # After the pending TIMES OUT, a previously-valid token no longer
        # validates (a stale pending cannot be completed late).
        clock.advance(10.0)  # > PATH_PENDING_TIMEOUT
        self.assertFalse(state.validate(_SPOOFED_VICTIM_ADDR, t1))

        # A NEWER candidate replaces the slot with a fresh token (single slot,
        # bounded memory, no wedge).
        t2 = state.should_challenge(_ROAMED_ADDR)
        self.assertIsNotNone(t2)
        assert t2 is not None
        self.assertNotEqual(t1, t2)
        self.assertEqual(state.pending_addr, _ROAMED_ADDR)

        # The fresh candidate's token validates (return-routability completes).
        self.assertTrue(state.validate(_ROAMED_ADDR, t2))

        # A response from a NON-pending addr never validates.
        clock2 = _FakeClock()
        state2 = PathValidationState(clock=clock2)
        tok = state2.should_challenge(_ROAMED_ADDR)
        assert tok is not None
        self.assertFalse(state2.validate(_SPOOFED_VICTIM_ADDR, tok))


if __name__ == "__main__":
    unittest.main()
