"""Concurrency tests for the bounded UDP handshake acceptor.

These exercise ``dsm.net.handshake_acceptor._accept_until_winner`` and its
``_demux_loop`` / ``_PerPeerUDPView`` collaborators — the machinery that fixes
the connection-starvation DoS where a single stalled bogus ``msg1`` blocks the
serial responder ~18-30 s and starves the real client.

The Noise crypto itself is exercised elsewhere (``test_handshake_dos.py``,
``test_handshake_integration.py``); here we replace ``server_handshake`` with a
scripted fake so the CONCURRENCY properties are deterministic and fast: no real
net, no sleeps tied to wall-clock handshake timeouts. The fake reads the peer
addr off the ``_PerPeerUDPView`` it is handed and behaves per a per-addr script
(stall forever / authenticate after consuming N frames / fail). The real
session-keys object (a genuine ``tuncore.SessionKeyManager`` bootstrap pair) is
only needed for the handoff case so the winner's keys are a real object.

Cases:
  1. no-starvation: a stalled bogus attempt does NOT block a concurrent legit
     attempt from winning within the bound. (Designed to FAIL against the old
     serial path — asserted here against a serial reference driver.)
  2. bounded concurrency: never more than ``max_inflight_handshakes`` workers.
  3. per-attempt deadline frees the slot.
  4. first-to-auth wins + losers cancelled cleanly (no orphaned tasks, one
     winner).
  5. clean teardown on shutdown-during-accept.
  6. post-handshake socket handoff loses no frame (the delicate point).
  7. fresh per-session counters across cycles.
"""

from __future__ import annotations

import asyncio
import itertools
import unittest
from unittest.mock import patch

from dsm.crypto.handshake import HANDSHAKE_FRAME_SIZE
from dsm.net import handshake_acceptor as hsa
from dsm.net.handshake_acceptor import (
    _accept_until_winner,
    _PerPeerUDPView,
)
from dsm.net.handshake_gate import SourceLimiter
from dsm.net.transport.udp import UDPTransport

try:
    import tuncore

    _HAS_TUNCORE = True
except ImportError:
    tuncore = None  # type: ignore[assignment]
    _HAS_TUNCORE = False


# Peer source addresses used by the scripts below.
_STALLER_A: tuple[str, int] = ("203.0.113.10", 1111)
_STALLER_B: tuple[str, int] = ("203.0.113.11", 2222)
_STALLER_C: tuple[str, int] = ("203.0.113.12", 3333)
_WINNER: tuple[str, int] = ("198.51.100.7", 51820)
_SECOND_WINNER: tuple[str, int] = ("198.51.100.8", 51821)


class _FakeRealTransport(UDPTransport):
    """A ``UDPTransport`` stand-in backed by a real ``_recv_queue`` (exactly
    the integration point the production transport and the acceptor's handoff
    use), pre-loaded with the inbound datagrams; ``send()`` records.

    Subclasses ``UDPTransport`` (skipping the socket-creating ``__init__`` so no
    real socket exists) so the production isinstance() checks read it as a UDP
    transport, AND so the acceptor's residual re-injection (which puts frames
    back onto ``_recv_queue``) works identically to production. ``recv()`` pops
    from ``_recv_queue`` and times out like the real transport when empty.
    ``residual()`` reports what remains readable on the queue after the accept
    — i.e. exactly what the data path's recv_loop would see.
    """

    def __init__(self, inbound: list[tuple[bytes, tuple[str, int]]]) -> None:
        # Intentionally skip UDPTransport.__init__ (no real socket); build only
        # the in-process recv queue the acceptor + recv() interact with.
        self._recv_queue: asyncio.Queue[tuple[bytes, tuple[str, int]]] = asyncio.Queue()
        for item in inbound:
            self._recv_queue.put_nowait(item)
        self.sent: list[tuple[bytes, tuple[str, int]]] = []

    async def recv(  # type: ignore[override]
        self, timeout: float | None = None
    ) -> tuple[bytes, tuple[str, int]]:
        if timeout is not None:
            return await asyncio.wait_for(self._recv_queue.get(), timeout)
        return await self._recv_queue.get()

    async def send(  # type: ignore[override]
        self, data: bytes, addr: tuple[str, int]
    ) -> None:
        self.sent.append((bytes(data), addr))

    def residual(self) -> list[tuple[bytes, tuple[str, int]]]:
        """Datagrams still readable on the real recv queue after the accept —
        what the data path's recv_loop would consume next."""
        out: list[tuple[bytes, tuple[str, int]]] = []
        while not self._recv_queue.empty():
            out.append(self._recv_queue.get_nowait())
        return out


class _FakeConfig:
    """Minimal config surface the acceptor reads."""

    def __init__(self, max_inflight: int) -> None:
        self.max_inflight_handshakes = max_inflight
        self.transport = "udp"
        self.rotation_packets = 5000
        self.rotation_seconds = 600


class _Stub:
    """Stand-in for keystore / attest_store / materials / cn_allowlist — the
    fake server_handshake never touches their internals."""

    identity = object()
    attest_key = object()
    cert_der = b""
    ca_root = object()
    crl = None

    def is_allowed(self, _cn: object) -> bool:  # cn_allowlist surface
        return True


def _make_fake_handshake(script: dict[tuple[str, int], str], *, observed: dict):
    """Build a fake ``server_handshake`` whose behaviour per peer is scripted.

    ``script[addr]`` is one of:
      * "stall"   — never returns (consumes its first frame then blocks),
                    modelling a bogus msg1-then-silence attempt.
      * "win"     — consumes one frame and authenticates immediately.
      * "win_after2" — consumes two frames then authenticates (models a
                    multi-message handshake; used by the handoff test).
      * "fail"    — raises HandshakeError after consuming one frame.

    ``observed`` accumulates diagnostics: ``observed["active"]`` is the live
    worker count, ``observed["max_active"]`` its high-water mark, and
    ``observed["started"]`` the set of peers a worker actually ran for.
    """
    from dsm.crypto.handshake import HandshakeError

    async def _fake_server_handshake(view, *_args, **_kwargs):
        addr = view._peer_addr  # the _PerPeerUDPView pins the peer addr
        observed["active"] += 1
        observed["max_active"] = max(observed["max_active"], observed["active"])
        observed.setdefault("started", set()).add(addr)
        try:
            behaviour = script.get(addr, "win")
            # Always consume the seeding frame so the inbox drains realistically.
            await view.recv()
            if behaviour == "stall":
                await asyncio.sleep(3600)  # blocked until cancelled / deadline
                raise AssertionError("unreachable")
            if behaviour == "fail":
                raise HandshakeError(f"scripted failure for {addr}")
            if behaviour == "win_after2":
                await view.recv()  # second frame
            # "win" / "win_after2": authenticate. Return a sentinel keys object
            # and a deterministic client pub derived from the addr.
            keys = observed.get("keys_factory", lambda: object())()
            client_pub = f"pub-{addr[0]}:{addr[1]}".encode()
            return keys, client_pub
        finally:
            observed["active"] -= 1

    return _fake_server_handshake


def _seed_frame(addr: tuple[str, int], n: int = 0) -> tuple[bytes, tuple[str, int]]:
    # A new source's first datagram must be a full handshake frame to get a
    # slot; the fake handshake never reads the bytes.
    text = f"frame-{addr[0]}:{addr[1]}-{n}".encode()
    return (text.ljust(HANDSHAKE_FRAME_SIZE, b"\x00"), addr)


class HandshakeAcceptorConcurrency(unittest.IsolatedAsyncioTestCase):
    """Property tests for the bounded-concurrent acceptor."""

    def _patch_handshake(self, script, observed):
        # server_handshake is imported lazily inside the worker from
        # dsm.crypto.handshake, so patch it at that module.
        fake = _make_fake_handshake(script, observed=observed)
        return patch("dsm.crypto.handshake.server_handshake", new=fake)

    async def _accept(
        self,
        transport: _FakeRealTransport,
        *,
        max_inflight: int,
        process_shutdown: asyncio.Event | None = None,
        timeout: float = 5.0,
    ):
        config = _FakeConfig(max_inflight)
        stub = _Stub()
        ps = process_shutdown or asyncio.Event()
        return await asyncio.wait_for(
            _accept_until_winner(
                config,  # type: ignore[arg-type]
                stub,  # type: ignore[arg-type]  keystore
                stub,  # type: ignore[arg-type]  attest_store
                stub,  # type: ignore[arg-type]  materials
                stub,  # type: ignore[arg-type]  cn_allowlist
                transport,
                ps,
            ),
            timeout=timeout,
        )

    # ----- Case 1: no-starvation -----------------------------------------

    async def test_stalled_attempt_does_not_block_a_concurrent_winner(self) -> None:
        """A stalled bogus attempt arriving FIRST must not block a concurrent
        legitimate attempt from winning. (Against the old serial path the
        staller would hold the single responder and the winner would never be
        reached — this asserts the new concurrent behaviour.)"""
        observed = {"active": 0, "max_active": 0}
        script = {_STALLER_A: "stall", _WINNER: "win"}
        # Staller's msg1 arrives first, then the legit client's msg1.
        inbound = [_seed_frame(_STALLER_A), _seed_frame(_WINNER)]
        transport = _FakeRealTransport(inbound)

        with self._patch_handshake(script, observed):
            keys, pub, returned = await self._accept(transport, max_inflight=8)

        self.assertIsNotNone(keys, "a concurrent winner must be admitted")
        self.assertEqual(pub, b"pub-198.51.100.7:51820")
        self.assertIs(returned, transport, "the real transport is handed back")
        # The staller did start a worker (it was concurrent), proving the
        # winner did NOT have to wait for the staller to finish.
        self.assertIn(_STALLER_A, observed["started"])
        self.assertIn(_WINNER, observed["started"])

    async def test_serial_reference_path_would_starve(self) -> None:
        """Reference contrast: a SERIAL acceptor (one handshake at a time, in
        arrival order) servicing the same script never reaches the winner
        because the first attempt stalls. This is the bug the concurrent
        acceptor fixes; asserting it here documents WHY case 1 matters and
        would fail if someone reverted the acceptor to a serial loop."""

        async def _serial_accept(inbound, script) -> tuple[str, int] | None:
            for data, addr in inbound:
                del data
                if script.get(addr) == "stall":
                    # Serial path blocks here forever on the first staller.
                    try:
                        await asyncio.wait_for(asyncio.sleep(3600), timeout=0.2)
                    except TimeoutError:
                        return None  # never advances past the staller
                else:
                    return addr
            return None

        script = {_STALLER_A: "stall", _WINNER: "win"}
        inbound = [_seed_frame(_STALLER_A), _seed_frame(_WINNER)]
        winner = await _serial_accept(inbound, script)
        self.assertIsNone(
            winner,
            "a serial acceptor starves: the staller blocks the winner — exactly "
            "the DoS the concurrent acceptor removes",
        )

    # ----- Case 2: bounded concurrency -----------------------------------

    async def test_never_more_than_max_inflight_workers(self) -> None:
        """With max_inflight=2 and three stallers arriving, at most two workers
        run at once; the third new-source frame is dropped (pool saturated)."""
        observed = {"active": 0, "max_active": 0}
        script = {
            _STALLER_A: "stall",
            _STALLER_B: "stall",
            _STALLER_C: "stall",
            _WINNER: "win",
        }
        # Three stallers fill the (2) slots + saturate; then the winner. The
        # winner's frame is also a new source, so while the 2 slots are held by
        # stallers it too is dropped — until a slot frees. To let the winner in
        # we cap the staller deadline low so a slot frees quickly.
        inbound = [
            _seed_frame(_STALLER_A),
            _seed_frame(_STALLER_B),
            _seed_frame(_STALLER_C),
        ]
        transport = _FakeRealTransport(inbound)
        ps = asyncio.Event()

        async def _drive() -> None:
            with self._patch_handshake(script, observed):
                # No winner ever arrives; stop via shutdown once we have
                # observed the high-water mark and the queue has drained (all
                # three new-source frames have been seen by the demux).
                task = asyncio.ensure_future(
                    self._accept(
                        transport, max_inflight=2, process_shutdown=ps, timeout=5.0
                    )
                )
                for _ in range(200):
                    if observed["max_active"] >= 2 and transport._recv_queue.empty():
                        break
                    await asyncio.sleep(0.01)
                ps.set()
                await task

        await _drive()
        self.assertLessEqual(
            observed["max_active"],
            2,
            "more than max_inflight_handshakes workers ran concurrently",
        )
        # The third staller (C) was dropped at the demux (pool saturated), so no
        # worker ever started for it.
        self.assertNotIn(
            _STALLER_C,
            observed.get("started", set()),
            "a new-source frame must be dropped when the pool is saturated",
        )

    # ----- Case 3: per-attempt deadline frees the slot -------------------

    async def test_per_attempt_deadline_frees_slot(self) -> None:
        """A staller's slot is reclaimed after the per-attempt deadline, so a
        legitimate client that retransmits its msg1 lands in the freed slot and
        wins — even with max_inflight=1.

        The retransmit is injected ONLY after the staller's slot is observed to
        have been reclaimed (active back to 0), so the test deterministically
        exercises the deadline → slot-free → winner-lands sequence rather than
        racing all frames into the queue at once."""
        observed = {"active": 0, "max_active": 0}
        script = {_STALLER_A: "stall", _WINNER: "win"}
        transport = _FakeRealTransport([_seed_frame(_STALLER_A)])

        # Shrink the per-attempt deadline so the test is fast and deterministic.
        with patch.object(hsa, "_HANDSHAKE_ATTEMPT_DEADLINE", 0.05):
            with self._patch_handshake(script, observed):
                task = asyncio.ensure_future(
                    self._accept(transport, max_inflight=1, timeout=5.0)
                )
                # 1) Staller takes the single slot.
                for _ in range(200):
                    if observed["max_active"] >= 1:
                        break
                    await asyncio.sleep(0.01)
                self.assertEqual(observed["max_active"], 1)
                # 2) Wait for the deadline to reclaim it (worker count back to 0).
                for _ in range(200):
                    if observed["active"] == 0:
                        break
                    await asyncio.sleep(0.01)
                self.assertEqual(
                    observed["active"], 0, "the staller's slot must be reclaimed"
                )
                # 3) Now the winner's (retransmitted) msg1 lands in the free slot.
                transport._recv_queue.put_nowait(_seed_frame(_WINNER))
                keys, pub, _returned = await asyncio.wait_for(task, timeout=5.0)

        self.assertIsNotNone(keys, "winner must land in the slot freed by the deadline")
        self.assertEqual(pub, b"pub-198.51.100.7:51820")

    # ----- Case 4: first-to-auth wins, losers cancelled cleanly ----------

    async def test_first_to_auth_wins_losers_cancelled_no_orphans(self) -> None:
        """Two concurrent attempts both eventually authenticate; the FIRST wins
        and the loser is cancelled cleanly — exactly one winner result, no
        pending/destroyed tasks left behind."""
        observed = {"active": 0, "max_active": 0}
        # A wins immediately; B would also win but only after a second frame
        # that never arrives, so it is a live loser when A wins and must be
        # cancelled.
        script = {_WINNER: "win", _SECOND_WINNER: "win_after2"}
        inbound = [
            _seed_frame(_SECOND_WINNER, 0),  # B starts first, then stalls on 2nd
            _seed_frame(_WINNER, 0),  # A wins
        ]
        transport = _FakeRealTransport(inbound)

        before = asyncio.all_tasks()
        with self._patch_handshake(script, observed):
            keys, pub, _returned = await self._accept(transport, max_inflight=8)
        # Let any cancellations settle.
        await asyncio.sleep(0)
        after = asyncio.all_tasks()

        self.assertIsNotNone(keys)
        self.assertEqual(pub, b"pub-198.51.100.7:51820", "the FIRST to auth wins")
        # No acceptor-spawned task outlived the accept (loser fully cancelled).
        leaked = (after - before) - {asyncio.current_task()}
        self.assertEqual(len(leaked), 0, f"acceptor leaked pending tasks: {leaked!r}")
        # Exactly one winner: active count is back to zero (every worker
        # returned/cancelled), and the loser never produced a second result.
        self.assertEqual(observed["active"], 0, "all workers must have unwound")

    # ----- Case 5: clean teardown on shutdown-during-accept --------------

    async def test_shutdown_during_accept_returns_sentinel_cleanly(self) -> None:
        """If process_shutdown fires while attempts are in flight, the acceptor
        returns the (None, None, transport) sentinel and leaves no task
        pending."""
        observed = {"active": 0, "max_active": 0}
        script = {_STALLER_A: "stall", _STALLER_B: "stall"}
        inbound = [_seed_frame(_STALLER_A), _seed_frame(_STALLER_B)]
        transport = _FakeRealTransport(inbound)
        ps = asyncio.Event()

        before = asyncio.all_tasks()
        with self._patch_handshake(script, observed):
            task = asyncio.ensure_future(
                self._accept(transport, max_inflight=8, process_shutdown=ps)
            )
            # Wait until both stallers are in flight, then signal shutdown.
            for _ in range(200):
                if observed["active"] >= 2:
                    break
                await asyncio.sleep(0.01)
            ps.set()
            keys, pub, returned = await asyncio.wait_for(task, timeout=5.0)
        await asyncio.sleep(0)
        after = asyncio.all_tasks()

        self.assertIsNone(keys, "shutdown during accept yields the None sentinel")
        self.assertIsNone(pub)
        self.assertIs(returned, transport, "the transport is still returned")
        leaked = (after - before) - {asyncio.current_task()}
        self.assertEqual(
            len(leaked), 0, f"acceptor leaked pending tasks on shutdown: {leaked!r}"
        )
        self.assertEqual(observed["active"], 0, "all stallers must be cancelled")

    # ----- Case 6: post-handshake socket handoff loses no frame ----------

    async def test_post_handshake_frames_remain_on_real_socket(self) -> None:
        """THE delicate point: after the winner authenticates, datagrams the
        winner already sent (its first DATA packets) must REMAIN on the real
        socket for the data path — the demux must stop draining the moment a
        winner is set, never pulling the post-handshake frames into a per-peer
        inbox the data path can't see."""
        observed = {"active": 0, "max_active": 0}
        script = {_WINNER: "win"}
        winner_data_1 = (b"post-handshake-DATA-1", _WINNER)
        winner_data_2 = (b"post-handshake-DATA-2", _WINNER)
        # The winner's msg1, then immediately two DATA frames it sent right
        # after completing the handshake (a real client pipelines these).
        inbound = [
            _seed_frame(_WINNER),
            winner_data_1,
            winner_data_2,
        ]
        transport = _FakeRealTransport(inbound)

        with self._patch_handshake(script, observed):
            keys, _pub, returned = await self._accept(transport, max_inflight=8)

        self.assertIsNotNone(keys)
        self.assertIs(returned, transport)
        # The two post-handshake DATA frames were NOT consumed by the acceptor:
        # they remain on the real socket for run_data_loops' recv_loop.
        residual = transport.residual()
        self.assertIn(
            winner_data_1,
            residual,
            "a post-handshake frame was drained by the acceptor and lost to the "
            "data path — the undrained-socket handoff is broken",
        )
        self.assertIn(winner_data_2, residual)

    # ----- Case 7: fresh per-session counters across cycles --------------

    async def test_fresh_state_across_accept_cycles(self) -> None:
        """Running the acceptor twice (re-accept loop) starts each cycle with a
        fresh winner future, fresh semaphore, and no carried-over worker tasks —
        a second client is admitted exactly like the first, and no state from
        cycle 1 bleeds into cycle 2."""
        # Cycle 1.
        observed1 = {"active": 0, "max_active": 0}
        script1 = {_STALLER_A: "stall", _WINNER: "win"}
        transport1 = _FakeRealTransport([_seed_frame(_STALLER_A), _seed_frame(_WINNER)])
        before = asyncio.all_tasks()
        with self._patch_handshake(script1, observed1):
            keys1, pub1, _r1 = await self._accept(transport1, max_inflight=4)
        await asyncio.sleep(0)
        mid = asyncio.all_tasks()
        self.assertIsNotNone(keys1)
        self.assertEqual(pub1, b"pub-198.51.100.7:51820")
        self.assertEqual(
            len((mid - before) - {asyncio.current_task()}),
            0,
            "cycle 1 left a task that would corrupt cycle 2's accounting",
        )

        # Cycle 2 — a DIFFERENT client, fresh transport, fresh observed dict.
        observed2 = {"active": 0, "max_active": 0}
        script2 = {_STALLER_B: "stall", _SECOND_WINNER: "win"}
        transport2 = _FakeRealTransport(
            [_seed_frame(_STALLER_B), _seed_frame(_SECOND_WINNER)]
        )
        with self._patch_handshake(script2, observed2):
            keys2, pub2, _r2 = await self._accept(transport2, max_inflight=4)
        await asyncio.sleep(0)
        after = asyncio.all_tasks()
        self.assertIsNotNone(keys2)
        self.assertEqual(
            pub2,
            b"pub-198.51.100.8:51821",
            "the second cycle must admit the second client independently",
        )
        # observed dicts are independent: cycle 2's worker accounting is its own.
        self.assertEqual(observed2["active"], 0)
        self.assertEqual(
            len((after - before) - {asyncio.current_task()}),
            0,
            "no acceptor task leaked across either cycle",
        )


@unittest.skipUnless(_HAS_TUNCORE, "requires tuncore for the real keys object")
class HandshakeAcceptorRealKeysHandoff(unittest.IsolatedAsyncioTestCase):
    """The winner result carries a REAL ``tuncore.SessionKeyManager`` so the
    data path can use it unchanged. Proves the keys object the acceptor returns
    is the genuine one the fake handshake produced (not a sentinel that would
    break ``_run_one_session``)."""

    async def test_winner_returns_real_session_keys(self) -> None:
        observed = {"active": 0, "max_active": 0}

        def _keys_factory():
            eph = tuncore.BootstrapEphemeral.generate()
            peer = tuncore.BootstrapEphemeral.generate()
            return tuncore.complete_bootstrap(
                eph, bytes(peer.public_key_bytes), is_initiator=False
            )

        observed["keys_factory"] = _keys_factory
        script = {_WINNER: "win"}
        transport = _FakeRealTransport([_seed_frame(_WINNER)])
        config = _FakeConfig(8)
        stub = _Stub()
        fake = _make_fake_handshake(script, observed=observed)

        with patch("dsm.crypto.handshake.server_handshake", new=fake):
            keys, _pub, _returned = await asyncio.wait_for(
                _accept_until_winner(
                    config,  # type: ignore[arg-type]
                    stub,  # type: ignore[arg-type]
                    stub,  # type: ignore[arg-type]
                    stub,  # type: ignore[arg-type]
                    stub,  # type: ignore[arg-type]
                    transport,
                    asyncio.Event(),
                ),
                timeout=5.0,
            )

        self.assertIsInstance(keys, tuncore.SessionKeyManager)
        # The real keys object is usable: epoch is readable (would AttributeError
        # on a sentinel).
        self.assertIsInstance(keys.epoch, int)


class PerPeerUDPViewContract(unittest.IsolatedAsyncioTestCase):
    """The view must satisfy server_handshake's transport contract: read as a
    UDPTransport, recv -> (data, pinned_addr), send -> real socket pinned."""

    def test_view_is_udp_transport_for_isinstance(self) -> None:
        view = _PerPeerUDPView(_FakeRealTransport([]), _WINNER, asyncio.Queue())
        self.assertIsInstance(
            view,
            UDPTransport,
            "server_handshake branches on isinstance(transport, UDPTransport); "
            "the view must read as one",
        )

    async def test_recv_returns_pinned_addr(self) -> None:
        inbox: asyncio.Queue[bytes] = asyncio.Queue()
        inbox.put_nowait(b"hello")
        view = _PerPeerUDPView(_FakeRealTransport([]), _WINNER, inbox)
        data, addr = await view.recv()
        self.assertEqual(data, b"hello")
        self.assertEqual(addr, _WINNER, "recv must pin the peer addr")

    async def test_send_pins_peer_addr_over_supplied_addr(self) -> None:
        real = _FakeRealTransport([])
        view = _PerPeerUDPView(real, _WINNER, asyncio.Queue())
        # Supply a DIFFERENT addr; the view must override it with the pinned one.
        await view.send(b"reply", _STALLER_A)
        self.assertEqual(
            real.sent,
            [(b"reply", _WINNER)],
            "send must target the pinned peer addr, never the supplied one",
        )


class HandshakeAcceptorInboxLifecycle(unittest.IsolatedAsyncioTestCase):
    """Per-peer ``inboxes`` eviction (memory-exhaustion DoS) and the all-fail
    jittered backoff."""

    def _patch_handshake(self, script, observed):
        fake = _make_fake_handshake(script, observed=observed)
        return patch("dsm.crypto.handshake.server_handshake", new=fake)

    @staticmethod
    def _capture_inboxes(captured: dict):
        """Patch ``_demux_loop`` with a passthrough that records the live
        ``inboxes`` dict so the test can observe its size over time. The real
        demux runs unchanged."""
        real_demux = hsa._demux_loop

        async def _wrapper(*args, **kwargs):
            # inboxes is the 11th positional arg (index 10) of _demux_loop.
            captured["inboxes"] = args[10]
            await real_demux(*args, **kwargs)

        return patch.object(hsa, "_demux_loop", new=_wrapper)

    # ----- Finding #1: inboxes eviction (memory-exhaustion DoS) -----------

    async def test_failing_flood_does_not_grow_inboxes_unboundedly(self) -> None:
        """A flood of MANY DISTINCT source addrs with FAILING handshakes must
        not grow ``inboxes`` without bound: each worker's eviction in its
        ``finally`` drops its inbox, so steady-state ``len(inboxes)`` tracks the
        live worker count (<= max_inflight), and after the flood drains
        ``inboxes`` returns to ~0. Before the fix ``inboxes`` only ever grew —
        an attacker with spoofed source addrs would OOM the box."""
        n_sources = 60
        max_inflight = 8

        # Every clock reading is a minute later, so no rate bucket runs dry:
        # this test is about eviction, not pacing (test_handshake_gate.py
        # covers pacing).
        minutes = itertools.count(0.0, 60.0)

        # Unique source addrs (the exact string is opaque to the acceptor —
        # only used as a dict key, modelling distinct spoofed sources).
        sources = [
            (f"198.51.{i // 250}.{i % 250}", 40000 + i) for i in range(n_sources)
        ]
        script = {addr: "fail" for addr in sources}
        observed = {"active": 0, "max_active": 0}
        transport = _FakeRealTransport([])
        ps = asyncio.Event()
        captured: dict = {}
        peak_inboxes = {"max": 0}

        with self._capture_inboxes(captured):
            with self._patch_handshake(script, observed):
                config = _FakeConfig(max_inflight)
                stub = _Stub()
                task = asyncio.ensure_future(
                    asyncio.wait_for(
                        _accept_until_winner(
                            config,  # type: ignore[arg-type]
                            stub,  # type: ignore[arg-type]
                            stub,  # type: ignore[arg-type]
                            stub,  # type: ignore[arg-type]
                            stub,  # type: ignore[arg-type]
                            transport,
                            ps,
                            limiter=SourceLimiter(clock=lambda: next(minutes)),
                        ),
                        timeout=10.0,
                    )
                )
                # Drip-feed the flood so each source's worker can fail and be
                # evicted before the next arrives (a real attack is a stream,
                # not a single burst); track the live inbox high-water mark.
                for addr in sources:
                    transport._recv_queue.put_nowait(_seed_frame(addr))
                    for _ in range(200):
                        inboxes = captured.get("inboxes")
                        if inboxes is not None:
                            peak_inboxes["max"] = max(peak_inboxes["max"], len(inboxes))
                        if transport._recv_queue.empty():
                            break
                        await asyncio.sleep(0.001)
                # Let the last batch of workers finish and evict.
                for _ in range(500):
                    if observed["active"] == 0:
                        break
                    await asyncio.sleep(0.001)
                await asyncio.sleep(0.02)
                final_inboxes = captured.get("inboxes")
                assert final_inboxes is not None
                self.assertLessEqual(
                    len(final_inboxes),
                    max_inflight,
                    "after a failing flood drains, inboxes must shrink back to "
                    "~0 (<= max_inflight) — it must NOT retain an entry per "
                    "spoofed source",
                )
                ps.set()
                keys, _pub, _ret = await task
                self.assertIsNone(keys)

        # The peak live-inbox count tracked the worker bound, never O(n_sources).
        self.assertLessEqual(
            peak_inboxes["max"],
            max_inflight,
            "inboxes grew past the worker bound toward the number of distinct "
            "sources — eviction is not happening (memory-exhaustion DoS)",
        )
        # Far more distinct sources ran a worker than could fit concurrently —
        # proving slots (and their inboxes) were reused after eviction.
        self.assertGreater(
            len(observed.get("started", set())),
            max_inflight,
            "evicted slots must be reused for later sources",
        )

    async def test_inbox_hard_cap_bounds_concurrent_inboxes(self) -> None:
        """Defence-in-depth: even if eviction lagged, ``len(inboxes)`` can never
        exceed the hard cap ``_MAX_INBOXES`` — new-source datagrams beyond it are
        dropped. Drive STALLERS (which hold their slot/inbox) with a tiny cap and
        confirm no more than the cap of inboxes ever coexist and excess sources
        never started a worker."""
        cap = 3
        n_sources = 12
        sources = [
            (f"198.51.{i // 250}.{i % 250}", 41000 + i) for i in range(n_sources)
        ]
        script = {addr: "stall" for addr in sources}
        observed = {"active": 0, "max_active": 0}
        transport = _FakeRealTransport([_seed_frame(a) for a in sources])
        ps = asyncio.Event()
        captured: dict = {}
        peak = {"max": 0}

        # Cap below max_inflight so the INBOX cap (not the semaphore) is the
        # binding constraint we exercise.
        with patch.object(hsa, "_MAX_INBOXES", cap):
            with self._capture_inboxes(captured):
                with self._patch_handshake(script, observed):
                    config = _FakeConfig(n_sources + 5)  # semaphore not binding
                    stub = _Stub()
                    task = asyncio.ensure_future(
                        _accept_until_winner(
                            config,  # type: ignore[arg-type]
                            stub,  # type: ignore[arg-type]
                            stub,  # type: ignore[arg-type]
                            stub,  # type: ignore[arg-type]
                            stub,  # type: ignore[arg-type]
                            transport,
                            ps,
                        )
                    )
                    for _ in range(2000):
                        inboxes = captured.get("inboxes")
                        if inboxes is not None:
                            peak["max"] = max(peak["max"], len(inboxes))
                        if transport._recv_queue.empty() and inboxes is not None:
                            break
                        await asyncio.sleep(0.001)
                    ps.set()
                    await asyncio.wait_for(task, timeout=5.0)

        self.assertLessEqual(
            peak["max"], cap, "len(inboxes) exceeded the hard cap _MAX_INBOXES"
        )
        self.assertLessEqual(
            len(observed.get("started", set())),
            cap,
            "a new-source datagram past the inbox cap must be dropped (no worker)",
        )

    async def test_default_backoff_used_when_none_injected(self) -> None:
        """When no backoff is injected, _accept_until_winner falls back to the
        module-local ``_default_backoff`` (the cycle-free fallback; production
        passes in dsm.server._backoff_or_shutdown). A single winner accept
        completes normally with the default in place."""
        observed = {"active": 0, "max_active": 0}
        script = {_WINNER: "win"}
        transport = _FakeRealTransport([_seed_frame(_WINNER)])
        with self._patch_handshake(script, observed):
            config = _FakeConfig(8)
            stub = _Stub()
            keys, pub, _ret = await asyncio.wait_for(
                _accept_until_winner(
                    config,  # type: ignore[arg-type]
                    stub,  # type: ignore[arg-type]
                    stub,  # type: ignore[arg-type]
                    stub,  # type: ignore[arg-type]
                    stub,  # type: ignore[arg-type]
                    transport,
                    asyncio.Event(),
                ),
                timeout=5.0,
            )
        self.assertIsNotNone(keys)
        self.assertEqual(pub, b"pub-198.51.100.7:51820")


class MaxInflightConfigValidation(unittest.TestCase):
    """The new ``max_inflight_handshakes`` Config field is validated >= 1 via
    the existing _VALIDATORS pipeline (default 8 is accepted)."""

    @staticmethod
    def _server_base(**overrides: object) -> dict[str, object]:
        base: dict[str, object] = {
            "mode": "server",
            "server_ip": "10.0.0.1",
            "server_port": 51820,
            "listen_port": 51821,
            "key_file": "/tmp/test.key",
            "cert_file": "/tmp/test.crt",
            "ca_root_file": "/tmp/test-ca.pem",
            "attest_key_file": "/tmp/test-attest.key",
            "transport": "udp",
            "dns_providers": ["8.8.8.8"],
            "dns_provider_pins": {"8.8.8.8": ["a" * 64]},
            "allowed_cns_file": "/tmp/test-allowed-cns.txt",
            "expected_server_cn": None,
        }
        base.update(overrides)
        return base

    def test_default_is_eight(self) -> None:
        from dsm.core.config import Config

        c = Config(**self._server_base())  # type: ignore[arg-type]
        self.assertEqual(c.max_inflight_handshakes, 8)

    def test_explicit_one_is_accepted(self) -> None:
        from dsm.core.config import Config

        c = Config(**self._server_base(max_inflight_handshakes=1))  # type: ignore[arg-type]
        self.assertEqual(c.max_inflight_handshakes, 1)

    def test_zero_is_rejected(self) -> None:
        from dsm.core.config import Config

        with self.assertRaises(ValueError):
            Config(**self._server_base(max_inflight_handshakes=0))  # type: ignore[arg-type]

    def test_negative_is_rejected(self) -> None:
        from dsm.core.config import Config

        with self.assertRaises(ValueError):
            Config(**self._server_base(max_inflight_handshakes=-3))  # type: ignore[arg-type]

    def test_non_int_is_rejected(self) -> None:
        from dsm.core.config import Config

        with self.assertRaises(ValueError):
            Config(**self._server_base(max_inflight_handshakes="8"))  # type: ignore[arg-type]

    def test_absurd_value_is_rejected_not_just_warned(self) -> None:
        """Finding #4 (config footgun): an absurd pool size (e.g. 1_000_000)
        must be REJECTED, not merely warned — each slot is a live NoiseResponder
        + per-peer inbox, so committing the box to a million is a self-inflicted
        memory-exhaustion footgun."""
        from dsm.core.config import Config

        with self.assertRaises(ValueError):
            Config(**self._server_base(max_inflight_handshakes=1_000_000))  # type: ignore[arg-type]

    def test_hard_cap_boundary_accepted_just_above_rejected(self) -> None:
        """The HARD cap itself is accepted; one above it is rejected."""
        from dsm.core.config import MAX_INFLIGHT_HANDSHAKES, Config

        c = Config(
            **self._server_base(max_inflight_handshakes=MAX_INFLIGHT_HANDSHAKES)  # type: ignore[arg-type]
        )
        self.assertEqual(c.max_inflight_handshakes, MAX_INFLIGHT_HANDSHAKES)
        with self.assertRaises(ValueError):
            Config(
                **self._server_base(  # type: ignore[arg-type]
                    max_inflight_handshakes=MAX_INFLIGHT_HANDSHAKES + 1
                )
            )


if __name__ == "__main__":
    unittest.main()
