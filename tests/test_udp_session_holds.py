"""Regression: the server UDP send_packet closure must NOT trigger a
session shutdown when the destination addr is not yet known.

Root cause: on the server side, ``dest_addr`` returns ``None`` until the
first authenticated client packet arrives and ``_post_authenticate``
commits the client addr. The chaff scheduler fires immediately on
ESTABLISHED; before the fix it hit the ``addr is None`` branch in
``make_send_fn`` and called ``shutdown.set()`` — killing every UDP session
within ~50 ms of handshake completion.

After the fix the branch silently drops the packet (chaff is disposable)
and returns without touching ``shutdown``.

These tests use a real ``tuncore.SessionKeyManager`` (gated on the
extension being built) so the encrypt path exercises the actual AEAD code;
only the transport and destination-addr resolution are stubbed.
"""

from __future__ import annotations

import asyncio
import unittest
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import tuncore as _tuncore  # noqa: TCH004 (runtime import, conditional)
    from dsm.net.transport.udp import UDPTransport

try:
    import tuncore

    _HAS_TUNCORE = True
except ImportError:
    tuncore = None  # type: ignore[assignment]
    _HAS_TUNCORE = False


def _make_session_keys() -> _tuncore.SessionKeyManager:
    """Build a real SessionKeyManager via a loopback bootstrap DH."""
    local = tuncore.BootstrapEphemeral.generate()
    peer = tuncore.BootstrapEphemeral.generate()
    peer_pub = bytes(peer.public_key_bytes)
    return tuncore.complete_bootstrap(local, peer_pub, is_initiator=True)


def _make_stub_udp() -> UDPTransport:
    """Build a UDPTransport subclass that records sends without touching a
    socket.  Returns an instance that passes ``isinstance(x, UDPTransport)``
    — required for the UDP branch inside ``make_send_fn`` to activate.
    """
    from dsm.net.transport.udp import UDPTransport

    class _StubUDP(UDPTransport):
        def __init__(self) -> None:
            # Skip the real __init__ (asyncio setup, socket allocation).
            self.sent: list[tuple[bytes, tuple[str, int]]] = []

        async def send(  # type: ignore[override]
            self, data: bytes, addr: tuple[str, int]
        ) -> None:
            self.sent.append((data, addr))

    return _StubUDP()


@unittest.skipUnless(
    _HAS_TUNCORE,
    "tuncore (Rust crypto core) not built; run `maturin develop` in rust/tuncore/",
)
class TestUDPSessionHolds(unittest.IsolatedAsyncioTestCase):
    """Verify that send_packet with dest_addr() == None drops the packet
    (no send, no shutdown) rather than triggering a shutdown."""

    async def test_drop_not_shutdown_when_addr_unknown(self) -> None:
        """Core regression: addr is None → packet dropped, shutdown NOT set."""
        from dsm.session import SequenceCounter, make_send_fn

        sk = _make_session_keys()
        transport = _make_stub_udp()
        seq = SequenceCounter()
        shutdown = asyncio.Event()

        # dest_addr always returns None — simulates the server before the
        # first authenticated client packet arrives.
        send_packet = make_send_fn(
            sk,
            transport,  # type: ignore[arg-type]
            lambda: None,
            seq,
            shutdown=shutdown,
        )

        # Any valid inner size works; use the smallest size class.
        from dsm.core.protocol import GCM_TAG_SIZE, OUTER_HEADER_SIZE, SIZE_CLASSES

        smallest = SIZE_CLASSES[0]  # 128 bytes wire
        inner_size = smallest - OUTER_HEADER_SIZE - GCM_TAG_SIZE
        payload = b"\x00" * inner_size

        # Must NOT raise.
        await send_packet(payload, smallest)

        # The packet was dropped — transport never received anything.
        self.assertEqual(
            transport.sent,
            [],
            "transport.send() must NOT be called when dest_addr is None",
        )
        # The session must remain alive.
        self.assertFalse(
            shutdown.is_set(),
            "shutdown MUST NOT be set when addr is unknown (drop-and-wait fix)",
        )

    async def test_send_succeeds_when_addr_known(self) -> None:
        """Sanity check: when dest_addr returns a valid addr the packet IS sent."""
        from dsm.session import SequenceCounter, make_send_fn

        sk = _make_session_keys()
        transport = _make_stub_udp()
        seq = SequenceCounter()
        shutdown = asyncio.Event()
        peer_addr = ("127.0.0.1", 51820)

        send_packet = make_send_fn(
            sk,
            transport,  # type: ignore[arg-type]
            lambda: peer_addr,
            seq,
            shutdown=shutdown,
        )

        from dsm.core.protocol import GCM_TAG_SIZE, OUTER_HEADER_SIZE, SIZE_CLASSES

        smallest = SIZE_CLASSES[0]
        inner_size = smallest - OUTER_HEADER_SIZE - GCM_TAG_SIZE
        await send_packet(b"\x01" * inner_size, smallest)

        self.assertEqual(len(transport.sent), 1, "packet must be sent when addr known")
        sent_data, sent_addr = transport.sent[0]
        self.assertEqual(sent_addr, peer_addr)
        self.assertEqual(len(sent_data), smallest, "wire size must match target_size")
        self.assertFalse(shutdown.is_set(), "no shutdown for a normal send")

    async def test_multiple_drops_then_addr_set(self) -> None:
        """N drops while addr is None, then addr is committed, send succeeds.

        Models the real session lifecycle: chaff fires N times before the
        first client packet arrives (each time addr is None → drop), then
        _post_authenticate sets the addr and the next send goes through.
        """
        from dsm.session import SequenceCounter, make_send_fn

        sk = _make_session_keys()
        transport = _make_stub_udp()
        seq = SequenceCounter()
        shutdown = asyncio.Event()
        committed: list[tuple[str, int] | None] = [None]

        def _dest() -> tuple[str, int] | None:
            return committed[0]

        send_packet = make_send_fn(
            sk,
            transport,  # type: ignore[arg-type]
            _dest,
            seq,
            shutdown=shutdown,
        )

        from dsm.core.protocol import GCM_TAG_SIZE, OUTER_HEADER_SIZE, SIZE_CLASSES

        smallest = SIZE_CLASSES[0]
        inner_size = smallest - OUTER_HEADER_SIZE - GCM_TAG_SIZE
        payload = b"\x00" * inner_size

        # Five drops while addr is unknown.
        for _ in range(5):
            await send_packet(payload, smallest)

        self.assertEqual(transport.sent, [], "all five must be dropped")
        self.assertFalse(shutdown.is_set(), "no shutdown after drops")

        # Simulate _post_authenticate committing the client addr.
        committed[0] = ("10.8.0.2", 55000)
        await send_packet(payload, smallest)

        self.assertEqual(len(transport.sent), 1, "send must succeed after addr set")
        self.assertFalse(shutdown.is_set())
