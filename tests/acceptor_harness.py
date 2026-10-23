"""Run the always-on acceptor until its first client (spec §7): a stand-in
for the one-client accept, for tests that used it only as a harness.

UDP: the harness plays the dispatcher and moves every datagram from the
socket straight into the acceptor's intake. It skips offer()'s 1400-byte
filter on purpose, so the demux's own size rules stay in view (offer() has
its own tests in test_client_acceptor.py). A fake handshake that never asks
the session table is admitted once it returns, as HARNESS_CN with the key it
returned: the acceptor's fail-closed check needs the table's mark.
"""

from __future__ import annotations

import asyncio
import contextlib
import time
from collections.abc import Callable, Generator
from typing import Any
from unittest.mock import patch

from dsm.crypto import handshake
from dsm.crypto.handshake import VerifiedClient
from dsm.net.handshake_acceptor import AcceptedClient, ClientAcceptor
from dsm.net.handshake_gate import HandshakeGate, SourceLimiter
from dsm.net.session_slot import SessionTable
from dsm.net.transport.tcp import TCPTransport
from dsm.net.transport.udp import UDPTransport

Addr = tuple[str, int]
# The CN the session's client has in test_slot_hardening.py, and the one a
# fake that never asks the table is admitted as.
HARNESS_CN = "dsm-a-client"


class _AdmitsAfter:
    """Wraps ``server_handshake``. A fake that never called admit_client is
    admitted once it returns, as HARNESS_CN with the key it returned; a real
    handshake, or a fake that asks, is left as it is."""

    def __init__(self, inner: Callable[..., Any]) -> None:
        self._inner = inner

    async def __call__(
        self, transport: Any, *args: Any, admit_client: Any, **kwargs: Any
    ) -> tuple[Any, bytes]:
        asked: list[VerifiedClient] = []

        def _admit(client: VerifiedClient) -> Any:
            asked.append(client)
            return admit_client(client)

        keys, pub = await self._inner(transport, *args, admit_client=_admit, **kwargs)
        if not asked:
            admit_client(VerifiedClient(cn=HARNESS_CN, noise_static=pub))
        return keys, pub


@contextlib.contextmanager
def fakes_admitted() -> Generator[None]:
    """While inside, a fake ``server_handshake`` that never asks the table
    is admitted after it returns. Enter it after the fake is patched in."""
    wrapped = _AdmitsAfter(handshake.server_handshake)
    with patch.object(handshake, "server_handshake", wrapped):
        yield


async def _feed(sock: UDPTransport, acceptor: ClientAcceptor) -> None:
    """Play the dispatcher: every datagram goes to the acceptor's intake."""
    while True:
        data, addr = await sock.recv()
        await acceptor._intake.put((data, addr))


async def first_client(
    config: Any,
    keystore: Any,
    attest_store: Any,
    materials: Any,
    cn_allowlist: Any,
    source: UDPTransport | asyncio.Queue[tuple[TCPTransport, Addr]],
    process_shutdown: asyncio.Event,
    limiter: SourceLimiter | None = None,
    table: SessionTable | None = None,
    gate: HandshakeGate | None = None,
    *,
    clock: Callable[[], float] = time.monotonic,
) -> AcceptedClient | None:
    """Serve ``source`` until the first client or ``process_shutdown``, then
    stop. Without ``table``, one is built from the allowlist's order, as
    run_server builds it; a stand-in allowlist gives HARNESS_CN the first
    address."""
    if limiter is None:
        limiter = SourceLimiter()
    if table is None:
        table = SessionTable(getattr(cn_allowlist, "order", ()) or (HARNESS_CN,))
    udp = source if isinstance(source, UDPTransport) else None
    tcp = None if isinstance(source, UDPTransport) else source
    first: asyncio.Future[AcceptedClient] = asyncio.get_running_loop().create_future()

    def _on_client(accepted: AcceptedClient) -> None:
        if not first.done():
            first.set_result(accepted)

    acceptor = ClientAcceptor(
        config,
        keystore,
        attest_store,
        materials,
        cn_allowlist,
        limiter,
        table,
        gate,
        _on_client,
        udp=udp,
        tcp=tcp,
        clock=clock,
    )
    with fakes_admitted():
        run = asyncio.ensure_future(acceptor.run())
        helpers = {asyncio.ensure_future(process_shutdown.wait())}
        if udp is not None:
            helpers.add(asyncio.ensure_future(_feed(udp, acceptor)))
        try:
            await asyncio.wait(
                {run, first, *helpers}, return_when=asyncio.FIRST_COMPLETED
            )
        finally:
            for task in helpers:
                task.cancel()
            await acceptor.stop()
            await asyncio.wait({run, *helpers})
    error = None if run.cancelled() else run.exception()
    if error is not None:
        raise error
    return first.result() if first.done() else None


async def accept_first(
    config: Any,
    keystore: Any,
    attest_store: Any,
    materials: Any,
    cn_allowlist: Any,
    source: UDPTransport | asyncio.Queue[tuple[TCPTransport, Addr]],
    process_shutdown: asyncio.Event,
    limiter: SourceLimiter | None = None,
    table: SessionTable | None = None,
    gate: HandshakeGate | None = None,
    *,
    clock: Callable[[], float] = time.monotonic,
) -> tuple[Any, bytes | None, UDPTransport | TCPTransport | None]:
    """first_client(), returned as the one-client accept did:
    ``(session_keys, client_pub, transport)``, with the client's device key
    as client_pub (the real server_handshake returns the same bytes). On
    shutdown ``(None, None, socket)`` for UDP, ``(None, None, None)`` for
    TCP."""
    won = await first_client(
        config,
        keystore,
        attest_store,
        materials,
        cn_allowlist,
        source,
        process_shutdown,
        limiter,
        table,
        gate,
        clock=clock,
    )
    if won is not None:
        return won.session_keys, won.client.noise_static, won.transport
    return None, None, source if isinstance(source, UDPTransport) else None
