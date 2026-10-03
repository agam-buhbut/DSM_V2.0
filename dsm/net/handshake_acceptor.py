"""Bounded-concurrent UDP handshake acceptor.

The serial accept path drives one ``server_handshake`` at a time over the
shared UDP socket, so a single well-formed msg1 followed by silence parks the
responder across its retries (~18 s), and a slow trickle of such attempts
starves a legitimate client. nftables rate-limiting bounds the packet rate but
cannot tell a slow genuine handshake from a slow bogus one.

Here a bounded pool of workers validates handshakes concurrently. Only one
session is ever admitted (one TUN, one forwarding/MASQUERADE setup, one DNS
proxy, one socket): the first worker to authenticate wins and the others are
cancelled. While a session is live the acceptor is not running, so new
handshake traffic queues on the kernel socket.

* :func:`_demux_loop` is the only caller of the real ``transport.recv()``. It
  routes each datagram to a bounded per-source inbox; the first datagram from
  a new source spawns a worker on a :class:`_PerPeerUDPView`, which gives
  ``server_handshake`` the transport surface it expects with the source
  address pinned.
* Workers run under a semaphore of ``config.max_inflight_handshakes``, each
  with a hard per-attempt deadline.

Handoff: once a winner is chosen the demux stops reading the real socket, so
the client's first post-handshake datagrams stay queued for the data path.
Any the demux had already routed into the winner's inbox are re-injected
ahead of the real queue. The handoff is loss-free up to the smaller of the
winner's inbox (``_WINNER_INBOX_FRAMES``) and the real recv queue
(``RECV_QUEUE_SIZE`` in ``udp.py``), both 256 frames — the same backpressure
the live data path already applies.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

from dsm.net.transport.udp import UDPTransport

if TYPE_CHECKING:
    import tuncore
    from dsm.core.config import Config
    from dsm.crypto.attest_store import AttestStore
    from dsm.crypto.auth_loader import CertAuthMaterials
    from dsm.crypto.cert_allowlist import CNAllowlist
    from dsm.crypto.keystore import KeyStore
    from dsm.net.transport.tcp import TCPTransport

log = logging.getLogger(__name__)

# Jittered retry backoff, as dsm.server._backoff_or_shutdown: returns True iff
# process_shutdown fired during the wait. Injected by the caller because
# importing dsm.server here would be an import cycle.
BackoffFn = Callable[[int, "asyncio.Event"], Awaitable[bool]]


def _emit_handshake_failure(err: Exception) -> None:
    """Emit the failed-handshake netaudit event with a coarse error label.

    Every ``CertAuthError`` subclass collapses to ``"cert_auth"`` so the audit
    stream cannot tell an allowlist miss from a CRL hit. Duplicates
    ``dsm.server._emit_handshake_failure`` to avoid an import cycle.
    """
    from dsm.core import netaudit
    from dsm.crypto.handshake import CertAuthError

    error_label = "cert_auth" if isinstance(err, CertAuthError) else type(err).__name__
    netaudit.emit(
        "handshake_end",
        role="server",
        outcome="failed",
        error=error_label,
    )


async def _default_backoff(
    consecutive_failures: int, process_shutdown: asyncio.Event
) -> bool:
    """Fallback backoff for direct calls; same timing as the server's."""
    from dsm.core.rand import csprng_float

    base = min(
        _DEFAULT_BACKOFF_BASE * (2 ** min(consecutive_failures - 1, 4)),
        _DEFAULT_BACKOFF_MAX,
    )
    jitter = (csprng_float() - 0.5) * _DEFAULT_BACKOFF_JITTER * base
    delay = max(0.0, base + jitter)
    try:
        await asyncio.wait_for(process_shutdown.wait(), timeout=delay)
        return True
    except TimeoutError:
        return False


# Per-attempt deadline (s): room for one lost-and-retransmitted message within
# server_handshake's own retry budget, while capping how long one bogus msg1
# can hold a worker slot.
_HANDSHAKE_ATTEMPT_DEADLINE = 12.0

# A correct handshake has at most one unconsumed frame queued; 8 absorbs
# reordering and retransmits. Overflow drops, so a flooding source only hurts
# itself.
_PER_PEER_INBOX_FRAMES = 8

# The winner's inbox is widened to this so the client's pipelined first DATA
# burst, routed in before the demux notices the winner, is not dropped at the
# handshake depth.
_WINNER_INBOX_FRAMES = 256

# Hard cap on tracked sources, against a spoofed-source flood. The semaphore
# normally binds first: an inbox only outlives its worker until the worker's
# finally evicts it.
_MAX_INBOXES = 4096

# Shutdown/winner check cadence (s), matching the data loop's recv cadence.
_ACCEPT_DEMUX_POLL = 0.1

# Consecutive failed attempts before new-worker spawns are paced by the
# backoff, so a flood of doomed attempts cannot tight-loop.
_ALL_FAIL_BACKOFF_THRESHOLD = 3

# Same values as dsm.server._HANDSHAKE_RETRY_BACKOFF_* (not imported: cycle).
_DEFAULT_BACKOFF_BASE = 0.5  # seconds
_DEFAULT_BACKOFF_MAX = 5.0  # seconds
_DEFAULT_BACKOFF_JITTER = 0.5  # ±this fraction of base


class _PerPeerUDPView(UDPTransport):
    """One peer's slice of a real :class:`UDPTransport`.

    ``recv()`` drains this peer's inbox and always reports the pinned address,
    so ``server_handshake``'s per-message source checks hold by construction.
    ``send()`` ignores the requested address and sends to the pinned one, so a
    worker cannot be steered at another host.

    Subclasses ``UDPTransport`` because ``server_handshake`` branches on
    ``isinstance(transport, UDPTransport)``. ``__init__`` skips the base
    initializer: only ``recv`` and ``send`` are ever called on a view.
    """

    def __init__(  # pylint: disable=super-init-not-called
        self,
        real: UDPTransport,
        peer_addr: tuple[str, int],
        inbox: asyncio.Queue[bytes],
    ) -> None:
        self._real = real
        self._peer_addr = peer_addr
        self._inbox = inbox

    async def recv(  # type: ignore[override]
        self, timeout: float | None = None
    ) -> tuple[bytes, tuple[str, int]]:
        if timeout is not None:
            data = await asyncio.wait_for(self._inbox.get(), timeout)
        else:
            data = await self._inbox.get()
        return data, self._peer_addr

    async def send(  # type: ignore[override]
        self, data: bytes, addr: tuple[str, int]
    ) -> None:
        del addr  # pinned to peer_addr
        await self._real.send(data, self._peer_addr)


class _AcceptState:
    """Failure count for one accept cycle; drives the all-fail backoff."""

    __slots__ = ("consecutive_failures",)

    def __init__(self) -> None:
        self.consecutive_failures = 0


async def _run_handshake_worker(
    config: Config,
    keystore: KeyStore,
    attest_store: AttestStore,
    materials: CertAuthMaterials,
    cn_allowlist: CNAllowlist,
    view: _PerPeerUDPView,
    peer_addr: tuple[str, int],
    winner: asyncio.Future[tuple[tuncore.SessionKeyManager, bytes, tuple[str, int]]],
    state: _AcceptState,
) -> None:
    """Run one peer's handshake under the per-attempt deadline.

    The first success sets ``winner``; a later success is discarded.
    """
    from cryptography.x509.oid import ExtendedKeyUsageOID

    from dsm.crypto.handshake import (
        CertAuthError,
        CertRevokedError,
        CNNotAllowedError,
        HandshakeError,
        server_handshake,
    )

    try:
        session_keys, client_pub = await asyncio.wait_for(
            server_handshake(
                view,  # type: ignore[arg-type]  # virtual UDPTransport subclass
                keystore.identity,
                attest_key=attest_store.attest_key,
                cert_der=materials.cert_der,
                ca_root=materials.ca_root,
                cn_allowlist=cn_allowlist,
                crl=materials.crl,
                required_client_eku=ExtendedKeyUsageOID.CLIENT_AUTH,
                rotation_packets=config.rotation_packets,
                rotation_seconds=config.rotation_seconds,
            ),
            timeout=_HANDSHAKE_ATTEMPT_DEADLINE,
        )
    except TimeoutError:
        log.info(
            "handshake attempt from %s exceeded %.0fs deadline — slot reclaimed",
            peer_addr,
            _HANDSHAKE_ATTEMPT_DEADLINE,
        )
        state.consecutive_failures += 1
        return
    except (
        CNNotAllowedError,
        CertRevokedError,
        CertAuthError,
        HandshakeError,
    ) as e:
        # Same opaque INFO/WARNING logging as the serial path; detail at DEBUG.
        if isinstance(e, (CNNotAllowedError, CertRevokedError, CertAuthError)):
            log.warning("handshake rejected (cert auth) from %s", peer_addr)
        else:
            log.info("handshake failed from %s", peer_addr)
        log.debug("handshake failure detail (%s): %s", peer_addr, e)
        _emit_handshake_failure(e)
        state.consecutive_failures += 1
        return

    if not winner.done():
        winner.set_result((session_keys, client_pub, peer_addr))
        state.consecutive_failures = 0
        log.info("handshake winner: %s", peer_addr)
    else:
        log.debug(
            "handshake from %s authenticated after a winner — discarded", peer_addr
        )


def _is_winner_addr(
    winner: asyncio.Future[tuple[tuncore.SessionKeyManager, bytes, tuple[str, int]]],
    addr: tuple[str, int],
) -> bool:
    if not winner.done() or winner.cancelled():
        return False
    _, _, win_addr = winner.result()
    return win_addr == addr


def _promote_winner_inbox(
    inboxes: dict[tuple[str, int], asyncio.Queue[bytes]],
    win_addr: tuple[str, int],
) -> None:
    """Swap the winner's inbox for a wider queue holding the same frames.

    Called from the winning worker's ``finally`` with no await after
    ``winner.set_result``, so the demux cannot route into the old queue in
    between.
    """
    old = inboxes.get(win_addr)
    if old is None or old.maxsize >= _WINNER_INBOX_FRAMES:
        return
    wider: asyncio.Queue[bytes] = asyncio.Queue(maxsize=_WINNER_INBOX_FRAMES)
    while not old.empty():
        try:
            wider.put_nowait(old.get_nowait())
        except asyncio.QueueFull:  # pragma: no cover - wider is strictly larger
            break
    inboxes[win_addr] = wider


async def _demux_loop(
    config: Config,
    keystore: KeyStore,
    attest_store: AttestStore,
    materials: CertAuthMaterials,
    cn_allowlist: CNAllowlist,
    transport: UDPTransport,
    winner: asyncio.Future[tuple[tuncore.SessionKeyManager, bytes, tuple[str, int]]],
    process_shutdown: asyncio.Event,
    workers: set[asyncio.Task[None]],
    semaphore: asyncio.Semaphore,
    inboxes: dict[tuple[str, int], asyncio.Queue[bytes]],
    state: _AcceptState,
    backoff: BackoffFn,
) -> None:
    """Route datagrams from the real socket to per-source inboxes.

    Runs until a winner is set or shutdown is requested. A datagram from an
    unknown source spawns a worker if a slot is free. ``inboxes`` and
    ``workers`` belong to the caller, which re-injects the winner's residual
    frames and cancels the losers.
    """
    while not winner.done() and not process_shutdown.is_set():
        try:
            data, addr = await transport.recv(timeout=_ACCEPT_DEMUX_POLL)
        except TimeoutError:
            continue

        # A winner may have landed while we were in recv(): keep the winner's
        # frame for re-injection and drop anyone else's.
        if winner.done():
            _, _, win_addr = winner.result()
            if addr == win_addr:
                win_inbox = inboxes.get(win_addr)
                if win_inbox is not None:
                    try:
                        win_inbox.put_nowait(data)
                    except asyncio.QueueFull:
                        log.debug("winner inbox full at handoff — dropping %s", addr)
            return

        inbox = inboxes.get(addr)
        if inbox is not None:
            # Sources whose worker has finished were evicted, so they fall
            # through below and may start a fresh attempt.
            try:
                inbox.put_nowait(data)
            except asyncio.QueueFull:
                log.debug("per-peer inbox full for %s — dropping frame", addr)
            continue

        if state.consecutive_failures >= _ALL_FAIL_BACKOFF_THRESHOLD:
            if await backoff(state.consecutive_failures, process_shutdown):
                return
            if winner.done() or process_shutdown.is_set():
                continue

        # New source without a free slot: drop it. A genuine client's msg1
        # retransmit gets in once a slot frees.
        if semaphore.locked():
            log.debug(
                "handshake pool saturated — dropping new-source frame from %s", addr
            )
            continue
        if len(inboxes) >= _MAX_INBOXES:
            log.warning(
                "handshake inbox cap (%d) reached — dropping new-source frame "
                "from %s",
                _MAX_INBOXES,
                addr,
            )
            continue

        await semaphore.acquire()
        new_inbox: asyncio.Queue[bytes] = asyncio.Queue(maxsize=_PER_PEER_INBOX_FRAMES)
        new_inbox.put_nowait(data)
        inboxes[addr] = new_inbox
        view = _PerPeerUDPView(transport, addr, new_inbox)

        async def _slot_scoped(
            v: _PerPeerUDPView = view, a: tuple[str, int] = addr
        ) -> None:
            try:
                await _run_handshake_worker(
                    config,
                    keystore,
                    attest_store,
                    materials,
                    cn_allowlist,
                    v,
                    a,
                    winner,
                    state,
                )
            finally:
                semaphore.release()
                # Evict so failing sources cannot grow ``inboxes``. The
                # winner's inbox stays, widened, for the residual re-injection.
                if not _is_winner_addr(winner, a):
                    inboxes.pop(a, None)
                else:
                    _promote_winner_inbox(inboxes, a)

        task = asyncio.ensure_future(_slot_scoped())
        workers.add(task)
        task.add_done_callback(workers.discard)


async def _cancel_and_drain(tasks: set[asyncio.Task[None]]) -> None:
    """Cancel and await ``tasks`` so no loser outlives the accept."""
    pending = [t for t in tasks if not t.done()]
    for task in pending:
        task.cancel()
    for task in pending:
        try:
            await task
        except asyncio.CancelledError:
            pass


def _reinject_winner_residual(
    transport: UDPTransport,
    win_addr: tuple[str, int],
    inboxes: dict[tuple[str, int], asyncio.Queue[bytes]],
) -> None:
    """Put the winner's post-handshake frames back on the real recv queue.

    The worker stops reading its inbox after the last handshake message, but
    the demux may already have routed the client's first DATA packets there;
    without this they would be lost. They go ahead of anything already queued,
    because they arrived first. ``UDPTransport`` has no public re-inject API,
    so this writes its ``_recv_queue`` directly. Loss-free while the residual
    plus the queued frames fit ``RECV_QUEUE_SIZE``; overflow is logged.
    """
    win_inbox = inboxes.get(win_addr)
    if win_inbox is None or win_inbox.empty():
        return

    residual: list[bytes] = []
    while not win_inbox.empty():
        residual.append(win_inbox.get_nowait())

    real_q = transport._recv_queue  # pylint: disable=protected-access  # pyright: ignore[reportPrivateUsage]  # fmt: skip
    carried: list[tuple[bytes, tuple[str, int]]] = []
    while not real_q.empty():
        carried.append(real_q.get_nowait())
    for frame in residual:
        try:
            real_q.put_nowait((frame, win_addr))
        except asyncio.QueueFull:
            log.warning("recv queue full re-injecting winner frame — dropped")
    for item in carried:
        try:
            real_q.put_nowait(item)
        except asyncio.QueueFull:
            log.warning("recv queue full restoring carried frame — dropped")


async def _accept_until_winner(  # pyright: ignore[reportUnusedFunction]  # used by dsm.server
    config: Config,
    keystore: KeyStore,
    attest_store: AttestStore,
    materials: CertAuthMaterials,
    cn_allowlist: CNAllowlist,
    transport_obj: UDPTransport,
    process_shutdown: asyncio.Event,
    backoff: BackoffFn | None = None,
) -> tuple[
    tuncore.SessionKeyManager | None,
    bytes | None,
    UDPTransport | TCPTransport | None,
]:
    """Accept one UDP client by validating handshakes concurrently.

    Same contract as ``dsm.server._accept_one_session``: returns
    ``(session_keys, client_pub, transport)`` for the winner, where
    ``transport`` is the same real UDP transport, still holding the winner's
    post-handshake datagrams; or ``(None, None, transport_obj)`` when
    shutdown arrives first. Production passes ``dsm.server._backoff_or_shutdown``
    as ``backoff``; it defaults to :func:`_default_backoff`.
    """
    if backoff is None:
        backoff = _default_backoff

    loop = asyncio.get_running_loop()
    winner: asyncio.Future[tuple[tuncore.SessionKeyManager, bytes, tuple[str, int]]]
    winner = loop.create_future()
    semaphore = asyncio.Semaphore(config.max_inflight_handshakes)
    workers: set[asyncio.Task[None]] = set()
    inboxes: dict[tuple[str, int], asyncio.Queue[bytes]] = {}
    state = _AcceptState()

    shutdown_wait = asyncio.ensure_future(process_shutdown.wait())
    demux = asyncio.ensure_future(
        _demux_loop(
            config,
            keystore,
            attest_store,
            materials,
            cn_allowlist,
            transport_obj,
            winner,
            process_shutdown,
            workers,
            semaphore,
            inboxes,
            state,
            backoff,
        )
    )
    try:
        await asyncio.wait(
            {winner, demux, shutdown_wait},
            return_when=asyncio.FIRST_COMPLETED,
        )
        # Stop reading the real socket so the winner's later datagrams stay
        # queued for the data path.
        if not demux.done():
            demux.cancel()
        try:
            await demux
        except asyncio.CancelledError:
            pass
        # Copy: the done-callbacks mutate the set.
        await _cancel_and_drain(set(workers))
    finally:
        if not shutdown_wait.done():
            shutdown_wait.cancel()
            try:
                await shutdown_wait
            except asyncio.CancelledError:
                pass

    if winner.done() and not winner.cancelled():
        session_keys, client_pub, peer = winner.result()
        # The demux and all workers have stopped, so nothing else touches the
        # inboxes now.
        _reinject_winner_residual(transport_obj, peer, inboxes)
        return session_keys, client_pub, transport_obj

    return None, None, transport_obj
