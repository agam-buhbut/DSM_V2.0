"""Bounded-concurrent handshake acceptor.

The serial accept path drove one ``server_handshake`` at a time, so a single
well-formed msg1 followed by silence parked the responder across its retries
(~18 s), and a slow trickle of such attempts starved a legitimate client.
nftables rate-limiting bounds the packet rate but cannot tell a slow genuine
handshake from a slow bogus one.

Here a bounded pool of workers validates handshakes concurrently. The server
serves one session at a time (one TUN, one forwarding/MASQUERADE setup, one
DNS proxy, one socket), and the acceptor runs in two places:

* Between sessions (the idle accept): the first worker to authenticate wins
  and the others are cancelled.
* While a session runs (:class:`SessionWatch`, step R): over UDP the live
  session still reads every datagram first and hands over each one it
  cannot use (did not open, or already seen); over TCP the run's one
  listener stays open and the watch reads its queue. A client that passes
  the full handshake and the run's
  :class:`~dsm.net.session_slot.SessionSlot` (the live session's CN, so the
  same client coming back) ends the session and becomes the next one.
  Another client is refused before the last handshake frame.

* :func:`_demux_loop` is the only caller of the real ``transport.recv()``. It
  routes each datagram to a bounded per-source inbox. A new source must open
  with a full handshake frame, find a free slot and pass the run's
  :class:`~dsm.net.handshake_gate.SourceLimiter`; then it gets a worker on a
  :class:`_PerPeerUDPView`, which gives ``server_handshake`` the transport
  surface it expects with the source address pinned. The demux awaits
  nothing but the socket, so no source can pause routing for the others.
  In a session it reads the live session's leftovers through an
  :class:`_IntakeView` instead.
* Workers run under a semaphore of ``config.max_inflight_handshakes``, each
  with a hard per-attempt deadline. With the run's slot, a client that
  passed every check also needs the slot's yes before the last frame.
* :func:`_accept_until_winner_tcp` does the same for TCP. The run's
  :class:`~dsm.net.transport.tcp.TCPListener` queues each accepted
  connection, and :func:`_tcp_admit_loop` gives it a slot and a worker under
  the same pool, limits and deadline, or closes it at once.

Handoff: once a winner is chosen the demux stops reading, so the client's
first post-handshake datagrams stay queued for the data path. Any the demux
had already routed into the winner's inbox (and, in a session, any the live
session handed over since) are re-injected ahead of the real queue once
nothing else reads the socket. The handoff is loss-free up to the smaller of
the winner's inbox (``_WINNER_INBOX_FRAMES``) and the real recv queue
(``RECV_QUEUE_SIZE`` in ``udp.py``), both 256 frames, and in a session the
intake (``_INTAKE_FRAMES``, 64) — the same backpressure the live data path
already applies.
"""

# The idle accept and the in-session accept (step R) share the demux, the
# workers and the TCP machinery, so this module is over pylint's 1000-line
# ceiling by design.
# pylint: disable=too-many-lines

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from dsm.core.log import RepeatLog
from dsm.crypto.handshake import HANDSHAKE_FRAME_SIZE
from dsm.net.handshake_gate import SourceLimiter
from dsm.net.transport.tcp import FramingError, TCPTransport
from dsm.net.transport.udp import UDPTransport

if TYPE_CHECKING:
    import tuncore
    from dsm.core.config import Config
    from dsm.crypto.attest_store import AttestStore
    from dsm.crypto.auth_loader import CertAuthMaterials
    from dsm.crypto.cert_allowlist import CNAllowlist
    from dsm.crypto.keystore import KeyStore
    from dsm.net.session_slot import SessionSlot

log = logging.getLogger(__name__)

# One line per 10 s at most: a flood of connections would otherwise log one
# line per connection.
_tcp_full_log = RepeatLog(log, logging.DEBUG)


def _emit_handshake_failure(err: Exception) -> None:
    """Emit the failed-handshake netaudit event with a coarse error label.

    Every ``CertAuthError`` subclass collapses to ``"cert_auth"`` so the audit
    stream cannot tell an allowlist miss from a CRL hit (the human log lines
    hide that too). Other errors keep their class name; the exception
    message is never emitted (``tests/test_netaudit_no_leak.py``).
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
# done-callback evicts it.
_MAX_INBOXES = 4096

# Shutdown/winner check cadence (s), matching the data loop's recv cadence.
_ACCEPT_DEMUX_POLL = 0.1

# Packets the live session cannot use (did not open, or already seen),
# waiting for the in-session accept. Every handshake frame is 1400 bytes, so
# about 90 KB. When it is full a packet is dropped, like loss on the link.
_INTAKE_FRAMES = 64


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


async def _run_handshake_worker(
    config: Config,
    keystore: KeyStore,
    attest_store: AttestStore,
    materials: CertAuthMaterials,
    cn_allowlist: CNAllowlist,
    transport: UDPTransport | TCPTransport,
    peer_addr: tuple[str, int],
    winner: asyncio.Future[tuple[tuncore.SessionKeyManager, bytes, tuple[str, int]]],
    *,
    who: str,
    slot: SessionSlot | None = None,
    session_live: bool = False,
) -> None:
    """Run one handshake attempt under the per-attempt deadline.

    The first success sets ``winner`` with ``peer_addr``; a later success is
    discarded. ``transport`` is a :class:`_PerPeerUDPView` or one accepted
    TCP connection. ``who`` names the peer in log lines: its address for
    UDP, as before, and a fixed label for TCP, whose log never named peers.
    A connection error ends only this attempt.

    With ``slot`` (the run's :class:`SessionSlot`), a client that passed
    every check must also pass the slot's rules before it gets the last
    handshake frame; ``session_live`` says whether a session runs now. The
    worker's own task is its mark in the slot, so the accept can tell which
    attempt passed and must not be cancelled.
    """
    from cryptography.x509.oid import ExtendedKeyUsageOID

    from dsm.crypto.handshake import (
        CertAuthError,
        CertRevokedError,
        ClientRefusedError,
        CNNotAllowedError,
        HandshakeError,
        VerifiedClient,
        server_handshake,
    )

    attempt: object = asyncio.current_task() or object()
    admit_client: Callable[[VerifiedClient], None] | None = None
    if slot is not None:
        run_slot = slot

        def _admit(client: VerifiedClient) -> None:
            if winner.done():
                raise ClientRefusedError("another client already won this accept")
            run_slot.admit(attempt, client, session_live=session_live)

        admit_client = _admit

    try:
        try:
            session_keys, client_pub = await asyncio.wait_for(
                server_handshake(
                    transport,
                    keystore.identity,
                    attest_key=attest_store.attest_key,
                    cert_der=materials.cert_der,
                    ca_root=materials.ca_root,
                    cn_allowlist=cn_allowlist,
                    crl=materials.crl,
                    required_client_eku=ExtendedKeyUsageOID.CLIENT_AUTH,
                    rotation_packets=config.rotation_packets,
                    rotation_seconds=config.rotation_seconds,
                    admit_client=admit_client,
                ),
                timeout=_HANDSHAKE_ATTEMPT_DEADLINE,
            )
        except TimeoutError:
            log.info(
                "handshake attempt from %s exceeded %.0fs deadline — slot reclaimed",
                who,
                _HANDSHAKE_ATTEMPT_DEADLINE,
            )
            return
        except ClientRefusedError as e:
            # The slot logged why, rate-limited and without an address; one
            # line per attempt here would repeat it.
            log.debug("handshake refused by the session rules: %s", e)
            _emit_handshake_failure(e)
            return
        except (
            CNNotAllowedError,
            CertRevokedError,
            CertAuthError,
            HandshakeError,
        ) as e:
            # Same opaque INFO/WARNING logging as before; detail at DEBUG.
            if isinstance(e, (CNNotAllowedError, CertRevokedError, CertAuthError)):
                log.warning("handshake rejected (cert auth) from %s", who)
            else:
                log.info("handshake failed from %s", who)
            log.debug("handshake failure detail (%s): %s", who, e)
            _emit_handshake_failure(e)
            return
        except (FramingError, OSError) as e:
            # A bad length prefix, a reset or an early close on this connection.
            log.info("handshake transport error (%s)", type(e).__name__)
            # Never str(e): asyncio's OSError text can carry addresses. The class
            # name and the OS error text are enough.
            detail = type(e).__name__
            if isinstance(e, OSError) and e.errno:
                detail = f"{detail}: {os.strerror(e.errno)}"
            log.debug("handshake transport error detail: %s", detail)
            return

        if winner.done():
            log.debug("handshake from %s authenticated after a winner — discarded", who)
            return
        if slot is not None:
            if slot.admitted is not attempt:
                # server_handshake returned without asking the slot: a bug.
                # Fail closed rather than let an unchecked client in.
                log.error("a handshake ended without the session check; dropped it")
                return
            slot.confirm(attempt)
        winner.set_result((session_keys, client_pub, peer_addr))
        log.info("handshake winner: %s", who)
    finally:
        if slot is not None:
            slot.release(attempt)


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

    Called from the winning worker's done-callback, which normally runs
    before the accept re-injects. If not, the re-inject drains the old
    queue, so nothing is lost. The demux may route one last frame into the
    old queue first (it stops once it sees the winner); it is copied over
    with the rest.
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
    limiter: SourceLimiter,
    *,
    slot: SessionSlot | None = None,
    session_live: bool = False,
) -> None:
    """Route datagrams from the real socket to per-source inboxes.

    Runs until a winner is set or shutdown is requested. A datagram from an
    unknown source starts a worker only if it is a full handshake frame, a
    slot is free and ``limiter`` admits its address. Nothing here awaits
    anything but the socket. ``inboxes`` and ``workers`` belong to the
    caller, which re-injects the winner's residual frames and cancels the
    losers.

    ``slot`` and ``session_live`` go to each worker; ``session_live`` also
    makes each new start need the limiter's in-session budget.
    """
    # (inboxes stays the 11th positional parameter: a test wraps this
    # function and reads it by position.)
    size_drops = RepeatLog(log, logging.DEBUG)
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

        # A new source must open with a full handshake frame. Scanners,
        # probes and stray packets are dropped before they can take a slot.
        if len(data) != HANDSHAKE_FRAME_SIZE:
            size_drops.log("dropped a new-source datagram of the wrong size")
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
        # Never waits: the pool has a free slot (checked above).
        await semaphore.acquire()
        # Asked last, so a packet dropped above spends none of its address's
        # budget. From here to the done-callback below nothing awaits, so the
        # slot and the address are always given back.
        if not limiter.try_start(addr[0], in_session=session_live):
            semaphore.release()
            continue

        new_inbox: asyncio.Queue[bytes] = asyncio.Queue(maxsize=_PER_PEER_INBOX_FRAMES)
        new_inbox.put_nowait(data)
        inboxes[addr] = new_inbox
        view = _PerPeerUDPView(transport, addr, new_inbox)

        # A done-callback, not a ``finally`` in the worker: a task cancelled
        # before its first step never runs its body, but its done-callbacks
        # still run, exactly once.
        def _end_attempt(_task: asyncio.Task[None], a: tuple[str, int] = addr) -> None:
            semaphore.release()
            # Evict so failing sources cannot grow ``inboxes``. The winner's
            # inbox stays, widened, for the residual re-injection.
            if not _is_winner_addr(winner, a):
                inboxes.pop(a, None)
            else:
                _promote_winner_inbox(inboxes, a)
            # Last, so an error in ``finish`` cannot leave a dead inbox.
            limiter.finish(a[0])

        task = asyncio.ensure_future(
            _run_handshake_worker(
                config,
                keystore,
                attest_store,
                materials,
                cn_allowlist,
                view,
                addr,
                winner,
                who=str(addr),
                slot=slot,
                session_live=session_live,
            )
        )
        task.add_done_callback(_end_attempt)
        workers.add(task)
        task.add_done_callback(workers.discard)


async def _cancel_and_drain(
    tasks: set[asyncio.Task[None]], keep: object | None = None
) -> None:
    """Cancel and await ``tasks`` so no loser outlives the accept.

    ``keep`` is the attempt that passed the session check (the run's
    ``SessionSlot.admitted``), if any. It is awaited, never cancelled: its
    client may already have the last handshake frame. Its own deadline bounds
    the wait.
    """
    pending = [t for t in tasks if not t.done()]
    for task in pending:
        if task is not keep:
            task.cancel()
    for task in pending:
        try:
            await task
        except asyncio.CancelledError:
            pass


def _drain_inbox(inbox: asyncio.Queue[bytes] | None) -> list[bytes]:
    """Take every frame out of ``inbox``, oldest first."""
    frames: list[bytes] = []
    while inbox is not None and not inbox.empty():
        frames.append(inbox.get_nowait())
    return frames


def _reinject_frames(
    transport: UDPTransport,
    win_addr: tuple[str, int],
    frames: list[bytes],
) -> None:
    """Put the winner's post-handshake frames back on the real recv queue.

    The worker stops reading its inbox after the last handshake message, but
    the demux may already have routed the client's first DATA packets there
    (and, in a session, the live session may have handed over more); without
    this they would be lost. They go ahead of anything already queued,
    because they arrived first. ``UDPTransport`` has no public re-inject API,
    so this writes its ``_recv_queue`` directly. Loss-free while the frames
    plus the queued ones fit ``RECV_QUEUE_SIZE``; overflow is logged.
    """
    if not frames:
        return
    real_q = transport._recv_queue  # pylint: disable=protected-access  # pyright: ignore[reportPrivateUsage]  # fmt: skip
    carried: list[tuple[bytes, tuple[str, int]]] = []
    while not real_q.empty():
        carried.append(real_q.get_nowait())
    for frame in frames:
        try:
            real_q.put_nowait((frame, win_addr))
        except asyncio.QueueFull:
            log.warning("recv queue full re-injecting winner frame — dropped")
    for item in carried:
        try:
            real_q.put_nowait(item)
        except asyncio.QueueFull:
            log.warning("recv queue full restoring carried frame — dropped")


def _report_winner(
    winner: asyncio.Future[tuple[tuncore.SessionKeyManager, bytes, tuple[str, int]]],
    on_winner: Callable[[tuple[str, int]], None] | None,
) -> None:
    """Call ``on_winner`` with the winner's address once it is set.

    A done-callback, so it runs one loop step after the winning worker set
    the result: before the winner's client can answer the last frame.
    """
    if on_winner is None:
        return
    report = on_winner

    def _done(
        fut: asyncio.Future[tuple[tuncore.SessionKeyManager, bytes, tuple[str, int]]],
    ) -> None:
        if not fut.cancelled():
            report(fut.result()[2])

    winner.add_done_callback(_done)


async def _accept_round(
    config: Config,
    keystore: KeyStore,
    attest_store: AttestStore,
    materials: CertAuthMaterials,
    cn_allowlist: CNAllowlist,
    transport: UDPTransport,
    stop: asyncio.Event,
    limiter: SourceLimiter,
    *,
    slot: SessionSlot | None = None,
    session_live: bool = False,
    on_winner: Callable[[tuple[str, int]], None] | None = None,
) -> tuple[
    tuple[tuncore.SessionKeyManager, bytes, tuple[str, int]] | None, list[bytes]
]:
    """One UDP accept: the demux and its workers, until a client wins or
    ``stop`` is set.

    ``transport`` is the run's socket (idle accept) or an
    :class:`_IntakeView` (in-session accept). Returns the winner
    ``(session_keys, client_pub, peer_addr)`` with the frames its inbox
    still held, oldest first, or ``(None, [])``; re-injecting them is the
    caller's job. An attempt past the slot's check is waited for, never
    cancelled, and may still win after ``stop`` is set. ``on_winner`` gets
    the winner's address one loop step after it won.
    """
    loop = asyncio.get_running_loop()
    winner: asyncio.Future[tuple[tuncore.SessionKeyManager, bytes, tuple[str, int]]]
    winner = loop.create_future()
    _report_winner(winner, on_winner)
    semaphore = asyncio.Semaphore(config.max_inflight_handshakes)
    workers: set[asyncio.Task[None]] = set()
    inboxes: dict[tuple[str, int], asyncio.Queue[bytes]] = {}

    stop_wait = asyncio.ensure_future(stop.wait())
    demux = asyncio.ensure_future(
        _demux_loop(
            config,
            keystore,
            attest_store,
            materials,
            cn_allowlist,
            transport,
            winner,
            stop,
            workers,
            semaphore,
            inboxes,
            limiter,
            slot=slot,
            session_live=session_live,
        )
    )
    try:
        await asyncio.wait(
            {winner, demux, stop_wait},
            return_when=asyncio.FIRST_COMPLETED,
        )
    finally:
        # Stop reading first, so the winner's later datagrams stay queued for
        # the data path (idle) or in the intake (in a session).
        await _cancel_and_drain({demux})
        if not stop_wait.done():
            stop_wait.cancel()
            try:
                await stop_wait
            except asyncio.CancelledError:
                pass
        # Copy: the done-callbacks mutate the set.
        await _cancel_and_drain(
            set(workers), keep=slot.admitted if slot is not None else None
        )

    error = None if demux.cancelled() else demux.exception()
    if error is not None:
        # A bug in the demux must not look like a quiet end.
        raise error
    if winner.done() and not winner.cancelled():
        win = winner.result()
        # The demux and all workers have stopped, so nothing else touches
        # the inboxes now.
        return win, _drain_inbox(inboxes.get(win[2]))
    return None, []


async def _accept_until_winner(  # pyright: ignore[reportUnusedFunction]  # used by dsm.server
    config: Config,
    keystore: KeyStore,
    attest_store: AttestStore,
    materials: CertAuthMaterials,
    cn_allowlist: CNAllowlist,
    transport_obj: UDPTransport,
    process_shutdown: asyncio.Event,
    limiter: SourceLimiter | None = None,
    slot: SessionSlot | None = None,
) -> tuple[
    tuncore.SessionKeyManager | None,
    bytes | None,
    UDPTransport | TCPTransport | None,
]:
    """Accept one UDP client by validating handshakes concurrently.

    Returns ``(session_keys, client_pub, transport)`` for the winner, where
    ``transport`` is the same real UDP transport, still holding the winner's
    post-handshake datagrams; or ``(None, None, transport_obj)`` when
    shutdown arrives first. Production passes the run's one
    :class:`SourceLimiter` and :class:`SessionSlot`, so the limits and the
    session rules hold across accepts; without a limiter this call makes its
    own, and without a slot every authenticated client may win.
    """
    if limiter is None:
        limiter = SourceLimiter()
    win, held = await _accept_round(
        config,
        keystore,
        attest_store,
        materials,
        cn_allowlist,
        transport_obj,
        process_shutdown,
        limiter,
        slot=slot,
    )
    if win is None:
        return None, None, transport_obj
    session_keys, client_pub, peer = win
    _reinject_frames(transport_obj, peer, held)
    return session_keys, client_pub, transport_obj


async def _tcp_admit_loop(
    config: Config,
    keystore: KeyStore,
    attest_store: AttestStore,
    materials: CertAuthMaterials,
    cn_allowlist: CNAllowlist,
    connections: asyncio.Queue[tuple[TCPTransport, tuple[str, int]]],
    winner: asyncio.Future[tuple[tuncore.SessionKeyManager, bytes, tuple[str, int]]],
    workers: set[asyncio.Task[None]],
    semaphore: asyncio.Semaphore,
    open_conns: dict[tuple[str, int], TCPTransport],
    limiter: SourceLimiter,
    *,
    slot: SessionSlot | None = None,
    session_live: bool = False,
) -> None:
    """Admit queued TCP connections until a winner is set.

    The TCP twin of :func:`_demux_loop`. A connection is closed at once when
    the pool is full or ``limiter`` refuses its address; otherwise it takes a
    slot and a worker. ``open_conns`` and ``workers`` belong to the caller.

    ``slot`` and ``session_live`` work as in :func:`_demux_loop`.
    """
    while not winner.done():
        conn, peer = await connections.get()
        if winner.done():
            conn.close()
            return
        if semaphore.locked():
            _tcp_full_log.log("handshake pool saturated — closing a new TCP connection")
            conn.close()
            continue
        # TCP gives each open connection its own peer address; this check
        # only keeps open_conns one-to-one.
        if peer in open_conns:
            conn.close()
            continue
        # Never waits: the pool has a free slot (checked above).
        await semaphore.acquire()
        # Asked last, so a connection closed above spends none of its
        # address's budget. From here to the done-callback below nothing
        # awaits, so the slot and the address are always given back.
        if not limiter.try_start(peer[0], in_session=session_live):
            semaphore.release()
            conn.close()
            continue
        open_conns[peer] = conn

        # A done-callback, not a ``finally`` in the worker: a task cancelled
        # before its first step never runs its body, but its done-callbacks
        # still run, exactly once. The close is the sync one; nothing here
        # may await.
        def _end_attempt(
            _task: asyncio.Task[None],
            c: TCPTransport = conn,
            p: tuple[str, int] = peer,
        ) -> None:
            semaphore.release()
            if not _is_winner_addr(winner, p):
                open_conns.pop(p, None)
                c.close()
            # Last, so an error in ``finish`` cannot leave a connection open.
            limiter.finish(p[0])

        task = asyncio.ensure_future(
            _run_handshake_worker(
                config,
                keystore,
                attest_store,
                materials,
                cn_allowlist,
                conn,
                peer,
                winner,
                who="a TCP client",
                slot=slot,
                session_live=session_live,
            )
        )
        task.add_done_callback(_end_attempt)
        workers.add(task)
        task.add_done_callback(workers.discard)


async def _accept_until_winner_tcp(  # pyright: ignore[reportUnusedFunction]  # used by dsm.server
    config: Config,
    keystore: KeyStore,
    attest_store: AttestStore,
    materials: CertAuthMaterials,
    cn_allowlist: CNAllowlist,
    connections: asyncio.Queue[tuple[TCPTransport, tuple[str, int]]],
    process_shutdown: asyncio.Event,
    limiter: SourceLimiter | None = None,
    slot: SessionSlot | None = None,
    *,
    session_live: bool = False,
    on_winner: Callable[[tuple[str, int]], None] | None = None,
) -> tuple[
    tuncore.SessionKeyManager | None,
    bytes | None,
    TCPTransport | None,
]:
    """Accept one TCP client by checking connections concurrently.

    ``connections`` is fed by the run's listener
    (:attr:`TCPListener.connections`). Connections share the UDP acceptor's
    pool (``config.max_inflight_handshakes``), per-address limits and
    per-attempt deadline. Returns ``(session_keys, client_pub, transport)``
    for the first connection to authenticate, where ``transport`` is that
    connection, or ``(None, None, None)`` when ``process_shutdown`` is set
    first (the process shutdown for the idle accept, the session's end for
    the in-session one). Every other connection handed over, including any
    still queued, is closed before return. ``slot``, ``session_live`` and
    ``on_winner`` work as in :func:`_accept_round`.
    """
    if limiter is None:
        limiter = SourceLimiter()

    loop = asyncio.get_running_loop()
    winner: asyncio.Future[tuple[tuncore.SessionKeyManager, bytes, tuple[str, int]]]
    winner = loop.create_future()
    _report_winner(winner, on_winner)
    semaphore = asyncio.Semaphore(config.max_inflight_handshakes)
    workers: set[asyncio.Task[None]] = set()
    open_conns: dict[tuple[str, int], TCPTransport] = {}

    shutdown_wait = asyncio.ensure_future(process_shutdown.wait())
    admit = asyncio.ensure_future(
        _tcp_admit_loop(
            config,
            keystore,
            attest_store,
            materials,
            cn_allowlist,
            connections,
            winner,
            workers,
            semaphore,
            open_conns,
            limiter,
            slot=slot,
            session_live=session_live,
        )
    )
    try:
        await asyncio.wait(
            {winner, admit, shutdown_wait},
            return_when=asyncio.FIRST_COMPLETED,
        )
    finally:
        await _cancel_and_drain({admit})
        if not shutdown_wait.done():
            shutdown_wait.cancel()
            try:
                await shutdown_wait
            except asyncio.CancelledError:
                pass
        # Copy: the done-callbacks mutate the set. Each worker's callback
        # gives back its slot and address and closes a loser's connection.
        # An attempt past the session check is waited for, not cancelled.
        await _cancel_and_drain(
            set(workers), keep=slot.admitted if slot is not None else None
        )
        while not connections.empty():
            queued, _ = connections.get_nowait()
            queued.close()

    win = winner.result() if winner.done() and not winner.cancelled() else None
    error = None if admit.cancelled() else admit.exception()
    if error is not None or win is None:
        for conn in open_conns.values():
            conn.close()
        if error is not None:
            # A bug in the admit loop must not look like a shutdown.
            raise error
        return None, None, None
    session_keys, client_pub, peer = win
    transport = open_conns.pop(peer)
    # A loser's done-callback can run one loop pass after the drain, so close
    # what is left here too (a second close does nothing).
    for conn in open_conns.values():
        conn.close()
    return session_keys, client_pub, transport


class _IntakeView(UDPTransport):
    """The live session's leftovers, seen by the demux as a UDP socket.

    ``recv()`` reads the intake that the live session fills with packets it
    cannot use (did not open, or already seen). ``send()`` goes out on the
    run's real socket, so msg2 and the bootstrap reply leave from the
    server's one UDP port, as in the idle accept. ``__init__`` skips the base
    initializer: only ``recv`` and ``send`` are ever called on a view.
    """

    def __init__(  # pylint: disable=super-init-not-called
        self,
        real: UDPTransport,
        intake: asyncio.Queue[tuple[bytes, tuple[str, int]]],
    ) -> None:
        self._real = real
        self._intake = intake

    async def recv(self, timeout: float | None = None) -> tuple[bytes, tuple[str, int]]:
        if timeout is not None:
            return await asyncio.wait_for(self._intake.get(), timeout)
        return await self._intake.get()

    async def send(self, data: bytes, addr: tuple[str, int]) -> None:
        await self._real.send(data, addr)


@dataclass(frozen=True)
class Winner:
    """The client that won an in-session accept: the next session's peer."""

    session_keys: tuncore.SessionKeyManager
    client_pub: bytes
    # UDP: the run's socket; the winner's packets held so far are back at
    # the front of its queue. TCP: the winner's own connection.
    transport: UDPTransport | TCPTransport


class SessionWatch:
    """Accept handshakes while a session is live, so a client that comes back
    can replace its old session at once (step R).

    The server makes one right before each session (it starts at once) and
    calls :meth:`stop` after the session ended. UDP (``udp=`` the run's
    socket): the live session hands over each packet it cannot use (did not
    open, or already seen) through :attr:`offer`; the demux, workers, pool,
    limits and deadline are the idle accept's. TCP (``tcp=`` the run's
    listener queue): the idle accept's TCP machinery on the run's one
    listener. A client that passes the full handshake and the slot's rules
    sets :attr:`end_session`, so the live session stops, and :meth:`stop`
    hands it over as the next session's peer. A crash here (a bug) is logged
    once; the session runs on and just cannot be replaced until it ends.
    """

    def __init__(
        self,
        config: Config,
        keystore: KeyStore,
        attest_store: AttestStore,
        materials: CertAuthMaterials,
        cn_allowlist: CNAllowlist,
        limiter: SourceLimiter,
        slot: SessionSlot,
        *,
        udp: UDPTransport | None = None,
        tcp: asyncio.Queue[tuple[TCPTransport, tuple[str, int]]] | None = None,
    ) -> None:
        self.end_session = asyncio.Event()
        self._stop = asyncio.Event()
        self._real = udp
        self._intake: asyncio.Queue[tuple[bytes, tuple[str, int]]] | None = None
        self._held: list[bytes] = []
        self._winner_addr: tuple[str, int] | None = None
        self._full_log = RepeatLog(log, logging.DEBUG)
        work: Coroutine[Any, Any, Winner | None]
        if udp is not None:
            intake: asyncio.Queue[tuple[bytes, tuple[str, int]]] = asyncio.Queue(
                maxsize=_INTAKE_FRAMES
            )
            self._intake = intake
            work = self._accept_udp(
                config,
                keystore,
                attest_store,
                materials,
                cn_allowlist,
                _IntakeView(udp, intake),
                udp,
                limiter,
                slot,
            )
        elif tcp is not None:
            work = self._accept_tcp(
                config,
                keystore,
                attest_store,
                materials,
                cn_allowlist,
                tcp,
                limiter,
                slot,
            )
        else:
            raise ValueError("SessionWatch needs udp= or tcp=")
        # UDP: give the watch each packet the live session cannot use (did
        # not open, or already seen; run_data_loops' ``unauthenticated``).
        # None for TCP.
        self.offer: Callable[[bytes, tuple[str, int], bool], None] | None = (
            self._offer if udp is not None else None
        )
        self._task: asyncio.Task[Winner | None] = asyncio.ensure_future(work)
        self._task.add_done_callback(self._log_crash)

    async def _accept_udp(
        self,
        config: Config,
        keystore: KeyStore,
        attest_store: AttestStore,
        materials: CertAuthMaterials,
        cn_allowlist: CNAllowlist,
        view: _IntakeView,
        real: UDPTransport,
        limiter: SourceLimiter,
        slot: SessionSlot,
    ) -> Winner | None:
        win, held = await _accept_round(
            config,
            keystore,
            attest_store,
            materials,
            cn_allowlist,
            view,
            self._stop,
            limiter,
            slot=slot,
            session_live=True,
            on_winner=self._won,
        )
        if win is None:
            return None
        session_keys, client_pub, _peer = win
        self._held = held
        return Winner(session_keys, client_pub, real)

    async def _accept_tcp(
        self,
        config: Config,
        keystore: KeyStore,
        attest_store: AttestStore,
        materials: CertAuthMaterials,
        cn_allowlist: CNAllowlist,
        connections: asyncio.Queue[tuple[TCPTransport, tuple[str, int]]],
        limiter: SourceLimiter,
        slot: SessionSlot,
    ) -> Winner | None:
        session_keys, client_pub, conn = await _accept_until_winner_tcp(
            config,
            keystore,
            attest_store,
            materials,
            cn_allowlist,
            connections,
            self._stop,
            limiter,
            slot,
            session_live=True,
            on_winner=self._won,
        )
        if session_keys is None or client_pub is None or conn is None:
            return None
        return Winner(session_keys, client_pub, conn)

    def _won(self, addr: tuple[str, int]) -> None:
        self._winner_addr = addr
        self.end_session.set()

    def _log_crash(self, task: asyncio.Task[Winner | None]) -> None:
        if task.cancelled():
            return
        error = task.exception()
        if error is not None:
            log.error(
                "in-session handshake accept failed; this session cannot be "
                "replaced until it ends",
                exc_info=error,
            )

    def _offer(self, data: bytes, addr: tuple[str, int], seen: bool) -> None:
        """Take one packet the live session cannot use. Never raises.

        ``seen`` is True when the session's replay window had already seen
        the packet, and False when it did not open.
        """
        intake = self._intake
        if intake is None:
            return
        win = self._winner_addr
        if win is not None:
            # A client won: keep only its packets, any size, seen or not, so
            # its first data packets (their sequence numbers start again at
            # 1) reach its new session in order.
            if addr != win:
                return
        elif seen or len(data) != HANDSHAKE_FRAME_SIZE or self._task.done():
            # Before a winner only a full handshake frame can start or feed an
            # attempt. A seen packet is the live client's own (a handshake
            # frame starts with 8 random bytes, never a seen sequence number),
            # so it costs no signature and no budget. After a crash nothing
            # reads the intake.
            return
        try:
            intake.put_nowait((data, addr))
        except asyncio.QueueFull:
            self._full_log.log("in-session handshake queue full, dropping a frame")

    def _take_intake(self, addr: tuple[str, int]) -> list[bytes]:
        """Empty the intake; keep the frames from ``addr``, oldest first."""
        frames: list[bytes] = []
        intake = self._intake
        while intake is not None and not intake.empty():
            data, src = intake.get_nowait()
            if src == addr:
                frames.append(data)
        return frames

    async def stop(self) -> Winner | None:
        """Stop accepting; return the client that won, if one did.

        Call it once, after the session has ended (nothing reads the socket
        then). An attempt already past the session check is waited for (its
        own 12 s deadline bounds that) and may still win; other attempts are
        cancelled, and queued TCP connections are closed. UDP: the winner's
        packets held so far go back to the front of the socket queue, oldest
        first.
        """
        self._stop.set()
        await asyncio.wait({self._task})
        if self._task.cancelled() or self._task.exception() is not None:
            return None  # a crash was logged when it happened
        win = self._task.result()
        if win is not None and self._real is not None and self._winner_addr is not None:
            frames = self._held + self._take_intake(self._winner_addr)
            _reinject_frames(self._real, self._winner_addr, frames)
        return win
