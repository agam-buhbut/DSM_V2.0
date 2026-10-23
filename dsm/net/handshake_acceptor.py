"""Bounded-concurrent handshake acceptor.

The serial accept path drove one ``server_handshake`` at a time, so a single
well-formed msg1 followed by silence parked the responder across its retries
(~18 s), and a slow trickle of such attempts starved a legitimate client.
nftables rate-limiting bounds the packet rate but cannot tell a slow genuine
handshake from a slow bogus one.

Here a bounded pool of workers validates handshakes concurrently.
:class:`ClientAcceptor` runs for the whole run (spec §2.7). Each attempt
that passes the full handshake and the run's
:class:`~dsm.net.session_slot.SessionTable` (one tunnel address and one
session per CN, and each CN's takeover allowance) is handed to
``on_client`` and becomes a session; the other attempts go on.

* :func:`_demux` reads the frames no session fits (UDP; the dispatcher
  hands them over through :meth:`ClientAcceptor.offer`, which keeps only
  1400-byte frames) and routes each to a bounded per-source inbox. A new
  source must open with a full handshake frame, find a free slot and pass
  the run's :class:`~dsm.net.handshake_gate.SourceLimiter`; then it gets a
  worker on a :class:`_PerPeerUDPView`, which gives ``server_handshake`` the
  transport surface it expects with the source address pinned. The demux
  awaits nothing but its read and a cookie reply's send, so no source can
  pause routing for the others. :func:`_admit_tcp` does the same for the
  connections the run's listener queues.
* With the run's :class:`~dsm.net.handshake_gate.HandshakeGate` (wire v2),
  a new UDP source's 1400-byte frame must also carry a valid mac1, and,
  under load, a mac2 from a cookie: the demux answers a missing cookie with
  a cookie reply and keeps no state; a known address's reply comes from its
  own small budget (spec §3.7). A TCP connection's first frame must come
  within ``_TCP_FIRST_FRAME_DEADLINE`` and be 1400 bytes with a valid mac1
  (no cookies: TCP already proves the address); only then is it charged the
  shared start limits (the accept charges only its address's). A bad mac1
  is dropped silently and counted in one INFO line a minute. A failed or
  refused attempt, and a start the pool or the limits refuse, turn cookies
  on for 30 s. Without a gate (tests only) nothing of this is checked.
* Workers run under a semaphore of ``config.max_inflight_handshakes``, each
  with a hard per-attempt deadline. A client that passed every check also
  needs the table's yes before the last frame.
* Push-out (spec §4): with the run's gate, a new UDP source or TCP
  connection that finds no room may take the place of a stalled attempt —
  one at least ``_PUSH_OUT_AFTER_S`` old (from the msg1 that started it, or
  from the TCP accept), that is not busy making its msg2 (a wait for the TPM
  counts; a TCP connection that has sent nothing yet is not busy) and that
  has not passed the table's check. If its address already runs
  ``PER_SOURCE_INFLIGHT`` attempts, only that address's own oldest such
  attempt can go, and the new one takes over its share too; otherwise, when
  every slot is full, the oldest such attempt of any address gives up its
  slot, and a known address may take a stranger's attempt of any age (spec
  §3.7 E3). Without a gate (tests only) nothing is pushed out.
* A stranger's start that proved its address (a valid mac2, or a TCP
  connection) and then ended without a session bars that address for 30 s
  (spec §3.7 E2).

Handoff: the frames still in a passing client's inbox go with it
(``AcceptedClient.held``). Nothing awaits between its bootstrap reply and
``on_client``, so its session is in the table before its first data packet
can arrive; later packets reach the session through the dispatcher.
"""

# The acceptor's views, push-out rules and TCP machinery keep this module
# over pylint's 1000-line ceiling by design.
# pylint: disable=too-many-lines

from __future__ import annotations

import asyncio
import enum
import logging
import os
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from dsm.core.log import RepeatLog
from dsm.crypto.handshake import HANDSHAKE_FRAME_SIZE
from dsm.net._addresses import TunnelAssignment
from dsm.net.handshake_gate import (
    GLOBAL_START_RATE,
    PER_SOURCE_INFLIGHT,
    HandshakeGate,
    Msg1Verdict,
    SourceLimiter,
)
from dsm.net.transport.tcp import FramingError, TCPTransport
from dsm.net.transport.udp import UDPTransport

if TYPE_CHECKING:
    import tuncore
    from dsm.core.config import Config
    from dsm.crypto.attest_store import AttestStore
    from dsm.crypto.auth_loader import CertAuthMaterials
    from dsm.crypto.cert_allowlist import CNAllowlist
    from dsm.crypto.handshake import VerifiedClient
    from dsm.crypto.keystore import KeyStore
    from dsm.net.session_slot import SessionTable

log = logging.getLogger(__name__)

# One line per 10 s at most: a flood of connections would otherwise log one
# line per connection.
_tcp_full_log = RepeatLog(log, logging.DEBUG)

# A TCP connection that sent no first frame in time: one DEBUG line per 10 s
# at most, with a count, never the address.
_tcp_first_frame_log = RepeatLog(log, logging.DEBUG)

# A stalled attempt was pushed out for a new one (spec §4.3): one INFO line
# per 10 s at most, with a count, never an address.
_push_out_log = RepeatLog(log, logging.INFO)

# A full intake (spec §2.7): one DEBUG line per 10 s at most, with a count,
# never an address.
_intake_full_log = RepeatLog(log, logging.DEBUG)


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


def _note_trouble(gate: HandshakeGate | None) -> None:
    """An attempt failed or a start was refused: cookies on for 30 s."""
    if gate is not None:
        gate.load.note_trouble()


async def _send_cookie_reply(
    transport: UDPTransport, reply: bytes, addr: tuple[str, int]
) -> None:
    """Send a cookie reply. A send error drops it: the client resends msg1."""
    try:
        await transport.send(reply, addr)
    except OSError as e:
        log.debug("cookie reply not sent (%s)", type(e).__name__)


class _FirstFrameTCP(TCPTransport):
    """One TCP connection whose first frame was already read to check its
    mac1. ``recv()`` gives that frame back once, then reads the connection.
    ``__init__`` skips the base initializer: only ``recv`` and ``send`` are
    ever called on a view.
    """

    def __init__(  # pylint: disable=super-init-not-called
        self,
        real: TCPTransport,
        first: bytes,
        on_msg2: Callable[[], None] | None = None,
    ) -> None:
        self._real = real
        self._first: bytes | None = first
        self._on_msg2 = on_msg2

    async def recv(self, timeout: float | None = None) -> bytes:
        first = self._first
        if first is not None:
            self._first = None
            return first
        return await self._real.recv(timeout)

    async def send(self, data: bytes) -> None:
        await self._real.send(data)
        # The first send is msg2: once it has left, the attempt is no longer
        # signing. A resend does not call this again.
        on_msg2, self._on_msg2 = self._on_msg2, None
        if on_msg2 is not None:
            on_msg2()


# Per-attempt deadline (s): room for one lost-and-retransmitted message within
# server_handshake's own retry budget, while capping how long one bogus msg1
# can hold a worker slot.
_HANDSHAKE_ATTEMPT_DEADLINE = 12.0

# A correct handshake has at most one unconsumed frame queued; 8 absorbs
# reordering and retransmits. Overflow drops, so a flooding source only hurts
# itself.
_PER_PEER_INBOX_FRAMES = 8

# Hard cap on tracked sources, against a spoofed-source flood. The semaphore
# normally binds first: an inbox only outlives its worker until the worker's
# done-callback evicts it.
_MAX_INBOXES = 4096

# Frames no session fits, waiting for the acceptor (spec §2.7). Every new
# handshake passes here, for the whole run: room for every client's msg1
# after a restart, plus junk. Every handshake frame is 1400 bytes, so about
# 360 KB when full. When it is full a frame is dropped, like loss on the link.
_INTAKE_FRAMES = 256

# Step S (spec §4): stalled attempts must not hold the handshake slots.

# A TCP connection gets this long to send its first full frame (spec §4.2). A
# real client sends msg1 right after connecting; 3 s covers a slow link and
# one lost TCP segment.
_TCP_FIRST_FRAME_DEADLINE = 3.0
# The age, counted from its start, an attempt must reach before a new start
# that finds no room can push it out (spec §4.3). A real client finishes
# within the server's signature, one round trip and its own signature.
_PUSH_OUT_AFTER_S = 1.5
# How much longer than _PUSH_OUT_AFTER_S the slot rule lets an attempt stay
# protected while its msg2 waits for the TPM (spec §4.4).
_SIGNING_ALLOWANCE_S = 0.25
# One msg2 signature on the box's TPM, as the slot rule assumes it (spec §4.4,
# handshake_gate.py's GLOBAL_START_RATE note). Kept at the measured value even
# where signing is faster: the larger value is the safe side.
_SERVER_SIGNING_TIME_S = 0.21
# The time a real client gets from msg2 leaving to its msg3: what
# _PUSH_OUT_AFTER_S leaves after the server's own signature. A push-out
# victim whose msg2 left more recently was held up by the server's TPM
# queue, so it did not stall (owner decision 2026-10-23).
_REPLY_ALLOWANCE_S = _PUSH_OUT_AFTER_S - _SERVER_SIGNING_TIME_S


def _slot_rule_ok(  # pyright: ignore[reportUnusedFunction]  # used by dsm.server
    max_inflight: int,
) -> bool:
    """Whether ``max_inflight`` slots meet condition (1) of the slot rule
    (spec §4.4): strangers starting at the overall limit keep fewer attempts
    protected at once than there are slots. Conditions (2) and (3) use only
    code constants, so a unit test pins them; ``run_server`` warns at start
    when this is False.
    """
    return max_inflight > GLOBAL_START_RATE * (_PUSH_OUT_AFTER_S + _SIGNING_ALLOWANCE_S)


class _PassedOn(enum.Enum):
    """How a pushed-out attempt's place went to a new attempt (spec §4.3),
    so its done-callback gives back exactly what the new one did not take."""

    SLOT_ONLY = enum.auto()  # case 2: it gives its address's share back
    SLOT_AND_SHARE = enum.auto()  # case 1: the new same-address attempt holds both


@dataclass(eq=False)
class _Attempt:
    """One running attempt, as push-out (spec §4.3) and the failed-start
    penalty (spec §3.7 E2) see it."""

    ip: str
    # Step S's clock at the attempt's start (UDP: its msg1; TCP: the accept).
    # It never moves later.
    started: float
    # From entering the msg2 signing path, any wait in the TPM queue included,
    # until msg2 has been sent: no push-out meanwhile.
    signing: bool
    passed_on: _PassedOn | None = None
    # The start proved its address: over UDP its msg1 needed a cookie (the
    # server was under load); over TCP the connection itself, with the gate.
    # Only a proved start that ends without a session costs the penalty.
    proved: bool = False
    # Step S's clock, for msg2_at.
    clock: Callable[[], float] = field(default=time.monotonic, repr=False)
    # Step S's clock when msg2 first left; None before.
    msg2_at: float | None = None

    def msg2_sent(self) -> None:
        self.signing = False
        self.msg2_at = self.clock()


def _running_from(attempts: Mapping[asyncio.Task[None], _Attempt], ip: str) -> int:
    """How many of ``ip``'s attempts still hold its address's share."""
    return sum(
        1
        for task, rec in attempts.items()
        if rec.ip == ip and rec.passed_on is None and not task.done()
    )


def _pick_victim(
    attempts: Mapping[asyncio.Task[None], _Attempt],
    now: float,
    past_admit: Callable[[asyncio.Task[None]], bool],
    *,
    ip: str | None = None,
    any_age: Callable[[str], bool] | None = None,
) -> asyncio.Task[None] | None:
    """The oldest attempt that can be pushed out (from ``ip`` only, when
    given), or None (spec §4.3): at least ``_PUSH_OUT_AFTER_S`` old, not
    signing (a wait for the TPM counts; a TCP connection that has sent
    nothing yet is not signing), not ``past_admit`` (past the session
    check), not passed on already, not ended. A record whose address
    ``any_age`` says yes to may go at any age (E3, spec §3.7).
    A clock that stepped back gives a negative age, which reads as too young.
    A tie keeps the earlier record, and the dict holds records in start order.
    """
    victim: asyncio.Task[None] | None = None
    oldest = 0.0
    for task, rec in attempts.items():
        if rec.passed_on is not None or task.done() or rec.signing:
            continue
        if ip is not None and rec.ip != ip:
            continue
        too_young = now - rec.started < _PUSH_OUT_AFTER_S
        if too_young and (any_age is None or not any_age(rec.ip)):
            continue
        if past_admit(task):
            continue
        if victim is None or rec.started < oldest:
            victim, oldest = task, rec.started
    return victim


def _choose_push_out(
    attempts: Mapping[asyncio.Task[None], _Attempt],
    now: float,
    ip: str,
    *,
    pool_full: bool,
    past_admit: Callable[[asyncio.Task[None]], bool],
    is_known: Callable[[str], bool],
) -> tuple[asyncio.Task[None], _PassedOn] | None:
    """The attempt a new start from ``ip`` may push out, and how, or None.

    Case 1 first, whether or not the pool is full: ``ip`` is at its in-flight
    cap, so only its own oldest pushable attempt can help, and the new start
    takes over that attempt's share and slot. If it has none, None: it is
    refused as today: dropped as pool saturated when every slot is full,
    else by the limiter's in-flight line. Case 2: the pool is full, so the
    oldest pushable attempt of any address gives up its slot; when ``ip`` is
    known, a stranger's attempt may go at any age (E3, spec §3.7).
    ``past_admit`` tells an attempt past the session check.
    """
    if _running_from(attempts, ip) >= PER_SOURCE_INFLIGHT:
        own = _pick_victim(attempts, now, past_admit, ip=ip)
        return None if own is None else (own, _PassedOn.SLOT_AND_SHARE)
    if pool_full:

        def _stranger(rec_ip: str) -> bool:
            return not is_known(rec_ip)

        any_age = _stranger if is_known(ip) else None
        other = _pick_victim(attempts, now, past_admit, any_age=any_age)
        return None if other is None else (other, _PassedOn.SLOT_ONLY)
    return None


def _push_out(
    attempts: dict[asyncio.Task[None], _Attempt],
    victim: asyncio.Task[None],
    how: _PassedOn,
) -> None:
    """Hand ``victim``'s place to a new attempt: mark how, then cancel it.

    Marked first: a loop can take two new starts in one step, and the
    victim's task ends only on a later one, so the mark is what keeps it from
    being picked twice; its done-callback reads the mark too.
    """
    attempts[victim].passed_on = how
    victim.cancel()
    _push_out_log.log(
        "pushed out a stalled handshake attempt to make room for a new one"
    )


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
        on_msg2: Callable[[], None] | None = None,
    ) -> None:
        self._real = real
        self._peer_addr = peer_addr
        self._inbox = inbox
        self._on_msg2 = on_msg2

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
        # The worker's first send is msg2 (cookie replies go out on the real
        # socket): once it has left, the attempt is no longer signing. A
        # resend does not call this again.
        on_msg2, self._on_msg2 = self._on_msg2, None
        if on_msg2 is not None:
            on_msg2()

    def hand_over(self) -> tuple[UDPTransport, tuple[bytes, ...]]:
        """The run's socket and the frames still in this peer's inbox, oldest
        first: what a passing client's new session takes over (spec §2.7)."""
        held: list[bytes] = []
        while not self._inbox.empty():
            held.append(self._inbox.get_nowait())
        return self._real, tuple(held)


async def _cancel_and_drain(tasks: set[asyncio.Task[None]]) -> None:
    """Cancel and await ``tasks`` so no attempt outlives the acceptor's stop.

    Every task is awaited, even after one failed: a cancelled worker may
    still wait for its signing thread, and the server zeroizes the attest key
    once the acceptor has stopped. The first error that is not a cancel is
    raised once all are done.
    """
    pending = [t for t in tasks if not t.done()]
    for task in pending:
        task.cancel()
    first_error: Exception | None = None
    for task in pending:
        try:
            await task
        except asyncio.CancelledError:
            pass
        except Exception as e:  # noqa: BLE001  # raised once all are done
            if first_error is None:
                first_error = e
    if first_error is not None:
        raise first_error


# --- The always-on acceptor (multi-client, spec §2.7) -----------------------


@dataclass(frozen=True)
class AcceptedClient:
    """A client that passed the full handshake and the session table's
    checks: what its session is made from (spec §2.2)."""

    # Out of repr: it holds the session's keys.
    session_keys: tuncore.SessionKeyManager = field(repr=False)
    client: VerifiedClient
    tunnel: TunnelAssignment
    # UDP: the run's socket. TCP: the client's own connection.
    transport: UDPTransport | TCPTransport
    # The handshake address: where the session first sends (spec §2.10).
    peer: tuple[str, int]
    # UDP frames still in the client's inbox when it passed (spec §2.7).
    held: tuple[bytes, ...] = ()


async def _run_attempt(
    config: Config,
    keystore: KeyStore,
    attest_store: AttestStore,
    materials: CertAuthMaterials,
    cn_allowlist: CNAllowlist,
    transport: UDPTransport | TCPTransport,
    peer_addr: tuple[str, int],
    on_client: Callable[[AcceptedClient], None],
    *,
    who: str,
    table: SessionTable,
    gate: HandshakeGate | None = None,
    limiter: SourceLimiter | None = None,
    record: _Attempt | None = None,
) -> None:
    """Run one handshake attempt under the per-attempt deadline.

    ``transport`` is a :class:`_PerPeerUDPView` or one accepted TCP
    connection. The hook is ``table.admit``, with this task as the
    attempt's mark: it picks the client's tunnel address and may refuse the
    client before the last frame. A client that passes is confirmed in
    ``table``, its address noted as known in ``limiter`` (the run's), and
    handed to ``on_client`` with the frames still in its inbox, all with no
    ``await`` in between (spec §2.7). ``who`` names the peer in log lines:
    its address for UDP, a fixed label for TCP. A connection error ends
    only this attempt.

    With ``gate`` (wire v2), a TCP connection's first frame must come within
    ``_TCP_FIRST_FRAME_DEADLINE`` and be 1400 bytes with a valid mac1 before
    anything else happens, and every failure counts as trouble. Only then
    does ``limiter`` charge the shared start limits; once any CN has
    connected in this run they include the newcomer limit (spec §3.7 E1).

    ``record`` is the attempt's record. Over TCP it is marked as signing
    once the first frame passed, until msg2 has left (UDP's view does that
    for UDP), and it loses its ``proved`` bit when the shared limits refuse
    the first frame, which is not the address's doing. Over both it loses
    that bit when msg3 does not open (spec §3.7 E2).
    """
    from cryptography.x509.oid import ExtendedKeyUsageOID

    from dsm.crypto.handshake import (
        BadMsg3Error,
        CertAuthError,
        CertRevokedError,
        ClientRefusedError,
        CNNotAllowedError,
        HandshakeError,
        server_handshake,
    )

    attempt: object = asyncio.current_task() or object()

    def _admit(client: VerifiedClient) -> TunnelAssignment:
        return table.admit(attempt, client)

    conn = transport  # TCP: the connection the session keeps
    try:
        try:
            # Not wait_for: on Python 3.11 it runs the handshake as a second
            # task and can stop waiting for it when a second cancel lands,
            # while its signature still runs in a thread. Here the handshake
            # runs in this task, so its own wait for that thread holds.
            async with asyncio.timeout(_HANDSHAKE_ATTEMPT_DEADLINE):
                if gate is not None and isinstance(transport, TCPTransport):
                    # TCP gets no cookies (its own handshake proved the
                    # address), but its first frame needs a valid mac1 before
                    # anything is signed, and it must come soon (spec §4.2).
                    # A wrong size or a bad mac1 is scanner noise, not
                    # trouble. No first frame in time, a spent shared limit,
                    # or a read that resets or breaks framing (the except
                    # branches below) is trouble.
                    try:
                        async with asyncio.timeout(_TCP_FIRST_FRAME_DEADLINE):
                            first = await transport.recv()
                    except TimeoutError:
                        _note_trouble(gate)
                        _tcp_first_frame_log.log(
                            "TCP handshake start dropped: no first frame in time"
                        )
                        return
                    if len(first) != HANDSHAKE_FRAME_SIZE or not gate.mac1_ok(first):
                        log.debug("TCP handshake start dropped: wrong size or bad mac1")
                        return
                    # Only now the shared start limits: a silent connection or
                    # a bad first frame spends none of them (spec §4.2).
                    if limiter is not None and not limiter.try_shared(
                        peer_addr[0], in_session=table.ever_confirmed
                    ):
                        _note_trouble(gate)
                        if record is not None:
                            record.proved = False
                        return
                    if record is not None:
                        # Entering the msg2 signing path: no push-out until
                        # msg2 has left, any wait for the TPM included.
                        record.signing = True
                    transport = _FirstFrameTCP(
                        transport,
                        first,
                        on_msg2=None if record is None else record.msg2_sent,
                    )
                session_keys, _client_pub = await server_handshake(
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
                    admit_client=_admit,
                )
        except TimeoutError:
            _note_trouble(gate)
            log.info(
                "handshake attempt from %s exceeded %.0fs deadline — slot reclaimed",
                who,
                _HANDSHAKE_ATTEMPT_DEADLINE,
            )
            return
        except ClientRefusedError as e:
            _note_trouble(gate)
            # The table logged why, rate-limited and without an address; one
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
            _note_trouble(gate)
            if isinstance(e, BadMsg3Error) and record is not None:
                # Over UDP a spoofed datagram in this attempt looks the same:
                # no penalty, so it cannot bar a real client (spec §3.7 E2).
                record.proved = False
            # Same opaque INFO/WARNING logging as before; detail at DEBUG.
            if isinstance(e, (CNNotAllowedError, CertRevokedError, CertAuthError)):
                log.warning("handshake rejected (cert auth) from %s", who)
            else:
                log.info("handshake failed from %s", who)
            log.debug("handshake failure detail (%s): %s", who, e)
            _emit_handshake_failure(e)
            return
        except (FramingError, OSError) as e:
            _note_trouble(gate)
            # A bad length prefix, a reset or an early close on this connection.
            log.info("handshake transport error (%s)", type(e).__name__)
            # Never str(e): asyncio's OSError text can carry addresses. The class
            # name and the OS error text are enough.
            detail = type(e).__name__
            if isinstance(e, OSError) and e.errno:
                detail = f"{detail}: {os.strerror(e.errno)}"
            log.debug("handshake transport error detail: %s", detail)
            return

        # From here to on_client nothing awaits: the session is in the table
        # before the client's first data packet can arrive (spec §2.7).
        if not table.is_admitted(attempt):
            # server_handshake returned without asking the table: a bug.
            # Fail closed rather than let an unchecked client in.
            log.error("a handshake ended without the session check; dropped it")
            return
        client, tunnel = table.confirm(attempt)
        if limiter is not None:
            limiter.note_known(peer_addr[0], client.cn)
        if isinstance(conn, _PerPeerUDPView):
            run_socket, held = conn.hand_over()
            on_client(
                AcceptedClient(
                    session_keys, client, tunnel, run_socket, peer_addr, held
                )
            )
        else:
            on_client(AcceptedClient(session_keys, client, tunnel, conn, peer_addr))
    finally:
        table.release(attempt)


def _log_unexpected(done: asyncio.Task[None]) -> None:
    """Log an attempt's error that none of its handlers caught (a bug, or a
    TPM error from tuncore), once, with its traceback and no address. Without
    this the task's exception would never be read."""
    if done.cancelled():
        return
    error = done.exception()
    if error is not None:
        log.error(
            "a handshake attempt failed with an unexpected error",
            exc_info=error,
        )


def _penalized(done: asyncio.Task[None], rec: _Attempt) -> bool:
    """Whether an ended attempt costs its address the failed-start penalty
    (spec §3.7 E2): its start proved the address, and no stop cancelled it
    (a push-out is not a stop). A success says True too: its address is
    known by then, and the limiter never bars a known address."""
    return rec.proved and not (done.cancelled() and rec.passed_on is None)


def _stalled(rec: _Attempt, now: float) -> bool:
    """Whether a push-out victim stalled, so its address pays the penalty
    (spec §3.7 E2): at least ``_PUSH_OUT_AFTER_S`` old (a younger one went
    by E3), and its msg2, if one left, left at least ``_REPLY_ALLOWANCE_S``
    ago (a later one waited in the server's TPM queue, not the client's
    doing)."""
    if now - rec.started < _PUSH_OUT_AFTER_S:
        return False
    return rec.msg2_at is None or now - rec.msg2_at >= _REPLY_ALLOWANCE_S


async def _demux(
    config: Config,
    keystore: KeyStore,
    attest_store: AttestStore,
    materials: CertAuthMaterials,
    cn_allowlist: CNAllowlist,
    transport: UDPTransport,
    on_client: Callable[[AcceptedClient], None],
    table: SessionTable,
    workers: set[asyncio.Task[None]],
    semaphore: asyncio.Semaphore,
    inboxes: dict[tuple[str, int], asyncio.Queue[bytes]],
    limiter: SourceLimiter,
    *,
    gate: HandshakeGate | None = None,
    attempts: dict[asyncio.Task[None], _Attempt] | None = None,
    clock: Callable[[], float] = time.monotonic,
    intake: asyncio.Queue[tuple[bytes, tuple[str, int]]] | None = None,
) -> None:
    """Route handshake frames to per-source inboxes, until cancelled.

    Frames come from ``intake`` (what the dispatcher offers the acceptor)
    or, without it, from ``transport.recv()`` (tests). Replies leave on
    ``transport``, the run's socket, and each passing client is handed on
    with it. A frame from a new source starts a worker only if it is a full
    handshake frame, finds room (a free slot, its address below its
    in-flight cap) or, with ``gate``, may push out a stalled attempt (spec
    §4.3), and ``limiter`` admits its address; once any CN has connected in
    this run that includes the newcomer limit (spec §3.7 E1). Nothing here
    awaits but the read and a cookie reply's send. ``inboxes`` and
    ``workers`` belong to the caller.

    ``gate`` (wire v2) checks mac1, and under load mac2, right after the
    size check, before any slot. ``attempts`` holds each running attempt's
    record (tests pass their own); ``clock`` is Step S's own, never the
    limiter's, and dates each attempt's start.
    """
    # (inboxes stays the 11th positional parameter: a test wraps this
    # function and reads it by position.)
    records: dict[asyncio.Task[None], _Attempt] = {} if attempts is None else attempts
    size_drops = RepeatLog(log, logging.DEBUG)

    def _start(
        src: tuple[str, int], frame: bytes, started: float, proved: bool
    ) -> None:
        """Start one attempt in a slot the caller holds for it: a free one,
        or a pushed-out attempt's. Its msg1 is already here, so it is
        signing from the start until its view has sent msg2."""
        new_inbox: asyncio.Queue[bytes] = asyncio.Queue(maxsize=_PER_PEER_INBOX_FRAMES)
        new_inbox.put_nowait(frame)
        inboxes[src] = new_inbox
        record = _Attempt(
            ip=src[0], started=started, signing=True, proved=proved, clock=clock
        )
        view = _PerPeerUDPView(transport, src, new_inbox, on_msg2=record.msg2_sent)

        # A done-callback, not a ``finally`` in the worker: a task cancelled
        # before its first step never runs its body, but its done-callbacks
        # still run, exactly once.
        def _end_attempt(done: asyncio.Task[None], a: tuple[str, int] = src) -> None:
            # The record first, so an error below cannot leave it behind.
            rec = records.pop(done)
            if rec.passed_on is None:
                # A pushed-out attempt's slot belongs to the one that took it.
                semaphore.release()
            # Evict so failing sources cannot grow ``inboxes``. A client that
            # passed took its held frames with it.
            inboxes.pop(a, None)
            # Last, so an error in ``finish`` cannot leave a dead inbox. After
            # a same-address push-out the new attempt holds this share.
            if rec.passed_on is not _PassedOn.SLOT_AND_SHARE:
                limiter.finish(a[0], failed=_penalized(done, rec))
            _log_unexpected(done)

        task = asyncio.ensure_future(
            _run_attempt(
                config,
                keystore,
                attest_store,
                materials,
                cn_allowlist,
                view,
                src,
                on_client,
                who=str(src),
                table=table,
                gate=gate,
                limiter=limiter,
                record=record,
            )
        )
        records[task] = record
        task.add_done_callback(_end_attempt)
        workers.add(task)
        task.add_done_callback(workers.discard)

    while True:
        if intake is not None:
            data, addr = await intake.get()
        else:
            data, addr = await transport.recv()

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

        # Wire v2: mac1, and under load a cookie, before any slot or state.
        # Under load only a msg1 with a valid mac2 gets past here, so it
        # proved its address (spec §3.7 E2).
        under_load = False
        if gate is not None:
            under_load = gate.load.under_load(len(workers))
            verdict = gate.check_msg1(data, addr, under_load=under_load)
            if verdict is Msg1Verdict.NEED_COOKIE:
                # A known address's reply comes from its own small budget, so
                # a spoofed flood that empties the shared one cannot keep it
                # waiting (spec §3.7, C1). A spent one is not logged: no line
                # may tell that an address is known.
                known = limiter.is_known(addr[0])
                if not known or limiter.take_known_cookie(addr[0]):
                    reply = gate.cookie_reply(data, addr, shared_budget=not known)
                    if reply is not None:
                        await _send_cookie_reply(transport, reply, addr)
                continue
            if verdict is Msg1Verdict.DROP:
                continue

        now = clock()
        pool_full = semaphore.locked()
        # No room: a full pool, or the address at its in-flight cap. With the
        # run's gate a start that got this far proved its address (with any
        # slot in use the server is under load, so it carried a valid mac2),
        # and it may push out a stalled attempt (spec §4.3); a known address
        # may push out a stranger's of any age (E3). Without a gate (tests
        # only) nothing is pushed out.
        push = (
            _choose_push_out(
                records,
                now,
                addr[0],
                pool_full=pool_full,
                past_admit=table.is_admitted,
                is_known=limiter.is_known,
            )
            if gate is not None
            else None
        )
        if push is not None:
            victim, how = push
            # Asked before anything changes, so a refusal leaves the old
            # attempt alone. The new attempt takes the old one's slot.
            if not limiter.try_start(
                addr[0],
                in_session=table.ever_confirmed,
                inherits_share=how is _PassedOn.SLOT_AND_SHARE,
            ):
                _note_trouble(gate)
                continue
            if not _stalled(records[victim], now):
                # It did not stall: it costs its address nothing (spec §3.7 E2).
                records[victim].proved = False
            _push_out(records, victim, how)
            _start(addr, data, now, under_load)
            continue

        # New source without a free slot: drop it. A genuine client's msg1
        # retransmit gets in once a slot frees.
        if pool_full:
            log.debug(
                "handshake pool saturated — dropping new-source frame from %s", addr
            )
            _note_trouble(gate)
            continue
        if len(inboxes) >= _MAX_INBOXES:
            log.warning(
                "handshake inbox cap (%d) reached — dropping new-source frame "
                "from %s",
                _MAX_INBOXES,
                addr,
            )
            _note_trouble(gate)
            continue
        # Never waits: the pool has a free slot (checked above).
        await semaphore.acquire()
        # Asked last, so a packet dropped above spends none of its address's
        # budget. From here to the done-callback nothing awaits, so the slot
        # and the address are always given back.
        if not limiter.try_start(addr[0], in_session=table.ever_confirmed):
            semaphore.release()
            _note_trouble(gate)
            continue
        _start(addr, data, now, under_load)


async def _admit_tcp(
    config: Config,
    keystore: KeyStore,
    attest_store: AttestStore,
    materials: CertAuthMaterials,
    cn_allowlist: CNAllowlist,
    connections: asyncio.Queue[tuple[TCPTransport, tuple[str, int]]],
    on_client: Callable[[AcceptedClient], None],
    table: SessionTable,
    workers: set[asyncio.Task[None]],
    semaphore: asyncio.Semaphore,
    open_conns: dict[tuple[str, int], TCPTransport],
    limiter: SourceLimiter,
    *,
    gate: HandshakeGate | None = None,
    attempts: dict[asyncio.Task[None], _Attempt] | None = None,
    clock: Callable[[], float] = time.monotonic,
) -> None:
    """Admit queued TCP connections, until cancelled.

    The TCP twin of :func:`_demux`. A connection takes a free slot, or with
    ``gate`` may push out a stalled attempt (spec §4.3; the connection
    itself proves its address); otherwise it is closed at once, as when
    ``limiter`` refuses its address. With ``gate``, a connection is charged
    only its address's limits here; its worker checks the first frame, then
    charges the shared ones. A connection that becomes a session is handed
    to ``on_client`` and stays open; every other one is closed when its
    attempt ends. ``open_conns`` and ``workers`` belong to the caller;
    ``attempts`` and ``clock`` work as in :func:`_demux`, and an attempt's
    age counts from its accept.
    """
    records: dict[asyncio.Task[None], _Attempt] = {} if attempts is None else attempts
    while True:
        conn, peer = await connections.get()
        now = clock()
        pool_full = semaphore.locked()
        push = (
            _choose_push_out(
                records,
                now,
                peer[0],
                pool_full=pool_full,
                past_admit=table.is_admitted,
                is_known=limiter.is_known,
            )
            if gate is not None
            else None
        )
        if pool_full and push is None:
            _tcp_full_log.log("handshake pool saturated — closing a new TCP connection")
            _note_trouble(gate)
            conn.close()
            continue
        # TCP gives each open connection its own peer address; this check
        # only keeps open_conns one-to-one.
        if peer in open_conns:
            conn.close()
            continue
        # With the gate only the per-address limits are charged here; the
        # worker charges the shared ones once the first frame passed mac1,
        # so a silent connection spends none of them (spec §4.2).
        shared = gate is None
        if push is not None:
            victim, how = push
            # Asked before anything changes, so a refusal leaves the old
            # attempt alone. The new attempt takes the old one's slot.
            if not limiter.try_start(
                peer[0],
                in_session=table.ever_confirmed,
                shared=shared,
                inherits_share=how is _PassedOn.SLOT_AND_SHARE,
            ):
                _note_trouble(gate)
                conn.close()
                continue
            if not _stalled(records[victim], now):
                # It did not stall: it costs its address nothing (spec §3.7 E2).
                records[victim].proved = False
            _push_out(records, victim, how)
        else:
            # Never waits: the pool has a free slot (checked above).
            await semaphore.acquire()
            # Asked last, so a connection closed above spends none of its
            # address's budget. From here to the done-callback below nothing
            # awaits, so the slot and the address are always given back.
            if not limiter.try_start(
                peer[0], in_session=table.ever_confirmed, shared=shared
            ):
                semaphore.release()
                _note_trouble(gate)
                conn.close()
                continue
        open_conns[peer] = conn
        # Not signing yet: the worker sets that once the first frame passed.
        # With the gate the connection itself proved its address (E2).
        record = _Attempt(
            ip=peer[0], started=now, signing=False, proved=gate is not None, clock=clock
        )

        def _hand_on(accepted: AcceptedClient, p: tuple[str, int] = peer) -> None:
            # The session owns the connection now: the attempt's end must
            # not close it.
            open_conns.pop(p, None)
            on_client(accepted)

        # A done-callback, not a ``finally`` in the worker: a task cancelled
        # before its first step never runs its body, but its done-callbacks
        # still run, exactly once. The close is the sync one; nothing here
        # may await.
        def _end_attempt(
            done: asyncio.Task[None],
            c: TCPTransport = conn,
            p: tuple[str, int] = peer,
        ) -> None:
            # The record first, so an error below cannot leave it behind.
            rec = records.pop(done)
            if rec.passed_on is None:
                # A pushed-out attempt's slot belongs to the one that took it.
                semaphore.release()
            if open_conns.pop(p, None) is not None:
                c.close()
            # Last, so an error in ``finish`` cannot leave a connection open.
            # After a same-address push-out the new attempt holds this share.
            if rec.passed_on is not _PassedOn.SLOT_AND_SHARE:
                limiter.finish(p[0], failed=_penalized(done, rec))
            _log_unexpected(done)

        task = asyncio.ensure_future(
            _run_attempt(
                config,
                keystore,
                attest_store,
                materials,
                cn_allowlist,
                conn,
                peer,
                _hand_on,
                who="a TCP client",
                table=table,
                gate=gate,
                limiter=limiter,
                record=record,
            )
        )
        records[task] = record
        task.add_done_callback(_end_attempt)
        workers.add(task)
        task.add_done_callback(workers.discard)


class ClientAcceptor:
    """The run's handshake acceptor (spec §2.7). It runs for the whole run
    and turns each checked client into a session through ``on_client``.

    UDP (``udp=`` the run's socket): the dispatcher hands over each packet
    no session fits through :meth:`offer`, and replies leave on the socket.
    TCP (``tcp=`` the run's listener queue): each queued connection gets an
    attempt. Both share one pool of ``config.max_inflight_handshakes``
    slots, the run's ``limiter``, ``table`` and ``gate``, the attempt
    deadline, and Step S's ``clock`` (never the limiter's). ``gate`` is None
    only in tests.

    :meth:`run` serves until :meth:`stop`. A bug in its loop raises from
    :meth:`run`; the server then logs it, calls :meth:`stop`, backs off and
    calls :meth:`run` again, with empty inboxes. ``on_client`` must be sync
    and must never raise: it runs inside an attempt, after the client got
    its bootstrap reply.
    """

    def __init__(
        self,
        config: Config,
        keystore: KeyStore,
        attest_store: AttestStore,
        materials: CertAuthMaterials,
        cn_allowlist: CNAllowlist,
        limiter: SourceLimiter,
        table: SessionTable,
        gate: HandshakeGate,
        on_client: Callable[[AcceptedClient], None],
        *,
        udp: UDPTransport | None = None,
        tcp: asyncio.Queue[tuple[TCPTransport, tuple[str, int]]] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if (udp is None) == (tcp is None):
            raise ValueError("ClientAcceptor needs exactly one of udp= or tcp=")
        self._config = config
        self._keystore = keystore
        self._attest_store = attest_store
        self._materials = materials
        self._cn_allowlist = cn_allowlist
        self._limiter = limiter
        self._table = table
        self._gate: HandshakeGate | None = gate
        self._on_client = on_client
        self._udp = udp
        self._tcp = tcp
        self._clock = clock
        # UDP frames no session fits, waiting for the demux. They survive a
        # restart of run(): frames offered during the server's backoff wait.
        self._intake: asyncio.Queue[tuple[bytes, tuple[str, int]]] = asyncio.Queue(
            maxsize=_INTAKE_FRAMES
        )
        self._workers: set[asyncio.Task[None]] = set()
        self._serving: asyncio.Task[None] | None = None
        # True from run() until the next stop(): the order is run(), stop(),
        # run(), and a second loop would leave the first out of stop()'s reach.
        self._started = False

    def offer(self, data: bytes, addr: tuple[str, int]) -> None:
        """Take one UDP packet that no session fits. Only 1400-byte frames
        are kept: every handshake frame is that size, so small junk cannot
        push a real msg1 out of the intake (spec §2.7). Never raises."""
        if len(data) != HANDSHAKE_FRAME_SIZE:
            return
        try:
            self._intake.put_nowait((data, addr))
        except asyncio.QueueFull:
            _intake_full_log.log("handshake intake full, dropping a frame")

    async def run(self) -> None:
        """Serve handshakes until :meth:`stop`. Raises only a bug in the
        demux or the admit loop. The order is: ``run()``, then :meth:`stop`
        once it ended or was cancelled (a cancel of this task alone leaves
        the loop running), then the next ``run()``. A ``run()`` scheduled
        before a :meth:`stop` still serves, until the next ``stop()``.

        Raises:
            RuntimeError: called again before :meth:`stop`.
        """
        if self._started:
            raise RuntimeError("run() was called again before stop()")
        self._started = True
        semaphore = asyncio.Semaphore(self._config.max_inflight_handshakes)
        if self._udp is not None:
            work = _demux(
                self._config,
                self._keystore,
                self._attest_store,
                self._materials,
                self._cn_allowlist,
                self._udp,
                self._on_client,
                self._table,
                self._workers,
                semaphore,
                {},
                self._limiter,
                gate=self._gate,
                clock=self._clock,
                intake=self._intake,
            )
        else:
            assert self._tcp is not None  # __init__ checked: exactly one
            work = _admit_tcp(
                self._config,
                self._keystore,
                self._attest_store,
                self._materials,
                self._cn_allowlist,
                self._tcp,
                self._on_client,
                self._table,
                self._workers,
                semaphore,
                {},
                self._limiter,
                gate=self._gate,
                clock=self._clock,
            )
        serving = asyncio.ensure_future(work)
        self._serving = serving
        # wait(), not await: stop() cancels the loop, and that is no cancel
        # of this task.
        await asyncio.wait({serving})
        if not serving.cancelled():
            error = serving.exception()
            if error is not None:
                raise error

    async def stop(self) -> None:
        """Cancel the loop and every attempt, and wait for each: a cancelled
        worker still waits for its signing thread. Then close the queued TCP
        connections. It returns only once every attempt's done-callbacks have
        run (its slot, share, inbox and connection are back). A client that
        already had its bootstrap reply is not served: the server is
        stopping. Raises the first error an attempt raised while it was being
        stopped (a bug), once all are done. A cancel of the task that awaits
        it still goes through, once every attempt has ended."""
        current = asyncio.current_task()
        cancels = current.cancelling() if current is not None else 0
        tasks = set(self._workers)
        if self._serving is not None:
            tasks.add(self._serving)
            self._serving = None
        try:
            await _cancel_and_drain(tasks)
        finally:
            # Only now, so a run() that starts mid-drain is still refused.
            self._started = False
            while self._tcp is not None and not self._tcp.empty():
                conn, _ = self._tcp.get_nowait()
                conn.close()
            # A worker that ended in the same loop pass as one the drain
            # awaited may still have its done-callbacks queued: let them run
            # first. Each worker leaves the set in its last callback, and
            # every one left here is done, so this takes one loop pass.
            if self._workers:
                await asyncio.wait(set(self._workers))
        # _cancel_and_drain swallows CancelledError, so a cancel aimed at our
        # caller would otherwise vanish into the worker it awaits.
        if current is not None and current.cancelling() > cancels:
            raise asyncio.CancelledError
