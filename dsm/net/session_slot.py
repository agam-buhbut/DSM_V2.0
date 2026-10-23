"""Who holds a session, and who may take it over.

A :class:`SessionSlot` is one session's slot. While a session runs the server
still accepts handshakes, so a client that crashed and came back does not
wait for the old session's dead-peer timer. After a handshake passed every
check (certificate chain, attest signature, allowlist, CRL) and before the
server sends the last handshake frame, the slot decides whether that client
may have the session:

* Only one handshake at a time may sit between this check and becoming the
  next session.
* While a session runs, only a client with the same CN (the name in its
  certificate) may take it over: that is the same client coming back.
  A slot refuses any other CN, but the server's :class:`SessionTable`
  gives each CN its own slot, so another client never meets this rule.
* Each CN may take its session over 3 times at once, then once a minute.
  Two devices that share one CN would otherwise push each other off
  forever. When the budget is spent, the old session stays.

A :class:`SessionTable` is for a server with several clients at once
(multi-client spec §2.3, §2.4). Each CN gets the tunnel address of its line
in the allowlist file and its own :class:`SessionSlot`, so the rules above
hold for each CN alone, and another CN is never refused.

Nothing here touches the wire.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from dsm.core.log import RepeatLog
from dsm.crypto.handshake import ClientRefusedError, VerifiedClient
from dsm.net._addresses import SERVER_TUN_IP, TUN_PREFIX_LEN, TunnelAssignment
from dsm.net.handshake_gate import TokenBucket

if TYPE_CHECKING:
    import tuncore
    from dsm.net.transport.tcp import TCPTransport
    from dsm.net.transport.udp import UDPTransport

log = logging.getLogger(__name__)

# Session takeovers per CN: 3 at once, then 1 a minute (owner decision
# 2026-10-09). A client that crashes more often than that waits for the old
# session's dead-peer timer, as it did before a session could be taken over.
REPLACE_BURST = 3.0
REPLACE_RATE = 1.0 / 60.0  # tokens per second

# Each session's view queue and TUN queue (multi-client spec, Numbers):
# today's one-client RECV_QUEUE_SIZE, so each session keeps the share one
# client has today.
SESSION_QUEUE_PACKETS = 256

# The pool (multi-client spec, Numbers): every host address of the tunnel
# network but the server's own, 10.8.0.2 to 10.8.0.254.
_SERVER = ipaddress.IPv4Address(SERVER_TUN_IP)
_NETWORK = ipaddress.IPv4Network(f"{SERVER_TUN_IP}/{TUN_PREFIX_LEN}", strict=False)
_POOL = tuple(address for address in _NETWORK.hosts() if address != _SERVER)


def _key_hash(noise_static: bytes) -> str:
    """The 16-hex key hash the server already logs when a client connects."""
    return hashlib.sha256(noise_static).hexdigest()[:16]


class SessionSlot:
    """One session's slot: who holds it, and who may take it over.

    A :class:`SessionTable` makes one per CN and keeps it for the run.
    Nothing here awaits, so a check and the mark it sets happen in one step
    on the event loop.
    """

    def __init__(self, *, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._holder: VerifiedClient | None = None
        self._admitted: tuple[object, VerifiedClient] | None = None
        # One budget per CN that ever took its session over. Only CNs on the
        # allowlist get that far, so the allowlist bounds this table.
        self._budgets: dict[str, TokenBucket] = {}
        self._other_client_log = RepeatLog(log, logging.INFO, clock=clock)
        self._too_often_log = RepeatLog(log, logging.WARNING, clock=clock)

    @property
    def holder(self) -> VerifiedClient | None:
        """The client of the live session (or of the next one), or None."""
        return self._holder

    @property
    def admitted(self) -> object | None:
        """The attempt that passed :meth:`admit` and has not ended, or None."""
        return None if self._admitted is None else self._admitted[0]

    def admit(
        self, attempt: object, client: VerifiedClient, *, session_live: bool
    ) -> None:
        """Let ``client`` have the last handshake frame, or refuse it.

        ``attempt`` marks the handshake; pass the same object to
        :meth:`confirm` or :meth:`release`. ``session_live`` is True for the
        accept that runs during a session. A takeover spends one token of the
        CN's budget here, after every check passed.

        Raises:
            ClientRefusedError: another attempt is finishing; or a session
                runs and its client is unknown, has another CN, or this CN
                took its session over too often lately.
        """
        if self._admitted is not None:
            raise ClientRefusedError("another handshake is finishing")
        if session_live:
            holder = self._holder
            if holder is None:
                # Cannot happen: a session starts only after confirm() set
                # the holder. Refuse rather than guess.
                raise ClientRefusedError("the live session's client is unknown")
            if client.cn != holder.cn:
                self._other_client_log.log(
                    "handshake refused: another client is connected (client_cn=%s)",
                    client.cn,
                )
                raise ClientRefusedError("another client holds the session")
            now = self._clock()
            budget = self._budgets.get(client.cn)
            if budget is None:
                budget = TokenBucket(REPLACE_RATE, REPLACE_BURST, now)
                self._budgets[client.cn] = budget
            if not budget.ready(now):
                self._too_often_log.log(
                    "client_cn=%s reconnected too often; keeping its current "
                    "session (two devices with one name?)",
                    client.cn,
                )
                raise ClientRefusedError("this client took its session over too often")
            budget.take()
        self._admitted = (attempt, client)

    def confirm(self, attempt: object) -> None:
        """``attempt`` won: its client holds the session from now on.

        Logs a takeover when another client held the session before, and a
        warning when the device key changed.

        Raises:
            RuntimeError: ``attempt`` did not pass :meth:`admit`.
        """
        if self._admitted is None or self._admitted[0] is not attempt:
            raise RuntimeError("confirm without a matching admit")
        _, client = self._admitted
        self._admitted = None
        old = self._holder
        self._holder = client
        if old is None:
            return
        log.info("client reconnected (client_cn=%s); ending its old session", client.cn)
        if old.noise_static != client.noise_static:
            log.warning(
                "client_cn=%s reconnected with a different device key "
                "(noise_static_sha256=%s, was %s); if this repeats, two devices "
                "share this name",
                client.cn,
                _key_hash(client.noise_static),
                _key_hash(old.noise_static),
            )

    def release(self, attempt: object) -> None:
        """``attempt`` ended without winning. Does nothing if it holds nothing."""
        if self._admitted is not None and self._admitted[0] is attempt:
            self._admitted = None

    def clear(self) -> None:
        """The session ended with no newer one for this client.

        An attempt still marked keeps its mark. With several clients the
        acceptor runs all the time, so this CN's next attempt may be past the
        check right now, and it must still be able to win (multi-client spec
        §2.4). It ends through :meth:`confirm` or :meth:`release` as usual.
        """
        self._holder = None


@dataclass(eq=False)
class ServerSession:
    """One live session of a server with several clients (spec §2.4).

    ``eq=False``: two sessions are never equal, and each hashes by identity,
    so the table can key its maps by session.
    """

    number: int
    client: VerifiedClient
    tunnel: TunnelAssignment
    session_keys: tuncore.SessionKeyManager = field(repr=False)
    # UDP: its _SessionUDPView, filled by the dispatcher; TCP: its connection.
    transport: UDPTransport | TCPTransport
    shutdown: asyncio.Event
    # Out of the repr: a queue's repr lists the client's packets in it.
    tun_queue: asyncio.Queue[bytes] = field(repr=False)
    # The handshake address: where the session starts sending, and its first
    # hint. Later hints live in the table.
    peer: tuple[str, int]
    tun_drops: int = 0


class SessionTable:
    """The server's sessions when it serves several clients at once (spec §2.4).

    Each CN gets the tunnel address of its allowlist line for the whole run,
    and its own :class:`SessionSlot`, made at its first :meth:`admit` and kept
    for the run, so its takeover allowance outlives its session. Nothing here
    awaits, so a check and the change it makes happen in one step on the
    event loop.
    """

    def __init__(
        self, cns: Sequence[str], *, clock: Callable[[], float] = time.monotonic
    ) -> None:
        """``cns``: the allowlist file's order (``CNAllowlist.order``).

        Raises:
            ValueError: an assignment fails its checks. The server then stops
                at start, before a takeover token could be spent on it.
        """
        self._clock = clock
        # Names past the pool's end get none: zip stops at the shorter.
        self._assignments = {
            cn: TunnelAssignment(
                client=address, server=_SERVER, prefix_len=TUN_PREFIX_LEN
            )
            for cn, address in zip(cns, _POOL, strict=False)
        }
        if len(cns) > len(_POOL):
            log.warning(
                "the allowlist has %d names; only the first %d get a tunnel address",
                len(cns),
                len(_POOL),
            )
        self._slots: dict[str, SessionSlot] = {}
        # Each attempt past admit, until confirm or release: its client.
        self._admitted: dict[object, VerifiedClient] = {}
        self._by_cn: dict[str, ServerSession] = {}
        self._by_tunnel: dict[bytes, ServerSession] = {}
        # The hints, both ways: an address belongs to at most one session.
        self._by_peer: dict[tuple[str, int], ServerSession] = {}
        self._hints: dict[ServerSession, tuple[str, int]] = {}
        self._ever_confirmed = False
        self._no_address_log = RepeatLog(log, logging.WARNING, clock=clock)

    def assignment_for(self, cn: str) -> TunnelAssignment | None:
        """The tunnel address of ``cn``, or None past the pool's end."""
        return self._assignments.get(cn)

    def addresses(self) -> dict[str, str]:
        """Tunnel address to CN, for every CN with an address."""
        return {str(t.client): cn for cn, t in self._assignments.items()}

    def admit(self, attempt: object, client: VerifiedClient) -> TunnelAssignment:
        """The handshake hook: let ``client`` have the last frame, and give it
        its tunnel address.

        ``attempt`` marks the handshake; pass the same object to
        :meth:`confirm` or :meth:`release`. A takeover spends one token of
        the CN's allowance here, after every check passed.

        Raises:
            ClientRefusedError: the CN has no tunnel address; another attempt
                of this CN is finishing; or this CN took its session over too
                often lately.
        """
        tunnel = self._assignments.get(client.cn)
        if tunnel is None:
            self._no_address_log.log(
                "client_cn=%s has no tunnel address (its allowlist line is past "
                "the first %d); refused",
                client.cn,
                len(_POOL),
            )
            raise ClientRefusedError("this client has no tunnel address")
        slot = self._slots.get(client.cn)
        if slot is None:
            slot = SessionSlot(clock=self._clock)
            self._slots[client.cn] = slot
        slot.admit(attempt, client, session_live=slot.holder is not None)
        self._admitted[attempt] = client
        return tunnel

    def is_admitted(self, attempt: object) -> bool:
        """Whether ``attempt`` passed :meth:`admit` and has not ended: its
        client may already have the last handshake frame."""
        return attempt in self._admitted

    def confirm(self, attempt: object) -> tuple[VerifiedClient, TunnelAssignment]:
        """``attempt`` finished: its client may have its session now.

        Logs step R's takeover line, and its warning on a new device key.

        Raises:
            RuntimeError: ``attempt`` did not pass :meth:`admit`.
        """
        client = self._admitted.pop(attempt, None)
        if client is None:
            raise RuntimeError("confirm without a matching admit")
        self._slots[client.cn].confirm(attempt)
        self._ever_confirmed = True
        return client, self._assignments[client.cn]

    def release(self, attempt: object) -> None:
        """``attempt`` ended without a session. Does nothing if it holds
        nothing, so also after :meth:`confirm`."""
        client = self._admitted.pop(attempt, None)
        if client is not None:
            self._slots[client.cn].release(attempt)

    @property
    def ever_confirmed(self) -> bool:
        """Whether any CN has connected in this run (spec §3.7, E1)."""
        return self._ever_confirmed

    def add(self, session: ServerSession) -> ServerSession | None:
        """Make ``session`` its CN's session, the owner of its tunnel address
        and the holder of its hint (its handshake address). Returns the CN's
        old session, or None. The caller ends the returned session (sets its
        ``shutdown``); ``add`` only reroutes."""
        cn = session.client.cn
        old = self._by_cn.get(cn)
        if old is not None:
            self._drop_hint(old)
        self._by_cn[cn] = session
        self._by_tunnel[session.tunnel.client.packed] = session
        self.note_peer(session, session.peer)
        return old

    def remove(self, session: ServerSession) -> bool:
        """Take ``session`` out where it is still the current one.

        True when it was its CN's current session: its tunnel address is free
        and the CN's slot is cleared, so the CN's next attempt is no takeover.
        False when a takeover replaced it.
        """
        self._drop_hint(session)
        cn = session.client.cn
        if self._by_cn.get(cn) is not session:
            return False
        del self._by_cn[cn]
        del self._by_tunnel[session.tunnel.client.packed]
        self._slots[cn].clear()
        return True

    def by_tunnel(self, address: bytes) -> ServerSession | None:
        """The session that owns ``address`` (4 raw bytes), or None."""
        return self._by_tunnel.get(address)

    def by_peer(self, addr: tuple[str, int]) -> ServerSession | None:
        """The session whose hint is ``addr``, or None."""
        return self._by_peer.get(addr)

    def note_peer(self, session: ServerSession, addr: tuple[str, int]) -> None:
        """Make ``addr`` the hint of ``session`` (its packets are checked
        against it first), taking it from any other session. Does nothing for
        a session that is no longer its CN's current one."""
        if self._by_cn.get(session.client.cn) is not session:
            return
        self._drop_hint(session)
        other = self._by_peer.get(addr)
        if other is not None:
            del self._hints[other]
        self._by_peer[addr] = session
        self._hints[session] = addr

    def abandon(self, cn: str) -> None:
        """A client of ``cn`` passed :meth:`confirm` but got no session (a bug
        in starting it, spec §2.2). Clears the CN's slot, so its next attempt
        is not a takeover of a session that does not exist. A failed takeover
        leaves the old session running, and that session stays a takeover
        target. The slot then names the client that got no session, so step
        R's lines at the CN's next takeover compare against that client.
        A CN with no slot is a no-op: ``on_client`` calls this from an error
        handler and relies on it never raising."""
        slot = self._slots.get(cn)
        if slot is not None and cn not in self._by_cn:
            slot.clear()

    def sessions(self) -> list[ServerSession]:
        """Every live session, one per CN."""
        return list(self._by_cn.values())

    @property
    def any_live(self) -> bool:
        """Whether a session runs."""
        return bool(self._by_cn)

    def _drop_hint(self, session: ServerSession) -> None:
        addr = self._hints.pop(session, None)
        if addr is not None:
            del self._by_peer[addr]
