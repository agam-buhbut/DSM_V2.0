"""DSM VPN client mode."""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import socket
import time
from collections.abc import Callable, Coroutine
from contextlib import AsyncExitStack
from enum import Enum, auto
from pathlib import Path
from types import TracebackType
from typing import Any, TypeVar, cast

from cryptography.x509.oid import ExtendedKeyUsageOID

from dsm.core import netaudit
from dsm.core.atomic_io import atomic_write
from dsm.core.config import Config
from dsm.core.fsm import SessionFSM, State
from dsm.core.log import RepeatLog
from dsm.core.path_security import check_user_file_permissions
from dsm.core.preflight import check_clock_sync
from dsm.core.protocol import ReassemblyBuffer
from dsm.crypto.attest_store import AttestStore
from dsm.crypto.auth_loader import (
    AuthMaterialsError,
    load_cert_materials,
    verify_cert_matches_identity,
)
from dsm.crypto.keystore import KeyStore
from dsm.net._addresses import SERVER_TUN_IP
from dsm.net.nftables import (
    NFTablesManager,
    PreHandshakeKillSwitch,
    TcpTimestampsDisabler,
)
from dsm.net.resolv_conf import ResolvConfError, ResolvConfManager
from dsm.net.transport.tcp import TCPTransport
from dsm.net.transport.udp import UDPTransport
from dsm.net.tunnel import SrcValidMarkEnabler, TunDevice
from dsm.session import (
    DataPathContext,
    LivenessState,
    RekeyState,
    SequenceCounter,
    auto_mtu_loop,
    make_auto_cap,
    make_send_fn,
    setup_signal_handlers,
)
from dsm.traffic.scheduler import SendScheduler
from dsm.traffic.shaper import TrafficShaper, make_chaff_packet

log = logging.getLogger(__name__)

_T = TypeVar("_T")

# Waits between tries while there is no tunnel: 1 s, doubling up to 30 s,
# with no limit on tries. The pre-handshake kill switch stays up meanwhile.
RETRY_FIRST_S = 1.0
RETRY_MAX_S = 30.0
# After this many failed tries in a row, a client that looked up the
# server's name at start says the address may have changed.
HOSTNAME_HINT_AFTER = 5
# The outage notice comes once per outage, and at most once in this many
# seconds, so a server that takes the session and drops it at once cannot
# flood the log.
OUTAGE_NOTICE_EVERY_S = 60.0

_OUTAGE_NOTICE = (
    "no tunnel: all traffic is blocked until DSM connects again; it keeps "
    "trying. To get internet back without the VPN, stop DSM: Ctrl-C, or "
    "`sudo systemctl stop dsm-client`. If DSM is not running, run "
    "`sudo dsm cleanup`."
)
_HOSTNAME_HINT = (
    "server IP may have changed since DSM looked up its name at start; DSM "
    "does not look it up again while the tunnel is down. If this goes on, "
    "stop and start DSM: a restart keeps the kill switch up, so the name "
    "cannot be looked up and the old address is used again."
)
_KEPT_AFTER_ERROR = (
    "DSM stopped on an error and left the kill switch up, so all traffic "
    "stays blocked. Start DSM again, or run `sudo dsm cleanup` to get "
    "internet back without the VPN."
)
_KEPT_ON_STOP = (
    "stopped; the start-up kill switch stays up (--stop-keeps-block). "
    "dsm-client.service takes it down only for `systemctl stop` and keeps "
    "it otherwise. If it is still up when you want internet back, run "
    "`sudo dsm cleanup`."
)

# The address a server name had at the last run whose handshake worked. A
# start whose lookup fails (a kill switch left up blocks it) uses it instead
# of exiting. In /run, so a reboot clears it; `dsm cleanup` leaves it alone.
_SERVER_ENDPOINT_FILE = Path("/run/dsm/server-endpoint.json")
_USING_SAVED_ADDRESS = (
    "could not look up the server name; using the last address it had"
)


class _End(Enum):
    """How one try ended."""

    SETUP_ERROR = auto()  # a host problem at the first try: exit 1
    FAILED = auto()  # no session: connect or handshake failed, or a stop
    ENDED = auto()  # a session was up and has ended


async def _resolve_server_endpoint(server_ip: str, server_port: int) -> str:
    """Resolve the configured server endpoint to a single literal IPv4.

    An IPv4 literal is returned unchanged with no network I/O. A hostname gets
    one A-record lookup: the trailing dot stops ``resolv.conf`` search-domain
    expansion (so only the hostname itself leaks), and the timeout keeps a
    slow resolver from stalling startup or the SIGTERM handler. Raises
    ``OSError`` if the name does not resolve in time.
    """
    try:
        ipaddress.IPv4Address(server_ip)
        return server_ip
    except ipaddress.AddressValueError:
        pass
    loop = asyncio.get_running_loop()
    query = server_ip if server_ip.endswith(".") else server_ip + "."
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(
                query, server_port, family=socket.AF_INET, type=socket.SOCK_DGRAM
            ),
            timeout=10.0,
        )
    except TimeoutError as e:
        raise OSError(f"timed out resolving server hostname {server_ip!r}") from e
    if not infos:
        raise OSError(f"could not resolve server hostname {server_ip!r}")
    # An AF_INET sockaddr is (host, port); the host is already a str.
    return str(infos[0][4][0])


def _save_server_endpoint(name: str, ip: str) -> None:
    """Keep ``ip`` as the last address found for the server name ``name``.

    Written like the other /run/dsm state files (folder 0700, file 0600,
    temp file then rename). A failure logs one WARNING; DSM goes on.
    """
    try:
        folder = _SERVER_ENDPOINT_FILE.parent
        folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(folder, 0o700)
        atomic_write(
            _SERVER_ENDPOINT_FILE,
            json.dumps({"name": name, "ip": ip}).encode(),
            mode=0o600,
        )
    except OSError as e:
        log.warning("could not save %s: %s", _SERVER_ENDPOINT_FILE, e)


def _saved_server_ip(name: str) -> str | None:
    """The address saved for the server name ``name``, or None.

    A file that is missing, a symlink, not owned by the user DSM runs as
    (root), open to group or world, not JSON, for another name, or without
    an IPv4 address counts as no file.
    """
    try:
        check_user_file_permissions(_SERVER_ENDPOINT_FILE)
        fd = os.open(_SERVER_ENDPOINT_FILE, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as f:
            saved: object = json.loads(f.read())
    except (OSError, ValueError):
        # Missing, a symlink, foreign, open to others, unreadable or not
        # JSON: no address we can trust. The caller logs the lookup error.
        return None
    if not isinstance(saved, dict):
        return None
    entry = cast(dict[str, object], saved)
    ip = entry.get("ip")
    if entry.get("name") != name or not isinstance(ip, str):
        return None
    try:
        ipaddress.IPv4Address(ip)
    except ipaddress.AddressValueError:
        return None
    return ip


def _emit_handshake_failure(err: Exception) -> None:
    """Emit the failed-handshake audit event WITHOUT the exception
    message.

    The operator-facing ERROR log already carries the full detail (a
    client owns its server and needs to debug its cert), but the netaudit
    stream (a separate, machine-readable sink that may be shipped or
    retained differently) is kept minimal and symmetric with the
    server-side emit — only the exception class, never str(err)."""
    netaudit.emit(
        "handshake_end",
        role="client",
        outcome="failed",
        error=type(err).__name__,
    )


class _Reconnect:
    """The waits between tries, and the log lines about an outage.

    An outage starts when a try gets no session or a session ends, and ends
    when a session is up again.
    """

    def __init__(
        self,
        *,
        looked_up_name: bool,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._looked_up_name = looked_up_name
        self._notice = RepeatLog(
            log, logging.WARNING, interval_s=OUTAGE_NOTICE_EVERY_S, clock=clock
        )
        self._waits = 0
        self._failures = 0
        self._noticed = False
        self._hinted = False

    def connected(self) -> None:
        """A session is up: the outage is over."""
        self._waits = 0
        self._failures = 0
        self._noticed = False
        self._hinted = False

    def failed(self) -> None:
        """A try got no session."""
        self._failures += 1
        if (
            self._looked_up_name
            and not self._hinted
            and self._failures >= HOSTNAME_HINT_AFTER
        ):
            log.warning(_HOSTNAME_HINT)
            self._hinted = True

    def next_wait(self) -> float:
        """The wait before the next try. Logs the outage notice once."""
        if not self._noticed:
            self._notice.log(_OUTAGE_NOTICE)
            self._noticed = True
        delay = min(RETRY_FIRST_S * 2.0 ** min(self._waits, 5), RETRY_MAX_S)
        self._waits += 1
        return delay


async def _wait_or_stop(shutdown: asyncio.Event, delay: float) -> bool:
    """Wait ``delay`` seconds before the next try.

    Returns True as soon as the user stops DSM, False when the wait is over.
    """
    try:
        await asyncio.wait_for(shutdown.wait(), timeout=delay)
    except TimeoutError:
        return False
    return True


async def _unless_stopped(
    shutdown: asyncio.Event, work: Coroutine[Any, Any, _T]
) -> _T | None:
    """Run ``work``, but cancel it as soon as ``shutdown`` is set.

    Returns what ``work`` returns, or None when the stop came first; errors
    from ``work`` go up. A connect or a handshake can take tens of seconds,
    and a stop must not wait for them: under systemd a slow stop ends in
    SIGKILL, which leaves the kill switch up.
    """
    task = asyncio.ensure_future(work)
    stop = asyncio.ensure_future(shutdown.wait())
    both: set[asyncio.Future[Any]] = {task, stop}
    try:
        await asyncio.wait(both, return_when=asyncio.FIRST_COMPLETED)
    finally:
        task.cancel()
        stop.cancel()
        await asyncio.gather(task, stop, return_exceptions=True)
    if task.cancelled():
        return None
    return task.result()


async def _set_when(src: asyncio.Event, dst: asyncio.Event) -> None:
    """Set ``dst`` once ``src`` is set."""
    await src.wait()
    dst.set()


async def _cancel_and_wait(task: asyncio.Task[None]) -> None:
    """Cancel ``task`` and wait for it, so no task is left pending."""
    task.cancel()
    # gather keeps our own cancel of ``task`` quiet, but a cancel of the
    # caller while it waits here still goes through (a bare except would
    # swallow both).
    await asyncio.gather(task, return_exceptions=True)


async def run_client(
    config: Config,
    passphrase_fd: int | None = None,
    passphrase_env_file: str | None = None,
    *,
    stop_keeps_block: bool = False,
) -> int:
    """Run DSM in client mode until the user stops it.

    The kill switch stays up from before the passphrase read until the user
    stops DSM (a signal: Ctrl-C, ``systemctl stop``). Each session swaps the
    pre-handshake kill switch for the full one and, when it ends, swaps it
    back, each time in one nft commit. A session that ends any other way
    (dead peer, SESSION_CLOSE, a TCP reset, a rekey that gives up) and a
    connect or handshake that fails keep the block: the client tries again
    with backoff, with the address it found at start. A server name is
    looked up once, at start; its address is saved once a handshake with it
    works, and a later start whose lookup fails uses the address saved for
    the same name.

    Every host change of a session is registered on that session's
    ``AsyncExitStack`` the moment it succeeds, so any failure unwinds them in
    reverse order and never leaves the host half configured.

    With ``stop_keeps_block`` (``--stop-keeps-block``, which
    dsm-client.service passes) a stop leaves the pre-handshake kill switch
    up: the unit's ExecStopPost takes it down only for ``systemctl stop``
    and keeps it otherwise (a restart, a signal sent straight to DSM); the
    next start replaces it.

    Returns:
        0 when the user stops DSM, 1 on a setup error a retry cannot fix
        (keys, cert, or a UDP port in use or a read-only resolv.conf at the
        first try). Both take the kill switch down, except a stop with
        ``stop_keeps_block``. An unexpected error goes up with the kill
        switch still up (fail closed); the next start replaces it.
    """
    import tuncore
    from dsm.core.hardening import harden_and_gate

    if not harden_and_gate(config):
        return 1

    # Cert auth materials must load BEFORE we touch any host state, so a
    # missing cert file aborts cleanly with no rules / no TUN created.
    try:
        materials = load_cert_materials(config)
    except AuthMaterialsError as e:
        log.error("cert auth materials missing or invalid: %s", e)
        return 1

    async with AsyncExitStack() as stack:
        # Create the shutdown event and install signal handlers BEFORE the
        # pre-handshake kill switch, so a SIGTERM during startup unwinds the
        # stack instead of killing the process with the kill switch up. Only
        # the signal handlers set `shutdown`: it means the user stopped DSM,
        # the one case that takes the kill switch down.
        shutdown = asyncio.Event()
        setup_signal_handlers(shutdown)

        # The kill-switch rules need a literal address, so a hostname is
        # resolved and pinned here, before the kill switch goes up. This one
        # cleartext lookup is accepted; see config._validate_server_ip. The
        # name is not looked up again in this run, not even while the client
        # reconnects: no lookup goes out through the kill switch.
        # save_address: the address came from a working lookup of a name; it
        # is saved once a handshake with it works (F3).
        save_address = False
        try:
            server_ip = await _resolve_server_endpoint(
                config.server_ip, config.server_port
            )
        except OSError as e:
            saved_ip = _saved_server_ip(config.server_ip)
            if saved_ip is None:
                log.error(
                    "could not resolve server endpoint %r: %s — refusing to "
                    "start (fail-closed)",
                    config.server_ip,
                    e,
                )
                log.error(
                    "if an earlier DSM run left its kill switch up, it blocks "
                    "this lookup: run `sudo dsm cleanup`, then start DSM "
                    "again, or set server_ip to the server's IP address"
                )
                return 1
            # A kill switch left up (by a crash, or kept for a restart)
            # blocks the lookup: use the address saved for this name after
            # an earlier good handshake. The log line names no address.
            log.warning(_USING_SAVED_ADDRESS)
            server_ip = saved_ip
        else:
            if server_ip != config.server_ip:
                log.info(
                    "resolved server hostname %s -> %s", config.server_ip, server_ip
                )
                # A working lookup always wins. Its address replaces the
                # saved one only once a handshake with it works.
                save_address = True

        # Pre-handshake kill switch: applied BEFORE the (possibly interactive)
        # passphrase read + key unlock below, so the host is fail-closed for
        # the ENTIRE startup window. Allows only loopback, DHCP renewal and
        # the configured server endpoint. It replaces, in the same nft
        # commit, any client kill-switch table a crashed run left, so a
        # restart has no gap. Each session upgrades it to the full kill
        # switch (which also covers the TUN and DNS leaks) and swaps it back
        # when the session ends.
        pre_killswitch = PreHandshakeKillSwitch(server_ip, config.server_port)
        try:
            pre_killswitch.apply()
        except OSError as e:
            # Fail closed: never proceed to connect without the egress lock.
            # OSError covers a missing/unresolvable nft (FileNotFoundError).
            log.error(
                "pre-handshake kill switch could not be installed: %s — "
                "refusing to start (fail-closed). Ensure nftables is present "
                "and the daemon has CAP_NET_ADMIN.",
                e,
            )
            return 1

        def _release_kill_switch(
            exc_type: type[BaseException] | None,
            _exc: BaseException | None,
            _tb: TracebackType | None,
        ) -> bool:
            # Only a stop the user asked for, or a setup error a retry cannot
            # fix, gets here without an error: take the kill switch down. An
            # error leaves it up (fail closed); the next start replaces it.
            # With --stop-keeps-block a stop leaves it up too, and the unit's
            # ExecStopPost decides: down only for `systemctl stop`. A setup
            # error that meets a stop also keeps it: the safe side.
            if exc_type is not None:
                log.error(_KEPT_AFTER_ERROR)
            elif stop_keeps_block and shutdown.is_set():
                log.info(_KEPT_ON_STOP)
            else:
                pre_killswitch.remove()
            return False

        stack.push(_release_kill_switch)

        # Read the passphrase once and unlock both stores, now BEHIND the kill
        # switch. Identity (X25519 Noise static) and attest key (ECDSA P-256)
        # live behind the same passphrase by design — both are provisioned
        # together by `dsm enroll`. On failure the AsyncExitStack unwinds,
        # removing the kill switch and restoring the host.
        from dsm.crypto._stores import load_daemon_stores

        keystore = KeyStore(config.key_file)
        attest_store = AttestStore(config.attest_key_file)
        if not load_daemon_stores(
            keystore,
            attest_store,
            passphrase_fd=passphrase_fd,
            passphrase_env_file=passphrase_env_file,
        ):
            return 1

        # Register the unloads now that the stores are loaded. They unwind
        # before the kill switch is removed; the identity stays resident for
        # the whole run, across reconnects.
        stack.callback(keystore.unload)
        stack.callback(attest_store.unload)

        # With both stores unlocked, confirm the loaded cert was issued for
        # THIS device's keys. Catches the cert_file substitution failure mode
        # at startup with a clear error, rather than at the server's
        # AttestBindingMismatchError much later in the handshake. On failure
        # the stack unwinds (unloading the stores, removing the kill switch).
        try:
            verify_cert_matches_identity(materials.cert_der, keystore, attest_store)
        except AuthMaterialsError as e:
            log.error("cert/identity consistency check failed: %s", e)
            return 1

        # The handshake rejects attestation timestamps more than ~5 minutes
        # off, so an unsynchronized clock fails with a confusing peer error.
        _clock_warn = check_clock_sync()
        if _clock_warn:
            log.warning(_clock_warn)

        # Imported here, not at the top, so tests can replace them.
        from dsm.crypto.handshake import (
            CertAuthError,
            CertRevokedError,
            CNMismatchError,
            HandshakeError,
            client_handshake,
        )
        from dsm.session import run_data_loops

        assert (
            config.expected_server_cn is not None
        ), "client mode requires expected_server_cn (validated in Config)"
        expected_server_cn: str = config.expected_server_cn
        server_addr = (server_ip, config.server_port)
        reconnect = _Reconnect(looked_up_name=server_ip != config.server_ip)

        async def _connect_and_run(first_try: bool) -> _End:
            """One try: connect, handshake, and run a session until it ends.

            At the first try, a UDP port in use or a read-only resolv.conf is
            a setup error: DSM exits and removes the kill switch, as the user
            is there and nothing was protected yet. On later tries every
            failure keeps the block, so nothing on the host or the network
            can turn the kill switch off.
            """
            nonlocal save_address
            fsm = SessionFSM()
            async with AsyncExitStack() as attempt:
                transport: UDPTransport | TCPTransport
                if config.transport == "udp":
                    transport = UDPTransport()
                    try:
                        await transport.bind(
                            local_port=config.listen_port,
                            pmtu_discover=config.pmtu_discover,
                        )
                    except OSError as e:
                        reason = os.strerror(e.errno) if e.errno else str(e)
                        if first_try:
                            # A fixed listen_port that is already taken:
                            # one line and exit, like the server.
                            log.error(
                                "cannot listen on UDP port %d: %s; exiting",
                                config.listen_port,
                                reason,
                            )
                            return _End.SETUP_ERROR
                        log.error(
                            "cannot listen on UDP port %d: %s; trying again",
                            config.listen_port,
                            reason,
                        )
                        return _End.FAILED
                    attempt.push_async_callback(transport.aclose)
                else:
                    transport = TCPTransport()
                    attempt.push_async_callback(transport.aclose)
                    try:
                        await _unless_stopped(
                            shutdown,
                            transport.connect(server_ip, config.server_port),
                        )
                    except OSError as e:
                        # Not str(e): asyncio's connect error holds the address.
                        reason = os.strerror(e.errno) if e.errno else type(e).__name__
                        log.error("cannot connect to the server: %s", reason)
                        return _End.FAILED
                    if shutdown.is_set():
                        return _End.FAILED

                fsm.transition(State.CONNECTING)
                fsm.transition(State.HANDSHAKING)

                try:
                    handshake = await _unless_stopped(
                        shutdown,
                        client_handshake(
                            transport,
                            keystore.identity,
                            server_addr,
                            attest_key=attest_store.attest_key,
                            cert_der=materials.cert_der,
                            ca_root=materials.ca_root,
                            expected_server_cn=expected_server_cn,
                            crl=materials.crl,
                            required_server_eku=ExtendedKeyUsageOID.SERVER_AUTH,
                            rotation_packets=config.rotation_packets,
                            rotation_seconds=config.rotation_seconds,
                        ),
                    )
                except (
                    CNMismatchError,
                    CertRevokedError,
                    CertAuthError,
                    HandshakeError,
                ) as e:
                    # Most-specific first: CNMismatchError and
                    # CertRevokedError are subclasses of CertAuthError, which
                    # is a subclass of HandshakeError. All of them come from
                    # the network (someone on the path can send a bad or
                    # revoked cert), so they keep the block and DSM retries.
                    if isinstance(e, CNMismatchError):
                        prefix = "server CN check failed"
                    elif isinstance(e, CertRevokedError):
                        prefix = "server cert revoked"
                    elif isinstance(e, CertAuthError):
                        prefix = "server cert auth failed"
                    else:
                        prefix = "handshake failed"
                    log.error("%s: %s", prefix, e)
                    _emit_handshake_failure(e)
                    fsm.transition(State.TEARDOWN)
                    return _End.FAILED
                except OSError as e:
                    reason = os.strerror(e.errno) if e.errno else type(e).__name__
                    log.error("handshake failed: %s", reason)
                    _emit_handshake_failure(e)
                    fsm.transition(State.TEARDOWN)
                    return _End.FAILED
                if handshake is None:
                    return _End.FAILED  # the user stopped DSM first
                session_keys, _handshake_hash, server_static_pub = handshake

                fsm.transition(State.ESTABLISHED)

                if save_address:
                    # The run's first good handshake proves the looked-up
                    # address: keep it for a start whose lookup fails (F3).
                    # A run with no good handshake leaves the old file alone.
                    _save_server_endpoint(config.server_ip, server_ip)
                    save_address = False

                # Host-mutating resources.
                #
                # Apply order is fixed by dependency:
                #   tcp_ts → src_valid_mark → tun → nft → resolv
                # (nft references tun's name; resolv goes last so the kill
                # switch is already up when the new resolver becomes visible.)
                #
                # Unwind order is anonymity-critical: the full kill switch
                # MUST stay applied while the TUN is being torn down. Tun
                # teardown briefly removes the routing rule that forces
                # traffic through the tunnel; during that window unmarked
                # traffic can fall to the main routing table and hit the WAN
                # interface. The kill switch is never removed here: the
                # session ends by swapping it back to the pre-handshake table
                # in one nft commit, after the TUN is closed.
                #
                # Desired unwind: resolv → tun → swap back → src_valid_mark
                #                 → tcp_ts
                # Reverse of that (= AsyncExitStack registration order):
                #         tcp_ts, src_valid_mark, swap back, tun, resolv
                # which is NOT the apply order. An explicit try/except keeps
                # partial-failure safety: if any apply between tun and resolv
                # fails, we undo by hand what was already applied.

                tcp_ts = TcpTimestampsDisabler()
                tcp_ts.apply()
                attempt.callback(tcp_ts.remove)

                # Lets strict rp_filter hosts accept the server's replies once
                # the not-fwmark ip rule is in (see SrcValidMarkEnabler). On
                # before tun.configure adds that rule; registered here so it
                # is restored only after tun.close has removed the rule again.
                src_valid_mark = SrcValidMarkEnabler()
                src_valid_mark.apply()
                attempt.callback(src_valid_mark.remove)

                tun = TunDevice(config.tun_name)
                tun.open()
                try:
                    tun.configure(mtu=config.mtu)
                    nft = NFTablesManager(
                        server_ip, config.server_port, config.tun_name
                    )
                    nft.apply()
                    try:
                        resolv = ResolvConfManager(nameserver=SERVER_TUN_IP)
                        resolv.apply()
                    except ResolvConfError:
                        if not first_try:
                            # Keep the block: back to the pre-handshake table
                            # in one commit. If that fails, its error goes up
                            # and DSM stops with the full kill switch up.
                            pre_killswitch.apply()
                            raise
                        # First try: DSM exits and removes every table.
                        try:
                            nft.remove()
                        # cleanup path: any failure here must not mask the original
                        except Exception:  # noqa: BLE001
                            log.warning("nft.remove during failed apply also failed")
                        raise
                except Exception as e:
                    # tun.configure, nft.apply or resolv.apply failed. Close
                    # the TUN by hand: its cleanup is not registered yet. Any
                    # error but ResolvConfError goes up with the kill switch
                    # still up.
                    try:
                        tun.close()
                    # cleanup path: any failure here must not mask the original
                    except Exception:  # noqa: BLE001
                        log.warning("tun.close during failed apply also failed")
                    if isinstance(e, ResolvConfError):
                        # A host problem, not a bug: one line, no traceback.
                        if first_try:
                            log.error("%s; exiting", e)
                            return _End.SETUP_ERROR
                        log.error("%s; trying again", e)
                        return _End.FAILED
                    raise

                # All three are up. Register in REVERSE of the desired unwind
                # (AsyncExitStack pops LIFO): resolv.remove first, then
                # tun.close under the full kill switch, then the swap back to
                # the pre-handshake table.
                attempt.callback(pre_killswitch.apply)
                attempt.callback(tun.close)
                attempt.callback(resolv.remove)

                log.info("tunnel established")
                reconnect.connected()

                # After the handshake has exchanged several full-size
                # datagrams, the kernel may have learned the path MTU via
                # ICMP. Log it once so the operator can tell whether the
                # configured tun MTU is a good fit. When `auto_mtu` is on, the
                # adapter loop below also acts on it; the warning still shows
                # when `auto_mtu` is off so a misconfigured static MTU is
                # visible at startup.
                if isinstance(transport, UDPTransport):
                    path_mtu = transport.get_path_mtu()
                    if path_mtu is not None:
                        # See dsm.session.WIRE_OVERHEAD for the breakdown.
                        from dsm.session import WIRE_OVERHEAD

                        usable = path_mtu - WIRE_OVERHEAD
                        log.info(
                            "kernel path MTU = %d (usable inner %d)",
                            path_mtu,
                            usable,
                        )
                        if usable < config.mtu and not config.auto_mtu:
                            log.warning(
                                "configured tun mtu=%d exceeds usable inner %d "
                                "(path MTU %d); enable `auto_mtu` or lower "
                                "`mtu` in config to avoid fragmentation",
                                config.mtu,
                                usable,
                                path_mtu,
                            )

                seq = SequenceCounter()
                replay = tuncore.ReplayWindow()
                rekey = RekeyState()
                liveness = LivenessState()
                reassembly = ReassemblyBuffer()

                # The session's own end event. A stop also ends it (the task
                # below copies `shutdown` into it); a session that ends any
                # other way leaves `shutdown` unset, so the loop reconnects.
                session_end = asyncio.Event()
                attempt.push_async_callback(
                    _cancel_and_wait,
                    asyncio.ensure_future(_set_when(shutdown, session_end)),
                )

                send_packet = make_send_fn(
                    session_keys,
                    transport,
                    lambda: server_addr,
                    seq,
                    liveness=liveness,
                    shutdown=session_end,
                )

                # Build the shaper here, right before the send loop starts, as
                # the server does. Its slots start when it is built: built
                # before the handshake, the first poll would find every slot
                # of the setup time due and send them all back to back.
                shaper = TrafficShaper.from_config(config)
                # Slow-link auto cap: count what arrives, report it to the
                # server, and cap our own top tier on sustained loss. Wired
                # before the scheduler starts so the tier listener sees every
                # tier change; the server does the same. (None, None) in TCP
                # mode or when turned off.
                link_stats, autocap = make_auto_cap(config, transport, shaper, seq)

                # Shaper-driven: the tier shaper decides when packets leave
                # (real first, chaff in the other slots), so the wire rate
                # follows the tier, not the real traffic. No should_chaff_fn:
                # the client always knows its destination, so chaff may fill
                # every free slot.
                scheduler = SendScheduler(
                    send_fn=send_packet,
                    chaff_fn=lambda: make_chaff_packet(
                        shaper, session_keys.epoch & 0x0F
                    ),
                    shaper=shaper,
                )
                await scheduler.start()
                attempt.push_async_callback(scheduler.stop)

                ctx = DataPathContext(
                    tun=tun,
                    session_keys=session_keys,
                    fsm=fsm,
                    shaper=shaper,
                    send_fn=send_packet,
                    scheduler=scheduler,
                    rekey=rekey,
                    liveness=liveness,
                    shutdown=session_end,
                    reassembly=reassembly,
                    # Pass the UDPTransport so post-rekey hook can rebind to a
                    # fresh ephemeral src port; None on TCP.
                    udp_transport=(
                        transport if isinstance(transport, UDPTransport) else None
                    ),
                    # Static pubs for mutual-init tie-break.
                    local_static_pub=bytes(keystore.identity.public_key),
                    remote_static_pub=server_static_pub,
                    link_stats=link_stats,
                    autocap=autocap,
                )

                # The AsyncExitStack stays in this module; ``run_data_loops``
                # only owns the loops + the SESSION_CLOSE / FSM teardown.
                await run_data_loops(
                    ctx,
                    transport,
                    session_keys,
                    replay,
                    fsm,
                    extra_loops=(auto_mtu_loop(ctx, transport, config),),
                    udp_addr_filter=lambda addr: addr == server_addr,
                    shutdown_log="shutting down",
                )
            return _End.ENDED

        # Connect, run the session, and connect again when it ends, until the
        # user stops DSM. Between tries only the pre-handshake table is up.
        first = True
        while not shutdown.is_set():
            end = await _connect_and_run(first)
            if end is _End.SETUP_ERROR:
                return 1
            if shutdown.is_set():
                break
            first = False
            if end is _End.FAILED:
                reconnect.failed()
            if await _wait_or_stop(shutdown, reconnect.next_wait()):
                break

    return 0
