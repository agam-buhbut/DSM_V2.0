"""DSM VPN server mode."""

from __future__ import annotations

import asyncio
import ipaddress
import itertools
import logging
import os
from collections.abc import Awaitable, Callable
from contextlib import AsyncExitStack
from dataclasses import dataclass
from pathlib import Path

from dsm.core.config import Config
from dsm.core.fsm import ProtocolError, SessionFSM, State
from dsm.core.preflight import check_clock_sync
from dsm.core.protocol import WIRE_VERSION, PacketType, ReassemblyBuffer
from dsm.crypto.attest_store import AttestStore
from dsm.crypto.auth_loader import (
    AuthMaterialsError,
    load_cert_materials,
    verify_cert_matches_identity,
)
from dsm.crypto.cert_allowlist import CNAllowlist, CNAllowlistError
from dsm.crypto.keystore import KeyStore
from dsm.net._addresses import SERVER_TUN_IP, TUN_PREFIX_LEN
from dsm.net.dns import DNSResolver
from dsm.net.dns_blocklist import DnsBlocklist
from dsm.net.dns_proxy import DNSProxyPortInUseError, LocalDNSProxy
from dsm.net.forwarding import IPForwardingManager, MasqueradeManager
from dsm.net.handshake_acceptor import (
    _slot_rule_ok,  # pyright: ignore[reportPrivateUsage]
)

# isort: split
# Its own statement: isort and ruff disagree on an import whose name carries
# a pyright pragma, and isort would merge this one into the one above.
from dsm.net.handshake_acceptor import AcceptedClient, ClientAcceptor
from dsm.net.handshake_gate import (
    GateKeyError,
    HandshakeGate,
    SourceLimiter,
    server_gate_keys,
)
from dsm.net.nftables import ServerRateLimitManager, TcpTimestampsDisabler
from dsm.net.session_router import ClientTun, TunRouter, UDPDispatcher

# isort: split
# Its own statement, for the same reason as _slot_rule_ok's.
from dsm.net.session_router import (
    _SessionUDPView,  # pyright: ignore[reportPrivateUsage]
)

# isort: split
from dsm.net.session_slot import SESSION_QUEUE_PACKETS, ServerSession, SessionTable
from dsm.net.transport.tcp import TCPListener, TCPTransport
from dsm.net.transport.udp import UDPTransport
from dsm.net.tunnel import TunDevice
from dsm.session import (
    DataPathContext,
    LivenessState,
    PathValidationState,
    RekeyState,
    SequenceCounter,
    make_addr_send_fn,
    make_auto_cap,
    make_send_fn,
    setup_signal_handlers,
)
from dsm.traffic.scheduler import SendScheduler
from dsm.traffic.shaper import TrafficShaper, make_chaff_packet

# Backoff after the acceptor crashes (a bug; see _run_acceptor), so a crash
# that repeats cannot spin. Failed handshakes do not back off: the acceptor
# drops and rate-limits them without waiting.
_HANDSHAKE_RETRY_BACKOFF_BASE = 0.5  # seconds
_HANDSHAKE_RETRY_BACKOFF_MAX = 5.0  # seconds
_HANDSHAKE_RETRY_BACKOFF_JITTER = 0.5  # ±this fraction of base

log = logging.getLogger(__name__)

# The server socket's receive queue (multi-client spec §2.6): every client's
# packets wait in it, so 16 sessions' worth of a client's RECV_QUEUE_SIZE.
# With 10 clients at the top tier it holds about half a second of all
# inbound; memory is used only while packets wait (about 6 MB at most).
SERVER_RECV_QUEUE_PACKETS = 4096

# The server's tunnel address and the clients' network.
_TUNNEL = ipaddress.IPv4Interface(f"{SERVER_TUN_IP}/{TUN_PREFIX_LEN}")


class ListenError(Exception):
    """The TCP listening socket could not be opened (e.g. the port is in use)."""


async def _backoff_or_shutdown(
    consecutive_failures: int, process_shutdown: asyncio.Event
) -> bool:
    """Sleep the jittered backoff after an acceptor crash, or return
    early on shutdown.

    Failed handshakes do not come here: they end only their own attempt.

    Returns:
        ``True`` if ``process_shutdown`` was set during the wait (the caller
        stops), ``False`` if the backoff elapsed normally.
    """
    # Doubles per failure up to _HANDSHAKE_RETRY_BACKOFF_MAX, with ±50%
    # jitter so an accept error that repeats does not retry on a fixed beat
    # an attacker can synchronize to.
    base = min(
        _HANDSHAKE_RETRY_BACKOFF_BASE * (2 ** min(consecutive_failures - 1, 4)),
        _HANDSHAKE_RETRY_BACKOFF_MAX,
    )
    # Draw the jitter from the CSPRNG-backed helper in dsm.core.rand, then
    # clamp. Imported lazily to avoid a top-level dependency on
    # dsm.core.rand from server.py.
    from dsm.core.rand import csprng_float

    jitter = (csprng_float() - 0.5) * _HANDSHAKE_RETRY_BACKOFF_JITTER * base
    delay = max(0.0, base + jitter)
    try:
        await asyncio.wait_for(process_shutdown.wait(), timeout=delay)
        return True
    except TimeoutError:
        return False


async def _open_tcp_listener(config: Config) -> TCPListener:
    """Open the run's one TCP listener on ``listen_port`` (TCP mode only).

    Raises:
        ListenError: the port cannot be opened (for example, it is in use).
    """
    listener = TCPListener()
    try:
        await listener.start(port=config.listen_port)
    except OSError as e:
        listener.close()
        reason = os.strerror(e.errno) if e.errno else str(e)
        raise ListenError(
            f"cannot listen on TCP port {config.listen_port}: {reason}"
        ) from e
    return listener


@dataclass(frozen=True)
class _Host:
    """The host state sessions use: the shared TUN (for the router and each
    session's ClientTun) and the DNS proxy (for ``forget``)."""

    tun: TunDevice
    dns_proxy: LocalDNSProxy


async def _set_up_host(
    config: Config,
    stack: AsyncExitStack,
    blocklist: DnsBlocklist | None,
    table: SessionTable,
) -> _Host:
    """Build the host state every client shares, once, at start: the TUN,
    forwarding, the NAT table with client isolation and a flow tag per CN,
    and the DNS proxy with a cache per client (multi-client spec §2.2). Each
    teardown goes on ``stack`` right after its setup, so a failure half way
    unwinds what was built, and the run's end unwinds it all in reverse.

    Raises:
        RuntimeError: the TUN could not be opened or configured, or the NAT
            table did not load (the server then stops).
        DNSProxyPortInUseError: something else holds 10.8.0.1:53.
        OSError: the DNS proxy could not bind for another reason.
    """
    # The TUN first, so it goes last: forwarding and the NAT rules name it.
    # Its close also restores the host's IPv6 if configure stopped half way.
    tun = TunDevice(config.tun_name)
    tun.open()
    stack.callback(tun.close)
    tun.configure(local_ip=SERVER_TUN_IP, mtu=config.mtu, server_mode=True)
    clients = table.addresses()
    log.info(
        "tunnel %s/%d up; addresses for %d clients",
        SERVER_TUN_IP,
        TUN_PREFIX_LEN,
        len(clients),
    )

    # IPv4 forwarding and MASQUERADE, so client traffic reaches the internet
    # and its replies come back.
    ip_forward = IPForwardingManager(tun_name=config.tun_name)
    ip_forward.apply()
    stack.callback(ip_forward.remove)

    masquerade = MasqueradeManager(tun_name=config.tun_name, clients=clients)
    masquerade.apply()
    if not masquerade.applied:
        # Fail closed: without the table the kernel neither NATs nor keeps
        # clients apart, and no flow carries a tag. apply() logged why, and a
        # failed load leaves nothing to remove.
        raise RuntimeError(
            "the NAT table (MASQUERADE, client isolation, flow tags) did not load"
        )
    stack.callback(masquerade.remove)

    def _resolver() -> DNSResolver:
        return DNSResolver(
            providers=config.dns_providers,
            provider_pins=config.dns_provider_pins,
            debug_dns=config.debug_dns,
        )

    # One proxy on the TUN address for every client, each client with its
    # own resolver (its own cache); the first resolver answers the server's
    # own queries.
    dns_proxy = LocalDNSProxy(
        _resolver(),
        bind_ip=SERVER_TUN_IP,
        bind_port=53,
        debug_dns=config.debug_dns,
        blocklist=blocklist,
        per_client=_resolver,
    )
    await dns_proxy.start()
    stack.callback(dns_proxy.stop)  # sync
    return _Host(tun=tun, dns_proxy=dns_proxy)


async def _run_acceptor(
    acceptor: ClientAcceptor, process_shutdown: asyncio.Event
) -> None:
    """Run the run's one acceptor until shutdown (multi-client spec §2.7).

    ``run()`` ends only by a bug: log it with its traceback, stop the
    acceptor (every attempt ends and gives back what it held), wait the
    jittered backoff, and run it again with empty inboxes. ``stop()`` raises
    a bug a worker hit while being stopped, once every attempt has ended; it
    is logged the same way. Live sessions are not touched. It sees shutdown
    only during a backoff: the caller cancels it, then calls
    ``acceptor.stop()``.
    """
    failures = 0
    while True:
        try:
            await acceptor.run()
        except Exception:
            log.exception("handshake accept failed; retrying after a backoff")
        try:
            await acceptor.stop()
        except Exception:
            log.exception("handshake accept failed; retrying after a backoff")
        failures += 1
        if await _backoff_or_shutdown(failures, process_shutdown):
            return


def _drive_fsm_to_idle(fsm: SessionFSM) -> None:
    """Return a session's FSM to IDLE from wherever a failed session left it,
    so its closing FSM lines are logged. Any active state can reach
    TEARDOWN, and TEARDOWN -> IDLE; best-effort, never raises."""
    try:
        if fsm.state not in (State.IDLE, State.TEARDOWN):
            fsm.transition(State.TEARDOWN)
        if fsm.state is State.TEARDOWN:
            fsm.transition(State.IDLE)
    except ProtocolError:
        log.error(
            "could not drive FSM to IDLE from %s after a failed session",
            fsm.state.name,
        )


def _queue_path_challenge(
    ctx: DataPathContext,
    path_send: Callable[[bytes, int, tuple[str, int]], Awaitable[None]],
    candidate: tuple[str, int],
    token: bytes,
) -> None:
    """Queue a PATH_CHALLENGE for the pending candidate address.

    It leaves in a normal shaper slot like any packet, so it never shows up
    as an off-beat packet. As a control message it goes ahead of any queued
    data, so it leaves well inside the 5 s pending timeout. When its turn
    comes the scheduler sends it with ``path_send`` to ``candidate``, not to
    the committed egress, which stays untouched.
    """
    # imported here: private helper, not part of dsm.session's public surface
    from dsm.session import _build_control_packet  # pyright: ignore[reportPrivateUsage]

    padded, target_size = _build_control_packet(
        ctx, PacketType.PATH_CHALLENGE, payload=token
    )

    async def _to_candidate(data: bytes, size: int) -> None:
        await path_send(data, size, candidate)

    ctx.scheduler.enqueue(padded, target_size, send_via=_to_candidate, control=True)


async def _run_one_session(
    config: Config,
    fsm: SessionFSM,
    keystore: KeyStore,
    session: ServerSession,
    tun: TunDevice,
    on_peer: Callable[[tuple[str, int]], None],
) -> None:
    """Run one client's session until it ends, then unwind its own state.

    ``tun`` is the session's :class:`ClientTun`. ``session.shutdown`` ends
    it: the run sets it on a signal, and run_server's ``on_client`` on a
    takeover. All protocol state (sequence counter, rekey, liveness,
    reassembly, shaper, replay window, egress address) is new here, so each
    session starts from a clean epoch and an empty replay window: carrying
    state across sessions would be a nonce-reuse / replay-bypass bug.
    ``on_peer`` gets each new egress address a PATH_RESPONSE validated, so
    the dispatcher checks this session first for that address's packets.
    """
    import tuncore

    client_pub_bytes = bytes(session.client.noise_static)
    # Log a hash, not the raw key prefix. The Noise static is a stable
    # per-device identifier; logging even 64 bits of it lets a journald
    # reader correlate sessions across server restarts, defeating the
    # anonymity property. The first 16 hex chars of SHA-256(pub) are still
    # device-stable so operators can cross-reference logs to known clients,
    # but don't expose the raw key material in journald.
    import hashlib

    log.info(
        "client connected (noise_static_sha256=%s)",
        hashlib.sha256(client_pub_bytes).hexdigest()[:16],
    )

    fsm.transition(State.ESTABLISHED)
    transport = session.transport
    session_keys = session.session_keys
    session_shutdown = session.shutdown

    async with AsyncExitStack() as session_stack:
        # A TCP session owns its connection; a UDP session reads through its
        # view of the run's socket, which the run closes.
        if config.transport == "tcp":
            session_stack.push_async_callback(transport.aclose)

        # Fresh per-session protocol state: never reuse another session's.
        shaper = TrafficShaper.from_config(config)
        replay = tuncore.ReplayWindow()
        seq = SequenceCounter()
        rekey = RekeyState()
        liveness = LivenessState()
        reassembly = ReassemblyBuffer()

        # The committed egress address. It starts at the handshake address:
        # the handshake proved the client receives there (spec §2.10), so a
        # takeover's new session can send at once, and a spoofed source on a
        # first data packet cannot point the stream elsewhere. Only a
        # validated PATH_RESPONSE moves it.
        client_addr: list[tuple[str, int] | None] = [session.peer]

        send_packet = make_send_fn(
            session_keys,
            transport,
            lambda: client_addr[0],
            seq,
            liveness=liveness,
            shutdown=session_shutdown,
        )

        # Shaper-driven (mirrors the client): the tier shaper decides when
        # packets leave. should_chaff is only a GATE that keeps free slots
        # empty while the egress cell is empty; the server's starts at the
        # handshake address, so here it is open from the start.
        def _chaff_allowed() -> bool:
            return client_addr[0] is not None

        # Slow-link auto cap, wired exactly as the client does: before the
        # scheduler starts, so the tier listener sees every tier change.
        # (None, None) in TCP mode or when turned off.
        link_stats, autocap = make_auto_cap(config, transport, shaper, seq)

        # Scheduler+shaper params must mirror the client's — divergence here
        # reintroduces a direction-correlation fingerprint. See
        # tests/test_symmetric_shaping.py for the regression lock.
        server_scheduler = SendScheduler(
            send_fn=send_packet,
            chaff_fn=lambda: make_chaff_packet(shaper, session_keys.epoch & 0x0F),
            should_chaff_fn=_chaff_allowed,
            shaper=shaper,
        )
        await server_scheduler.start()
        session_stack.push_async_callback(server_scheduler.stop)

        ctx = DataPathContext(
            tun=tun,
            session_keys=session_keys,
            fsm=fsm,
            shaper=shaper,
            send_fn=send_packet,
            scheduler=server_scheduler,
            rekey=rekey,
            liveness=liveness,
            shutdown=session_shutdown,
            reassembly=reassembly,
            # Static pubs for mutual-init tie-break.
            local_static_pub=bytes(keystore.identity.public_key),
            remote_static_pub=client_pub_bytes,
            link_stats=link_stats,
            autocap=autocap,
        )

        # Return-routability state for egress roaming. Egress starts at the
        # handshake address; an authenticated packet from a DIFFERENT source
        # is treated as an unvalidated candidate and probed with a
        # PATH_CHALLENGE — egress does NOT roam there until the candidate echoes
        # the token in a PATH_RESPONSE. This blocks the on-path attack where a
        # genuine client packet is suppressed and reinjected with a SPOOFED
        # victim source: it is AEAD-valid (so it delivers to TUN) but the victim
        # never returns a valid PATH_RESPONSE, so egress stays on the real
        # client. Uses the SAME SequenceCounter as the data path so seq numbers
        # stay monotonic (replay window + nonce uniqueness).
        path_validation = PathValidationState()
        path_send = make_addr_send_fn(session_keys, transport, seq)

        async def _post_authenticate(addr: tuple[str, int], inner: object) -> None:
            from dsm.core.protocol import InnerPacket

            assert isinstance(inner, InnerPacket)
            committed = client_addr[0]

            # An empty cell would commit its first address; the server's starts
            # at the handshake address (see above), so it never is.
            if committed is None:
                client_addr[0] = addr
                return

            # A PATH_RESPONSE from the pending candidate with a matching token
            # COMMITS the roam. Validate BEFORE the same-addr fast path so a
            # response from the new candidate addr (which differs from the
            # committed addr) is acted on here.
            if inner.ptype == PacketType.PATH_RESPONSE:
                if path_validation.validate(addr, inner.payload):
                    client_addr[0] = addr
                    path_validation.clear()
                    on_peer(addr)  # the dispatcher's hint follows
                    log.info("egress roam validated, committed to new peer addr")
                return

            # Same committed addr: nothing to do (steady state).
            if addr == committed:
                return

            # A different authenticated source: hold as the pending candidate and
            # (rate-limited) probe it. Egress stays on the committed real client.
            token = path_validation.should_challenge(addr)
            if token is not None:
                _queue_path_challenge(ctx, path_send, addr, token)

        from dsm.session import run_data_loops

        await run_data_loops(
            ctx,
            transport,
            session_keys,
            replay,
            fsm,
            post_authenticate=_post_authenticate,
            shutdown_log="session closing",
        )


async def _serve_client(
    config: Config,
    keystore: KeyStore,
    table: SessionTable,
    host: _Host,
    session: ServerSession,
) -> None:
    """One session's task (multi-client spec §2.2): run the session, then
    take it out of the table, whatever ended it."""
    # The handshake is done: the session's FSM starts where the accept left
    # it before.
    fsm = SessionFSM()
    fsm.transition(State.CONNECTING)
    fsm.transition(State.HANDSHAKING)
    try:
        await _run_one_session(
            config,
            fsm,
            keystore,
            session,
            ClientTun(host.tun, session, _TUNNEL.network),
            lambda addr: table.note_peer(session, addr),
        )
    except Exception:
        # A bug in the session's setup or teardown (the data loops contain
        # their own errors, TUN writes too): it ends this session only. Its
        # client comes back after its dead-peer timer.
        log.exception(
            "session %d failed (client_cn=%s); other clients are not affected",
            session.number,
            session.client.cn,
        )
        _drive_fsm_to_idle(fsm)
    finally:
        if table.remove(session):
            # No newer session for this CN: its DNS state goes too, so memory
            # follows live sessions. A takeover keeps it (same CN, address).
            host.dns_proxy.forget(str(session.tunnel.client))
        log.info("session %d ended (client_cn=%s)", session.number, session.client.cn)


async def run_server(
    config: Config,
    passphrase_fd: int | None = None,
    passphrase_env_file: str | None = None,
) -> int:
    """Run DSM in server mode using transactional resource management.

    Returns:
        0 after a signal, 1 when the start fails or when the TUN or packet
        routing fails. ``main()`` ``sys.exit``s this so a misconfigured
        server is a nonzero exit and ``Restart=on-failure`` behaves
        correctly.
    """
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

    # The handshake gate's keys come from the CA certificate and this
    # server's CN (wire v2): a client must know both before the server
    # answers it at all. A certificate without one usable CN stops here,
    # before any host state changes.
    try:
        gate_keys = server_gate_keys(materials)
    except GateKeyError as e:
        log.error("handshake gate keys could not be made: %s", e)
        return 1

    if not config.allowed_cns_file:
        log.error(
            "server mode requires allowed_cns_file in config "
            "(validated by Config; should not reach this branch)"
        )
        return 1
    try:
        cn_allowlist = CNAllowlist.from_file(Path(config.allowed_cns_file))
    except CNAllowlistError as e:
        log.error("CN allowlist load failed: %s", e)
        return 1
    if len(cn_allowlist) == 0:
        log.error(
            "CN allowlist at %s is empty; refusing to start (would accept no clients)",
            config.allowed_cns_file,
        )
        return 1
    log.info("CN allowlist loaded (%d entries)", len(cn_allowlist))

    # Read the passphrase once and unlock both stores.
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

    # With both stores unlocked, confirm the loaded cert was issued for
    # THIS device's keys. Catches the cert_file substitution failure mode
    # at startup with a clear error, rather than at first peer's
    # AttestBindingMismatchError much later.
    try:
        verify_cert_matches_identity(materials.cert_der, keystore, attest_store)
    except AuthMaterialsError as e:
        log.error("cert/identity consistency check failed: %s", e)
        attest_store.unload()
        keystore.unload()
        return 1

    async with AsyncExitStack() as stack:
        # The run's resources, on one stack that unwinds once, in reverse,
        # when the daemon exits: the stores, the rate limiter, the socket or
        # listener, and the host state every client shares (TUN, forwarding,
        # NAT, DNS proxy). Each session keeps its own state on its own stack
        # in _run_one_session. Sync cleanups use stack.callback; async ones
        # use stack.push_async_callback.

        # Register keystore unload first so it unwinds last — the encrypted
        # identity must stay in memory for the lifetime of the run. Mirrors
        # client.py.
        stack.callback(keystore.unload)
        stack.callback(attest_store.unload)

        rate_limiter = ServerRateLimitManager(config.listen_port)
        try:
            rate_limiter.apply()
        except (RuntimeError, OSError) as e:
            # Fail closed: refuse to serve without handshake-flood protection.
            # OSError covers a missing/unresolvable nft (FileNotFoundError), so
            # an absent nftables yields this clean exit, not a raw traceback.
            log.error(
                "server handshake rate-limit could not be installed: %s — "
                "refusing to start (fail-closed). Ensure nftables is present "
                "and the daemon has CAP_NET_ADMIN.",
                e,
            )
            return 1
        stack.callback(rate_limiter.remove)

        tcp_ts = TcpTimestampsDisabler()
        tcp_ts.apply()
        stack.callback(tcp_ts.remove)

        # DNS blocklist: one per daemon run, shared by every session. It loads
        # in a worker thread and checks the list files every 5 minutes, so no
        # session waits for it.
        blocklist: DnsBlocklist | None = None
        if config.dns_blocklist:
            blocklist = DnsBlocklist(config.config_dir / "dns")
            blocklist.start()
            stack.push_async_callback(blocklist.stop)

        # The handshake rejects attestation timestamps more than ~5 minutes
        # off, so an unsynchronized clock fails with a confusing peer error.
        _clock_warn = check_clock_sync()
        if _clock_warn:
            log.warning(_clock_warn)

        # process_shutdown is set only by the signal handlers. Set up before
        # the port opens, so a signal during the start still ends the run.
        process_shutdown = asyncio.Event()
        setup_signal_handlers(process_shutdown)

        # Transport. UDP mode: one UDP socket for the whole run, and no TCP
        # port is opened at all. TCP mode: one TCP listener, open for the
        # whole run; each session's connection lives on its session stack.
        # Either way a port that cannot be opened is one ERROR line and exit 1:
        # retrying cannot fix it, and systemd restarts us after its delay.
        udp: UDPTransport | None = None
        listener: TCPListener | None = None
        if config.transport == "udp":
            # A bigger queue than a client's: every client's packets wait in
            # it (spec §2.6).
            udp = UDPTransport(recv_queue_size=SERVER_RECV_QUEUE_PACKETS)
            try:
                await udp.bind(
                    local_port=config.listen_port,
                    pmtu_discover=config.pmtu_discover,
                )
            except OSError as e:
                reason = os.strerror(e.errno) if e.errno else str(e)
                log.error(
                    "cannot listen on UDP port %d: %s; exiting",
                    config.listen_port,
                    reason,
                )
                return 1
            stack.push_async_callback(udp.aclose)
            log.info(
                "server listening on UDP port %d (wire v%d)",
                config.listen_port,
                WIRE_VERSION,
            )
        else:
            try:
                listener = await _open_tcp_listener(config)
            except ListenError as e:
                log.error("%s; exiting", e)
                return 1
            stack.callback(listener.close)
            log.info(
                "server listening on TCP port %d (wire v%d)",
                config.listen_port,
                WIRE_VERSION,
            )

        # Each allowlisted CN's tunnel address, by its line in the file. The
        # host state comes up once, after the port: a busy port touches none.
        try:
            table = SessionTable(cn_allowlist.order)
        except ValueError as e:
            # A bad assignment: a bug, caught before any host state.
            log.error("tunnel addresses could not be built: %s; exiting", e)
            return 1
        try:
            host = await _set_up_host(config, stack, blocklist, table)
        except DNSProxyPortInUseError as e:
            # A host resolver holds :53. Retrying cannot fix that, so exit
            # with a clear message, before any client.
            log.error(
                "FATAL: DNS proxy port conflict — %s. "
                "Stop the host resolver or change the TUN address, "
                "then restart dsm.",
                e,
            )
            return 1
        except (OSError, RuntimeError) as e:
            log.error("could not set up the tunnel at start: %s; exiting", e)
            return 1

        # Limits on starting handshake attempts, per source address and
        # overall, and the gate in front of new handshakes (mac1, cookies,
        # the load rule). One of each for the whole run.
        limiter = SourceLimiter()
        gate = HandshakeGate(gate_keys)
        # Push-out keeps a steady stream of stalled handshakes from holding
        # every slot only when there are enough slots (spec §4.4, condition
        # 1). More slots never break the rule, so only too few warn.
        slots = config.max_inflight_handshakes
        if not _slot_rule_ok(slots):
            enough = next(n for n in itertools.count(slots + 1) if _slot_rule_ok(n))
            log.warning(
                "max_inflight_handshakes=%d is too low for the handshake slot "
                "rule: a steady stream of stalled handshakes could keep every "
                "slot busy, so new devices wait. Use %d or more.",
                slots,
                enough,
            )

        session_numbers = itertools.count(1)
        # Every session's task: asyncio may drop a task nobody holds, and the
        # stop waits for each.
        session_tasks: set[asyncio.Task[None]] = set()
        dispatcher: UDPDispatcher | None = None

        def on_client(accepted: AcceptedClient) -> None:
            # Runs inside a handshake worker, after the client got its
            # bootstrap reply (spec §2.2). It never raises.
            routing_now = dispatcher
            try:
                transport: UDPTransport | TCPTransport = accepted.transport
                if routing_now is not None and isinstance(transport, UDPTransport):
                    transport = _SessionUDPView(
                        transport, lambda: routing_now.unmatched
                    )
                session = ServerSession(
                    number=next(session_numbers),
                    client=accepted.client,
                    tunnel=accepted.tunnel,
                    session_keys=accepted.session_keys,
                    transport=transport,
                    shutdown=asyncio.Event(),
                    tun_queue=asyncio.Queue(SESSION_QUEUE_PACKETS),
                    peer=accepted.peer,
                )
                if session.tunnel != table.assignment_for(session.client.cn):
                    # A wiring bug: add() routes by session.tunnel, so this
                    # client would get another CN's downloads.
                    raise RuntimeError("the session's tunnel is not its CN's")
            except Exception:
                # Never raise into the worker: the client already has its
                # bootstrap reply. It gets no session; its dead-peer timer
                # brings it back, and its next attempt must not count as a
                # takeover of a session that does not exist.
                log.exception(
                    "could not start a session for client_cn=%s", accepted.client.cn
                )
                table.abandon(accepted.client.cn)
                if isinstance(accepted.transport, TCPTransport):
                    accepted.transport.close()  # no session owns it
                return
            # Nothing below can raise.
            old = table.add(session)
            if old is not None:
                old.shutdown.set()  # a takeover: the new one is routed already
            log.info(
                "session %d: client_cn=%s, tunnel address %s",
                session.number,
                session.client.cn,
                session.tunnel.client,
            )
            task = asyncio.create_task(
                _serve_client(config, keystore, table, host, session)
            )
            session_tasks.add(task)
            task.add_done_callback(session_tasks.discard)
            if routing_now is not None:
                # Frames that reached the attempt after its last handshake
                # frame are the new session's.
                for frame in accepted.held:
                    routing_now.route(frame, accepted.peer)

        if udp is not None:
            acceptor = ClientAcceptor(
                config,
                keystore,
                attest_store,
                materials,
                cn_allowlist,
                limiter,
                table,
                gate,
                on_client,
                udp=udp,
            )
            dispatcher = UDPDispatcher(udp, table, acceptor.offer)
        else:
            assert listener is not None
            acceptor = ClientAcceptor(
                config,
                keystore,
                attest_store,
                materials,
                cn_allowlist,
                limiter,
                table,
                gate,
                on_client,
                tcp=listener.connections,
            )

        router = asyncio.create_task(
            TunRouter(host.tun, table, _TUNNEL.network, _TUNNEL.ip).run()
        )
        routing = [router]
        if dispatcher is not None:
            routing.append(asyncio.create_task(dispatcher.run()))
        accepting = asyncio.create_task(_run_acceptor(acceptor, process_shutdown))
        signalled = asyncio.create_task(process_shutdown.wait())
        rc = 0
        # Routing failures already logged, so the stop does not log them again.
        reported: set[asyncio.Task[None]] = set()
        try:
            # Until a signal, or until the TUN or packet routing fails. A
            # routing bug fails closed: its state may be wrong.
            await asyncio.wait(
                [signalled, *routing], return_when=asyncio.FIRST_COMPLETED
            )
            for task in routing:
                if not task.done():
                    continue
                rc = 1
                reported.add(task)
                err = task.exception()
                if task is router and isinstance(err, OSError):
                    log.error("the tunnel device failed (%s); stopping", err)
                else:
                    log.error("packet routing failed; stopping", exc_info=err)
        finally:
            # Stop in this order (spec §2.2): no new clients; every session
            # ends (each sends SESSION_CLOSE); then routing. The host state
            # unwinds with the stack after that. Each stage runs in a finally,
            # so a second cancel, or a bug one stage raises, still runs the
            # next. process_shutdown also ends an acceptor loop that a cancel
            # missed, at its backoff check.
            process_shutdown.set()
            signalled.cancel()
            accepting.cancel()
            try:
                try:
                    try:
                        await asyncio.gather(accepting, return_exceptions=True)
                    finally:
                        await acceptor.stop()
                except Exception:
                    # A worker's bug: log it and go on, so every session still
                    # ends before the host state goes.
                    log.exception("handshake accept failed while stopping")
                finally:
                    for session in table.sessions():
                        session.shutdown.set()
                    await asyncio.gather(*session_tasks, return_exceptions=True)
            finally:
                for task in routing:
                    task.cancel()
                await asyncio.gather(signalled, *routing, return_exceptions=True)
                # A failure after the wait above (for example the TUN went away
                # while the sessions closed) is logged here, not dropped.
                for task in routing:
                    if task in reported or task.cancelled():
                        continue
                    err = task.exception()
                    if err is not None:
                        log.error("packet routing failed while stopping", exc_info=err)

    return rc
