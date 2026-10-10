"""DSM VPN server mode."""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Awaitable, Callable
from contextlib import AsyncExitStack
from pathlib import Path
from typing import TYPE_CHECKING

from dsm.core.config import Config
from dsm.core.fsm import ProtocolError, SessionFSM, State
from dsm.core.preflight import check_clock_sync
from dsm.core.protocol import PacketType, ReassemblyBuffer
from dsm.crypto.attest_store import AttestStore
from dsm.crypto.auth_loader import (
    AuthMaterialsError,
    load_cert_materials,
    verify_cert_matches_identity,
)
from dsm.crypto.cert_allowlist import CNAllowlist, CNAllowlistError
from dsm.crypto.keystore import KeyStore
from dsm.net._addresses import SERVER_TUN_IP
from dsm.net.dns import DNSResolver
from dsm.net.dns_blocklist import DnsBlocklist
from dsm.net.dns_proxy import DNSProxyPortInUseError, LocalDNSProxy
from dsm.net.forwarding import IPForwardingManager, MasqueradeManager
from dsm.net.handshake_acceptor import (
    _accept_until_winner,  # pyright: ignore[reportPrivateUsage]
)

# isort: split
# Its own statement: isort and ruff disagree on one shared import whose
# names each carry a pyright pragma.
from dsm.net.handshake_acceptor import (
    _accept_until_winner_tcp,  # pyright: ignore[reportPrivateUsage]
)

# isort: split
# Its own statement too: isort would merge it into the one above.
from dsm.net.handshake_acceptor import SessionWatch, Winner
from dsm.net.handshake_gate import SourceLimiter
from dsm.net.nftables import ServerRateLimitManager, TcpTimestampsDisabler
from dsm.net.session_slot import SessionSlot
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

if TYPE_CHECKING:
    import tuncore
    from dsm.crypto.auth_loader import CertAuthMaterials

# Backoff after an unexpected accept error (see the accept loop in
# run_server), so an error that repeats cannot spin. Failed handshakes do
# not back off: the acceptors drop and rate-limit them without waiting.
_HANDSHAKE_RETRY_BACKOFF_BASE = 0.5  # seconds
_HANDSHAKE_RETRY_BACKOFF_MAX = 5.0  # seconds
_HANDSHAKE_RETRY_BACKOFF_JITTER = 0.5  # ±this fraction of base

log = logging.getLogger(__name__)


class ListenError(Exception):
    """The TCP listening socket could not be opened (e.g. the port is in use)."""


async def _backoff_or_shutdown(
    consecutive_failures: int, process_shutdown: asyncio.Event
) -> bool:
    """Sleep the jittered backoff after an unexpected accept error, or return
    early on shutdown.

    Failed handshakes do not come here: they end only their own attempt.

    Returns:
        ``True`` if ``process_shutdown`` was set during the wait (the caller
        must abandon the accept), ``False`` if the backoff elapsed normally.
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


async def _accept_one_session(
    config: Config,
    fsm: SessionFSM,
    keystore: KeyStore,
    attest_store: AttestStore,
    materials: CertAuthMaterials,
    cn_allowlist: CNAllowlist,
    transport_obj: UDPTransport | TCPTransport | None,
    process_shutdown: asyncio.Event,
    limiter: SourceLimiter,
    listener: TCPListener,
    slot: SessionSlot,
) -> tuple[
    tuncore.SessionKeyManager | None,
    bytes | None,
    UDPTransport | TCPTransport | None,
]:
    """Accept exactly one TCP client on the run's listener.

    ``_accept_until_winner_tcp`` checks the listener's connections side by
    side under the same pool, per-address limits and 12 s attempt deadline
    as UDP. The listener was opened once at start and stays open, also while
    the session runs (the in-session accept reads the same queue). The FSM
    is expected to be in ``CONNECTING`` on entry. ``transport_obj`` is the
    previous session's connection, or None; it is closed first. ``limiter``
    and ``slot`` are the run's.

    Returns:
        ``(session_keys, client_pub, transport)`` on success, where
        ``transport`` is the winning connection. On shutdown during the
        accept wait, returns ``(None, None, None)`` with the FSM back in
        IDLE, so the caller can break the outer loop and unwind cleanly.
    """
    if transport_obj is not None:
        # Its session stack normally closed it already; aclose() is safe twice.
        await transport_obj.aclose()

    fsm.transition(State.HANDSHAKING)
    session_keys, client_pub, transport = await _accept_until_winner_tcp(
        config,
        keystore,
        attest_store,
        materials,
        cn_allowlist,
        listener.connections,
        process_shutdown,
        limiter,
        slot,
    )
    if session_keys is None:
        _drive_fsm_to_idle(fsm)
    return session_keys, client_pub, transport


def _start_watch(
    config: Config,
    keystore: KeyStore,
    attest_store: AttestStore,
    materials: CertAuthMaterials,
    cn_allowlist: CNAllowlist,
    transport_obj: UDPTransport | TCPTransport,
    listener: TCPListener | None,
    limiter: SourceLimiter,
    slot: SessionSlot,
) -> SessionWatch:
    """Start the accept that runs while the next session is live (step R):
    on the run's UDP socket, or on the run's one TCP listener."""
    if config.transport == "udp":
        assert isinstance(transport_obj, UDPTransport)
        return SessionWatch(
            config,
            keystore,
            attest_store,
            materials,
            cn_allowlist,
            limiter,
            slot,
            udp=transport_obj,
        )
    assert listener is not None
    return SessionWatch(
        config,
        keystore,
        attest_store,
        materials,
        cn_allowlist,
        limiter,
        slot,
        tcp=listener.connections,
    )


def _drive_fsm_to_idle(fsm: SessionFSM) -> None:
    """Return the FSM to IDLE from wherever a failed session left it so the
    re-accept loop can start the next session. Any active state can reach
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
    session_keys: tuncore.SessionKeyManager,
    client_pub: bytes,
    transport: UDPTransport | TCPTransport,
    process_shutdown: asyncio.Event,
    blocklist: DnsBlocklist | None = None,
    end_session: asyncio.Event | None = None,
    unauthenticated: Callable[[bytes, tuple[str, int], bool], None] | None = None,
) -> None:
    """Stand up per-session host state, run the data loops, then unwind.

    Builds a fresh per-session ``AsyncExitStack`` holding TUN, IP
    forwarding, MASQUERADE, the DNS proxy and resolver (and, for TCP, the
    accepted transport). All per-session protocol state (sequence counter,
    rekey, liveness, reassembly, shaper, replay window, client addr) is
    re-created here so a re-accepted client starts from a clean epoch and an
    empty replay window — carrying stale state across sessions would be a
    nonce-reuse / replay-bypass bug.

    A fresh ``session_shutdown`` event drives ``run_data_loops``; bridge
    tasks set it when ``process_shutdown`` is set (a signal) or when
    ``end_session`` is set (the in-session accept found a client that takes
    the session over, step R). The bridges are cancelled when the session
    ends.

    ``blocklist`` is the daemon's one DNS blocklist (None when
    ``dns_blocklist`` is off); this session's DNS proxy answers from it.
    ``unauthenticated`` gets each UDP packet this session cannot use (did
    not open, or already seen), with ``seen`` set for the second
    (``SessionWatch.offer``); None for TCP.
    """
    import tuncore

    client_pub_bytes = bytes(client_pub)
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

    async with AsyncExitStack() as session_stack:
        # For TCP the accepted transport is per-session — close it when this
        # session unwinds (UDP transport lives on the outer stack).
        if config.transport == "tcp":
            session_stack.push_async_callback(transport.aclose)

        # TUN device. Registered FIRST so it unwinds LAST — MASQUERADE and
        # IP-forwarding reference the TUN name and must be removed before it
        # closes.
        tun = TunDevice(config.tun_name)
        tun.open()
        tun.configure(local_ip=SERVER_TUN_IP, mtu=config.mtu, server_mode=True)
        session_stack.callback(tun.close)

        # Enable IPv4 forwarding + MASQUERADE so decrypted client traffic
        # actually reaches the internet. Without these, the kernel either
        # drops the packet (forwarding off) or replies are unroutable
        # (replies addressed to 10.8.0.0/24, no NAT). Apply AFTER the TUN
        # exists so the MASQUERADE rule can reference its name.
        ip_forward = IPForwardingManager(tun_name=config.tun_name)
        ip_forward.apply()
        session_stack.callback(ip_forward.remove)

        masquerade = MasqueradeManager(tun_name=config.tun_name)
        masquerade.apply()
        session_stack.callback(masquerade.remove)

        # DNS proxy: listen on the TUN address for DNS queries arriving from
        # clients through the tunnel. Forwards to the pinned DoH/DoT
        # resolver.
        resolver = DNSResolver(
            providers=config.dns_providers,
            provider_pins=config.dns_provider_pins,
            debug_dns=config.debug_dns,
        )
        dns_proxy = LocalDNSProxy(
            resolver,
            bind_ip=SERVER_TUN_IP,
            bind_port=53,
            debug_dns=config.debug_dns,
            blocklist=blocklist,
        )
        await dns_proxy.start()
        session_stack.callback(dns_proxy.stop)  # sync

        # Fresh per-session protocol state. A re-accepted client gets a clean
        # SequenceCounter / ReplayWindow / epoch — never reuse the previous
        # session's instances.
        shaper = TrafficShaper.from_config(config)
        replay = tuncore.ReplayWindow()
        seq = SequenceCounter()
        rekey = RekeyState()
        liveness = LivenessState()
        reassembly = ReassemblyBuffer()

        # Fresh session_shutdown drives run_data_loops. Bridges set it when a
        # SIGTERM comes (process_shutdown) or when a client takes the session
        # over (end_session). They are cancelled in the session_stack unwind
        # (registered below) so they do not leak across sessions.
        session_shutdown = asyncio.Event()

        async def _propagate(src: asyncio.Event, dst: asyncio.Event) -> None:
            await src.wait()
            dst.set()

        bridges = [
            asyncio.ensure_future(_propagate(process_shutdown, session_shutdown))
        ]
        if end_session is not None:
            bridges.append(
                asyncio.ensure_future(_propagate(end_session, session_shutdown))
            )

        async def _cancel_bridges() -> None:
            # Cancel AND await so each task is fully retired before the next
            # session starts — a bare .cancel() would leave a pending task and
            # (on a session that ended without a signal) emit a "Task was
            # destroyed but it is pending" warning.
            for bridge in bridges:
                bridge.cancel()
            for bridge in bridges:
                try:
                    await bridge
                except asyncio.CancelledError:
                    pass

        session_stack.push_async_callback(_cancel_bridges)

        # One-element cell holding the committed egress addr. None until the
        # first authenticated packet; post_authenticate may later overwrite it
        # with the SAME addr, or a new src port after a validated roam.
        client_addr: list[tuple[str, int] | None] = [None]

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
        # empty until client_addr is known — otherwise each chaff packet would
        # burn a sequence number only to be dropped by make_send_fn's
        # "destination addr not yet known" path.
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

        # Return-routability state for egress roaming. The first authenticated
        # addr commits normally; a later authenticated packet from a DIFFERENT
        # source is treated as an unvalidated candidate and probed with a
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

            # First authenticated addr: commit (no challenge for the first one).
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
            unauthenticated=unauthenticated,
            shutdown_log="server shutting down",
        )


async def run_server(
    config: Config,
    passphrase_fd: int | None = None,
    passphrase_env_file: str | None = None,
) -> int:
    """Run DSM in server mode using transactional resource management.

    Returns:
        0 on a clean shutdown (signal arriving during the handshake-accept
        wait, or the session ending), 1 on any startup error path.
        ``main()`` ``sys.exit``s this so a misconfigured server is a nonzero
        exit and ``Restart=on-failure`` behaves correctly.
    """
    from dsm.core.hardening import harden_and_gate

    if not harden_and_gate(config):
        return 1

    fsm = SessionFSM()

    # Cert auth materials must load BEFORE we touch any host state, so a
    # missing cert file aborts cleanly with no rules / no TUN created.
    try:
        materials = load_cert_materials(config)
    except AuthMaterialsError as e:
        log.error("cert auth materials missing or invalid: %s", e)
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
        # OUTER stack — process-lifetime resources. Unwinds exactly once when
        # the daemon exits (process_shutdown set). Per-session host state
        # (TUN, forwarding, masquerade, DNS) lives on a separate INNER stack
        # inside _run_one_session, so it is torn down and rebuilt around each
        # accepted client. Sync cleanups use stack.callback; async ones use
        # stack.push_async_callback.

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

        # process_shutdown is set ONLY by the signal handlers (the whole
        # daemon is terminating). A session ending on its own (dead-peer
        # timeout, peer SESSION_CLOSE, rekey give-up) sets a SEPARATE
        # per-session event inside _run_one_session — never this one — so the
        # re-accept loop below can distinguish "accept the next client" from
        # "the process is shutting down". Set up BEFORE the accept loop so a
        # SIGTERM arriving while we wait for msg1 unblocks the loop.
        process_shutdown = asyncio.Event()
        setup_signal_handlers(process_shutdown)

        # Transport. UDP mode: one UDP socket for the whole run, and no TCP
        # port is opened at all. TCP mode: one TCP listener for the whole run,
        # open also while a session runs, so a client that comes back can
        # replace its old session; each session's connection lives on its
        # session stack. Either way a port that cannot be opened is one ERROR
        # line and exit 1: retrying cannot fix it, and systemd restarts us
        # after its delay.
        transport_obj: UDPTransport | TCPTransport | None = None
        listener: TCPListener | None = None
        if config.transport == "udp":
            transport_obj = UDPTransport()
            try:
                await transport_obj.bind(
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
            stack.push_async_callback(transport_obj.aclose)
            log.info("server listening on UDP port %d", config.listen_port)
        else:
            try:
                listener = await _open_tcp_listener(config)
            except ListenError as e:
                log.error("%s; exiting", e)
                return 1
            stack.callback(listener.close)
            log.info("server listening on TCP port %d", config.listen_port)

        # Limits on starting handshake attempts, per source address and
        # overall. One for the whole run, so they hold across accept cycles.
        limiter = SourceLimiter()
        # Who holds the session and who may take it over (step R). One for
        # the whole run, handed to every accept.
        slot = SessionSlot()

        fsm.transition(State.CONNECTING)

        # OUTER loop: accept a client, serve it until its session ends, then
        # serve the next. While a session runs, a SessionWatch keeps accepting
        # handshakes. A client that passes the full handshake and the slot's
        # rules (the session's CN: the same client coming back) ends the
        # session and is served next without a new accept ("pending").
        # Exits only on process_shutdown.
        accept_failures = 0
        pending: Winner | None = None
        while not process_shutdown.is_set():
            if pending is not None:
                session_keys = pending.session_keys
                client_pub = pending.client_pub
                transport_obj = pending.transport
                pending = None
                fsm.transition(State.HANDSHAKING)
            else:
                try:
                    if config.transport == "udp":
                        # Validate handshakes concurrently so one stalled bogus
                        # msg1 cannot starve a real client. The acceptor does no
                        # per-attempt FSM churn: HANDSHAKING here, CONNECTING at
                        # the loop tail.
                        assert isinstance(transport_obj, UDPTransport)
                        fsm.transition(State.HANDSHAKING)
                        (
                            session_keys,
                            client_pub,
                            transport_obj,
                        ) = await _accept_until_winner(
                            config,
                            keystore,
                            attest_store,
                            materials,
                            cn_allowlist,
                            transport_obj,
                            process_shutdown,
                            limiter,
                            slot,
                        )
                        if session_keys is None:
                            # Shutdown during accept: leave HANDSHAKING so the
                            # unwind below is clean.
                            _drive_fsm_to_idle(fsm)
                    else:
                        assert listener is not None
                        (
                            session_keys,
                            client_pub,
                            transport_obj,
                        ) = await _accept_one_session(
                            config,
                            fsm,
                            keystore,
                            attest_store,
                            materials,
                            cn_allowlist,
                            transport_obj,
                            process_shutdown,
                            limiter,
                            listener,
                            slot,
                        )
                except Exception:
                    # Anything raised by the accept (a bug, or the host out of
                    # a resource such as file descriptors) must not take the
                    # daemon down for every later client. A bad frame does not
                    # get here: it ends only its own attempt. Reset, wait the
                    # usual jittered backoff so a repeating error cannot spin,
                    # then accept again (TCP: on the same listener).
                    log.exception("accept failed; retrying after a backoff")
                    _drive_fsm_to_idle(fsm)
                    if config.transport == "tcp" and transport_obj is not None:
                        await transport_obj.aclose()
                        transport_obj = None
                    accept_failures += 1
                    await _backoff_or_shutdown(accept_failures, process_shutdown)
                    if not process_shutdown.is_set():
                        fsm.transition(State.CONNECTING)
                    continue

                if (
                    session_keys is None
                    or client_pub is None
                    or transport_obj is None
                    or process_shutdown.is_set()
                ):
                    # Shutdown came during the accept, or as a client won it
                    # (that client is not served). The UDP socket and the TCP
                    # listener unwind with the outer stack; a TCP winner's
                    # connection is closed here.
                    _drive_fsm_to_idle(fsm)
                    if config.transport == "tcp" and transport_obj is not None:
                        await transport_obj.aclose()
                    break
                accept_failures = 0

            watch = _start_watch(
                config,
                keystore,
                attest_store,
                materials,
                cn_allowlist,
                transport_obj,
                listener,
                limiter,
                slot,
            )
            dns_clash: DNSProxyPortInUseError | None = None
            try:
                await _run_one_session(
                    config,
                    fsm,
                    keystore,
                    session_keys,
                    client_pub,
                    transport_obj,
                    process_shutdown,
                    blocklist,
                    watch.end_session,
                    watch.offer,
                )
            except DNSProxyPortInUseError as e:
                dns_clash = e
            except Exception:
                # A per-session host-setup failure (TUN open/configure, DNS-proxy
                # bind, forwarding sysctls) previously propagated out of this
                # loop and crashed the whole server, denying service to ALL
                # future clients. _run_one_session's per-session AsyncExitStack
                # has already unwound any partial state; reset the FSM and keep
                # the daemon up. The loop tail re-arms CONNECTING for the next
                # client.
                log.exception(
                    "session failed; recovering — daemon stays up for the "
                    "next client"
                )
                _drive_fsm_to_idle(fsm)
            finally:
                # Always, also on a fatal error or a cancel: no handshake task
                # may outlive the session it watched.
                pending = await watch.stop()

            if dns_clash is not None or process_shutdown.is_set():
                if pending is not None and config.transport == "tcp":
                    # A client that won during this session is not served.
                    await pending.transport.aclose()
                if dns_clash is not None:
                    # A host resolver holds :53. Retrying cannot fix that and
                    # would loop on the same bind error, so exit with a clear
                    # message.
                    log.error(
                        "FATAL: DNS proxy port conflict — %s. "
                        "Stop the host resolver or change the TUN address, "
                        "then restart dsm.",
                        dns_clash,
                    )
                    return 1
                break
            if pending is None:
                # Nobody took the session over: the next accept is open to any
                # allowed client.
                slot.clear()
            # The session ended (dead peer, SESSION_CLOSE, a takeover, a setup
            # error); run_data_loops or _drive_fsm_to_idle left the FSM in
            # IDLE. The UDP socket and the TCP listener serve on.
            fsm.transition(State.CONNECTING)
            if pending is not None:
                # LocalDNSProxy.stop() closes its socket one loop step later,
                # and the next session binds the same address at once; a clash
                # there is fatal. Give asyncio that step.
                await asyncio.sleep(0)

    return 0
