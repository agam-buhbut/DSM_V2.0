"""DSM VPN server mode."""

from __future__ import annotations

import asyncio
import logging
from contextlib import AsyncExitStack
from pathlib import Path
from typing import TYPE_CHECKING

from cryptography.x509.oid import ExtendedKeyUsageOID

from dsm.core import netaudit
from dsm.core.config import Config
from dsm.core.fsm import SessionFSM, State
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
from dsm.net.dns_proxy import LocalDNSProxy
from dsm.net.forwarding import IPForwardingManager, MasqueradeManager
from dsm.net.nftables import ServerRateLimitManager, TcpTimestampsDisabler
from dsm.net.transport.tcp import TCPTransport
from dsm.net.transport.udp import UDPTransport
from dsm.net.tunnel import TunDevice
from dsm.session import (
    DataPathContext,
    LivenessState,
    PathValidationState,
    RekeyState,
    SequenceCounter,
    make_addr_send_fn,
    make_send_fn,
    setup_signal_handlers,
)
from dsm.traffic.scheduler import SendScheduler
from dsm.traffic.shaper import TrafficShaper, make_chaff_packet

if TYPE_CHECKING:
    import tuncore
    from dsm.crypto.auth_loader import CertAuthMaterials

# Backoff parameters for failed handshake retries. UDP retries cycle very
# fast because there's no kernel-side rate limit on bad packets reaching
# the handshake coroutine; TCP retries are gated by the kernel's accept
# queue but a malicious peer racing the listen() can still burn slots in
# a tight loop. A small jittered sleep between retries gives legitimate
# clients a chance to win against a flood.
_HANDSHAKE_RETRY_BACKOFF_BASE = 0.5  # seconds
_HANDSHAKE_RETRY_BACKOFF_MAX = 5.0  # seconds
_HANDSHAKE_RETRY_BACKOFF_JITTER = 0.5  # ±this fraction of base

log = logging.getLogger(__name__)


def _emit_handshake_failure(err: Exception) -> None:
    """Emit the failed-handshake audit event WITHOUT the exception message,
    and with a COARSE family label for cert-auth rejections.

    Phase 1.13: the human WARNING/DEBUG logs already hide cert-auth detail so
    a journald reader can't distinguish CNNotAllowedError (allowlist miss)
    from CertRevokedError (CRL hit) from a binding mismatch and enumerate the
    allowlist / CRL. The netaudit stream (enabled by --debug-net) must apply
    the SAME redaction: collapse every CertAuthError subclass to "cert_auth".
    Non-cert HandshakeErrors keep their precise class (no enumeration risk).
    The client side stays precise — a client owns its server.
    """
    from dsm.crypto.handshake import CertAuthError

    error_label = "cert_auth" if isinstance(err, CertAuthError) else type(err).__name__
    netaudit.emit(
        "handshake_end",
        role="server",
        outcome="failed",
        error=error_label,
    )


async def _backoff_or_shutdown(
    consecutive_failures: int, process_shutdown: asyncio.Event
) -> bool:
    """Sleep the jittered handshake-retry backoff, or return early on
    shutdown.

    Returns:
        ``True`` if ``process_shutdown`` was set during the wait (the caller
        must abandon the accept), ``False`` if the backoff elapsed normally.
    """
    # Doubles per failure up to _HANDSHAKE_RETRY_BACKOFF_MAX, with ±50%
    # jitter so a flood of bad handshakes does not produce a deterministic
    # retry cadence an attacker can synchronize to.
    base = min(
        _HANDSHAKE_RETRY_BACKOFF_BASE * (2 ** min(consecutive_failures - 1, 4)),
        _HANDSHAKE_RETRY_BACKOFF_MAX,
    )
    # Use the same CSPRNG-backed helper the shaper uses for jitter, then
    # clamp. Imported lazily to avoid a top-level dependency on
    # dsm.core.rand from server.py.
    from dsm.core.rand import csprng_float

    jitter = (csprng_float() - 0.5) * _HANDSHAKE_RETRY_BACKOFF_JITTER * base
    delay = max(0.0, base + jitter)
    try:
        await asyncio.wait_for(process_shutdown.wait(), timeout=delay)
        return True  # shutdown arrived during backoff
    except TimeoutError:
        return False


async def _accept_one_session(
    config: Config,
    fsm: SessionFSM,
    keystore: KeyStore,
    attest_store: AttestStore,
    materials: CertAuthMaterials,
    cn_allowlist: CNAllowlist,
    transport_obj: UDPTransport | TCPTransport | None,
    process_shutdown: asyncio.Event,
) -> tuple[
    tuncore.SessionKeyManager | None,
    bytes | None,
    UDPTransport | TCPTransport | None,
]:
    """Accept exactly one client via the handshake retry loop.

    Drives the handshake (with jittered backoff between rejected attempts)
    until a client authenticates or ``process_shutdown`` is set. The FSM is
    expected to be in ``CONNECTING`` on entry.

    Returns:
        ``(session_keys, client_pub, transport)`` on success. On shutdown
        during the accept wait, returns ``(None, None, transport_obj)`` so
        the caller can break the outer loop and unwind cleanly. ``transport``
        is the (possibly re-created, for TCP) transport that the handshake
        succeeded on.
    """
    from dsm.crypto.handshake import (
        CertAuthError,
        CertRevokedError,
        CNNotAllowedError,
        HandshakeError,
        server_handshake,
    )

    consecutive_failures = 0
    while not process_shutdown.is_set():
        # For TCP, re-create the listening transport on each attempt (and
        # close any previous failed-attempt transport).
        if config.transport == "tcp":
            if transport_obj is not None:
                await transport_obj.aclose()
            transport_obj = TCPTransport()
            await transport_obj.listen(port=config.listen_port)
            log.info("server listening on TCP port %d", config.listen_port)

        fsm.transition(State.HANDSHAKING)
        if transport_obj is None:
            # Unreachable in practice — UDP path sets it once before the
            # outer loop, TCP path sets it on every iteration above. Explicit
            # check keeps the type narrowing for the handshake call.
            raise RuntimeError("internal: handshake reached with no transport")
        try:
            session_keys, client_pub = await server_handshake(
                transport_obj,
                keystore.identity,
                attest_key=attest_store.attest_key,
                cert_der=materials.cert_der,
                ca_root=materials.ca_root,
                cn_allowlist=cn_allowlist,
                crl=materials.crl,
                required_client_eku=ExtendedKeyUsageOID.CLIENT_AUTH,
                rotation_packets=config.rotation_packets,
                rotation_seconds=config.rotation_seconds,
            )
            return session_keys, client_pub, transport_obj
        except (
            CNNotAllowedError,
            CertRevokedError,
            CertAuthError,
            HandshakeError,
        ) as e:
            err_name = type(e).__name__
            # Anti-information-leak: at INFO/WARNING, log only an opaque
            # "cert auth failed" so an attacker who can read journald (or a
            # log shipper) cannot distinguish "this cert is on the CRL" from
            # "this CN is not in the allowlist" from "binding mismatch" —
            # each of those would otherwise let them enumerate the negative
            # space of the allowlist or partially recover CRL contents
            # through trial. The specific class name (and the exception
            # message) is only emitted at DEBUG.
            if isinstance(e, (CNNotAllowedError, CertRevokedError, CertAuthError)):
                log.warning("handshake rejected (cert auth) — waiting for next client")
                log.debug("cert auth detail: %s: %s", err_name, e)
            else:
                log.info("handshake failed — waiting for next client")
                log.debug("handshake failure detail: %s: %s", err_name, e)
            _emit_handshake_failure(e)
            # Reset FSM for the next attempt:
            # HANDSHAKING → TEARDOWN → IDLE → CONNECTING.
            fsm.transition(State.TEARDOWN)
            fsm.transition(State.IDLE)
            fsm.transition(State.CONNECTING)

            consecutive_failures += 1
            if await _backoff_or_shutdown(consecutive_failures, process_shutdown):
                break  # shutdown arrived during backoff

    return None, None, transport_obj


async def _run_one_session(
    config: Config,
    fsm: SessionFSM,
    keystore: KeyStore,
    session_keys: tuncore.SessionKeyManager,
    client_pub: bytes,
    transport: UDPTransport | TCPTransport,
    process_shutdown: asyncio.Event,
) -> None:
    """Stand up per-session host state, run the data loops, then unwind.

    Builds a fresh per-session ``AsyncExitStack`` holding TUN, IP
    forwarding, MASQUERADE, the DNS proxy and resolver (and, for TCP, the
    accepted transport). All per-session protocol state (sequence counter,
    rekey, liveness, reassembly, shaper, replay window, client addr) is
    re-created here so a re-accepted client starts from a clean epoch and an
    empty replay window — carrying stale state across sessions would be a
    nonce-reuse / replay-bypass bug.

    A fresh ``session_shutdown`` event drives ``run_data_loops``; a bridge
    task propagates ``process_shutdown`` into it so a signal arriving during
    a live session also stops the loops. The bridge is cancelled when the
    session ends.
    """
    import tuncore

    client_pub_bytes = bytes(client_pub)
    # Log a hash, not the raw key prefix. The Noise static is a stable
    # per-device identifier; logging even 64 bits of it lets a journald
    # reader correlate sessions across server restarts, defeating the
    # anonymity property. The first 16 hex chars of SHA-256(pub) are still
    # device-stable so operators can cross-reference logs to known clients,
    # but don't expose the raw key material in journald.
    import hashlib as _hl

    log.info(
        "client connected (noise_static_sha256=%s)",
        _hl.sha256(client_pub_bytes).hexdigest()[:16],
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
        )
        await dns_proxy.start()
        session_stack.callback(dns_proxy.stop)  # sync
        session_stack.push_async_callback(resolver.close)  # async (httpx.aclose)

        # Fresh per-session protocol state. A re-accepted client gets a clean
        # SequenceCounter / ReplayWindow / epoch — never reuse the previous
        # session's instances.
        shaper = TrafficShaper(
            config.padding_min,
            config.padding_max,
            envelope_idle_floor_min_pps=config.envelope_idle_floor_min_pps,
            envelope_idle_floor_max_pps=config.envelope_idle_floor_max_pps,
            envelope_ceiling_pps=config.envelope_ceiling_pps,
            envelope_rise_per_s=config.envelope_rise_per_s,
            envelope_fall_half_life_s=config.envelope_fall_half_life_s,
            envelope_latency_budget_ms=config.envelope_latency_budget_ms,
        )
        replay = tuncore.ReplayWindow()
        seq = SequenceCounter()
        rekey = RekeyState()
        liveness = LivenessState()
        reassembly = ReassemblyBuffer()

        # Fresh session_shutdown drives run_data_loops; the bridge propagates
        # a process-shutdown signal into it so a SIGTERM during this live
        # session also stops the loops. The bridge is cancelled in the
        # session_stack unwind (registered below) so it does not leak across
        # sessions.
        session_shutdown = asyncio.Event()

        async def _propagate(src: asyncio.Event, dst: asyncio.Event) -> None:
            await src.wait()
            dst.set()

        bridge = asyncio.ensure_future(_propagate(process_shutdown, session_shutdown))

        async def _cancel_bridge() -> None:
            # Cancel AND await so the task is fully retired before the next
            # session is accepted — a bare .cancel() would leave a pending
            # task and (on a session that ended without a signal) emit a
            # "Task was destroyed but it is pending" warning.
            bridge.cancel()
            try:
                await bridge
            except asyncio.CancelledError:
                pass

        session_stack.push_async_callback(_cancel_bridge)

        # M-BUG-9: wrap the client_addr cell in a small class that enforces
        # the monotonic-set-once invariant via the type system rather than
        # convention. set() rejects None and a wrong shape (post_authenticate
        # may overwrite with the SAME addr — or a new src port after rebind —
        # which is allowed; setting to None is a programming error).
        class _ClientAddr:
            __slots__ = ("_addr",)

            def __init__(self) -> None:
                self._addr: tuple[str, int] | None = None

            def set(self, addr: tuple[str, int]) -> None:
                # Defensive runtime guard against a future caller passing
                # None or wrong shape (the type annotation is the primary
                # contract; this catches type-eraser misuse).
                if addr is None or len(addr) != 2:  # type: ignore[unreachable]
                    raise TypeError(f"client_addr must be (host, port), got {addr!r}")
                self._addr = addr

            def get(self) -> tuple[str, int] | None:
                return self._addr

        client_addr = _ClientAddr()

        send_packet = make_send_fn(
            session_keys,
            transport,
            client_addr.get,
            seq,
            liveness=liveness,
            shutdown=session_shutdown,
        )

        # Phase 2: envelope-driven (mirrors the client). The shaper's paced
        # wire budget decides how many packets leave per poll; should_chaff
        # is now only a GATE that suppresses chaff-fill until client_addr is
        # known — otherwise the direct chaff send would hit make_send_fn's
        # "destination addr not yet known" path and trigger shutdown.
        def _chaff_allowed() -> bool:
            return client_addr.get() is not None

        # Scheduler+shaper params must mirror the client's — divergence here
        # reintroduces a direction-correlation fingerprint. See
        # tests/test_symmetric_shaping.py for the regression lock.
        server_scheduler = SendScheduler(
            send_fn=send_packet,
            chaff_fn=lambda: make_chaff_packet(shaper, session_keys.epoch & 0x0F),
            should_chaff_fn=_chaff_allowed,
            jitter_ms_min=config.jitter_ms_min,
            jitter_ms_max=config.jitter_ms_max,
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
            # M-BUG-1: static pubs for mutual-init tie-break.
            local_static_pub=bytes(keystore.identity.public_key),
            remote_static_pub=client_pub_bytes,
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

        async def _send_challenge(candidate: tuple[str, int], token: bytes) -> None:
            # The challenge goes DIRECTLY to the pending candidate — NOT through
            # the scheduler (which always targets the committed egress) and
            # WITHOUT touching the committed egress. Bounded so a wedged/unroutable
            # candidate (e.g. the spoofed victim) cannot pin the recv loop.
            # local import (avoids cycle churn):
            from dsm.session import (
                _build_control_packet,  # pyright: ignore[reportPrivateUsage]
            )

            padded, target_size = _build_control_packet(
                ctx, PacketType.PATH_CHALLENGE, payload=token
            )
            try:
                await asyncio.wait_for(
                    path_send(padded, target_size, candidate), timeout=5.0
                )
            except (TimeoutError, OSError) as e:
                log.debug("PATH_CHALLENGE send to %s failed: %s", candidate, e)

        async def _post_authenticate(addr: tuple[str, int], inner: object) -> None:
            from dsm.core.protocol import InnerPacket

            assert isinstance(inner, InnerPacket)
            committed = client_addr.get()

            # First authenticated addr: commit (no challenge for the first one).
            if committed is None:
                client_addr.set(addr)
                return

            # A PATH_RESPONSE from the pending candidate with a matching token
            # COMMITS the roam. Validate BEFORE the same-addr fast path so a
            # response from the new candidate addr (which differs from the
            # committed addr) is acted on here.
            if inner.ptype == PacketType.PATH_RESPONSE:
                if path_validation.validate(addr, inner.payload):
                    client_addr.set(addr)
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
                await _send_challenge(addr, token)

        from dsm.session import run_data_loops

        await run_data_loops(
            ctx,
            transport,
            session_keys,
            replay,
            fsm,
            post_authenticate=_post_authenticate,
            shutdown_log="server shutting down",
        )
        # session_stack unwinds here (resolver → dns_proxy → masquerade →
        # ip_forward → tun, plus the bridge cancel and TCP transport close).


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
    import tuncore

    try:
        tuncore.harden_process()
    except Exception as e:  # noqa: BLE001  # see linter report
        log.warning(
            "process hardening partially failed: %s — continuing without it. "
            "Ensure the service has CAP_SYS_RESOURCE and unrestricted prctl.",
            e,
        )

    # Independent ctypes backstop for the most security-critical bit, in
    # case harden_process() above failed partway: a crash must not dump
    # key material to a core file.
    from dsm.core.hardening import ProcessHardeningError, set_process_nondumpable

    try:
        set_process_nondumpable()
    except ProcessHardeningError as e:
        log.warning("core-dump backstop (PR_SET_DUMPABLE) failed: %s", e)

    from dsm.crypto.attest_gate import (
        MalformedAttestBuildError,
        SoftAttestNotAllowedError,
        enforce_attest_backend_policy,
    )

    try:
        enforce_attest_backend_policy(config)
    except (SoftAttestNotAllowedError, MalformedAttestBuildError) as e:
        log.error("%s", e)
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
        # stack.push_async_callback (mixing them is the classic footgun).

        # Register keystore unload first so it unwinds last — the encrypted
        # identity must stay in memory for the lifetime of the run. Mirrors
        # client.py.
        stack.callback(keystore.unload)
        stack.callback(attest_store.unload)

        rate_limiter = ServerRateLimitManager(config.listen_port)
        try:
            rate_limiter.apply()
        except RuntimeError as e:
            # Fail closed: refuse to serve without handshake-flood protection.
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

        # process_shutdown is set ONLY by the signal handlers (the whole
        # daemon is terminating). A session ending on its own (dead-peer
        # timeout, peer SESSION_CLOSE, rekey give-up) sets a SEPARATE
        # per-session event inside _run_one_session — never this one — so the
        # re-accept loop below can distinguish "accept the next client" from
        # "the process is shutting down". Set up BEFORE the accept loop so a
        # SIGTERM arriving while we wait for msg1 unblocks the loop.
        process_shutdown = asyncio.Event()
        setup_signal_handlers(process_shutdown)

        # Transport: the UDP transport lives for the whole run (bound once,
        # here, on the outer stack). TCP needs a fresh listening transport per
        # accept because listen() accepts one connection and closes its server
        # socket — that re-creation happens inside _accept_one_session, and the
        # accepted TCP transport is registered on the per-session stack.
        transport_obj: UDPTransport | TCPTransport | None
        if config.transport == "udp":
            transport_obj = UDPTransport()
            await transport_obj.bind(
                local_port=config.listen_port,
                pmtu_discover=config.pmtu_discover,
            )
            stack.push_async_callback(transport_obj.aclose)
            log.info("server listening on UDP port %d", config.listen_port)
        else:
            transport_obj = None

        fsm.transition(State.CONNECTING)

        # OUTER re-accept loop: accept one client, serve it to session-end,
        # then loop back and accept the next. Exits only on process_shutdown.
        while not process_shutdown.is_set():
            session_keys, client_pub, transport_obj = await _accept_one_session(
                config,
                fsm,
                keystore,
                attest_store,
                materials,
                cn_allowlist,
                transport_obj,
                process_shutdown,
            )
            if session_keys is None or client_pub is None or transport_obj is None:
                # process_shutdown arrived while waiting for a handshake; the
                # UDP transport unwinds with the outer stack. A held TCP
                # listening transport was never registered anywhere, so close
                # it manually here.
                if config.transport == "tcp" and transport_obj is not None:
                    await transport_obj.aclose()
                break  # clean process shutdown during accept

            await _run_one_session(
                config,
                fsm,
                keystore,
                session_keys,
                client_pub,
                transport_obj,
                process_shutdown,
            )

            # The session ended. If it was a process shutdown, the loop
            # condition breaks below. Otherwise (dead-peer / SESSION_CLOSE /
            # roam) the FSM is already back in IDLE (run_data_loops drove
            # TEARDOWN → IDLE), so move it to CONNECTING for the next accept.
            # For UDP we keep the same outer transport; for TCP
            # _accept_one_session re-creates the listener next iteration.
            if not process_shutdown.is_set():
                fsm.transition(State.CONNECTING)

        # OUTER stack cleanup (rate limiter, tcp_ts, UDP transport, store
        # unloads) happens automatically here.

    # Clean shutdown (signal arrived during accept or a live session): exit 0.
    return 0
