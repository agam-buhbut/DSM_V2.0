"""Noise XX handshake orchestration over transport.

Client (initiator):
    msg1 = write_message_1()  -> send
    recv -> read_message_2()  -> server_static_key
    msg3 = write_message_3()  -> send
    -> NoiseTransport

Server (responder):
    recv -> read_message_1()
    msg2 = write_message_2()  -> send
    recv -> read_message_3()  -> client_static_key
    -> NoiseTransport
"""

from __future__ import annotations

import asyncio
import contextlib
import fcntl
import hmac
import json
import logging
import os
from collections.abc import Awaitable, Callable, Generator
from pathlib import Path
from typing import TYPE_CHECKING

from dsm.core.atomic_io import atomic_write
from dsm.core.path_security import (
    InsecureFilePermissionsError,
    check_user_file_permissions,
)
from dsm.net.transport.tcp import TCPTransport
from dsm.net.transport.udp import UDPTransport

if TYPE_CHECKING:
    import tuncore

log = logging.getLogger(__name__)

# Handshake timeout per message (seconds)
HANDSHAKE_TIMEOUT = 5.0
MAX_RETRIES = 3
BACKOFF_BASE = 1.0  # seconds; retry delays: 1s, 2s, 4s

DEFAULT_KNOWN_HOSTS_PATH = Path("/opt/mtun/known_hosts.json")

# Every frame on the wire during the handshake is exactly this many bytes,
# so the three Noise XX messages + two bootstrap messages are indistinguishable
# from a normal 1400B data packet. The Rust side already pre-pads Noise XX
# output to this size; bootstrap messages are padded explicitly in Python
# because NoiseTransport.encrypt returns only the ciphertext+tag.
HANDSHAKE_FRAME_SIZE = 1400

# Bootstrap exchange: the plaintext is a 32-byte X25519 public key.
# NoiseTransport.encrypt(32) -> 32 + 16 (GCM tag) = 48 bytes.
BOOTSTRAP_CIPHERTEXT_SIZE = 32 + 16


def _pad_to_frame(data: bytes, expected_size: int) -> bytes:
    """Pad a handshake ciphertext to HANDSHAKE_FRAME_SIZE with CSPRNG bytes.

    No length prefix on the wire — both sides know the expected ciphertext
    size from the protocol (pubkey + GCM tag = 48B). This matches the
    Rust-side `pack_handshake` construction so all 5 handshake frames
    have the same on-the-wire structure.
    """
    if len(data) != expected_size:
        raise HandshakeError(
            f"handshake payload size mismatch: {len(data)} != {expected_size}"
        )
    return bytes(data) + os.urandom(HANDSHAKE_FRAME_SIZE - expected_size)


def _unpad_from_frame(blob: bytes, expected_size: int) -> bytes:
    """Extract the ciphertext prefix from a fixed-size handshake frame."""
    if len(blob) != HANDSHAKE_FRAME_SIZE:
        raise HandshakeError(
            f"handshake frame wrong size: {len(blob)} != {HANDSHAKE_FRAME_SIZE}"
        )
    return bytes(blob[:expected_size])


async def client_handshake(
    transport: UDPTransport | TCPTransport,
    identity: tuncore.IdentityKeyPair,
    server_addr: tuple[str, int],
    known_hosts_path: Path | None = None,
    strict_keys: bool = True,
) -> tuple[tuncore.SessionKeyManager, bytes]:
    """Perform Noise XX handshake as initiator (client).

    Args:
        transport: UDPTransport or TCPTransport instance
        identity: tuncore.IdentityKeyPair
        server_addr: (host, port) of the server
        known_hosts_path: path to encrypted known_hosts file
        strict_keys: abort on any key mismatch (vs warn)

    Returns:
        (SessionKeyManager, handshake_hash) on success

    Raises:
        HandshakeError on failure
    """
    import tuncore

    initiator = tuncore.NoiseInitiator(identity)

    # Message 1: -> e
    msg1 = initiator.write_message_1()
    await _send(transport, msg1, server_addr)

    # Message 2: <- e, ee, s, es
    # Retransmit msg1 on timeout so the server gets another chance to respond
    async def _retransmit_msg1() -> None:
        await _send(transport, msg1, server_addr)

    msg2, recv_addr = await _recv(transport, retransmit=_retransmit_msg1)
    if isinstance(transport, UDPTransport) and recv_addr != server_addr:
        raise HandshakeError(
            f"msg2 from unexpected source {recv_addr}, expected {server_addr}"
        )
    # PyO3 hands us Vec<u8> as Python list[int]; coerce to bytes once at
    # the FFI boundary so every downstream consumer (TOFU known_hosts
    # serialization, HMAC compare, log .hex()) works on a real bytes object.
    server_static = bytes(initiator.read_message_2(msg2))

    # Validate server static key against cache (HMAC-protected)
    if known_hosts_path:
        _check_known_host(
            known_hosts_path, server_addr[0], server_static, strict_keys,
            identity=identity, server_port=server_addr[1],
        )

    # Message 3: -> s, se
    # Single send — loss recovery is handled via the bootstrap-round retransmit
    # below, which resends msg3 + bootstrap_init together. Multi-sending msg3
    # alone would be ambiguous: the server processes msg3 then waits for
    # bootstrap_init, and a duplicate msg3 would be misread as bootstrap_init.
    msg3 = initiator.write_message_3()
    await _send(transport, msg3, server_addr)

    # Snapshot the handshake hash before transitioning to transport state —
    # into_transport() consumes the initiator.
    handshake_hash = bytes(initiator.get_handshake_hash())

    # Transition to Noise transport and perform ephemeral DH bootstrap
    # to derive keys from SECRET material (not public handshake hash).
    noise_transport = initiator.into_transport()
    client_secret, client_public = tuncore.generate_ephemeral()
    try:
        # Send client ephemeral public via Noise transport (encrypted), padded
        # to HANDSHAKE_FRAME_SIZE to match the 3 Noise XX frame sizes.
        bootstrap_init_ct = bytes(noise_transport.encrypt(bytes(client_public)))
        bootstrap_init_frame = _pad_to_frame(bootstrap_init_ct, BOOTSTRAP_CIPHERTEXT_SIZE)
        await _send(transport, bootstrap_init_frame, server_addr)

        # Receive server ephemeral public. On timeout, resend BOTH msg3 and
        # the bootstrap frame — we don't know which was lost, and resending
        # only msg3 would cause the server to wait for bootstrap forever
        # while resending only bootstrap_init would leave server stuck on
        # msg3 recv (rejecting the bootstrap frame as an invalid msg3).
        async def _retransmit_bootstrap() -> None:
            await _send(transport, msg3, server_addr)
            await _send(transport, bootstrap_init_frame, server_addr)

        bootstrap_resp_frame, _ = await _recv(transport, retransmit=_retransmit_bootstrap)
        bootstrap_resp_ct = _unpad_from_frame(bootstrap_resp_frame, BOOTSTRAP_CIPHERTEXT_SIZE)
        server_public = noise_transport.decrypt(bootstrap_resp_ct)
        if len(server_public) != 32:
            raise HandshakeError("invalid bootstrap ephemeral from server")

        # Derive session keys from ephemeral DH (secure, not public h).
        # Rust-side zeroizes the secret after consumption.
        session_keys = tuncore.bootstrap_session_from_dh(
            bytes(client_secret), bytes(server_public), is_initiator=True
        )
    finally:
        # Drop the Python reference to the ephemeral secret immediately so the
        # GC can collect. Python bytes are immutable — real zeroization happens
        # Rust-side; this just minimizes the lifetime of the copy in the PyObject.
        del client_secret

    log.info("handshake complete (client)")
    return session_keys, handshake_hash


async def server_handshake(
    transport: UDPTransport | TCPTransport,
    identity: tuncore.IdentityKeyPair,
    client_addr: tuple[str, int] | None = None,
) -> tuple[tuncore.SessionKeyManager, bytes]:
    """Perform Noise XX handshake as responder (server).

    Returns:
        (SessionKeyManager, client_static_pubkey)
    """
    import tuncore

    responder = tuncore.NoiseResponder(identity)

    # Message 1: -> e (capture sender address for UDP reply).
    # Wait indefinitely — there is no peer state to time out against
    # before any client has connected. SIGINT/SIGTERM still cancels
    # this task cleanly via the AsyncExitStack shutdown.
    msg1, recv_addr = await _recv(transport, indefinite=True)
    responder.read_message_1(msg1)
    addr = recv_addr or client_addr

    # Message 2: <- e, ee, s, es
    msg2 = responder.write_message_2()
    await _send(transport, msg2, addr)

    # Message 3: -> s, se (validate source matches msg1 sender for UDP)
    # Retransmit msg2 on timeout so the client gets another chance to respond
    async def _retransmit_msg2() -> None:
        await _send(transport, msg2, addr)

    msg3, msg3_addr = await _recv(transport, retransmit=_retransmit_msg2)
    if isinstance(transport, UDPTransport) and addr is not None and msg3_addr != addr:
        raise HandshakeError(
            f"msg3 from unexpected source {msg3_addr}, expected {addr}"
        )
    # Coerce list[int] -> bytes at the FFI boundary (see server_handshake).
    client_static = bytes(responder.read_message_3(msg3))

    # Snapshot the handshake hash before transitioning to transport state —
    # into_transport() consumes the responder.
    handshake_hash = bytes(responder.get_handshake_hash())

    # Transition to Noise transport and perform ephemeral DH bootstrap
    # to derive keys from SECRET material (not public handshake hash).
    noise_transport = responder.into_transport()

    # Receive client ephemeral public
    bootstrap_init_frame, _ = await _recv(transport)
    bootstrap_init_ct = _unpad_from_frame(bootstrap_init_frame, BOOTSTRAP_CIPHERTEXT_SIZE)
    client_public = noise_transport.decrypt(bootstrap_init_ct)
    if len(client_public) != 32:
        raise HandshakeError("invalid bootstrap ephemeral from client")

    # Generate server ephemeral and send it back
    server_secret, server_public = tuncore.generate_ephemeral()
    try:
        bootstrap_resp_ct = bytes(noise_transport.encrypt(bytes(server_public)))
        bootstrap_resp_frame = _pad_to_frame(bootstrap_resp_ct, BOOTSTRAP_CIPHERTEXT_SIZE)
        await _send(transport, bootstrap_resp_frame, addr)

        # Derive session keys from ephemeral DH (secure, not public h).
        # Rust-side zeroizes the secret after consumption.
        session_keys = tuncore.bootstrap_session_from_dh(
            bytes(server_secret), bytes(client_public), is_initiator=False
        )
    finally:
        del server_secret

    log.info("handshake complete (server)")
    # handshake_hash is already captured above; returned for diagnostics
    _ = handshake_hash  # noqa: F841 (kept for symmetry with client)
    return session_keys, client_static


class HandshakeError(Exception):
    pass


class KeyMismatchError(HandshakeError):
    pass


async def _send(
    transport: UDPTransport | TCPTransport,
    data: bytes,
    addr: tuple[str, int] | None,
) -> None:
    """Send a pre-framed handshake message (exactly HANDSHAKE_FRAME_SIZE bytes).

    Callers pass either a Noise XX message (Rust pads to HANDSHAKE_FRAME_SIZE)
    or a bootstrap frame produced by ``_pad_to_frame``. No further wrapping
    happens here; a size check catches misuse.
    """
    data = bytes(data)
    if len(data) != HANDSHAKE_FRAME_SIZE:
        raise HandshakeError(
            f"handshake send size mismatch: {len(data)} != {HANDSHAKE_FRAME_SIZE}"
        )
    if isinstance(transport, UDPTransport):
        assert addr is not None, "UDP transport requires addr"
        await transport.send(data, addr)
    else:
        await transport.send(data)


async def _recv(
    transport: UDPTransport | TCPTransport,
    retransmit: Callable[[], Awaitable[None]] | None = None,
    *,
    indefinite: bool = False,
) -> tuple[bytes, tuple[str, int] | None]:
    """Receive a HANDSHAKE_FRAME_SIZE frame and return it verbatim.

    Callers are responsible for extracting the inner payload (Rust does
    this for Noise XX via ``read_message_*``; bootstrap uses
    ``_unpad_from_frame``).

    Args:
        transport: UDP or TCP transport
        retransmit: optional async callback to resend the last outgoing
            message before each retry, so the peer gets another chance to
            respond if the original send was lost. Ignored when
            ``indefinite=True``.
        indefinite: when True, block until a packet arrives or the task
            is cancelled — no MAX_RETRIES timeout. Used by the server's
            initial msg1 wait, where there is no in-flight peer state to
            time out against (we're literally waiting for any client to
            connect). Cancellation (SIGINT/SIGTERM via the AsyncExitStack
            shutdown) still tears the recv down cleanly.

    Returns:
        (frame, addr) where addr is the sender address for UDP, None for TCP.
    """
    if indefinite:
        if isinstance(transport, UDPTransport):
            frame, addr = await transport.recv()
            return bytes(frame), addr
        frame = await transport.recv()
        return bytes(frame), None

    for attempt in range(MAX_RETRIES):
        try:
            if isinstance(transport, UDPTransport):
                frame, addr = await asyncio.wait_for(transport.recv(), HANDSHAKE_TIMEOUT)
                return bytes(frame), addr
            else:
                frame = await asyncio.wait_for(transport.recv(), HANDSHAKE_TIMEOUT)
                return bytes(frame), None
        except asyncio.TimeoutError:
            if attempt == MAX_RETRIES - 1:
                raise HandshakeError(
                    f"handshake recv timed out after {MAX_RETRIES} attempts"
                )
            delay = BACKOFF_BASE * (2 ** attempt)
            log.warning("handshake recv timeout, retry %d/%d in %.1fs",
                        attempt + 1, MAX_RETRIES, delay)
            await asyncio.sleep(delay)
            if retransmit is not None:
                log.debug("retransmitting last handshake message (attempt %d)", attempt + 1)
                await retransmit()

    raise HandshakeError("handshake recv failed")


def _check_known_host(
    path: Path,
    server_ip: str,
    server_static: bytes,
    strict: bool,
    identity: tuncore.IdentityKeyPair,
    server_port: int = 0,
) -> None:
    """TOFU check: verify server static key against HMAC-protected known_hosts."""
    host_key = f"{server_ip}:{server_port}" if server_port else server_ip

    if not path.exists():
        _save_known_host(path, host_key, server_static, identity)
        log.info("TOFU: saved server static key for %s", host_key)
        return

    hosts = _load_known_hosts(path, identity)
    cached = hosts.get(host_key)

    if cached is None:
        # No entry under the canonical host:port key. Do fresh TOFU, even if
        # a stale entry exists under an older key format (e.g. bare IP). We
        # do NOT migrate the trust relationship from an older format, since
        # the old entry's provenance can't be re-verified here.
        _save_known_host(path, host_key, server_static, identity)
        log.info("TOFU: saved server static key for %s", host_key)
        return

    if not hmac.compare_digest(bytes.fromhex(cached), server_static):
        msg = f"SECURITY WARNING: server static key changed for {host_key}"
        log.critical(msg)
        if strict:
            raise KeyMismatchError(msg)
        log.warning("continuing despite key mismatch (strict_keys=False)")


def _known_hosts_hmac(identity: tuncore.IdentityKeyPair, payload: bytes) -> bytes:
    """Compute HMAC-SHA256 over payload using a key derived from the identity's
    secret. The derived key never crosses the FFI boundary (audit H2)."""
    return bytes(identity.compute_hmac(b"known-hosts", payload))


def _load_known_hosts(
    path: Path, identity: tuncore.IdentityKeyPair,
) -> dict[str, str]:
    if not path.exists():
        return {}

    try:
        check_user_file_permissions(path)
    except InsecureFilePermissionsError as e:
        raise HandshakeError(str(e)) from e

    try:
        raw = path.read_bytes()
    except OSError:
        return {}

    # Format: HMAC(32 bytes) || JSON payload
    if len(raw) < 32:
        raise HandshakeError(
            f"known_hosts file too short ({len(raw)} bytes), possibly corrupted. "
            f"Delete {path} manually to reset trust."
        )

    stored_mac = raw[:32]
    payload = raw[32:]

    # Try current (secret-key-based) HMAC first
    expected_mac = _known_hosts_hmac(identity, payload)

    if not hmac.compare_digest(stored_mac, expected_mac):
        raise HandshakeError(
            f"known_hosts HMAC verification failed for {path}. "
            "File may have been tampered with. Delete the file manually to reset trust."
        )

    try:
        return json.loads(payload)
    except json.JSONDecodeError as e:
        raise HandshakeError(f"known_hosts corrupted (invalid JSON): {e}") from e


def _save_known_hosts_dict(
    path: Path,
    hosts: dict[str, str],
    identity: tuncore.IdentityKeyPair,
) -> None:
    """Write a known_hosts dict to disk with HMAC integrity."""
    payload = json.dumps(hosts).encode()
    mac = _known_hosts_hmac(identity, payload)
    atomic_write(path, mac + payload)


@contextlib.contextmanager
def _known_hosts_lock(path: Path) -> Generator[None, None, None]:
    """Hold an exclusive flock on a sidecar file across read-modify-write.

    Without this, two clients TOFU-saving to the same path simultaneously
    can race: both read the same baseline, both add their entry, the
    second atomic_write rename wins, and the first entry is lost.
    """
    lock_path = path.with_suffix(path.suffix + ".lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _save_known_host(
    path: Path,
    host_key: str,
    static_key: bytes,
    identity: tuncore.IdentityKeyPair,
) -> None:
    with _known_hosts_lock(path):
        hosts = _load_known_hosts(path, identity)
        hosts[host_key] = static_key.hex()
        _save_known_hosts_dict(path, hosts, identity)
