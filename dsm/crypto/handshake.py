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
import hmac
import json
import logging
import os
from collections.abc import Awaitable, Callable
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

# Pad every handshake message to this size so the three Noise XX messages are
# indistinguishable from data packets (which are also 1400B) on the wire.
# Otherwise a DPI rule can flag the (~32, ~96, ~64) size triple as Noise XX.
HANDSHAKE_FRAME_SIZE = 1400
_HANDSHAKE_LEN_PREFIX = 2
_HANDSHAKE_MAX_PAYLOAD = HANDSHAKE_FRAME_SIZE - _HANDSHAKE_LEN_PREFIX


def _pad_handshake(msg: bytes) -> bytes:
    """Frame a Noise message into a fixed-size padded envelope."""
    if len(msg) > _HANDSHAKE_MAX_PAYLOAD:
        raise HandshakeError(
            f"handshake message too large: {len(msg)} > {_HANDSHAKE_MAX_PAYLOAD}"
        )
    prefix = len(msg).to_bytes(_HANDSHAKE_LEN_PREFIX, "big")
    pad = os.urandom(HANDSHAKE_FRAME_SIZE - _HANDSHAKE_LEN_PREFIX - len(msg))
    return prefix + msg + pad


def _unpad_handshake(blob: bytes) -> bytes:
    """Strip the fixed-size envelope and return the inner Noise message."""
    if len(blob) != HANDSHAKE_FRAME_SIZE:
        raise HandshakeError(
            f"handshake frame wrong size: {len(blob)} != {HANDSHAKE_FRAME_SIZE}"
        )
    length = int.from_bytes(blob[:_HANDSHAKE_LEN_PREFIX], "big")
    if length > _HANDSHAKE_MAX_PAYLOAD:
        raise HandshakeError(f"handshake inner length out of range: {length}")
    return blob[_HANDSHAKE_LEN_PREFIX : _HANDSHAKE_LEN_PREFIX + length]


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
    server_static = initiator.read_message_2(msg2)

    # Validate server static key against cache (HMAC-protected)
    if known_hosts_path:
        _check_known_host(
            known_hosts_path, server_addr[0], server_static, strict_keys,
            identity=identity, server_port=server_addr[1],
        )

    # Message 3: -> s, se
    msg3 = initiator.write_message_3()
    await _send(transport, msg3, server_addr)

    # Derive session keys from handshake hash (replaces Snow transport)
    handshake_hash = bytes(initiator.get_handshake_hash())
    session_keys = tuncore.SessionKeyManager.from_handshake_hash(
        handshake_hash, is_initiator=True,
    )
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

    # Message 1: -> e (capture sender address for UDP reply)
    msg1, recv_addr = await _recv(transport)
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
    client_static = responder.read_message_3(msg3)

    # Derive session keys from handshake hash (replaces Snow transport)
    handshake_hash = bytes(responder.get_handshake_hash())
    session_keys = tuncore.SessionKeyManager.from_handshake_hash(
        handshake_hash, is_initiator=False,
    )
    log.info("handshake complete (server)")
    return session_keys, bytes(client_static)


class HandshakeError(Exception):
    pass


class KeyMismatchError(HandshakeError):
    pass


async def _send(transport: UDPTransport | TCPTransport, data: bytes, addr: tuple[str, int] | None) -> None:
    """Send a Noise message via UDP or TCP, padded to the fixed handshake size."""
    framed = _pad_handshake(data)
    if isinstance(transport, UDPTransport):
        assert addr is not None, "UDP transport requires addr"
        await transport.send(framed, addr)
    else:
        await transport.send(framed)


async def _recv(
    transport: UDPTransport | TCPTransport,
    retransmit: Callable[[], Awaitable[None]] | None = None,
) -> tuple[bytes, tuple[str, int] | None]:
    """Receive a padded handshake frame, return the inner Noise message.

    Args:
        transport: UDP or TCP transport
        retransmit: optional async callback to resend the last outgoing message
            before each retry, so the peer gets another chance to respond if
            the original send was lost.

    Returns:
        (data, addr) where addr is the sender address for UDP, None for TCP.
    """
    for attempt in range(MAX_RETRIES):
        try:
            if isinstance(transport, UDPTransport):
                frame, addr = await asyncio.wait_for(transport.recv(), HANDSHAKE_TIMEOUT)
                return _unpad_handshake(frame), addr
            else:
                frame = await asyncio.wait_for(transport.recv(), HANDSHAKE_TIMEOUT)
                return _unpad_handshake(frame), None
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


def _save_known_host(
    path: Path,
    host_key: str,
    static_key: bytes,
    identity: tuncore.IdentityKeyPair,
) -> None:
    hosts = _load_known_hosts(path, identity)
    hosts[host_key] = static_key.hex()
    _save_known_hosts_dict(path, hosts, identity)
