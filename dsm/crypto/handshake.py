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
import hashlib
import hmac
import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from dsm.net.transport.tcp import TCPTransport
from dsm.net.transport.udp import UDPTransport

if TYPE_CHECKING:
    import tuncore

log = logging.getLogger(__name__)

# Handshake timeout per message (seconds)
HANDSHAKE_TIMEOUT = 5.0
MAX_RETRIES = 3
BACKOFF_BASE = 1.0  # seconds; retry delays: 1s, 2s, 4s


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
    msg2, _ = await _recv(transport)
    server_static = initiator.read_message_2(msg2)

    # Validate server static key against cache (HMAC-protected)
    if known_hosts_path:
        _check_known_host(
            known_hosts_path, server_addr[0], server_static, strict_keys,
            identity=identity,
        )

    # Message 3: -> s, se
    msg3 = initiator.write_message_3()
    await _send(transport, msg3, server_addr)

    # Derive session keys from handshake hash (replaces Snow transport)
    handshake_hash = bytes(initiator.get_handshake_hash())
    session_keys = tuncore.SessionKeyManager.from_handshake_hash(
        handshake_hash, is_initiator=True, initial_epoch=1,
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

    # Message 3: -> s, se
    msg3, _ = await _recv(transport)
    client_static = responder.read_message_3(msg3)

    # Derive session keys from handshake hash (replaces Snow transport)
    handshake_hash = bytes(responder.get_handshake_hash())
    session_keys = tuncore.SessionKeyManager.from_handshake_hash(
        handshake_hash, is_initiator=False, initial_epoch=1,
    )
    log.info("handshake complete (server)")
    return session_keys, bytes(client_static)


class HandshakeError(Exception):
    pass


class KeyMismatchError(HandshakeError):
    pass


async def _send(transport: UDPTransport | TCPTransport, data: bytes, addr: tuple[str, int] | None) -> None:
    """Send via UDP or TCP transport."""
    if isinstance(transport, UDPTransport):
        assert addr is not None, "UDP transport requires addr"
        await transport.send(data, addr)
    else:
        await transport.send(data)


async def _recv(
    transport: UDPTransport | TCPTransport,
) -> tuple[bytes, tuple[str, int] | None]:
    """Receive via UDP or TCP transport with retry + exponential backoff.

    Returns:
        (data, addr) where addr is the sender address for UDP, None for TCP.
    """
    for attempt in range(MAX_RETRIES):
        try:
            if isinstance(transport, UDPTransport):
                data, addr = await asyncio.wait_for(transport.recv(), HANDSHAKE_TIMEOUT)
                return data, addr
            else:
                data = await asyncio.wait_for(transport.recv(), HANDSHAKE_TIMEOUT)
                return data, None
        except asyncio.TimeoutError:
            if attempt == MAX_RETRIES - 1:
                raise HandshakeError(
                    f"handshake recv timed out after {MAX_RETRIES} attempts"
                )
            delay = BACKOFF_BASE * (2 ** attempt)
            log.warning("handshake recv timeout, retry %d/%d in %.1fs",
                        attempt + 1, MAX_RETRIES, delay)
            await asyncio.sleep(delay)

    raise HandshakeError("handshake recv failed")


def _check_known_host(
    path: Path,
    server_ip: str,
    server_static: bytes,
    strict: bool,
    identity: tuncore.IdentityKeyPair | None = None,
) -> None:
    """TOFU check: verify server static key against HMAC-protected known_hosts."""
    import tuncore
    if not path.exists():
        _save_known_host(path, server_ip, server_static, identity)
        log.info("TOFU: saved server static key for %s", server_ip)
        return

    hosts = _load_known_hosts(path, identity)
    cached = hosts.get(server_ip)

    if cached is None:
        _save_known_host(path, server_ip, server_static, identity)
        log.info("TOFU: saved server static key for %s", server_ip)
        return

    if bytes.fromhex(cached) != server_static:
        msg = f"SECURITY WARNING: server static key changed for {server_ip}"
        log.critical(msg)
        if strict:
            raise KeyMismatchError(msg)
        log.warning("continuing despite key mismatch (strict_keys=False)")


def _hmac_key(identity: tuncore.IdentityKeyPair | None) -> bytes:
    """Derive HMAC key from identity secret key for known_hosts integrity."""
    import tuncore
    if identity is not None:
        return bytes(identity.derive_hmac_key(b"known-hosts"))
    return hashlib.sha256(b"dsm-known-hosts-hmac-default-insecure").digest()


def _legacy_hmac_key(identity_pub: bytes | None) -> bytes:
    """Legacy HMAC key derivation (public-key-based). Used for migration only."""
    base = identity_pub or b"dsm-known-hosts-default"
    return hashlib.sha256(b"dsm-known-hosts-hmac-" + base).digest()


def _load_known_hosts(
    path: Path, identity: tuncore.IdentityKeyPair | None = None,
) -> dict[str, str]:
    import tuncore
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
    key = _hmac_key(identity)
    expected_mac = hmac.new(key, payload, hashlib.sha256).digest()

    if not hmac.compare_digest(stored_mac, expected_mac):
        # Try legacy (public-key-based) HMAC for one-time migration
        identity_pub = bytes(identity.public_key) if identity is not None else None
        legacy_key = _legacy_hmac_key(identity_pub)
        legacy_mac = hmac.new(legacy_key, payload, hashlib.sha256).digest()
        if hmac.compare_digest(stored_mac, legacy_mac):
            log.warning("known_hosts uses legacy HMAC, migrating to secret-key-based HMAC")
            # Re-save with new HMAC
            new_mac = hmac.new(key, payload, hashlib.sha256).digest()
            path.write_bytes(new_mac + payload)
        else:
            raise HandshakeError(
                f"known_hosts HMAC verification failed for {path}. "
                "File may have been tampered with. Delete the file manually to reset trust."
            )

    try:
        return json.loads(payload)
    except json.JSONDecodeError as e:
        raise HandshakeError(f"known_hosts corrupted (invalid JSON): {e}") from e


def _save_known_host(
    path: Path,
    server_ip: str,
    static_key: bytes,
    identity: tuncore.IdentityKeyPair | None = None,
) -> None:
    import tuncore
    hosts = _load_known_hosts(path, identity)
    hosts[server_ip] = static_key.hex()
    path.parent.mkdir(parents=True, exist_ok=True)

    import os as _os
    payload = json.dumps(hosts).encode()
    key = _hmac_key(identity)
    mac = hmac.new(key, payload, hashlib.sha256).digest()
    path.write_bytes(mac + payload)
    _os.chmod(path, 0o600)
