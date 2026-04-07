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
) -> tuncore.NoiseTransport:
    """Perform Noise XX handshake as initiator (client).

    Args:
        transport: UDPTransport or TCPTransport instance
        identity: tuncore.IdentityKeyPair
        server_addr: (host, port) of the server
        known_hosts_path: path to encrypted known_hosts file
        strict_keys: abort on any key mismatch (vs warn)

    Returns:
        tuncore.NoiseTransport on success

    Raises:
        HandshakeError on failure
    """
    import tuncore

    initiator = tuncore.NoiseInitiator(identity)

    # Message 1: -> e
    msg1 = initiator.write_message_1()
    await _send(transport, msg1, server_addr)

    # Message 2: <- e, ee, s, es
    msg2 = await _recv(transport)
    server_static = initiator.read_message_2(msg2)

    # Validate server static key against cache (HMAC-protected)
    if known_hosts_path:
        _check_known_host(
            known_hosts_path, server_addr[0], server_static, strict_keys,
            identity_pub=identity.public_key,
        )

    # Message 3: -> s, se
    msg3 = initiator.write_message_3()
    await _send(transport, msg3, server_addr)

    noise_transport = initiator.into_transport()
    log.info("handshake complete (client)")
    return noise_transport


async def server_handshake(
    transport: UDPTransport | TCPTransport,
    identity: tuncore.IdentityKeyPair,
    client_addr: tuple[str, int] | None = None,
) -> tuple[tuncore.NoiseTransport, bytes]:
    """Perform Noise XX handshake as responder (server).

    Returns:
        (tuncore.NoiseTransport, client_static_pubkey)
    """
    import tuncore

    responder = tuncore.NoiseResponder(identity)

    # Message 1: -> e
    msg1 = await _recv(transport)
    responder.read_message_1(msg1)

    # Message 2: <- e, ee, s, es
    msg2 = responder.write_message_2()
    await _send(transport, msg2, client_addr)

    # Message 3: -> s, se
    msg3 = await _recv(transport)
    client_static = responder.read_message_3(msg3)

    noise_transport = responder.into_transport()
    log.info("handshake complete (server)")
    return noise_transport, bytes(client_static)


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


async def _recv(transport: UDPTransport | TCPTransport) -> bytes:
    """Receive via UDP or TCP transport with retry + exponential backoff."""
    for attempt in range(MAX_RETRIES):
        try:
            if isinstance(transport, UDPTransport):
                data, _ = await asyncio.wait_for(transport.recv(), HANDSHAKE_TIMEOUT)
                return data
            else:
                return await asyncio.wait_for(transport.recv(), HANDSHAKE_TIMEOUT)
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
    identity_pub: bytes | None = None,
) -> None:
    """TOFU check: verify server static key against HMAC-protected known_hosts."""
    if not path.exists():
        _save_known_host(path, server_ip, server_static, identity_pub)
        log.info("TOFU: saved server static key for %s", server_ip)
        return

    hosts = _load_known_hosts(path, identity_pub)
    cached = hosts.get(server_ip)

    if cached is None:
        _save_known_host(path, server_ip, server_static, identity_pub)
        log.info("TOFU: saved server static key for %s", server_ip)
        return

    if bytes.fromhex(cached) != server_static:
        msg = f"SECURITY WARNING: server static key changed for {server_ip}"
        log.critical(msg)
        if strict:
            raise KeyMismatchError(msg)
        log.warning("continuing despite key mismatch (strict_keys=False)")


def _hmac_key(identity_pub: bytes | None) -> bytes:
    """Derive HMAC key from identity public key for known_hosts integrity."""
    base = identity_pub or b"dsm-known-hosts-default"
    return hashlib.sha256(b"dsm-known-hosts-hmac-" + base).digest()


def _load_known_hosts(
    path: Path, identity_pub: bytes | None = None
) -> dict[str, str]:
    try:
        raw = path.read_bytes()
    except OSError:
        return {}

    # Format: HMAC(32 bytes) || JSON payload
    if len(raw) < 32:
        log.warning("known_hosts too short, treating as empty")
        return {}

    stored_mac = raw[:32]
    payload = raw[32:]
    key = _hmac_key(identity_pub)
    expected_mac = hmac.new(key, payload, hashlib.sha256).digest()

    if not hmac.compare_digest(stored_mac, expected_mac):
        log.warning("known_hosts HMAC mismatch — file may be tampered, treating as empty")
        return {}

    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return {}


def _save_known_host(
    path: Path,
    server_ip: str,
    static_key: bytes,
    identity_pub: bytes | None = None,
) -> None:
    hosts = _load_known_hosts(path, identity_pub)
    hosts[server_ip] = static_key.hex()
    path.parent.mkdir(parents=True, exist_ok=True)

    payload = json.dumps(hosts).encode()
    key = _hmac_key(identity_pub)
    mac = hmac.new(key, payload, hashlib.sha256).digest()
    path.write_bytes(mac + payload)
