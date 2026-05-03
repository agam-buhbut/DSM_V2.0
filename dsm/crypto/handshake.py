"""Noise XX handshake orchestration over transport.

Both peers carry a CA-signed device cert + a per-handshake binding
signature inside the Noise XX msg2 (server->client) and msg3
(client->server) payloads. The cert binds:
  * device subject CN
  * the hardware-bound ECDSA P-256 signing pubkey
  * the device's X25519 Noise static (via custom critical extension)

The binding signature is over the Noise handshake hash captured at
the point the message is sent — post-msg1 for msg2, post-msg2 for
msg3 — and is freshness/role-bound, so a captured payload cannot
replay against a different handshake or role.

Client (initiator):
    msg1 = write_message_1()                       -> send
    recv -> read_message_2() -> (server_static, attest_payload)
    verify_attest_payload(server_attest, role=RESPONDER) -> server_cert
    enforce: server_cert.subject_cn == expected_server_cn
    msg3 = write_message_3(our_attest_payload)     -> send
    -> NoiseTransport (then bootstrap DH)

Server (responder):
    recv -> read_message_1()
    msg2 = write_message_2(our_attest_payload)     -> send
    recv -> read_message_3() -> (client_static, attest_payload)
    verify_attest_payload(client_attest, role=INITIATOR) -> client_cert
    enforce: cn_allowlist.is_allowed(client_cert.subject_cn)
    enforce: not crl.is_revoked(client_cert.serial_number) (if CRL)
    -> NoiseTransport (then bootstrap DH)
"""

from __future__ import annotations

import asyncio
import logging
import os
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

from cryptography.x509 import Certificate as X509Certificate
from cryptography.x509 import ObjectIdentifier

from dsm.core import netaudit
from dsm.crypto.attest import (
    AttestError,
    PeerRole,
    build_attest_payload,
    verify_attest_payload,
)
from dsm.crypto.cert import CertError
from dsm.crypto.cert_allowlist import CNAllowlist
from dsm.crypto.crl import CRL, CRLError
from dsm.net.transport.tcp import TCPTransport
from dsm.net.transport.udp import UDPTransport

if TYPE_CHECKING:
    import tuncore

log = logging.getLogger(__name__)

HANDSHAKE_TIMEOUT = 5.0
MAX_RETRIES = 3
BACKOFF_BASE = 1.0  # retry delays: 1s, 2s, 4s

# Every frame on the wire during the handshake is exactly this many bytes.
# The Rust side already pre-pads Noise XX output to this size; bootstrap
# messages are padded explicitly in Python because NoiseTransport.encrypt
# returns only the ciphertext+tag.
HANDSHAKE_FRAME_SIZE = 1400

# Bootstrap exchange: plaintext is a 32-byte X25519 public key.
# NoiseTransport.encrypt(32) -> 32 + 16 (GCM tag) = 48 bytes.
BOOTSTRAP_CIPHERTEXT_SIZE = 32 + 16


class HandshakeError(Exception):
    pass


class CertAuthError(HandshakeError):
    """Cert / binding-attestation verification failed."""


class CNNotAllowedError(CertAuthError):
    """Server saw a client cert whose CN is not in the allowlist."""


class CNMismatchError(CertAuthError):
    """Client saw a server cert whose CN does not match expected_server_cn."""


class CertRevokedError(CertAuthError):
    """Peer's cert serial appears in the CRL."""


def _pad_to_frame(data: bytes, expected_size: int) -> bytes:
    """Pad a handshake ciphertext to HANDSHAKE_FRAME_SIZE with CSPRNG bytes."""
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
    *,
    attest_key: tuncore.AttestKey,
    cert_der: bytes,
    ca_root: X509Certificate,
    expected_server_cn: str,
    crl: CRL | None = None,
    required_server_eku: ObjectIdentifier | None = None,
    rotation_packets: int | None = None,
    rotation_seconds: int | None = None,
) -> tuple[tuncore.SessionKeyManager, bytes]:
    """Perform Noise XX handshake as initiator (client).

    Args:
        transport: UDPTransport or TCPTransport.
        identity: long-term Noise X25519 keypair (this device's).
        server_addr: (host, port) of the server.
        attest_key: hardware-bound ECDSA P-256 signing key (this
            device's). Must match the public key embedded in
            ``cert_der`` (caller verifies at startup).
        cert_der: DER-encoded device cert for this client (issued by
            the CA, with the noiseStaticBinding extension carrying the
            current device's Noise static pub).
        ca_root: pinned CA root cert.
        expected_server_cn: server cert subject CN we will accept.
        crl: optional revocation list (will be consulted for the
            received server cert's serial number).
        required_server_eku: optional EKU OID required on the server
            cert (typically id-kp-serverAuth).

    Returns:
        (SessionKeyManager, handshake_hash) on success.

    Raises:
        HandshakeError on transport/protocol failure.
        CertAuthError on cert validation / CN policy / CRL failure.
    """
    import tuncore

    initiator = tuncore.NoiseInitiator(identity)
    our_static_pub = bytes(identity.public_key)

    started_at = asyncio.get_event_loop().time()
    netaudit.emit(
        "handshake_start",
        role="client",
        server_addr=f"{server_addr[0]}:{server_addr[1]}",
        expected_server_cn=expected_server_cn,
    )

    # Message 1: -> e
    msg1 = initiator.write_message_1()
    await _send(transport, msg1, server_addr)

    # Message 2: <- e, ee, s, es [+ server attest payload]
    async def _retransmit_msg1() -> None:
        await _send(transport, msg1, server_addr)

    msg2, recv_addr = await _recv(transport, retransmit=_retransmit_msg1)
    if isinstance(transport, UDPTransport) and recv_addr != server_addr:
        raise HandshakeError(
            f"msg2 from unexpected source {recv_addr}, expected {server_addr}"
        )

    # Snapshot the handshake hash that signs msg2's binding *before*
    # read_message_2 advances the Noise state past it.
    binding_hash_for_msg2 = bytes(initiator.get_handshake_hash())
    server_static_raw, server_attest_payload = initiator.read_message_2(msg2)
    server_static = bytes(server_static_raw)

    # Verify server attestation: cert chain → CA, binding → server_static,
    # signature over (binding_hash_for_msg2, server_static, RESPONDER).
    try:
        server_cert = verify_attest_payload(
            payload=bytes(server_attest_payload),
            ca_root=ca_root,
            handshake_hash=binding_hash_for_msg2,
            expected_remote_static=server_static,
            expected_peer_role=PeerRole.RESPONDER,
            required_eku=required_server_eku,
        )
    except (AttestError, CertError) as e:
        raise CertAuthError(f"server attestation verify failed: {e}") from e

    if server_cert.subject_cn != expected_server_cn:
        raise CNMismatchError(
            f"server CN {server_cert.subject_cn!r} does not match "
            f"expected {expected_server_cn!r}"
        )
    if crl is not None:
        try:
            if crl.is_revoked(server_cert.serial_number):
                raise CertRevokedError(
                    f"server cert serial {server_cert.serial_number} "
                    "is revoked"
                )
        except CRLError as e:
            raise CertAuthError(f"CRL check failed: {e}") from e

    # Message 3: -> s, se [+ client attest payload]
    # Snapshot binding hash *before* write_message_3 advances Noise state.
    binding_hash_for_msg3 = bytes(initiator.get_handshake_hash())
    our_attest_payload = build_attest_payload(
        attest_key=attest_key,
        cert_der=cert_der,
        handshake_hash=binding_hash_for_msg3,
        our_static_pub=our_static_pub,
        our_role=PeerRole.INITIATOR,
    )
    msg3 = initiator.write_message_3(our_attest_payload)
    await _send(transport, msg3, server_addr)

    # Final handshake hash (post-msg3) — used by bootstrap DH key
    # derivation (downstream callers).
    handshake_hash = bytes(initiator.get_handshake_hash())

    noise_transport = initiator.into_transport()
    client_secret, client_public = tuncore.generate_ephemeral()
    try:
        bootstrap_init_ct = bytes(
            noise_transport.encrypt(bytes(client_public))
        )
        bootstrap_init_frame = _pad_to_frame(
            bootstrap_init_ct, BOOTSTRAP_CIPHERTEXT_SIZE
        )
        await _send(transport, bootstrap_init_frame, server_addr)

        # Receive server ephemeral public. On timeout, resend BOTH msg3 and
        # the bootstrap frame — we don't know which was lost, and
        # resending only one would deadlock the protocol step.
        async def _retransmit_bootstrap() -> None:
            await _send(transport, msg3, server_addr)
            await _send(transport, bootstrap_init_frame, server_addr)

        bootstrap_resp_frame, _ = await _recv(
            transport, retransmit=_retransmit_bootstrap
        )
        bootstrap_resp_ct = _unpad_from_frame(
            bootstrap_resp_frame, BOOTSTRAP_CIPHERTEXT_SIZE
        )
        server_public = noise_transport.decrypt(bootstrap_resp_ct)
        if len(server_public) != 32:
            raise HandshakeError(
                "invalid bootstrap ephemeral from server"
            )

        session_keys = tuncore.bootstrap_session_from_dh(
            bytes(client_secret),
            bytes(server_public),
            is_initiator=True,
            rotation_packets=rotation_packets,
            rotation_seconds=rotation_seconds,
        )
    finally:
        del client_secret

    duration_s = asyncio.get_event_loop().time() - started_at
    log.info(
        "handshake complete (client) — server_cn=%s",
        server_cert.subject_cn,
    )
    netaudit.emit(
        "handshake_end",
        role="client",
        outcome="ok",
        peer_cn=server_cert.subject_cn,
        peer_serial=server_cert.serial_number,
        duration_s=round(duration_s, 4),
    )
    return session_keys, handshake_hash


async def server_handshake(
    transport: UDPTransport | TCPTransport,
    identity: tuncore.IdentityKeyPair,
    *,
    attest_key: tuncore.AttestKey,
    cert_der: bytes,
    ca_root: X509Certificate,
    cn_allowlist: CNAllowlist,
    crl: CRL | None = None,
    required_client_eku: ObjectIdentifier | None = None,
    client_addr: tuple[str, int] | None = None,
    rotation_packets: int | None = None,
    rotation_seconds: int | None = None,
) -> tuple[tuncore.SessionKeyManager, bytes]:
    """Perform Noise XX handshake as responder (server).

    Returns:
        (SessionKeyManager, client_static_pubkey)

    Raises:
        HandshakeError on transport/protocol failure.
        CertAuthError / CNNotAllowedError / CertRevokedError on cert
            policy failure.
    """
    import tuncore

    responder = tuncore.NoiseResponder(identity)
    our_static_pub = bytes(identity.public_key)

    netaudit.emit(
        "handshake_start",
        role="server",
        client_addr=(
            f"{client_addr[0]}:{client_addr[1]}" if client_addr else None
        ),
    )
    started_at: float | None = None  # set after msg1 arrives

    # Message 1: -> e (capture sender address for UDP reply).
    # Wait indefinitely — there is no peer state to time out against
    # before any client has connected.
    msg1, recv_addr = await _recv(transport, indefinite=True)
    started_at = asyncio.get_event_loop().time()
    responder.read_message_1(msg1)
    addr = recv_addr or client_addr

    # Message 2: <- e, ee, s, es [+ server attest payload]
    binding_hash_for_msg2 = bytes(responder.get_handshake_hash())
    our_attest_payload = build_attest_payload(
        attest_key=attest_key,
        cert_der=cert_der,
        handshake_hash=binding_hash_for_msg2,
        our_static_pub=our_static_pub,
        our_role=PeerRole.RESPONDER,
    )
    msg2 = responder.write_message_2(our_attest_payload)
    await _send(transport, msg2, addr)

    # Message 3: -> s, se [+ client attest payload]
    async def _retransmit_msg2() -> None:
        await _send(transport, msg2, addr)

    msg3, msg3_addr = await _recv(transport, retransmit=_retransmit_msg2)
    if (
        isinstance(transport, UDPTransport)
        and addr is not None
        and msg3_addr != addr
    ):
        raise HandshakeError(
            f"msg3 from unexpected source {msg3_addr}, expected {addr}"
        )

    binding_hash_for_msg3 = bytes(responder.get_handshake_hash())
    client_static_raw, client_attest_payload = responder.read_message_3(
        msg3
    )
    client_static = bytes(client_static_raw)

    try:
        client_cert = verify_attest_payload(
            payload=bytes(client_attest_payload),
            ca_root=ca_root,
            handshake_hash=binding_hash_for_msg3,
            expected_remote_static=client_static,
            expected_peer_role=PeerRole.INITIATOR,
            required_eku=required_client_eku,
        )
    except (AttestError, CertError) as e:
        raise CertAuthError(f"client attestation verify failed: {e}") from e

    if not cn_allowlist.is_allowed(client_cert.subject_cn):
        raise CNNotAllowedError(
            f"client CN {client_cert.subject_cn!r} not in allowlist"
        )
    if crl is not None:
        try:
            if crl.is_revoked(client_cert.serial_number):
                raise CertRevokedError(
                    f"client cert serial {client_cert.serial_number} "
                    "is revoked"
                )
        except CRLError as e:
            raise CertAuthError(f"CRL check failed: {e}") from e

    # Final handshake hash (post-msg3).
    handshake_hash = bytes(responder.get_handshake_hash())
    noise_transport = responder.into_transport()

    # Bootstrap: receive client ephemeral, send server ephemeral.
    bootstrap_init_frame, _ = await _recv(transport)
    bootstrap_init_ct = _unpad_from_frame(
        bootstrap_init_frame, BOOTSTRAP_CIPHERTEXT_SIZE
    )
    client_public = noise_transport.decrypt(bootstrap_init_ct)
    if len(client_public) != 32:
        raise HandshakeError("invalid bootstrap ephemeral from client")

    server_secret, server_public = tuncore.generate_ephemeral()
    try:
        bootstrap_resp_ct = bytes(
            noise_transport.encrypt(bytes(server_public))
        )
        bootstrap_resp_frame = _pad_to_frame(
            bootstrap_resp_ct, BOOTSTRAP_CIPHERTEXT_SIZE
        )
        await _send(transport, bootstrap_resp_frame, addr)

        session_keys = tuncore.bootstrap_session_from_dh(
            bytes(server_secret),
            bytes(client_public),
            is_initiator=False,
            rotation_packets=rotation_packets,
            rotation_seconds=rotation_seconds,
        )
    finally:
        del server_secret

    duration_s = (
        asyncio.get_event_loop().time() - started_at
        if started_at is not None
        else 0.0
    )
    log.info(
        "handshake complete (server) — client_cn=%s",
        client_cert.subject_cn,
    )
    netaudit.emit(
        "handshake_end",
        role="server",
        outcome="ok",
        peer_cn=client_cert.subject_cn,
        peer_serial=client_cert.serial_number,
        duration_s=round(duration_s, 4),
    )
    _ = handshake_hash  # captured for diagnostic symmetry with client
    return session_keys, client_static


async def _send(
    transport: UDPTransport | TCPTransport,
    data: bytes,
    addr: tuple[str, int] | None,
) -> None:
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
    """Receive a HANDSHAKE_FRAME_SIZE frame.

    Args:
        retransmit: optional async callback resending the last outgoing
            message before each retry, so peer gets another chance to
            respond if our send was lost. Ignored when ``indefinite=True``.
        indefinite: when True, block until a packet arrives or the task
            is cancelled — no MAX_RETRIES timeout. Used by the server's
            initial msg1 wait.
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
                frame, addr = await asyncio.wait_for(
                    transport.recv(), HANDSHAKE_TIMEOUT
                )
                return bytes(frame), addr
            else:
                frame = await asyncio.wait_for(
                    transport.recv(), HANDSHAKE_TIMEOUT
                )
                return bytes(frame), None
        except asyncio.TimeoutError:
            if attempt == MAX_RETRIES - 1:
                raise HandshakeError(
                    f"handshake recv timed out after {MAX_RETRIES} attempts"
                )
            delay = BACKOFF_BASE * (2**attempt)
            log.warning(
                "handshake recv timeout, retry %d/%d in %.1fs",
                attempt + 1,
                MAX_RETRIES,
                delay,
            )
            await asyncio.sleep(delay)
            if retransmit is not None:
                log.debug(
                    "retransmitting last handshake message (attempt %d)",
                    attempt + 1,
                )
                await retransmit()

    raise HandshakeError("handshake recv failed")
