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
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, TypeVar

from cryptography.x509 import Certificate as X509Certificate
from cryptography.x509 import ObjectIdentifier

from dsm.core import netaudit
from dsm.core.log import RepeatLog
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

# One for the whole module, so the count spans attempts: a peer that keeps
# resending the same message does so across retries too.
_skip_log = RepeatLog(log, logging.DEBUG)

HANDSHAKE_TIMEOUT = 5.0
MAX_RETRIES = 3
BACKOFF_BASE = 1.0  # retry delays: 1s, 2s, 4s
# Bound the server's wait for the FIRST client message. A spoofed UDP msg1
# that passes the low-order check but is never followed by msg3 would
# otherwise lock the server's single handshake coroutine indefinitely.
# After this timeout the caller (run_server's retry loop) is free to start
# a fresh accept.
MSG1_WAIT_TIMEOUT = 30.0

# Every frame on the wire during the handshake is exactly this many bytes.
# The Rust side already pre-pads Noise XX output to this size; bootstrap
# messages are padded explicitly in Python because NoiseTransport.encrypt
# returns only the ciphertext+tag.
HANDSHAKE_FRAME_SIZE = 1400

# Bootstrap exchange: plaintext is a 32-byte X25519 public key.
# NoiseTransport.encrypt(32) -> 32 + 16 (GCM tag) = 48 bytes.
BOOTSTRAP_CIPHERTEXT_SIZE = 32 + 16

# Bytes [0:32] of msg1 are the client's Noise ephemeral key. A client that
# hears no msg2 resends msg1, and the copy can reach the server while it
# waits for msg3 or for the bootstrap frame. A later handshake message
# repeats those 32 bytes only by chance (2**-256). Only they are compared,
# so a resend whose padding differs still matches.
_MSG1_EPHEMERAL_SIZE = 32

# Under load the server answers msg1 with a cookie reply (wire v2). A client
# takes at most this many per attempt, then fails it; the next attempt starts
# over. Two cover a cookie secret that changed between reply and resend.
MAX_COOKIE_REPLIES = 2


def _is_resent_msg1(frame: bytes, msg1: bytes) -> bool:
    """True if ``frame`` is a copy of ``msg1`` (same size, same ephemeral)."""
    # The ephemeral key is public, so a plain compare is fine.
    return (
        len(frame) == HANDSHAKE_FRAME_SIZE
        and frame[:_MSG1_EPHEMERAL_SIZE] == msg1[:_MSG1_EPHEMERAL_SIZE]
    )


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


class ClientRefusedError(HandshakeError):
    """The server's rules refused a client that passed every check.

    Raised by an ``admit_client`` hook (see :func:`server_handshake`), for
    example while another client holds the server's one session.
    """


@dataclass(frozen=True, slots=True)
class VerifiedClient:
    """A client that passed every handshake check: certificate chain, attest
    signature, CN allowlist and CRL."""

    cn: str
    # 32 bytes. The client's certificate binds its TPM attest key to it. Out
    # of repr: a stable device ID, which the logs show only hashed.
    noise_static: bytes = field(repr=False)


def _pad_to_frame(data: bytes, expected_size: int) -> bytes:
    """Pad a handshake ciphertext to HANDSHAKE_FRAME_SIZE with CSPRNG bytes."""
    if len(data) != expected_size:
        raise HandshakeError(
            f"handshake payload size mismatch: {len(data)} != {expected_size}"
        )
    return bytes(data) + os.urandom(HANDSHAKE_FRAME_SIZE - expected_size)


def _pin_source(
    transport: UDPTransport | TCPTransport,
    got: tuple[str, int] | None,
    expected: tuple[str, int] | None,
    what: str,
) -> None:
    """Reject a UDP frame whose source addr does not match the pinned peer.

    AEAD already rejects forged *content*; this additionally drops a
    UDP-spoofed frame from any other source before it can influence the
    handshake. A no-op for TCP (connection-oriented) and when the peer
    address is not yet pinned (``expected is None``, e.g. server pre-msg1).
    """
    if isinstance(transport, UDPTransport) and expected is not None and got != expected:
        raise HandshakeError(
            f"{what} from unexpected source {got}, expected {expected}"
        )


def _unpad_from_frame(blob: bytes, expected_size: int) -> bytes:
    """Extract the ciphertext prefix from a fixed-size handshake frame."""
    if len(blob) != HANDSHAKE_FRAME_SIZE:
        raise HandshakeError(
            f"handshake frame wrong size: {len(blob)} != {HANDSHAKE_FRAME_SIZE}"
        )
    return bytes(blob[:expected_size])


_NoiseT = TypeVar("_NoiseT")


def _translate_noise_errors(what: str, call: Callable[[], _NoiseT]) -> _NoiseT:
    """Run a tuncore Noise/transport call that parses peer-controlled
    bytes, translating the PyO3 ``RuntimeError`` it raises on malformed
    input into a typed :class:`HandshakeError`.

    Rust's Noise readers (``read_message_1/2/3``) and
    ``NoiseTransport.decrypt`` surface every internal failure — wrong
    frame size, low-order ephemeral, AEAD auth failure — as a bare
    ``RuntimeError`` (PyO3 ``py_err``). ``run_server`` / ``run_client``
    catch only ``HandshakeError`` / ``CertAuthError``, so an
    unauthenticated malformed ``msg1`` would otherwise escape the retry
    loop and terminate ``asyncio.run``.
    """
    try:
        return call()
    except RuntimeError as e:
        raise HandshakeError(f"{what}: {e}") from e


async def _attest_payload_in_thread(
    *,
    attest_key: tuncore.AttestKey,
    cert_der: bytes,
    handshake_hash: bytes,
    our_static_pub: bytes,
    our_role: PeerRole,
) -> bytes:
    """Run ``build_attest_payload`` in a worker thread, off the event loop.

    Its signature took about 0.2 s on the server box's TPM, and the server
    can be serving a live session meanwhile; ``AttestKey.sign`` releases the
    GIL, so the session's packets keep moving. A cancelled handshake still
    waits for the thread to finish: the server zeroizes the attest key when
    it stops, and that must not happen while a signature is using it.
    """
    work = asyncio.ensure_future(
        asyncio.to_thread(
            build_attest_payload,
            attest_key=attest_key,
            cert_der=cert_der,
            handshake_hash=handshake_hash,
            our_static_pub=our_static_pub,
            our_role=our_role,
        )
    )
    try:
        return await asyncio.shield(work)
    except asyncio.CancelledError:
        # The thread cannot be stopped; wait it out (one signature at most),
        # then let the cancel go on. A second cancel does not cut the wait.
        while not work.done():
            try:
                await asyncio.wait({work})
            except asyncio.CancelledError:
                continue
        # The handshake is over either way and the cancel is what the caller
        # must see, so an error from the signature is dropped. Read it here,
        # or asyncio logs it later as "never retrieved", with its text.
        if not work.cancelled():
            error = work.exception()
            if error is not None:
                log.debug("signature after a cancel failed: %s", type(error).__name__)
        raise


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
) -> tuple[tuncore.SessionKeyManager, bytes, bytes]:
    """Perform Noise XX handshake as initiator (client).

    msg1 carries the server gate's mac1 (wire v2), made from ``ca_root`` and
    ``expected_server_cn``. Under load the server first sends a cookie reply;
    the client resends the same msg1 with mac2 at once, at most
    ``MAX_COOKIE_REPLIES`` times, within the same retry budget.

    Returns ``(session_keys, handshake_hash, server_static_pub)``.
    ``server_static_pub`` is the 32-byte X25519 Noise static recovered
    from msg2 and used by the caller for the M-BUG-1 mutual-rekey
    tie-break.

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
        HandshakeError on transport/protocol failure, or when the gate
            keys cannot be made (an empty or too long
            ``expected_server_cn``).
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

    # The server's gate (wire v2) wants mac1 in msg1 and, under load, a mac2
    # made from a cookie. Its keys come from the CA certificate and the name
    # we expect the server to have. Imported here, like tuncore: the gate
    # loads the Rust module at import.
    from dsm.net.handshake_gate import (
        GateKeyError,
        GateKeys,
        compute_mac1,
        open_cookie_reply,
        stamp_mac2,
        stamp_msg1,
    )

    try:
        gate_keys = GateKeys.derive(ca_root, expected_server_cn)
    except GateKeyError as e:
        raise HandshakeError(f"handshake gate keys could not be made: {e}") from e

    # Message 1: -> e, stamped. mac1 once per attempt, from the time it
    # starts, so resends keep it; random bytes where mac2 goes.
    msg1 = bytearray(initiator.write_message_1())
    mac1 = compute_mac1(bytes(msg1[:32]), gate_keys, time.time())
    stamp_msg1(msg1, mac1)
    await _send(transport, bytes(msg1), server_addr)

    # Message 2: <- e, ee, s, es [+ server attest payload]
    async def _retransmit_msg1() -> None:
        # The latest stamp: after a cookie reply it carries mac2.
        await _send(transport, bytes(msg1), server_addr)

    def _cookie_in(frame: bytes, addr: tuple[str, int] | None) -> bytes | None:
        # Cookie replies come over UDP only, from the server's address. A
        # frame from another address goes on to the source pin.
        if not isinstance(transport, UDPTransport) or addr != server_addr:
            return None
        return open_cookie_reply(frame, gate_keys, mac1)

    cookie_replies = 0

    async def _cookie_reply(frame: bytes, addr: tuple[str, int] | None) -> bool:
        # Under load the server answers msg1 with a cookie reply. Tried
        # before msg2: a failed Noise read could spoil the handshake state.
        nonlocal cookie_replies
        cookie = _cookie_in(frame, addr)
        if cookie is None:
            return False
        cookie_replies += 1
        if cookie_replies > MAX_COOKIE_REPLIES:
            raise HandshakeError(
                f"the server sent more than {MAX_COOKIE_REPLIES} cookie replies"
            )
        stamp_mac2(msg1, cookie)
        await _send(transport, bytes(msg1), server_addr)
        return True

    msg2, recv_addr = await _recv_with_retry(
        transport, retransmit=_retransmit_msg1, handle=_cookie_reply
    )
    _pin_source(transport, recv_addr, server_addr, "msg2")

    # Snapshot the handshake hash that signs msg2's binding *before*
    # read_message_2 advances the Noise state past it.
    binding_hash_for_msg2 = bytes(initiator.get_handshake_hash())
    server_static_raw, server_attest_payload = _translate_noise_errors(
        "read msg2", lambda: initiator.read_message_2(msg2)
    )
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
                    f"server cert serial {server_cert.serial_number} " "is revoked"
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
    # BootstrapEphemeral holds the secret in mlock'd heap inside Rust; Python
    # only sees the public key. complete_bootstrap consumes the secret in
    # place — no transient Python bytes copy of the DH scalar ever exists.
    client_ephemeral = tuncore.BootstrapEphemeral.generate()
    bootstrap_init_ct = bytes(
        noise_transport.encrypt(bytes(client_ephemeral.public_key_bytes))
    )
    bootstrap_init_frame = _pad_to_frame(bootstrap_init_ct, BOOTSTRAP_CIPHERTEXT_SIZE)
    await _send(transport, bootstrap_init_frame, server_addr)

    # Receive server ephemeral public. On timeout, resend BOTH msg3 and
    # the bootstrap frame — we don't know which was lost, and
    # resending only one would deadlock the protocol step.
    async def _retransmit_bootstrap() -> None:
        await _send(transport, msg3, server_addr)
        await _send(transport, bootstrap_init_frame, server_addr)

    # When msg3 is slow, the server's timer resends msg2, and the copy can
    # land here. It is the msg2 already read, byte for byte, so skip it and
    # keep waiting; any other frame is still read as the reply. msg2's bytes
    # crossed the wire in the clear, so a plain compare is fine.
    def _resent_msg2(frame: bytes) -> bool:
        return frame == msg2

    async def _late_cookie_reply(frame: bytes, addr: tuple[str, int] | None) -> bool:
        # A cookie reply held back in the network can land after msg2. It is
        # not the bootstrap reply: skip it like a copy of msg2, with the same
        # log line and count, and no new resend of msg1.
        if _cookie_in(frame, addr) is None:
            return False
        _skip_log.log("handshake: skipped a copy of an earlier handshake message")
        return True

    bootstrap_resp_frame, bs_addr = await _recv_with_retry(
        transport,
        retransmit=_retransmit_bootstrap,
        skip=_resent_msg2,
        handle=_late_cookie_reply,
    )
    # Pin source on the bootstrap response. AEAD already rejects forged
    # content, but a UDP-spoofed bootstrap frame from any source would
    # otherwise reach noise_transport.decrypt — fail AEAD, raise
    # HandshakeError, and waste a handshake retry. Pin to server_addr so
    # the server's legitimate response is the only one that lands here.
    _pin_source(transport, bs_addr, server_addr, "bootstrap response")
    bootstrap_resp_ct = _unpad_from_frame(
        bootstrap_resp_frame, BOOTSTRAP_CIPHERTEXT_SIZE
    )
    server_public = _translate_noise_errors(
        "decrypt bootstrap response", lambda: noise_transport.decrypt(bootstrap_resp_ct)
    )
    if len(server_public) != 32:
        raise HandshakeError("invalid bootstrap ephemeral from server")

    session_keys = _translate_noise_errors(
        "bootstrap key derivation (client)",
        lambda: tuncore.complete_bootstrap(
            client_ephemeral,
            bytes(server_public),
            is_initiator=True,
            rotation_packets=rotation_packets,
            rotation_seconds=rotation_seconds,
        ),
    )

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
    # Return the server's Noise static pub too so
    # the data path can plumb it into DataPathContext for the
    # mutual-rekey tie-break.
    return session_keys, handshake_hash, bytes(server_static)


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
    admit_client: Callable[[VerifiedClient], None] | None = None,
) -> tuple[tuncore.SessionKeyManager, bytes]:
    """Perform Noise XX handshake as responder (server).

    ``admit_client`` (optional) is the caller's last say on a client that
    passed every check (certificate chain, attest signature, allowlist,
    CRL). It runs once, after the client's bootstrap frame is read and
    checked, and before the bootstrap reply, the last handshake frame, is
    made and sent. It may raise :class:`ClientRefusedError`; then no reply
    goes out and no session keys are made. Without it nothing changes.

    Returns:
        (SessionKeyManager, client_static_pubkey)

    Raises:
        HandshakeError on transport/protocol failure.
        CertAuthError / CNNotAllowedError / CertRevokedError on cert
            policy failure.
        ClientRefusedError when ``admit_client`` refuses the client.
    """
    import tuncore

    responder = tuncore.NoiseResponder(identity)
    our_static_pub = bytes(identity.public_key)

    netaudit.emit(
        "handshake_start",
        role="server",
        client_addr=(f"{client_addr[0]}:{client_addr[1]}" if client_addr else None),
    )
    # Message 1: -> e (capture sender address for UDP reply).
    # The server-msg1 wait uses a single long timeout (no retries) since
    # there's no peer state to time out against before any client has
    # connected; MSG1_WAIT_TIMEOUT still bounds it so a spoofed/dropped
    # msg1 cannot stall the loop.
    try:
        msg1, recv_addr = await _recv_one(transport, MSG1_WAIT_TIMEOUT)
    except TimeoutError:
        raise HandshakeError(f"msg1 wait timed out after {MSG1_WAIT_TIMEOUT}s")
    started_at = asyncio.get_event_loop().time()
    _translate_noise_errors("read msg1", lambda: responder.read_message_1(msg1))
    addr = recv_addr or client_addr

    def _resent_msg1(frame: bytes) -> bool:
        return _is_resent_msg1(frame, msg1)

    # Message 2: <- e, ee, s, es [+ server attest payload]
    binding_hash_for_msg2 = bytes(responder.get_handshake_hash())
    # Off the event loop: the server may be serving a live session.
    our_attest_payload = await _attest_payload_in_thread(
        attest_key=attest_key,
        cert_der=cert_der,
        handshake_hash=binding_hash_for_msg2,
        our_static_pub=our_static_pub,
        our_role=PeerRole.RESPONDER,
    )
    msg2 = responder.write_message_2(our_attest_payload)
    await _send(transport, msg2, addr)

    # Message 3: -> s, se [+ client attest payload]
    # A client that hears nothing for HANDSHAKE_TIMEOUT resends msg1. That
    # copy is skipped, never read as msg3. It does not trigger a msg2 resend:
    # the retry below already resends msg2 at about the same moment, and
    # older clients fail on a second msg2 that reaches them while they wait
    # for the bootstrap reply (newer ones skip it).
    async def _retransmit_msg2() -> None:
        await _send(transport, msg2, addr)

    msg3, msg3_addr = await _recv_with_retry(
        transport, retransmit=_retransmit_msg2, skip=_resent_msg1
    )
    _pin_source(transport, msg3_addr, addr, "msg3")

    binding_hash_for_msg3 = bytes(responder.get_handshake_hash())
    client_static_raw, client_attest_payload = _translate_noise_errors(
        "read msg3", lambda: responder.read_message_3(msg3)
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
                    f"client cert serial {client_cert.serial_number} " "is revoked"
                )
        except CRLError as e:
            raise CertAuthError(f"CRL check failed: {e}") from e

    noise_transport = responder.into_transport()

    # A copy of msg1 that was slow on the way can still land after msg3. So
    # can a copy of msg3: a client that hears no bootstrap reply resends msg3
    # and then the bootstrap frame. Anyone on the path sees msg3's bytes, so
    # a plain compare is fine.
    def _resent_msg1_or_msg3(frame: bytes) -> bool:
        return _resent_msg1(frame) or frame == msg3

    bootstrap_init_frame, bs_addr = await _recv_with_retry(
        transport, skip=_resent_msg1_or_msg3
    )
    # Pin source: msg1 + msg3 are already source-pinned to ``addr``; the
    # bootstrap_init must come from the same peer. AEAD blocks content forge,
    # but a UDP-spoofed bootstrap frame would otherwise fail AEAD and abort
    # the handshake — wasting state and a retry slot.
    _pin_source(transport, bs_addr, addr, "bootstrap_init")
    bootstrap_init_ct = _unpad_from_frame(
        bootstrap_init_frame, BOOTSTRAP_CIPHERTEXT_SIZE
    )
    client_public = _translate_noise_errors(
        "decrypt bootstrap init", lambda: noise_transport.decrypt(bootstrap_init_ct)
    )
    if len(client_public) != 32:
        raise HandshakeError("invalid bootstrap ephemeral from client")

    # The caller's last say, after every check passed and before the last
    # frame: once the reply is out, the client thinks it is connected.
    if admit_client is not None:
        admit_client(
            VerifiedClient(cn=client_cert.subject_cn, noise_static=client_static)
        )

    server_ephemeral = tuncore.BootstrapEphemeral.generate()
    bootstrap_resp_ct = bytes(
        noise_transport.encrypt(bytes(server_ephemeral.public_key_bytes))
    )
    bootstrap_resp_frame = _pad_to_frame(bootstrap_resp_ct, BOOTSTRAP_CIPHERTEXT_SIZE)
    await _send(transport, bootstrap_resp_frame, addr)

    session_keys = _translate_noise_errors(
        "bootstrap key derivation (server)",
        lambda: tuncore.complete_bootstrap(
            server_ephemeral,
            bytes(client_public),
            is_initiator=False,
            rotation_packets=rotation_packets,
            rotation_seconds=rotation_seconds,
        ),
    )

    duration_s = asyncio.get_event_loop().time() - started_at
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
        if addr is None:
            # Runtime check (not assert) so behavior is identical under
            # python -O. UDP responder code may legitimately have a None
            # addr if msg1 arrived without a sender — refuse rather than
            # send to (None, *).
            raise HandshakeError("UDP transport requires destination addr")
        await transport.send(data, addr)
    else:
        await transport.send(data)


async def _recv_one(
    transport: UDPTransport | TCPTransport,
    timeout: float,
) -> tuple[bytes, tuple[str, int] | None]:
    """Receive one frame with ``timeout`` seconds.

    Unifies the UDP-returns-(bytes, addr) vs TCP-returns-bytes split
    that the original handshake code branched at six call sites. Raises
    ``asyncio.TimeoutError`` on timeout — caller decides retry / failure.
    """
    if isinstance(transport, UDPTransport):
        frame, addr = await asyncio.wait_for(transport.recv(), timeout)
        return bytes(frame), addr
    frame = await asyncio.wait_for(transport.recv(), timeout)
    return bytes(frame), None


async def _recv_one_skipping(
    transport: UDPTransport | TCPTransport,
    timeout: float,
    skip: Callable[[bytes], bool] | None,
    handle: Callable[[bytes, tuple[str, int] | None], Awaitable[bool]] | None = None,
) -> tuple[bytes, tuple[str, int] | None]:
    """Like ``_recv_one``, but drops frames for which ``skip`` returns True
    and shows the rest to ``handle`` first: a frame it returns True for was
    dealt with (a cookie reply, answered with a resend) and the wait goes on.

    Neither restarts the wait: it still ends ``timeout`` seconds after it
    began. Raises ``TimeoutError`` like ``_recv_one``.
    """
    if skip is None and handle is None:
        return await _recv_one(transport, timeout)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise TimeoutError
        frame, addr = await _recv_one(transport, remaining)
        if skip is not None and skip(frame):
            _skip_log.log("handshake: skipped a copy of an earlier handshake message")
            continue
        if handle is not None and await handle(frame, addr):
            continue
        return frame, addr


async def _recv_with_retry(
    transport: UDPTransport | TCPTransport,
    retransmit: Callable[[], Awaitable[None]] | None = None,
    skip: Callable[[bytes], bool] | None = None,
    handle: Callable[[bytes, tuple[str, int] | None], Awaitable[bool]] | None = None,
    gave_up: str | None = None,
) -> tuple[bytes, tuple[str, int] | None]:
    """Per-message handshake recv with bounded retries.

    ``retransmit`` (optional) resends the last outgoing message between
    retries so the peer gets another chance to respond if our send was
    lost. ``skip`` (optional) picks frames to drop unread, such as a copy
    of an earlier message; dropping one does not restart the wait. After
    ``MAX_RETRIES`` consecutive ``HANDSHAKE_TIMEOUT`` waits, raises
    ``HandshakeError`` so callers can surface a typed failure.
    ``handle`` (optional) is passed on to :func:`_recv_one_skipping`.
    ``gave_up`` (optional) is the error text after the last wait.
    """
    for attempt in range(MAX_RETRIES):
        try:
            return await _recv_one_skipping(transport, HANDSHAKE_TIMEOUT, skip, handle)
        except TimeoutError:
            if attempt == MAX_RETRIES - 1:
                raise HandshakeError(
                    gave_up or f"handshake recv timed out after {MAX_RETRIES} attempts"
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
