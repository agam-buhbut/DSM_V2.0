"""Key rotation (rekey) helpers shared by client and server."""

from __future__ import annotations

import asyncio
import logging
import struct
import time
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

from dsm.core import netaudit
from dsm.core.fsm import SessionFSM, State
from dsm.core.protocol import InnerPacket, PacketType
from dsm.traffic.shaper import TrafficShaper

if TYPE_CHECKING:
    import tuncore
    from dsm.session import RekeyState

log = logging.getLogger(__name__)

REKEY_PAYLOAD_SIZE = 36  # 4 (epoch) + 32 (ephemeral pub)
MIN_REKEY_INTERVAL = 60  # seconds — minimum time between rekey operations

# Retry budget for a lost REKEY_ACK. The initiator resends the SAME
# REKEY_INIT (same ephemeral, same new_epoch) up to MAX_REKEY_RETRIES
# times, each separated by REKEY_ACK_TIMEOUT, before giving up and
# tearing down the session.
#
# Total retry window MUST exceed MIN_REKEY_INTERVAL (60s) so that a
# responder that just completed a rekey and is silently rate-limiting
# our INIT (because its 60s window hasn't elapsed) still has time to
# accept us on a later retransmit. Previous values (5s × 3 = 15s) gave
# up well before the responder's rate-limit window cleared, causing
# spurious teardowns under tight-budget configs (H-CRYPT-6 audit).
# 8s × 9 = 72s comfortably crosses the 60s threshold.
REKEY_ACK_TIMEOUT = 8.0
MAX_REKEY_RETRIES = 9


SendFn = Callable[[bytes, int], Awaitable[None]]


async def _send_rekey_packet(
    ptype: PacketType,
    payload: bytes,
    session_keys: tuncore.SessionKeyManager,
    shaper: TrafficShaper,
    send_fn: SendFn,
) -> None:
    """Build a rekey-family inner packet, pad, and send it.

    All four REKEY_INIT/REKEY_ACK construction sites share the same
    shape — same epoch_id derivation, same shaper.pad_packet call,
    same send_fn invocation. Centralised here so future protocol
    fields (e.g. an explicit rekey reason) land in one place.
    """
    inner = InnerPacket(
        ptype=ptype,
        epoch_id=session_keys.epoch & 0x0F,
        payload=payload,
    )
    padded, target_size = shaper.pad_packet(inner)
    await send_fn(padded, target_size)


def _is_rate_limited(last_rekey_time: float | None) -> bool:
    """Return True if a rekey should be skipped due to rate limiting."""
    if last_rekey_time is None:
        return False
    elapsed = time.monotonic() - last_rekey_time
    if elapsed < MIN_REKEY_INTERVAL:
        log.debug("rekey rate limit: skipping (last rekey %.1fs ago)", elapsed)
        return True
    return False


async def initiate_rekey(
    session_keys: tuncore.SessionKeyManager,
    fsm: SessionFSM,
    shaper: TrafficShaper,
    send_fn: SendFn,
    last_rekey_time: float | None = None,
) -> tuple[float | None, int | None, bytes | None]:
    """Start a key rotation: generate ephemeral keypair, send REKEY_INIT.

    Returns ``(timestamp, new_epoch, init_payload)`` on success. The
    ``init_payload`` is the `(epoch, ephemeral_pub)` blob that went
    into the REKEY_INIT; callers should stash it in ``RekeyState`` so
    ``resend_rekey_init`` can retransmit the same INIT on ACK timeout.
    Returns ``(last_rekey_time, None, None)`` if the rekey was skipped.
    """
    if fsm.state != State.ESTABLISHED:
        log.warning("cannot initiate rekey in state %s", fsm.state.name)
        return last_rekey_time, None, None

    if _is_rate_limited(last_rekey_time):
        return last_rekey_time, None, None

    fsm.transition(State.REKEYING)
    new_epoch, ephemeral_pub = session_keys.initiate_rotation()
    payload = struct.pack("!I", new_epoch) + bytes(ephemeral_pub)
    await _send_rekey_packet(
        PacketType.REKEY_INIT,
        payload,
        session_keys,
        shaper,
        send_fn,
    )
    log.info("rekey initiated, new epoch=%d", new_epoch)
    return time.monotonic(), new_epoch, payload


async def resend_rekey_init(
    payload: bytes,
    session_keys: tuncore.SessionKeyManager,
    shaper: TrafficShaper,
    send_fn: SendFn,
) -> None:
    """Retransmit a REKEY_INIT with the same rotation payload.

    Re-uses the original ephemeral public key and epoch so the server,
    if it has already processed the first INIT, can match its cached
    ACK and retransmit it without re-deriving keys. Padding is
    re-randomized per call via ``shaper.pad_packet``; an observer
    cannot see a byte-identical retransmit.
    """
    await _send_rekey_packet(
        PacketType.REKEY_INIT,
        payload,
        session_keys,
        shaper,
        send_fn,
    )


async def handle_rekey_init(
    payload: bytes,
    session_keys: tuncore.SessionKeyManager,
    fsm: SessionFSM,
    shaper: TrafficShaper,
    send_fn: SendFn,
    last_rekey_time: float | None = None,
    cached_ack_epoch: int | None = None,
    cached_ack_payload: bytes | None = None,
    *,
    # rekey_state typed under TYPE_CHECKING only to avoid cyclic import
    # at runtime (session.py imports from rekey.py).
    rekey_state: RekeyState | None = None,
    local_static_pub: bytes | None = None,
    remote_static_pub: bytes | None = None,
) -> tuple[float | None, int | None, bytes | None]:
    """Process a REKEY_INIT: complete rotation as responder, send REKEY_ACK.

    Returns ``(last_rekey_time, cached_ack_epoch, cached_ack_payload)``.
    Caller (session.py) stores the ack cache in ``RekeyState`` so that a
    duplicate REKEY_INIT (arrives when our first ACK was lost) can be
    answered by re-sending the same ACK bytes under our current send keys,
    rather than trying to re-rotate — the second `prepare_rotation_responder`
    would fail its ``new_epoch == current_epoch + 1`` precondition after
    the first one applied.

    Mutual-init tie-break (audit M-BUG-1): if our own rekey is in
    flight (``rekey_state.in_progress``) AND the incoming INIT arrives
    in REKEYING state, both sides have initiated within an RTT. Without
    a tie-break, each side's `handle_rekey_init` rejects the other's
    INIT (state != ESTABLISHED), both ACK timeouts fire, both tear
    down. With static-pub-based tie-break: the side with the LOWER
    canonical pub is the "winning initiator", the side with the higher
    pub yields its own init and processes the peer's. Requires the
    caller to pass both ``local_static_pub`` and ``remote_static_pub``;
    if either is omitted (older call sites), the tie-break is skipped
    and behavior matches the pre-fix code.
    """
    if fsm.state != State.ESTABLISHED:
        # Mutual-init tie-break point.
        if (
            fsm.state == State.REKEYING
            and rekey_state is not None
            and rekey_state.in_progress
            and local_static_pub is not None
            and remote_static_pub is not None
        ):
            # Compare canonically. Lower pub "wins" — its INIT prevails.
            if bytes(local_static_pub) < bytes(remote_static_pub):
                log.info(
                    "mutual REKEY_INIT race — local pub is lower; "
                    "keeping our INIT, ignoring peer's",
                )
                return last_rekey_time, cached_ack_epoch, cached_ack_payload
            # Local pub is higher → we yield: abort our in-flight init,
            # fall through to process peer's INIT.
            log.info(
                "mutual REKEY_INIT race — local pub is higher; "
                "yielding to peer's INIT, aborting our pending one",
            )
            # DSM-003: drop the Rust-side pending_rotation that our own
            # initiate_rotation() set. Clearing only the Python rekey_state
            # leaves the abandoned initiator init inside the SessionKeyManager,
            # so the next needs_rotation()-driven initiate_rotation() raises
            # "rotation already in progress" and tears down a healthy session.
            # abort_rotation() is idempotent and zeroizes the abandoned
            # ephemeral (LockedKey32 drop).
            if not session_keys.abort_rotation():
                log.warning(
                    "mutual-init yield: no pending rotation to abort "
                    "(unexpected — our initiate_rotation should have set one)"
                )
            rekey_state.in_progress = False
            rekey_state.reset_retry()
            rekey_state.pending_epoch = None
            fsm.transition(State.ESTABLISHED)
        else:
            log.warning("rekey init received in state %s, ignoring", fsm.state.name)
            return last_rekey_time, cached_ack_epoch, cached_ack_payload

    if len(payload) < REKEY_PAYLOAD_SIZE:
        log.warning("rekey init payload too short, ignoring")
        return last_rekey_time, cached_ack_epoch, cached_ack_payload

    new_epoch = struct.unpack("!I", payload[:4])[0]
    remote_ephemeral_pub = payload[4:36]

    # Duplicate-INIT short-circuit (the client's previous ACK was lost).
    # If we're already at the epoch the client is trying to rotate to and
    # we have the ACK we sent cached, re-send it under current keys.
    if (
        cached_ack_epoch is not None
        and cached_ack_epoch == new_epoch
        and session_keys.epoch == new_epoch
        and cached_ack_payload is not None
    ):
        log.info(
            "duplicate REKEY_INIT for epoch %d — re-sending cached ACK",
            new_epoch,
        )
        # M-BUG-12: bound the await so a stuck TCP send (peer backpressure)
        # can't pin the recv loop for arbitrary time.
        try:
            await asyncio.wait_for(
                _send_rekey_packet(
                    PacketType.REKEY_ACK,
                    cached_ack_payload,
                    session_keys,
                    shaper,
                    send_fn,
                ),
                timeout=5.0,
            )
        except TimeoutError:
            log.warning("REKEY_ACK retransmit timed out — peer may be wedged")
        return last_rekey_time, cached_ack_epoch, cached_ack_payload

    if _is_rate_limited(last_rekey_time):
        # H-CRYPT-6: previous code logged this at DEBUG so a stalled
        # rekey was invisible to operators. Bump to WARNING so the
        # symptom shows up in journald before the initiator hits its
        # extended retry budget. The initiator's MAX_REKEY_RETRIES *
        # REKEY_ACK_TIMEOUT is now > MIN_REKEY_INTERVAL so eventually
        # one of the retries lands after our rate-limit clears and the
        # rekey completes; the WARNING flags the transient stall.
        log.warning(
            "REKEY_INIT received but our last rekey was <%ds ago; "
            "silently dropping (initiator will retransmit until our "
            "rate-limit window clears)",
            MIN_REKEY_INTERVAL,
        )
        return last_rekey_time, cached_ack_epoch, cached_ack_payload

    fsm.transition(State.REKEYING)

    # Two-phase flow: derive the new keys but do NOT apply yet, so the
    # REKEY_ACK below goes out under the OLD keys. If we applied first, the
    # peer (still at old epoch) could not decrypt the ACK.
    try:
        our_ephemeral_pub, prepared_epoch = session_keys.prepare_rotation_responder(
            remote_ephemeral_pub,
            new_epoch,
        )
    except Exception as e:  # noqa: BLE001  # see linter report
        log.warning("rekey responder prepare failed: %s", e)
        fsm.transition(State.ESTABLISHED)
        return last_rekey_time, cached_ack_epoch, cached_ack_payload

    # Send ACK under old keys (session_keys epoch not yet rotated).
    # M-BUG-12: bound the send so TCP backpressure doesn't stall the
    # recv loop indefinitely.
    ack_payload = struct.pack("!I", prepared_epoch) + bytes(our_ephemeral_pub)
    try:
        await asyncio.wait_for(
            _send_rekey_packet(
                PacketType.REKEY_ACK,
                ack_payload,
                session_keys,
                shaper,
                send_fn,
            ),
            timeout=5.0,
        )
    except TimeoutError:
        log.warning("REKEY_ACK send timed out — peer may be wedged")
        fsm.transition(State.ESTABLISHED)
        return last_rekey_time, cached_ack_epoch, cached_ack_payload

    # Now apply the rotation.
    try:
        completed_epoch = session_keys.apply_rotation_responder()
    except Exception as e:  # noqa: BLE001  # see linter report
        log.warning("rekey responder apply failed: %s", e)
        fsm.transition(State.ESTABLISHED)
        return last_rekey_time, cached_ack_epoch, cached_ack_payload

    fsm.transition(State.ESTABLISHED)
    log.info("rekey completed as responder, epoch=%d", completed_epoch)
    netaudit.emit("rekey_epoch", role="responder", new_epoch=completed_epoch)
    # Cache the ACK we just sent under the NEW keys (after apply) so a
    # duplicate INIT retransmitted by the client (with its stale pending
    # rotation) lands here, matches cached_ack_epoch, and we re-send the
    # same payload under current keys.
    return time.monotonic(), completed_epoch, ack_payload


def handle_rekey_ack(
    payload: bytes,
    session_keys: tuncore.SessionKeyManager,
    fsm: SessionFSM,
    expected_epoch: int | None = None,
) -> float | None:
    """Process a REKEY_ACK: complete rotation as initiator.

    Returns the timestamp of completed rekey, or None if failed.
    """
    if fsm.state != State.REKEYING:
        log.warning("rekey ack received in state %s, ignoring", fsm.state.name)
        return None

    if expected_epoch is None:
        log.warning("rekey ack received but no rekey was initiated, ignoring")
        return None

    if len(payload) < REKEY_PAYLOAD_SIZE:
        log.warning("rekey ack payload too short, ignoring")
        return None

    ack_epoch = struct.unpack("!I", payload[:4])[0]
    if ack_epoch != expected_epoch:
        log.warning(
            "rekey ack epoch mismatch: got %d, expected %d", ack_epoch, expected_epoch
        )
        return None

    remote_ephemeral_pub = payload[4:36]

    try:
        completed_epoch = session_keys.complete_rotation_initiator(remote_ephemeral_pub)
    except Exception as e:  # noqa: BLE001  # see linter report
        log.warning("rekey initiator completion failed: %s", e)
        fsm.transition(State.ESTABLISHED)
        return None

    fsm.transition(State.ESTABLISHED)
    log.info("rekey completed as initiator, epoch=%d", completed_epoch)
    netaudit.emit("rekey_epoch", role="initiator", new_epoch=completed_epoch)
    return time.monotonic()
