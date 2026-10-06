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

# Retry plan for a lost REKEY_ACK. The initiator resends the SAME
# REKEY_INIT (same ephemeral, same new_epoch) until the ACK comes or it
# runs out of retries, then tears the session down.
#
# The first two retries come soon: a lost packet is most often a single
# drop, and a round trip here is the shaper wait each way (up to about
# 0.5 s) plus the network RTT, so 1.5 s and then 2.5 s more is enough to
# tell "lost" from "slow". After that the retries wait REKEY_ACK_TIMEOUT
# each, so a long outage does not flood the link.
#
# The time to the LAST retry (REKEY_RETRY_BUDGET) MUST exceed
# MIN_REKEY_INTERVAL (60s) so that a responder that just completed a rekey
# and is silently rate-limiting our INIT (because its 60s window hasn't
# elapsed) still gets a later retry it can accept.
# 1.5 + 2.5 + 8 x 8 = 68s. The responder keeps its old keys for
# PEER_CONFIRM_LIMIT_SECS (session_keys.rs, 75s) so it can still answer
# the last retry; a test checks that limit stays above this budget.
REKEY_ACK_TIMEOUT = 8.0
REKEY_EARLY_RETRY_DELAYS = (1.5, 2.5)
MAX_REKEY_RETRIES = 10


def rekey_retry_delay(
    retries_used: int, ack_timeout: float = REKEY_ACK_TIMEOUT
) -> float:
    """Seconds to wait for the ACK after the INIT that ``retries_used``
    retries have been sent before. The early delays never exceed
    ``ack_timeout``."""
    if retries_used < len(REKEY_EARLY_RETRY_DELAYS):
        return min(REKEY_EARLY_RETRY_DELAYS[retries_used], ack_timeout)
    return ack_timeout


# Time from the first INIT to the last retry.
REKEY_RETRY_BUDGET = sum(rekey_retry_delay(i) for i in range(MAX_REKEY_RETRIES))


SendFn = Callable[[bytes, int], Awaitable[None]]

# A synchronous, fire-and-forget paced-enqueue callable. The data path
# passes ``SendScheduler.enqueue`` with ``control=True``, so the packet waits
# in the control queue, ahead of any queued data.
# When supplied, control-plane REKEY_INIT/REKEY_ACK leave in the tier
# shaper's next free slot instead of immediately via ``send_fn``, so their
# wire timing is indistinguishable from the steady stream. ``enqueue`` only
# *queues*; the retransmit logic is gated on
# ACK-receipt timeout (REKEY_ACK_TIMEOUT), not on send completion, so
# fire-and-forget is safe (see the module docstring of session.py and the
# retry scheduler in tun_send_loop).
PacedSend = Callable[[bytes, int], None]


async def _send_rekey_packet(
    ptype: PacketType,
    payload: bytes,
    session_keys: tuncore.SessionKeyManager,
    shaper: TrafficShaper,
    send_fn: SendFn,
    paced_send: PacedSend | None = None,
) -> None:
    """Build a rekey-family inner packet, pad, and send it.

    All four REKEY_INIT/REKEY_ACK construction sites share the same
    shape — same epoch_id derivation, same shaper.pad_packet call,
    same send invocation.

    When ``paced_send`` is supplied the padded packet is handed
    to the paced scheduler queue (fire-and-forget) instead of the bounded
    direct ``send_fn``, so it leaves in a shaper slot. The padding is
    identical either way — the wire packet is the same size class / AEAD
    shape as a real data packet, only its release timing differs. When
    ``paced_send`` is None the bounded direct-await path is used.
    """
    inner = InnerPacket(
        ptype=ptype,
        epoch_id=session_keys.epoch & 0x0F,
        payload=payload,
    )
    padded, target_size = shaper.pad_packet(inner)
    if paced_send is not None:
        paced_send(padded, target_size)
    else:
        await send_fn(padded, target_size)


def _is_rate_limited(last_rekey_time: float | None) -> bool:
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
    *,
    paced_send: PacedSend | None = None,
) -> tuple[float | None, int | None, bytes | None]:
    """Start a key rotation: generate ephemeral keypair, send REKEY_INIT.

    Returns ``(timestamp, new_epoch, init_payload)`` on success. The
    ``init_payload`` is the `(epoch, ephemeral_pub)` blob that went
    into the REKEY_INIT; callers should stash it in ``RekeyState`` so
    ``resend_rekey_init`` can retransmit the same INIT on ACK timeout.
    Returns ``(last_rekey_time, None, None)`` if the rekey was skipped.

    When ``paced_send`` is supplied the REKEY_INIT rides the
    shaper schedule (fire-and-forget enqueue) instead of the bounded direct
    ``send_fn``. This is safe because the retransmit budget is driven by
    REKEY_ACK_TIMEOUT (ACK *receipt*), not by send completion — a paced
    INIT leaves in the next free slot, far inside the 8 s window.
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
        paced_send=paced_send,
    )
    log.info("rekey initiated, new epoch=%d", new_epoch)
    return time.monotonic(), new_epoch, payload


async def resend_rekey_init(
    payload: bytes,
    session_keys: tuncore.SessionKeyManager,
    shaper: TrafficShaper,
    send_fn: SendFn,
    *,
    paced_send: PacedSend | None = None,
) -> None:
    """Retransmit a REKEY_INIT with the same rotation payload.

    Re-uses the original ephemeral public key and epoch so the server,
    if it has already processed the first INIT, can match its cached
    ACK and retransmit it without re-deriving keys. Padding is
    re-randomized per call via ``shaper.pad_packet``; an observer
    cannot see a byte-identical retransmit.

    When ``paced_send`` is supplied the retransmit also rides
    the shaper schedule (same justification as ``initiate_rekey`` — the
    next ACK-timeout retry is the recovery mechanism, not send completion).
    """
    await _send_rekey_packet(
        PacketType.REKEY_INIT,
        payload,
        session_keys,
        shaper,
        send_fn,
        paced_send=paced_send,
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
    paced_send: PacedSend | None = None,
) -> tuple[float | None, int | None, bytes | None]:
    """Process a REKEY_INIT: complete rotation as responder, send REKEY_ACK.

    Returns ``(last_rekey_time, cached_ack_epoch, cached_ack_payload)``.
    Caller (session.py) stores the ack cache in ``RekeyState`` so that a
    duplicate REKEY_INIT (arrives when our first ACK was lost) can be
    answered by re-sending the same ACK bytes under our current send keys,
    rather than trying to re-rotate — the second `prepare_rotation_responder`
    would fail its ``new_epoch == current_epoch + 1`` precondition after
    the first one applied.

    Mutual-init tie-break: if our own rekey is in
    flight (``rekey_state.in_progress``) AND the incoming INIT arrives
    in REKEYING state, both sides have initiated within an RTT. Without
    a tie-break, each side's `handle_rekey_init` rejects the other's
    INIT (state != ESTABLISHED), both ACK timeouts fire, both tear
    down. With static-pub-based tie-break: the side with the LOWER
    canonical pub is the "winning initiator", the side with the higher
    pub yields its own init and processes the peer's. Requires the
    caller to pass both ``local_static_pub`` and ``remote_static_pub``;
    if either is omitted the tie-break is skipped.
    """
    if fsm.state != State.ESTABLISHED:
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
            # Drop the Rust-side pending_rotation that our own
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
            # Our own initiate_rekey just stamped last_rekey_time, which
            # would rate-limit-drop the peer's winning INIT below. Clear the
            # anchor here — and ONLY on this genuine-yield path — so the peer's
            # INIT is processed rather than silently dropped.
            last_rekey_time = None
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
        if paced_send is not None:
            # The replay takes the next free slot like any packet, so it
            # never shows up as an off-beat packet on the wire.
            await _send_rekey_packet(
                PacketType.REKEY_ACK,
                cached_ack_payload,
                session_keys,
                shaper,
                send_fn,
                paced_send=paced_send,
            )
            return last_rekey_time, cached_ack_epoch, cached_ack_payload
        # Direct path: bound the await so a stuck TCP send (peer
        # backpressure) can't pin the recv loop for arbitrary time.
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
        # WARNING, not DEBUG: a stalled rekey must be visible in journald before
        # the initiator hits its
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
    # tuncore raises opaque PyO3 errors; treat all as prepare failure
    except Exception as e:  # noqa: BLE001
        log.warning("rekey responder prepare failed: %s", e)
        fsm.transition(State.ESTABLISHED)
        return last_rekey_time, cached_ack_epoch, cached_ack_payload

    # Send ACK under old keys (session_keys epoch not yet rotated).
    ack_payload = struct.pack("!I", prepared_epoch) + bytes(our_ephemeral_pub)
    # Pace the ACK so its wire timing matches the steady stream.
    # The packet is BUILT now (old-epoch nibble) but LEAVES later in a
    # shaper slot. Two safety properties keep this correct across the
    # immediately-following apply_rotation_responder():
    #   * the receiver EXEMPTS REKEY_ACK from the epoch-nibble check
    #     (decrypt_packet), so a NEW nibble restamped at send
    #     time by make_send_fn does not drop it; and
    #   * the responder DEFERS its send-key swap until the initiator sends
    #     under the new keys (session_keys.rs), so the paced ACK, and any
    #     cached-ACK resend, still encrypts under the OLD send key the
    #     pre-rotation initiator can decrypt.
    # enqueue is fire-and-forget: no TimeoutError self-heal is needed
    # because the scheduler — not this recv-loop frame — owns delivery
    # and cannot pin the recv loop on a wedged transport (it drops oldest).
    if paced_send is not None:
        await _send_rekey_packet(
            PacketType.REKEY_ACK,
            ack_payload,
            session_keys,
            shaper,
            send_fn,
            paced_send=paced_send,
        )
    else:
        # Direct path: bound the send so TCP backpressure doesn't stall the
        # recv loop indefinitely.
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
            # This leaves pending_responder_rotation set in Rust with no apply.
            # That is tolerated: the next REKEY_INIT's
            # prepare_rotation_responder overwrites the stale pending (dropping
            # and zeroizing its keys), so the responder self-heals on the next
            # rekey instead of wedging permanently.
            fsm.transition(State.ESTABLISHED)
            return last_rekey_time, cached_ack_epoch, cached_ack_payload

    try:
        completed_epoch = session_keys.apply_rotation_responder()
    # tuncore raises opaque PyO3 errors; treat all as prepare failure
    except Exception as e:  # noqa: BLE001
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
    # tuncore raises opaque PyO3 errors; treat all as completion failure
    except Exception as e:  # noqa: BLE001
        log.warning("rekey initiator completion failed: %s", e)
        fsm.transition(State.ESTABLISHED)
        return None

    fsm.transition(State.ESTABLISHED)
    log.info("rekey completed as initiator, epoch=%d", completed_epoch)
    netaudit.emit("rekey_epoch", role="initiator", new_epoch=completed_epoch)
    return time.monotonic()
