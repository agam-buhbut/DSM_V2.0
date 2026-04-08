"""Key rotation (rekey) helpers shared by client and server."""

from __future__ import annotations

import logging
import struct
import time
from typing import TYPE_CHECKING, Any

from dsm.core.fsm import SessionFSM, State
from dsm.core.protocol import InnerPacket, PacketType
from dsm.traffic.shaper import TrafficShaper

if TYPE_CHECKING:
    import tuncore

log = logging.getLogger(__name__)

REKEY_PAYLOAD_SIZE = 36  # 4 (epoch) + 32 (ephemeral pub)
MIN_REKEY_INTERVAL = 60  # seconds — minimum time between rekey operations


async def initiate_rekey(
    session_keys: tuncore.SessionKeyManager,
    fsm: SessionFSM,
    shaper: TrafficShaper,
    send_fn: Any,
    last_rekey_time: float | None = None,
) -> float | None:
    """Start a key rotation: generate ephemeral keypair, send REKEY_INIT.

    Returns the timestamp of the initiated rekey, or last_rekey_time if skipped.
    """
    if fsm.state != State.ESTABLISHED:
        log.warning("cannot initiate rekey in state %s", fsm.state.name)
        return last_rekey_time

    now = time.monotonic()
    if last_rekey_time is not None and (now - last_rekey_time) < MIN_REKEY_INTERVAL:
        log.debug("rekey rate limit: skipping (last rekey %.1fs ago)", now - last_rekey_time)
        return last_rekey_time

    fsm.transition(State.REKEYING)
    new_epoch, ephemeral_pub = session_keys.initiate_rotation()
    payload = struct.pack("!I", new_epoch) + bytes(ephemeral_pub)
    inner = InnerPacket(
        ptype=PacketType.REKEY_INIT,
        epoch_id=session_keys.epoch & 0x03,
        payload=payload,
    )
    padded, target_size = shaper.pad_packet(inner)
    await send_fn(padded, target_size)
    log.info("rekey initiated, new epoch=%d", new_epoch)
    return now


async def handle_rekey_init(
    payload: bytes,
    session_keys: tuncore.SessionKeyManager,
    fsm: SessionFSM,
    shaper: TrafficShaper,
    send_fn: Any,
    last_rekey_time: float | None = None,
) -> float | None:
    """Process a REKEY_INIT: complete rotation as responder, send REKEY_ACK.

    Returns the timestamp of completed rekey, or last_rekey_time if rejected.
    """
    if fsm.state != State.ESTABLISHED:
        log.warning("rekey init received in state %s, ignoring", fsm.state.name)
        return last_rekey_time

    now = time.monotonic()
    if last_rekey_time is not None and (now - last_rekey_time) < MIN_REKEY_INTERVAL:
        log.warning("rekey rate limit: ignoring REKEY_INIT (last rekey %.1fs ago)",
                     now - last_rekey_time)
        return last_rekey_time

    if len(payload) < REKEY_PAYLOAD_SIZE:
        log.warning("rekey init payload too short, ignoring")
        return last_rekey_time

    new_epoch = struct.unpack("!I", payload[:4])[0]
    remote_ephemeral_pub = payload[4:36]

    fsm.transition(State.REKEYING)
    try:
        our_ephemeral_pub, completed_epoch = session_keys.complete_rotation_responder(
            remote_ephemeral_pub, new_epoch,
        )
    except Exception as e:
        log.warning("rekey responder failed: %s", e)
        fsm.transition(State.ESTABLISHED)
        return last_rekey_time

    ack_payload = struct.pack("!I", completed_epoch) + bytes(our_ephemeral_pub)
    inner = InnerPacket(
        ptype=PacketType.REKEY_ACK,
        epoch_id=session_keys.epoch & 0x03,
        payload=ack_payload,
    )
    padded, target_size = shaper.pad_packet(inner)
    await send_fn(padded, target_size)
    fsm.transition(State.ESTABLISHED)
    log.info("rekey completed as responder, epoch=%d", completed_epoch)
    return now


def handle_rekey_ack(
    payload: bytes,
    session_keys: tuncore.SessionKeyManager,
    fsm: SessionFSM,
) -> float | None:
    """Process a REKEY_ACK: complete rotation as initiator.

    Returns the timestamp of completed rekey, or None if failed.
    """
    if len(payload) < REKEY_PAYLOAD_SIZE:
        log.warning("rekey ack payload too short, ignoring")
        return None
    _new_epoch = struct.unpack("!I", payload[:4])[0]
    remote_ephemeral_pub = payload[4:36]

    try:
        completed_epoch = session_keys.complete_rotation_initiator(remote_ephemeral_pub)
    except Exception as e:
        log.warning("rekey initiator completion failed: %s", e)
        fsm.transition(State.ESTABLISHED)
        return None

    fsm.transition(State.ESTABLISHED)
    log.info("rekey completed as initiator, epoch=%d", completed_epoch)
    return time.monotonic()
