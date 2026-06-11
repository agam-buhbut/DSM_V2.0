"""Phase 1.2 regression: an ACK-send timeout leaves a stale responder
pending in Rust, but the NEXT REKEY_INIT must still rotate (the wedge is
gone because prepare_rotation_responder now overwrites a stale pending)."""

from __future__ import annotations

import asyncio
import struct
import unittest

try:
    import tuncore

    _HAS_TUNCORE = True
except ImportError:
    tuncore = None  # type: ignore[assignment]
    _HAS_TUNCORE = False

from dsm.core.fsm import SessionFSM, State
from dsm.rekey import handle_rekey_init
from dsm.traffic.shaper import TrafficShaper


def _responder() -> tuncore.SessionKeyManager:
    ours = tuncore.BootstrapEphemeral.generate()
    peer = tuncore.BootstrapEphemeral.generate()
    return tuncore.complete_bootstrap(ours, peer.public_key_bytes, False)


@unittest.skipUnless(_HAS_TUNCORE, "tuncore extension not built")
class ResponderWedgeRecovery(unittest.IsolatedAsyncioTestCase):
    async def test_ack_send_timeout_does_not_wedge_next_rekey(self) -> None:
        session_keys = _responder()
        fsm = SessionFSM()
        fsm.transition(State.CONNECTING)
        fsm.transition(State.HANDSHAKING)
        fsm.transition(State.ESTABLISHED)
        shaper = TrafficShaper(128, 1400)

        async def hanging_send(_data: bytes, _size: int) -> None:
            await asyncio.sleep(3600)  # forces the ACK-send TimeoutError path

        new_epoch = session_keys.epoch + 1
        eph = tuncore.BootstrapEphemeral.generate()
        payload = struct.pack("!I", new_epoch) + eph.public_key_bytes

        # Shrink the internal 5s wait_for bound so the timeout fires fast.
        import dsm.rekey as rekey_mod

        orig_wait_for = rekey_mod.asyncio.wait_for

        async def fast_wait_for(coro, timeout):  # type: ignore[no-untyped-def]
            return await orig_wait_for(coro, 0.05)

        rekey_mod.asyncio.wait_for = fast_wait_for  # type: ignore[assignment]
        try:
            # First INIT: ACK send hangs -> times out -> stale pending left.
            await handle_rekey_init(
                payload,
                session_keys,
                fsm,
                shaper,
                hanging_send,
                last_rekey_time=None,
            )
        finally:
            rekey_mod.asyncio.wait_for = orig_wait_for  # type: ignore[assignment]

        # The wedge check: a SECOND prepare must now OVERWRITE the stale
        # pending and succeed. Before the Rust fix this raises
        # "responder rotation already prepared".
        next_epoch = session_keys.epoch + 1
        eph2 = tuncore.BootstrapEphemeral.generate()
        session_keys.prepare_rotation_responder(eph2.public_key_bytes, next_epoch)
        # And apply must still consume exactly that one pending.
        session_keys.apply_rotation_responder()


if __name__ == "__main__":
    unittest.main()
