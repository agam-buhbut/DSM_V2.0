"""A1 regression: a responder grace-window DATA packet passes the client's
epoch-nibble check.

On a responder deferred send-swap the manager reports ``epoch == new`` while
``send`` still holds the OLD key. ``encrypt()`` (and thus the wire bytes) uses
the OLD key, so the inner epoch_id nibble stamped by ``make_send_fn`` MUST come
from ``send_epoch`` (OLD), not ``epoch`` (NEW). If it stamped ``epoch``, the
still-pre-rotation initiator would drop every grace-window DATA packet on the
``inner.epoch_id != expected_eid`` check.
"""

from __future__ import annotations

import unittest

try:
    import tuncore

    _HAS_TUNCORE = True
except ImportError:
    tuncore = None  # type: ignore[assignment]
    _HAS_TUNCORE = False

from dsm.core.protocol import (
    OUTER_HEADER_SIZE,
    SEQ_STRUCT,
    InnerPacket,
    OuterPacket,
    PacketType,
)
from dsm.session import decrypt_packet


def _pair() -> tuple[tuncore.SessionKeyManager, tuncore.SessionKeyManager]:
    ours = tuncore.BootstrapEphemeral.generate()
    peer = tuncore.BootstrapEphemeral.generate()
    our_pub = ours.public_key_bytes
    peer_pub = peer.public_key_bytes
    initiator = tuncore.complete_bootstrap(ours, peer_pub, True)
    responder = tuncore.complete_bootstrap(peer, our_pub, False)
    return initiator, responder


@unittest.skipUnless(_HAS_TUNCORE, "tuncore extension not built")
class ResponderGraceSendEpochStamp(unittest.TestCase):
    def _rotate_responder(
        self,
        initiator: tuncore.SessionKeyManager,
        responder: tuncore.SessionKeyManager,
    ) -> int:
        start_epoch = responder.epoch
        rot_eph = tuncore.BootstrapEphemeral.generate()
        responder.prepare_rotation_responder(rot_eph.public_key_bytes, start_epoch + 1)
        responder.apply_rotation_responder()
        # Recv-swap is immediate: epoch advances, send key stays OLD.
        self.assertEqual(responder.epoch, start_epoch + 1)
        self.assertEqual(responder.send_epoch, start_epoch)
        self.assertEqual(initiator.epoch, start_epoch)
        return start_epoch

    def test_data_stamped_with_send_epoch_survives(self) -> None:
        initiator, responder = _pair()
        start_epoch = self._rotate_responder(initiator, responder)

        # make_send_fn stamps the nibble from session_keys.send_epoch (the fix).
        eid = responder.send_epoch & 0x0F
        self.assertEqual(eid, start_epoch & 0x0F)
        inner = InnerPacket(
            ptype=PacketType.DATA, epoch_id=eid, payload=b"grace-window data"
        )
        seq = 1
        aad = SEQ_STRUCT.pack(seq)
        nonce, ct, _e = responder.encrypt(inner.serialize(), aad)
        wire = OuterPacket(seq=seq, nonce=bytes(nonce), ciphertext=bytes(ct)).serialize(
            OUTER_HEADER_SIZE + len(ct)
        )

        replay = tuncore.ReplayWindow()
        result = decrypt_packet(wire, initiator, replay)
        self.assertIsNotNone(
            result, "grace-window DATA stamped with send_epoch must not be dropped"
        )
        out_inner, _prev = result
        self.assertEqual(out_inner.ptype, PacketType.DATA)
        self.assertEqual(out_inner.payload, b"grace-window data")

    def test_data_stamped_with_new_epoch_is_dropped(self) -> None:
        # Control: stamping the NEW epoch nibble (the pre-fix bug) IS dropped,
        # confirming the nibble check is what send_epoch must satisfy.
        initiator, responder = _pair()
        self._rotate_responder(initiator, responder)

        wrong_eid = responder.epoch & 0x0F  # NEW nibble
        inner = InnerPacket(
            ptype=PacketType.DATA, epoch_id=wrong_eid, payload=b"grace-window data"
        )
        seq = 1
        aad = SEQ_STRUCT.pack(seq)
        nonce, ct, _e = responder.encrypt(inner.serialize(), aad)
        wire = OuterPacket(seq=seq, nonce=bytes(nonce), ciphertext=bytes(ct)).serialize(
            OUTER_HEADER_SIZE + len(ct)
        )

        replay = tuncore.ReplayWindow()
        self.assertIsNone(decrypt_packet(wire, initiator, replay))


if __name__ == "__main__":
    unittest.main()
