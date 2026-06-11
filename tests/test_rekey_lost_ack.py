"""Phase 1.1 regression: a lost REKEY_ACK recovers without teardown.

decrypt_packet must NOT drop a REKEY_ACK on the epoch-id nibble check —
the ACK self-validates via its own 4-byte epoch field + AEAD, and the
initiator that retransmits its INIT is still at the OLD epoch so a
NEW-stamped ACK would otherwise be dropped (Phase 1.1).
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
class RekeyAckEpochExempt(unittest.TestCase):
    def test_rekey_ack_new_stamp_decrypts_at_old_epoch_during_grace(self) -> None:
        initiator, responder = _pair()
        start_epoch = responder.epoch

        # Rotate the RESPONDER one epoch, leaving the INITIATOR at the OLD
        # epoch — this simulates the lost-ACK case: the initiator never got
        # the first ACK, never completed rotation, and is retransmitting its
        # INIT. The responder uses the deferred-send-swap (session_keys.rs
        # H-BUG-2/3), so it now reports epoch+1 but still SENDS under the OLD
        # (start_epoch) key for the grace window. responder_send(start_epoch)
        # == initiator_recv(start_epoch), so the initiator can still decrypt.
        rot_eph = tuncore.BootstrapEphemeral.generate()
        new_epoch = start_epoch + 1
        responder.prepare_rotation_responder(rot_eph.public_key_bytes, new_epoch)
        responder.apply_rotation_responder()
        # The recv-swap is immediate so epoch() should already report new_epoch
        # while the send key stays old during grace. If epoch() lags, derive
        # new_eid from new_epoch directly — the test needs ack epoch_id != the
        # initiator's expected (start_epoch) nibble.
        self.assertEqual(initiator.epoch, start_epoch)

        # Build a REKEY_ACK stamped with the NEW epoch nibble — exactly what
        # _send_rekey_packet + make_send_fn produce when re-sending the cached
        # ACK — and AEAD-encrypt it via the responder (which is in send-grace,
        # so the bytes go out under the OLD send key).
        new_eid = new_epoch & 0x0F
        ack_payload = new_epoch.to_bytes(4, "big") + b"\x00" * 32
        inner = InnerPacket(
            ptype=PacketType.REKEY_ACK, epoch_id=new_eid, payload=ack_payload
        )
        plaintext = inner.serialize()
        seq = 1
        aad = SEQ_STRUCT.pack(seq)
        nonce, ct, _e = responder.encrypt(plaintext, aad)
        wire = OuterPacket(seq=seq, nonce=bytes(nonce), ciphertext=bytes(ct)).serialize(
            OUTER_HEADER_SIZE + len(ct)
        )

        # Initiator is still at start_epoch: its current-epoch recv key matches
        # the responder's grace send key, so AEAD succeeds — but the inner
        # epoch_id nibble (new) != the initiator's expected (old), so WITHOUT
        # the fix decrypt_packet drops the ACK on the nibble check.
        replay = tuncore.ReplayWindow()
        result = decrypt_packet(wire, initiator, replay)
        self.assertIsNotNone(result, "REKEY_ACK must survive the epoch nibble check")
        out_inner, _prev = result
        self.assertEqual(out_inner.ptype, PacketType.REKEY_ACK)
        self.assertEqual(out_inner.payload, ack_payload)

    def test_data_packet_still_dropped_on_epoch_mismatch(self) -> None:
        # Control: DATA with a wrong epoch_id nibble is STILL dropped (the
        # exemption must be REKEY_ACK-only). Same-epoch pair, deliberately
        # wrong nibble.
        sender, receiver = _pair()
        wrong_eid = (sender.epoch + 1) & 0x0F
        inner = InnerPacket(ptype=PacketType.DATA, epoch_id=wrong_eid, payload=b"hello")
        plaintext = inner.serialize()
        seq = 1
        aad = SEQ_STRUCT.pack(seq)
        nonce, ct, _epoch = sender.encrypt(plaintext, aad)
        wire = OuterPacket(seq=seq, nonce=bytes(nonce), ciphertext=bytes(ct)).serialize(
            OUTER_HEADER_SIZE + len(ct)
        )
        replay = tuncore.ReplayWindow()
        self.assertIsNone(decrypt_packet(wire, receiver, replay))


if __name__ == "__main__":
    unittest.main()
