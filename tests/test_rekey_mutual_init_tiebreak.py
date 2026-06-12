"""Mutual-init rekey TIE-BREAK (M-BUG-1), uncovered by the existing
test_rekey_mutual_init.py (which only locks the Rust abort_rotation hook).

Scenario: both peers call ``initiate_rekey`` within an RTT, so each
receives the other's REKEY_INIT while already in REKEYING with its own
init in flight. Without a tie-break, each side rejects the other's INIT
(state != ESTABLISHED), both ACK timeouts fire, both tear down — a
split-brain. ``handle_rekey_init`` resolves it deterministically from the
static Noise pubs: the side with the LOWER canonical pub keeps its INIT
(the "winner"); the side with the HIGHER pub yields (aborts its own
pending rotation, returns to ESTABLISHED) and processes the peer's INIT
as responder.

These run against the REAL tuncore SessionKeyManager (a bootstrap pair, so
the keys interoperate) through the real handle_rekey_init / handle_rekey_ack
flow. The discriminating properties:

  * deterministic winner: the lower-pub side keeps its init regardless of
    which INIT is delivered first (test_winner_is_lower_pub_either_order);
  * convergence / no split-brain: both peers end at the SAME epoch with
    interoperable encrypt/decrypt (test_mutual_init_converges_no_split_brain);
  * the yielding side's abort cleanup leaves it able to rekey again
    (test_yielding_side_can_rekey_again).

NOT covered here (and why): the *retransmit-driven* recovery that happens
when the tie-break is skipped because the older call sites omit the static
pubs — that lives in session.py's tun_send_loop scheduler, not in
rekey.py, so it is out of scope for a rekey.py-level test. We do assert the
skip itself (test_tiebreak_skipped_without_static_pubs) leaves the loser's
INIT rejected, which is the precondition the scheduler then recovers from.
"""

from __future__ import annotations

import unittest

try:
    import tuncore

    _HAS_TUNCORE = True
except ImportError:
    tuncore = None  # type: ignore[assignment]
    _HAS_TUNCORE = False

from dsm.core.fsm import SessionFSM, State
from dsm.core.protocol import InnerPacket, PacketType
from dsm.rekey import handle_rekey_ack, handle_rekey_init, initiate_rekey
from dsm.session import RekeyState
from dsm.traffic.shaper import TrafficShaper


def _bootstrap_pair() -> tuple[tuncore.SessionKeyManager, tuncore.SessionKeyManager]:
    """Two interoperable SessionKeyManagers from one bootstrap DH."""
    a_eph = tuncore.BootstrapEphemeral.generate()
    b_eph = tuncore.BootstrapEphemeral.generate()
    a = tuncore.complete_bootstrap(a_eph, b_eph.public_key_bytes, True)
    b = tuncore.complete_bootstrap(b_eph, a_eph.public_key_bytes, False)
    return a, b


def _ordered_static_pubs() -> tuple[bytes, bytes]:
    """Return (low_pub, high_pub) so the tie-break direction is known."""
    p1 = bytes(tuncore.IdentityKeyPair.generate().public_key)
    p2 = bytes(tuncore.IdentityKeyPair.generate().public_key)
    low, high = sorted([p1, p2])
    return low, high


def _established_fsm() -> SessionFSM:
    fsm = SessionFSM()
    fsm.transition(State.CONNECTING)
    fsm.transition(State.HANDSHAKING)
    fsm.transition(State.ESTABLISHED)
    return fsm


def _inner_payload(padded: bytes) -> bytes:
    return InnerPacket.deserialize(padded).payload


def _inner_type(padded: bytes) -> PacketType:
    return InnerPacket.deserialize(padded).ptype


class _Peer:
    """A rekey participant: keys + FSM + RekeyState + a send capture."""

    def __init__(self, keys: tuncore.SessionKeyManager, static_pub: bytes) -> None:
        self.keys = keys
        self.static_pub = static_pub
        self.fsm = _established_fsm()
        self.rekey = RekeyState()
        self.sent: list[bytes] = []

    async def send(self, data: bytes, _size: int) -> None:
        self.sent.append(data)

    async def initiate(self, shaper: TrafficShaper) -> None:
        _t, new_epoch, _payload = await initiate_rekey(
            self.keys, self.fsm, shaper, self.send
        )
        self.rekey.in_progress = True
        self.rekey.pending_epoch = new_epoch

    @property
    def last_init_payload(self) -> bytes:
        # The REKEY_INIT this peer just sent (first captured packet).
        assert _inner_type(self.sent[0]) is PacketType.REKEY_INIT
        return _inner_payload(self.sent[0])


@unittest.skipUnless(_HAS_TUNCORE, "tuncore extension not built")
class MutualInitTieBreakTest(unittest.IsolatedAsyncioTestCase):
    async def _both_initiate(
        self,
    ) -> tuple[_Peer, _Peer, TrafficShaper]:
        keys_a, keys_b = _bootstrap_pair()
        low_pub, high_pub = _ordered_static_pubs()
        winner = _Peer(keys_a, low_pub)  # lower pub -> keeps its INIT
        loser = _Peer(keys_b, high_pub)  # higher pub -> yields
        shaper = TrafficShaper(128, 1400)
        await winner.initiate(shaper)
        await loser.initiate(shaper)
        # Both are now mid-rekey with an init in flight.
        self.assertEqual(winner.fsm.state, State.REKEYING)
        self.assertEqual(loser.fsm.state, State.REKEYING)
        self.assertTrue(winner.rekey.in_progress)
        self.assertTrue(loser.rekey.in_progress)
        return winner, loser, shaper

    async def test_mutual_init_converges_no_split_brain(self) -> None:
        winner, loser, shaper = await self._both_initiate()

        winner_init = winner.last_init_payload
        loser_init = loser.last_init_payload

        # Winner receives loser's INIT: lower pub -> keep ours, ignore theirs.
        await handle_rekey_init(
            loser_init,
            winner.keys,
            winner.fsm,
            shaper,
            winner.send,
            rekey_state=winner.rekey,
            local_static_pub=winner.static_pub,
            remote_static_pub=loser.static_pub,
        )
        # Winner sent NO extra packet and is still driving its own rekey.
        self.assertEqual(len(winner.sent), 1)
        self.assertEqual(winner.fsm.state, State.REKEYING)

        # Loser receives winner's INIT: higher pub -> yield + respond.
        await handle_rekey_init(
            winner_init,
            loser.keys,
            loser.fsm,
            shaper,
            loser.send,
            rekey_state=loser.rekey,
            local_static_pub=loser.static_pub,
            remote_static_pub=winner.static_pub,
        )
        # Loser yielded its own init (no longer in_progress), completed the
        # rotation as responder, and emitted a REKEY_ACK.
        self.assertFalse(loser.rekey.in_progress)
        self.assertEqual(loser.fsm.state, State.ESTABLISHED)
        self.assertEqual(len(loser.sent), 2)
        self.assertIs(_inner_type(loser.sent[1]), PacketType.REKEY_ACK)

        # Winner consumes the ACK and completes as initiator.
        ack_payload = _inner_payload(loser.sent[1])
        result = handle_rekey_ack(
            ack_payload,
            winner.keys,
            winner.fsm,
            expected_epoch=winner.rekey.pending_epoch,
        )
        self.assertIsNotNone(result)
        self.assertEqual(winner.fsm.state, State.ESTABLISHED)

        # KEY PROPERTY: both peers converged to the SAME epoch (one rotation,
        # one winner) and their keys still interoperate — no split-brain.
        self.assertEqual(winner.keys.epoch, loser.keys.epoch)
        aad = (1).to_bytes(8, "big")
        nonce, ct, _epoch = winner.keys.encrypt(b"post-rekey", aad)
        pt = loser.keys.decrypt(bytes(nonce), bytes(ct), aad, 1, False)
        self.assertEqual(bytes(pt), b"post-rekey")

    async def test_winner_is_lower_pub_either_order(self) -> None:
        # Determinism: whichever side has the lower pub keeps its INIT, and
        # the outcome does not depend on which INIT is delivered first.
        # Deliver the WINNER's INIT to the loser FIRST this time.
        winner, loser, shaper = await self._both_initiate()
        winner_init = winner.last_init_payload
        loser_init = loser.last_init_payload

        await handle_rekey_init(
            winner_init,
            loser.keys,
            loser.fsm,
            shaper,
            loser.send,
            rekey_state=loser.rekey,
            local_static_pub=loser.static_pub,
            remote_static_pub=winner.static_pub,
        )
        # The higher-pub side yields immediately, regardless of order.
        self.assertFalse(loser.rekey.in_progress)
        self.assertEqual(loser.fsm.state, State.ESTABLISHED)

        await handle_rekey_init(
            loser_init,
            winner.keys,
            winner.fsm,
            shaper,
            winner.send,
            rekey_state=winner.rekey,
            local_static_pub=winner.static_pub,
            remote_static_pub=loser.static_pub,
        )
        # The lower-pub side never yields: still REKEYING, still in_progress,
        # no ACK emitted in response to the loser's (now-abandoned) INIT.
        self.assertTrue(winner.rekey.in_progress)
        self.assertEqual(winner.fsm.state, State.REKEYING)
        self.assertEqual(len(winner.sent), 1)

    async def test_yielding_side_can_rekey_again(self) -> None:
        # DSM-003: the yield path must abort the Rust-side pending_rotation,
        # not just clear the Python flag, or the loser's NEXT initiate_rotation
        # raises "rotation already in progress". After yielding + completing as
        # responder, a fresh initiate must succeed cleanly.
        winner, loser, shaper = await self._both_initiate()
        winner_init = winner.last_init_payload

        await handle_rekey_init(
            winner_init,
            loser.keys,
            loser.fsm,
            shaper,
            loser.send,
            rekey_state=loser.rekey,
            local_static_pub=loser.static_pub,
            remote_static_pub=winner.static_pub,
        )
        self.assertEqual(loser.fsm.state, State.ESTABLISHED)

        # A brand-new rotation initiated by the (previously yielding) loser
        # must not raise — the abandoned pending was aborted.
        loser.sent.clear()
        loser.rekey = RekeyState()
        await loser.initiate(shaper)
        self.assertEqual(loser.fsm.state, State.REKEYING)
        self.assertIs(_inner_type(loser.sent[0]), PacketType.REKEY_INIT)

    async def test_tiebreak_skipped_without_static_pubs(self) -> None:
        # Older call sites omit the static pubs -> tie-break is disabled and
        # behavior matches pre-fix: a REKEY_INIT arriving in REKEYING is
        # rejected (no state change, no ACK). This is the precondition the
        # send-loop retransmit scheduler recovers from (out of scope here).
        winner, loser, shaper = await self._both_initiate()
        winner_init = winner.last_init_payload
        before_state = loser.fsm.state
        before_sent = len(loser.sent)

        await handle_rekey_init(
            winner_init,
            loser.keys,
            loser.fsm,
            shaper,
            loser.send,
            rekey_state=loser.rekey,
            # static pubs intentionally omitted.
        )
        # No tie-break: the INIT was ignored. Loser keeps its own init and
        # emits nothing.
        self.assertEqual(loser.fsm.state, before_state)
        self.assertTrue(loser.rekey.in_progress)
        self.assertEqual(len(loser.sent), before_sent)


if __name__ == "__main__":
    unittest.main()
