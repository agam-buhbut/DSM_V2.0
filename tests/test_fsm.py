"""Tests for dsm.core.fsm — Session Finite State Machine."""

import unittest

from dsm.core.fsm import ProtocolError, SessionFSM, State


class TestSessionFSM(unittest.TestCase):
    def test_initial_state(self) -> None:
        fsm = SessionFSM()
        self.assertEqual(fsm.state, State.IDLE)

    def test_valid_forward_path(self) -> None:
        fsm = SessionFSM()
        fsm.transition(State.CONNECTING)
        self.assertEqual(fsm.state, State.CONNECTING)
        fsm.transition(State.HANDSHAKING)
        self.assertEqual(fsm.state, State.HANDSHAKING)
        fsm.transition(State.ESTABLISHED)
        self.assertEqual(fsm.state, State.ESTABLISHED)

    def test_rekeying_roundtrip(self) -> None:
        fsm = SessionFSM()
        fsm.transition(State.CONNECTING)
        fsm.transition(State.HANDSHAKING)
        fsm.transition(State.ESTABLISHED)
        fsm.transition(State.REKEYING)
        self.assertEqual(fsm.state, State.REKEYING)
        fsm.transition(State.ESTABLISHED)
        self.assertEqual(fsm.state, State.ESTABLISHED)

    def test_teardown_from_established(self) -> None:
        fsm = SessionFSM()
        fsm.transition(State.CONNECTING)
        fsm.transition(State.HANDSHAKING)
        fsm.transition(State.ESTABLISHED)
        fsm.transition(State.TEARDOWN)
        self.assertEqual(fsm.state, State.TEARDOWN)
        fsm.transition(State.IDLE)
        self.assertEqual(fsm.state, State.IDLE)

    def test_invalid_transition_raises(self) -> None:
        fsm = SessionFSM()
        with self.assertRaises(ProtocolError):
            fsm.transition(State.ESTABLISHED)  # can't jump from IDLE

    def test_invalid_transition_forces_teardown(self) -> None:
        fsm = SessionFSM()
        fsm.transition(State.CONNECTING)
        fsm.transition(State.HANDSHAKING)
        fsm.transition(State.ESTABLISHED)
        with self.assertRaises(ProtocolError):
            fsm.transition(State.CONNECTING)  # invalid from ESTABLISHED
        self.assertEqual(fsm.state, State.TEARDOWN)

    def test_is_active(self) -> None:
        fsm = SessionFSM()
        self.assertFalse(fsm.is_active())
        fsm.transition(State.CONNECTING)
        self.assertTrue(fsm.is_active())
        fsm.transition(State.TEARDOWN)
        self.assertFalse(fsm.is_active())

    def test_on_enter_callback(self) -> None:
        fsm = SessionFSM()
        entered: list[State] = []
        fsm.on_enter(State.CONNECTING, lambda: entered.append(State.CONNECTING))
        fsm.transition(State.CONNECTING)
        self.assertEqual(entered, [State.CONNECTING])

    def test_on_exit_callback(self) -> None:
        fsm = SessionFSM()
        exited: list[State] = []
        fsm.on_exit(State.IDLE, lambda: exited.append(State.IDLE))
        fsm.transition(State.CONNECTING)
        self.assertEqual(exited, [State.IDLE])

    def test_on_enter_failure_noncritical(self) -> None:
        fsm = SessionFSM()
        fsm.on_enter(State.CONNECTING, lambda: (_ for _ in ()).throw(RuntimeError("oops")))
        # Non-critical state: callback fails but transition still happens
        fsm.transition(State.CONNECTING)
        self.assertEqual(fsm.state, State.CONNECTING)

    def test_on_enter_failure_critical(self) -> None:
        fsm = SessionFSM()
        fsm.transition(State.CONNECTING)
        fsm.transition(State.HANDSHAKING)
        fsm.on_enter(State.ESTABLISHED, lambda: (_ for _ in ()).throw(RuntimeError("critical")))
        with self.assertRaises(RuntimeError):
            fsm.transition(State.ESTABLISHED)
        # Critical state failure forces TEARDOWN
        self.assertEqual(fsm.state, State.TEARDOWN)

    def test_multiple_rekeying_cycles(self) -> None:
        fsm = SessionFSM()
        fsm.transition(State.CONNECTING)
        fsm.transition(State.HANDSHAKING)
        fsm.transition(State.ESTABLISHED)
        for _ in range(5):
            fsm.transition(State.REKEYING)
            fsm.transition(State.ESTABLISHED)
        self.assertEqual(fsm.state, State.ESTABLISHED)


if __name__ == "__main__":
    unittest.main()
