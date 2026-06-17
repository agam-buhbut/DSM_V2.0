"""Regression (server.py lc-1): a per-session host-setup failure must not crash
the re-accept loop. ``_drive_fsm_to_idle`` returns the FSM to IDLE from any
active state so the loop can serve the next client instead of the daemon dying.
"""

import pytest

from dsm.core.fsm import SessionFSM, State
from dsm.server import _drive_fsm_to_idle

# Shortest valid transition path from IDLE to each state.
_PATH_TO: dict[State, list[State]] = {
    State.IDLE: [],
    State.CONNECTING: [State.CONNECTING],
    State.HANDSHAKING: [State.CONNECTING, State.HANDSHAKING],
    State.ESTABLISHED: [State.CONNECTING, State.HANDSHAKING, State.ESTABLISHED],
    State.REKEYING: [
        State.CONNECTING,
        State.HANDSHAKING,
        State.ESTABLISHED,
        State.REKEYING,
    ],
    State.TEARDOWN: [State.CONNECTING, State.TEARDOWN],
}


def _fsm_in(state: State) -> SessionFSM:
    fsm = SessionFSM()
    for step in _PATH_TO[state]:
        fsm.transition(step)
    assert fsm.state is state
    return fsm


class TestDriveFsmToIdle:
    @pytest.mark.parametrize("state", list(State))
    def test_drives_any_state_to_idle(self, state: State) -> None:
        fsm = _fsm_in(state)
        _drive_fsm_to_idle(fsm)
        assert fsm.state is State.IDLE

    def test_idle_to_connecting_still_valid_after_recovery(self) -> None:
        # After recovery the re-accept loop tail does IDLE -> CONNECTING.
        fsm = _fsm_in(State.ESTABLISHED)
        _drive_fsm_to_idle(fsm)
        fsm.transition(State.CONNECTING)
        assert fsm.state is State.CONNECTING
