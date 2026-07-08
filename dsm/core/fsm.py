"""Session Finite State Machine — 6 states.

IDLE -> CONNECTING -> HANDSHAKING -> ESTABLISHED -> REKEYING -> TEARDOWN -> IDLE

Invalid transitions raise ProtocolError and trigger TEARDOWN.
"""

from __future__ import annotations

import logging
from enum import Enum, auto

log = logging.getLogger(__name__)


class State(Enum):
    IDLE = auto()
    CONNECTING = auto()
    HANDSHAKING = auto()
    ESTABLISHED = auto()
    REKEYING = auto()
    TEARDOWN = auto()


class ProtocolError(Exception):
    pass


# Valid transitions: {from_state: {to_state, ...}}
_TRANSITIONS: dict[State, set[State]] = {
    State.IDLE: {State.CONNECTING},
    State.CONNECTING: {State.HANDSHAKING, State.TEARDOWN},
    State.HANDSHAKING: {State.ESTABLISHED, State.TEARDOWN},
    State.ESTABLISHED: {State.REKEYING, State.TEARDOWN},
    State.REKEYING: {State.ESTABLISHED, State.TEARDOWN},
    State.TEARDOWN: {State.IDLE},
}


class SessionFSM:
    """Enforced session state machine."""

    def __init__(self) -> None:
        self._state = State.IDLE

    @property
    def state(self) -> State:
        return self._state

    def transition(self, target: State) -> None:
        """Transition to target state. Raises ProtocolError on invalid transition."""
        valid = _TRANSITIONS.get(self._state, set())
        if target not in valid:
            msg = f"invalid transition: {self._state.name} -> {target.name}"
            log.error(msg)
            if target != State.TEARDOWN and State.TEARDOWN in valid:
                # Force teardown on invalid transition
                self._do_transition(State.TEARDOWN)
            raise ProtocolError(msg)
        self._do_transition(target)

    def _do_transition(self, target: State) -> None:
        old = self._state
        self._state = target
        log.info("FSM: %s -> %s", old.name, target.name)
