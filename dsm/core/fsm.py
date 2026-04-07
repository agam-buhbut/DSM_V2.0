"""Session Finite State Machine — 6 states.

IDLE -> CONNECTING -> HANDSHAKING -> ESTABLISHED -> REKEYING -> TEARDOWN -> IDLE

Invalid transitions raise ProtocolError and trigger TEARDOWN.
"""

from __future__ import annotations

import logging
from enum import Enum, auto
from typing import Callable

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


# States where on_enter callback failure must abort the transition.
# If nftables apply fails during ESTABLISHED entry, traffic is unprotected.
_CRITICAL_ENTER_STATES: set[State] = {State.ESTABLISHED}


class SessionFSM:
    """Enforced session state machine."""

    def __init__(self) -> None:
        self._state = State.IDLE
        self._on_enter: dict[State, list[Callable[[], None]]] = {s: [] for s in State}
        self._on_exit: dict[State, list[Callable[[], None]]] = {s: [] for s in State}

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
        for cb in self._on_exit[old]:
            try:
                cb()
            except Exception:
                log.exception("on_exit callback failed for %s", old.name)
        self._state = target
        log.info("FSM: %s -> %s", old.name, target.name)
        for cb in self._on_enter[target]:
            try:
                cb()
            except Exception:
                if target in _CRITICAL_ENTER_STATES:
                    log.critical("critical on_enter callback failed for %s, forcing TEARDOWN", target.name)
                    self._state = State.TEARDOWN
                    raise
                log.exception("on_enter callback failed for %s", target.name)

    def on_enter(self, state: State, callback: Callable[[], None]) -> None:
        """Register a callback to run when entering a state."""
        self._on_enter[state].append(callback)

    def on_exit(self, state: State, callback: Callable[[], None]) -> None:
        """Register a callback to run when exiting a state."""
        self._on_exit[state].append(callback)

    def is_active(self) -> bool:
        """True if the session is in an active state (not IDLE or TEARDOWN)."""
        return self._state not in (State.IDLE, State.TEARDOWN)
