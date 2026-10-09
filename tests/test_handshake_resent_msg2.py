"""The client skips a copy of msg2 that reaches it while it waits for the
server's bootstrap reply. When msg3 is slow, the server's timer resends msg2;
before this fix the client read that copy as the bootstrap reply and failed.
Real tuncore Noise over an in-memory UDP link (the link from
test_handshake_resent_msg1.py); nothing waits on the wall clock."""

from __future__ import annotations

import os
from collections.abc import Callable

import pytest

from dsm.crypto.handshake import HANDSHAKE_FRAME_SIZE, HandshakeError
from tests.cert_helpers import (
    CLIENT_AUTH_OID,
    SERVER_AUTH_OID,
    make_enrolled_device,
    make_test_ca,
)
from tests.test_handshake_resent_msg1 import (
    _CLIENT,
    _SERVER,
    Addr,
    _End,
    _Pki,
    _run_pair,
)


class _ServerEnd(_End):
    """The server's end of the link. Right after msg2 (its first send) it
    also delivers ``extra(msg2)``, which the client reads while it waits for
    the bootstrap reply."""

    def __init__(self, extra: Callable[[bytes], bytes]) -> None:
        super().__init__(_SERVER)
        self._extra = extra

    async def send(self, data: bytes, addr: Addr) -> None:
        await super().send(data, addr)
        if len(self.sent) == 1:
            assert self.peer is not None
            self.peer.inbox.put_nowait((self._extra(self.sent[0]), self.me))


def _link(extra: Callable[[bytes], bytes]) -> tuple[_End, _ServerEnd]:
    client, server = _End(_CLIENT), _ServerEnd(extra)
    client.peer, server.peer = server, client
    return client, server


@pytest.fixture(name="pki")
def _pki() -> _Pki:
    # _run_pair expects these two CNs.
    ca = make_test_ca()
    return _Pki(
        ca=ca,
        client=make_enrolled_device(
            ca, subject_cn="dsm-f2-client", eku=CLIENT_AUTH_OID
        ),
        server=make_enrolled_device(
            ca, subject_cn="dsm-f2-server", eku=SERVER_AUTH_OID
        ),
    )


async def test_a_resent_msg2_during_the_bootstrap_wait_is_skipped(pki: _Pki) -> None:
    """(red today) The copy is skipped and the handshake completes."""
    client_end, server_end = _link(lambda msg2: msg2)
    client_task, server_task, pending = await _run_pair(pki, client_end, server_end)
    client_task.result()
    server_task.result()
    assert pending == set()
    # msg1, msg3 and the bootstrap frame went out once each: skipping the
    # copy cost no resend.
    assert len(client_end.sent) == 3


async def test_a_msg2_with_one_byte_changed_still_fails(pki: _Pki) -> None:
    """Review Focus 6: only a byte-for-byte copy of msg2 is skipped."""

    def _one_byte_changed(msg2: bytes) -> bytes:
        return msg2[:-1] + bytes([msg2[-1] ^ 0x01])

    client_end, server_end = _link(_one_byte_changed)
    client_task, _server_task, _pending = await _run_pair(pki, client_end, server_end)
    assert isinstance(client_task.exception(), HandshakeError)


async def test_any_other_frame_in_place_of_the_bootstrap_reply_still_fails(
    pki: _Pki,
) -> None:
    """Review Focus 6: anything else is still read as the reply, as today."""
    client_end, server_end = _link(lambda _msg2: os.urandom(HANDSHAKE_FRAME_SIZE))
    client_task, _server_task, _pending = await _run_pair(pki, client_end, server_end)
    assert isinstance(client_task.exception(), HandshakeError)
