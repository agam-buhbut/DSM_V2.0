"""The server skips a copy of msg3 that reaches it while it waits for the
client's bootstrap frame. After a lost bootstrap frame the client resends msg3
and then the bootstrap frame; before this fix the server read that msg3 copy
as the bootstrap frame and failed. Real tuncore Noise over an in-memory UDP
link (the link from test_handshake_resent_msg1.py); nothing waits on the
wall clock."""

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


class _ClientEnd(_End):
    """The client's end of the link. Right after msg3 (its second send) it
    also delivers ``extra(msg3)``, which the server reads while it waits for
    the bootstrap frame."""

    def __init__(self, extra: Callable[[bytes], bytes]) -> None:
        super().__init__(_CLIENT)
        self._extra = extra

    async def send(self, data: bytes, addr: Addr) -> None:
        await super().send(data, addr)
        if len(self.sent) == 2:
            assert self.peer is not None
            self.peer.inbox.put_nowait((self._extra(self.sent[1]), self.me))


def _link(extra: Callable[[bytes], bytes]) -> tuple[_ClientEnd, _End]:
    client, server = _ClientEnd(extra), _End(_SERVER)
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


async def test_a_resent_msg3_during_the_bootstrap_wait_is_skipped(pki: _Pki) -> None:
    """(red today) The copy is skipped and the handshake completes."""
    client_end, server_end = _link(lambda msg3: msg3)
    client_task, server_task, pending = await _run_pair(pki, client_end, server_end)
    server_task.result()
    client_task.result()
    assert pending == set()
    # msg1, msg3 and the bootstrap frame went out once each, and the server
    # sent msg2 and the bootstrap reply: skipping the copy cost no resend.
    assert len(client_end.sent) == 3
    assert len(server_end.sent) == 2


async def test_a_msg3_with_one_byte_changed_still_fails(pki: _Pki) -> None:
    """Only a byte-for-byte copy of msg3 is skipped. The last byte is in the
    padding, so a check that looked at a prefix would wrongly skip it."""

    def _one_byte_changed(msg3: bytes) -> bytes:
        return msg3[:-1] + bytes([msg3[-1] ^ 0x01])

    client_end, server_end = _link(_one_byte_changed)
    _client_task, server_task, _pending = await _run_pair(pki, client_end, server_end)
    error = server_task.exception()
    assert isinstance(error, HandshakeError)
    assert "bootstrap init" in str(error)


async def test_any_other_frame_in_place_of_the_bootstrap_frame_still_fails(
    pki: _Pki,
) -> None:
    """Anything else is still read as the bootstrap frame, as today."""
    client_end, server_end = _link(lambda _msg3: os.urandom(HANDSHAKE_FRAME_SIZE))
    _client_task, server_task, _pending = await _run_pair(pki, client_end, server_end)
    error = server_task.exception()
    assert isinstance(error, HandshakeError)
    assert "bootstrap init" in str(error)
