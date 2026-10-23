"""A msg3 that does not open raises BadMsg3Error, so the acceptor can spare
the address (multi-client spec §3.7 E2, owner decision 2026-10-23): a
spoofed datagram that reaches the server before the real msg3 is read as
msg3. A later bad frame stays a plain HandshakeError. Real tuncore Noise
over the in-memory UDP link of test_handshake_resent_msg1.py; nothing waits
on the wall clock."""

from __future__ import annotations

import os

import pytest

from dsm.crypto.handshake import HANDSHAKE_FRAME_SIZE, BadMsg3Error, HandshakeError
from tests.cert_helpers import (
    CLIENT_AUTH_OID,
    SERVER_AUTH_OID,
    make_enrolled_device,
    make_test_ca,
)
from tests.test_handshake_resent_msg1 import _link, _Pki, _run_pair


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


async def test_a_frame_read_as_msg3_that_does_not_open_raises_bad_msg3(
    pki: _Pki,
) -> None:
    client_end, server_end = _link()
    # Right after msg1, a stranger's datagram from the client's address: the
    # server reads it as msg3 (the real msg3 comes only after msg2).
    client_end.inject_after = {0: os.urandom(HANDSHAKE_FRAME_SIZE)}
    _client_task, server_task, _pending = await _run_pair(pki, client_end, server_end)
    assert isinstance(server_task.exception(), BadMsg3Error)


async def test_a_bad_frame_after_msg3_is_not_a_bad_msg3(pki: _Pki) -> None:
    client_end, server_end = _link()
    # Right after the real msg3: read as the bootstrap frame.
    client_end.inject_after = {1: os.urandom(HANDSHAKE_FRAME_SIZE)}
    _client_task, server_task, _pending = await _run_pair(pki, client_end, server_end)
    error = server_task.exception()
    assert isinstance(error, HandshakeError)
    assert not isinstance(error, BadMsg3Error)
