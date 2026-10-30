"""Over TCP a msg3 that does not open raises BadMsg3Error. Over UDP such a
frame is skipped and the wait goes on, so a lost or late msg3 is read from
the client's resend. A bad frame after msg3 is still a plain HandshakeError.
Real tuncore Noise over in-memory links; the lost-msg3 test uses short timers
(about 0.3 s)."""

from __future__ import annotations

import os

import pytest

import tuncore
from dsm.crypto import handshake
from dsm.crypto.cert_allowlist import CNAllowlist
from dsm.crypto.handshake import (
    HANDSHAKE_FRAME_SIZE,
    BadMsg3Error,
    HandshakeError,
    server_handshake,
)
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
    _link,
    _Pki,
    _run_pair,
)
from tests.test_tcp_accept_concurrency import _Conn


class _LossyEnd(_End):
    """The client's end: send number ``lose`` (from 0) never arrives;
    with ``late``, it arrives right after the next send instead."""

    def __init__(self, lose: int, *, late: bool = False) -> None:
        super().__init__(_CLIENT)
        self._lose = lose
        self._late = late
        self._held: bytes | None = None

    async def send(self, data: bytes, addr: Addr) -> None:
        n = len(self.sent)
        if n == self._lose:
            self.sent.append(bytes(data))
            self._held = bytes(data) if self._late else None
            return
        await super().send(data, addr)
        if self._held is not None:
            assert self.peer is not None
            self.peer.inbox.put_nowait((self._held, self.me))
            self._held = None


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


@pytest.fixture(name="short_timers")
def _short_timers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(handshake, "HANDSHAKE_TIMEOUT", 0.2)
    monkeypatch.setattr(handshake, "BACKOFF_BASE", 0.05)


@pytest.mark.usefixtures("short_timers")
@pytest.mark.parametrize("late", [False, True], ids=["lost", "reordered"])
async def test_a_lost_or_late_msg3_is_recovered_over_udp(pki: _Pki, late: bool) -> None:
    client_end = _LossyEnd(1, late=late)  # send 1 is msg3
    server_end = _End(_SERVER)
    client_end.peer, server_end.peer = server_end, client_end
    client_task, server_task, pending = await _run_pair(pki, client_end, server_end)
    _keys, client_static = server_task.result()
    client_task.result()
    assert pending == set()
    assert client_static == bytes(pki.client.identity.public_key)
    # msg1, msg3, the bootstrap frame, then one resend of msg3 and the
    # bootstrap frame: one resend round was enough.
    assert len(client_end.sent) == 5


async def test_over_tcp_a_frame_that_does_not_open_as_msg3_raises_bad_msg3(
    pki: _Pki,
) -> None:
    msg1 = bytes(tuncore.NoiseInitiator(pki.client.identity).write_message_1())
    conn = _Conn(_CLIENT, [msg1, os.urandom(HANDSHAKE_FRAME_SIZE)])
    with pytest.raises(BadMsg3Error):
        await server_handshake(
            conn,
            pki.server.identity,
            attest_key=pki.server.attest_key,
            cert_der=pki.server.cert_der,
            ca_root=pki.ca.certificate,
            cn_allowlist=CNAllowlist(cns=frozenset({"dsm-f2-client"})),
        )
    assert len(conn.sent) == 1  # msg2 only


async def test_a_bad_frame_after_msg3_is_not_a_bad_msg3(pki: _Pki) -> None:
    client_end, server_end = _link()
    # Right after the real msg3: read as the bootstrap frame.
    client_end.inject_after = {1: os.urandom(HANDSHAKE_FRAME_SIZE)}
    _client_task, server_task, _pending = await _run_pair(pki, client_end, server_end)
    error = server_task.exception()
    assert isinstance(error, HandshakeError)
    assert not isinstance(error, BadMsg3Error)
