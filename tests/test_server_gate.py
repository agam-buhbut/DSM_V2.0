"""run_server and the handshake gate (wire v2): the keys are made at start
from the server's own certificate, a certificate without a usable CN stops
the start, and the run's one gate reaches every accept and every in-session
accept, UDP and TCP. Host I/O is faked as in test_server_dns_fatal.py.
Laptop: yes (old wheel); if it hangs there, box only.
"""

from __future__ import annotations

import asyncio
import datetime
import logging
from dataclasses import replace
from typing import Any
from unittest.mock import patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from dsm import server as server_mod
from dsm.core.fsm import SessionFSM, State
from dsm.net.handshake_gate import (
    GateKeyError,
    GateKeys,
    HandshakeGate,
    server_gate_keys,
)
from dsm.server import _drive_fsm_to_idle, run_server
from tests.cert_helpers import SERVER_AUTH_OID, make_enrolled_device, make_test_ca
from tests.test_server_dns_fatal import _base_patches, _server_config

KEYS = GateKeys(mac1_key=bytes(32), cookie_key=bytes(32))


class _Materials:
    def __init__(self, cert_der: bytes, ca_root: x509.Certificate) -> None:
        self.cert_der = cert_der
        self.ca_root = ca_root
        self.crl = None


class _Watch:
    """Stands in for SessionWatch and keeps the gate it was given."""

    gates: list[Any] = []

    def __init__(self, *args: Any, udp: Any = None, tcp: Any = None) -> None:
        del udp, tcp
        _Watch.gates.append(args[7])
        self.end_session = asyncio.Event()
        self.offer = None

    async def stop(self) -> None:
        return None


class _Listener:
    def __init__(self) -> None:
        self.connections: asyncio.Queue[Any] = asyncio.Queue()

    def close(self) -> None:
        pass


async def _session(*args: Any) -> None:
    _drive_fsm_to_idle(args[1])


async def _never(*_a: Any, **_k: Any) -> tuple[Any, Any, Any]:
    raise AssertionError("this accept must not run")


def test_server_gate_keys_use_the_ca_and_the_servers_own_cn() -> None:
    ca = make_test_ca()
    server = make_enrolled_device(ca, subject_cn="dsm-gate-server", eku=SERVER_AUTH_OID)
    keys = server_gate_keys(_Materials(server.cert_der, ca.certificate))
    assert keys == GateKeys.derive(ca.certificate, "dsm-gate-server")


def test_a_server_certificate_without_a_cn_has_no_gate_keys() -> None:
    ca = make_test_ca()
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "dsm")]))
        .issuer_name(ca.certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(ca.private_key, hashes.SHA384())
    )
    with pytest.raises(GateKeyError):
        server_gate_keys(_Materials(cert.public_bytes(Encoding.DER), ca.certificate))


async def test_a_server_certificate_without_a_usable_cn_stops_the_start(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.ERROR, logger="dsm")
    captured: dict[str, Any] = {}
    with (
        _base_patches(_never, captured),
        patch("dsm.server.server_gate_keys", side_effect=GateKeyError("no usable CN")),
    ):
        rc = await run_server(replace(_server_config(), dns_blocklist=False))
    assert rc == 1
    assert "handshake gate keys could not be made: no usable CN" in [
        r.getMessage() for r in caplog.records
    ]


async def test_one_gate_goes_to_every_udp_accept_and_watch() -> None:
    _Watch.gates = []
    captured: dict[str, Any] = {}
    accept_gates: list[Any] = []

    async def _accept(*args: Any, **_k: Any) -> tuple[Any, Any, Any]:
        accept_gates.append(args[9])
        if len(accept_gates) == 2:
            captured["event"].set()
            return None, None, args[5]
        return object(), b"\x01" * 32, args[5]

    with (
        _base_patches(_accept, captured),
        patch("dsm.server.server_gate_keys", return_value=KEYS) as make_keys,
        patch("dsm.server.SessionWatch", _Watch),
        patch("dsm.server._run_one_session", _session),
    ):
        rc = await run_server(replace(_server_config(), dns_blocklist=False))
    assert rc == 0
    make_keys.assert_called_once()
    assert len(accept_gates) == 2
    assert len(_Watch.gates) == 1
    gate = accept_gates[0]
    assert isinstance(gate, HandshakeGate)
    assert all(g is gate for g in accept_gates + _Watch.gates)


async def test_one_gate_goes_to_every_tcp_accept_and_watch() -> None:
    _Watch.gates = []
    captured: dict[str, Any] = {}
    accept_gates: list[Any] = []

    class _Conn:
        async def aclose(self) -> None:
            pass

    async def _accept(*args: Any) -> tuple[Any, Any, Any]:
        accept_gates.append(args[11])
        if len(accept_gates) == 2:
            captured["event"].set()
            return None, None, None
        return object(), b"\x01" * 32, _Conn()

    async def _listener(_config: Any) -> _Listener:
        return _Listener()

    with (
        _base_patches(_never, captured),
        patch("dsm.server.server_gate_keys", return_value=KEYS),
        patch("dsm.server._open_tcp_listener", _listener),
        patch("dsm.server._accept_one_session", _accept),
        patch("dsm.server.SessionWatch", _Watch),
        patch("dsm.server._run_one_session", _session),
    ):
        rc = await run_server(
            replace(_server_config(), dns_blocklist=False, transport="tcp")
        )
    assert rc == 0
    assert len(accept_gates) == 2
    assert len(_Watch.gates) == 1
    gate = accept_gates[0]
    assert isinstance(gate, HandshakeGate)
    assert all(g is gate for g in accept_gates + _Watch.gates)


async def test_accept_one_session_hands_the_gate_to_the_tcp_accept() -> None:
    gate = HandshakeGate(KEYS)
    seen: dict[str, Any] = {}

    async def _tcp_accept(*args: Any) -> tuple[None, None, None]:
        # By position: test_server_handshake_limiter.py's stand-ins take no
        # keywords, so _accept_one_session passes the gate as the 10th.
        seen["gate"] = args[9]
        return None, None, None

    fsm = SessionFSM()
    fsm.transition(State.CONNECTING)
    with patch("dsm.server._accept_until_winner_tcp", _tcp_accept):
        await server_mod._accept_one_session(
            _server_config(),
            fsm,
            object(),
            object(),
            object(),
            object(),
            None,
            asyncio.Event(),
            object(),
            _Listener(),
            object(),
            gate,
        )
    assert seen["gate"] is gate
