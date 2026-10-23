"""run_server and the handshake gate (wire v2): the keys are made at start
from the server's own certificate, a certificate without a usable CN stops
the start, and the run's one gate reaches the run's one
acceptor, UDP and TCP. Host I/O is faked as in test_server_dns_fatal.py.
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

from dsm.net.handshake_gate import (
    GateKeyError,
    GateKeys,
    HandshakeGate,
    server_gate_keys,
)
from dsm.server import run_server
from tests.cert_helpers import SERVER_AUTH_OID, make_enrolled_device, make_test_ca
from tests.test_server_dns_fatal import _base_patches, _run_until, _server_config
from tests.test_server_multi import _Acceptor

KEYS = GateKeys(mac1_key=bytes(32), cookie_key=bytes(32))


class _Materials:
    def __init__(self, cert_der: bytes, ca_root: x509.Certificate) -> None:
        self.cert_der = cert_der
        self.ca_root = ca_root
        self.crl = None


class _Listener:
    def __init__(self) -> None:
        self.connections: asyncio.Queue[Any] = asyncio.Queue()

    def close(self) -> None:
        pass


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
        _base_patches(captured),
        patch("dsm.server.server_gate_keys", side_effect=GateKeyError("no usable CN")),
    ):
        rc = await run_server(replace(_server_config(), dns_blocklist=False))
    assert rc == 1
    assert "handshake gate keys could not be made: no usable CN" in [
        r.getMessage() for r in caplog.records
    ]


async def test_the_one_gate_goes_to_the_udp_acceptor() -> None:
    captured: dict[str, Any] = {}
    _Acceptor.made = []
    with (
        _base_patches(captured),
        patch("dsm.server.server_gate_keys", return_value=KEYS) as make_keys,
        patch("dsm.server.ClientAcceptor", _Acceptor),
    ):
        rc = await _run_until(replace(_server_config(), dns_blocklist=False), captured)
    assert rc == 0
    make_keys.assert_called_once()
    (acceptor,) = _Acceptor.made
    assert isinstance(acceptor.gate, HandshakeGate)
    assert acceptor.udp is not None and acceptor.tcp is None


async def test_the_one_gate_goes_to_the_tcp_acceptor() -> None:
    captured: dict[str, Any] = {}
    _Acceptor.made = []

    async def _listener(_config: Any) -> _Listener:
        return _Listener()

    with (
        _base_patches(captured),
        patch("dsm.server.server_gate_keys", return_value=KEYS),
        patch("dsm.server._open_tcp_listener", _listener),
        patch("dsm.server.ClientAcceptor", _Acceptor),
    ):
        rc = await _run_until(
            replace(_server_config(), dns_blocklist=False, transport="tcp"), captured
        )
    assert rc == 0
    (acceptor,) = _Acceptor.made
    assert isinstance(acceptor.gate, HandshakeGate)
    assert acceptor.tcp is not None and acceptor.udp is None
