"""Why the server refused a client, in one line with no address (QA M3).

A client whose cert chained to the CA and whose attest signature checked
out is named, with the reason: not on the allowlist, revoked, or the wrong
type of cert (signed with the server profile). The netaudit event stays
coarse. dsm enroll --import refuses a cert of the wrong type for the mode.
Real handshakes over loopback UDP, as in tests/test_handshake_admit_hook.py.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterator
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ExtendedKeyUsageOID

from dsm.crypto import handshake
from dsm.crypto.cert_allowlist import CNAllowlist
from dsm.crypto.enroll import EnrollError, import_signed_cert
from dsm.crypto.handshake import (
    CertAuthError,
    CertRevokedError,
    CNNotAllowedError,
    WrongCertTypeError,
    client_handshake,
    server_handshake,
)
from dsm.net.handshake_acceptor import _log_cert_refusal, _run_attempt
from tests.cert_helpers import SERVER_AUTH_OID, make_enrolled_device, make_test_ca
from tests.test_handshake_admit_hook import _udp_pair

CLIENT_CN = "dsm-refused-client"
SERVER_CN = "dsm-refused-server"


@pytest.fixture(autouse=True)
def _no_so_mark() -> Iterator[None]:
    with (
        patch("dsm.net.transport.udp.apply_so_mark", lambda sock: None),
        patch("dsm.net.transport.tcp.apply_so_mark", lambda sock: None),
        patch.object(handshake, "HANDSHAKE_TIMEOUT", 0.2),
        patch.object(handshake, "BACKOFF_BASE", 0.01),
    ):
        yield


async def _server_result(
    *, client_eku: object, allow: set[str]
) -> BaseException | None:
    ca = make_test_ca()
    client = make_enrolled_device(ca, subject_cn=CLIENT_CN, eku=client_eku)  # type: ignore[arg-type]
    server = make_enrolled_device(ca, subject_cn=SERVER_CN, eku=SERVER_AUTH_OID)
    server_t, client_t, addr = await _udp_pair()
    try:
        results = await asyncio.wait_for(
            asyncio.gather(
                client_handshake(
                    client_t,
                    client.identity,
                    addr,
                    attest_key=client.attest_key,
                    cert_der=client.cert_der,
                    ca_root=ca.certificate,
                    expected_server_cn=SERVER_CN,
                ),
                server_handshake(
                    server_t,
                    server.identity,
                    attest_key=server.attest_key,
                    cert_der=server.cert_der,
                    ca_root=ca.certificate,
                    cn_allowlist=CNAllowlist(cns=frozenset(allow)),
                    required_client_eku=ExtendedKeyUsageOID.CLIENT_AUTH,
                ),
                return_exceptions=True,
            ),
            timeout=30.0,
        )
    finally:
        await client_t.aclose()
        await server_t.aclose()
    outcome = results[1]
    return outcome if isinstance(outcome, BaseException) else None


async def test_a_server_profile_cert_is_the_wrong_type_and_named() -> None:
    err = await _server_result(client_eku=SERVER_AUTH_OID, allow={CLIENT_CN})
    assert isinstance(err, WrongCertTypeError)
    assert err.cn == CLIENT_CN


async def test_a_cn_not_on_the_allowlist_is_named() -> None:
    err = await _server_result(
        client_eku=ExtendedKeyUsageOID.CLIENT_AUTH, allow={"dsm-someone-else"}
    )
    assert isinstance(err, CNNotAllowedError)
    assert err.cn == CLIENT_CN
    assert str(err) == f"client CN {CLIENT_CN!r} not in allowlist"


@pytest.mark.parametrize(
    ("err", "line"),
    [
        (
            CNNotAllowedError("x", cn="dsm-a-client"),
            "client_cn=dsm-a-client refused: not in the allowlist",
        ),
        (
            CertRevokedError("x", cn="dsm-a-client"),
            "client_cn=dsm-a-client refused: revoked",
        ),
        (
            WrongCertTypeError("x", cn="dsm-a-client"),
            "client_cn=dsm-a-client refused: wrong certificate type",
        ),
    ],
)
def test_a_proven_cn_gets_an_info_line_with_the_reason(
    err: Exception, line: str, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="dsm")
    _log_cert_refusal(err)
    assert [(r.levelno, r.getMessage()) for r in caplog.records] == [
        (logging.INFO, line)
    ]


def test_an_unproven_cert_gets_no_name_and_no_address(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="dsm")
    _log_cert_refusal(CertAuthError("client attestation verify failed: chain"))
    assert [(r.levelno, r.getMessage()) for r in caplog.records] == [
        (logging.WARNING, "handshake rejected (cert auth)")
    ]


def test_enroll_import_refuses_a_cert_of_the_wrong_type(tmp_path: Path) -> None:
    ca = make_test_ca()
    device = make_enrolled_device(
        ca, subject_cn="dsm-wrongtype-client", eku=SERVER_AUTH_OID
    )
    cert_in = tmp_path / "signed.pem"
    cert_in.write_bytes(device.cert.public_bytes(Encoding.PEM))
    ca_path = tmp_path / "ca.pem"
    ca_path.write_bytes(ca.pem)
    keystore = MagicMock()
    keystore.identity = device.identity
    attest = MagicMock()
    attest.attest_key = device.attest_key
    out = tmp_path / "device.crt"
    with pytest.raises(EnrollError, match="not a client certificate"):
        import_signed_cert(
            cert_input_path=cert_in,
            cert_output_path=out,
            ca_root_path=ca_path,
            keystore=keystore,
            attest_store=attest,
            role="client",
        )
    assert not out.exists()


def test_a_cn_with_a_newline_cannot_forge_a_log_line(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="dsm")
    _log_cert_refusal(CNNotAllowedError("x", cn="a\nb"))
    (record,) = caplog.records
    assert record.getMessage() == "client_cn='a\\nb' refused: not in the allowlist"


async def test_the_acceptor_logs_the_refusal_without_the_address(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # QA M3's line came from _run_attempt: it named the IP:port, not the CN.
    refused = CNNotAllowedError(
        f"client CN {CLIENT_CN!r} not in allowlist", cn=CLIENT_CN
    )
    caplog.set_level(logging.INFO, logger="dsm")
    with patch("dsm.crypto.handshake.server_handshake", AsyncMock(side_effect=refused)):
        await _run_attempt(
            MagicMock(),
            MagicMock(),
            MagicMock(),
            MagicMock(),
            MagicMock(),
            MagicMock(),
            ("203.0.113.5", 40112),
            MagicMock(),
            who="('203.0.113.5', 40112)",
            table=MagicMock(),
        )
    lines = [r.getMessage() for r in caplog.records]
    assert f"client_cn={CLIENT_CN} refused: not in the allowlist" in lines
    assert not any("203.0.113.5" in line for line in lines)
