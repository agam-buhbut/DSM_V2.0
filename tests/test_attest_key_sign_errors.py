"""An attest key that cannot sign stops the daemon at start (#53), and a sign
the TPM refuses during a client handshake is a failed try (#16).

On the TPM build the TPM first loads the attest key at its first sign, so a
key from a cleared TPM, or from another TPM, passed every start-up check.
Stand-in keys raise the RuntimeError that tuncore gives for every TPM fault,
so no TPM is needed. Nothing waits on the wall clock.
"""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import cast
from unittest.mock import MagicMock, patch

import pytest
from cryptography.x509.oid import ExtendedKeyUsageOID

import tuncore
from dsm.crypto.attest_store import AttestStore
from dsm.crypto.auth_loader import (
    AttestKeyUnusableError,
    AuthMaterialsError,
    verify_cert_matches_identity,
)
from dsm.crypto.cert_allowlist import CNAllowlist
from dsm.crypto.handshake import (
    CertAuthError,
    HandshakeError,
    client_handshake,
    server_handshake,
)
from dsm.crypto.keystore import KeyStore
from dsm.crypto.tpm_preflight import tcti_in_use
from dsm.server import run_server
from tests.cert_helpers import (
    CLIENT_AUTH_OID,
    SERVER_AUTH_OID,
    EnrolledDevice,
    make_enrolled_device,
    make_test_ca,
)
from tests.test_client_fail_closed import _Run
from tests.test_handshake_resent_msg1 import _SERVER, _link
from tests.test_server_dns_fatal import _base_patches, _server_config

# What tuncore raised on the box for a key the TPM could not load (#53).
_INTEGRITY = "TPM error: integrity check failed (associated with parameter number 1)"
# A TPM in dictionary-attack lockout, which another TPM user can cause (#16).
_LOCKOUT = "TPM error: the TPM is in DA lockout mode"
_SWTPM = "swtpm:host=127.0.0.1,port=2321"
_KEY_FILE = Path("/opt/mtun/attest.key")


def _device(cn: str = "dsm-53-server") -> EnrolledDevice:
    return make_enrolled_device(make_test_ca(), subject_cn=cn, eku=SERVER_AUTH_OID)


def _stores(
    device: EnrolledDevice, sign_error: str | None
) -> tuple[KeyStore, AttestStore, MagicMock]:
    """Both stores, loaded with ``device``'s keys. With ``sign_error`` the
    attest key's sign raises it as a RuntimeError, as tuncore does."""
    keystore = MagicMock(spec=KeyStore)
    keystore.identity = device.identity
    key = MagicMock(wraps=device.attest_key)
    if sign_error is not None:
        key.sign.side_effect = RuntimeError(sign_error)
    attest_store = MagicMock(spec=AttestStore)
    attest_store.path = _KEY_FILE
    attest_store.attest_key = key
    attest_store.public_spki_der.return_value = bytes(
        cast(tuncore.AttestKey, device.attest_key).public_spki_der()
    )
    return keystore, attest_store, key


@pytest.mark.parametrize(
    ("env", "named"),
    [
        ({}, "device:/dev/tpmrm0"),
        ({"TCTI": _SWTPM}, _SWTPM),
        # The Rust backend reads TPM2TOOLS_TCTI first.
        ({"TPM2TOOLS_TCTI": _SWTPM, "TCTI": "device:/dev/tpmrm1"}, _SWTPM),
    ],
    ids=["default", "TCTI", "TPM2TOOLS_TCTI-first"],
)
def test_an_attest_key_the_tpm_cannot_load_stops_the_start(
    env: dict[str, str], named: str
) -> None:
    device = _device()
    keystore, attest_store, key = _stores(device, _INTEGRITY)
    with patch.dict(os.environ):
        os.environ.pop("TPM2TOOLS_TCTI", None)
        os.environ.pop("TCTI", None)
        os.environ.update(env)
        with pytest.raises(AuthMaterialsError) as info:
            verify_cert_matches_identity(device.cert_der, keystore, attest_store)
    assert key.sign.call_count == 1
    message = str(info.value)
    assert message.startswith(
        f"this host's TPM cannot use its attest key {_KEY_FILE} (TCTI {named}): "
    )
    assert isinstance(info.value, AttestKeyUnusableError)
    assert _INTEGRITY in message
    assert "deploy/GUIDE.md §7g" in message
    assert isinstance(info.value.__cause__, RuntimeError)


def test_an_attest_key_that_signs_passes_the_start_check() -> None:
    device = _device()
    keystore, attest_store, key = _stores(device, None)
    verify_cert_matches_identity(device.cert_der, keystore, attest_store)
    # One real sign: on the TPM build this is the TPM's first load of the key.
    assert key.sign.call_count == 1


def test_a_cert_for_other_keys_stops_the_start_before_any_sign() -> None:
    """The sign comes after both cert checks. Keys from two enrollments (two
    passphrases) never match one cert, so the sign never sends the TPM a
    wrong passphrase, which its dictionary-attack lockout would count."""
    keystore, attest_store, key = _stores(_device(), None)
    with pytest.raises(AuthMaterialsError, match="noiseStaticBinding"):
        verify_cert_matches_identity(_device().cert_der, keystore, attest_store)
    assert key.sign.call_count == 0


def test_an_attest_key_from_another_enrollment_stops_the_start_before_any_sign() -> (
    None
):
    """The identity key matches the cert, the attest key does not: it may
    have another passphrase, so the SPKI check must come before the sign."""
    device = _device()
    keystore, _, _ = _stores(device, None)
    _, other_store, other_key = _stores(_device(), None)
    with pytest.raises(AuthMaterialsError, match="SubjectPublicKeyInfo"):
        verify_cert_matches_identity(device.cert_der, keystore, other_store)
    assert other_key.sign.call_count == 0


@pytest.mark.parametrize(
    ("env", "named"),
    [
        ({}, "device:/dev/tpmrm0"),
        ({"TCTI": _SWTPM}, _SWTPM),
        ({"TPM2TOOLS_TCTI": _SWTPM, "TCTI": "device:/dev/tpmrm1"}, _SWTPM),
        ({"TPM2TOOLS_TCTI": "", "TCTI": _SWTPM}, _SWTPM),
    ],
    ids=["default", "TCTI", "TPM2TOOLS_TCTI-first", "empty-skipped"],
)
def test_tcti_in_use_follows_the_rust_order(env: dict[str, str], named: str) -> None:
    with patch.dict(os.environ):
        os.environ.pop("TPM2TOOLS_TCTI", None)
        os.environ.pop("TCTI", None)
        os.environ.update(env)
        assert tcti_in_use() == named


class _RefusingKey:
    """An attest key whose TPM refuses every sign."""

    def __init__(self) -> None:
        self.signs = 0

    def sign(self, _msg: bytes) -> bytes:
        self.signs += 1
        raise RuntimeError(_LOCKOUT)


async def test_a_sign_the_tpm_refuses_in_a_client_handshake_is_a_handshake_error() -> (
    None
):
    """The real client_handshake against a real server over an in-memory
    link: msg2 checks out, then the client's TPM refuses the msg3 sign.
    run_client keeps the block and tries again on a HandshakeError."""
    ca = make_test_ca()
    client = make_enrolled_device(ca, subject_cn="dsm-16-client", eku=CLIENT_AUTH_OID)
    server = make_enrolled_device(ca, subject_cn="dsm-16-server", eku=SERVER_AUTH_OID)
    refusing = _RefusingKey()
    client_end, server_end = _link()
    server_task = asyncio.ensure_future(
        server_handshake(
            server_end,
            server.identity,
            attest_key=server.attest_key,
            cert_der=server.cert_der,
            ca_root=ca.certificate,
            cn_allowlist=CNAllowlist(cns=frozenset({"dsm-16-client"})),
            required_client_eku=ExtendedKeyUsageOID.CLIENT_AUTH,
        )
    )
    try:
        with pytest.raises(HandshakeError) as info:
            await client_handshake(
                client_end,
                client.identity,
                _SERVER,
                attest_key=cast(tuncore.AttestKey, refusing),
                cert_der=client.cert_der,
                ca_root=ca.certificate,
                expected_server_cn="dsm-16-server",
                required_server_eku=ExtendedKeyUsageOID.SERVER_AUTH,
            )
    finally:
        server_task.cancel()
        await asyncio.gather(server_task, return_exceptions=True)
    # Not a cert error: run_client logs it as "handshake failed: ...".
    assert not isinstance(info.value, CertAuthError)
    assert str(info.value) == f"this host's attest key could not sign: {_LOCKOUT}"
    assert isinstance(info.value.__cause__, RuntimeError)
    assert refusing.signs == 1
    assert len(client_end.sent) == 1  # msg1 only: no msg3 went out


_UNUSABLE = AttestKeyUnusableError(
    "this host's TPM cannot use its attest key /opt/mtun/attest.key "
    f"(TCTI {_SWTPM}): {_INTEGRITY}. If the TPM was cleared, enroll again."
)


def _tpm_lines(caplog: pytest.LogCaptureFixture) -> list[str]:
    lines = [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]
    assert len(lines) == 1
    assert lines[0].startswith("this host's TPM cannot use its attest key")
    assert "consistency check failed" not in lines[0]
    return lines


def test_the_unusable_key_error_is_an_auth_materials_error() -> None:
    assert issubclass(AttestKeyUnusableError, AuthMaterialsError)


async def test_the_server_logs_an_unusable_attest_key_without_the_cert_prefix(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.ERROR, logger="dsm")
    with (
        _base_patches({}),
        patch("dsm.server.verify_cert_matches_identity", side_effect=_UNUSABLE),
    ):
        rc = await asyncio.wait_for(run_server(_server_config()), 5.0)
    assert rc == 1
    _tpm_lines(caplog)


async def test_the_client_logs_an_unusable_attest_key_without_the_cert_prefix(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.ERROR, logger="dsm")
    real_patch = patch

    def _patch_verify(target: str, *args: object, **kwargs: object) -> object:
        # _Run builds its own patches inside run(); only this one differs.
        if target == "dsm.client.verify_cert_matches_identity":
            kwargs["side_effect"] = _UNUSABLE
        return real_patch(target, *args, **kwargs)

    with patch("tests.test_client_fail_closed.patch", _patch_verify):
        rc = await _Run().run()
    assert rc == 1
    _tpm_lines(caplog)
