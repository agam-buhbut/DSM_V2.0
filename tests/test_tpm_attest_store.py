"""TPM-backend Python tests for Task 3.10.

Two lanes:

  * The ``attest_tpm_tcti`` config-validation tests need only
    ``dsm.core.config`` — they run under EITHER wheel (no tuncore import,
    no TPM), mirroring ``tests/test_config.py``'s ``_base()`` pattern.

  * The store-roundtrip / preflight / backend-flag tests gate on the
    ``swtpm_tcti`` fixture (``tests/conftest.py``), which SKIPS under the soft
    wheel and spins up a hermetic swtpm under the TPM wheel.
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_public_key

from dsm.core.config import Config


def _base(**overrides: Any) -> dict[str, Any]:
    """Valid base client config dict (same shape as tests/test_config.py)."""
    defaults: dict[str, Any] = {
        "mode": "client",
        "server_ip": "10.0.0.1",
        "server_port": 51820,
        "listen_port": 51821,
        "key_file": "/tmp/test.key",
        "cert_file": "/tmp/test.crt",
        "ca_root_file": "/tmp/test-ca.pem",
        "attest_key_file": "/tmp/test-attest.key",
        "expected_server_cn": "dsm-test-server",
        "transport": "udp",
    }
    defaults.update(overrides)
    return defaults


class TestAttestTpmTctiConfig:
    """attest_tpm_tcti validation — wheel-agnostic (no tuncore/TPM)."""

    def test_default_is_none(self) -> None:
        assert Config(**_base()).attest_tpm_tcti is None

    def test_accepts_device_tcti(self) -> None:
        c = Config(**_base(attest_tpm_tcti="device:/dev/tpmrm0"))
        assert c.attest_tpm_tcti == "device:/dev/tpmrm0"

    def test_accepts_swtpm_tcti(self) -> None:
        c = Config(**_base(attest_tpm_tcti="swtpm:host=127.0.0.1,port=2321"))
        assert c.attest_tpm_tcti == "swtpm:host=127.0.0.1,port=2321"

    def test_rejects_unknown_family(self) -> None:
        with pytest.raises(ValueError):
            Config(**_base(attest_tpm_tcti="nonsense"))

    def test_rejects_empty_string(self) -> None:
        # An unset TCTI must be None, not "".
        with pytest.raises(ValueError):
            Config(**_base(attest_tpm_tcti=""))


def _verify_p256(spki_der: bytes, msg: bytes, sig_der: bytes) -> None:
    """Verify a DER ECDSA-SHA256 signature against an SPKI DER public key.

    Raises ``cryptography.exceptions.InvalidSignature`` on mismatch.
    """
    pub = load_der_public_key(spki_der)
    assert isinstance(pub, ec.EllipticCurvePublicKey)
    pub.verify(sig_der, msg, ec.ECDSA(hashes.SHA256()))


class TestTpmAttestStore:
    """TPM-backend AttestStore + preflight. Skipped under the soft wheel via
    the swtpm_tcti fixture."""

    def test_backend_flag_is_tpm(self, swtpm_tcti: str) -> None:
        # The fixture already skips unless this is False, but assert it
        # explicitly so the lane's intent is documented in the test body.
        import tuncore

        assert tuncore.ATTEST_BACKEND_IS_SOFTWARE is False

    def test_generate_produces_key_and_blob(self, swtpm_tcti: str, tmp_path) -> None:
        from dsm.crypto.attest_store import AttestStore

        path = tmp_path / "attest.key"
        store = AttestStore(str(path))
        # generate() creates the key with EMPTY auth and binds the passphrase as
        # the key's TPM auth at store time (Task 3.12). The in-memory key is the
        # fresh empty-auth one (the enroll CSR path), so it signs right away.
        spki = store.generate(b"operator-passphrase")
        assert store.is_loaded
        assert path.is_file()
        assert path.read_bytes()[:4] == b"DSMT"  # TPM context blob, not DSMK
        assert len(spki) == 91  # fixed-size P-256 SubjectPublicKeyInfo
        # The freshly generated (empty-auth) key signs before any reload — this
        # mirrors enroll.build_csr, which signs the CSR with the in-memory key
        # immediately after generate().
        msg = b"enroll CSR: fresh empty-auth key signs before reload"
        _verify_p256(spki, msg, bytes(store.attest_key.sign(msg)))
        store.unload()

    def test_store_roundtrip_signs_and_verifies(
        self, swtpm_tcti: str, tmp_path
    ) -> None:
        from dsm.crypto.attest_store import AttestStore

        path = tmp_path / "attest.key"
        store = AttestStore(str(path))
        # The passphrase is now LOAD-BEARING on the TPM backend (Task 3.12): it
        # is bound as the key's TPM auth at store time.
        passphrase = b"correct-operator-passphrase"
        spki = store.generate(passphrase)
        store.unload()

        # Reload from the DSMT blob with the SAME passphrase: the TPM-resident
        # key reloads to the identical public key and its derived auth lets it
        # sign.
        store2 = AttestStore(str(path))
        spki2 = store2.load(passphrase)
        assert spki2 == spki

        # The restored key signs (auth installed via tr_set_auth) and the
        # signature verifies under its own SPKI.
        msg = b"DSM-BIND-v1\x00 task-3.12 roundtrip"
        sig = store2.attest_key.sign(msg)
        _verify_p256(spki2, msg, bytes(sig))
        with pytest.raises(InvalidSignature):
            _verify_p256(spki2, b"tampered", bytes(sig))
        store2.unload()

    def test_wrong_passphrase_fails_to_sign(self, swtpm_tcti: str, tmp_path) -> None:
        # SECURITY (Task 3.12): the passphrase is bound as the key's TPM auth, so
        # loading with the WRONG passphrase reconstructs the key (same public)
        # but derives the wrong auth — the TPM then REJECTS the sign with an
        # authorization-HMAC failure. Disk blob + TPM access are NOT enough
        # without the passphrase.
        from dsm.crypto.attest_store import AttestStore

        path = tmp_path / "attest.key"
        store = AttestStore(str(path))
        spki = store.generate(b"the-real-passphrase")
        store.unload()

        # Reload with a wrong passphrase: load() itself succeeds (no TPM call;
        # the public reconstructs and SPKI matches), but signing must fail.
        store_bad = AttestStore(str(path))
        spki_bad = store_bad.load(b"a-wrong-passphrase")
        assert spki_bad == spki  # same key material — only the auth is wrong
        with pytest.raises(RuntimeError) as ei:
            store_bad.attest_key.sign(b"attempt to sign without the passphrase")
        # Must be the TPM authorization rejection, not an incidental error.
        msg = str(ei.value).lower()
        assert "tpm error" in msg and "authorization" in msg, (
            f"wrong-passphrase sign must fail with the TPM auth rejection, "
            f"got: {ei.value}"
        )
        store_bad.unload()

    def test_preflight_passes_on_reachable_swtpm(self, swtpm_tcti: str) -> None:
        from dsm.crypto.tpm_preflight import preflight_tpm

        # swtpm is up and the Owner hierarchy has empty auth — must not raise.
        preflight_tpm(swtpm_tcti)

    def test_preflight_raises_actionable_error_when_tcti_is_dead(
        self, swtpm_tcti: str, monkeypatch
    ) -> None:
        from dsm.crypto.tpm_preflight import TpmPreflightError, preflight_tpm

        # Point the backend at a swtpm TCTI that nothing is listening on, then
        # confirm the preflight surfaces a typed, actionable error rather than a
        # raw tss-esapi failure. _free_port reserves an unused port.
        from tests.conftest import _free_port

        dead = f"swtpm:host=127.0.0.1,port={_free_port()}"
        monkeypatch.setenv("TCTI", dead)
        with pytest.raises(TpmPreflightError) as ei:
            preflight_tpm(dead)
        # The guidance names the endpoint and points at the device/group fix.
        assert dead in str(ei.value)
        assert "tss" in str(ei.value)
