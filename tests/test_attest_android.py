"""Tests for ``dsm.crypto.attest_android``: the opt-in, default-OFF server/CA
mobile (Android Keystore) hardware-attestation profile.

All chains are SYNTHETIC (see tests/android_attest_helpers.py): a fake
Google-rooted hardware-attestation hierarchy built offline. No network, no
real Google root.
"""

from __future__ import annotations

import datetime
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import NameOID

from dsm.core.config import Config
from dsm.crypto.attest_android import (
    AndroidAttestAuthorizationError,
    AndroidAttestBindingError,
    AndroidAttestChainError,
    AndroidAttestConfigError,
    AndroidAttestExtensionError,
    AndroidAttestProfileDisabledError,
    AndroidAttestRevokedError,
    AndroidAttestRootOfTrustError,
    AndroidAttestSecurityLevelError,
    AndroidAttestUntrustedRootError,
    AndroidSecurityLevel,
    verify_android_key_attestation,
    verify_mobile_enrollment,
)
from tests.android_attest_helpers import (
    make_attestation_root,
    make_synthetic_chain,
)

# StrongBox / TEE / Software ASN.1 ENUMERATED values.
_STRONGBOX = 2
_TEE = 1
_SOFTWARE = 0


def _noise_static() -> bytes:
    # A deterministic-looking 32-byte X25519-static stand-in (content is
    # opaque to the verifier; only exact-match matters).
    return bytes(range(32))


def _spki(priv: ec.EllipticCurvePrivateKey) -> bytes:
    return priv.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )


def _make_config(tmp: Path, **overrides: object) -> Config:
    base: dict[str, object] = {
        "mode": "client",
        "server_ip": "203.0.113.1",
        "server_port": 51820,
        "listen_port": 0,
        "key_file": "/opt/mtun/identity.key",
        "cert_file": "/opt/mtun/device.crt",
        "ca_root_file": "/opt/mtun/dsm_ca_root.pem",
        "attest_key_file": "/opt/mtun/attest.key",
        "expected_server_cn": "dsm-1234abcd-server",
        "config_dir": tmp,
    }
    base.update(overrides)
    return Config(**base)  # type: ignore[arg-type]


class VerifyChainAccept(unittest.TestCase):
    def test_strongbox_chain_with_matching_binding_accepted(self) -> None:
        challenge = _noise_static()
        ch = make_synthetic_chain(challenge=challenge)
        result = verify_android_key_attestation(
            attestation_chain_der=ch.chain_der,
            google_root=ch.root.certificate,
            expected_attested_spki_der=ch.attested_spki_der,
            expected_challenge=challenge,
        )
        self.assertEqual(
            result.attestation_security_level, AndroidSecurityLevel.STRONG_BOX
        )
        self.assertEqual(
            result.keymaster_security_level, AndroidSecurityLevel.STRONG_BOX
        )
        self.assertEqual(result.attestation_challenge, challenge)
        self.assertEqual(result.attested_spki_der, ch.attested_spki_der)

    def test_root_included_in_chain_accepted(self) -> None:
        challenge = _noise_static()
        ch = make_synthetic_chain(challenge=challenge, include_root_in_chain=True)
        result = verify_android_key_attestation(
            attestation_chain_der=ch.chain_der,
            google_root=ch.root.certificate,
            expected_attested_spki_der=ch.attested_spki_der,
            expected_challenge=challenge,
        )
        self.assertEqual(
            result.keymaster_security_level, AndroidSecurityLevel.STRONG_BOX
        )

    def test_rsa_rooted_chain_accepted(self) -> None:
        challenge = _noise_static()
        ch = make_synthetic_chain(challenge=challenge, use_rsa_root=True)
        result = verify_android_key_attestation(
            attestation_chain_der=ch.chain_der,
            google_root=ch.root.certificate,
            expected_attested_spki_der=ch.attested_spki_der,
            expected_challenge=challenge,
        )
        self.assertEqual(
            result.attestation_security_level, AndroidSecurityLevel.STRONG_BOX
        )

    def test_tee_accepted_when_min_is_tee(self) -> None:
        challenge = _noise_static()
        ch = make_synthetic_chain(
            challenge=challenge,
            attestation_security_level=_TEE,
            keymaster_security_level=_TEE,
        )
        result = verify_android_key_attestation(
            attestation_chain_der=ch.chain_der,
            google_root=ch.root.certificate,
            expected_attested_spki_der=ch.attested_spki_der,
            expected_challenge=challenge,
            min_security_level=AndroidSecurityLevel.TRUSTED_ENVIRONMENT,
        )
        self.assertEqual(
            result.keymaster_security_level,
            AndroidSecurityLevel.TRUSTED_ENVIRONMENT,
        )


class VerifyChainReject(unittest.TestCase):
    def test_software_level_rejected_when_strongbox_required(self) -> None:
        challenge = _noise_static()
        ch = make_synthetic_chain(
            challenge=challenge,
            attestation_security_level=_SOFTWARE,
            keymaster_security_level=_SOFTWARE,
        )
        with self.assertRaises(AndroidAttestSecurityLevelError):
            verify_android_key_attestation(
                attestation_chain_der=ch.chain_der,
                google_root=ch.root.certificate,
                expected_attested_spki_der=ch.attested_spki_der,
                expected_challenge=challenge,
            )

    def test_tee_rejected_when_strongbox_required(self) -> None:
        challenge = _noise_static()
        ch = make_synthetic_chain(
            challenge=challenge,
            attestation_security_level=_TEE,
            keymaster_security_level=_TEE,
        )
        with self.assertRaises(AndroidAttestSecurityLevelError):
            verify_android_key_attestation(
                attestation_chain_der=ch.chain_der,
                google_root=ch.root.certificate,
                expected_attested_spki_der=ch.attested_spki_der,
                expected_challenge=challenge,
            )

    def test_keymaster_software_even_if_attestation_strongbox_rejected(
        self,
    ) -> None:
        # Defence-in-depth: BOTH levels must clear the bar. A chain claiming
        # StrongBox attestation but a software-resident key is rejected.
        challenge = _noise_static()
        ch = make_synthetic_chain(
            challenge=challenge,
            attestation_security_level=_STRONGBOX,
            keymaster_security_level=_SOFTWARE,
        )
        with self.assertRaises(AndroidAttestSecurityLevelError):
            verify_android_key_attestation(
                attestation_chain_der=ch.chain_der,
                google_root=ch.root.certificate,
                expected_attested_spki_der=ch.attested_spki_der,
                expected_challenge=challenge,
            )

    def test_untrusted_root_rejected(self) -> None:
        challenge = _noise_static()
        ch = make_synthetic_chain(challenge=challenge)
        # Pin a DIFFERENT, unrelated root than the one that issued the chain.
        other_root = make_attestation_root(common_name="Attacker Root")
        with self.assertRaises(AndroidAttestUntrustedRootError):
            verify_android_key_attestation(
                attestation_chain_der=ch.chain_der,
                google_root=other_root.certificate,
                expected_attested_spki_der=ch.attested_spki_der,
                expected_challenge=challenge,
            )

    def test_attested_key_mismatch_rejected(self) -> None:
        challenge = _noise_static()
        ch = make_synthetic_chain(challenge=challenge)
        wrong_key = ec.generate_private_key(ec.SECP256R1())
        with self.assertRaises(AndroidAttestBindingError):
            verify_android_key_attestation(
                attestation_chain_der=ch.chain_der,
                google_root=ch.root.certificate,
                expected_attested_spki_der=_spki(wrong_key),
                expected_challenge=challenge,
            )

    def test_challenge_mismatch_rejected(self) -> None:
        challenge = _noise_static()
        ch = make_synthetic_chain(challenge=challenge)
        with self.assertRaises(AndroidAttestBindingError):
            verify_android_key_attestation(
                attestation_chain_der=ch.chain_der,
                google_root=ch.root.certificate,
                expected_attested_spki_der=ch.attested_spki_der,
                expected_challenge=b"\xaa" * 32,  # wrong Noise static
            )

    def test_missing_extension_rejected(self) -> None:
        # A leaf without the key-attestation extension cannot prove anything.
        challenge = _noise_static()
        ch = make_synthetic_chain(challenge=challenge)
        # Re-issue a plain leaf (no attestation ext) under the same key/chain.
        start = datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=60)
        plain_leaf = (
            x509.CertificateBuilder()
            .subject_name(
                x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "no-ext")])
            )
            .issuer_name(ch.intermediate.certificate.subject)
            .public_key(ch.attested_priv.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(start)
            .not_valid_after(start + datetime.timedelta(days=365))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True
            )
            .sign(private_key=ch.intermediate.private_key, algorithm=hashes.SHA256())
        )
        chain = [plain_leaf.public_bytes(Encoding.DER), ch.intermediate.der]
        with self.assertRaises(AndroidAttestExtensionError):
            verify_android_key_attestation(
                attestation_chain_der=chain,
                google_root=ch.root.certificate,
                expected_attested_spki_der=ch.attested_spki_der,
                expected_challenge=challenge,
            )

    def test_empty_chain_rejected(self) -> None:
        root = make_attestation_root()
        with self.assertRaises(AndroidAttestChainError):
            verify_android_key_attestation(
                attestation_chain_der=[],
                google_root=root.certificate,
                expected_attested_spki_der=b"",
                expected_challenge=b"",
            )


class MobileEnrollmentGate(unittest.TestCase):
    def test_disabled_by_default_not_attempted(self) -> None:
        with TemporaryDirectory() as d:
            cfg = _make_config(Path(d))  # allow_android_keystore_attest defaults off
            # A deliberately un-parseable chain proves we short-circuit BEFORE
            # any chain work: we get "disabled", not a chain/parse error.
            with self.assertRaises(AndroidAttestProfileDisabledError):
                verify_mobile_enrollment(
                    attestation_chain_der=[b"not-a-cert"],
                    expected_attested_spki_der=b"x",
                    expected_noise_static=b"y",
                    config=cfg,
                )

    def test_enabled_without_root_file_config_error(self) -> None:
        with TemporaryDirectory() as d:
            cfg = _make_config(Path(d), allow_android_keystore_attest=True)
            with self.assertRaises(AndroidAttestConfigError):
                verify_mobile_enrollment(
                    attestation_chain_der=[b"not-a-cert"],
                    expected_attested_spki_der=b"x",
                    expected_noise_static=b"y",
                    config=cfg,
                )

    def test_enabled_happy_path_through_config(self) -> None:
        challenge = _noise_static()
        ch = make_synthetic_chain(challenge=challenge)
        with TemporaryDirectory() as d:
            root_pem = Path(d) / "google_root.pem"
            root_pem.write_bytes(ch.root.certificate.public_bytes(Encoding.PEM))
            cfg = _make_config(
                Path(d),
                allow_android_keystore_attest=True,
                android_attest_root_file=str(root_pem),
                android_attest_min_security_level="strongbox",
            )
            result = verify_mobile_enrollment(
                attestation_chain_der=ch.chain_der,
                expected_attested_spki_der=ch.attested_spki_der,
                expected_noise_static=challenge,
                config=cfg,
            )
            self.assertEqual(
                result.keymaster_security_level, AndroidSecurityLevel.STRONG_BOX
            )

    def test_enabled_tee_min_via_config_accepts_tee(self) -> None:
        challenge = _noise_static()
        ch = make_synthetic_chain(
            challenge=challenge,
            attestation_security_level=_TEE,
            keymaster_security_level=_TEE,
        )
        with TemporaryDirectory() as d:
            root_pem = Path(d) / "google_root.pem"
            root_pem.write_bytes(ch.root.certificate.public_bytes(Encoding.PEM))
            cfg = _make_config(
                Path(d),
                allow_android_keystore_attest=True,
                android_attest_root_file=str(root_pem),
                android_attest_min_security_level="tee",
            )
            result = verify_mobile_enrollment(
                attestation_chain_der=ch.chain_der,
                expected_attested_spki_der=ch.attested_spki_der,
                expected_noise_static=challenge,
                config=cfg,
            )
            self.assertEqual(
                result.attestation_security_level,
                AndroidSecurityLevel.TRUSTED_ENVIRONMENT,
            )


class VerifyAuthorizationList(unittest.TestCase):
    """teeEnforced origin/purpose enforcement (security review H1/H2)."""

    def test_generated_sign_key_accepted(self) -> None:
        # origin=GENERATED(0) + purpose including SIGN(2) (plus an unrelated
        # purpose) is accepted.
        challenge = _noise_static()
        ch = make_synthetic_chain(
            challenge=challenge, tee_origin=0, tee_purposes=(2, 3)
        )
        result = verify_android_key_attestation(
            attestation_chain_der=ch.chain_der,
            google_root=ch.root.certificate,
            expected_attested_spki_der=ch.attested_spki_der,
            expected_challenge=challenge,
        )
        self.assertEqual(result.attested_spki_der, ch.attested_spki_der)

    def test_imported_key_rejected(self) -> None:
        # origin=IMPORTED(2): the private half may be attacker-held — reject
        # even though the security level reads StrongBox.
        challenge = _noise_static()
        ch = make_synthetic_chain(challenge=challenge, tee_origin=2)
        with self.assertRaises(AndroidAttestAuthorizationError):
            verify_android_key_attestation(
                attestation_chain_der=ch.chain_der,
                google_root=ch.root.certificate,
                expected_attested_spki_der=ch.attested_spki_der,
                expected_challenge=challenge,
            )

    def test_purpose_without_sign_rejected(self) -> None:
        # purpose lacks SIGN(2) (only ENCRYPT(0)/DECRYPT(1)).
        challenge = _noise_static()
        ch = make_synthetic_chain(challenge=challenge, tee_purposes=(0, 1))
        with self.assertRaises(AndroidAttestAuthorizationError):
            verify_android_key_attestation(
                attestation_chain_der=ch.chain_der,
                google_root=ch.root.certificate,
                expected_attested_spki_der=ch.attested_spki_der,
                expected_challenge=challenge,
            )

    def test_missing_origin_rejected(self) -> None:
        # teeEnforced carries no origin → cannot prove the key was GENERATED.
        challenge = _noise_static()
        ch = make_synthetic_chain(challenge=challenge, tee_origin=None)
        with self.assertRaises(AndroidAttestAuthorizationError):
            verify_android_key_attestation(
                attestation_chain_der=ch.chain_der,
                google_root=ch.root.certificate,
                expected_attested_spki_der=ch.attested_spki_der,
                expected_challenge=challenge,
            )


class VerifyRevocation(unittest.TestCase):
    """Operator-supplied attestation-revocation-list enforcement (AND-4)."""

    def test_revoked_leaf_serial_rejected(self) -> None:
        challenge = _noise_static()
        ch = make_synthetic_chain(challenge=challenge)
        leaf = x509.load_der_x509_certificate(ch.chain_der[0])
        with self.assertRaises(AndroidAttestRevokedError):
            verify_android_key_attestation(
                attestation_chain_der=ch.chain_der,
                google_root=ch.root.certificate,
                expected_attested_spki_der=ch.attested_spki_der,
                expected_challenge=challenge,
                revoked_serials={leaf.serial_number},
            )

    def test_revoked_intermediate_serial_rejected(self) -> None:
        challenge = _noise_static()
        ch = make_synthetic_chain(challenge=challenge)
        with self.assertRaises(AndroidAttestRevokedError):
            verify_android_key_attestation(
                attestation_chain_der=ch.chain_der,
                google_root=ch.root.certificate,
                expected_attested_spki_der=ch.attested_spki_der,
                expected_challenge=challenge,
                revoked_serials=[ch.intermediate.certificate.serial_number],
            )

    def test_unrelated_revocation_list_still_accepts(self) -> None:
        # A revocation list that contains no chain serial leaves the otherwise
        # valid chain accepted — no false positives.
        challenge = _noise_static()
        ch = make_synthetic_chain(challenge=challenge)
        result = verify_android_key_attestation(
            attestation_chain_der=ch.chain_der,
            google_root=ch.root.certificate,
            expected_attested_spki_der=ch.attested_spki_der,
            expected_challenge=challenge,
            revoked_serials={0xDEADBEEF},
        )
        self.assertEqual(result.attestation_challenge, challenge)

    def test_default_none_revocation_is_unchanged(self) -> None:
        # Omitting revoked_serials (the default) verifies exactly as before.
        challenge = _noise_static()
        ch = make_synthetic_chain(challenge=challenge)
        result = verify_android_key_attestation(
            attestation_chain_der=ch.chain_der,
            google_root=ch.root.certificate,
            expected_attested_spki_der=ch.attested_spki_der,
            expected_challenge=challenge,
        )
        self.assertEqual(result.attested_spki_der, ch.attested_spki_der)


class VerifyRootOfTrust(unittest.TestCase):
    """Opt-in verified-boot / bootloader-lock gate (require_locked, AND-4)."""

    def test_locked_verified_accepted_when_required(self) -> None:
        challenge = _noise_static()
        ch = make_synthetic_chain(
            challenge=challenge, tee_root_of_trust=(True, 0)  # locked, Verified
        )
        result = verify_android_key_attestation(
            attestation_chain_der=ch.chain_der,
            google_root=ch.root.certificate,
            expected_attested_spki_der=ch.attested_spki_der,
            expected_challenge=challenge,
            require_locked=True,
        )
        self.assertEqual(
            result.keymaster_security_level, AndroidSecurityLevel.STRONG_BOX
        )

    def test_unlocked_rejected_when_required(self) -> None:
        challenge = _noise_static()
        ch = make_synthetic_chain(
            challenge=challenge, tee_root_of_trust=(False, 0)  # unlocked
        )
        with self.assertRaises(AndroidAttestRootOfTrustError):
            verify_android_key_attestation(
                attestation_chain_der=ch.chain_der,
                google_root=ch.root.certificate,
                expected_attested_spki_der=ch.attested_spki_der,
                expected_challenge=challenge,
                require_locked=True,
            )

    def test_unverified_boot_state_rejected_when_required(self) -> None:
        challenge = _noise_static()
        ch = make_synthetic_chain(
            challenge=challenge, tee_root_of_trust=(True, 2)  # locked, Unverified
        )
        with self.assertRaises(AndroidAttestRootOfTrustError):
            verify_android_key_attestation(
                attestation_chain_der=ch.chain_der,
                google_root=ch.root.certificate,
                expected_attested_spki_der=ch.attested_spki_der,
                expected_challenge=challenge,
                require_locked=True,
            )

    def test_missing_root_of_trust_rejected_when_required(self) -> None:
        # The default chain carries no RootOfTrust; require_locked must fail
        # closed rather than silently pass.
        challenge = _noise_static()
        ch = make_synthetic_chain(challenge=challenge)
        with self.assertRaises(AndroidAttestRootOfTrustError):
            verify_android_key_attestation(
                attestation_chain_der=ch.chain_der,
                google_root=ch.root.certificate,
                expected_attested_spki_der=ch.attested_spki_der,
                expected_challenge=challenge,
                require_locked=True,
            )

    def test_unlocked_ignored_when_not_required(self) -> None:
        # Default require_locked=False: an unlocked device still verifies (the
        # gate is strictly opt-in), so existing callers are unaffected.
        challenge = _noise_static()
        ch = make_synthetic_chain(challenge=challenge, tee_root_of_trust=(False, 2))
        result = verify_android_key_attestation(
            attestation_chain_der=ch.chain_der,
            google_root=ch.root.certificate,
            expected_attested_spki_der=ch.attested_spki_der,
            expected_challenge=challenge,
        )
        self.assertEqual(result.attestation_challenge, challenge)


if __name__ == "__main__":
    unittest.main()
