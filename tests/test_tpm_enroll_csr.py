"""TPM-backend CSR assembly tests (Phase 3 / Task 3.7).

These exercise the Python-side ``build_csr`` TPM path: the TBS is shaped
by ``cryptography`` with a throwaway P-256 key, the TPM's exported SPKI is
substituted for the throwaway SPKI, the TPM signs the substituted TBS, and
the final ``CertificationRequest`` SEQUENCE is hand-assembled. The result
must be a valid, server-acceptable PKCS#10 indistinguishable from a
soft-produced CSR except for the (TPM-resident) key.

The whole module self-skips under the soft wheel via the ``swtpm_tcti``
fixture (it skips unless ``ATTEST_BACKEND_IS_SOFTWARE`` is False and swtpm
is installed), so the normal soft suite is unaffected. It does NOT modify
any pre-existing test.
"""

from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from dsm.crypto.cert import (
    DSM_NOISE_STATIC_BINDING_OID,
    encode_noise_static_binding_value,
)
from dsm.crypto.enroll import build_csr

# A deterministic 32-byte X25519 static so the extension comparison is exact.
_NOISE_STATIC = bytes(range(32))
_CN = "dsm-aabbcc-client"


def _spki_of(csr: x509.CertificateSigningRequest) -> bytes:
    return csr.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def test_tpm_csr_signature_is_valid(swtpm_tcti: str) -> None:
    """The TPM-assembled CSR re-parses and its signature verifies."""
    import tuncore

    attest_key = tuncore.AttestKey.generate()
    csr_der = build_csr(attest_key=attest_key, noise_static_pub=_NOISE_STATIC, cn=_CN)

    csr = x509.load_der_x509_csr(csr_der)
    assert csr.is_signature_valid


def test_tpm_csr_spki_matches_tpm_key(swtpm_tcti: str) -> None:
    """The CSR's SubjectPublicKeyInfo equals the TPM key's exported SPKI."""
    import tuncore

    attest_key = tuncore.AttestKey.generate()
    csr_der = build_csr(attest_key=attest_key, noise_static_pub=_NOISE_STATIC, cn=_CN)

    csr = x509.load_der_x509_csr(csr_der)
    assert _spki_of(csr) == bytes(attest_key.public_spki_der())


def test_tpm_csr_subject_matches(swtpm_tcti: str) -> None:
    """The CSR subject is exactly the requested CN."""
    import tuncore

    attest_key = tuncore.AttestKey.generate()
    csr_der = build_csr(attest_key=attest_key, noise_static_pub=_NOISE_STATIC, cn=_CN)

    csr = x509.load_der_x509_csr(csr_der)
    assert csr.subject.rfc4514_string() == f"CN={_CN}"


def test_tpm_csr_noise_binding_is_byte_identical_to_soft(
    swtpm_tcti: str,
) -> None:
    """The critical ``id-dsm-noiseStaticBinding`` extension in the TPM CSR is
    byte-identical to the canonical soft encoding for the same Noise static
    input. If this diverged, the server-side binding check would break."""
    import tuncore

    attest_key = tuncore.AttestKey.generate()
    csr_der = build_csr(attest_key=attest_key, noise_static_pub=_NOISE_STATIC, cn=_CN)

    csr = x509.load_der_x509_csr(csr_der)
    ext = csr.extensions.get_extension_for_oid(DSM_NOISE_STATIC_BINDING_OID)
    assert ext.critical
    # ext.value is an UnrecognizedExtension; .value is the raw extnValue bytes.
    assert isinstance(ext.value, x509.UnrecognizedExtension)
    assert ext.value.value == encode_noise_static_binding_value(_NOISE_STATIC)
