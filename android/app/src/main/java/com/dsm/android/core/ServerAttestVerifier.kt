package com.dsm.android.core

import java.io.ByteArrayInputStream
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.cert.CertificateException
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateFactory
import java.security.cert.CertificateNotYetValidException
import java.security.cert.CertificateParsingException
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.time.Instant
import java.util.Date
import java.util.Locale

/**
 * Verifies the server's attestation payload received in Noise XX msg2.
 *
 * A full implementation mirrors `verify_attest_payload` in
 * `dsm/crypto/attest.py`: unframe the payload, validate the device cert chain
 * to the pinned CA root, check the cert's noiseStaticBinding extension equals
 * the static recovered from Noise, verify the binding signature over the
 * (handshake-hash, static, RESPONDER) pre-image, and enforce the timestamp
 * window. It returns the validated server subject CN.
 */
fun interface ServerAttestVerifier {
    /**
     * @return the validated server subject CN.
     * @throws HandshakeException on any cert / binding / signature failure.
     */
    fun verify(attestPayload: ByteArray, remoteStatic: ByteArray, bindingHash: ByteArray): String
}

/** A server-attestation verification failure. Mirrors `AttestError` / `CertError`. */
class ServerAttestException(message: String, cause: Throwable? = null) : HandshakeException(message) {
    init {
        // HandshakeException's constructor takes only a message (its public API is
        // frozen), so chain the cause explicitly to preserve the diagnostic trail.
        if (cause != null) initCause(cause)
    }
}

/**
 * Real CA-pinned server attestation verifier, mirroring the Python client's
 * server check: `client_handshake` (`dsm/crypto/handshake.py`) +
 * `verify_attest_payload` (`dsm/crypto/attest.py`) + `validate_chain`
 * (`dsm/crypto/cert.py`).
 *
 * Verification uses only `java.security` (no BouncyCastle). The custom critical
 * `noiseStaticBinding` extension is handled manually — that is exactly why this
 * does NOT use [java.security.cert.CertPathValidator], which would reject the
 * unrecognized critical extension.
 *
 * SECURITY-CRITICAL: this is how the client decides the server is genuine. Every
 * error path fails closed (throws); no path returns a CN it has not fully
 * authenticated. No key material is logged.
 *
 * @param caRoot the pinned DSM CA root the server cert must chain to.
 * @param expectedServerCn the only server subject CN that will be accepted.
 * @param codec the attest-payload codec (matched to the on-wire payload size);
 *   reused for unframing and for rebuilding the 86-byte binding pre-image so the
 *   layout cannot drift from the signer side.
 * @param clockSkewSeconds freshness window for the signed timestamp (±, seconds).
 * @param clock injectable now() for deterministic tests.
 */
class RealServerAttestVerifier(
    private val caRoot: X509Certificate,
    private val expectedServerCn: String,
    private val codec: AttestPayloadCodec,
    private val clockSkewSeconds: Long = DEFAULT_CLOCK_SKEW_SECONDS,
    private val clock: () -> Instant = Instant::now,
) : ServerAttestVerifier {

    override fun verify(
        attestPayload: ByteArray,
        remoteStatic: ByteArray,
        bindingHash: ByteArray,
    ): String {
        // 1. Unframe the wire payload -> (ts, cert_der, sig_der). Mirrors
        //    attest.py::verify_attest_payload step 1.
        val unframed = try {
            codec.unframe(attestPayload)
        } catch (e: AttestPayloadCodec.FormatException) {
            throw ServerAttestException("malformed server attest payload: ${e.message}", e)
        }
        if (unframed.certDer.isEmpty() || unframed.sigDer.isEmpty()) {
            throw ServerAttestException("attest payload missing cert or signature")
        }

        // Length guards so the codec's pre-image builder cannot raise an
        // untyped IllegalArgumentException out of the verifier's contract.
        if (remoteStatic.size != AttestPayloadCodec.NOISE_STATIC_PUB_LEN) {
            throw ServerAttestException(
                "noise static from handshake has wrong length: ${remoteStatic.size}",
            )
        }
        if (bindingHash.size != AttestPayloadCodec.HANDSHAKE_HASH_LEN) {
            throw ServerAttestException("binding handshake hash has wrong length: ${bindingHash.size}")
        }

        // 2. Freshness: the signed timestamp (authenticated via the binding
        //    pre-image) must be within ±clockSkewSeconds of now. Computed in
        //    integer epoch seconds with overflow-safe arithmetic so a malicious
        //    u64 timestamp (e.g. u64::MAX) fails closed rather than throwing an
        //    untyped error. Mirrors attest.py::verify_attest_payload step 5.
        val nowSec = clock().epochSecond
        val delta = try {
            Math.subtractExact(nowSec, unframed.timestampSecs)
        } catch (e: ArithmeticException) {
            throw ServerAttestException("server attest timestamp out of representable range", e)
        }
        if (delta > clockSkewSeconds || delta < -clockSkewSeconds) {
            throw ServerAttestException(
                "server attest timestamp outside ±${clockSkewSeconds}s of now",
            )
        }

        // 3. Parse + chain-validate the leaf to the pinned CA root.
        //    Mirrors cert.py::validate_chain.
        val cert = parseCert(unframed.certDer)
        validateChain(cert)

        // 4. Subject CN must equal the pinned expected CN. Mirrors the CN check
        //    in handshake.py::client_handshake (CNMismatchError).
        val cn = subjectCn(cert)
        if (cn != expectedServerCn) {
            throw CnMismatchException(
                "server CN \"$cn\" does not match expected \"$expectedServerCn\"",
            )
        }

        // 5. Verify the per-handshake binding signature under the cert's P-256
        //    pubkey. Mirrors attest.py::verify_attest_payload step 4.
        val leafPub = cert.publicKey
        if (leafPub !is ECPublicKey) {
            throw ServerAttestException("server cert public key must be ECDSA")
        }
        // The binding ext is checked to equal remoteStatic in step 6; the static
        // the signer committed to (remoteStatic, recovered from Noise) is the
        // same value, so the reconstructed pre-image is identical to the signer's.
        val preImage = codec.bindingPreImage(
            timestamp = unframed.timestampSecs,
            handshakeHash = bindingHash,
            noiseStaticPub = remoteStatic,
            role = AttestPayloadCodec.PeerRole.RESPONDER,
        )
        verifyBindingSignature(leafPub, preImage, unframed.sigDer)

        // 6. The cert's critical noiseStaticBinding extension must equal the
        //    static recovered from the Noise handshake (constant-time compare).
        //    Mirrors attest.py step 3 + cert.py noise_static_pub.
        val certBinding = noiseStaticBinding(cert)
        if (!MessageDigest.isEqual(certBinding, remoteStatic)) {
            throw ServerAttestException(
                "cert noiseStaticBinding does not match the static from the Noise handshake",
            )
        }

        return cn
    }

    private fun parseCert(der: ByteArray): X509Certificate =
        try {
            val cf = CertificateFactory.getInstance("X.509")
            cf.generateCertificate(ByteArrayInputStream(der)) as X509Certificate
        } catch (e: CertificateException) {
            throw ServerAttestException("failed to parse server cert: ${e.message}", e)
        } catch (e: ClassCastException) {
            throw ServerAttestException("server cert is not an X.509 certificate", e)
        }

    /**
     * Single-hop DSM CA chain validation, mirroring `cert.py::validate_chain`:
     * issuer DN match, EC CA, strong signature hash, signature under the CA
     * pubkey, validity window, required serverAuth EKU, keyUsage
     * digitalSignature, and basicConstraints CA:FALSE (present + critical).
     */
    private fun validateChain(cert: X509Certificate) {
        // 1. Issuer / subject DN match.
        if (cert.issuerX500Principal != caRoot.subjectX500Principal) {
            throw ServerAttestException("server cert issuer does not match the pinned CA subject")
        }

        // 2a. The CA must be EC (single-hop DSM CA). Mirrors validate_chain's
        //     EllipticCurvePublicKey check on the CA pubkey.
        if (caRoot.publicKey !is ECPublicKey) {
            throw ServerAttestException("pinned CA pubkey is not EC; only EC CAs are supported")
        }

        // 2b. Reject weak signature hashes (SHA-1 / MD5). Mirrors
        //     cert.py::check_strong_signature_hash.
        requireStrongSignatureHash(cert)

        // 2c. Signature verifies under the CA pubkey.
        try {
            cert.verify(caRoot.publicKey)
        } catch (e: GeneralSecurityException) {
            throw ServerAttestException("server cert signature does not verify under the pinned CA", e)
        }

        // 3. Validity window.
        try {
            cert.checkValidity(Date.from(clock()))
        } catch (e: CertificateExpiredException) {
            throw ServerAttestException("server cert is expired", e)
        } catch (e: CertificateNotYetValidException) {
            throw ServerAttestException("server cert is not yet valid", e)
        }

        // 4. Required serverAuth EKU. The client authenticates the SERVER, so the
        //    server cert must assert id-kp-serverAuth. validate_chain makes EKU
        //    caller-configurable; the DSM client deploy passes serverAuth, which
        //    this verifier enforces unconditionally (stricter, fail-closed).
        val ekus = try {
            cert.extendedKeyUsage
        } catch (e: CertificateParsingException) {
            throw ServerAttestException("server cert extendedKeyUsage is malformed", e)
        } ?: throw ServerAttestException("server cert missing extendedKeyUsage extension")
        if (EKU_SERVER_AUTH !in ekus) {
            throw ServerAttestException("server cert EKU does not include serverAuth ($EKU_SERVER_AUTH)")
        }

        // 4b. keyUsage must assert digitalSignature (the leaf signs the binding).
        val ku = cert.keyUsage
            ?: throw ServerAttestException("server cert missing keyUsage extension")
        if (ku.isEmpty() || !ku[KU_DIGITAL_SIGNATURE]) {
            throw ServerAttestException("server cert keyUsage must assert digitalSignature")
        }

        // 6. basicConstraints must be present, critical, and CA:FALSE. A leaf is
        //    end-entity only; getBasicConstraints() == -1 means "not a CA", and
        //    membership in criticalExtensionOIDs proves present + critical.
        val criticalOids = cert.criticalExtensionOIDs ?: emptySet()
        if (OID_BASIC_CONSTRAINTS !in criticalOids) {
            throw ServerAttestException("server cert basicConstraints must be present and critical")
        }
        if (cert.basicConstraints != -1) {
            throw ServerAttestException("server cert basicConstraints is CA:TRUE; end-entity only")
        }
    }

    private fun requireStrongSignatureHash(cert: X509Certificate) {
        val alg = cert.sigAlgName.uppercase(Locale.ROOT)
        if (STRONG_SIG_HASH_PREFIXES.none { alg.startsWith(it) }) {
            throw ServerAttestException("server cert signed with a weak hash: ${cert.sigAlgName}")
        }
    }

    /**
     * Extract the single subject CN by walking the DER `Name` directly (the
     * `javax.naming` LDAP DN parser is not on the Android platform). This reads
     * the CN `AttributeValue` straight from the ASN.1 — the same structured read
     * `cryptography` does in `cert.py::subject_cn` — so it is immune to RFC 2253
     * string-escaping ambiguity. Mirrors the "exactly one CN" requirement.
     */
    private fun subjectCn(cert: X509Certificate): String {
        val nameDer = cert.subjectX500Principal.encoded
        val name = readTlv(nameDer, 0)
            ?: throw ServerAttestException("server cert subject DN malformed")
        if (name.tag != DER_SEQUENCE) {
            throw ServerAttestException("server cert subject is not a Name SEQUENCE")
        }
        val cns = mutableListOf<String>()
        var rdnOff = name.contentStart
        val nameEnd = name.contentStart + name.contentLen
        while (rdnOff < nameEnd) {
            val rdn = readTlv(nameDer, rdnOff)
                ?: throw ServerAttestException("server cert subject RDN malformed")
            if (rdn.tag != DER_SET) {
                throw ServerAttestException("server cert subject RDN is not a SET")
            }
            var atvOff = rdn.contentStart
            val rdnEnd = rdn.contentStart + rdn.contentLen
            while (atvOff < rdnEnd) {
                val atv = readTlv(nameDer, atvOff)
                    ?: throw ServerAttestException("server cert subject attribute malformed")
                if (atv.tag != DER_SEQUENCE) {
                    throw ServerAttestException("server cert subject attribute is not a SEQUENCE")
                }
                val oid = readTlv(nameDer, atv.contentStart)
                    ?: throw ServerAttestException("server cert subject attribute type malformed")
                if (oid.tag != DER_OID) {
                    throw ServerAttestException("server cert subject attribute type is not an OID")
                }
                val value = readTlv(nameDer, oid.contentStart + oid.contentLen)
                    ?: throw ServerAttestException("server cert subject attribute value malformed")
                if (oidContentEquals(nameDer, oid, CN_OID_CONTENT)) {
                    cns += decodeDirectoryString(nameDer, value)
                }
                atvOff = atv.contentStart + atv.contentLen
            }
            rdnOff = rdn.contentStart + rdn.contentLen
        }
        if (cns.size != 1) {
            throw ServerAttestException("server cert subject must have exactly one CN, got ${cns.size}")
        }
        return cns.single()
    }

    private fun decodeDirectoryString(buf: ByteArray, value: Tlv): String {
        val bytes = buf.copyOfRange(value.contentStart, value.contentStart + value.contentLen)
        return when (value.tag) {
            DER_UTF8_STRING -> String(bytes, Charsets.UTF_8)
            DER_PRINTABLE_STRING, DER_IA5_STRING -> String(bytes, Charsets.US_ASCII)
            DER_TELETEX_STRING -> String(bytes, Charsets.ISO_8859_1)
            DER_BMP_STRING -> String(bytes, Charsets.UTF_16BE)
            else -> throw ServerAttestException(
                "server cert CN uses unsupported string type 0x${value.tag.toString(16)}",
            )
        }
    }

    private fun oidContentEquals(buf: ByteArray, oid: Tlv, expected: ByteArray): Boolean {
        if (oid.contentLen != expected.size) {
            return false
        }
        for (i in expected.indices) {
            if (buf[oid.contentStart + i] != expected[i]) {
                return false
            }
        }
        return true
    }

    /** A parsed DER tag-length-value header. Single-byte tags only (sufficient here). */
    private data class Tlv(val tag: Int, val contentStart: Int, val contentLen: Int)

    /** A decoded DER length + the offset of its first content byte. */
    private data class DerLength(val length: Int, val contentStart: Int)

    /**
     * Decode a DER length whose first byte is at [lenStart]. Supports short and
     * long-form lengths; rejects indefinite-length and overlong (> 4-byte)
     * encodings. Returns null on malformed input; does NOT bounds-check the
     * length against the buffer end — each caller applies its own end rule
     * (fits-within vs spans-to-end).
     */
    private fun readDerLength(buf: ByteArray, lenStart: Int): DerLength? {
        if (lenStart >= buf.size) {
            return null
        }
        val first = buf[lenStart].toInt() and 0xFF
        var idx = lenStart + 1
        val length: Int
        if (first < 0x80) {
            length = first
        } else {
            val numBytes = first and 0x7F
            if (numBytes == 0 || numBytes > 4 || idx + numBytes > buf.size) {
                return null
            }
            var len = 0
            for (i in 0 until numBytes) {
                len = (len shl 8) or (buf[idx + i].toInt() and 0xFF)
            }
            idx += numBytes
            length = len
        }
        if (length < 0) {
            return null
        }
        return DerLength(length, idx)
    }

    /**
     * Parse one DER TLV at [off]. Rejects any header/content that runs past the
     * buffer. Returns null on malformed input (caller fails closed).
     */
    private fun readTlv(buf: ByteArray, off: Int): Tlv? {
        if (off < 0 || off >= buf.size) {
            return null
        }
        val tag = buf[off].toInt() and 0xFF
        val len = readDerLength(buf, off + 1) ?: return null
        if (len.contentStart + len.length > buf.size) {
            return null
        }
        return Tlv(tag, len.contentStart, len.length)
    }

    private fun verifyBindingSignature(pub: PublicKey, preImage: ByteArray, sigDer: ByteArray) {
        val ok = try {
            Signature.getInstance("SHA256withECDSA").run {
                initVerify(pub)
                update(preImage)
                verify(sigDer)
            }
        } catch (e: GeneralSecurityException) {
            // A malformed DER signature also lands here (SignatureException).
            throw ServerAttestException("server binding signature failed to verify", e)
        }
        if (!ok) {
            throw ServerAttestException("server binding signature does not verify under the cert pubkey")
        }
    }

    /**
     * Extract the 32-byte X25519 static from the critical `noiseStaticBinding`
     * extension, matching the OID + encoding in `dsm/crypto/cert.py`.
     *
     * `getExtensionValue` returns the extnValue wrapped in an outer DER OCTET
     * STRING; the inner extnValue is itself a DER `OCTET STRING(32)` per the DSM
     * convention (`04 20 || 32 bytes`).
     */
    private fun noiseStaticBinding(cert: X509Certificate): ByteArray {
        val critical = cert.criticalExtensionOIDs ?: emptySet()
        if (OID_NOISE_STATIC_BINDING !in critical) {
            // Absent or non-critical: cert.py requires the extension be critical.
            throw ServerAttestException("noiseStaticBinding extension missing or not critical")
        }
        val raw = cert.getExtensionValue(OID_NOISE_STATIC_BINDING)
            ?: throw ServerAttestException("noiseStaticBinding extension missing")
        val extnValue = derUnwrapOctetString(raw)
            ?: throw ServerAttestException("noiseStaticBinding outer DER wrapper malformed")
        val expectedLen = OCTET_STRING_PREFIX.size + AttestPayloadCodec.NOISE_STATIC_PUB_LEN
        if (extnValue.size != expectedLen ||
            extnValue[0] != OCTET_STRING_PREFIX[0] ||
            extnValue[1] != OCTET_STRING_PREFIX[1]
        ) {
            throw ServerAttestException("noiseStaticBinding extension value malformed")
        }
        return extnValue.copyOfRange(OCTET_STRING_PREFIX.size, expectedLen)
    }

    /**
     * Decode a single DER OCTET STRING that spans the whole input and return its
     * content bytes, or null if the framing is malformed. Supports short and
     * long-form lengths; rejects indefinite length and trailing data.
     */
    private fun derUnwrapOctetString(der: ByteArray): ByteArray? {
        if (der.size < 2 || der[0] != DER_OCTET_STRING_TAG) {
            return null
        }
        val len = readDerLength(der, 1) ?: return null
        // Must span exactly to the end (reject trailing data).
        if (len.contentStart + len.length != der.size) {
            return null
        }
        return der.copyOfRange(len.contentStart, len.contentStart + len.length)
    }

    companion object {
        /** ±300 s, mirroring `DEFAULT_CLOCK_SKEW` in dsm/crypto/attest.py. */
        const val DEFAULT_CLOCK_SKEW_SECONDS: Long = 300

        /** id-kp-serverAuth (RFC 5280). The client authenticates the server. */
        const val EKU_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"

        /** basicConstraints extension OID (2.5.29.19). */
        const val OID_BASIC_CONSTRAINTS = "2.5.29.19"

        /** DSM noiseStaticBinding OID, matching `DSM_NOISE_STATIC_BINDING_OID`. */
        const val OID_NOISE_STATIC_BINDING = "1.3.6.1.4.1.99999.1.1"

        /** keyUsage bit index for digitalSignature (bit 0). */
        private const val KU_DIGITAL_SIGNATURE = 0

        // DER universal tags used by the subject-Name walker.
        private const val DER_SEQUENCE = 0x30
        private const val DER_SET = 0x31
        private const val DER_OID = 0x06
        private const val DER_UTF8_STRING = 0x0C
        private const val DER_PRINTABLE_STRING = 0x13
        private const val DER_TELETEX_STRING = 0x14
        private const val DER_IA5_STRING = 0x16
        private const val DER_BMP_STRING = 0x1E

        /** DER OID *content* bytes for id-at-commonName (2.5.4.3). */
        private val CN_OID_CONTENT = byteArrayOf(0x55, 0x04, 0x03)

        private const val DER_OCTET_STRING_TAG: Byte = 0x04

        /** DER `OCTET STRING(32)` prefix (`04 20`), matching cert.py's convention. */
        private val OCTET_STRING_PREFIX: ByteArray =
            byteArrayOf(DER_OCTET_STRING_TAG, AttestPayloadCodec.NOISE_STATIC_PUB_LEN.toByte())

        /** SHA-2 family only; SHA-1 / MD5 rejected (cert.py _STRONG_HASH_NAMES). */
        private val STRONG_SIG_HASH_PREFIXES = listOf("SHA256", "SHA384", "SHA512")
    }
}
