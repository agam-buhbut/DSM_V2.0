package com.dsm.android.core

import com.dsm.android.attest.KeyHandle
import com.dsm.android.attest.KeystoreAttestSigner
import java.security.cert.X509Certificate
import uniffi.tuncore.AttestSigner

/**
 * The FFI-free inputs the [HandshakeDriver] needs that are derived purely from
 * the provisioning bundle + the device's signing key: the CA-pinned server
 * verifier, the client attest signer, the device cert DER, and the pinned
 * server CN.
 *
 * Pulling this out of [com.dsm.android.DsmVpnService] (which can only run with
 * the native core + Android Keystore) is what lets a host JVM test assert the
 * connect path selects the right verifier / signer.
 */
class HandshakeInputs(
    val serverVerifier: ServerAttestVerifier,
    val signer: AttestSigner,
    val deviceCertDer: ByteArray,
    val expectedServerCn: String,
)

/**
 * Assemble the FFI-free handshake inputs from the provisioned artifacts.
 *
 * The server is authenticated by a [RealServerAttestVerifier] pinned to
 * [caRoot] + [expectedServerCn]; the client attests with a [KeystoreAttestSigner]
 * over [keyHandle] (the B1-attested Keystore key on-device, a fake in tests).
 * No key material is constructed or logged here.
 */
fun buildHandshakeInputs(
    caRoot: X509Certificate,
    deviceCertDer: ByteArray,
    expectedServerCn: String,
    codec: AttestPayloadCodec,
    keyHandle: KeyHandle,
): HandshakeInputs =
    HandshakeInputs(
        serverVerifier = RealServerAttestVerifier(
            caRoot = caRoot,
            expectedServerCn = expectedServerCn,
            codec = codec,
        ),
        signer = KeystoreAttestSigner(keyHandle),
        deviceCertDer = deviceCertDer,
        expectedServerCn = expectedServerCn,
    )
