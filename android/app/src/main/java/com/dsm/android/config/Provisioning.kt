package com.dsm.android.config

import java.io.ByteArrayInputStream
import java.io.File
import java.io.IOException
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import uniffi.tuncore.IdentityKeyPair

/**
 * On-device provisioning layout the B1 enroll writes into the app's private
 * `filesDir`, and the loader that fail-closed reads it back for a connect.
 *
 * Layout (all under `filesDir/dsm/`):
 * ```
 * dsm/config.toml        client config (DsmConfig.parse); see DsmConfig
 * dsm/identity.blob       IdentityKeyPair.encryptToStore() blob (Noise static)
 * dsm/device_cert.der     CA-issued DSM device cert, DER (noiseStaticBinding ext)
 * dsm/ca_root.pem|.der    pinned CA root the server cert must chain to
 * ```
 *
 * Every artifact is mandatory: an un-provisioned device fails closed with an
 * actionable [ProvisioningException] rather than a crash or a silent skip of
 * server authentication.
 */
object ProvisioningLayout {
    const val DIR = "dsm"
    const val CONFIG = "config.toml"
    const val IDENTITY_BLOB = "identity.blob"
    const val DEVICE_CERT_DER = "device_cert.der"
    const val CA_ROOT_PEM = "ca_root.pem"
    const val CA_ROOT_DER = "ca_root.der"

    /** The provisioning directory under an app `filesDir`. */
    fun dir(filesDir: File): File = File(filesDir, DIR)
}

/** A provisioning load / validation failure. Always actionable; fails closed. */
class ProvisioningException(message: String, cause: Throwable? = null) :
    Exception(message, cause)

/**
 * Seam for decrypting the persisted identity. The default delegates to the
 * UniFFI native core ([IdentityKeyPair.decryptFromStore]), which is only
 * loadable on-device; JVM unit tests inject a fake so the loader's file +
 * fail-closed logic is exercised without the `.so`.
 */
fun interface IdentityDecryptor {
    /** @throws Exception on a wrong passphrase or a corrupt blob. */
    fun decrypt(blob: ByteArray, passphrase: ByteArray): IdentityKeyPair

    companion object {
        /** Production decryptor over the native core (on-device only). */
        val DEFAULT = IdentityDecryptor { blob, passphrase ->
            IdentityKeyPair.decryptFromStore(blob, passphrase)
        }
    }
}

/**
 * A loaded, validated provisioning bundle. The network/non-secret config, the
 * pinned CA root, and the device cert DER are fully materialized; the Noise
 * identity is opened lazily via [openIdentity] (it touches the native core, so
 * it is kept off the FFI-free load path).
 */
class Provisioning(
    val config: DsmConfig,
    val caRoot: X509Certificate,
    val deviceCertDer: ByteArray,
    private val identityBlob: ByteArray,
) {
    // TODO(owner): AND-2 — wrap identity.blob at rest with a non-extractable
    // AndroidKeyStore AES-256-GCM key (needs a coordinated on-device enroll
    // WRITE path that does not exist yet; today the blob is passphrase-only).
    /**
     * Unseal the persisted Noise identity with the config passphrase. The
     * passphrase bytes are zeroed after the attempt; the identity secret stays
     * inside the native core.
     *
     * @throws ProvisioningException if decryption fails (wrong passphrase /
     *   corrupt blob).
     */
    fun openIdentity(decryptor: IdentityDecryptor = IdentityDecryptor.DEFAULT): IdentityKeyPair {
        val passphrase = config.identityPassphrase.bytes()
        try {
            return decryptor.decrypt(identityBlob, passphrase)
        } catch (e: Exception) {
            // Catch-broad: the native decrypt surfaces a typed FfiException, but
            // any failure here must become an actionable provisioning error and
            // must NOT echo the passphrase or blob contents.
            throw ProvisioningException("failed to unseal persisted identity (bad passphrase or corrupt identity.blob)", e)
        } finally {
            passphrase.fill(0)
        }
    }
}

/**
 * Loads the [Provisioning] bundle from the on-device [dir]. Every read fails
 * closed: a missing or unreadable artifact, a malformed config, or an
 * unparseable CA root throws [ProvisioningException] with a message naming the
 * artifact, so an un-provisioned device gives an actionable status.
 */
class ProvisioningLoader(private val dir: File) {

    /** True only when every required artifact is present (cheap existence check). */
    fun isProvisioned(): Boolean =
        file(ProvisioningLayout.CONFIG).isFile &&
            file(ProvisioningLayout.IDENTITY_BLOB).isFile &&
            file(ProvisioningLayout.DEVICE_CERT_DER).isFile &&
            caRootFile() != null

    /** @throws ProvisioningException if any artifact is missing or invalid. */
    fun load(): Provisioning {
        val config = loadConfig()
        val identityBlob = readRequired(ProvisioningLayout.IDENTITY_BLOB, "identity store blob")
        val deviceCertDer = readRequired(ProvisioningLayout.DEVICE_CERT_DER, "device certificate")
        if (deviceCertDer.isEmpty()) {
            throw ProvisioningException("device certificate (device_cert.der) is empty")
        }
        val caRoot = loadCaRoot()
        return Provisioning(config, caRoot, deviceCertDer, identityBlob)
    }

    private fun loadConfig(): DsmConfig {
        val text = readRequiredText(ProvisioningLayout.CONFIG, "client config")
        return try {
            DsmConfig.parse(text)
        } catch (e: DsmConfig.ConfigException) {
            throw ProvisioningException("invalid client config (config.toml): ${e.message}", e)
        }
    }

    private fun loadCaRoot(): X509Certificate {
        val caFile = caRootFile()
            ?: throw ProvisioningException(
                "pinned CA root not provisioned (expected dsm/${ProvisioningLayout.CA_ROOT_PEM} " +
                    "or dsm/${ProvisioningLayout.CA_ROOT_DER}); refusing to connect",
            )
        val bytes = readBytes(caFile, "pinned CA root")
        return try {
            // CertificateFactory accepts both PEM and DER for X.509.
            val cf = CertificateFactory.getInstance("X.509")
            cf.generateCertificate(ByteArrayInputStream(bytes)) as X509Certificate
        } catch (e: CertificateException) {
            throw ProvisioningException("pinned CA root is not a valid X.509 certificate: ${e.message}", e)
        } catch (e: ClassCastException) {
            throw ProvisioningException("pinned CA root is not an X.509 certificate", e)
        }
    }

    private fun caRootFile(): File? {
        val pem = file(ProvisioningLayout.CA_ROOT_PEM)
        if (pem.isFile) return pem
        val der = file(ProvisioningLayout.CA_ROOT_DER)
        if (der.isFile) return der
        return null
    }

    private fun readRequired(name: String, label: String): ByteArray =
        readBytes(requireFile(name, label), label)

    private fun readRequiredText(name: String, label: String): String =
        readBytes(requireFile(name, label), label).toString(Charsets.UTF_8)

    private fun requireFile(name: String, label: String): File {
        val f = file(name)
        if (!f.isFile) {
            throw ProvisioningException(
                "missing provisioning artifact: $label (expected dsm/$name); device not enrolled",
            )
        }
        return f
    }

    private fun readBytes(f: File, label: String): ByteArray =
        try {
            f.readBytes()
        } catch (e: IOException) {
            throw ProvisioningException("failed to read $label (dsm/${f.name}): ${e.message}", e)
        }

    private fun file(name: String): File = File(dir, name)
}
