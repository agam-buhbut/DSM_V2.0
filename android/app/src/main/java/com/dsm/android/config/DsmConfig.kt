package com.dsm.android.config

/**
 * A passphrase value that never reveals itself through [toString] / logging.
 *
 * The plaintext is only materialized as bytes at the point it is needed (the
 * identity-store decrypt) via [bytes]; callers should zero the returned array
 * after use. The wrapping [String] is immutable on the JVM and cannot be
 * scrubbed — a known limitation acceptable for the dev/B4-bring-up literal
 * source; a production build should source the passphrase from a user prompt
 * or a Keystore-wrapped secret instead of the config file.
 */
class Passphrase(private val value: String) {
    /** UTF-8 bytes of the passphrase. Caller should zero the array after use. */
    fun bytes(): ByteArray = value.toByteArray(Charsets.UTF_8)

    /** Redacted — never echoes the secret (guards against config logging). */
    override fun toString(): String = "Passphrase(***)"
}

/**
 * Minimal client configuration, parsed from the TOML-subset the DSM client
 * needs (see `config.example.toml`). This intentionally parses only the small
 * key set a mobile client consumes — it is NOT a general TOML implementation.
 *
 * Supported line forms (outside any `[section]` header, which is ignored):
 * ```
 * key = "string"
 * key = 123
 * key = true
 * # comment
 * ```
 *
 * The mobile-provisioning keys this adds over the daemon config:
 * ```
 * keystore_alias      = "dsm_b1_real"   # the B1-attested Keystore signing key
 * identity_passphrase = "..."           # opens dsm/identity.blob (dev source)
 * ```
 */
data class DsmConfig(
    val serverIp: String,
    val serverPort: Int,
    val expectedServerCn: String,
    val transport: Transport,
    val tunAddress: String,
    val dns: String,
    val mtu: Int,
    val rotationPackets: Long?,
    val rotationSeconds: Long?,
    /** Android Keystore alias of the B1-attested signing key (`dsm_b1_real`). */
    val keystoreAlias: String,
    /** Passphrase that unseals the persisted Noise identity (`identity.blob`). */
    val identityPassphrase: Passphrase,
) {
    enum class Transport {
        UDP,
        ;

        companion object {
            fun parse(raw: String): Transport =
                when (raw.lowercase()) {
                    "udp" -> UDP
                    else -> throw ConfigException("transport must be \"udp\", got \"$raw\"")
                }
        }
    }

    /** Configuration parse / validation failure. */
    class ConfigException(message: String) : Exception(message)

    companion object {
        // The in-tunnel addressing contract (see dsm/net/_addresses.py and
        // dsm/net/tunnel.py): server is 10.8.0.1, this client takes 10.8.0.2,
        // and the in-tunnel DNS resolver lives on the server TUN IP.
        const val DEFAULT_TUN_ADDRESS = "10.8.0.2"
        const val DEFAULT_DNS = "10.8.0.1"

        // Inner MTU. B3's inner-packet fragmentation is deferred, so the inner
        // MTU is held at 1360 so a full inner DATA packet (plus the outer UDP +
        // AEAD overhead) never exceeds a typical 1500-byte path and neither side
        // fragments. Raise only once fragmentation lands.
        const val DEFAULT_MTU = 1360
        const val TUN_PREFIX_LEN = 24

        // The B1 enroll attests this Keystore alias to the Noise static; the
        // on-device run reuses that already-attested key (it is NOT regenerated).
        const val DEFAULT_KEYSTORE_ALIAS = "dsm_b1_real"

        /**
         * Parse a config from a TOML-subset string.
         *
         * @throws ConfigException on a malformed line, a bad value, or a
         *   missing required key.
         */
        fun parse(text: String): DsmConfig {
            val kv = mutableMapOf<String, String>()
            for ((lineNo, rawLine) in text.lineSequence().withIndex()) {
                val line = stripComment(rawLine).trim()
                if (line.isEmpty()) continue
                if (line.startsWith("[") && line.endsWith("]")) continue // section header
                val eq = line.indexOf('=')
                if (eq <= 0) {
                    throw ConfigException("malformed config at line ${lineNo + 1}: \"$rawLine\"")
                }
                val key = line.substring(0, eq).trim()
                val value = unquote(line.substring(eq + 1).trim())
                kv[key] = value
            }

            val serverIp = required(kv, "server_ip")
            val serverPort = required(kv, "server_port").toIntOrNull()
                ?: throw ConfigException("server_port must be an integer")
            val expectedServerCn = required(kv, "expected_server_cn")
            val transport = Transport.parse(kv["transport"] ?: "udp")
            val mtu = (kv["mtu"]?.toIntOrNull()) ?: DEFAULT_MTU
            if (mtu < 576) throw ConfigException("mtu too small: $mtu")
            val rotationPackets = kv["rotation_packets"]?.toLongOrNull()
            val rotationSeconds = kv["rotation_seconds"]?.toLongOrNull()

            return DsmConfig(
                serverIp = serverIp,
                serverPort = serverPort,
                expectedServerCn = expectedServerCn,
                transport = transport,
                tunAddress = kv["tun_address"] ?: DEFAULT_TUN_ADDRESS,
                dns = kv["dns"] ?: DEFAULT_DNS,
                mtu = mtu,
                rotationPackets = rotationPackets,
                rotationSeconds = rotationSeconds,
                keystoreAlias = kv["keystore_alias"] ?: DEFAULT_KEYSTORE_ALIAS,
                // AND-2: no hardcoded fallback — a missing identity_passphrase
                // fails closed. A KDF over a public constant is no protection.
                identityPassphrase = Passphrase(required(kv, "identity_passphrase")),
            )
        }

        private fun required(kv: Map<String, String>, key: String): String =
            kv[key] ?: throw ConfigException("missing required config key: $key")

        private fun stripComment(line: String): String {
            // A '#' inside a quoted string is not a comment.
            var inString = false
            for (i in line.indices) {
                val c = line[i]
                if (c == '"') inString = !inString
                if (c == '#' && !inString) return line.substring(0, i)
            }
            return line
        }

        private fun unquote(value: String): String {
            if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
                return value.substring(1, value.length - 1)
            }
            return value
        }
    }
}
