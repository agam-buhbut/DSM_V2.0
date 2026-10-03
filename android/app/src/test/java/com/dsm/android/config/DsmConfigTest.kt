package com.dsm.android.config

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class DsmConfigTest {

    private val minimalBody =
        """
        server_ip = "10.0.0.1"
        server_port = 1194
        expected_server_cn = "srv"
        identity_passphrase = "test-pass"
        """.trimIndent()

    private val valid =
        """
        # DSM client config
        mode = "client"
        server_ip = "203.0.113.7"
        server_port = 51820
        transport = "udp"   # inline comment
        expected_server_cn = "dsm-abcd-server"
        mtu = 1380
        rotation_packets = 5000
        rotation_seconds = 600
        identity_passphrase = "test-pass"
        [traffic]
        padding_min = 128
        """.trimIndent()

    @Test
    fun parsesValidConfig() {
        val cfg = DsmConfig.parse(valid)
        assertEquals("203.0.113.7", cfg.serverIp)
        assertEquals(51820, cfg.serverPort)
        assertEquals(DsmConfig.Transport.UDP, cfg.transport)
        assertEquals("dsm-abcd-server", cfg.expectedServerCn)
        assertEquals(1380, cfg.mtu)
        assertEquals(5000L, cfg.rotationPackets)
        assertEquals(600L, cfg.rotationSeconds)
        // Defaults for unspecified in-tunnel addressing.
        assertEquals(DsmConfig.DEFAULT_TUN_ADDRESS, cfg.tunAddress)
        assertEquals(DsmConfig.DEFAULT_DNS, cfg.dns)
    }

    @Test
    fun appliesDefaultsForOptionalKeys() {
        val minimal =
            """
            server_ip = "10.0.0.1"
            server_port = 1194
            expected_server_cn = "srv"
            identity_passphrase = "test-pass"
            """.trimIndent()
        val cfg = DsmConfig.parse(minimal)
        assertEquals(DsmConfig.Transport.UDP, cfg.transport)
        assertEquals(DsmConfig.DEFAULT_MTU, cfg.mtu)
        assertNull(cfg.rotationPackets)
        assertNull(cfg.rotationSeconds)
    }

    @Test
    fun missingRequiredKeyThrows() {
        val missing =
            """
            server_ip = "10.0.0.1"
            expected_server_cn = "srv"
            """.trimIndent()
        val e = assertThrows(DsmConfig.ConfigException::class.java) { DsmConfig.parse(missing) }
        assertEquals("missing required config key: server_port", e.message)
    }

    @Test
    fun badTransportThrows() {
        val bad =
            """
            server_ip = "10.0.0.1"
            server_port = 1194
            transport = "carrier-pigeon"
            expected_server_cn = "srv"
            """.trimIndent()
        assertThrows(DsmConfig.ConfigException::class.java) { DsmConfig.parse(bad) }
    }

    @Test
    fun malformedLineThrows() {
        val bad =
            """
            server_ip = "10.0.0.1"
            this line has no equals
            """.trimIndent()
        assertThrows(DsmConfig.ConfigException::class.java) { DsmConfig.parse(bad) }
    }

    @Test
    fun hashInsideQuotedStringIsNotAComment() {
        val cfg = DsmConfig.parse(
            """
            server_ip = "1.2.3.4"
            server_port = 9
            expected_server_cn = "cn#1-not-a-comment"
            identity_passphrase = "test-pass"
            """.trimIndent(),
        )
        assertEquals("cn#1-not-a-comment", cfg.expectedServerCn)
    }

    @Test
    fun mtuDefaultsTo1360() {
        // B3 inner fragmentation deferred — inner MTU held at 1360.
        assertEquals(1360, DsmConfig.DEFAULT_MTU)
        assertEquals(1360, DsmConfig.parse(minimalBody).mtu)
    }

    @Test
    fun keystoreAliasDefaultsToB1AndOverrides() {
        assertEquals("dsm_b1_real", DsmConfig.parse(minimalBody).keystoreAlias)
        val over = DsmConfig.parse("$minimalBody\nkeystore_alias = \"other_alias\"")
        assertEquals("other_alias", over.keystoreAlias)
    }

    @Test
    fun identityPassphraseIsRequiredAndOverrides() {
        // AND-2: no hardcoded default — a config without identity_passphrase
        // must fail closed rather than fall back to a public constant.
        val without =
            """
            server_ip = "10.0.0.1"
            server_port = 1194
            expected_server_cn = "srv"
            """.trimIndent()
        val e = assertThrows(DsmConfig.ConfigException::class.java) { DsmConfig.parse(without) }
        assertEquals("missing required config key: identity_passphrase", e.message)
        val over = DsmConfig.parse("$without\nidentity_passphrase = \"hunter2\"")
        assertArrayEquals("hunter2".toByteArray(), over.identityPassphrase.bytes())
    }

    @Test
    fun passphraseIsNotLeakedByToString() {
        val cfg = DsmConfig.parse("$minimalBody\nidentity_passphrase = \"s3cret-pass\"")
        // Neither the wrapper nor the (data class) config may echo the secret.
        assertFalse(cfg.identityPassphrase.toString().contains("s3cret-pass"))
        assertFalse(cfg.toString().contains("s3cret-pass"))
    }
}
