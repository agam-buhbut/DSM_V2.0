package com.dsm.android

import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-1 regression guard: the TUN must capture ALL traffic — IPv4 AND IPv6 — so
 * no v6 flow (or AAAA DNS) can escape the tunnel in cleartext on a dual-stack
 * link.
 *
 * [DsmVpnService.buildTun] installs exactly [TUN_ROUTES], so asserting on that
 * list checks the capture policy without a real `VpnService.Builder` (a system
 * class that returns stubs under JVM unit tests). [TUN_ROUTES] is top-level, so
 * this test loads no Android-derived class. A future edit that drops the IPv6
 * default route fails here.
 */
class DsmVpnServiceTunRoutesTest {

    @Test
    fun tunRoutesCaptureAllIpv6() {
        assertTrue(
            "TUN must install an IPv6 default route (::/0) — AND-1 leak guard",
            TUN_ROUTES.any { it.address == "::" && it.prefixLength == 0 },
        )
    }

    @Test
    fun tunRoutesStillCaptureAllIpv4() {
        assertTrue(
            "TUN must install an IPv4 default route (0.0.0.0/0)",
            TUN_ROUTES.any { it.address == "0.0.0.0" && it.prefixLength == 0 },
        )
    }
}
