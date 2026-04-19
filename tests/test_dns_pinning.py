"""Tests for SSL context hardening (TLS 1.3 only, pin verification helpers)."""

import ssl
import unittest

from dsm.net.dns_pinning import build_pinned_ssl_context


class TestTls13Only(unittest.TestCase):
    def test_minimum_and_maximum_are_tls13(self) -> None:
        ctx = build_pinned_ssl_context()
        self.assertEqual(ctx.minimum_version, ssl.TLSVersion.TLSv1_3)
        self.assertEqual(ctx.maximum_version, ssl.TLSVersion.TLSv1_3)

    def test_hostname_and_cert_verification_on(self) -> None:
        ctx = build_pinned_ssl_context()
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ssl.CERT_REQUIRED)


if __name__ == "__main__":
    unittest.main()
