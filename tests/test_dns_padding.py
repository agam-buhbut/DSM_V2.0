"""Tests for EDNS(0) padding on upstream DNS queries (RFC 7830 / RFC 8467)."""

import unittest

import dns.edns
import dns.message

from dsm.net.dns import EDNS_PADDING_BLOCK, _build_dns_query, A_RECORD


class TestEdnsPadding(unittest.TestCase):
    def test_query_is_block_aligned(self) -> None:
        for hostname in (
            "a.com",
            "x",
            "cloudflare-dns.com",
            "a-very-long-subdomain.example.org",
            "deeply.nested.multi.label.domain.example",
        ):
            wire = _build_dns_query(hostname, A_RECORD)
            self.assertEqual(
                len(wire) % EDNS_PADDING_BLOCK, 0,
                f"query for {hostname!r} is not {EDNS_PADDING_BLOCK}-byte aligned: "
                f"len={len(wire)}",
            )

    def test_query_carries_padding_option(self) -> None:
        wire = _build_dns_query("example.com", A_RECORD)
        msg = dns.message.from_wire(wire)
        otypes = [opt.otype for opt in msg.options]
        self.assertIn(dns.edns.PADDING, otypes)

    def test_padded_length_meets_or_exceeds_unpadded(self) -> None:
        wire = _build_dns_query("example.com", A_RECORD)
        self.assertGreaterEqual(len(wire), EDNS_PADDING_BLOCK)

    def test_long_qname_still_aligns(self) -> None:
        label = "a" * 60
        hostname = ".".join([label] * 4)
        wire = _build_dns_query(hostname, A_RECORD)
        self.assertEqual(len(wire) % EDNS_PADDING_BLOCK, 0)


if __name__ == "__main__":
    unittest.main()
