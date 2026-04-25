"""Tests for dsm.net.dns_proxy — qname redaction and debug_dns gating."""

import hashlib
import unittest

import dns.message
import dns.rdatatype

from dsm.net.dns_proxy import LocalDNSProxy, _redact_qname


class _StubResolver:
    """Resolver stub that always raises, to exercise the failure-log path."""

    def __init__(self) -> None:
        self.closed = False

    async def resolve(self, hostname: str) -> list[str]:
        raise RuntimeError("stub-upstream-fail")

    async def close(self) -> None:
        self.closed = True


class TestQnameRedaction(unittest.TestCase):
    def test_redaction_is_stable_and_short(self) -> None:
        redacted = _redact_qname("example.com")
        self.assertEqual(len(redacted), 16)
        expected = hashlib.sha256(b"example.com").hexdigest()[:16]
        self.assertEqual(redacted, expected)

    def test_different_qnames_produce_different_hashes(self) -> None:
        self.assertNotEqual(_redact_qname("a.com"), _redact_qname("b.com"))


def _build_query_wire(qname: str) -> bytes:
    return dns.message.make_query(qname, dns.rdatatype.A).to_wire()


class TestDebugDnsFlag(unittest.IsolatedAsyncioTestCase):
    async def _run_with_flag(self, debug_dns: bool) -> str:
        stub = _StubResolver()
        proxy = LocalDNSProxy(stub, bind_ip="127.0.0.1", debug_dns=debug_dns)  # type: ignore[arg-type]
        sent: list[bytes] = []

        def _send(wire: bytes, to: tuple[str, int]) -> None:
            sent.append(wire)

        with self.assertLogs("dsm.net.dns_proxy", level="WARNING") as captured:
            await proxy._handle_query(
                _build_query_wire("secret-site.example"),
                ("127.0.0.1", 12345),
                _send,
            )
        self.assertTrue(sent, "expected a SERVFAIL response to be sent")
        return "\n".join(captured.output)

    async def test_default_redacts_qname(self) -> None:
        log_text = await self._run_with_flag(debug_dns=False)
        self.assertNotIn("secret-site.example", log_text)
        self.assertIn(_redact_qname("secret-site.example"), log_text)

    async def test_debug_flag_emits_plaintext_qname(self) -> None:
        log_text = await self._run_with_flag(debug_dns=True)
        self.assertIn("secret-site.example", log_text)


if __name__ == "__main__":
    unittest.main()
