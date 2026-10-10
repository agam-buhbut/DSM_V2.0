"""Regression: DNSProxyPortInUseError from LocalDNSProxy.start() must be
FATAL — log at ERROR, return 1, do NOT retry the accept loop.

Prior behavior: the broad ``except Exception`` in the run_server accept loop
caught it, logged at WARNING (buried), then looped back to accept the next
client and immediately hit the same bind error again — infinite retry on a
persistent operator config error (e.g. unbound already holding :53).

Fixed behavior: explicit ``except DNSProxyPortInUseError`` catches it BEFORE
the broad handler, logs at ERROR with the actionable message, and returns 1
(fatal exit).

Mocking strategy mirrors test_lifecycle.py::ServerReAccept._patches: all
host-state I/O is mocked at the boundary (no root, no network, no real TUN /
nftables / DNS). Only the LocalDNSProxy.start behaviour is varied here.
"""

from __future__ import annotations

import logging
import unittest
from collections.abc import Generator
from contextlib import contextmanager
from unittest.mock import patch

from dsm.core.config import Config
from dsm.net.dns_proxy import DNSProxyPortInUseError
from dsm.net.handshake_gate import GateKeys


def _server_config() -> Config:
    return Config(
        mode="server",
        server_ip="0.0.0.0",
        server_port=51820,
        listen_port=51820,
        key_file="/tmp/dsm-test.key",
        cert_file="/tmp/dsm-test.crt",
        ca_root_file="/tmp/dsm-test-ca.pem",
        attest_key_file="/tmp/dsm-test-attest.key",
        allowed_cns_file="/tmp/dsm-test-allowed-cns.txt",
        transport="udp",
        dns_providers=["https://10.0.0.53/dns-query"],
        dns_provider_pins={"https://10.0.0.53/dns-query": ["a" * 64]},
    )


class _NonEmptyAllowlist:
    """Duck-typed CNAllowlist: non-empty so run_server does not abort."""

    def __len__(self) -> int:
        return 1


class _FakeMaterials:
    cert_der = b""
    ca_root = object()
    crl = None


class _FakeStore:
    def __init__(self, *_a: object, **_k: object) -> None:
        self.identity = type("_Id", (), {"public_key": b"\x00" * 32})()
        self.attest_key = object()

    def unload(self) -> None:
        pass


class _SyncManager:
    def __init__(self, *_a: object, **_k: object) -> None:
        pass

    def apply(self) -> None:
        pass

    def remove(self) -> None:
        pass


class _FakeTun:
    def __init__(self, *_a: object, **_k: object) -> None:
        pass

    def open(self) -> None:
        pass

    def configure(self, *_a: object, **_k: object) -> None:
        pass

    def close(self) -> None:
        pass


class _FakeResolver:
    def __init__(self, *_a: object, **_k: object) -> None:
        pass

    async def close(self) -> None:
        pass


class _FakeScheduler:
    def __init__(self, *_a: object, **_k: object) -> None:
        pass

    async def start(self) -> None:
        pass

    async def stop(self) -> None:
        pass


class _FakeUDPTransport:
    async def bind(self, *_a: object, **_k: object) -> None:
        pass

    async def aclose(self) -> None:
        pass


async def _noop_send(*_a: object, **_k: object) -> None:
    pass


@contextmanager
def _base_patches(
    accept_side_effect: object,
    captured_shutdown: dict,
) -> Generator[None, None, None]:
    """Context manager applying all shared host-I/O mocks.

    ``captured_shutdown`` receives the ``process_shutdown`` event injected
    by ``setup_signal_handlers`` so individual tests can trigger shutdown.
    ``accept_side_effect`` stands in for ``dsm.server._accept_until_winner``:
    its demux needs real datagrams, which this host-mocked harness never
    supplies.
    """

    def _capture_signal_handlers(shutdown: object) -> None:
        captured_shutdown["event"] = shutdown

    patches = [
        patch("tuncore.harden_process"),
        patch("dsm.core.hardening.set_process_nondumpable"),
        patch("dsm.crypto.attest_gate.enforce_attest_backend_policy"),
        patch("dsm.server.load_cert_materials", return_value=_FakeMaterials()),
        patch(
            "dsm.server.server_gate_keys",
            return_value=GateKeys(mac1_key=bytes(32), cookie_key=bytes(32)),
        ),
        patch("dsm.server.verify_cert_matches_identity"),
        patch("dsm.server.CNAllowlist.from_file", return_value=_NonEmptyAllowlist()),
        patch("dsm.crypto._stores.load_daemon_stores", return_value=True),
        patch("dsm.server.KeyStore", _FakeStore),
        patch("dsm.server.AttestStore", _FakeStore),
        patch("dsm.server.ServerRateLimitManager", _SyncManager),
        patch("dsm.server.TcpTimestampsDisabler", _SyncManager),
        patch("dsm.server.IPForwardingManager", _SyncManager),
        patch("dsm.server.MasqueradeManager", _SyncManager),
        patch("dsm.server.TunDevice", _FakeTun),
        patch("dsm.server.DNSResolver", _FakeResolver),
        patch("dsm.server.SendScheduler", _FakeScheduler),
        patch("dsm.server.make_send_fn", return_value=_noop_send),
        patch("dsm.server.UDPTransport", _FakeUDPTransport),
        patch("dsm.server.setup_signal_handlers", _capture_signal_handlers),
        patch(
            "dsm.server._accept_until_winner",
            side_effect=accept_side_effect,
        ),
    ]
    for p in patches:
        p.start()
    try:
        yield
    finally:
        for p in reversed(patches):
            p.stop()


class TestDNSPortConflictFatal(unittest.IsolatedAsyncioTestCase):
    """When LocalDNSProxy.start() raises DNSProxyPortInUseError, run_server
    must:
      1. Log at ERROR (not WARNING or lower).
      2. Return a non-zero exit code (fatal, not recovered).
      3. NOT loop back and retry (accept called exactly once).
    """

    async def test_dns_port_in_use_is_fatal_not_recovered(self) -> None:
        from dsm.server import run_server

        captured: dict = {}
        accept_calls = {"n": 0}

        async def _accept(*args: object, **_k: object) -> tuple[object, bytes, object]:
            accept_calls["n"] += 1
            # (session_keys, client_pub, transport): hand back the UDP
            # transport the acceptor was given (args[5]).
            return object(), b"\xbb" * 32, args[5]

        port_in_use_err = DNSProxyPortInUseError(
            "DNS proxy cannot bind 10.8.0.1:53 — another resolver is already "
            "bound there. Stop the host resolver, or change the TUN address."
        )

        class _FailingDNSProxy:
            def __init__(self, *_a: object, **_k: object) -> None:
                pass

            async def start(self) -> None:
                raise port_in_use_err

            def stop(self) -> None:
                pass

        error_records: list[logging.LogRecord] = []

        class _CapturingHandler(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                error_records.append(record)

        handler = _CapturingHandler(level=logging.ERROR)
        server_logger = logging.getLogger("dsm.server")
        server_logger.addHandler(handler)
        try:
            with (
                _base_patches(_accept, captured),
                patch("dsm.server.LocalDNSProxy", _FailingDNSProxy),
            ):
                rc = await run_server(_server_config())
        finally:
            server_logger.removeHandler(handler)

        # Must exit non-zero (fatal):
        self.assertNotEqual(
            rc, 0, "DNSProxyPortInUseError must produce a non-zero exit code"
        )
        self.assertEqual(rc, 1, "run_server must return 1 on fatal DNS port conflict")

        # Must have logged at ERROR level (not just WARNING):
        error_msgs = [
            r.getMessage() for r in error_records if r.levelno >= logging.ERROR
        ]
        self.assertTrue(
            error_msgs,
            "run_server must log at ERROR when DNS port is in use; "
            f"only WARNING/lower found. All captured records: {error_records!r}",
        )

        # The error message must mention the conflict so the operator knows what to fix:
        combined = "\n".join(error_msgs)
        self.assertIn(
            "DNS",
            combined,
            "ERROR log must reference DNS to guide the operator",
        )

        # Must NOT retry — accept is called once (one successful auth),
        # then dns_proxy.start() fails, and run_server returns immediately.
        self.assertEqual(
            accept_calls["n"],
            1,
            "run_server must not retry the accept loop after DNSProxyPortInUseError; "
            f"got {accept_calls['n']} accept calls",
        )

    async def test_other_session_errors_still_recover(self) -> None:
        """Sanity: a plain RuntimeError from _run_one_session still recovers
        (the broad except is NOT removed — only DNSProxyPortInUseError is fatal).
        The server loops back and accepts a second client.
        """
        from dsm.server import run_server

        captured: dict = {}
        accept_calls = {"n": 0}

        async def _accept(*args: object, **_k: object) -> tuple[object, bytes, object]:
            accept_calls["n"] += 1
            return object(), bytes([accept_calls["n"]]) * 32, args[5]

        run_loops_calls = {"n": 0}

        async def _run_data_loops(*args: object, **_k: object) -> None:
            run_loops_calls["n"] += 1
            if run_loops_calls["n"] >= 2:
                # Second session: simulate SIGTERM so the loop exits.
                captured["event"].set()
            # Drive FSM to IDLE to satisfy run_server's re-accept contract.
            from dsm.core.fsm import State

            fsm = args[4]
            try:
                fsm.transition(State.TEARDOWN)
            except Exception:  # noqa: BLE001
                pass
            try:
                fsm.transition(State.IDLE)
            except Exception:  # noqa: BLE001
                pass

        # A proxy that blows up with a non-DNSProxyPortInUseError on the
        # first session, then works normally on the second.
        proxy_calls = {"n": 0}

        class _FlakeyDNSProxy:
            def __init__(self, *_a: object, **_k: object) -> None:
                pass

            async def start(self) -> None:
                proxy_calls["n"] += 1
                if proxy_calls["n"] == 1:
                    raise RuntimeError("transient TUN fluke")

            def stop(self) -> None:
                pass

        with (
            _base_patches(_accept, captured),
            patch("dsm.server.LocalDNSProxy", _FlakeyDNSProxy),
            patch("dsm.session.run_data_loops", side_effect=_run_data_loops),
        ):
            rc = await run_server(_server_config())

        # Server must have recovered from the first transient error and served
        # a second session, then exited cleanly (process_shutdown set → exit 0).
        self.assertEqual(
            rc, 0, "transient session errors must recover, not kill server"
        )
        self.assertGreaterEqual(
            accept_calls["n"],
            2,
            "server must re-accept after a transient session error",
        )


if __name__ == "__main__":
    unittest.main()
