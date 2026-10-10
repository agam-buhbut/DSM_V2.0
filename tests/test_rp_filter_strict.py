"""Client works on hosts with strict reverse-path filtering (rp_filter=1).

The client's ``ip rule not fwmark <FWMARK> table 100`` sends every unmarked
packet to the TUN. The server's replies arrive on the physical link with no
mark, so the strict reverse-path check looks up the way back to the server
in table 100, finds the TUN, and drops them. The fix (as in wg-quick):

  * the kill-switch table saves DSM's socket mark into conntrack on output
    and copies it back onto the replies in prerouting (mangle priority);
  * ``net.ipv4.conf.all.src_valid_mark=1`` while connected, so the
    reverse-path check uses that mark. The prior value is restored on exit,
    and saved under /run/dsm so ``dsm cleanup`` restores it after a crash.

Only I/O boundaries are mocked: ``subprocess.run`` (nft / sysctl), the
``sysctl_path`` translator (redirected into a tmp tree, as in
tests/test_sysctl.py) and the state-file path.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
from contextlib import ExitStack
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from dsm.core import sysctl
from dsm.core.config import Config
from dsm.net import cleanup, nftables
from dsm.net._addresses import SINGLE_CLIENT_TUNNEL
from dsm.net.nftables import NFTablesManager
from dsm.net.transport._fwmark import SO_MARK_VALUE

_SERVER_IP = "203.0.113.7"
_PORT = 51820
_TUN = "mtun0"
_KEY = "net.ipv4.conf.all.src_valid_mark"
_MARK = f"{SO_MARK_VALUE:#x}"


def _table_body(rules: str, table: str) -> str:
    """Text of one ``table inet <name> { ... }`` block (brace matched)."""
    start = rules.index(f"table inet {table} {{")
    depth = 0
    for i in range(start, len(rules)):
        if rules[i] == "{":
            depth += 1
        elif rules[i] == "}":
            depth -= 1
            if depth == 0:
                return rules[start : i + 1]
    raise AssertionError(f"unterminated table {table}")


def _chain_lines(body: str, chain: str) -> list[str]:
    """Stripped, non-comment rule lines of ``chain`` inside ``body``."""
    out: list[str] = []
    inside = False
    for line in body.splitlines():
        s = line.strip()
        if s.startswith(f"chain {chain} "):
            inside = True
            continue
        if inside and s == "}":
            return out
        if inside and s and not s.startswith("#"):
            out.append(s)
    raise AssertionError(f"chain {chain} not found")


def _killswitch() -> str:
    return _table_body(
        NFTablesManager(_SERVER_IP, _PORT, _TUN)._render(), "dsm_killswitch"
    )


# --------------------------------------------------------------------------- #
# nftables: mark save / restore
# --------------------------------------------------------------------------- #


_SAVE = (
    f"meta mark {_MARK} ip daddr {_SERVER_IP} meta l4proto {{ tcp, udp }} "
    f"th dport {_PORT} ct mark set meta mark"
)
_RESTORE = (
    f"ip saddr {_SERVER_IP} meta l4proto {{ tcp, udp }} th sport {_PORT} "
    f"ct direction reply ct mark {_MARK} meta mark set ct mark"
)
_RESTORE_PMTU = (
    "icmp type destination-unreachable icmp code frag-needed "
    f"ct original ip daddr {_SERVER_IP} ct original proto-dst {_PORT} "
    f"ct mark {_MARK} meta mark set ct mark"
)


def test_mark_save_chain_copies_socket_mark_into_conntrack() -> None:
    lines = _chain_lines(_killswitch(), "mark_save")
    assert lines[0] == "type filter hook output priority mangle; policy accept;"
    # Only marked packets to the current server's IP and port.
    assert lines[1:] == [_SAVE]


def test_mark_restore_chain_copies_mark_back_before_routing() -> None:
    lines = _chain_lines(_killswitch(), "mark_restore")
    # prerouting at mangle (-150): after conntrack (-200), before routing.
    assert lines[0] == "type filter hook prerouting priority mangle; policy accept;"
    # Replies from the current server only, plus its frag-needed errors.
    assert lines[1:] == [_RESTORE, _RESTORE_PMTU]


def test_every_mark_rule_names_the_server_ip_and_port() -> None:
    body = _killswitch()
    rules = _chain_lines(body, "mark_save")[1:] + _chain_lines(body, "mark_restore")[1:]
    assert rules
    for s in rules:
        assert _SERVER_IP in s, s
        assert str(_PORT) in s, s
        assert f"ct mark {_MARK}" in s or f"meta mark {_MARK}" in s, s


def test_mark_rules_follow_a_different_server() -> None:
    body = _table_body(
        NFTablesManager("198.51.100.9", 4433, _TUN)._render(), "dsm_killswitch"
    )
    rules = _chain_lines(body, "mark_save")[1:] + _chain_lines(body, "mark_restore")[1:]
    for s in rules:
        assert "198.51.100.9" in s and "4433" in s, s
        assert _SERVER_IP not in s and str(_PORT) not in s, s


def test_mark_restore_only_on_reply_direction() -> None:
    # An entry the far side opened (original direction inbound) never gets
    # the mark back, even if its ct mark is 0x1.
    restore = _chain_lines(_killswitch(), "mark_restore")[1]
    assert "ct direction reply" in restore


def test_mark_restore_keeps_path_mtu_but_never_marks_redirects() -> None:
    rules = _chain_lines(_killswitch(), "mark_restore")[1:]
    assert _RESTORE_PMTU in rules
    # A restored mark would let a "related" ICMP redirect through the input
    # chain's `ct state established,related meta mark` accept, ahead of the
    # explicit redirect drop. Only tcp/udp and frag-needed get a mark.
    for s in rules:
        assert "redirect" not in s
        assert "l4proto icmp " not in s


def test_mark_chains_never_drop_or_accept() -> None:
    body = _killswitch()
    for chain in ("mark_save", "mark_restore"):
        for s in _chain_lines(body, chain)[1:]:
            assert not s.endswith(("drop", "accept", "reject")), s


def test_mark_comes_from_the_single_fwmark_source() -> None:
    with patch.object(nftables, "FWMARK", 0x2A):
        body = _table_body(
            NFTablesManager(_SERVER_IP, _PORT, _TUN)._render(), "dsm_killswitch"
        )
    assert "meta mark 0x2a ip daddr" in body
    assert "ct mark set meta mark" in body
    assert body.count("ct mark 0x2a meta mark set ct mark") == 2
    assert "{FWMARK}" not in body


def test_no_fwmark_placeholder_left_in_rendered_rules() -> None:
    rendered = NFTablesManager(_SERVER_IP, _PORT, _TUN)._render()
    assert "{FWMARK}" not in rendered


def test_mark_chains_are_removed_with_the_kill_switch() -> None:
    # The chains live in dsm_killswitch, so remove() and crash cleanup (both
    # delete that table) take them away too.
    calls: list[list[str]] = []

    def fake_run(cmd: list[str], *_a: object, **_k: object) -> object:
        calls.append(list(cmd))
        return subprocess.CompletedProcess(args=cmd, returncode=0)

    with patch.object(nftables.subprocess, "run", fake_run):
        NFTablesManager(_SERVER_IP, _PORT, _TUN).remove()
    assert ["nft", "delete", "table", "inet", "dsm_killswitch"] in calls
    assert "dsm_killswitch" in cleanup._DSM_TABLES
    assert "chain mark_save" in _killswitch()
    assert "chain mark_restore" in _killswitch()


# --------------------------------------------------------------------------- #
# src_valid_mark sysctl
# --------------------------------------------------------------------------- #


@pytest.fixture
def fake_proc(tmp_path: Path) -> Any:
    """Redirect /proc/sys into tmp and the state file into tmp/run."""
    from dsm.net.tunnel import SrcValidMarkEnabler

    root = tmp_path / "proc"
    state = tmp_path / "run" / "dsm" / "src_valid_mark.orig"

    def fake_path(key: str) -> Path:
        return root / key.replace(".", "/")

    with (
        patch.object(sysctl, "sysctl_path", fake_path),
        patch.object(SrcValidMarkEnabler, "STATE_PATH", state),
    ):
        yield fake_path, state


def _seed(fake_path: Any, value: str) -> Path:
    path: Path = fake_path(_KEY)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"{value}\n")
    return path


def test_src_valid_mark_set_while_up_and_restored(fake_proc: Any) -> None:
    from dsm.net.tunnel import SrcValidMarkEnabler

    fake_path, state = fake_proc
    knob = _seed(fake_path, "0")

    svm = SrcValidMarkEnabler()
    svm.apply()
    assert knob.read_text().strip() == "1"
    # Prior value saved for crash cleanup, private to root.
    assert state.read_text().strip() == "0"
    assert state.stat().st_mode & 0o777 == 0o600

    svm.remove()
    assert knob.read_text().strip() == "0"
    assert not state.exists()


def test_src_valid_mark_already_on_is_left_alone(fake_proc: Any) -> None:
    from dsm.net.tunnel import SrcValidMarkEnabler

    fake_path, state = fake_proc
    knob = _seed(fake_path, "1")

    svm = SrcValidMarkEnabler()
    svm.apply()
    assert not state.exists()
    svm.remove()
    # The operator had it on (e.g. wg-quick): exit must not turn it off.
    assert knob.read_text().strip() == "1"


def test_stale_state_from_a_crash_is_kept_for_cleanup(fake_proc: Any) -> None:
    from dsm.net.tunnel import SrcValidMarkEnabler

    fake_path, state = fake_proc
    # An earlier run crashed: knob left at 1, operator's 0 saved on disk.
    knob = _seed(fake_path, "1")
    state.parent.mkdir(parents=True)
    state.write_text("0\n")

    svm = SrcValidMarkEnabler()
    svm.apply()
    svm.remove()
    assert knob.read_text().strip() == "1"
    # Still there, so `dsm cleanup` can put the operator's 0 back.
    assert state.read_text().strip() == "0"


def test_stale_state_is_not_overwritten_on_start(fake_proc: Any) -> None:
    from dsm.net.tunnel import SrcValidMarkEnabler

    fake_path, state = fake_proc
    # Earlier crash saved "1"; since then the knob was set to 0 by hand.
    knob = _seed(fake_path, "0")
    state.parent.mkdir(parents=True)
    state.write_text("1\n")

    svm = SrcValidMarkEnabler()
    svm.apply()
    assert knob.read_text().strip() == "1"
    # The crash-saved value is kept, not replaced by the current "0".
    assert state.read_text().strip() == "1"
    svm.remove()
    # Clean exit restores what this run saw; the old file stays for cleanup.
    assert knob.read_text().strip() == "0"
    assert state.read_text().strip() == "1"


def test_failed_restore_keeps_the_saved_value(fake_proc: Any) -> None:
    from dsm.net.tunnel import SrcValidMarkEnabler

    fake_path, state = fake_proc
    knob = _seed(fake_path, "0")

    svm = SrcValidMarkEnabler()
    svm.apply()
    assert knob.read_text().strip() == "1"

    real_write_text = Path.write_text

    def deny_knob(self: Path, *a: Any, **k: Any) -> int:
        if self == knob:
            raise PermissionError("read-only /proc")
        return real_write_text(self, *a, **k)

    with patch.object(Path, "write_text", deny_knob):
        svm.remove()
    assert knob.read_text().strip() == "1"
    # Restore failed: keep the file so `dsm cleanup` can try again.
    assert state.read_text().strip() == "0"


def test_remove_twice_is_safe(fake_proc: Any) -> None:
    from dsm.net.tunnel import SrcValidMarkEnabler

    fake_path, state = fake_proc
    knob = _seed(fake_path, "0")

    svm = SrcValidMarkEnabler()
    svm.apply()
    svm.remove()
    svm.remove()
    assert knob.read_text().strip() == "0"
    assert not state.exists()


def test_src_valid_mark_unreadable_does_not_raise(fake_proc: Any) -> None:
    from dsm.net.tunnel import SrcValidMarkEnabler

    _fake_path, state = fake_proc  # key never seeded -> read fails
    svm = SrcValidMarkEnabler()
    svm.apply()
    svm.remove()
    assert not state.exists()


def test_src_valid_mark_write_failure_drops_state_file(fake_proc: Any) -> None:
    from dsm.net.tunnel import SrcValidMarkEnabler

    fake_path, state = fake_proc
    knob = _seed(fake_path, "0")

    real_write_text = Path.write_text

    def deny_knob(self: Path, *a: Any, **k: Any) -> int:
        if self == knob:
            raise PermissionError("read-only /proc")
        return real_write_text(self, *a, **k)

    with patch.object(Path, "write_text", deny_knob):
        SrcValidMarkEnabler().apply()
    assert knob.read_text().strip() == "0"
    # Nothing changed, so crash cleanup must have nothing to restore.
    assert not state.exists()


# --------------------------------------------------------------------------- #
# Crash cleanup
# --------------------------------------------------------------------------- #


def _run_cleanup(state: Path, *, sysctl_rc: int = 0) -> list[str]:
    from dsm.net.tunnel import SrcValidMarkEnabler

    runs: list[str] = []

    def fake_run(cmd: list[str], *_a: object, **_k: object) -> object:
        runs.append(" ".join(cmd))
        rc = sysctl_rc if cmd[0] == "sysctl" else 0
        return subprocess.CompletedProcess(args=cmd, returncode=rc)

    with (
        patch.object(cleanup.subprocess, "run", fake_run),
        patch.object(SrcValidMarkEnabler, "STATE_PATH", state),
        patch.object(cleanup, "RESOLV_CONF", state.parent / "resolv.conf"),
        patch.object(cleanup, "RESOLV_BACKUP", state.parent / "resolv.orig"),
    ):
        cleanup.cleanup_host_state()
    return runs


def test_cleanup_restores_saved_src_valid_mark(tmp_path: Path) -> None:
    state = tmp_path / "src_valid_mark.orig"
    state.write_text("0\n")
    runs = _run_cleanup(state)
    assert f"sysctl -w {_KEY}=0" in runs
    assert not state.exists()


def test_cleanup_restores_saved_value_one(tmp_path: Path) -> None:
    state = tmp_path / "src_valid_mark.orig"
    state.write_text("1\n")
    runs = _run_cleanup(state)
    assert f"sysctl -w {_KEY}=1" in runs
    assert not state.exists()


def test_cleanup_keeps_state_when_restore_fails(tmp_path: Path) -> None:
    state = tmp_path / "src_valid_mark.orig"
    state.write_text("0\n")
    runs = _run_cleanup(state, sysctl_rc=1)
    assert f"sysctl -w {_KEY}=0" in runs
    # Not restored, so the saved value stays for the next try.
    assert state.read_text().strip() == "0"


def test_cleanup_keeps_state_when_sysctl_missing(tmp_path: Path) -> None:
    from dsm.net.tunnel import SrcValidMarkEnabler

    state = tmp_path / "src_valid_mark.orig"
    state.write_text("0\n")

    def no_binary(cmd: list[str], *_a: object, **_k: object) -> object:
        raise FileNotFoundError(cmd[0])

    with (
        patch.object(cleanup.subprocess, "run", no_binary),
        patch.object(SrcValidMarkEnabler, "STATE_PATH", state),
        patch.object(cleanup, "RESOLV_CONF", tmp_path / "resolv.conf"),
        patch.object(cleanup, "RESOLV_BACKUP", tmp_path / "resolv.orig"),
    ):
        cleanup.cleanup_host_state()
    assert state.read_text().strip() == "0"


def test_cleanup_without_state_leaves_src_valid_mark(tmp_path: Path) -> None:
    # No state file: dsm did not change it (or already restored it), so the
    # operator's value must not be touched.
    runs = _run_cleanup(tmp_path / "src_valid_mark.orig")
    assert not any(_KEY in r for r in runs)


def test_cleanup_ignores_bad_state_value(tmp_path: Path) -> None:
    state = tmp_path / "src_valid_mark.orig"
    state.write_text("1; reboot\n")
    runs = _run_cleanup(state)
    assert not any(_KEY in r for r in runs)
    assert not state.exists()


# --------------------------------------------------------------------------- #
# Client lifecycle order
# --------------------------------------------------------------------------- #


def _client_config() -> Config:
    return Config(
        mode="client",
        server_ip="10.0.0.1",
        server_port=51820,
        listen_port=0,
        key_file="/tmp/dsm-test.key",
        cert_file="/tmp/dsm-test.crt",
        ca_root_file="/tmp/dsm-test-ca.pem",
        attest_key_file="/tmp/dsm-test-attest.key",
        expected_server_cn="dsm-test-server",
        transport="udp",
    )


async def test_client_sets_src_valid_mark_around_the_policy_route() -> None:
    events: list[str] = []

    def recorder(name: str) -> type:
        class _Rec:
            def __init__(self, *_a: object, **_k: object) -> None:
                pass

            def apply(self) -> None:
                events.append(f"{name}.apply")

            def remove(self) -> None:
                events.append(f"{name}.remove")

            def open(self) -> None:
                pass

            def configure(self, *_a: object, **_k: object) -> None:
                events.append(f"{name}.configure")

            def close(self) -> None:
                events.append(f"{name}.close")

        return _Rec

    class _Materials:
        cert_der = b""
        ca_root = object()
        crl = None

    class _Identity:
        public_key = b"\x01" * 32

    class _FakeStore:
        def __init__(self, *_a: object, **_k: object) -> None:
            self.identity = _Identity()
            self.attest_key = object()

        def unload(self) -> None:
            pass

    class _FakeTransport:
        async def bind(self, *_a: object, **_k: object) -> int:
            return 0

        def get_path_mtu(self) -> int | None:
            return None

        async def aclose(self) -> None:
            pass

    class _FakeKeys:
        epoch = 0

    async def _handshake(*_a: object, **_k: object) -> tuple[Any, bytes, bytes, Any]:
        return _FakeKeys(), b"", b"\x02" * 32, SINGLE_CLIENT_TUNNEL

    async def _no_send(_data: bytes, _target_size: int) -> None:
        pass

    class _FakeScheduler:
        def __init__(self, *_a: object, **_k: object) -> None:
            pass

        async def start(self) -> None:
            pass

        async def stop(self) -> None:
            pass

    stops: list[asyncio.Event] = []

    async def _data_loops(
        *_a: object, extra_loops: tuple[Any, ...] = (), **_k: object
    ) -> None:
        for loop in extra_loops:
            loop.close()  # never started here
        # The user stops DSM here; a session that ends without a stop makes
        # the client reconnect.
        stops[0].set()

    patches = [
        patch("tuncore.harden_process"),
        patch("dsm.core.hardening.set_process_nondumpable"),
        patch("dsm.crypto.attest_gate.enforce_attest_backend_policy"),
        patch("dsm.client.setup_signal_handlers", stops.append),
        patch("dsm.client.load_cert_materials", return_value=_Materials()),
        patch("dsm.client.verify_cert_matches_identity"),
        patch("dsm.crypto._stores.load_daemon_stores", return_value=True),
        patch("dsm.client.KeyStore", _FakeStore),
        patch("dsm.client.AttestStore", _FakeStore),
        patch("dsm.client.PreHandshakeKillSwitch", recorder("pre")),
        patch("dsm.client.check_clock_sync", return_value=None),
        patch("dsm.client.UDPTransport", _FakeTransport),
        patch("dsm.crypto.handshake.client_handshake", _handshake),
        patch("dsm.client.TcpTimestampsDisabler", recorder("tcp_ts")),
        patch("dsm.client.SrcValidMarkEnabler", recorder("svm")),
        patch("dsm.client.TunDevice", recorder("tun")),
        patch("dsm.client.NFTablesManager", recorder("nft")),
        patch("dsm.client.ResolvConfManager", recorder("resolv")),
        patch("dsm.client.make_send_fn", return_value=_no_send),
        patch("dsm.client.TrafficShaper"),
        patch("dsm.client.SendScheduler", _FakeScheduler),
        patch("dsm.session.run_data_loops", _data_loops),
    ]
    with ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)
        from dsm.client import run_client

        rc = await asyncio.wait_for(run_client(_client_config()), timeout=10)

    assert rc == 0
    assert "svm.apply" in events and "svm.remove" in events
    # On before the not-fwmark rule goes in (tun.configure) ...
    assert events.index("svm.apply") < events.index("tun.configure")
    # ... and back to the old value only after that rule is gone (tun.close).
    assert events.index("svm.remove") > events.index("tun.close")


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read any directory")
def test_unreadable_state_dir_does_not_crash_start(fake_proc: Any) -> None:
    # /run/dsm is root-only; a check there without root raised before.
    from dsm.net.tunnel import SrcValidMarkEnabler

    fake_path, state = fake_proc
    _seed(fake_path, "1")
    state.parent.mkdir(parents=True)
    state.parent.chmod(0)
    try:
        svm = SrcValidMarkEnabler()
        svm.apply()
        svm.remove()
    finally:
        state.parent.chmod(0o700)
