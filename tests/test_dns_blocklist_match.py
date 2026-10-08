"""DnsBlocklist: matching, the allowlist, the canary, reloads and log lines."""

from __future__ import annotations

import errno
import logging
import os
from pathlib import Path

import pytest

from dsm.net import dns_blocklist as bl_mod
from dsm.net.dns_blocklist import CHECK_INTERVAL_S, DnsBlocklist, name_hash

_LOGGER = "dsm.net.dns_blocklist"


class _StopRun(BaseException):
    """Ends DnsBlocklist.run in a test (not an Exception, so run lets it out)."""


def _write(path: Path, body: bytes) -> None:
    path.write_bytes(body)
    path.chmod(0o600)


def _dns_dir(
    base: Path, *, block: dict[str, bytes], allow: bytes | None = None
) -> Path:
    dns_dir = base / "dns"
    (dns_dir / "block").mkdir(parents=True)
    dns_dir.chmod(0o700)
    (dns_dir / "block").chmod(0o700)
    for name, body in block.items():
        _write(dns_dir / "block" / name, body)
    if allow is not None:
        _write(dns_dir / "allow.txt", allow)
    return dns_dir


async def _loaded(
    base: Path, *, block: dict[str, bytes], allow: bytes | None = None
) -> DnsBlocklist:
    blocklist = DnsBlocklist(_dns_dir(base, block=block, allow=allow))
    await blocklist.refresh()
    return blocklist


def _warnings(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [
        r.getMessage()
        for r in caplog.records
        if r.name == _LOGGER and r.levelno == logging.WARNING
    ]


async def test_a_name_and_every_name_under_it_are_blocked(tmp_path: Path) -> None:
    blocklist = await _loaded(tmp_path, block={"a.txt": b"0.0.0.0 ads.example.com\n"})
    assert blocklist.is_blocked("ads.example.com")
    assert blocklist.is_blocked("x.y.ads.example.com")
    assert blocklist.is_blocked("ADS.Example.COM.")
    assert not blocklist.is_blocked("example.com")
    assert not blocklist.is_blocked("badads.example.com")
    assert not blocklist.is_blocked("ads.example.com.evil.net")
    assert not blocklist.is_blocked("")


async def test_the_allowlist_always_wins(tmp_path: Path) -> None:
    blocklist = await _loaded(
        tmp_path,
        block={"a.txt": b"||example.com^\n0.0.0.0 ads.shop.example.net\n"},
        allow=b"good.example.com\nshop.example.net\n",
    )
    assert blocklist.is_blocked("example.com")
    assert blocklist.is_blocked("bad.example.com")
    assert not blocklist.is_blocked("good.example.com")
    assert not blocklist.is_blocked("cdn.good.example.com")
    # An allowed parent beats a blocked name under it.
    assert not blocklist.is_blocked("ads.shop.example.net")


async def test_an_exception_rule_in_a_block_list_allows_the_name(
    tmp_path: Path,
) -> None:
    blocklist = await _loaded(
        tmp_path, block={"a.txt": b"||example.com^\n@@||cdn.example.com^\n"}
    )
    assert blocklist.is_blocked("ads.example.com")
    assert not blocklist.is_blocked("img.cdn.example.com")


async def test_the_firefox_canary_is_always_blocked(tmp_path: Path) -> None:
    assert DnsBlocklist(tmp_path / "missing").is_blocked("use-application-dns.net")
    blocklist = await _loaded(tmp_path, block={}, allow=b"use-application-dns.net\n")
    assert blocklist.is_blocked("use-application-dns.net")
    assert blocklist.is_blocked("x.USE-application-dns.net.")
    assert not blocklist.is_blocked("application-dns.net")


async def test_the_canary_beats_an_exception_rule_in_a_block_list(
    tmp_path: Path,
) -> None:
    # `@@||name^` lines go into the same allow table as allow.txt.
    blocklist = await _loaded(
        tmp_path,
        block={
            "a.txt": b"||example.com^\n"
            b"@@||use-application-dns.net^\n"
            b"@@||sub.use-application-dns.net^\n"
        },
    )
    assert blocklist.is_blocked("use-application-dns.net")
    assert blocklist.is_blocked("sub.use-application-dns.net")
    assert blocklist.is_blocked("other.use-application-dns.net")
    assert blocklist.is_blocked("ads.example.com")


def test_only_the_canary_is_blocked_before_the_first_load(tmp_path: Path) -> None:
    dns_dir = _dns_dir(tmp_path, block={"a.txt": b"0.0.0.0 ads.example.com\n"})
    blocklist = DnsBlocklist(dns_dir)
    assert not blocklist.is_blocked("ads.example.com")
    assert blocklist.is_blocked("use-application-dns.net")


async def test_missing_folder_loads_nothing_and_warns_once(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger=_LOGGER)
    blocklist = DnsBlocklist(tmp_path / "dns")
    await blocklist.refresh()
    await blocklist.refresh()
    warnings = _warnings(caplog)
    assert len(warnings) == 1
    assert "no names to block" in warnings[0]
    assert blocklist.is_blocked("use-application-dns.net")
    assert not blocklist.is_blocked("example.com")


async def test_a_failed_reload_keeps_the_old_lists_and_warns_once(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    blocklist = await _loaded(tmp_path, block={"a.txt": b"0.0.0.0 old.example.com\n"})
    bad = tmp_path / "dns" / "block" / "b.txt"
    bad.write_bytes(b"0.0.0.0 new.example.com\n")
    bad.chmod(0o644)
    caplog.set_level(logging.WARNING, logger=_LOGGER)
    await blocklist.refresh()
    await blocklist.refresh()
    warnings = _warnings(caplog)
    assert len(warnings) == 1
    assert warnings[0].startswith("DNS blocklist not loaded: ")
    assert "chmod 600" in warnings[0]
    assert blocklist.is_blocked("old.example.com")
    assert not blocklist.is_blocked("new.example.com")


async def test_a_disk_error_while_loading_is_handled_like_a_refused_list(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    blocklist = await _loaded(
        tmp_path, block={"a.txt": b"0.0.0.0 secret-old.example.com\n"}
    )
    real_load = bl_mod.load_lists
    failing = True

    def flaky_load(dns_dir: Path, key: bytes) -> bl_mod.LoadedLists:
        if failing:
            # The file name in an OSError must not reach the log.
            raise OSError(errno.EIO, os.strerror(errno.EIO), str(dns_dir / "x.txt"))
        return real_load(dns_dir, key)

    monkeypatch.setattr(bl_mod, "load_lists", flaky_load)
    caplog.set_level(logging.INFO, logger=_LOGGER)
    # The first load above was logged too when "dsm" is at INFO; check only
    # the two refreshes.
    caplog.clear()
    _write(tmp_path / "dns" / "block" / "b.txt", b"0.0.0.0 new.example.com\n")
    await blocklist.refresh()
    await blocklist.refresh()
    assert [r.getMessage() for r in caplog.records if r.name == _LOGGER] == [
        "DNS blocklist not loaded: Input/output error. "
        "The lists already in use stay."
    ]
    assert [r.levelno for r in caplog.records] == [logging.WARNING]
    assert blocklist.is_blocked("secret-old.example.com")
    assert not blocklist.is_blocked("new.example.com")
    assert "x.txt" not in caplog.text
    # Like a refused list, it is read again only when the files change.
    failing = False
    _write(tmp_path / "dns" / "block" / "c.txt", b"0.0.0.0 later.example.com\n")
    await blocklist.refresh()
    assert blocklist.is_blocked("new.example.com")
    assert blocklist.is_blocked("later.example.com")


async def test_fixing_the_mode_loads_at_the_next_check(tmp_path: Path) -> None:
    blocklist = await _loaded(tmp_path, block={"a.txt": b"0.0.0.0 old.example.com\n"})
    bad = tmp_path / "dns" / "block" / "b.txt"
    bad.write_bytes(b"0.0.0.0 new.example.com\n")
    bad.chmod(0o644)
    await blocklist.refresh()
    bad.chmod(0o600)
    await blocklist.refresh()
    assert blocklist.is_blocked("old.example.com")
    assert blocklist.is_blocked("new.example.com")


async def test_an_unchanged_folder_is_read_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reads: list[Path] = []
    real_load = bl_mod.load_lists

    def counting_load(dns_dir: Path, key: bytes) -> bl_mod.LoadedLists:
        reads.append(dns_dir)
        return real_load(dns_dir, key)

    monkeypatch.setattr(bl_mod, "load_lists", counting_load)
    dns_dir = _dns_dir(tmp_path, block={"a.txt": b"0.0.0.0 ads.example.com\n"})
    blocklist = DnsBlocklist(dns_dir)
    for _ in range(3):
        await blocklist.refresh()
    assert reads == [dns_dir]


def test_the_hourly_line_counts_blocked_queries_and_starts_over(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger=_LOGGER)
    blocklist = DnsBlocklist(tmp_path / "dns")
    for _ in range(3):
        blocklist.is_blocked("use-application-dns.net")
    blocklist.is_blocked("example.com")
    blocklist.log_blocked_count()
    blocklist.log_blocked_count()
    assert [r.getMessage() for r in caplog.records if r.name == _LOGGER] == [
        "DNS blocklist: queries blocked in the last hour: 3"
    ]


async def test_logs_never_show_names_or_hashes(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger=_LOGGER)
    names = (b"secret-tracker.example.com", b"private-allowed.example.org")
    blocklist = await _loaded(
        tmp_path,
        block={"a.txt": b"0.0.0.0 " + names[0] + b"\n"},
        allow=names[1] + b"\n",
    )
    assert blocklist.is_blocked(names[0].decode())
    assert not blocklist.is_blocked(names[1].decode())
    (tmp_path / "dns" / "block" / "a.txt").chmod(0o644)
    await blocklist.refresh()  # refused: one warning naming the file
    blocklist.log_blocked_count()
    assert caplog.records, "expected load, warning and count lines"
    for name in names:
        digest = name_hash(name, blocklist._key)
        assert name.decode() not in caplog.text
        assert f"{digest:016x}" not in caplog.text
        assert str(digest) not in caplog.text


async def test_run_loads_at_once_then_checks_every_5_minutes_and_counts_hourly(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO, logger=_LOGGER)
    dns_dir = _dns_dir(tmp_path, block={"a.txt": b"0.0.0.0 ads.example.com\n"})
    blocklist = DnsBlocklist(dns_dir)
    waits: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        waits.append(seconds)
        if len(waits) == 1:
            # The lists were loaded before the first wait.
            assert blocklist.is_blocked("ads.example.com")
        if len(waits) == 13:
            raise _StopRun

    with pytest.raises(_StopRun):
        await blocklist.run(sleep=fake_sleep)
    assert waits == [CHECK_INTERVAL_S] * 13
    assert CHECK_INTERVAL_S == 300.0
    counts = [
        r.getMessage() for r in caplog.records if "queries blocked" in r.getMessage()
    ]
    assert counts == ["DNS blocklist: queries blocked in the last hour: 1"]


async def test_run_keeps_checking_after_a_disk_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    dns_dir = _dns_dir(tmp_path, block={"a.txt": b"0.0.0.0 old.example.com\n"})
    real_load = bl_mod.load_lists
    loads = 0

    def flaky_load(path: Path, key: bytes) -> bl_mod.LoadedLists:
        nonlocal loads
        loads += 1
        if loads == 1:
            raise OSError(errno.EIO, os.strerror(errno.EIO), str(path))
        return real_load(path, key)

    monkeypatch.setattr(bl_mod, "load_lists", flaky_load)
    caplog.set_level(logging.INFO, logger=_LOGGER)
    blocklist = DnsBlocklist(dns_dir)
    waits: list[float] = []

    async def fake_sleep(seconds: float) -> None:
        waits.append(seconds)
        if len(waits) == 1:
            assert not blocklist.is_blocked("old.example.com")
            _write(dns_dir / "block" / "b.txt", b"0.0.0.0 new.example.com\n")
        if len(waits) == 2:
            raise _StopRun

    with pytest.raises(_StopRun):
        await blocklist.run(sleep=fake_sleep)
    assert waits == [CHECK_INTERVAL_S] * 2
    assert blocklist.is_blocked("old.example.com")
    assert blocklist.is_blocked("new.example.com")
    assert len(_warnings(caplog)) == 1
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]


async def test_run_reports_a_bug_once_and_ends(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def broken(_dns_dir: Path) -> bl_mod.Signature:
        raise RuntimeError("bug text that must not be logged")

    async def no_sleep(_seconds: float) -> None:
        raise AssertionError("run should have ended before its first wait")

    monkeypatch.setattr(bl_mod, "list_signature", broken)
    caplog.set_level(logging.ERROR, logger=_LOGGER)
    await DnsBlocklist(tmp_path / "dns").run(sleep=no_sleep)
    assert [r.getMessage() for r in caplog.records if r.name == _LOGGER] == [
        "DNS blocklist: list checks stopped (RuntimeError); the lists in use stay "
        "until dsm restarts"
    ]


async def test_stop_cancels_the_task_and_a_second_stop_does_nothing(
    tmp_path: Path,
) -> None:
    blocklist = DnsBlocklist(tmp_path / "dns")
    blocklist.start()
    task = blocklist._task
    await blocklist.stop()
    assert task is not None and task.done()
    assert blocklist._task is None
    await blocklist.stop()
