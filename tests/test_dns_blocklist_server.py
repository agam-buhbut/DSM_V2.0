"""The server makes one DNS blocklist per run and gives it to the run's one
DNS proxy."""

from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest.mock import patch

from dsm.net.dns_blocklist import DnsBlocklist
from dsm.net.session_slot import SessionTable
from dsm.server import _set_up_host
from tests.test_server_dns_fatal import _base_patches, _run_until, _server_config


class _FakeBlocklist:
    made: list[_FakeBlocklist] = []

    def __init__(self, dns_dir: Path) -> None:
        self.dns_dir = dns_dir
        self.started = False
        self.stopped = False
        _FakeBlocklist.made.append(self)

    def start(self) -> None:
        self.started = True

    async def stop(self) -> None:
        self.stopped = True


class _Quiet:
    """TUN, forwarding and NAT stand-ins that do nothing; the NAT table
    loads."""

    applied = True  # as MasqueradeManager.applied after a load that worked

    def __init__(self, *_a: Any, **_k: Any) -> None:
        pass

    def open(self) -> None:
        pass

    def configure(self, *_a: Any, **_k: Any) -> None:
        pass

    def close(self) -> None:
        pass

    def apply(self) -> None:
        pass

    def remove(self) -> None:
        pass


async def _run_once(config: Any) -> tuple[int, dict[str, Any]]:
    captured: dict[str, Any] = {}
    _FakeBlocklist.made = []
    with _base_patches(captured), patch("dsm.server.DnsBlocklist", _FakeBlocklist):
        rc = await _run_until(config, captured)
    return rc, captured


async def test_one_blocklist_per_run_goes_to_the_host_setup(tmp_path: Path) -> None:
    rc, captured = await _run_once(replace(_server_config(), config_dir=tmp_path))
    assert rc == 0
    assert len(_FakeBlocklist.made) == 1
    made = _FakeBlocklist.made[0]
    assert made.dns_dir == tmp_path / "dns"
    assert made.started and made.stopped
    assert captured["blocklist"] is made


async def test_with_the_key_off_there_is_no_blocklist(tmp_path: Path) -> None:
    rc, captured = await _run_once(
        replace(_server_config(), config_dir=tmp_path, dns_blocklist=False)
    )
    assert rc == 0
    assert _FakeBlocklist.made == []
    assert captured["blocklist"] is None


async def test_the_one_dns_proxy_gets_the_runs_blocklist(tmp_path: Path) -> None:
    proxies: list[dict[str, Any]] = []

    class _RecordingProxy:
        def __init__(self, *_a: Any, **kwargs: Any) -> None:
            proxies.append(kwargs)

        async def start(self) -> None:
            pass

        def stop(self) -> None:
            pass

    blocklist = _FakeBlocklist(tmp_path / "dns")
    with (
        patch("dsm.server.TunDevice", _Quiet),
        patch("dsm.server.IPForwardingManager", _Quiet),
        patch("dsm.server.MasqueradeManager", _Quiet),
        patch("dsm.server.LocalDNSProxy", _RecordingProxy),
    ):
        async with AsyncExitStack() as stack:
            await _set_up_host(
                _server_config(), stack, blocklist, SessionTable(["dsm-a-client"])  # type: ignore[arg-type]
            )
    assert [p["blocklist"] for p in proxies] == [blocklist]


class _ProbeBlocklist(DnsBlocklist):
    """A blocklist whose ``run`` is a stand-in that counts and can be slow to
    end, so the start/stop rules can be checked without any list files."""

    def __init__(self) -> None:
        super().__init__(Path("unused"))
        self.runs = 0
        self.entered = asyncio.Event()
        self.cancelled = asyncio.Event()
        self.release = asyncio.Event()
        self.slow_end = False
        self.cleaned_up = False
        self.returns_at_once = False

    async def run(self, **_k: Any) -> None:
        self.runs += 1
        self.entered.set()
        if self.returns_at_once:
            return
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled.set()
            if self.slow_end:
                await self.release.wait()
                self.cleaned_up = True
            raise


async def _wait(event: asyncio.Event) -> None:
    # A broken start/stop fails here instead of hanging the test run.
    await asyncio.wait_for(event.wait(), timeout=5)


async def test_start_while_the_task_is_alive_does_nothing() -> None:
    blocklist = _ProbeBlocklist()
    blocklist.start()
    await _wait(blocklist.entered)
    blocklist.start()
    await asyncio.sleep(0)
    assert blocklist.runs == 1
    await blocklist.stop()
    assert blocklist.cancelled.is_set()


async def test_start_again_after_the_task_ended_runs_a_new_one() -> None:
    blocklist = _ProbeBlocklist()
    blocklist.returns_at_once = True
    blocklist.start()
    await _wait(blocklist.entered)
    await asyncio.sleep(0)  # let the first task finish
    blocklist.returns_at_once = False
    blocklist.entered.clear()
    blocklist.start()
    await _wait(blocklist.entered)
    assert blocklist.runs == 2
    await blocklist.stop()


async def test_stop_twice_is_safe() -> None:
    blocklist = _ProbeBlocklist()
    blocklist.start()
    await _wait(blocklist.entered)
    await blocklist.stop()
    await blocklist.stop()
    assert blocklist.cancelled.is_set()


async def test_stop_without_start_is_safe() -> None:
    await _ProbeBlocklist().stop()


async def test_stop_does_not_swallow_a_cancel_aimed_at_its_caller() -> None:
    blocklist = _ProbeBlocklist()
    blocklist.slow_end = True
    blocklist.start()
    await _wait(blocklist.entered)
    caller = asyncio.create_task(blocklist.stop())
    # The run task has seen its cancel and is slow to end: stop() is waiting.
    await _wait(blocklist.cancelled)
    caller.cancel()
    await asyncio.wait([caller])
    blocklist.release.set()
    assert caller.cancelled()


async def test_stop_clears_the_task_before_it_waits() -> None:
    blocklist = _ProbeBlocklist()
    blocklist.slow_end = True
    blocklist.start()
    await _wait(blocklist.entered)
    first = asyncio.create_task(blocklist.stop())
    await _wait(blocklist.cancelled)
    # A second stop() while the first still waits has nothing left to do: it
    # must not cancel the task again in the middle of its clean-up.
    await blocklist.stop()
    blocklist.release.set()
    await first
    assert blocklist.cleaned_up
