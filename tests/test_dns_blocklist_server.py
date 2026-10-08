"""The server makes one DNS blocklist per run and gives it to every session."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from pathlib import Path
from typing import Any
from unittest.mock import patch

from dsm.net.dns_blocklist import DnsBlocklist
from dsm.server import _drive_fsm_to_idle, run_server
from tests.test_server_dns_fatal import _base_patches, _server_config


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


def _accepter() -> Any:
    calls = {"n": 0}

    async def _accept(*args: Any, **_k: Any) -> tuple[Any, bytes, Any]:
        calls["n"] += 1
        # (session_keys, client_pub, transport): hand back the UDP transport
        # the acceptor was given (args[5]).
        return object(), bytes([calls["n"]]) * 32, args[5]

    return _accept


async def _serve_two_sessions(config: Any) -> tuple[int, list[Any]]:
    """Run the server through two sessions; return its exit code and the
    blocklist argument each session got."""
    captured: dict[str, Any] = {}
    seen: list[Any] = []

    async def _session(*args: Any) -> None:
        seen.append(args[7])
        if len(seen) == 2:
            captured["event"].set()  # process_shutdown
        _drive_fsm_to_idle(args[1])

    _FakeBlocklist.made = []
    with (
        _base_patches(_accepter(), captured),
        patch("dsm.server.DnsBlocklist", _FakeBlocklist),
        patch("dsm.server._run_one_session", new=_session),
    ):
        rc = await run_server(config)
    return rc, seen


async def test_one_blocklist_per_run_goes_to_every_session(tmp_path: Path) -> None:
    rc, seen = await _serve_two_sessions(replace(_server_config(), config_dir=tmp_path))
    assert rc == 0
    assert len(_FakeBlocklist.made) == 1
    made = _FakeBlocklist.made[0]
    assert made.dns_dir == tmp_path / "dns"
    assert made.started and made.stopped
    assert seen == [made, made]


async def test_with_the_key_off_there_is_no_blocklist(tmp_path: Path) -> None:
    config = replace(_server_config(), config_dir=tmp_path, dns_blocklist=False)
    rc, seen = await _serve_two_sessions(config)
    assert rc == 0
    assert _FakeBlocklist.made == []
    assert seen == [None, None]


async def test_each_session_gives_the_blocklist_to_its_dns_proxy(
    tmp_path: Path,
) -> None:
    # Box only: runs the real _run_one_session, which needs tuncore.Shaper.
    proxies: list[dict[str, Any]] = []
    captured: dict[str, Any] = {}

    class _RecordingProxy:
        def __init__(self, *_a: Any, **kwargs: Any) -> None:
            proxies.append(kwargs)

        async def start(self) -> None:
            pass

        def stop(self) -> None:
            pass

    async def _run_data_loops(*args: Any, **_k: Any) -> None:
        captured["event"].set()  # process_shutdown: one session only
        _drive_fsm_to_idle(args[4])

    _FakeBlocklist.made = []
    with (
        _base_patches(_accepter(), captured),
        patch("dsm.server.DnsBlocklist", _FakeBlocklist),
        patch("dsm.server.LocalDNSProxy", _RecordingProxy),
        patch("dsm.session.run_data_loops", side_effect=_run_data_loops),
    ):
        rc = await run_server(replace(_server_config(), config_dir=tmp_path))
    assert rc == 0
    assert [p["blocklist"] for p in proxies] == [_FakeBlocklist.made[0]]


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
