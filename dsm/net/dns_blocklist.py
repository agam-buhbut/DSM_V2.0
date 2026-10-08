"""Server DNS blocklist: names on the owner's lists get "no such name".

The lists live in one fixed folder, ``<config_dir>/dns/``: every
``block/*.txt`` file is a block list and ``allow.txt`` holds names that are
never blocked. DSM never downloads anything; ``deploy/dsm-blocklist-update.sh``
fills ``block/``. The files follow the same rules as DSM's other files:
owned by the uid dsm runs as, no group or world access, no links.

Each name is kept as an 8-byte keyed hash (blake2b, random key per run) in a
sorted ``array``: about 8 MB per million names. Logs show counts and file
paths only, never names or hashes.
"""

from __future__ import annotations

import asyncio
import errno
import hashlib
import ipaddress
import logging
import os
import re
import secrets
import stat
from array import array
from bisect import bisect_left
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import NamedTuple

log = logging.getLogger(__name__)

BLOCK_DIR = "block"
ALLOW_FILE = "allow.txt"
LIST_SUFFIX = ".txt"
# Limits that keep memory bounded. MAX_NAMES counts every entry read (block
# and allow, before duplicates are dropped).
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_NAMES = 2_000_000
CHECK_INTERVAL_S = 300.0
# 12 checks of 5 minutes: one count line an hour.
REPORT_EVERY_CHECKS = 12
# How long a device may remember a blocked answer (the SOA's TTL and minimum).
NEGATIVE_TTL_S = 300
# Firefox asks for this name before it turns on its own encrypted DNS, which
# would skip the blocklist. "No such name" tells it not to.
CANARY = "use-application-dns.net"

_CANARY_SUFFIX = "." + CANARY
_MAX_NAME_LEN = 253
_MAX_LINE_BYTES = 4096
_BOM = b"\xef\xbb\xbf"
_NAME_RE = re.compile(rb"[a-z0-9_-]{1,63}(?:\.[a-z0-9_-]{1,63})+")
_ADGUARD_RE = re.compile(rb"(@@)?\|\|([^|^$*/]+)\^")
_COMMON_IPS = frozenset((b"0.0.0.0", b"127.0.0.1", b"::", b"::1"))
# O_NONBLOCK: opening a FIFO named like a list must not hang the worker.
_OPEN_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC

Signature = tuple[tuple[str | int, ...], ...]


class BlocklistError(Exception):
    """A list file or folder was refused. The message names it and says why."""


class ParsedLine(NamedTuple):
    """What one list line gives."""

    names: tuple[bytes, ...]
    # True for `@@||name^`: an allow entry inside a block list.
    exception: bool
    # True when the line had something this reader does not take.
    skipped: bool


_NOTHING = ParsedLine((), False, False)
_SKIPPED = ParsedLine((), False, True)


def _clean_name(token: bytes) -> bytes | None:
    name = token.lower()
    if name.endswith(b"."):
        name = name[:-1]
    if len(name) > _MAX_NAME_LEN or _NAME_RE.fullmatch(name) is None:
        return None
    # No top-level domain is all digits, so this drops IPv4 addresses.
    if name.rsplit(b".", 1)[1].isdigit():
        return None
    return name


def _is_ip(token: bytes) -> bool:
    if token in _COMMON_IPS:
        return True
    try:
        ipaddress.ip_address(token.decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        return False
    return True


def parse_line(line: bytes) -> ParsedLine:
    """Read one line: a hosts line, one name, ``||name^`` or ``@@||name^``.

    ``#`` and ``!`` lines are comments. A ``#`` that starts a word ends the
    line. Any other AdGuard rule, a name with one label (``localhost``) and
    an IP address in place of a name are skipped.
    """
    text = line.strip()
    if not text or text.startswith((b"#", b"!")):
        return _NOTHING
    if text.startswith((b"||", b"@@")):
        match = _ADGUARD_RE.fullmatch(text)
        if match is None:
            return _SKIPPED
        name = _clean_name(match.group(2))
        if name is None:
            return _SKIPPED
        return ParsedLine((name,), match.group(1) is not None, False)
    tokens = text.split()
    cut = next((i for i, t in enumerate(tokens) if t.startswith(b"#")), len(tokens))
    tokens = tokens[:cut]
    if len(tokens) == 1:
        name = _clean_name(tokens[0])
        return _SKIPPED if name is None else ParsedLine((name,), False, False)
    if not _is_ip(tokens[0]):
        return _SKIPPED
    names = tuple(n for n in map(_clean_name, tokens[1:]) if n is not None)
    return ParsedLine(names, False, len(names) < len(tokens) - 1)


def name_hash(name: bytes, key: bytes) -> int:
    """The 8-byte keyed hash a name is stored as."""
    return int.from_bytes(hashlib.blake2b(name, digest_size=8, key=key).digest(), "big")


@dataclass(frozen=True, slots=True)
class LoadedLists:
    """Sorted name hashes without duplicates, and counts for the log."""

    block: array[int]
    allow: array[int]
    files: int
    skipped: int


def _no_lists() -> LoadedLists:
    return LoadedLists(array("Q"), array("Q"), 0, 0)


def _open_checked(path: Path, dir_fd: int | None, *, folder: bool) -> int:
    """Open ``path`` (by name inside ``dir_fd`` when given) under DSM's file rules.

    Raises:
        FileNotFoundError: it does not exist.
        BlocklistError: it is a link, the wrong kind, owned by another uid,
            open to group or world, or (a file) over MAX_FILE_BYTES.
    """
    name = path.name if dir_fd is not None else str(path)
    kind = "folder" if folder else "regular file"
    try:
        fd = os.open(name, _OPEN_FLAGS, dir_fd=dir_fd)
    except OSError as e:
        if isinstance(e, FileNotFoundError):
            raise
        if e.errno == errno.ELOOP:
            raise BlocklistError(
                f"{path} is a symlink; replace it with the real "
                f"{'folder' if folder else 'file'}"
            ) from e
        raise BlocklistError(f"cannot open {path}: {e.strerror}") from e
    try:
        st = os.fstat(fd)
        is_kind = stat.S_ISDIR(st.st_mode) if folder else stat.S_ISREG(st.st_mode)
        if not is_kind:
            raise BlocklistError(f"{path} is not a {kind}")
        if st.st_uid != os.getuid():
            raise BlocklistError(
                f"{path} is owned by uid {st.st_uid}, not {os.getuid()} "
                f"(the uid dsm runs as)"
            )
        if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            fix = 700 if folder else 600
            raise BlocklistError(
                f"{path} has group/world permissions "
                f"(mode {st.st_mode & 0o777:o}); run: chmod {fix} {path}"
            )
        if not folder and st.st_size > MAX_FILE_BYTES:
            raise BlocklistError(
                f"{path} is bigger than {MAX_FILE_BYTES:,} bytes, the limit "
                f"for one list"
            )
    except BaseException:
        os.close(fd)
        raise
    return fd


class _SortedHashes:
    """Hashes kept in 256 arrays by their top byte, so the final sort never
    needs one Python list of every hash (that would cost ~45 bytes a name)."""

    def __init__(self) -> None:
        self._buckets: list[array[int]] = [array("Q") for _ in range(256)]
        self.count = 0

    def add(self, value: int) -> None:
        self._buckets[value >> 56].append(value)
        self.count += 1

    def build(self) -> array[int]:
        out: array[int] = array("Q")
        for i, bucket in enumerate(self._buckets):
            out.extend(sorted(set(bucket)))
            self._buckets[i] = array("Q")
        return out


class _Reader:
    """Reads list files into block and allow hashes, under the limits."""

    def __init__(self, key: bytes) -> None:
        self._key = key
        self._block = _SortedHashes()
        self._allow = _SortedHashes()
        self._files = 0
        self._skipped = 0

    def read(self, path: Path, dir_fd: int, *, allow_only: bool) -> None:
        """Add one file's names. A missing file adds nothing.

        Raises:
            BlocklistError: the file is refused or breaks a limit.
        """
        try:
            fd = _open_checked(path, dir_fd, folder=False)
        except FileNotFoundError:
            return
        self._files += 1
        total = 0
        # True while reading the rest of a line longer than _MAX_LINE_BYTES.
        # Such a line is skipped whole: a cut piece must never be parsed, since
        # its tail could look like a name the list never held.
        in_long_line = False
        # Fewer, larger reads let the event loop run during a load.
        with os.fdopen(fd, "rb", buffering=1 << 20) as f:
            while line := f.readline(_MAX_LINE_BYTES):
                cut = len(line) == _MAX_LINE_BYTES and not line.endswith(b"\n")
                if total == 0:
                    line = line.removeprefix(_BOM)
                total += len(line)
                if total > MAX_FILE_BYTES:
                    raise BlocklistError(
                        f"{path} is bigger than {MAX_FILE_BYTES:,} bytes, the "
                        f"limit for one list"
                    )
                if in_long_line or cut:
                    if not in_long_line:
                        self._skipped += 1
                    in_long_line = cut
                    continue
                parsed = parse_line(line)
                self._skipped += parsed.skipped
                target = self._allow if allow_only or parsed.exception else self._block
                for name in parsed.names:
                    target.add(name_hash(name, self._key))
                if self._block.count + self._allow.count > MAX_NAMES:
                    raise BlocklistError(
                        f"{path} takes the lists over {MAX_NAMES:,} names, the "
                        f"limit; remove a list"
                    )

    def read_block_folder(self, block_dir: Path, dns_fd: int) -> None:
        """Read every ``*.txt`` in ``block_dir`` that does not start with a dot."""
        try:
            block_fd = _open_checked(block_dir, dns_fd, folder=True)
        except FileNotFoundError:
            return
        try:
            for entry in sorted(os.listdir(block_fd)):
                if not entry.startswith(".") and entry.endswith(LIST_SUFFIX):
                    self.read(block_dir / entry, block_fd, allow_only=False)
        finally:
            os.close(block_fd)

    def finish(self) -> LoadedLists:
        return LoadedLists(
            self._block.build(), self._allow.build(), self._files, self._skipped
        )


def load_lists(dns_dir: Path, key: bytes) -> LoadedLists:
    """Read ``allow.txt`` and every ``block/*.txt`` under ``dns_dir``.

    Runs in a worker thread. A missing folder or file means no names, not an
    error.

    Raises:
        BlocklistError: a file or folder is refused or a limit is broken.
            Nothing is returned, so the caller keeps the lists it has.
    """
    reader = _Reader(key)
    try:
        dns_fd = _open_checked(dns_dir, None, folder=True)
    except FileNotFoundError:
        return reader.finish()
    try:
        reader.read(dns_dir / ALLOW_FILE, dns_fd, allow_only=True)
        reader.read_block_folder(dns_dir / BLOCK_DIR, dns_fd)
    finally:
        os.close(dns_fd)
    return reader.finish()


def list_signature(dns_dir: Path) -> Signature:
    """A cheap look at the list files, without reading them.

    It changes when a list is added, removed, replaced or edited, or when a
    file's owner or mode changes (so fixing a refused file loads it).
    """
    block_dir = dns_dir / BLOCK_DIR
    paths = [dns_dir, dns_dir / ALLOW_FILE, block_dir]
    try:
        entries = os.listdir(block_dir)
    except OSError:
        entries = []
    paths += [
        block_dir / e
        for e in sorted(entries)
        if not e.startswith(".") and e.endswith(LIST_SUFFIX)
    ]
    out: list[tuple[str | int, ...]] = []
    for path in paths:
        try:
            st = os.stat(path, follow_symlinks=False)
        except OSError:
            out.append((str(path),))
            continue
        out.append(
            (
                str(path),
                st.st_ino,
                st.st_size,
                st.st_mtime_ns,
                st.st_ctime_ns,
                st.st_mode,
                st.st_uid,
            )
        )
    return tuple(out)


def _contains(table: array[int], value: int) -> bool:
    i = bisect_left(table, value)
    return i < len(table) and table[i] == value


def _name_and_parents(name: bytes) -> list[bytes]:
    """``a.b.com`` gives ``a.b.com`` and ``b.com``: list names have 2+ labels."""
    out: list[bytes] = []
    while b"." in name:
        out.append(name)
        name = name.partition(b".")[2]
    return out


class DnsBlocklist:
    """The lists in use, the change check, and the blocked-query count.

    Only ``list_signature`` and ``load_lists`` run in a worker thread; new
    lists are swapped in on the event loop thread, so no state is shared
    between threads.
    """

    def __init__(self, dns_dir: Path) -> None:
        self._dns_dir = dns_dir
        # New on every run and never logged or saved: without it a stored
        # hash cannot be checked against a guessed name.
        self._key = secrets.token_bytes(16)
        self._lists = _no_lists()
        self._signature: Signature | None = None
        self._blocked = 0
        self._task: asyncio.Task[None] | None = None

    def is_blocked(self, qname: str) -> bool:
        """True if ``qname`` (any case, trailing dot or not) gets NXDOMAIN.

        The canary always does. Otherwise a name is blocked when it or a
        parent is on a block list and neither it nor a parent is allowed.
        """
        name = qname.lower().rstrip(".")
        # First, so neither allow.txt nor an `@@||name^` line can turn it off.
        if name == CANARY or name.endswith(_CANARY_SUFFIX):
            self._blocked += 1
            return True
        lists = self._lists
        if not lists.block:
            return False
        hashes = [
            name_hash(n, self._key)
            for n in _name_and_parents(name.encode("ascii", "replace"))
        ]
        if any(_contains(lists.allow, h) for h in hashes):
            return False
        if any(_contains(lists.block, h) for h in hashes):
            self._blocked += 1
            return True
        return False

    async def refresh(self) -> None:
        """Load the lists again if the files changed since the last try.

        A refused load keeps the lists in use and warns once; it is not
        tried again until the files change.
        """
        signature = await asyncio.to_thread(list_signature, self._dns_dir)
        if signature == self._signature:
            return
        self._signature = signature
        try:
            lists = await asyncio.to_thread(load_lists, self._dns_dir, self._key)
        except (BlocklistError, OSError) as e:
            # A BlocklistError says which file and how to fix it. For a disk
            # error (EIO and the like) log only the reason: str(e) adds a path.
            reason = str(e) if isinstance(e, BlocklistError) else e.strerror
            log.warning(
                "DNS blocklist not loaded: %s. The lists already in use stay.", reason
            )
            return
        self._lists = lists
        log.info(
            "DNS blocklist loaded: %s names to block, %s allowed (files read: %d, "
            "lines skipped: %s)",
            f"{len(lists.block):,}",
            f"{len(lists.allow):,}",
            lists.files,
            f"{lists.skipped:,}",
        )
        if not lists.block:
            log.warning(
                "DNS blocklist is on but has no names to block; put lists in %s "
                "(deploy/GUIDE.md §7h)",
                self._dns_dir / BLOCK_DIR,
            )

    def log_blocked_count(self) -> None:
        """Log how many queries were blocked since the last call, if any."""
        if self._blocked:
            log.info(
                "DNS blocklist: queries blocked in the last hour: %s",
                f"{self._blocked:,}",
            )
            self._blocked = 0

    async def run(
        self, *, sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
    ) -> None:
        """Load now, then check for changes every 5 minutes; count hourly."""
        checks = 0
        try:
            while True:
                await self.refresh()
                await sleep(CHECK_INTERVAL_S)
                checks += 1
                if checks % REPORT_EVERY_CHECKS == 0:
                    self.log_blocked_count()
        # refresh() handles refused lists; this is for a bug. Report it once
        # and end, keeping the lists in use. Cancellation is not an Exception.
        except Exception as e:  # noqa: BLE001
            log.error(
                "DNS blocklist: list checks stopped (%s); the lists in use stay "
                "until dsm restarts",
                type(e).__name__,
            )

    def start(self) -> None:
        """Start ``run`` as a task on the running loop; does nothing if it runs."""
        if self._task is not None and not self._task.done():
            return
        self._task = asyncio.create_task(self.run())

    async def stop(self) -> None:
        """Cancel the task and wait for it to end."""
        # Cleared first, so a second stop() during the wait does nothing.
        task, self._task = self._task, None
        if task is None:
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            # The task ending is expected. A cancel aimed at our caller is not
            # ours to swallow.
            current = asyncio.current_task()
            if current is not None and current.cancelling():
                raise
