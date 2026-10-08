"""Reading DNS block lists: line formats, file rules, limits, change check."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from dsm.net import dns_blocklist as bl_mod
from dsm.net.dns_blocklist import (
    BlocklistError,
    ParsedLine,
    list_signature,
    load_lists,
    name_hash,
    parse_line,
)

KEY = b"k" * 16


def _h(name: bytes) -> int:
    return name_hash(name, KEY)


def _write(path: Path, body: bytes) -> None:
    path.write_bytes(body)
    path.chmod(0o600)


def _dns_dir(
    tmp_path: Path, *, block: dict[str, bytes], allow: bytes | None = None
) -> Path:
    dns_dir = tmp_path / "dns"
    (dns_dir / "block").mkdir(parents=True)
    dns_dir.chmod(0o700)
    (dns_dir / "block").chmod(0o700)
    for name, body in block.items():
        _write(dns_dir / "block" / name, body)
    if allow is not None:
        _write(dns_dir / "allow.txt", allow)
    return dns_dir


@pytest.mark.parametrize(
    ("line", "want"),
    [
        (b"0.0.0.0 ads.example.com", ParsedLine((b"ads.example.com",), False, False)),
        (
            b"127.0.0.1 a.example.com b.example.com",
            ParsedLine((b"a.example.com", b"b.example.com"), False, False),
        ),
        (b":: ads.example.com", ParsedLine((b"ads.example.com",), False, False)),
        (b"ads.example.com", ParsedLine((b"ads.example.com",), False, False)),
        (b"ADS.Example.COM.", ParsedLine((b"ads.example.com",), False, False)),
        (b"||ads.example.com^", ParsedLine((b"ads.example.com",), False, False)),
        (b"@@||good.example.com^", ParsedLine((b"good.example.com",), True, False)),
        (
            b"0.0.0.0 ads.example.com # a tracker",
            ParsedLine((b"ads.example.com",), False, False),
        ),
        (b"ads.example.com\r\n", ParsedLine((b"ads.example.com",), False, False)),
        (
            b"0.0.0.0 ads.example.com localhost",
            ParsedLine((b"ads.example.com",), False, True),
        ),
        (b"# a comment", ParsedLine((), False, False)),
        (b"! an AdGuard comment", ParsedLine((), False, False)),
        (b"   ", ParsedLine((), False, False)),
    ],
)
def test_lines_that_give_names(line: bytes, want: ParsedLine) -> None:
    assert parse_line(line) == want


@pytest.mark.parametrize(
    "line",
    [
        b"||ads.example.com^$third-party",
        b"||*.ads.example.com^",
        b"/banner[0-9]+/",
        b"@@||good.example.com^$important",
        b"example.com##.ad-box",
        b"[Adblock Plus 2.0]",
        b"127.0.0.1 localhost",
        b"fe80::1%lo0 localhost",
        b"0.0.0.0 0.0.0.0",
        b"0.0.0.0",
        b"localhost",
        b"exa mple.com",
        b"caf\xc3\xa9.example.com",
        b"a" * 64 + b".com",
        b"0.0.0.0 " + b"a." * 130 + b"com",
    ],
)
def test_lines_that_are_skipped_and_counted(line: bytes) -> None:
    parsed = parse_line(line)
    assert parsed.names == ()
    assert parsed.skipped


def test_name_hash_is_eight_bytes_and_keyed() -> None:
    assert 0 <= _h(b"ads.example.com") < 2**64
    assert _h(b"ads.example.com") != name_hash(b"ads.example.com", b"x" * 16)


def test_reads_every_list_and_the_allowlist(tmp_path: Path) -> None:
    dns_dir = _dns_dir(
        tmp_path,
        block={
            "a.txt": b"0.0.0.0 ads.example.com\n||track.example.net^\n"
            b"@@||ok.example.net^\n",
            "b.txt": b"ads.example.com\nmalware.example.org\n",
        },
        allow=b"good.example.com\n||also-good.example.com^\n",
    )
    lists = load_lists(dns_dir, KEY)
    assert list(lists.block) == sorted(
        {_h(b"ads.example.com"), _h(b"track.example.net"), _h(b"malware.example.org")}
    )
    assert list(lists.allow) == sorted(
        {_h(b"ok.example.net"), _h(b"good.example.com"), _h(b"also-good.example.com")}
    )
    assert lists.files == 3
    assert lists.skipped == 0


def test_a_missing_folder_or_file_means_no_names(tmp_path: Path) -> None:
    nothing = load_lists(tmp_path / "dns", KEY)
    assert (len(nothing.block), len(nothing.allow), nothing.files) == (0, 0, 0)
    dns_dir = tmp_path / "only"
    dns_dir.mkdir(mode=0o700)
    empty = load_lists(dns_dir, KEY)
    assert (len(empty.block), len(empty.allow), empty.files) == (0, 0, 0)


def test_a_real_hosts_header_blocks_only_real_names(tmp_path: Path) -> None:
    # The top of StevenBlack/hosts, with a byte order mark and CRLF line ends.
    header = (
        b"\xef\xbb\xbf# Title: StevenBlack/hosts\r\n#\r\n"
        b"127.0.0.1 localhost\r\n127.0.0.1 localhost.localdomain\r\n"
        b"127.0.0.1 local\r\n255.255.255.255 broadcasthost\r\n::1 localhost\r\n"
        b"::1 ip6-localhost\r\n::1 ip6-loopback\r\nfe80::1%lo0 localhost\r\n"
        b"ff00::0 ip6-localnet\r\nff00::0 ip6-mcastprefix\r\nff02::1 ip6-allnodes\r\n"
        b"ff02::2 ip6-allrouters\r\nff02::3 ip6-allhosts\r\n0.0.0.0 0.0.0.0\r\n\r\n"
        b"# Custom host records are listed here.\r\n"
        b"0.0.0.0 ads.example.com # inline note\r\n"
    )
    lists = load_lists(_dns_dir(tmp_path, block={"hosts.txt": header}), KEY)
    assert list(lists.block) == sorted(
        {_h(b"localhost.localdomain"), _h(b"ads.example.com")}
    )
    assert lists.skipped == 13


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604])
def test_a_list_open_to_others_is_refused(tmp_path: Path, mode: int) -> None:
    dns_dir = _dns_dir(tmp_path, block={"a.txt": b"ads.example.com\n"})
    (dns_dir / "block" / "a.txt").chmod(mode)
    with pytest.raises(BlocklistError, match="chmod 600"):
        load_lists(dns_dir, KEY)


def test_an_allowlist_open_to_others_is_refused(tmp_path: Path) -> None:
    dns_dir = _dns_dir(tmp_path, block={}, allow=b"good.example.com\n")
    (dns_dir / "allow.txt").chmod(0o644)
    with pytest.raises(BlocklistError, match="allow.txt has group/world"):
        load_lists(dns_dir, KEY)


@pytest.mark.parametrize("folder", ["", "block"])
def test_a_folder_open_to_others_is_refused(tmp_path: Path, folder: str) -> None:
    dns_dir = _dns_dir(tmp_path, block={"a.txt": b"ads.example.com\n"})
    (dns_dir / folder).chmod(0o755)
    with pytest.raises(BlocklistError, match="chmod 700"):
        load_lists(dns_dir, KEY)


def test_a_list_owned_by_another_uid_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    dns_dir = _dns_dir(tmp_path, block={"a.txt": b"ads.example.com\n"})
    monkeypatch.setattr(os, "getuid", lambda: os.geteuid() + 1)
    with pytest.raises(BlocklistError, match="owned by uid"):
        load_lists(dns_dir, KEY)


def test_a_symlinked_list_is_refused(tmp_path: Path) -> None:
    dns_dir = _dns_dir(tmp_path, block={"a.txt": b"ads.example.com\n"})
    (dns_dir / "block" / "b.txt").symlink_to(dns_dir / "block" / "a.txt")
    with pytest.raises(BlocklistError, match="symlink"):
        load_lists(dns_dir, KEY)


def test_a_symlinked_dns_folder_is_refused(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    (tmp_path / "dns").symlink_to(real)
    with pytest.raises(BlocklistError, match="symlink"):
        load_lists(tmp_path / "dns", KEY)


def test_a_fifo_named_like_a_list_is_refused(tmp_path: Path) -> None:
    # Opened without waiting for a writer, so the worker thread cannot hang.
    dns_dir = _dns_dir(tmp_path, block={})
    os.mkfifo(dns_dir / "block" / "a.txt", 0o600)
    with pytest.raises(BlocklistError, match="not a regular file"):
        load_lists(dns_dir, KEY)


def test_a_folder_named_like_a_list_is_refused(tmp_path: Path) -> None:
    dns_dir = _dns_dir(tmp_path, block={})
    (dns_dir / "block" / "a.txt").mkdir(mode=0o700)
    with pytest.raises(BlocklistError, match="not a regular file"):
        load_lists(dns_dir, KEY)


def test_hidden_and_temp_files_are_ignored(tmp_path: Path) -> None:
    dns_dir = _dns_dir(tmp_path, block={"a.txt": b"ads.example.com\n"})
    for name in (".fetch.AbCd1234", ".old.txt", "notes.md"):
        path = dns_dir / "block" / name
        path.write_bytes(b"other.example.com\n")
        path.chmod(0o644)  # would be refused if it were read
    lists = load_lists(dns_dir, KEY)
    assert list(lists.block) == [_h(b"ads.example.com")]
    assert lists.files == 1


def test_a_list_over_the_size_limit_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bl_mod, "MAX_FILE_BYTES", 10)
    dns_dir = _dns_dir(tmp_path, block={"a.txt": b"0.0.0.0 ads.example.com\n"})
    with pytest.raises(BlocklistError, match="bigger than 10 bytes"):
        load_lists(dns_dir, KEY)


def test_lists_over_the_name_limit_are_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bl_mod, "MAX_NAMES", 2)
    dns_dir = _dns_dir(
        tmp_path, block={"a.txt": b"a.example.com\nb.example.com\nc.example.com\n"}
    )
    with pytest.raises(BlocklistError, match="over 2 names"):
        load_lists(dns_dir, KEY)


def test_a_very_long_line_is_read_in_pieces(tmp_path: Path) -> None:
    body = b"a" * 10_000 + b"\n0.0.0.0 ads.example.com\n"
    lists = load_lists(_dns_dir(tmp_path, block={"a.txt": body}), KEY)
    assert list(lists.block) == [_h(b"ads.example.com")]
    assert lists.skipped >= 1


def test_the_tail_of_a_long_comment_is_not_a_line(tmp_path: Path) -> None:
    body = b"# " + b"x" * 4094 + b"evil.example.com\n0.0.0.0 ads.example.com\n"
    lists = load_lists(_dns_dir(tmp_path, block={"a.txt": body}), KEY)
    assert list(lists.block) == [_h(b"ads.example.com")]
    assert lists.skipped == 1


def test_a_hosts_line_cut_by_the_read_size_blocks_none_of_its_names(
    tmp_path: Path,
) -> None:
    # The first 4096 bytes end in a whole, valid name that is really the start
    # of "shop.example.com.au".
    line = b"0.0.0.0" + b" " * 4073 + b"shop.example.com.au tail.example.org\n"
    assert line[:4096].endswith(b" shop.example.com")
    body = line + b"0.0.0.0 ads.example.com\n"
    lists = load_lists(_dns_dir(tmp_path, block={"a.txt": body}), KEY)
    assert list(lists.block) == [_h(b"ads.example.com")]
    assert lists.skipped == 1


def test_a_line_that_just_fits_the_read_size_is_still_read(tmp_path: Path) -> None:
    line = b"0.0.0.0" + b" " * 4073 + b"ads.example.com\n"
    assert len(line) == 4096
    lists = load_lists(_dns_dir(tmp_path, block={"a.txt": line}), KEY)
    assert list(lists.block) == [_h(b"ads.example.com")]
    assert lists.skipped == 0


def test_a_long_last_line_without_a_line_end_is_skipped(tmp_path: Path) -> None:
    body = b"0.0.0.0 ads.example.com\n" + b"y" * 5000
    lists = load_lists(_dns_dir(tmp_path, block={"a.txt": body}), KEY)
    assert list(lists.block) == [_h(b"ads.example.com")]
    assert lists.skipped == 1


def test_the_bytes_of_a_long_line_count_toward_the_size_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The size check at open passes; the file then grows by one long line
    # while it is read, as a download could. Only the running total sees it.
    monkeypatch.setattr(bl_mod, "MAX_FILE_BYTES", 5000)
    real_open = bl_mod._open_checked  # pylint: disable=protected-access

    def grow_after_open(path: Path, dir_fd: int | None, *, folder: bool) -> int:
        fd = real_open(path, dir_fd, folder=folder)
        if not folder:
            with path.open("ab") as f:
                f.write(b"# " + b"x" * 6000 + b"\n")
        return fd

    monkeypatch.setattr(bl_mod, "_open_checked", grow_after_open)
    dns_dir = _dns_dir(tmp_path, block={"a.txt": b"0.0.0.0 ads.example.com\n"})
    with pytest.raises(BlocklistError, match="bigger than 5,000 bytes"):
        load_lists(dns_dir, KEY)


def test_the_signature_changes_when_the_lists_change(tmp_path: Path) -> None:
    dns_dir = _dns_dir(tmp_path, block={"a.txt": b"ads.example.com\n"})
    seen = [list_signature(dns_dir)]
    assert list_signature(dns_dir) == seen[0]
    path = dns_dir / "block" / "a.txt"
    path.chmod(0o644)  # a fix of the mode must load the file again
    seen.append(list_signature(dns_dir))
    path.chmod(0o600)
    seen.append(list_signature(dns_dir))
    new = dns_dir / "block" / "new"
    _write(new, b"other.example.com\n")
    os.replace(new, path)  # how the download script swaps a list in
    seen.append(list_signature(dns_dir))
    _write(dns_dir / "block" / "b.txt", b"more.example.com\n")
    seen.append(list_signature(dns_dir))
    (dns_dir / "block" / "b.txt").unlink()
    seen.append(list_signature(dns_dir))
    assert all(a != b for a, b in zip(seen, seen[1:]))
