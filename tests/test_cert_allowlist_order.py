"""CNAllowlist.order (multi-client spec §2.3): the file's order, each CN once
at its first line, so the n-th CN gets the n-th tunnel address."""

from __future__ import annotations

from pathlib import Path

from dsm.crypto.cert_allowlist import CNAllowlist


def _load(tmp_path: Path, text: str) -> CNAllowlist:
    path = tmp_path / "allowlist.txt"
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)
    return CNAllowlist.from_file(path)


def test_the_order_follows_the_file(tmp_path: Path) -> None:
    allowlist = _load(tmp_path, "dsm-c-client\ndsm-a-client\ndsm-b-client\n")
    assert allowlist.order == ("dsm-c-client", "dsm-a-client", "dsm-b-client")


def test_the_order_skips_comments_blank_lines_and_repeats(tmp_path: Path) -> None:
    allowlist = _load(
        tmp_path,
        "# devices\n"
        "\n"
        "dsm-b-client\n"
        "  \n"
        "dsm-a-client\n"
        "# a repeat keeps its first line\n"
        "dsm-b-client\n"
        "  dsm-c-client  \n",
    )
    assert allowlist.order == ("dsm-b-client", "dsm-a-client", "dsm-c-client")
    assert allowlist.cns == frozenset(allowlist.order)


def test_an_empty_file_has_no_order(tmp_path: Path) -> None:
    assert _load(tmp_path, "# nobody yet\n").order == ()


def test_built_directly_the_order_is_sorted() -> None:
    allowlist = CNAllowlist(
        cns=frozenset({"dsm-c-client", "dsm-a-client", "dsm-b-client"})
    )
    assert allowlist.order == ("dsm-a-client", "dsm-b-client", "dsm-c-client")
