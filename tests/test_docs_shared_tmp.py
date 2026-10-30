"""The docs never let another local user choose what root runs or installs
(review #56). /tmp is shared: anyone on the host can make a name there
before you do. Python started with -c or -m imports from the current folder
first, and so does Python reading its program from stdin (`python3 -`), so
root's Python in the docs always gets -I. Text checks on the docs, as the
unit and install.sh tests do."""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
DOCS = ("README.md", "deploy/GUIDE.md", "CONTRIBUTING.md", "PENTEST.md", "SECURITY.md")
# Not PENTEST.md: its captures come from tcpdump, which drops to its own user
# and could not write into a private folder in your home.
NO_TMP_DOCS = ("README.md", "deploy/GUIDE.md", "CONTRIBUTING.md")

# `sudo [/usr/bin/]python3 [flags] -c|-m|-`: group 1 holds the flags before it.
_ROOT_PYTHON = re.compile(
    r"\bsudo\s+(?:\S*/)?python3(?:\.\d+)?((?:\s+-[A-Za-z]+)*?)"
    r"\s+-(?:[cm]\b|(?=\s|$))"
)
_CD_TMP = re.compile(r"\bcd\s+/tmp\b")


def _hits(doc: str, found: Callable[[str], bool]) -> list[str]:
    lines = (REPO / doc).read_text().splitlines()
    return [
        f"{doc}:{n}: {line.strip()}" for n, line in enumerate(lines, 1) if found(line)
    ]


def _python_without_i(line: str) -> bool:
    return any("-I" not in m.group(1).split() for m in _ROOT_PYTHON.finditer(line))


@pytest.mark.parametrize("doc", DOCS)
def test_root_python_ignores_the_current_folder(doc: str) -> None:
    bad = _hits(doc, _python_without_i)
    assert not bad, "\n".join(bad)


@pytest.mark.parametrize("doc", DOCS)
def test_no_step_goes_into_tmp(doc: str) -> None:
    bad = _hits(doc, lambda line: _CD_TMP.search(line) is not None)
    assert not bad, "\n".join(bad)


@pytest.mark.parametrize("doc", NO_TMP_DOCS)
def test_no_fixed_name_under_tmp(doc: str) -> None:
    bad = _hits(doc, lambda line: "/tmp/" in line)
    assert not bad, "\n".join(bad)
