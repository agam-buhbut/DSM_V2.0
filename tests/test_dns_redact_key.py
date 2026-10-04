"""redact() tags a qname with a keyed hash, under a key that is new each run.

A plain SHA-256 of a name can be reversed by hashing a list of popular sites.
The tag is HMAC-SHA256 under a random 32-byte key made when dsm.net.dns is
first imported, so a log reader cannot check guesses against it, and the same
name gets a different tag after a restart.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import subprocess
import sys
from unittest.mock import patch

import dsm.net.dns as dns_mod
from dsm.net.dns import redact

_NAME = "example.com"
_TAG = re.compile(r"\Aqname-tag=[0-9a-f]{16}\Z")


def test_tag_is_hmac_sha256_of_the_name_under_the_process_key() -> None:
    expected = hmac.new(
        dns_mod._REDACT_KEY, _NAME.encode("utf-8"), hashlib.sha256
    ).hexdigest()[:16]

    assert redact(_NAME, False) == f"qname-tag={expected}"


def test_the_key_is_32_bytes() -> None:
    assert isinstance(dns_mod._REDACT_KEY, bytes)
    assert len(dns_mod._REDACT_KEY) == 32


def test_another_key_gives_another_tag() -> None:
    tag = redact(_NAME, False)

    with patch.object(dns_mod, "_REDACT_KEY", b"\x01" * 32):
        other = redact(_NAME, False)

    assert other != tag
    assert _TAG.match(other)


def test_debug_returns_the_plain_name() -> None:
    assert redact(_NAME, True) == _NAME


def test_a_name_that_cannot_be_encoded_is_still_tagged() -> None:
    # A lone surrogate cannot be encoded as UTF-8 strictly; redact() must not
    # raise from inside an error-logging path.
    assert _TAG.match(redact("bad\udc80name", False))


def test_two_runs_give_the_same_name_two_tags() -> None:
    code = "from dsm.net.dns import redact; print(redact('example.com', False))"

    def run() -> str:
        done = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            check=True,
            timeout=60,
        )
        return done.stdout.strip()

    first, second = run(), run()

    assert _TAG.match(first)
    assert _TAG.match(second)
    assert first != second
