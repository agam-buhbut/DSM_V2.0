"""Structural security tests for the root-run ``install.sh`` bootstrap.

These tests do NOT execute ``install.sh`` (it is a ``curl | sudo sh``
root/network installer). They parse the script text and assert on its
*structure*, mirroring the read-the-source-and-assert convention used in
``tests/test_cli.py``.

The load-bearing property is **verify-before-execute**: the minisign
signature check and the ``sha256sum -c`` checksum check on the downloaded
artifact MUST occur — as real command invocations — at earlier line numbers
than the first thing that installs/executes downloaded content (the
``apt-get install`` of runtime deps, the venv creation, or the ``pip
install`` of the wheel). The ordering test parses the actual command lines
(ignoring comments and strings inside other tokens), so reordering an
install above verification — or satisfying the check with a mere comment —
makes the test FAIL.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_INSTALL_SH = _REPO_ROOT / "install.sh"


def _read_lines() -> list[str]:
    return _INSTALL_SH.read_text(encoding="utf-8").splitlines()


def _strip_comment(line: str) -> str:
    """Return the code portion of a line with any ``#`` comment removed.

    Conservative: a ``#`` only starts a comment when it is at the start of
    the (stripped) line or preceded by whitespace. This avoids mistaking a
    ``#`` inside a value for a comment while still discarding real comments
    (which is what makes the ordering assertion robust against a commented
    mention of "minisign"/"sha256sum" satisfying it).
    """
    stripped = line.lstrip()
    if stripped.startswith("#"):
        return ""
    # Remove a trailing " # comment" (whitespace-preceded hash).
    return re.sub(r"\s#.*$", "", line)


def _code_lines() -> list[tuple[int, str]]:
    """1-based (lineno, code) for non-blank logical command lines.

    Comments are stripped, then backslash-continued physical lines are joined
    into a single logical line so that a command split across multiple
    physical lines (and its trailing ``|| die``) is matched as one unit. The
    reported line number is that of the FIRST physical line of the logical
    command — which is what the verify-before-execute ordering check needs.
    """
    out: list[tuple[int, str]] = []
    pending_lineno: int | None = None
    pending_parts: list[str] = []
    for idx, raw in enumerate(_read_lines(), start=1):
        code = _strip_comment(raw)
        if not code.strip() and pending_lineno is None:
            continue
        if pending_lineno is None:
            pending_lineno = idx
        if code.rstrip().endswith("\\"):
            pending_parts.append(code.rstrip()[:-1])
            continue
        pending_parts.append(code)
        joined = " ".join(p.strip() for p in pending_parts if p.strip())
        if joined.strip():
            out.append((pending_lineno, joined))
        pending_lineno = None
        pending_parts = []
    if pending_lineno is not None and pending_parts:
        joined = " ".join(p.strip() for p in pending_parts if p.strip())
        if joined.strip():
            out.append((pending_lineno, joined))
    return out


def _first_lineno(pattern: str) -> int | None:
    """Lowest line number whose *code* (comments stripped) matches ``pattern``.

    Returns ``None`` if no code line matches.
    """
    rx = re.compile(pattern)
    for lineno, code in _code_lines():
        if rx.search(code):
            return lineno
    return None


class TestVerifyBeforeExecuteOrdering(unittest.TestCase):
    """The verification commands must run before any install of downloaded
    content. Asserted on real command invocations, by line number."""

    def setUp(self) -> None:
        self.assertTrue(_INSTALL_SH.is_file(), f"missing {_INSTALL_SH}")

        # Verification command invocations (actual commands, not comments).
        # minisign signature verification: `minisign -V ...`
        self.minisign_verify_ln = _first_lineno(r"\bminisign\s+-V\b")
        # checksum verification: `sha256sum -c ...`
        self.sha256_check_ln = _first_lineno(r"\bsha256sum\s+-c\b")

        # Install / execute-downloaded-content invocations.
        # First runtime-dep apt-get install. The verifier (minisign) is the
        # ONLY apt-get install permitted before verification; exclude it so a
        # legitimate pre-verify `apt-get install -y minisign` does not trip
        # the ordering check, while any OTHER apt-get install must come after.
        self.apt_runtime_ln = self._first_runtime_apt_install()
        # venv creation: `python3 -m venv`
        self.venv_ln = _first_lineno(r"python3\s+-m\s+venv\b")
        # wheel install: `pip install ... .whl` (the verified artifact)
        self.pip_wheel_ln = _first_lineno(r"pip['\"]?\s+install\b")

    @staticmethod
    def _first_runtime_apt_install() -> int | None:
        rx = re.compile(r"\bapt-get\s+install\b")
        minisign_rx = re.compile(r"\bminisign\b")
        for lineno, code in _code_lines():
            if rx.search(code) and not minisign_rx.search(code):
                return lineno
        return None

    def test_verification_commands_exist(self) -> None:
        self.assertIsNotNone(
            self.minisign_verify_ln,
            "no `minisign -V` invocation found — signature verification absent",
        )
        self.assertIsNotNone(
            self.sha256_check_ln,
            "no `sha256sum -c` invocation found — checksum verification absent",
        )

    def test_install_commands_exist(self) -> None:
        self.assertIsNotNone(self.apt_runtime_ln, "no runtime `apt-get install` found")
        self.assertIsNotNone(self.venv_ln, "no `python3 -m venv` found")
        self.assertIsNotNone(self.pip_wheel_ln, "no `pip install` found")

    def test_minisign_verify_precedes_all_installs(self) -> None:
        assert self.minisign_verify_ln is not None
        for label, ln in (
            ("runtime apt-get install", self.apt_runtime_ln),
            ("venv creation", self.venv_ln),
            ("pip wheel install", self.pip_wheel_ln),
        ):
            assert ln is not None, label
            self.assertLess(
                self.minisign_verify_ln,
                ln,
                f"`minisign -V` (line {self.minisign_verify_ln}) must precede "
                f"{label} (line {ln}) — verify-before-execute violated",
            )

    def test_sha256_check_precedes_all_installs(self) -> None:
        assert self.sha256_check_ln is not None
        for label, ln in (
            ("runtime apt-get install", self.apt_runtime_ln),
            ("venv creation", self.venv_ln),
            ("pip wheel install", self.pip_wheel_ln),
        ):
            assert ln is not None, label
            self.assertLess(
                self.sha256_check_ln,
                ln,
                f"`sha256sum -c` (line {self.sha256_check_ln}) must precede "
                f"{label} (line {ln}) — verify-before-execute violated",
            )

    def test_wheel_download_precedes_checksum_precedes_install(self) -> None:
        """The wheel is downloaded, THEN checksum-verified, THEN installed —
        and the verified file is the same temp file (no re-download)."""
        wheel_dl_ln = _first_lineno(r'curl\b.*"\$BASE/\$WHEEL"')
        self.assertIsNotNone(wheel_dl_ln, "no `curl ... $BASE/$WHEEL` download")
        assert wheel_dl_ln is not None
        assert self.sha256_check_ln is not None
        assert self.pip_wheel_ln is not None
        self.assertLess(
            wheel_dl_ln,
            self.sha256_check_ln,
            "wheel must be downloaded before its checksum is checked",
        )
        self.assertLess(
            self.sha256_check_ln,
            self.pip_wheel_ln,
            "wheel checksum must be checked before the wheel is installed",
        )

    def test_only_minisign_apt_install_before_verification(self) -> None:
        """Every `apt-get install` before the minisign signature check must be
        the verifier itself — nothing else may be installed pre-verification."""
        assert self.minisign_verify_ln is not None
        rx = re.compile(r"\bapt-get\s+install\b")
        minisign_rx = re.compile(r"\bminisign\b")
        for lineno, code in _code_lines():
            if lineno >= self.minisign_verify_ln:
                break
            if rx.search(code):
                self.assertTrue(
                    minisign_rx.search(code),
                    f"line {lineno}: an `apt-get install` other than minisign "
                    "runs BEFORE signature verification — "
                    f"verify-before-execute violated: {code.strip()!r}",
                )


class TestFailClosed(unittest.TestCase):
    def setUp(self) -> None:
        self.text = _INSTALL_SH.read_text(encoding="utf-8")
        self.code = "\n".join(c for _, c in _code_lines())

    def test_set_eu_present(self) -> None:
        # `set -eu` (or a superset like -euo pipefail) on its own code line.
        self.assertRegex(
            self.code,
            r"(?m)^\s*set\s+-[A-Za-z]*e[A-Za-z]*u[A-Za-z]*\b"
            r"|^\s*set\s+-[A-Za-z]*u[A-Za-z]*e[A-Za-z]*\b",
            "install.sh must `set -eu` (fail-closed) near the top",
        )

    def test_minisign_verify_aborts_on_failure(self) -> None:
        # The minisign verify line must abort (|| die / || exit) on failure,
        # not be left to a swallowing pipe.
        for _, code in _code_lines():
            if re.search(r"\bminisign\s+-V\b", code):
                self.assertRegex(
                    code,
                    r"\|\|\s*(die|exit)\b",
                    "minisign verification must `|| die` on failure",
                )
                self.assertNotRegex(
                    code,
                    r"\bminisign\s+-V\b[^|]*\|[^|]",
                    "minisign verify result must not be piped into another "
                    "command (which could swallow its exit code)",
                )
                return
        self.fail("no `minisign -V` line found")

    def test_checksum_check_aborts_on_failure(self) -> None:
        for _, code in _code_lines():
            if re.search(r"\bsha256sum\s+-c\b", code):
                self.assertRegex(
                    code,
                    r"\|\|\s*(die|exit)\b",
                    "checksum check must `|| die` on failure",
                )
                return
        self.fail("no `sha256sum -c` line found")

    def test_checksum_not_fed_by_a_swallowing_pipe(self) -> None:
        """A `grep ... | sha256sum -c -` pipe hides grep's miss (the entry
        being absent) behind sha256sum's empty-input exit, which is
        implementation-dependent. The hardened script must not do that."""
        for _, code in _code_lines():
            self.assertNotRegex(
                code,
                r"\|\s*sha256sum\s+-c\b",
                "checksum must not be verified via a pipe into `sha256sum -c` "
                "(grep's failure to find the entry would be swallowed)",
            )

    def test_downloads_use_failing_https_curl(self) -> None:
        """Every curl invocation downloading release content must fail-fast on
        HTTP errors (-f) and not weaken TLS (no --insecure / -k)."""
        found_curl = False
        for _, code in _code_lines():
            if re.search(r"\bcurl\b", code):
                found_curl = True
                # -f may be standalone (-f) or bundled in a short-flag cluster
                # (e.g. -fsSL); also accept the long form --fail.
                self.assertRegex(
                    code,
                    r"\bcurl\b.*(?:\s-[A-Za-z]*f[A-Za-z]*\b|--fail\b)",
                    f"curl must use --fail/-f to abort on HTTP errors: {code!r}",
                )
                self.assertNotRegex(
                    code,
                    r"--insecure|\s-k\b",
                    f"curl must not disable TLS verification: {code!r}",
                )
        self.assertTrue(found_curl, "expected at least one curl download")

    def test_no_plain_http_release_urls(self) -> None:
        self.assertNotRegex(
            self.text,
            r"http://",
            "release URLs must be https (no plaintext http://)",
        )


class TestArgParsing(unittest.TestCase):
    def setUp(self) -> None:
        self.code = "\n".join(c for _, c in _code_lines())

    def test_uses_while_arg_loop(self) -> None:
        self.assertRegex(
            self.code,
            r"while\s+\[\s+\"?\$#\"?\s+-gt\s+0\s+\]",
            "args must be parsed with a `while [ $# -gt 0 ]` loop "
            "(not positional $1/$2)",
        )

    def test_rejects_unknown_flags(self) -> None:
        # A catch-all case arm that dies on unknown args.
        self.assertRegex(
            self.code,
            r"\*\)\s*die\b|\*\)[^)]*\bdie\b",
            "arg loop must reject unknown flags (a `*) die` catch-all arm)",
        )

    def test_both_flags_handled_in_loop(self) -> None:
        for flag in ("--eval", "--systemd"):
            self.assertRegex(
                self.code,
                rf"{re.escape(flag)}\)\s",
                f"{flag} must be a recognised case arm in the arg loop",
            )

    def test_no_positional_systemd_dispatch(self) -> None:
        """The old loose dispatch read flags from $1/$2 directly; ensure that
        positional check for --systemd is gone."""
        self.assertNotRegex(
            self.code,
            r"\$\{?2:?-?\}?\"?\s*=\s*\"?--systemd",
            "must not dispatch --systemd off positional $2",
        )


class TestVersionPin(unittest.TestCase):
    def setUp(self) -> None:
        self.code = "\n".join(c for _, c in _code_lines())

    def test_pins_a_version(self) -> None:
        self.assertRegex(
            self.code,
            r'DSM_VERSION="\d+\.\d+\.\d+"',
            "script must pin DSM_VERSION (anti-rollback / version pin)",
        )

    def test_wheel_name_embeds_pinned_version(self) -> None:
        self.assertRegex(
            self.code,
            r'WHEEL="dsm-\$\{DSM_VERSION\}',
            "wheel filename must embed the pinned ${DSM_VERSION}",
        )

    def test_refuses_missing_signed_entry(self) -> None:
        """The signed SHA256SUMS must be required to contain an entry for the
        pinned wheel; absence must fail closed (anti-rollback)."""
        # An exact-field selection of the wheel's line, then a non-empty guard.
        self.assertRegex(
            self.code,
            r"awk\b.*\$2\s*==\s*w",
            "must select the wheel's checksum line by exact field match",
        )
        self.assertRegex(
            self.code,
            r'\[\s+-n\s+"\$EXPECTED_LINE"\s+\]\s*\\?\s*\n?\s*\|\|\s*die'
            r"|\[\s+-n\s+\"\$EXPECTED_LINE\"\s+\]",
            "must die when the signed list has no entry for the pinned wheel",
        )


class TestPlaceholdersAndHygiene(unittest.TestCase):
    def setUp(self) -> None:
        self.text = _INSTALL_SH.read_text(encoding="utf-8")

    def test_owner_placeholders_present(self) -> None:
        for token in ("<OWNER/REPO>", "TODO(owner)"):
            self.assertIn(
                token,
                self.text,
                f"owner placeholder {token!r} must remain literal until release",
            )

    def test_minisign_pubkey_is_a_placeholder(self) -> None:
        self.assertRegex(
            self.text,
            r'MINISIGN_PUBKEY="[^"]*PLACEHOLDER[^"]*"',
            "MINISIGN_PUBKEY must remain a literal placeholder until release",
        )

    def test_uses_mktemp_not_predictable_tmp(self) -> None:
        self.assertRegex(
            self.text,
            r'WORK="\$\(mktemp -d\)"',
            "downloads must go to a mktemp -d dir, not a predictable /tmp name",
        )

    def test_eval_banner_is_loud(self) -> None:
        # An unmissable evaluation-only banner must be emitted in --eval mode.
        self.assertRegex(
            self.text,
            r"(?i)EVALUATION ONLY|EVALUATION INSTALL",
            "the --eval path must print a loud evaluation-only banner",
        )

    def test_no_world_obvious_secret_echo(self) -> None:
        """The script must not echo the (future real) private key or a
        passphrase. It only ever handles the PUBLIC key; assert no `echo`/
        `printf` of anything named *private*/*passphrase*/*secret*."""
        for _, code in _code_lines():
            if re.search(r"\b(echo|printf)\b", code):
                self.assertNotRegex(
                    code,
                    r"(?i)private[_-]?key|passphrase|secret[_-]?key",
                    f"must not print secret material: {code!r}",
                )


if __name__ == "__main__":
    unittest.main()
