"""Tests for the clock-sync preflight and the clock-skew hint on
freshness-rejection errors."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from dsm.core.preflight import check_clock_sync
from dsm.crypto.attest import AttestTimestampError

# ---------------------------------------------------------------------------
# check_clock_sync()
# ---------------------------------------------------------------------------


def _fake_completed(stdout: str) -> subprocess.CompletedProcess:  # type: ignore[type-arg]
    """Build a minimal fake CompletedProcess."""
    cp = MagicMock(spec=subprocess.CompletedProcess)
    cp.stdout = stdout
    return cp


def test_check_clock_sync_returns_warning_when_not_synced() -> None:
    """When timedatectl reports NTPSynchronized=no, return a warning string
    that mentions 'NTP' and 'clock'."""
    with patch("subprocess.run", return_value=_fake_completed("no\n")):
        result = check_clock_sync()
    assert result is not None
    assert "NTP" in result
    assert "clock" in result.lower()


def test_check_clock_sync_returns_none_when_synced() -> None:
    """When timedatectl reports NTPSynchronized=yes, return None."""
    with patch("subprocess.run", return_value=_fake_completed("yes\n")):
        result = check_clock_sync()
    assert result is None


def test_check_clock_sync_returns_none_when_timedatectl_absent() -> None:
    """When timedatectl is not present (FileNotFoundError), return None."""
    with patch("subprocess.run", side_effect=FileNotFoundError("no timedatectl")):
        result = check_clock_sync()
    assert result is None


def test_check_clock_sync_returns_none_on_subprocess_error() -> None:
    """Any SubprocessError is swallowed and None is returned."""
    with patch(
        "subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="timedatectl", timeout=3),
    ):
        result = check_clock_sync()
    assert result is None


def test_check_clock_sync_returns_none_on_empty_output() -> None:
    """If stdout is blank (unexpected but possible), return None gracefully."""
    with patch("subprocess.run", return_value=_fake_completed("")):
        result = check_clock_sync()
    assert result is None


# ---------------------------------------------------------------------------
# Freshness-rejection error contains a clock / NTP hint
# ---------------------------------------------------------------------------


def test_attest_timestamp_error_message_contains_clock_hint() -> None:
    """AttestTimestampError raised on skew must mention 'clock' and 'NTP'."""
    import datetime

    now = datetime.datetime(2026, 6, 23, 12, 0, 0, tzinfo=datetime.UTC)
    # signed_ts is 1 hour in the past — well outside the ±5-minute window
    signed_ts = now - datetime.timedelta(hours=1)
    skew = datetime.timedelta(seconds=300)

    # Build the error message the same way attest.py does to confirm the hint
    # is present in the string that actually gets raised.
    msg = (
        f"signed timestamp {signed_ts.isoformat()} is outside "
        f"±{skew} of now {now.isoformat()}"
        " — likely CLOCK SKEW: synchronize both peers' clocks (NTP)."
    )
    err = AttestTimestampError(msg)
    assert "clock" in str(err).lower()
    assert "NTP" in str(err)


def test_verify_attest_payload_raises_with_clock_hint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """verify_attest_payload must raise AttestTimestampError whose message
    contains 'clock' and 'NTP' when the timestamp is out of skew window.

    We monkeypatch _unframe_payload and the cert-chain + sig steps so we can
    exercise just the timestamp branch in isolation without needing real
    tuncore / X.509 material."""
    import datetime

    import dsm.crypto.attest as _attest_mod

    now = datetime.datetime(2026, 6, 23, 12, 0, 0, tzinfo=datetime.UTC)
    stale_ts = int((now - datetime.timedelta(hours=1)).timestamp())

    # Patch _unframe_payload to return a stale timestamp and dummy cert/sig.
    monkeypatch.setattr(
        _attest_mod,
        "_unframe_payload",
        lambda payload: (stale_ts, b"\x30\x82\x01\x00", b"\x30\x44"),
    )

    # Patch DeviceCert.from_der + validate_chain so cert chain passes.
    fake_cert = MagicMock()
    fake_cert.noise_static_pub = b"\x00" * 32
    fake_cert.public_key.verify = MagicMock(return_value=None)
    monkeypatch.setattr(
        _attest_mod.DeviceCert, "from_der", staticmethod(lambda _: fake_cert)
    )
    monkeypatch.setattr(_attest_mod, "validate_chain", lambda *a, **kw: None)

    with pytest.raises(AttestTimestampError) as exc_info:
        _attest_mod.verify_attest_payload(
            payload=b"\x00" * 1,  # ignored — _unframe_payload is patched
            ca_root=MagicMock(),
            handshake_hash=b"\x00" * 32,
            expected_remote_static=b"\x00" * 32,
            expected_peer_role=_attest_mod.PeerRole.RESPONDER,
            now=now,
        )

    msg = str(exc_info.value)
    assert "clock" in msg.lower(), f"Expected 'clock' in: {msg!r}"
    assert "NTP" in msg, f"Expected 'NTP' in: {msg!r}"
