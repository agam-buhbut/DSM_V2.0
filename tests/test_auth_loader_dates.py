"""Date problems in the cert materials are their own error (R1).

A CRL past its next update, the CA cert outside its dates, and, for the
client only, this host's own cert outside its dates raise
AuthMaterialsTimeError: the client keeps its block and tries again on
these. Every other problem stays a plain AuthMaterialsError (exit 1, Q1).
A host whose clock is synchronized keeps going on a stale CRL, with a
WARNING (re-decision 4(i), client and server alike).
"""

from __future__ import annotations

import datetime
import secrets
import unittest
from unittest.mock import MagicMock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding

from dsm.core import preflight
from dsm.core.config import Config
from dsm.crypto.auth_loader import (
    AuthMaterialsError,
    AuthMaterialsTimeError,
    load_cert_materials,
)
from dsm.crypto.cert import CertChainError, CertExpiredError
from tests.cert_helpers import make_leaf_cert
from tests.test_auth_loader import _build_crl, _ec_p256_spki_der, _MaterialsFixture

DAY = datetime.timedelta(days=1)


def _numbered_crl(
    fx: _MaterialsFixture, number: int, next_update: datetime.datetime
) -> bytes:
    now = datetime.datetime.now(datetime.UTC)
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(fx.ca.certificate.subject)
        .last_update(now - 10 * DAY)
        .next_update(next_update)
        .add_extension(x509.CRLNumber(number), critical=False)
        .sign(private_key=fx.ca.private_key, algorithm=hashes.SHA384())
    )
    return crl.public_bytes(Encoding.DER)


class TestDateProblems(unittest.TestCase):
    def setUp(self) -> None:
        self.fx = _MaterialsFixture()
        self.addCleanup(self.fx.cleanup)
        self.now = datetime.datetime.now(datetime.UTC)
        self.config = self.fx.make_config(
            ca_root_sha256=self.fx.ca_sha256, crl_strict=False
        )

    def _own_cert(
        self, not_before: datetime.datetime, not_after: datetime.datetime
    ) -> None:
        leaf = make_leaf_cert(
            self.fx.ca,
            subject_cn="dsm-authloader-client",
            leaf_public_spki_der=_ec_p256_spki_der(),
            noise_static_pub=secrets.token_bytes(32),
            not_before=not_before,
            not_after=not_after,
        )
        self.fx._write_600(self.fx.cert_path, leaf.public_bytes(Encoding.PEM))

    def _stale(self) -> Config:
        der = _build_crl(
            self.fx.ca, this_update=self.now - 10 * DAY, next_update=self.now - DAY
        )
        return self.fx.make_config(
            ca_root_sha256=self.fx.ca_sha256,
            crl_file=str(self.fx.write_crl_600(der)),
            crl_strict=True,
        )

    def test_a_stale_crl_is_a_date_problem(self) -> None:
        with self.assertRaises(AuthMaterialsTimeError) as err:
            load_cert_materials(self._stale())
        self.assertIn("is past its next update", str(err.exception))
        # Carry a new CRL; do not turn the check off (QA M8).
        self.assertNotIn("crl_strict=false", str(err.exception))

    def test_a_synchronized_clock_keeps_going_on_a_stale_crl(self) -> None:
        with self.assertLogs("dsm", level="WARNING") as logs:
            materials = load_cert_materials(self._stale(), clock_synced=lambda: True)
        self.assertIsNotNone(materials.crl)
        self.assertTrue(
            any(
                "DSM uses it because the clock is synchronized" in m
                for m in logs.output
            )
        )

    def test_an_unsynchronized_clock_is_refused_a_stale_crl(self) -> None:
        with self.assertRaises(AuthMaterialsTimeError):
            load_cert_materials(self._stale(), clock_synced=lambda: False)

    def test_the_clock_is_asked_only_for_a_stale_crl(self) -> None:
        der = _build_crl(
            self.fx.ca, this_update=self.now - DAY, next_update=self.now + 30 * DAY
        )
        fresh = self.fx.make_config(
            ca_root_sha256=self.fx.ca_sha256,
            crl_file=str(self.fx.write_crl_600(der)),
            crl_strict=True,
        )
        clock = MagicMock(return_value=True)
        load_cert_materials(fresh, clock_synced=clock)
        clock.assert_not_called()

    def test_a_rolled_back_crl_is_refused_even_with_a_synchronized_clock(self) -> None:
        newer = self.fx.write_crl_600(
            _numbered_crl(self.fx, 2, self.now + 30 * DAY), name="new.crl"
        )
        load_cert_materials(
            self.fx.make_config(
                ca_root_sha256=self.fx.ca_sha256, crl_file=str(newer), crl_strict=True
            )
        )
        older = self.fx.write_crl_600(
            _numbered_crl(self.fx, 1, self.now - DAY), name="old.crl"
        )
        config = self.fx.make_config(
            ca_root_sha256=self.fx.ca_sha256, crl_file=str(older), crl_strict=True
        )
        with self.assertRaises(AuthMaterialsError) as err:
            load_cert_materials(config, clock_synced=lambda: True)
        self.assertNotIsInstance(err.exception, AuthMaterialsTimeError)

    def test_a_ca_outside_its_dates_is_a_date_problem(self) -> None:
        expired = CertExpiredError("CA root expired (not_after=2025-01-01T00:00:00)")
        with patch("dsm.crypto.auth_loader.load_ca_root", side_effect=expired):
            with self.assertRaises(AuthMaterialsTimeError):
                load_cert_materials(self.config)

    def test_a_ca_that_fails_its_checks_is_a_mistake(self) -> None:
        bad = CertChainError("CA root must have basicConstraints CA:TRUE")
        with patch("dsm.crypto.auth_loader.load_ca_root", side_effect=bad):
            with self.assertRaises(AuthMaterialsError) as err:
                load_cert_materials(self.config)
        self.assertNotIsInstance(err.exception, AuthMaterialsTimeError)

    def test_a_missing_crl_under_crl_strict_is_a_mistake(self) -> None:
        config = self.fx.make_config(ca_root_sha256=self.fx.ca_sha256, crl_strict=True)
        with self.assertRaises(AuthMaterialsError) as err:
            load_cert_materials(config, clock_synced=lambda: True)
        self.assertNotIsInstance(err.exception, AuthMaterialsTimeError)

    def test_the_client_refuses_its_own_cert_once_it_ran_out(self) -> None:
        self._own_cert(self.now - 10 * DAY, self.now - DAY)
        with self.assertRaises(AuthMaterialsTimeError) as err:
            load_cert_materials(self.config, check_own_dates=True)
        self.assertIn("this host's cert ran out on", str(err.exception))

    def test_the_client_refuses_its_own_cert_before_it_is_valid(self) -> None:
        self._own_cert(self.now + DAY, self.now + 30 * DAY)
        with self.assertRaises(AuthMaterialsTimeError) as err:
            load_cert_materials(self.config, check_own_dates=True)
        self.assertIn("is not valid before", str(err.exception))

    def test_a_good_own_cert_passes(self) -> None:
        load_cert_materials(self.config, check_own_dates=True)

    def test_the_server_still_starts_with_its_own_cert_run_out(self) -> None:
        # No check_own_dates: the server keeps today's behaviour.
        self._own_cert(self.now - 10 * DAY, self.now - DAY)
        load_cert_materials(self.config)

    def test_a_try_that_fails_on_a_date_logs_nothing(self) -> None:
        # The client tries these again and says the problem once itself, so
        # the loader must not add a line on each try.
        stale = self._stale()
        with self.assertNoLogs("dsm", level="INFO"):
            for _ in range(2):
                with self.assertRaises(AuthMaterialsTimeError):
                    load_cert_materials(stale, check_own_dates=True)
        # No crl_file and crl_strict=false: _load_crl would warn on each try.
        self._own_cert(self.now - 10 * DAY, self.now - DAY)
        with self.assertNoLogs("dsm", level="INFO"):
            for _ in range(2):
                with self.assertRaises(AuthMaterialsTimeError):
                    load_cert_materials(self.config, check_own_dates=True)


class TestNtpSynchronized(unittest.TestCase):
    def _run(self, stdout: str) -> bool | None:
        done = MagicMock(stdout=stdout)
        with patch.object(preflight.subprocess, "run", return_value=done):
            return preflight.ntp_synchronized()

    def test_yes_no_and_unknown(self) -> None:
        self.assertIs(self._run("yes\n"), True)
        self.assertIs(self._run("no\n"), False)
        self.assertIsNone(self._run(""))

    def test_no_timedatectl_is_unknown(self) -> None:
        with patch.object(preflight.subprocess, "run", side_effect=FileNotFoundError):
            self.assertIsNone(preflight.ntp_synchronized())

    def test_the_warning_comes_only_for_no(self) -> None:
        with patch.object(preflight, "ntp_synchronized", return_value=None):
            self.assertIsNone(preflight.check_clock_sync())
        with patch.object(preflight, "ntp_synchronized", return_value=False):
            self.assertIn("NOT NTP-synchronized", preflight.check_clock_sync() or "")


if __name__ == "__main__":
    unittest.main()
