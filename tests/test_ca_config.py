"""The offline CA settings DSM depends on (deploy/openssl-ca.cnf)."""

from __future__ import annotations

import re
from pathlib import Path

CNF = Path(__file__).resolve().parent.parent / "deploy" / "openssl-ca.cnf"


def test_a_new_crl_outlives_the_certs_by_a_month() -> None:
    # A CRL reaches a host only when someone carries it there, so a short
    # life adds outages, not safety (D33). A cert runs out a month before
    # the CRL made with it, so the two never run out on the same day.
    text = CNF.read_text()
    assert re.search(r"^default_crl_days\s*=\s*395\s*$", text, re.M)
    assert re.search(r"^default_days\s*=\s*365\s*$", text, re.M)
