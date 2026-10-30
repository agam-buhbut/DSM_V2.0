"""apply_configured_tcti: the config's TCTI wins over the environment."""

from __future__ import annotations

import os
from unittest.mock import patch

from dsm.crypto.tpm_preflight import apply_configured_tcti

_TCTI = "swtpm:host=127.0.0.1,port=2321"


def test_a_set_tcti_replaces_both_env_vars() -> None:
    with patch.dict(
        os.environ, {"TPM2TOOLS_TCTI": "device:/dev/tpm0", "TCTI": "mssim:"}
    ):
        apply_configured_tcti(_TCTI)
        assert (os.environ["TPM2TOOLS_TCTI"], os.environ["TCTI"]) == (_TCTI, _TCTI)


def test_no_tcti_leaves_the_env_alone() -> None:
    with patch.dict(os.environ, {"TCTI": "mssim:"}):
        os.environ.pop("TPM2TOOLS_TCTI", None)
        apply_configured_tcti(None)
        assert os.environ.get("TPM2TOOLS_TCTI") is None
        assert os.environ["TCTI"] == "mssim:"
