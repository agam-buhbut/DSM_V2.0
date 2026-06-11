"""Phase 1.12: the shipped example config loads after the operator fills the
two required secrets (ca_root_sha256 + a CRL decision), and documents every
Config field.
"""

from __future__ import annotations

import os
import re
import tempfile
import unittest
from dataclasses import fields
from pathlib import Path

from dsm.core.config import Config, load

REPO_ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = REPO_ROOT / "config.example.toml"


class ExampleConfigBoots(unittest.TestCase):
    def test_example_loads_with_minimal_secrets_filled(self) -> None:
        text = EXAMPLE.read_text()
        # Fill the all-zeros pin placeholder with a real 64-hex value and set
        # crl_strict=false (the documented dev escape hatch) so a no-CRL copy
        # loads. Both substitutions are documented in the example itself.
        text = text.replace("0" * 64, "ab" * 32)
        if "crl_strict" not in text:
            self.fail("example must document crl_strict")
        text = re.sub(r"#\s*crl_strict\s*=.*", "crl_strict = false", text)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "config.toml"
            p.write_text(text)
            os.chmod(p, 0o600)
            cfg = load(p)
        self.assertEqual(cfg.jitter_ms_max, 100)

    def test_example_documents_every_field(self) -> None:
        text = EXAMPLE.read_text()
        # Every Config field name should appear somewhere in the example
        # (commented or active), except the internal-only config_dir.
        for f in fields(Config):
            if f.name == "config_dir":
                continue
            self.assertIn(f.name, text, f"example must mention config field {f.name!r}")


if __name__ == "__main__":
    unittest.main()
