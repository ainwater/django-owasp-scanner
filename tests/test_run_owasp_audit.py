from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "audit-kit" / "scripts" / "run_owasp_audit.sh"


class RunOwaspAuditTest(unittest.TestCase):
    def test_generate_only_returns_one_when_coverage_gate_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [
                    "bash",
                    str(RUNNER),
                    "--project",
                    str(ROOT),
                    "--product",
                    "Test",
                    "--output",
                    tmp,
                    "--generate-only",
                    "--skip-dd-import",
                    "--coverage-threshold",
                    "1",
                ],
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 1)
        self.assertIn("Coverage gates: fail", result.stderr)


if __name__ == "__main__":
    unittest.main()
