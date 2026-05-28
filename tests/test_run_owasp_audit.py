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

    def test_generate_only_returns_nonzero_when_manifest_generation_fails_after_gate_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            blocked_manifest = Path(tmp) / "reports" / "evidence-manifest.json"
            blocked_manifest.mkdir(parents=True)
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
                    "0",
                ],
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("evidence-manifest generation failed", result.stderr)

    def test_threshold_values_are_decimal_and_range_checked(self) -> None:
        cases = [("000", 0), ("08", 1), ("09", 1), ("100", 1), ("101", 1)]
        for threshold, expected_rc in cases:
            with self.subTest(threshold=threshold), tempfile.TemporaryDirectory() as tmp:
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
                        threshold,
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )

            self.assertEqual(result.returncode, expected_rc)
            self.assertNotIn("value too great for base", result.stderr)

    def test_header_labels_threshold_not_measured_coverage(self) -> None:
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
                    "0",
                ],
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0)
        self.assertIn("Coverage threshold : 0%", result.stdout)
        self.assertNotIn("Coverage : 0%", result.stdout)


if __name__ == "__main__":
    unittest.main()
