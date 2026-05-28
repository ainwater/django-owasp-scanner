from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "audit-kit" / "scripts" / "coverage_gates.py"
SPEC = importlib.util.spec_from_file_location("coverage_gates", SCRIPT)
coverage_gates = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(coverage_gates)


def write(path: Path, content: str = "ok") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def model() -> dict:
    return {
        "version": "OWASP Top 10:2025",
        "categories": [
            {
                "id": "A01",
                "name": "Broken Access Control",
                "automated_evidence": [
                    {"id": "semgrep", "artifacts": ["F4/semgrep.json"], "required": True},
                    {"id": "zap", "artifacts": ["F6/zap.xml"], "required": False},
                ],
                "manual_evidence": [
                    {"id": "authz", "artifacts": ["F2/authz.yml", "F2/authz-results.json"], "required": True}
                ],
            },
            {
                "id": "A02",
                "name": "Security Misconfiguration",
                "automated_evidence": [
                    {"id": "check", "artifacts": ["status/django-check.status"], "required": True}
                ],
                "manual_evidence": [],
            },
        ],
    }


class CoverageGatesTest(unittest.TestCase):
    def test_category_fails_when_required_manual_evidence_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = Path(tmp)
            write(reports / "F4" / "semgrep.json")
            write(reports / "status" / "django-check.status")

            result = coverage_gates.evaluate(reports, model(), threshold=80)

        a01 = result["categories"][0]
        self.assertEqual(a01["id"], "A01")
        self.assertEqual(a01["status"], "fail")
        self.assertEqual(a01["required_present"], 1)
        self.assertEqual(a01["required_total"], 2)
        self.assertEqual(a01["coverage_percent"], 50)
        self.assertEqual(a01["missing_required"], ["authz"])
        self.assertEqual(result["gates"]["status"], "fail")

    def test_global_gate_passes_when_required_evidence_meets_threshold(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = Path(tmp)
            write(reports / "F4" / "semgrep.json")
            write(reports / "F2" / "authz.yml")
            write(reports / "F2" / "authz-results.json")
            write(reports / "status" / "django-check.status")

            result = coverage_gates.evaluate(reports, model(), threshold=100)

        self.assertEqual([category["status"] for category in result["categories"]], ["pass", "pass"])
        self.assertEqual(result["summary"]["required_present"], 3)
        self.assertEqual(result["summary"]["required_total"], 3)
        self.assertEqual(result["summary"]["coverage_percent"], 100)
        self.assertEqual(
            result["gates"],
            {
                "status": "pass",
                "threshold": 100,
                "coverage_percent": 100,
                "failed_categories": [],
            },
        )

    def test_threshold_allows_partial_required_coverage_when_configured(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = Path(tmp)
            write(reports / "F4" / "semgrep.json")
            write(reports / "status" / "django-check.status")

            result = coverage_gates.evaluate(reports, model(), threshold=50)

        self.assertEqual(result["categories"][0]["status"], "pass")
        self.assertEqual(result["categories"][0]["missing_required"], ["authz"])
        self.assertEqual(result["gates"]["status"], "pass")

    def test_optional_evidence_does_not_reduce_gate_score(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = Path(tmp)
            write(reports / "F4" / "semgrep.json")
            write(reports / "F2" / "authz.yml")
            write(reports / "F2" / "authz-results.json")
            write(reports / "status" / "django-check.status")

            result = coverage_gates.evaluate(reports, model(), threshold=100)

        a01_optional = result["categories"][0]["automated"][1]
        self.assertEqual(a01_optional["id"], "zap")
        self.assertEqual(a01_optional["status"], "optional_missing")
        self.assertEqual(result["gates"]["status"], "pass")

    def test_threshold_must_be_between_zero_and_one_hundred(self) -> None:
        with self.assertRaisesRegex(ValueError, "between 0 and 100"):
            coverage_gates.parse_threshold("101")

        with self.assertRaisesRegex(ValueError, "integer"):
            coverage_gates.parse_threshold("high")

    def test_cli_exits_nonzero_when_gate_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = Path(tmp)
            write(reports / "metadata.json")

            result = subprocess.run(
                ["python3", str(SCRIPT), str(reports), "80"],
                capture_output=True,
                text=True,
                check=False,
            )

            gates = json.loads((reports / "gates.json").read_text())

        self.assertEqual(result.returncode, 1)
        self.assertEqual(gates["status"], "fail")


if __name__ == "__main__":
    unittest.main()
