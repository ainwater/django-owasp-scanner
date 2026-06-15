from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "audit-kit" / "scripts" / "final_report.py"
SPEC = importlib.util.spec_from_file_location("final_report", SCRIPT)
final_report = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(final_report)


def write(path: Path, content: str = "ok") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def sample_reports(tmp: Path) -> Path:
    reports = Path(tmp) / "reports"
    write(reports / "metadata.json", json.dumps({
        "product": "TestApp",
        "project": str(tmp),
        "timestamp": "2026-06-12T10:00:00Z",
        "target_url": "https://example.com",
    }))
    write(reports / "gates.json", json.dumps({
        "status": "pass",
        "threshold": 80,
        "coverage_percent": 85,
        "failed_categories": [],
    }))
    write(reports / "coverage.json", json.dumps([
        {"id": "A01", "name": "Broken Access Control", "status": "pass", "coverage_percent": 90, "required_present": 5, "required_total": 6, "missing_required": [], "failed_results": []},
        {"id": "A02", "name": "Security Misconfiguration", "status": "pass", "coverage_percent": 100, "required_present": 3, "required_total": 3, "missing_required": [], "failed_results": []},
        {"id": "A08", "name": "Software Integrity", "status": "fail", "coverage_percent": 50, "required_present": 1, "required_total": 2, "missing_required": ["upload_review"], "failed_results": ["bandit"]},
    ]))
    write(reports / "summary.json", json.dumps({
        "tool_status": {"ok": 12, "skipped": 4, "findings": 3},
        "artifacts": {"F1": 2, "F2": 5, "F4": 15, "F6": 3, "status": 20},
    }))
    write(reports / "evidence-manifest.json", json.dumps({
        "product": "TestApp",
        "project": {"path": "project/test", "target_url": "https://example.com"},
        "run": {"timestamp": "2026-06-12T10:00:00Z", "runner": "audit-kit/scripts/run_owasp_audit.sh"},
        "authorization": {"dast": True, "zap": True, "active_dast": False},
        "coverage_summary": {"coverage_percent": 85, "required_present": 18, "required_total": 22},
        "gates": {"status": "pass", "threshold": 80, "coverage_percent": 85},
    }))
    status_dir = reports / "status"
    write(status_dir / "tool-versions.status", "kind=host\nexit_code=0\n")
    write(status_dir / "bandit.status", "kind=toolbox\nexit_code=1\n")
    write(status_dir / "semgrep-django.status", "kind=toolbox\nexit_code=0\n")
    write(status_dir / "zap-baseline.status", "kind=skipped\nexit_code=0\n")
    return reports


class ReportGenerationTest(unittest.TestCase):
    def test_generates_markdown_with_expected_sections(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = sample_reports(tmp)
            result = final_report.generate(reports, "md")

            self.assertIn("OWASP Top 10:2025 Audit Report", result)
            self.assertIn("TestApp", result)
            self.assertIn("Executive Summary", result)
            self.assertIn("85%", result)
            self.assertIn("A01", result)
            self.assertIn("Broken Access Control", result)
            self.assertIn("pass", result.lower())

    def test_includes_tool_execution_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = sample_reports(tmp)
            result = final_report.generate(reports, "md")

            self.assertIn("Tool Execution", result)
            self.assertIn("bandit", result)

    def test_includes_gates_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = sample_reports(tmp)
            result = final_report.generate(reports, "md")

            self.assertIn("Executive Summary", result)
            self.assertIn("80%", result)

    def test_includes_authorization_section(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = sample_reports(tmp)
            result = final_report.generate(reports, "md")

            self.assertIn("Authorization", result)
            self.assertIn("DAST", result)

    def test_failed_category_shows_missing_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = sample_reports(tmp)
            result = final_report.generate(reports, "md")

            self.assertIn("A08", result)
            self.assertIn("upload_review", result)

    def test_generates_html_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = sample_reports(tmp)
            result = final_report.generate(reports, "html")

            self.assertIn("<html", result.lower())
            self.assertIn("TestApp", result)
            self.assertIn("</html>", result.lower())

    def test_writes_report_files_to_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = sample_reports(tmp)
            output = Path(tmp) / "output"
            output.mkdir()

            rc = final_report.run(reports, output)

            md_file = output / "owasp-audit-report.md"
            html_file = output / "owasp-audit-report.html"

            self.assertEqual(rc, 0)
            self.assertTrue(md_file.exists())
            self.assertTrue(html_file.exists())
            self.assertIn("OWASP Top 10:2025 Audit Report", md_file.read_text())
            self.assertIn("<html", html_file.read_text().lower())

    def test_handles_missing_files_gracefully(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = Path(tmp) / "reports"
            reports.mkdir()

            result = final_report.generate(reports, "md")

            self.assertIn("OWASP Top 10:2025 Audit Report", result)
            self.assertIn("unknown", result.lower())


class CLITest(unittest.TestCase):
    def test_cli_with_full_data(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = sample_reports(tmp)
            output = Path(tmp) / "output"
            output.mkdir()

            result = subprocess.run(
                ["python3", str(SCRIPT), str(reports), str(output)],
                capture_output=True, text=True, check=False,
            )

            self.assertEqual(result.returncode, 0)
            self.assertIn("Final report written", result.stdout)

    def test_cli_usage_without_args(self) -> None:
        result = subprocess.run(["python3", str(SCRIPT)], capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0)
