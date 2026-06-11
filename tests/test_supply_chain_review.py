from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "audit-kit" / "scripts" / "supply_chain_review.py"
SPEC = importlib.util.spec_from_file_location("supply_chain_review", SCRIPT)
supply_chain_review = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(supply_chain_review)


def write(path: Path, content: str = "ok") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def passing_review() -> dict:
    return {
        "checks": [
            {"id": "dependencies_locked", "status": "pass", "evidence": "Poetry lockfile committed and verified in CI"},
            {"id": "sources_trusted", "status": "pass", "evidence": "Only PyPI official packages, no GitHub tarballs"},
            {"id": "cve_triage_active", "status": "pass", "evidence": "Dependabot with 7-day SLA for Critical/High"},
            {"id": "sbom_generated", "status": "pass", "evidence": "CycloneDX SBOM generated in CI and archived"},
            {"id": "artifact_signing", "status": "pass", "evidence": "Docker images signed with Cosign, verified in deployment"},
            {"id": "cicd_pipeline_reviewed", "status": "pass", "evidence": "Pipeline secrets scoped per environment, no hardcoded creds"},
            {"id": "update_process", "status": "pass", "evidence": "Monthly dependency review with changelog and rollback plan"},
            {"id": "provenance_tracked", "status": "pass", "evidence": "SLSA Level 2 provenance for all releases"},
            {"id": "docker_hardening", "status": "pass", "evidence": "Non-root user, minimal base image, no leaked secrets in layers"},
            {"id": "dd_import_configured", "status": "pass", "evidence": "DefectDojo token scoped to product, auto-import from CI"},
        ],
    }


class LoadReviewTest(unittest.TestCase):
    def test_valid_review_loads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "review.json"
            write(path, json.dumps(passing_review()))
            review = supply_chain_review.load_review(path)
            self.assertEqual(len(review["checks"]), 10)

    def test_missing_checks_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "review.json"
            write(path, json.dumps({}))
            with self.assertRaises(RuntimeError):
                supply_chain_review.load_review(path)

    def test_empty_checks_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "review.json"
            write(path, json.dumps({"checks": []}))
            with self.assertRaises(RuntimeError):
                supply_chain_review.load_review(path)

    def test_non_dict_review_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "review.json"
            write(path, "[1, 2, 3]")
            with self.assertRaises(RuntimeError):
                supply_chain_review.load_review(path)

    def test_check_without_id_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "review.json"
            write(path, json.dumps({"checks": [{"status": "pass", "evidence": "x"}]}))
            with self.assertRaises(RuntimeError):
                supply_chain_review.load_review(path)

    def test_check_without_evidence_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "review.json"
            write(path, json.dumps({"checks": [{"id": "x", "status": "pass"}]}))
            with self.assertRaises(RuntimeError):
                supply_chain_review.load_review(path)

    def test_invalid_status_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "review.json"
            write(path, json.dumps({"checks": [{"id": "x", "status": "unknown", "evidence": "x"}]}))
            with self.assertRaises(RuntimeError):
                supply_chain_review.load_review(path)

    def test_duplicate_check_id_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "review.json"
            write(path, json.dumps({
                "checks": [
                    {"id": "x", "status": "pass", "evidence": "a"},
                    {"id": "x", "status": "fail", "evidence": "b"},
                ],
            }))
            with self.assertRaises(RuntimeError):
                supply_chain_review.load_review(path)

    def test_missing_file_raises(self) -> None:
        with self.assertRaises(RuntimeError):
            supply_chain_review.load_review(Path("/nonexistent/review.json"))


class EvaluateTest(unittest.TestCase):
    def test_all_pass_produces_pass_status(self) -> None:
        result = supply_chain_review.evaluate(passing_review(), Path("review.json"))
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["summary"]["failed"], 0)

    def test_one_fail_produces_fail_status(self) -> None:
        review = passing_review()
        review["checks"][0]["status"] = "fail"
        result = supply_chain_review.evaluate(review, Path("review.json"))
        self.assertEqual(result["status"], "fail")

    def test_warn_without_fail_gives_warn_status(self) -> None:
        review = passing_review()
        for c in review["checks"]:
            c["status"] = "warn"
        result = supply_chain_review.evaluate(review, Path("review.json"))
        self.assertEqual(result["status"], "warn")

    def test_findings_include_failed_checks(self) -> None:
        review = passing_review()
        review["checks"][2]["status"] = "fail"
        result = supply_chain_review.evaluate(review, Path("review.json"))
        self.assertIn("cve_triage_active", result["failed_checks"])


class RunTest(unittest.TestCase):
    def test_passing_review_returns_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = Path(tmp)
            review_path = reports / "review.json"
            write(review_path, json.dumps(passing_review()))

            rc = supply_chain_review.run(review_path, reports)
            results = reports / "F5" / "supply-chain-results.json"

            self.assertEqual(rc, 0)
            self.assertTrue(results.exists())
            data = json.loads(results.read_text())
            self.assertEqual(data["status"], "pass")

    def test_failing_review_returns_one(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = Path(tmp)
            review_path = reports / "review.json"
            review = passing_review()
            review["checks"][0]["status"] = "fail"
            write(review_path, json.dumps(review))

            rc = supply_chain_review.run(review_path, reports)
            self.assertEqual(rc, 1)

    def test_missing_review_file_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = Path(tmp)
            with self.assertRaises(RuntimeError):
                supply_chain_review.run(reports / "missing.json", reports)


class CLITest(unittest.TestCase):
    def test_cli_with_valid_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = Path(tmp)
            review_path = reports / "review.json"
            write(review_path, json.dumps(passing_review()))

            result = subprocess.run(
                ["python3", str(SCRIPT), str(review_path), str(reports)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0)

    def test_cli_with_failing_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = Path(tmp)
            review_path = reports / "review.json"
            review = passing_review()
            review["checks"][0]["status"] = "fail"
            write(review_path, json.dumps(review))

            result = subprocess.run(
                ["python3", str(SCRIPT), str(review_path), str(reports)],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 1)

    def test_cli_usage_without_args(self) -> None:
        result = subprocess.run(["python3", str(SCRIPT)], capture_output=True, text=True, check=False)
        self.assertNotEqual(result.returncode, 0)
