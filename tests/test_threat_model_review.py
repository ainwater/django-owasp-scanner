from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "audit-kit" / "scripts" / "threat_model_review.py"
SPEC = importlib.util.spec_from_file_location("threat_model_review", SCRIPT)
threat_model_review = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(threat_model_review)


def write(path: Path, content: str = "ok") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def passing_review() -> dict:
    return {
        "checks": [
            {"id": "threat_model_documented", "status": "pass", "evidence": "Threat model covers auth, payments, exports"},
            {"id": "abuse_cases_defined", "status": "pass", "evidence": "Abuse cases documented for 5 critical flows"},
            {"id": "business_limits_enforced", "status": "pass", "evidence": "Rate limits and quotas server-side"},
            {"id": "upload_type_validation", "status": "pass", "evidence": "Whitelist PDF/PNG, MIME check, magic bytes"},
            {"id": "upload_size_limits", "status": "pass", "evidence": "10MB limit in Nginx and Django"},
            {"id": "upload_storage_isolated", "status": "pass", "evidence": "Uploads in S3 private bucket, not MEDIA_ROOT"},
            {"id": "deserialization_safe", "status": "pass", "evidence": "No pickle, no yaml.load; DRF serializers only"},
            {"id": "serializer_fields_allowlist", "status": "pass", "evidence": "All serializers use fields or exclude"},
            {"id": "pipeline_integrity_verified", "status": "pass", "evidence": "GitHub branch protection, signed commits"},
            {"id": "artifact_signing", "status": "pass", "evidence": "Docker images signed with Cosign"},
        ],
    }


class LoadReviewTest(unittest.TestCase):
    def test_valid_review_loads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "review.json"
            write(path, json.dumps(passing_review()))
            review = threat_model_review.load_review(path)
            self.assertEqual(len(review["checks"]), 10)

    def test_missing_checks_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "review.json"
            write(path, json.dumps({}))
            with self.assertRaises(RuntimeError):
                threat_model_review.load_review(path)

    def test_empty_checks_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "review.json"
            write(path, json.dumps({"checks": []}))
            with self.assertRaises(RuntimeError):
                threat_model_review.load_review(path)

    def test_non_dict_review_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "review.json"
            write(path, "[1, 2, 3]")
            with self.assertRaises(RuntimeError):
                threat_model_review.load_review(path)

    def test_check_without_id_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "review.json"
            write(path, json.dumps({"checks": [{"status": "pass", "evidence": "x"}]}))
            with self.assertRaises(RuntimeError):
                threat_model_review.load_review(path)

    def test_invalid_status_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "review.json"
            write(path, json.dumps({"checks": [{"id": "x", "status": "maybe", "evidence": "x"}]}))
            with self.assertRaises(RuntimeError):
                threat_model_review.load_review(path)

    def test_check_without_evidence_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "review.json"
            write(path, json.dumps({"checks": [{"id": "x", "status": "pass"}]}))
            with self.assertRaises(RuntimeError):
                threat_model_review.load_review(path)

    def test_duplicate_check_id_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "review.json"
            write(path, json.dumps({
                "checks": [
                    {"id": "x", "status": "pass", "evidence": "a"},
                    {"id": "x", "status": "pass", "evidence": "b"},
                ],
            }))
            with self.assertRaises(RuntimeError):
                threat_model_review.load_review(path)

    def test_missing_file_raises(self) -> None:
        with self.assertRaises(RuntimeError):
            threat_model_review.load_review(Path("/nonexistent/review.json"))


class EvaluateTest(unittest.TestCase):
    def test_all_pass_produces_pass_status(self) -> None:
        review = passing_review()
        result = threat_model_review.evaluate(review, Path("review.json"))
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["summary"]["failed"], 0)

    def test_one_fail_produces_fail_status(self) -> None:
        review = passing_review()
        review["checks"][0]["status"] = "fail"
        result = threat_model_review.evaluate(review, Path("review.json"))
        self.assertEqual(result["status"], "fail")
        self.assertIn("threat_model_documented", result["failed_checks"])

    def test_warn_without_fail_gives_warn_status(self) -> None:
        review = passing_review()
        review["checks"][0]["status"] = "warn"
        result = threat_model_review.evaluate(review, Path("review.json"))
        self.assertEqual(result["status"], "warn")

    def test_findings_include_failed_and_warned_evidence(self) -> None:
        review = passing_review()
        review["checks"][0]["status"] = "fail"
        review["checks"][3]["status"] = "warn"
        result = threat_model_review.evaluate(review, Path("review.json"))
        self.assertEqual(len(result["findings"]), 2)


class RunTest(unittest.TestCase):
    def test_passing_review_returns_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = Path(tmp)
            review_path = reports / "review.json"
            write(review_path, json.dumps(passing_review()))

            rc = threat_model_review.run(review_path, reports)
            results = reports / "F3" / "threat-model-results.json"

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

            rc = threat_model_review.run(review_path, reports)

            self.assertEqual(rc, 1)

    def test_missing_review_file_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = Path(tmp)
            with self.assertRaises(RuntimeError):
                threat_model_review.run(reports / "missing.json", reports)


class CLITest(unittest.TestCase):
    def test_cli_with_valid_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = Path(tmp)
            review_path = reports / "review.json"
            write(review_path, json.dumps(passing_review()))

            result = subprocess.run(
                ["python3", str(SCRIPT), str(review_path), str(reports)],
                capture_output=True,
                text=True,
                check=False,
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
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 1)

    def test_cli_usage_without_args(self) -> None:
        result = subprocess.run(
            ["python3", str(SCRIPT)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
