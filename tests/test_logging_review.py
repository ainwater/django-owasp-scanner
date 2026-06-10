from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "audit-kit" / "scripts" / "logging_review.py"
SPEC = importlib.util.spec_from_file_location("logging_review", SCRIPT)
logging_review = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(logging_review)


def write(path: Path, content: str = "ok") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def passing_review() -> dict:
    return {
        "checks": [
            {"id": "security_events_logged", "status": "pass", "evidence": "Login/logout events in auth.log"},
            {"id": "credentials_redacted", "status": "pass", "evidence": "PII and tokens redacted via logging filter"},
            {"id": "log_integrity", "status": "pass", "evidence": "Logs shipped to immutable SIEM"},
            {"id": "error_messages_generic", "status": "pass", "evidence": "500.html template without stack traces"},
            {"id": "alerting_configured", "status": "pass", "evidence": "Sentry alerts on ERROR level"},
            {"id": "audit_trail", "status": "pass", "evidence": "Django admin log tracks model changes"},
        ],
    }


class LoadReviewTest(unittest.TestCase):
    def test_valid_review_loads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "review.json"
            write(path, json.dumps(passing_review()))
            review = logging_review.load_review(path)
            self.assertEqual(len(review["checks"]), 6)

    def test_missing_checks_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "review.json"
            write(path, json.dumps({}))
            with self.assertRaises(RuntimeError):
                logging_review.load_review(path)

    def test_empty_checks_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "review.json"
            write(path, json.dumps({"checks": []}))
            with self.assertRaises(RuntimeError):
                logging_review.load_review(path)

    def test_non_dict_review_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "review.json"
            write(path, "[1, 2, 3]")
            with self.assertRaises(RuntimeError):
                logging_review.load_review(path)

    def test_check_without_id_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "review.json"
            write(path, json.dumps({"checks": [{"status": "pass", "evidence": "x"}]}))
            with self.assertRaises(RuntimeError):
                logging_review.load_review(path)

    def test_check_without_status_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "review.json"
            write(path, json.dumps({"checks": [{"id": "x", "evidence": "x"}]}))
            with self.assertRaises(RuntimeError):
                logging_review.load_review(path)

    def test_check_without_evidence_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "review.json"
            write(path, json.dumps({"checks": [{"id": "x", "status": "pass"}]}))
            with self.assertRaises(RuntimeError):
                logging_review.load_review(path)

    def test_invalid_status_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "review.json"
            write(path, json.dumps({"checks": [{"id": "x", "status": "maybe", "evidence": "x"}]}))
            with self.assertRaises(RuntimeError):
                logging_review.load_review(path)

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
                logging_review.load_review(path)

    def test_missing_file_raises(self) -> None:
        with self.assertRaises(RuntimeError):
            logging_review.load_review(Path("/nonexistent/review.json"))


class EvaluateTest(unittest.TestCase):
    def test_all_pass_produces_pass_status(self) -> None:
        review = passing_review()
        result = logging_review.evaluate(review, Path("review.json"))
        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["summary"]["failed"], 0)

    def test_one_fail_produces_fail_status(self) -> None:
        review = passing_review()
        review["checks"][0]["status"] = "fail"
        result = logging_review.evaluate(review, Path("review.json"))
        self.assertEqual(result["status"], "fail")
        self.assertIn("security_events_logged", result["failed_checks"])

    def test_mixed_status_lists_failed_correctly(self) -> None:
        review = passing_review()
        review["checks"][0]["status"] = "fail"
        review["checks"][2]["status"] = "fail"
        result = logging_review.evaluate(review, Path("review.json"))
        self.assertEqual(result["summary"]["failed"], 2)
        self.assertEqual(result["summary"]["passed"], 4)

    def test_findings_include_failed_evidence(self) -> None:
        review = passing_review()
        review["checks"][3]["status"] = "fail"
        result = logging_review.evaluate(review, Path("review.json"))
        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(result["findings"][0]["id"], "error_messages_generic")


class RunTest(unittest.TestCase):
    def test_passing_review_writes_results_and_returns_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = Path(tmp)
            review_path = reports / "logging-review.json"
            write(review_path, json.dumps(passing_review()))

            rc = logging_review.run(review_path, reports)
            results = reports / "F7" / "logging-review-results.json"

            self.assertEqual(rc, 0)
            self.assertTrue(results.exists())
            data = json.loads(results.read_text())
            self.assertEqual(data["status"], "pass")

    def test_failing_review_returns_one(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = Path(tmp)
            review_path = reports / "logging-review.json"
            review = passing_review()
            review["checks"][0]["status"] = "fail"
            write(review_path, json.dumps(review))

            rc = logging_review.run(review_path, reports)

            self.assertEqual(rc, 1)

    def test_missing_review_file_raises(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = Path(tmp)
            with self.assertRaises(RuntimeError):
                logging_review.run(reports / "missing.json", reports)


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
