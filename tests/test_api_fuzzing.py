from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "audit-kit" / "scripts" / "api_fuzzing.py"
SPEC = importlib.util.spec_from_file_location("api_fuzzing", SCRIPT)
assert SPEC and SPEC.loader
api_fuzzing = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(api_fuzzing)


def passing_review(spec_name: str = "openapi.json") -> dict:
    return {
        "source": spec_name,
        "schema": "openapi3",
        "target": "https://staging.example.com/api",
        "authorization": {
            "dast": True,
            "active_dast": False,
            "header_name": "Authorization",
        },
        "summary": {"total": 2, "passed": 2, "failed": 0},
        "checks": [
            {"id": "get-users", "status": "pass", "method": "GET", "path": "/users", "evidence": "200 OK"},
            {"id": "get-me", "status": "pass", "method": "GET", "path": "/me", "evidence": "200 OK"},
        ],
        "findings": [],
    }


class ApiFuzzingTest(unittest.TestCase):
    def test_review_must_be_json_object(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "review.json"
            path.write_text("[]\n")

            with self.assertRaisesRegex(RuntimeError, "JSON object"):
                api_fuzzing.load_review(path)

    def test_missing_checks_list_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "review.json"
            path.write_text(json.dumps({"summary": {}}))

            with self.assertRaisesRegex(RuntimeError, "requires checks list"):
                api_fuzzing.load_review(path)

    def test_empty_checks_list_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "review.json"
            path.write_text(json.dumps({"checks": []}))

            with self.assertRaisesRegex(RuntimeError, "requires at least one check"):
                api_fuzzing.load_review(path)

    def test_duplicate_check_id_fails(self) -> None:
        review = passing_review()
        review["checks"] = [review["checks"][0], review["checks"][0]]

        with self.assertRaisesRegex(RuntimeError, "duplicate check id"):
            api_fuzzing.evaluate(review, Path("openapi.json"))

    def test_malformed_authorization_raises_runtime_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            review = root / "review.json"
            reports = root / "reports"
            payload = passing_review()
            payload["authorization"] = "Authorization: Bearer secret"
            review.write_text(json.dumps(payload))

            with self.assertRaisesRegex(RuntimeError, "authorization must be a JSON object"):
                api_fuzzing.run(review, reports)

    def test_authorization_flags_must_be_booleans(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            review = root / "review.json"
            payload = passing_review()
            payload["authorization"] = {"dast": "false", "active_dast": False, "header_name": "Authorization"}
            review.write_text(json.dumps(payload))

            with self.assertRaisesRegex(RuntimeError, r"authorization\.dast must be boolean"):
                api_fuzzing.load_review(review)

    def test_authorization_header_name_is_trimmed(self) -> None:
        review = passing_review()
        review["authorization"] = {"dast": True, "active_dast": False, "header_name": "  Authorization  "}

        result = api_fuzzing.evaluate(review, Path("openapi.json"))

        self.assertEqual(result["authorization"], {"dast": True, "active_dast": False, "header_name": "Authorization"})

    def test_load_review_returns_normalized_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            review_path = Path(tmp) / "review.json"
            payload = passing_review()
            payload["authorization"]["header_name"] = "  Authorization  "
            review_path.write_text(json.dumps(payload))

            review = api_fuzzing.load_review(review_path)

        self.assertEqual(review["authorization"], {"dast": True, "active_dast": False, "header_name": "Authorization"})

    def test_authorization_dast_must_be_true_for_accepted_review(self) -> None:
        review = passing_review()
        review["authorization"] = {"dast": False, "active_dast": False, "header_name": "Authorization"}

        with self.assertRaisesRegex(RuntimeError, r"authorization\.dast must be true"):
            api_fuzzing.evaluate(review, Path("openapi.json"))

    def test_passing_review_generates_pass_results(self) -> None:
        result = api_fuzzing.evaluate(passing_review(), Path("review.json"))

        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["summary"], {"total": 2, "passed": 2, "failed": 0})
        self.assertEqual(result["failed_checks"], [])

    def test_missing_file_error_uses_basename(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            private_dir = Path(tmp) / "private" / "client"
            path = private_dir / "openapi-review.json"

            with self.assertRaises(RuntimeError) as raised:
                api_fuzzing.load_review(path)

        self.assertIn("openapi-review.json", str(raised.exception))
        self.assertNotIn(str(private_dir), str(raised.exception))

    def test_failed_check_fails_result(self) -> None:
        review = passing_review()
        review["summary"] = {"total": 2, "passed": 1, "failed": 1}
        review["checks"][1]["status"] = "fail"
        review["findings"] = [{"id": "get-me", "severity": "medium", "evidence": "500 on schema case"}]

        result = api_fuzzing.evaluate(review, Path("openapi.json"))

        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["failed_checks"], ["get-me"])

    def test_evaluate_derives_canonical_summary_and_findings(self) -> None:
        review = passing_review()
        review["summary"] = {"total": 99, "passed": 99, "failed": 0}
        review["checks"][1]["status"] = "fail"
        review["findings"] = [{"id": "wrong", "severity": "low", "evidence": "ignore me"}]

        result = api_fuzzing.evaluate(review, Path("openapi.json"))

        self.assertEqual(result["summary"], {"total": 2, "passed": 1, "failed": 1})
        self.assertEqual(
            result["findings"],
            [{"id": "get-me", "method": "GET", "path": "/me", "evidence": "200 OK"}],
        )

    def test_run_writes_normalized_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            review = root / "review.json"
            reports = root / "reports"
            private_review = passing_review()
            private_review["checks"][0]["internal_notes"] = "do not export"
            private_review["summary"] = {"total": 500, "passed": 500, "failed": 0}
            private_review["findings"] = [{"id": "wrong", "evidence": "ignore me"}]
            review.write_text(json.dumps(private_review))

            rc = api_fuzzing.run(review, reports)
            evidence = json.loads((reports / "F6" / "api-fuzzing.json").read_text())
            results = json.loads((reports / "F6" / "api-fuzzing-results.json").read_text())

        self.assertEqual(rc, 0)
        self.assertEqual(evidence["source"], "review.json")
        self.assertNotIn("internal_notes", evidence["checks"][0])
        self.assertEqual(results["summary"], {"total": 2, "passed": 2, "failed": 0})
        self.assertEqual(results["findings"], [])
        self.assertEqual(evidence["authorization"], results["authorization"])
        self.assertEqual(results["status"], "pass")

    def test_cli_reports_active_dast_requirement(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            review = Path(tmp) / "review.json"
            payload = passing_review()
            payload["authorization"]["active_dast"] = True
            review.write_text(json.dumps(payload))

            result = api_fuzzing.main_for_args(["--requires-active-dast", str(review)])

            payload["authorization"]["active_dast"] = False
            review.write_text(json.dumps(payload))
            result_without_active = api_fuzzing.main_for_args(["--requires-active-dast", str(review)])

        self.assertEqual(result, 0)
        self.assertEqual(result_without_active, 1)

    def test_cli_reports_invalid_review_separately_for_active_dast_check(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            review = Path(tmp) / "review.json"
            review.write_text(json.dumps({"checks": []}))

            with self.assertRaises(SystemExit) as raised:
                api_fuzzing.main_for_args(["--requires-active-dast", str(review)])

        self.assertEqual(raised.exception.code, 2)
