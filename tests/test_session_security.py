from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "audit-kit" / "scripts" / "session_security.py"
SPEC = importlib.util.spec_from_file_location("session_security", SCRIPT)
assert SPEC and SPEC.loader
session_security = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(session_security)


PASSING_REVIEW = {
    "checks": [
        {"id": "logout_invalidates_session", "status": "pass", "evidence": "logout token rejected"},
        {"id": "session_rotation", "status": "pass", "evidence": "session key changes after login"},
        {"id": "enumeration_resistance", "status": "pass", "evidence": "login reset messages are generic"},
        {"id": "mfa_privileged", "status": "pass", "evidence": "admin role requires MFA"},
        {"id": "brute_force_protection", "status": "pass", "evidence": "login throttled after repeated failures"},
    ]
}


class SessionSecurityTest(unittest.TestCase):
    def test_review_must_be_json_object(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "session-review.json"
            path.write_text("[]\n")

            with self.assertRaisesRegex(RuntimeError, "JSON object"):
                session_security.load_review(path)

    def test_passing_review_generates_pass_results(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "session-review.json"
            path.write_text(json.dumps(PASSING_REVIEW))

            result = session_security.evaluate(session_security.load_review(path), source=path)

        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["summary"], {"total": 5, "pass": 5, "fail": 0})
        self.assertEqual(result["failed_controls"], [])

    def test_missing_required_control_fails(self) -> None:
        review = {"checks": PASSING_REVIEW["checks"][:-1]}

        result = session_security.evaluate(review, source=Path("session-review.json"))

        self.assertEqual(result["status"], "fail")
        self.assertIn("brute_force_protection", result["failed_controls"])

    def test_failed_control_fails_with_finding(self) -> None:
        review = {
            "checks": [
                *PASSING_REVIEW["checks"][:-1],
                {"id": "brute_force_protection", "status": "fail", "evidence": "no throttling"},
            ]
        }

        result = session_security.evaluate(review, source=Path("session-review.json"))

        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["findings"][0]["control"], "brute_force_protection")

    def test_not_applicable_required_control_fails(self) -> None:
        review = {
            "checks": [
                *PASSING_REVIEW["checks"][:-1],
                {"id": "brute_force_protection", "status": "not_applicable", "evidence": "no login form"},
            ]
        }

        result = session_security.evaluate(review, source=Path("session-review.json"))

        self.assertEqual(result["status"], "fail")
        self.assertIn("brute_force_protection", result["failed_controls"])

    def test_duplicate_control_id_fails(self) -> None:
        review = {"checks": [PASSING_REVIEW["checks"][0], PASSING_REVIEW["checks"][0]]}

        with self.assertRaisesRegex(RuntimeError, "duplicate check id"):
            session_security.evaluate(review, source=Path("session-review.json"))

    def test_run_writes_session_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            review = root / "session-review.json"
            reports = root / "reports"
            private_review = {
                "checks": [
                    {**PASSING_REVIEW["checks"][0], "internal_notes": "do not export"},
                    *PASSING_REVIEW["checks"][1:],
                ]
            }
            review.write_text(json.dumps(private_review))

            rc = session_security.run(review, reports)
            evidence = json.loads((reports / "F2" / "session-security.json").read_text())
            results = json.loads((reports / "F2" / "session-security-results.json").read_text())

        self.assertEqual(rc, 0)
        self.assertEqual(evidence["source"], "session-review.json")
        self.assertNotIn("internal_notes", evidence["checks"][0])
        self.assertEqual(results["status"], "pass")

    def test_load_error_uses_basename(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "session-review.json"
            path.write_text("{")

            with self.assertRaises(RuntimeError) as raised:
                session_security.load_review(path)

        self.assertIn("session-review.json", str(raised.exception))
        self.assertNotIn(tmp, str(raised.exception))

    def test_missing_file_error_uses_basename(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            private_dir = Path(tmp) / "private" / "client"
            path = private_dir / "session-review.json"

            with self.assertRaises(RuntimeError) as raised:
                session_security.load_review(path)

        self.assertIn("session-review.json", str(raised.exception))
        self.assertNotIn(str(private_dir), str(raised.exception))


if __name__ == "__main__":
    unittest.main()
