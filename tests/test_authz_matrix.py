from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "audit-kit" / "scripts" / "authz_matrix.py"
ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("authz_matrix", SCRIPT)
authz_matrix = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(authz_matrix)


MATRIX = """
version: 1
roles:
  - anonymous
  - owner
  - other_user
tenants:
  - alpha
  - beta
objects:
  - invoice:own
  - invoice:other
checks:
  - id: invoice-detail-owner
    endpoint: GET /api/invoices/{id}/
    role: owner
    tenant: alpha
    object: invoice:own
    expected: allow
    observed: allow
  - id: invoice-detail-cross-tenant
    endpoint: GET /api/invoices/{id}/
    role: other_user
    tenant: beta
    object: invoice:own
    expected: deny
    observed: allow
"""


class AuthzMatrixTest(unittest.TestCase):
    def test_load_matrix_requires_top_level_mapping(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "authz.yml"
            path.write_text("[]\n")

            with self.assertRaisesRegex(RuntimeError, "must be a mapping"):
                authz_matrix.load_matrix(path)

    def test_load_matrix_requires_non_empty_checks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "authz.yml"
            path.write_text("version: 1\nchecks:\n")

            with self.assertRaisesRegex(RuntimeError, "checks must not be empty"):
                authz_matrix.load_matrix(path)

    def test_evaluate_rejects_incomplete_checks(self) -> None:
        matrix = {"checks": [{"id": "missing-role", "endpoint": "GET /x", "expected": "deny", "observed": "deny"}]}

        with self.assertRaisesRegex(RuntimeError, "role"):
            authz_matrix.evaluate(matrix, source=Path("authz.yml"))

    def test_evaluate_rejects_invalid_expected_or_observed_values(self) -> None:
        matrix = {
            "checks": [
                {
                    "id": "invalid",
                    "endpoint": "GET /x",
                    "role": "owner",
                    "tenant": "alpha",
                    "object": "item:own",
                    "expected": "denied",
                    "observed": "allow",
                }
            ]
        }

        with self.assertRaisesRegex(RuntimeError, "expected"):
            authz_matrix.evaluate(matrix, source=Path("authz.yml"))

    def test_evaluate_rejects_values_outside_declared_dimensions(self) -> None:
        matrix = {
            "roles": ["owner"],
            "tenants": ["alpha"],
            "objects": ["item:own"],
            "checks": [
                {
                    "id": "unknown-role",
                    "endpoint": "GET /x",
                    "role": "other_user",
                    "tenant": "alpha",
                    "object": "item:own",
                    "expected": "deny",
                    "observed": "deny",
                }
            ],
        }

        with self.assertRaisesRegex(RuntimeError, "role"):
            authz_matrix.evaluate(matrix, source=Path("authz.yml"))

    def test_evaluate_matrix_reports_bypass_when_denied_case_allows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "authz.yml"
            path.write_text(MATRIX)

            result = authz_matrix.evaluate(authz_matrix.load_matrix(path), source=path)

        self.assertEqual(result["summary"], {"total": 2, "pass": 1, "fail": 1})
        self.assertEqual(result["status"], "fail")
        self.assertEqual(result["findings"][0]["type"], "authorization_bypass")
        self.assertEqual(result["findings"][0]["check_id"], "invoice-detail-cross-tenant")

    def test_write_artifacts_copies_matrix_and_writes_results(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "authz.yml"
            reports = root / "reports"
            source.write_text(MATRIX)

            rc = authz_matrix.run(source, reports)

            copied = reports / "F2" / "authz-matrix.yml"
            results = reports / "F2" / "authz-results.json"
            copied_text = copied.read_text()
            payload = json.loads(results.read_text())

        self.assertEqual(rc, 1)
        self.assertEqual(copied_text, MATRIX)
        self.assertEqual(payload["status"], "fail")
        self.assertEqual(payload["source"], "authz.yml")

    def test_authz_matrix_example_is_valid_and_contains_bypass_case(self) -> None:
        path = ROOT / "audit-kit" / "templates" / "authz-matrix.example.json"

        result = authz_matrix.evaluate(authz_matrix.load_matrix(path), source=path)

        self.assertGreaterEqual(result["summary"]["total"], 3)
        self.assertEqual(result["status"], "fail")
        self.assertIn("authorization_bypass", {finding["type"] for finding in result["findings"]})

    def test_idor_review_template_has_required_sections(self) -> None:
        content = (ROOT / "audit-kit" / "templates" / "A01-idor-review.example.md").read_text()

        self.assertIn("## Scope", content)
        self.assertIn("## Test Cases", content)
        self.assertIn("## Sign-off", content)


if __name__ == "__main__":
    unittest.main()
