from __future__ import annotations

import subprocess
import tempfile
import unittest
import json
from pathlib import Path

from tests.runner_test_helpers import RUNNER, ROOT, build_pr5_api_fuzzing_command, write, write_api_fuzzing_review, write_session_review


class RunOwaspAuditPr5Test(unittest.TestCase):
    def test_openapi_spec_flag_requires_value(self) -> None:
        result = subprocess.run(
            [
                "bash",
                str(RUNNER),
                "--project",
                str(ROOT),
                "--product",
                "Test",
                "--openapi-spec",
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--openapi-spec requiere PATH", result.stderr)
        self.assertNotIn("unbound variable", result.stderr.lower())

    def test_generate_only_with_api_review_writes_api_fuzzing_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            review = root / "api-review.json"
            spec = root / "openapi.json"
            output = root / "out"
            write_api_fuzzing_review(review)
            write(spec, '{"openapi":"3.0.0","paths":{}}')

            result = subprocess.run(
                build_pr5_api_fuzzing_command(
                    project=ROOT,
                    spec=spec,
                    authorize_dast=True,
                    api_fuzzing_review=review,
                    extra_args=["--output", str(output), "--generate-only", "--skip-dd-import", "--coverage-threshold", "0"],
                ),
                capture_output=True,
                text=True,
                check=False,
            )
            evidence = output / "reports" / "F6" / "api-fuzzing.json"
            results = output / "reports" / "F6" / "api-fuzzing-results.json"
            evidence_exists = evidence.is_file()
            results_exists = results.is_file()

        self.assertEqual(result.returncode, 0)
        self.assertTrue(evidence_exists)
        self.assertTrue(results_exists)

    def test_generate_only_manifest_records_pr5_authorization_without_target(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            review = root / "api-review.json"
            spec = root / "openapi.json"
            output = root / "out"
            write_api_fuzzing_review(review)
            write(spec, '{"openapi":"3.0.0","paths":{}}')

            command = build_pr5_api_fuzzing_command(
                project=ROOT,
                spec=spec,
                authorize_dast=True,
                api_fuzzing_review=review,
                extra_args=["--output", str(output), "--generate-only", "--skip-dd-import", "--coverage-threshold", "0"],
            )
            target_index = command.index("--target")
            del command[target_index : target_index + 2]
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            manifest = json.loads((output / "reports" / "evidence-manifest.json").read_text())

        self.assertEqual(result.returncode, 0)
        self.assertTrue(manifest["authorization"]["dast"])
        self.assertFalse(manifest["authorization"]["active_dast"])

    def test_api_fuzzing_requires_authorize_dast(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            spec = Path(tmp) / "openapi.json"
            write(spec, '{"openapi":"3.0.0","paths":{}}')
            result = subprocess.run(
                build_pr5_api_fuzzing_command(
                    project=ROOT,
                    spec=spec,
                    extra_args=["--generate-only", "--output", tmp],
                ),
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("authorize-dast", result.stderr)

    def test_active_api_fuzzing_requires_authorize_active_dast(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            spec = Path(tmp) / "openapi.json"
            write(spec, '{"openapi":"3.0.0","paths":{}}')
            result = subprocess.run(
                build_pr5_api_fuzzing_command(
                    project=ROOT,
                    spec=spec,
                    authorize_dast=True,
                    extra_args=["--schemathesis-max-examples", "10", "--generate-only", "--output", tmp],
                ),
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("authorize-active-dast", result.stderr)

    def test_api_fuzzing_review_declaring_active_dast_requires_authorize_active_dast(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            review = root / "api-review.json"
            spec = root / "openapi.json"
            payload = {
                **json.loads(json.dumps({
                    "source": "openapi.json",
                    "schema": "openapi3",
                    "target": "https://staging.example.com/api",
                    "authorization": {"dast": True, "active_dast": True, "header_name": "Authorization"},
                    "summary": {"total": 1, "passed": 1, "failed": 0},
                    "checks": [{"id": "get-users", "status": "pass", "method": "GET", "path": "/users", "evidence": "200 OK"}],
                    "findings": [],
                }))
            }
            write(review, json.dumps(payload))
            write(spec, '{"openapi":"3.0.0","paths":{}}')

            result = subprocess.run(
                build_pr5_api_fuzzing_command(
                    project=ROOT,
                    spec=spec,
                    authorize_dast=True,
                    api_fuzzing_review=review,
                    extra_args=["--generate-only", "--output", str(root / "out"), "--skip-dd-import", "--coverage-threshold", "0"],
                ),
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("authorize-active-dast", result.stderr)

    def test_dry_run_includes_api_fuzzing_readiness_and_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            spec = root / "openapi.json"
            write(spec, '{"openapi":"3.0.0","paths":{}}')
            result = subprocess.run(
                build_pr5_api_fuzzing_command(
                    project=ROOT,
                    spec=spec,
                    authorize_dast=True,
                    extra_args=["--dry-run", "--output", str(root / "out")],
                ),
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0)
        self.assertIn("5 DAST Auth & API Fuzzing", result.stdout)
        self.assertRegex(result.stdout, r"5a API Fuzzing\s+CONFIGURING")
        self.assertNotIn("api-fuzzing (host)", result.stdout)

    def test_api_fuzzing_status_does_not_record_secret_header_value(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            review = root / "api-review.json"
            spec = root / "openapi.json"
            output = root / "out"
            write_api_fuzzing_review(review)
            write(spec, '{"openapi":"3.0.0","paths":{}}')
            result = subprocess.run(
                build_pr5_api_fuzzing_command(
                    project=ROOT,
                    spec=spec,
                    authorize_dast=True,
                    api_fuzzing_review=review,
                    extra_args=["--output", str(output), "--generate-only", "--skip-dd-import", "--coverage-threshold", "0"],
                ),
                capture_output=True,
                text=True,
                check=False,
            )
            status_path = output / "reports" / "status" / "api-fuzzing.status"
            status_exists = status_path.is_file()
            status = status_path.read_text() if status_exists else ""

        self.assertEqual(result.returncode, 0)
        self.assertTrue(status_exists)
        self.assertIn("Authorization", status)
        self.assertNotIn("Bearer secret", status)

    def test_runner_rejects_bundled_api_fuzzing_templates_as_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            spec = Path(tmp) / "openapi.json"
            write(spec, '{"openapi":"3.0.0","paths":{}}')
            result = subprocess.run(
                build_pr5_api_fuzzing_command(
                    project=ROOT,
                    spec=spec,
                    authorize_dast=True,
                    api_fuzzing_review=ROOT / "audit-kit" / "templates" / "evidence-manifest.example.json",
                    extra_args=["--generate-only", "--output", tmp],
                ),
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("template", result.stderr.lower())

    def test_api_fuzzing_status_sanitizes_header_name_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            review = root / "api-review.json"
            spec = root / "openapi.json"
            output = root / "out"
            write_api_fuzzing_review(review)
            write(spec, '{"openapi":"3.0.0","paths":{}}')
            result = subprocess.run(
                build_pr5_api_fuzzing_command(
                    project=ROOT,
                    spec=spec,
                    authorize_dast=True,
                    api_fuzzing_review=review,
                    extra_args=[
                        "--output",
                        str(output),
                        "--generate-only",
                        "--skip-dd-import",
                        "--coverage-threshold",
                        "0",
                        "--auth-header-name",
                        "Authorization\ncommand=oops",
                    ],
                ),
                capture_output=True,
                text=True,
                check=False,
            )
            status_path = output / "reports" / "status" / "api-fuzzing.status"
            status_exists = status_path.is_file()
            status = status_path.read_text() if status_exists else ""

        self.assertEqual(result.returncode, 0)
        self.assertTrue(status_exists)
        self.assertIn("header=Authorizationcommandoops", status)
        self.assertNotIn("header=Authorization\ncommand=oops", status)

    def test_api_fuzzing_status_sanitizes_review_filename_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            review = root / "api-review\nexit_code=999.json"
            spec = root / "openapi.json"
            output = root / "out"
            write_api_fuzzing_review(review)
            write(spec, '{"openapi":"3.0.0","paths":{}}')
            result = subprocess.run(
                build_pr5_api_fuzzing_command(
                    project=ROOT,
                    spec=spec,
                    authorize_dast=True,
                    api_fuzzing_review=review,
                    extra_args=["--output", str(output), "--generate-only", "--skip-dd-import", "--coverage-threshold", "0"],
                ),
                capture_output=True,
                text=True,
                check=False,
            )
            status_path = output / "reports" / "status" / "api-fuzzing.status"
            status_exists = status_path.is_file()
            status = status_path.read_text() if status_exists else ""

        self.assertEqual(result.returncode, 0)
        self.assertTrue(status_exists)
        self.assertNotIn("api-review\nexit_code=999.json", status)
        self.assertNotIn("\nexit_code=999", status)

    def test_api_fuzzing_accepts_review_filename_starting_with_dash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            review = root / "-api-review.json"
            spec = root / "openapi.json"
            output = root / "out"
            write_api_fuzzing_review(review)
            write(spec, '{"openapi":"3.0.0","paths":{}}')

            result = subprocess.run(
                build_pr5_api_fuzzing_command(
                    project=ROOT,
                    spec=spec,
                    authorize_dast=True,
                    api_fuzzing_review=review,
                    extra_args=["--output", str(output), "--generate-only", "--skip-dd-import", "--coverage-threshold", "0"],
                ),
                capture_output=True,
                text=True,
                check=False,
            )
            status = (output / "reports" / "status" / "api-fuzzing.status").read_text()

        self.assertEqual(result.returncode, 0)
        self.assertIn("api-review.json", status)

    def test_session_review_accepts_filename_starting_with_dash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            review = root / "-session-review.json"
            output = root / "out"
            write_session_review(review)

            result = subprocess.run(
                [
                    "bash",
                    str(RUNNER),
                    "--project",
                    str(ROOT),
                    "--product",
                    "Test",
                    "--session-review",
                    str(review),
                    "--output",
                    str(output),
                    "--generate-only",
                    "--skip-dd-import",
                    "--coverage-threshold",
                    "0",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            status = (output / "reports" / "status" / "session-security.status").read_text()

        self.assertEqual(result.returncode, 0)
        self.assertIn("session-review.json", status)

    def test_api_fuzzing_accepts_relative_review_filename_starting_with_dash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            review = root / "-api-review.json"
            spec = root / "openapi.json"
            output = root / "out"
            write_api_fuzzing_review(review)
            write(spec, '{"openapi":"3.0.0","paths":{}}')

            result = subprocess.run(
                build_pr5_api_fuzzing_command(
                    project=ROOT,
                    spec=Path("openapi.json"),
                    authorize_dast=True,
                    api_fuzzing_review=Path("-api-review.json"),
                    extra_args=["--output", str(output), "--generate-only", "--skip-dd-import", "--coverage-threshold", "0"],
                ),
                capture_output=True,
                text=True,
                check=False,
                cwd=root,
            )

        self.assertEqual(result.returncode, 0)

    def test_session_review_accepts_relative_filename_starting_with_dash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            review = root / "-session-review.json"
            output = root / "out"
            write_session_review(review)

            result = subprocess.run(
                [
                    "bash",
                    str(RUNNER),
                    "--project",
                    str(ROOT),
                    "--product",
                    "Test",
                    "--session-review",
                    "-session-review.json",
                    "--output",
                    str(output),
                    "--generate-only",
                    "--skip-dd-import",
                    "--coverage-threshold",
                    "0",
                ],
                capture_output=True,
                text=True,
                check=False,
                cwd=root,
            )

        self.assertEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
