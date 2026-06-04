from __future__ import annotations

import subprocess
import tempfile
import unittest
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "audit-kit" / "scripts" / "run_owasp_audit.sh"


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def write_api_fuzzing_review(path: Path, status: str = "pass") -> None:
    checks = [
        {"id": "get-users", "status": status, "method": "GET", "path": "/users", "evidence": "200 OK"},
        {"id": "get-me", "status": status, "method": "GET", "path": "/me", "evidence": "200 OK"},
    ]
    payload = {
        "source": "openapi.json",
        "schema": "openapi3",
        "target": "https://staging.example.com/api",
        "authorization": {"dast": True, "active_dast": False, "header_name": "Authorization"},
        "summary": {"total": 2, "passed": 2 if status == "pass" else 0, "failed": 0 if status == "pass" else 2},
        "checks": checks,
        "findings": [] if status == "pass" else [{"id": "get-users", "severity": "medium", "evidence": "500 on invalid schema"}],
    }
    write(path, json.dumps(payload))


def build_pr5_api_fuzzing_command(
    *,
    project: Path,
    spec: Path,
    authorize_dast: bool = False,
    authorize_active_dast: bool = False,
    api_fuzzing_review: Path | None = None,
    extra_args: list[str] | None = None,
) -> list[str]:
    command = [
        "bash",
        str(RUNNER),
        "--project",
        str(project),
        "--product",
        "Test",
        "--target",
        "https://staging.example.com",
    ]
    if authorize_dast:
        command.append("--authorize-dast")
    if authorize_active_dast:
        command.append("--authorize-active-dast")
    command.extend(
        [
            "--openapi-spec",
            str(spec),
            "--api-base-url",
            "https://staging.example.com/api",
            "--auth-header-name",
            "Authorization",
            "--auth-header-value",
            "Bearer secret",
        ]
    )
    if api_fuzzing_review is not None:
        command.extend(["--api-fuzzing-review", str(api_fuzzing_review)])
    if extra_args:
        command.extend(extra_args)
    return command


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


if __name__ == "__main__":
    unittest.main()
