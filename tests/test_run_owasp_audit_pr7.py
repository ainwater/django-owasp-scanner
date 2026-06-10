from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.runner_test_helpers import RUNNER, make_django_project, make_fake_docker, write


class RunOwaspAuditPr7Test(unittest.TestCase):
    def test_generate_only_with_logging_review_produces_results(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            output = root / "out"
            make_django_project(project)
            review = output / "logging-review.json"
            review.parent.mkdir(parents=True, exist_ok=True)
            review.write_text(json.dumps({
                "checks": [
                    {"id": "security_events_logged", "status": "pass", "evidence": "Login/logout events logged"},
                    {"id": "credentials_redacted", "status": "pass", "evidence": "PII redacted via filter"},
                ],
            }))

            result = subprocess.run(
                [
                    "bash",
                    str(RUNNER),
                    "--project",
                    str(project),
                    "--product",
                    "Test",
                    "--logging-review",
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

            results_path = output / "reports" / "F7" / "logging-review-results.json"

            self.assertEqual(result.returncode, 0)
            self.assertTrue(results_path.exists())
            data = json.loads(results_path.read_text())
            self.assertEqual(data["status"], "pass")

    def test_logging_review_failure_makes_runner_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            output = root / "out"
            make_django_project(project)
            review = output / "logging-review.json"
            review.parent.mkdir(parents=True, exist_ok=True)
            review.write_text(json.dumps({
                "checks": [
                    {"id": "security_events_logged", "status": "fail", "evidence": "No logs found"},
                ],
            }))

            result = subprocess.run(
                [
                    "bash",
                    str(RUNNER),
                    "--project",
                    str(project),
                    "--product",
                    "Test",
                    "--logging-review",
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

            self.assertNotEqual(result.returncode, 0)

    def test_logging_review_step_skipped_without_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            output = root / "out"
            make_django_project(project)

            result = subprocess.run(
                [
                    "bash",
                    str(RUNNER),
                    "--project",
                    str(project),
                    "--product",
                    "Test",
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

            results_path = output / "reports" / "F7" / "logging-review-results.json"

            self.assertEqual(result.returncode, 0)
            self.assertFalse(results_path.exists())

    def test_dry_run_includes_logging_review_in_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            output = root / "out"
            make_django_project(project)
            review = output / "logging-review.json"
            review.parent.mkdir(parents=True, exist_ok=True)
            review.write_text(json.dumps({
                "checks": [
                    {"id": "security_events_logged", "status": "pass", "evidence": "Evidence"},
                ],
            }))

            result = subprocess.run(
                [
                    "bash",
                    str(RUNNER),
                    "--project",
                    str(project),
                    "--product",
                    "Test",
                    "--logging-review",
                    str(review),
                    "--output",
                    str(output),
                    "--dry-run",
                ],
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0)
            self.assertIn("logging-review", result.stdout)

    def test_logging_review_in_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            output = root / "out"
            make_django_project(project)
            review = output / "logging-review.json"
            review.parent.mkdir(parents=True, exist_ok=True)
            review.write_text(json.dumps({
                "checks": [
                    {"id": "security_events_logged", "status": "pass", "evidence": "Events logged"},
                    {"id": "credentials_redacted", "status": "pass", "evidence": "Redaction filter"},
                ],
            }))

            subprocess.run(
                [
                    "bash",
                    str(RUNNER),
                    "--project",
                    str(project),
                    "--product",
                    "Test",
                    "--logging-review",
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

            manifest = json.loads((output / "reports" / "evidence-manifest.json").read_text())

            f7_artifacts = manifest.get("artifacts", {}).get("F7", [])
            results_artifact = [
                a for a in f7_artifacts
                if a["path"] == "F7/logging-review-results.json"
            ]
            self.assertEqual(len(results_artifact), 1)
