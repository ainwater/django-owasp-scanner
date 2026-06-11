from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.runner_test_helpers import RUNNER, make_django_project, write


class RunOwaspAuditPr8Test(unittest.TestCase):
    def test_generate_only_with_threat_model_review_produces_results(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            output = root / "out"
            make_django_project(project)
            review = output / "review.json"
            review.parent.mkdir(parents=True, exist_ok=True)
            review.write_text(json.dumps({
                "checks": [
                    {"id": "threat_model_documented", "status": "pass", "evidence": "Covered"},
                    {"id": "upload_type_validation", "status": "pass", "evidence": "Whitelist"},
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
                    "--threat-model-review",
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

            results_path = output / "reports" / "F3" / "threat-model-results.json"

            self.assertEqual(result.returncode, 0)
            self.assertTrue(results_path.exists())
            data = json.loads(results_path.read_text())
            self.assertEqual(data["status"], "pass")

    def test_threat_model_review_failure_affects_runner(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            output = root / "out"
            make_django_project(project)
            review = output / "review.json"
            review.parent.mkdir(parents=True, exist_ok=True)
            review.write_text(json.dumps({
                "checks": [
                    {"id": "threat_model_documented", "status": "fail", "evidence": "Missing"},
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
                    "--threat-model-review",
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

    def test_threat_model_review_skipped_without_review(self) -> None:
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

            results_path = output / "reports" / "F3" / "threat-model-results.json"
            self.assertFalse(results_path.exists())

    def test_dry_run_includes_threat_model_review_in_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            output = root / "out"
            make_django_project(project)
            review = output / "review.json"
            review.parent.mkdir(parents=True, exist_ok=True)
            review.write_text(json.dumps({
                "checks": [
                    {"id": "threat_model_documented", "status": "pass", "evidence": "Done"},
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
                    "--threat-model-review",
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
            self.assertIn("threat-model-review", result.stdout)

    def test_threat_model_review_in_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            output = root / "out"
            make_django_project(project)
            review = output / "review.json"
            review.parent.mkdir(parents=True, exist_ok=True)
            review.write_text(json.dumps({
                "checks": [
                    {"id": "threat_model_documented", "status": "pass", "evidence": "Covered"},
                    {"id": "deserialization_safe", "status": "pass", "evidence": "No pickle"},
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
                    "--threat-model-review",
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
            f3_artifacts = manifest.get("artifacts", {}).get("F3", [])
            results_artifact = [a for a in f3_artifacts if a["path"] == "F3/threat-model-results.json"]
            self.assertEqual(len(results_artifact), 1)
