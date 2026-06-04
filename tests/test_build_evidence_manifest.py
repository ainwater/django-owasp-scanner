from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "audit-kit" / "scripts" / "build_evidence_manifest.py"
coverage_spec = importlib.util.spec_from_file_location("coverage_gates", SCRIPT.parent / "coverage_gates.py")
coverage_gates = importlib.util.module_from_spec(coverage_spec)
assert coverage_spec and coverage_spec.loader
coverage_spec.loader.exec_module(coverage_gates)
sys.modules["coverage_gates"] = coverage_gates
SPEC = importlib.util.spec_from_file_location("build_evidence_manifest", SCRIPT)
build_evidence_manifest = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
try:
    SPEC.loader.exec_module(build_evidence_manifest)
finally:
    del sys.modules["coverage_gates"]


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data) + "\n")


class BuildEvidenceManifestTest(unittest.TestCase):
    def test_manifest_includes_coverage_gates_and_root_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reports = root / "reports"
            reports.mkdir()
            model = root / "model.json"
            build_evidence_manifest.MODEL = model
            write_json(
                model,
                {
                    "version": "OWASP Top 10:2025",
                    "categories": [
                        {
                            "id": "A01",
                            "name": "Broken Access Control",
                            "automated_evidence": [
                                {"id": "semgrep", "artifacts": ["F4/semgrep.json"], "required": True}
                            ],
                            "manual_evidence": [],
                        }
                    ],
                },
            )
            write_json(
                reports / "metadata.json",
                {
                    "product": "App",
                    "project": str(root / "app"),
                    "settings_module": "config.settings",
                    "target_url": "",
                    "output_dir": str(root),
                    "timestamp": "20260528T000000Z",
                },
            )
            write_json(reports / "F4" / "semgrep.json", {})
            manifest = build_evidence_manifest.build(reports)
            coverage = json.loads((reports / "coverage.json").read_text())
            gates = json.loads((reports / "gates.json").read_text())

        self.assertEqual(manifest["coverage_summary"]["coverage_percent"], 100)
        self.assertEqual(manifest["gates"]["status"], "pass")
        self.assertIn("root", manifest["artifacts"])
        self.assertEqual(
            sorted(item["path"] for item in manifest["artifacts"]["root"]),
            ["coverage.json", "gates.json", "metadata.json", "summary.json"],
        )
        self.assertEqual(coverage, manifest["coverage"])
        self.assertEqual(gates, manifest["gates"])

    def test_manifest_records_missing_root_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            reports = Path(tmp) / "reports"
            reports.mkdir()

            artifacts = build_evidence_manifest.artifact_groups(reports)

        root_artifacts = {item["path"]: item for item in artifacts["root"]}
        self.assertFalse(root_artifacts["metadata.json"]["exists"])
        self.assertFalse(root_artifacts["summary.json"]["exists"])
        self.assertFalse(root_artifacts["coverage.json"]["exists"])
        self.assertFalse(root_artifacts["gates.json"]["exists"])

    def test_manifest_records_pr5_dast_authorization_without_target_url(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reports = root / "reports"
            reports.mkdir()
            model = root / "model.json"
            build_evidence_manifest.MODEL = model
            write_json(
                model,
                {
                    "version": "OWASP Top 10:2025",
                    "categories": [
                        {
                            "id": "A05",
                            "name": "Injection",
                            "automated_evidence": [],
                            "manual_evidence": [
                                {"id": "api_fuzzing", "artifacts": ["F6/api-fuzzing.json", "F6/api-fuzzing-results.json"], "required": True}
                            ],
                        }
                    ],
                },
            )
            write_json(
                reports / "metadata.json",
                {
                    "product": "App",
                    "project": str(root / "app"),
                    "settings_module": "",
                    "target_url": "",
                    "output_dir": str(root),
                    "timestamp": "20260528T000000Z",
                },
            )
            write_json(
                reports / "F6" / "api-fuzzing.json",
                {"authorization": {"dast": True, "active_dast": False, "header_name": "Authorization"}},
            )
            write_json(
                reports / "F6" / "api-fuzzing-results.json",
                {"status": "pass", "authorization": {"dast": True, "active_dast": False, "header_name": "Authorization"}},
            )
            env = {
                "AUDIT_COVERAGE_THRESHOLD": "0",
                "AUDIT_DAST_AUTHORIZED": "true",
                "AUDIT_ACTIVE_DAST_AUTHORIZED": "false",
                "AUDIT_RUN_ZAP": "false",
                "AUDIT_RUN_NUCLEI": "false",
                "AUDIT_RUN_TRUFFLEHOG": "false",
                "SKIP_DD_IMPORT": "true",
                "DD_API_TOKEN": "",
            }
            original = {key: os.environ.get(key) for key in env}
            os.environ.update(env)
            try:
                manifest = build_evidence_manifest.build(reports)
            finally:
                for key, value in original.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value

        self.assertTrue(manifest["authorization"]["dast"])
        self.assertFalse(manifest["authorization"]["active_dast"])

    def test_manifest_does_not_mark_zap_or_nuclei_authorized_without_target_url(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            reports = root / "reports"
            reports.mkdir()
            model = root / "model.json"
            build_evidence_manifest.MODEL = model
            write_json(
                model,
                {
                    "version": "OWASP Top 10:2025",
                    "categories": [
                        {
                            "id": "A05",
                            "name": "Injection",
                            "automated_evidence": [],
                            "manual_evidence": [
                                {"id": "api_fuzzing", "artifacts": ["F6/api-fuzzing.json", "F6/api-fuzzing-results.json"], "required": True}
                            ],
                        }
                    ],
                },
            )
            write_json(
                reports / "metadata.json",
                {
                    "product": "App",
                    "project": str(root / "app"),
                    "settings_module": "",
                    "target_url": "",
                    "output_dir": str(root),
                    "timestamp": "20260528T000000Z",
                },
            )
            write_json(
                reports / "F6" / "api-fuzzing.json",
                {"authorization": {"dast": True, "active_dast": False, "header_name": "Authorization"}},
            )
            write_json(
                reports / "F6" / "api-fuzzing-results.json",
                {"status": "pass", "authorization": {"dast": True, "active_dast": False, "header_name": "Authorization"}},
            )
            env = {
                "AUDIT_COVERAGE_THRESHOLD": "0",
                "AUDIT_DAST_AUTHORIZED": "true",
                "AUDIT_ACTIVE_DAST_AUTHORIZED": "false",
                "AUDIT_RUN_ZAP": "true",
                "AUDIT_RUN_NUCLEI": "true",
                "AUDIT_RUN_TRUFFLEHOG": "false",
                "SKIP_DD_IMPORT": "true",
                "DD_API_TOKEN": "",
            }
            original = {key: os.environ.get(key) for key in env}
            os.environ.update(env)
            try:
                manifest = build_evidence_manifest.build(reports)
            finally:
                for key, value in original.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value

        self.assertTrue(manifest["authorization"]["dast"])
        self.assertFalse(manifest["authorization"]["zap"])
        self.assertFalse(manifest["authorization"]["nuclei"])


if __name__ == "__main__":
    unittest.main()
