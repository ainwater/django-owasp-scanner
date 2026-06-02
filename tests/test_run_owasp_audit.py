from __future__ import annotations

import subprocess
import tempfile
import unittest
import os
import shlex
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "audit-kit" / "scripts" / "run_owasp_audit.sh"


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def make_django_project(root: Path) -> None:
    write(root / "manage.py", "")
    write(root / "django" / "__init__.py", "def setup():\n    return None\n")
    write(root / "django" / "conf.py", "class Settings: pass\nsettings = Settings()\n")
    write(root / "django" / "urls.py", "class Pattern:\n    def __init__(self, route): self._route = route\nclass UrlPattern:\n    def __init__(self, route, callback, name=''):\n        self.pattern = Pattern(route); self.callback = callback; self.name = name\ndef path(route, callback, name=''):\n    return UrlPattern(route, callback, name)\n")
    write(root / "app" / "__init__.py", "")
    write(root / "app" / "views.py", "def health(request):\n    return None\n")
    write(root / "app" / "urls.py", "from django.urls import path\nfrom . import views\nurlpatterns = [path('health/', views.health, name='health')]\n")
    write(root / "config" / "__init__.py", "")
    write(root / "config" / "settings.py", "from django.conf import settings\nSECRET_KEY = 'secret'\nDEBUG = False\nALLOWED_HOSTS = ['example.com']\nROOT_URLCONF = 'app.urls'\nINSTALLED_APPS = ['rest_framework', 'app']\nMIDDLEWARE = []\nREST_FRAMEWORK = {'DEFAULT_PERMISSION_CLASSES': ['rest_framework.permissions.IsAuthenticated']}\nfor name, value in list(globals().items()):\n    if name.isupper(): setattr(settings, name, value)\n")


def make_fake_docker(bin_dir: Path) -> None:
    write(
        bin_dir / "docker",
        "#!/usr/bin/env bash\n"
        "if [[ \"$1 $2 $3\" == \"image inspect owasp-audit:latest\" ]]; then exit 0; fi\n"
        "if [[ \"$1\" == \"run\" ]]; then exit 0; fi\n"
        "exit 0\n",
    )
    (bin_dir / "docker").chmod(0o755)


def make_recording_docker(bin_dir: Path, log_path: Path) -> None:
    write(
        bin_dir / "docker",
        "#!/usr/bin/env bash\n"
        f"printf '%s\\n' \"$*\" >> {shlex.quote(str(log_path))}\n"
        "if [[ \"$1 $2 $3\" == \"image inspect owasp-audit:latest\" ]]; then exit 0; fi\n"
        "if [[ \"$1\" == \"run\" ]]; then exit 0; fi\n"
        "exit 0\n",
    )
    (bin_dir / "docker").chmod(0o755)


def write_session_review(path: Path, status: str = "pass") -> None:
    controls = [
        "logout_invalidates_session",
        "session_rotation",
        "enumeration_resistance",
        "mfa_privileged",
        "brute_force_protection",
    ]
    checks = [{"id": control, "status": status, "evidence": f"{control} evidence"} for control in controls]
    write(path, json.dumps({"checks": checks}))


def make_fake_docker_without_image(bin_dir: Path) -> None:
    write(
        bin_dir / "docker",
        "#!/usr/bin/env bash\n"
        "if [[ \"$1\" == \"info\" ]]; then exit 0; fi\n"
        "if [[ \"$1 $2 $3\" == \"image inspect owasp-audit:latest\" ]]; then exit 1; fi\n"
        "if [[ \"$1\" == \"build\" ]]; then exit 23; fi\n"
        "if [[ \"$1\" == \"run\" ]]; then exit 0; fi\n"
        "exit 0\n",
    )
    (bin_dir / "docker").chmod(0o755)


class RunOwaspAuditTest(unittest.TestCase):
    def test_generate_only_returns_one_when_coverage_gate_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [
                    "bash",
                    str(RUNNER),
                    "--project",
                    str(ROOT),
                    "--product",
                    "Test",
                    "--output",
                    tmp,
                    "--generate-only",
                    "--skip-dd-import",
                    "--coverage-threshold",
                    "1",
                ],
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 1)
        self.assertIn("Coverage gates: fail", result.stderr)

    def test_generate_only_returns_nonzero_when_manifest_generation_fails_after_gate_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            blocked_manifest = Path(tmp) / "reports" / "evidence-manifest.json"
            blocked_manifest.mkdir(parents=True)
            result = subprocess.run(
                [
                    "bash",
                    str(RUNNER),
                    "--project",
                    str(ROOT),
                    "--product",
                    "Test",
                    "--output",
                    tmp,
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
        self.assertIn("evidence-manifest generation failed", result.stderr)

    def test_threshold_values_are_decimal_and_range_checked(self) -> None:
        cases = [("000", 0), ("08", 1), ("09", 1), ("100", 1), ("101", 1)]
        for threshold, expected_rc in cases:
            with self.subTest(threshold=threshold), tempfile.TemporaryDirectory() as tmp:
                result = subprocess.run(
                    [
                        "bash",
                        str(RUNNER),
                        "--project",
                        str(ROOT),
                        "--product",
                        "Test",
                        "--output",
                        tmp,
                        "--generate-only",
                        "--skip-dd-import",
                        "--coverage-threshold",
                        threshold,
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )

            self.assertEqual(result.returncode, expected_rc)
            self.assertNotIn("value too great for base", result.stderr)

    def test_header_labels_threshold_not_measured_coverage(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [
                    "bash",
                    str(RUNNER),
                    "--project",
                    str(ROOT),
                    "--product",
                    "Test",
                    "--output",
                    tmp,
                    "--generate-only",
                    "--skip-dd-import",
                    "--coverage-threshold",
                    "0",
                ],
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0)
        self.assertIn("Coverage threshold : 0%", result.stdout)
        self.assertNotIn("Coverage : 0%", result.stdout)

    def test_generate_only_with_settings_writes_django_introspection_artifacts(self) -> None:
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
                    "--settings",
                    "config.settings",
                    "--django-command-prefix",
                    "python3",
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

            settings_path = output / "reports" / "F2" / "django-settings.json"
            urls_path = output / "reports" / "F2" / "django-urls.json"
            settings_exists = settings_path.is_file()
            urls_exists = urls_path.is_file()

        self.assertEqual(result.returncode, 0)
        self.assertTrue(settings_exists)
        self.assertTrue(urls_exists)
        self.assertNotIn("[1/0]", result.stdout)

    def test_generate_only_with_authz_matrix_writes_a01_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            matrix = root / "authz.yml"
            output = root / "out"
            write(
                matrix,
                "version: 1\n"
                "checks:\n"
                "  - id: owner-detail\n"
                "    endpoint: GET /api/items/{id}/\n"
                "    role: owner\n"
                "    tenant: alpha\n"
                "    object: item:own\n"
                "    expected: allow\n"
                "    observed: allow\n",
            )
            result = subprocess.run(
                [
                    "bash",
                    str(RUNNER),
                    "--project",
                    str(ROOT),
                    "--product",
                    "Test",
                    "--authz-matrix",
                    str(matrix),
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
            copied = output / "reports" / "F2" / "authz-matrix.yml"
            results = output / "reports" / "F2" / "authz-results.json"
            copied_exists = copied.is_file()
            payload = json.loads(results.read_text()) if results.exists() else {}

        self.assertEqual(result.returncode, 0)
        self.assertTrue(copied_exists)
        self.assertEqual(payload["status"], "pass")
        self.assertNotIn("[1/0]", result.stdout)

    def test_authz_matrix_failure_makes_runner_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            matrix = root / "authz.yml"
            output = root / "out"
            write(
                matrix,
                "version: 1\n"
                "checks:\n"
                "  - id: cross-tenant-detail\n"
                "    endpoint: GET /api/items/{id}/\n"
                "    role: other_user\n"
                "    tenant: beta\n"
                "    object: item:own\n"
                "    expected: deny\n"
                "    observed: allow\n",
            )
            result = subprocess.run(
                [
                    "bash",
                    str(RUNNER),
                    "--project",
                    str(ROOT),
                    "--product",
                    "Test",
                    "--authz-matrix",
                    str(matrix),
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
            payload = json.loads((output / "reports" / "F2" / "authz-results.json").read_text())

        self.assertEqual(result.returncode, 1)
        self.assertEqual(payload["findings"][0]["type"], "authorization_bypass")
        self.assertIn("authz-matrix", result.stdout)

    def test_generate_only_with_idor_review_copies_manual_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            review = root / "idor.md"
            output = root / "out"
            write(review, "# IDOR Review\n\n- Status: accepted\n")

            result = subprocess.run(
                [
                    "bash",
                    str(RUNNER),
                    "--project",
                    str(ROOT),
                    "--product",
                    "Test",
                    "--idor-review",
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
            copied = output / "reports" / "F5" / "A01-idor-review.md"
            copied_text = copied.read_text() if copied.exists() else ""

        self.assertEqual(result.returncode, 0)
        self.assertIn("Status: accepted", copied_text)

    def test_generate_only_with_session_review_writes_session_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            review = root / "session-review.json"
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
            evidence = output / "reports" / "F2" / "session-security.json"
            results = output / "reports" / "F2" / "session-security-results.json"
            evidence_exists = evidence.is_file()
            payload = json.loads(results.read_text()) if results.exists() else {}

        self.assertEqual(result.returncode, 0)
        self.assertTrue(evidence_exists)
        self.assertEqual(payload["status"], "pass")

    def test_session_review_failure_makes_runner_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            review = root / "session-review.json"
            output = root / "out"
            write_session_review(review, status="fail")

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

        self.assertEqual(result.returncode, 1)
        self.assertIn("session-security", result.stdout)

    def test_session_review_status_does_not_record_private_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            private_dir = root / "private" / "client"
            review = private_dir / "session-review.json"
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
        self.assertNotIn(str(private_dir), status)

    def test_runner_rejects_bundled_authz_templates_as_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [
                    "bash",
                    str(RUNNER),
                    "--project",
                    str(ROOT),
                    "--product",
                    "Test",
                    "--authz-matrix",
                    str(ROOT / "audit-kit" / "templates" / "authz-matrix.example.json"),
                    "--output",
                    tmp,
                    "--generate-only",
                ],
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("template", result.stderr.lower())

    def test_runner_rejects_symlink_to_bundled_authz_template(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            link = Path(tmp) / "authz.yml"
            link.symlink_to(ROOT / "audit-kit" / "templates" / "authz-matrix.example.json")
            result = subprocess.run(
                [
                    "bash",
                    str(RUNNER),
                    "--project",
                    str(ROOT),
                    "--product",
                    "Test",
                    "--authz-matrix",
                    str(link),
                    "--output",
                    str(Path(tmp) / "out"),
                    "--generate-only",
                ],
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("template", result.stderr.lower())

    def test_runner_rejects_bundled_session_templates_as_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [
                    "bash",
                    str(RUNNER),
                    "--project",
                    str(ROOT),
                    "--product",
                    "Test",
                    "--session-review",
                    str(ROOT / "audit-kit" / "templates" / "evidence-manifest.example.json"),
                    "--output",
                    tmp,
                    "--generate-only",
                ],
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("template", result.stderr.lower())

    def test_dast_target_is_not_interpolated_into_http_headers_python(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            output = root / "out"
            fake_bin = root / "bin"
            marker = root / "target-injection"
            make_django_project(project)
            make_fake_docker(fake_bin)
            injected_target = f"https://example.com'), __import__('pathlib').Path({str(marker)!r}).write_text('pwned'), ('"
            env = {**os.environ, "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}"}
            result = subprocess.run(
                [
                    "bash",
                    str(RUNNER),
                    "--project",
                    str(project),
                    "--product",
                    "Test",
                    "--target",
                    injected_target,
                    "--authorize-dast",
                    "--output",
                    str(output),
                    "--skip-dd-import",
                    "--coverage-threshold",
                    "0",
                    "--no-build",
                ],
                capture_output=True,
                text=True,
                check=False,
                env=env,
            )
            marker_exists = marker.exists()

        self.assertFalse(marker_exists)

    def test_introspection_failure_makes_runner_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            output = root / "out"
            project.mkdir()
            write(project / "manage.py", "")
            result = subprocess.run(
                [
                    "bash",
                    str(RUNNER),
                    "--project",
                    str(project),
                    "--product",
                    "Test",
                    "--settings",
                    "missing.settings",
                    "--django-command-prefix",
                    "python3",
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
        self.assertIn("django-introspection", result.stdout)

    def test_introspection_handles_output_path_with_spaces(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            output = root / "out with spaces"
            make_django_project(project)
            result = subprocess.run(
                [
                    "bash",
                    str(RUNNER),
                    "--project",
                    str(project),
                    "--product",
                    "Test",
                    "--settings",
                    "config.settings",
                    "--django-command-prefix",
                    "python3",
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
            settings_exists = (output / "reports" / "F2" / "django-settings.json").is_file()

        self.assertEqual(result.returncode, 0)
        self.assertTrue(settings_exists)

    def test_django_check_failure_makes_full_runner_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            output = root / "out"
            fake_bin = root / "bin"
            make_django_project(project)
            make_fake_docker(fake_bin)
            write(
                project / "manage.py",
                "#!/usr/bin/env python3\n"
                "import sys\n"
                "if sys.argv[1:3] == ['check', '--deploy']:\n    raise SystemExit(7)\n"
                "raise SystemExit(0)\n",
            )
            (project / "manage.py").chmod(0o755)
            env = {**os.environ, "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}"}
            result = subprocess.run(
                [
                    "bash",
                    str(RUNNER),
                    "--project",
                    str(project),
                    "--product",
                    "Test",
                    "--settings",
                    "config.settings",
                    "--django-command-prefix",
                    "python3",
                    "--output",
                    str(output),
                    "--skip-dd-import",
                    "--coverage-threshold",
                    "0",
                    "--no-build",
                ],
                capture_output=True,
                text=True,
                check=False,
                env=env,
            )

        self.assertEqual(result.returncode, 7)
        self.assertIn("django-check-deploy", result.stdout)

    def test_skip_django_checks_skips_introspection_runtime_imports(self) -> None:
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
                    "--settings",
                    "missing.settings",
                    "--django-command-prefix",
                    "python3",
                    "--output",
                    str(output),
                    "--generate-only",
                    "--skip-django-checks",
                    "--skip-dd-import",
                    "--coverage-threshold",
                    "0",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            settings_exists = (output / "reports" / "F2" / "django-settings.json").exists()

        self.assertEqual(result.returncode, 0)
        self.assertFalse(settings_exists)
        self.assertIn("django-introspection", result.stdout)

    def test_unsafe_django_command_prefix_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            project.mkdir()
            result = subprocess.run(
                [
                    "bash",
                    str(RUNNER),
                    "--project",
                    str(project),
                    "--product",
                    "Test",
                    "--settings",
                    "config.settings",
                    "--django-command-prefix",
                    "python3; touch /tmp/owasp-prefix-pwned",
                    "--output",
                    str(Path(tmp) / "out"),
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
        self.assertIn("--django-command-prefix", result.stderr)

    def test_django_command_prefix_rejects_newlines(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            project.mkdir()
            result = subprocess.run(
                [
                    "bash",
                    str(RUNNER),
                    "--project",
                    str(project),
                    "--product",
                    "Test",
                    "--settings",
                    "config.settings",
                    "--django-command-prefix",
                    "python3\ntouch /tmp/owasp-prefix-pwned",
                    "--output",
                    str(Path(tmp) / "out"),
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
        self.assertIn("--django-command-prefix", result.stderr)

    def test_dry_run_marks_introspection_skipped_with_skip_django_checks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            project = Path(tmp) / "project"
            make_django_project(project)
            result = subprocess.run(
                [
                    "bash",
                    str(RUNNER),
                    "--project",
                    str(project),
                    "--product",
                    "Test",
                    "--settings",
                    "config.settings",
                    "--skip-django-checks",
                    "--output",
                    str(Path(tmp) / "out"),
                    "--dry-run",
                ],
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0)
        self.assertRegex(result.stdout, r"2 Django Introspection\s+SKIPPED")
        self.assertNotIn("django-introspection (host)", result.stdout)

    def test_dry_run_does_not_build_missing_toolbox_image(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            fake_bin = root / "bin"
            make_django_project(project)
            make_fake_docker_without_image(fake_bin)
            env = {**os.environ, "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}"}
            result = subprocess.run(
                [
                    "bash",
                    str(RUNNER),
                    "--project",
                    str(project),
                    "--product",
                    "Test",
                    "--settings",
                    "config.settings",
                    "--output",
                    str(root / "out"),
                    "--dry-run",
                ],
                capture_output=True,
                text=True,
                check=False,
                env=env,
            )

        self.assertEqual(result.returncode, 0)
        self.assertIn("docker image  : CONFIGURING", result.stdout)

    def test_dry_run_mentions_custom_semgrep_ruleset(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [
                    "bash",
                    str(RUNNER),
                    "--project",
                    str(ROOT),
                    "--product",
                    "Test",
                    "--output",
                    tmp,
                    "--dry-run",
                ],
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0)
        self.assertIn("audit-kit/semgrep/django-drf.yml", result.stdout)

    def test_dry_run_includes_idor_review_readiness_and_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            review = root / "idor.md"
            review.write_text("# IDOR review\n")
            result = subprocess.run(
                [
                    "bash",
                    str(RUNNER),
                    "--project",
                    str(ROOT),
                    "--product",
                    "Test",
                    "--idor-review",
                    str(review),
                    "--output",
                    str(root / "out"),
                    "--dry-run",
                ],
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0)
        self.assertRegex(result.stdout, r"4b A01 IDOR Review\s+READY")
        self.assertIn("idor-review (host)", result.stdout)

    def test_dry_run_includes_session_review_readiness_and_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            review = root / "session-review.json"
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
                    str(root / "out"),
                    "--dry-run",
                ],
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0)
        self.assertRegex(result.stdout, r"4c A01 Session Security\s+READY")
        self.assertIn("session-security (host)", result.stdout)

    def test_dry_run_readiness_uses_ten_pr_roadmap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [
                    "bash",
                    str(RUNNER),
                    "--project",
                    str(ROOT),
                    "--product",
                    "Test",
                    "--output",
                    tmp,
                    "--dry-run",
                ],
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertEqual(result.returncode, 0)
        self.assertIn("4 Authz & Session", result.stdout)
        self.assertIn("10 Final Report", result.stdout)
        self.assertNotIn("16 Final Audit Package", result.stdout)

    def test_full_run_mounts_custom_semgrep_ruleset_outside_project(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            output = root / "out"
            fake_bin = root / "bin"
            docker_log = root / "docker.log"
            make_django_project(project)
            make_recording_docker(fake_bin, docker_log)
            env = {**os.environ, "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}"}
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
                    "--skip-dd-import",
                    "--skip-dast",
                    "--coverage-threshold",
                    "0",
                    "--no-build",
                ],
                capture_output=True,
                text=True,
                check=False,
                env=env,
            )
            docker_commands = docker_log.read_text()

        self.assertEqual(result.returncode, 0)
        self.assertIn(f"{ROOT / 'audit-kit' / 'semgrep'}:/workspace/audit-kit-semgrep:ro", docker_commands)
        self.assertIn("--config /workspace/audit-kit-semgrep/django-drf.yml", docker_commands)
        self.assertNotIn("/workspace/project/audit-kit/semgrep/django-drf.yml", docker_commands)


if __name__ == "__main__":
    unittest.main()
