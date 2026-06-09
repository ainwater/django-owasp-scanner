from __future__ import annotations

import http.server
import json
import os
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

from tests.runner_test_helpers import RUNNER, make_django_project, make_fake_docker


class SecureHeadersHandler(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self) -> None:
        self.send_response(200)
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Permissions-Policy", "camera=()")
        self.send_header("Set-Cookie", "sessionid=secret-value; Secure; HttpOnly; SameSite=Lax; SecretAttr=private")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return None


class HeaderServer:
    def __enter__(self) -> str:
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), SecureHeadersHandler)
        port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return f"http://127.0.0.1:{port}"

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def build_web_policies_command(
    *,
    project: Path,
    target: str = "https://example.com",
    authorize_dast: bool = False,
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
        target,
    ]
    if authorize_dast:
        command.append("--authorize-dast")
    if extra_args:
        command.extend(extra_args)
    return command


class RunOwaspAuditPr6Test(unittest.TestCase):
    def test_web_policies_produces_artifacts_with_target_and_authorize_dast(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            output = root / "out"
            fake_bin = root / "bin"
            make_django_project(project)
            make_fake_docker(fake_bin)
            env = {**os.environ, "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}"}

            with HeaderServer() as target:
                result = subprocess.run(
                    [
                        *build_web_policies_command(
                            project=project,
                            target=target,
                            authorize_dast=True,
                            extra_args=["--output", str(output), "--skip-dd-import", "--coverage-threshold", "0", "--no-build"],
                        ),
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                    env=env,
                )

            raw_headers = output / "reports" / "F6" / "http-headers.txt"
            evidence = output / "reports" / "F6" / "web-policies.json"
            results_path = output / "reports" / "F6" / "web-policies-results.json"

            self.assertEqual(result.returncode, 0)
            self.assertIn("sessionid=[REDACTED]; Secure; HttpOnly; SameSite=Lax", raw_headers.read_text())
            self.assertNotIn("secret-value", raw_headers.read_text())
            self.assertNotIn("SecretAttr", raw_headers.read_text())
            self.assertNotIn("private", raw_headers.read_text())
            self.assertTrue(evidence.exists())
            self.assertTrue(results_path.exists())
            data = json.loads(results_path.read_text())
            self.assertEqual(data["status"], "pass")

    def test_web_policies_step_skipped_without_target(self) -> None:
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

            evidence = output / "reports" / "F6" / "web-policies.json"

            self.assertEqual(result.returncode, 0)
            self.assertFalse(evidence.exists())

    def test_web_policies_step_skipped_without_authorize_dast(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            output = root / "out"
            fake_bin = root / "bin"
            make_django_project(project)
            make_fake_docker(fake_bin)
            env = {**os.environ, "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}"}

            result = subprocess.run(
                [
                    *build_web_policies_command(
                        project=project,
                        authorize_dast=False,
                        extra_args=["--output", str(output), "--skip-dd-import", "--coverage-threshold", "0", "--no-build"],
                    ),
                ],
                capture_output=True,
                text=True,
                check=False,
                env=env,
            )

            evidence = output / "reports" / "F6" / "web-policies.json"

            self.assertEqual(result.returncode, 0)
            self.assertFalse(evidence.exists())

    def test_dry_run_includes_web_policies_in_plan(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            output = root / "out"
            fake_bin = root / "bin"
            make_django_project(project)
            make_fake_docker(fake_bin)
            env = {**os.environ, "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}"}

            result = subprocess.run(
                [
                    *build_web_policies_command(
                        project=project,
                        authorize_dast=True,
                        extra_args=["--output", str(output), "--dry-run", "--no-build"],
                    ),
                ],
                capture_output=True,
                text=True,
                check=False,
                env=env,
            )

            self.assertEqual(result.returncode, 0)
            self.assertIn("web-policies (host)", result.stdout)

    def test_web_policies_tool_count_includes_new_step(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            project = root / "project"
            output = root / "out"
            fake_bin = root / "bin"
            make_django_project(project)
            make_fake_docker(fake_bin)
            env = {**os.environ, "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}"}

            with HeaderServer() as target:
                result = subprocess.run(
                    [
                        *build_web_policies_command(
                            project=project,
                            target=target,
                            authorize_dast=True,
                            extra_args=["--output", str(output), "--skip-dd-import", "--coverage-threshold", "0", "--no-build"],
                        ),
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                    env=env,
                )

            self.assertEqual(result.returncode, 0)
            self.assertIn("web-policies", result.stdout)

    def test_web_policies_target_not_injected_in_command(self) -> None:
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

            subprocess.run(
                [
                    *build_web_policies_command(
                        project=project,
                        target=injected_target,
                        authorize_dast=True,
                        extra_args=["--output", str(output), "--skip-dd-import", "--coverage-threshold", "0", "--no-build"],
                    ),
                ],
                capture_output=True,
                text=True,
                check=False,
                env=env,
            )
            marker_exists = marker.exists()

            self.assertFalse(marker_exists)
