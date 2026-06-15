from __future__ import annotations

import importlib.util
import os
import stat
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "audit-kit" / "scripts" / "defectdojo_setup.py"
SPEC = importlib.util.spec_from_file_location("defectdojo_setup", SCRIPT)
defectdojo_setup = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(defectdojo_setup)


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


class DefectDojoSetupTest(unittest.TestCase):
    def test_creates_private_env_file_with_required_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dojo = root / "defectdojo"
            dojo.mkdir()

            created = defectdojo_setup.ensure_env(dojo)
            env_file = dojo / ".env"
            content = env_file.read_text()
            mode = stat.S_IMODE(env_file.stat().st_mode)

        self.assertTrue(created)
        self.assertIn("DD_DATABASE_PASSWORD=", content)
        self.assertIn("DD_DATABASE_URL=postgresql://defectdojo:", content)
        self.assertIn("DD_SECRET_KEY=", content)
        self.assertIn("DD_CREDENTIAL_AES_256_KEY=", content)
        self.assertIn("DD_ALLOWED_HOSTS=localhost,127.0.0.1", content)
        self.assertIn("DD_ADMIN_USER=admin", content)
        self.assertIn("DD_ADMIN_PASSWORD=", content)
        self.assertEqual(mode, 0o600)

    def test_existing_env_file_preserves_values_and_adds_missing_admin_password(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dojo = Path(tmp) / "defectdojo"
            write(dojo / ".env", "DD_DATABASE_PASSWORD=existing\n")

            created = defectdojo_setup.ensure_env(dojo)
            content = (dojo / ".env").read_text()

        self.assertFalse(created)
        self.assertIn("DD_DATABASE_PASSWORD=existing\n", content)
        self.assertIn("DD_ADMIN_USER=admin\n", content)
        self.assertIn("DD_ADMIN_PASSWORD=", content)

    def test_extracts_token_from_compose_output(self) -> None:
        output = "noise\nabc123token\n"
        self.assertEqual(defectdojo_setup.extract_token(output), "abc123token")

    def test_rejects_empty_token_output(self) -> None:
        with self.assertRaises(RuntimeError):
            defectdojo_setup.extract_token("\n")

    def test_main_prints_export_without_leaking_token_in_logs(self) -> None:
        class FakeRunner:
            def __init__(self) -> None:
                self.commands: list[list[str]] = []

            def __call__(self, command: list[str], cwd: Path) -> str:
                self.commands.append(command)
                if command[:2] == ["docker", "compose"] and "exec" in command:
                    return "secret-token\n"
                return ""

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            dojo = root / "defectdojo"
            dojo.mkdir()
            fake = FakeRunner()

            result = defectdojo_setup.setup(dojo, runner=fake, wait=False)

        self.assertEqual(result["DD_API_TOKEN"], "secret-token")
        self.assertEqual(result["DD_ADMIN_USER"], "admin")
        self.assertTrue(result["DD_ADMIN_PASSWORD"])
        self.assertTrue(any(command[:3] == ["docker", "compose", "up"] for command in fake.commands))
        self.assertTrue(any("DD_ADMIN_PASSWORD=" in part for command in fake.commands for part in command))

    def test_wait_for_api_retries_until_products_endpoint_is_available(self) -> None:
        class Response:
            def __init__(self, status: int) -> None:
                self.status = status

            def __enter__(self) -> "Response":
                return self

            def __exit__(self, *args: object) -> None:
                return None

        calls = 0

        def opener(request: object, timeout: float) -> Response:
            nonlocal calls
            calls += 1
            if calls == 1:
                return Response(502)
            return Response(200)

        defectdojo_setup.wait_for_api("http://localhost:8080", "token", attempts=2, delay=0, opener=opener)

        self.assertEqual(calls, 2)

    def test_skips_setup_when_token_already_exists(self) -> None:
        class FakeRunner:
            def __call__(self, command: list[str], cwd: Path) -> str:
                raise AssertionError("runner should not be called")

        env = {"DD_API_TOKEN": "existing-token", "DD_URL": "http://localhost:8080"}
        with tempfile.TemporaryDirectory() as tmp:
            result = defectdojo_setup.setup(Path(tmp) / "defectdojo", env=env, runner=FakeRunner())

        self.assertEqual(result["DD_API_TOKEN"], "existing-token")
        self.assertEqual(result["DD_URL"], "http://localhost:8080")


if __name__ == "__main__":
    unittest.main()
