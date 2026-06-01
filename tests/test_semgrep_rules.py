from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "audit-kit" / "semgrep" / "django-drf.yml"
IMAGE = os.environ.get("AUDIT_DOCKER_IMAGE", "owasp-audit:latest")
REQUIRED_RULE_IDS = {
    "django.auth-weak-password-hasher",
    "django.csrf-exempt",
    "django.mark-safe",
    "django.raw-sql",
    "drf.allow-any",
    "python.pickle-load",
    "python.yaml-load-unsafe",
}


def toolbox_available() -> bool:
    if shutil.which("docker") is None:
        return False
    return subprocess.run(["docker", "image", "inspect", IMAGE], capture_output=True, text=True, check=False).returncode == 0


def semgrep_command(src: Path, vulnerable: Path, safe: Path) -> list[str]:
    if shutil.which("semgrep"):
        return ["semgrep", "--config", str(RULES), "--json", str(vulnerable), str(safe)]
    if toolbox_available():
        return [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{RULES.parent}:/rules:ro",
            "-v",
            f"{src}:/src:ro",
            IMAGE,
            "-lc",
            "semgrep --config /rules/django-drf.yml --json /src/vulnerable.py /src/safe.py",
        ]
    raise unittest.SkipTest("Semgrep not available locally and Docker image not available")


def semgrep_rule_id(check_id: str) -> str:
    for prefix in ("audit-kit.semgrep.", "rules."):
        if check_id.startswith(prefix):
            return check_id.removeprefix(prefix)
    return check_id


def rule_ids(path: Path) -> set[str]:
    if not path.is_file():
        raise AssertionError(f"ruleset missing: {path}")
    content = path.read_text()
    return set(re.findall(r"(?m)^\s*-?\s*id:\s*([a-z0-9_.-]+)\s*$", content))


class SemgrepRulesTest(unittest.TestCase):
    def rule_blocks(self) -> list[str]:
        content = RULES.read_text()
        return ["id: " + block for block in re.split(r"(?m)^\s*-\s+id:\s*", content)[1:]]

    def test_ruleset_exists_and_defines_required_rule_ids(self) -> None:
        ids = rule_ids(RULES)
        self.assertTrue(REQUIRED_RULE_IDS <= ids, f"missing rules: {sorted(REQUIRED_RULE_IDS - ids)}")

    def test_missing_ruleset_fails_with_clear_assertion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / "missing.yml"
            with self.assertRaisesRegex(AssertionError, "ruleset missing"):
                rule_ids(missing)

    def test_ruleset_uses_owasp_metadata(self) -> None:
        for block in self.rule_blocks():
            rule_id = re.search(r"id:\s*([a-z0-9_.-]+)", block).group(1)
            with self.subTest(rule=rule_id):
                self.assertIn("severity:", block)
                self.assertIn("metadata:", block)
                self.assertIn("category: security", block)
                self.assertIn("owasp: \"2025\"", block)
                self.assertNotIn("TODO", block)

    def test_ruleset_covers_common_drf_allowany_forms(self) -> None:
        content = RULES.read_text()

        self.assertIn("permission_classes = [permissions.AllowAny]", content)
        self.assertIn("@permission_classes([permissions.AllowAny])", content)

    def test_pickle_rule_is_not_generic_loads_sink(self) -> None:
        content = RULES.read_text()

        self.assertIn("pickle.load(...)", content)
        self.assertIn("pickle.loads(...)", content)
        self.assertNotIn("$PICKLE.load", content)
        self.assertNotIn("$PICKLE.loads", content)

    def test_semgrep_command_prefers_local_semgrep(self) -> None:
        with mock.patch("shutil.which", return_value="/usr/bin/semgrep"):
            command = semgrep_command(Path("/src"), Path("/src/vulnerable.py"), Path("/src/safe.py"))

        self.assertEqual(
            command,
            ["semgrep", "--config", str(RULES), "--json", "/src/vulnerable.py", "/src/safe.py"],
        )

    def test_semgrep_rule_id_accepts_local_config_prefix(self) -> None:
        self.assertEqual(semgrep_rule_id("audit-kit.semgrep.django.csrf-exempt"), "django.csrf-exempt")

    def test_toolbox_semgrep_matches_representative_fixtures(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            vulnerable = Path(tmp) / "vulnerable.py"
            safe = Path(tmp) / "safe.py"
            vulnerable_source = (
                "from django.utils.decorators import method_decorator\n"
                "from django.views.decorators.csrf import csrf_exempt\n"
                "from django.utils.safestring import mark_safe\n"
                "from rest_framework.decorators import permission_classes\n"
                "from rest_framework import permissions\n"
                "from rest_framework.permissions import AllowAny, IsAuthenticated\n"
                "import pickle\n"
                "import yaml\n\n"
                "@csrf_exempt\n"
                "def insecure_function(request):\n"
                "    return None\n\n"
                "@method_decorator(csrf_exempt, name='dispatch')\n"
                "class InsecureView(object):\n"
                "    pass\n\n"
                "def sql(cursor, name):\n"
                "    cursor.execute('select * from users')\n"
                "    cursor.execute(f'select * from users where name = {name}')\n\n"
                "def unsafe_html(value):\n"
                "    return mark_safe(value)\n\n"
                "def deserialize(value):\n"
                "    pickle.loads(value)\n"
                "    yaml.load(value)\n"
                "    yaml.load(value, Loader=yaml.SafeLoader)\n\n"
                "    yaml.load(value, Loader=yaml.CSafeLoader)\n"
                "    yaml.load(value, Loader=CSafeLoader)\n\n"
                "    yaml.load(value, yaml.SafeLoader)\n"
                "    yaml.load(value, SafeLoader)\n\n"
                "@permission_classes([permissions.AllowAny])\n"
                "def public_view(request):\n"
                "    return None\n\n"
                "permission_classes = [permissions.AllowAny]\n"
                "permission_classes = [AllowAny, IsAuthenticated]\n"
                "permission_classes = [permissions.AllowAny, permissions.IsAuthenticated]\n"
                "@permission_classes([AllowAny, IsAuthenticated])\n"
                "def mixed_public_view(request):\n"
                "    return None\n\n"
                "PASSWORD_HASHERS = ['django.contrib.auth.hashers.MD5PasswordHasher']\n"
            )
            safe_source = (
                "from django.utils.decorators import method_decorator\n"
                "from rest_framework.permissions import IsAuthenticated\n"
                "import json\n"
                "import yaml\n\n"
                "def normal_view(request):\n"
                "    return None\n\n"
                "def safe_sql(cursor, name):\n"
                "    cursor.execute('select * from users where name = %s', [name])\n\n"
                "def safe_deserialize(value):\n"
                "    json.loads(value)\n"
                "    yaml.safe_load(value)\n"
                "    yaml.load(value, Loader=yaml.SafeLoader)\n"
                "    yaml.load(value, Loader=yaml.CSafeLoader)\n\n"
                "    yaml.load(value, yaml.SafeLoader)\n"
                "    yaml.load(value, SafeLoader)\n\n"
                "permission_classes = [IsAuthenticated]\n"
                "PASSWORD_HASHERS = ['django.contrib.auth.hashers.PBKDF2PasswordHasher']\n"
            )
            vulnerable.write_text(vulnerable_source)
            safe.write_text(safe_source)
            line_for = {line.strip(): number for number, line in enumerate(vulnerable_source.splitlines(), 1)}
            command = semgrep_command(Path(tmp), vulnerable, safe)

            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,
            )

        self.assertIn(result.returncode, {0, 1}, result.stderr)
        payload = json.loads(result.stdout)
        findings = payload.get("results", [])
        ids = {semgrep_rule_id(str(finding.get("check_id", ""))) for finding in findings}
        safe_findings = [finding for finding in findings if str(finding.get("path", "")).endswith("safe.py")]

        self.assertIn("django.csrf-exempt", ids)
        self.assertIn("django.raw-sql", ids)
        self.assertIn("django.mark-safe", ids)
        self.assertIn("python.pickle-load", ids)
        self.assertIn("python.yaml-load-unsafe", ids)
        self.assertIn("drf.allow-any", ids)
        self.assertIn("django.auth-weak-password-hasher", ids)
        self.assertGreaterEqual(sum(1 for f in findings if semgrep_rule_id(str(f.get("check_id", ""))) == "django.csrf-exempt"), 2)
        self.assertIn(line_for["cursor.execute('select * from users')"], {f.get("start", {}).get("line") for f in findings if semgrep_rule_id(str(f.get("check_id", ""))) == "django.raw-sql"})
        yaml_lines = {f.get("start", {}).get("line") for f in findings if semgrep_rule_id(str(f.get("check_id", ""))) == "python.yaml-load-unsafe"}
        self.assertNotIn(line_for["yaml.load(value, Loader=yaml.SafeLoader)"], yaml_lines)
        self.assertNotIn(line_for["yaml.load(value, Loader=yaml.CSafeLoader)"], yaml_lines)
        self.assertNotIn(line_for["yaml.load(value, Loader=CSafeLoader)"], yaml_lines)
        self.assertNotIn(line_for["yaml.load(value, yaml.SafeLoader)"], yaml_lines)
        self.assertNotIn(line_for["yaml.load(value, SafeLoader)"], yaml_lines)
        allowany_lines = {f.get("start", {}).get("line") for f in findings if semgrep_rule_id(str(f.get("check_id", ""))) == "drf.allow-any"}
        self.assertIn(line_for["permission_classes = [AllowAny, IsAuthenticated]"], allowany_lines)
        self.assertIn(line_for["permission_classes = [permissions.AllowAny, permissions.IsAuthenticated]"], allowany_lines)
        self.assertIn(line_for["@permission_classes([AllowAny, IsAuthenticated])"], allowany_lines)
        self.assertEqual(safe_findings, [])


if __name__ == "__main__":
    unittest.main()
