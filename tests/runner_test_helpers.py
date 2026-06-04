from __future__ import annotations

import json
import shlex
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
