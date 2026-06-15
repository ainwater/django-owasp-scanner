#!/usr/bin/env python3
from __future__ import annotations

import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, Any


Runner = Callable[[list[str], Path], str]
UrlOpener = Callable[[urllib.request.Request, float], Any]


def run_command(command: list[str], cwd: Path) -> str:
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        stderr = result.stderr.strip().replace("\n", " ")[:700]
        raise RuntimeError(f"command failed ({result.returncode}): {' '.join(command)}: {stderr}")
    return result.stdout


def token_hex(length: int) -> str:
    return secrets.token_hex(length)


def read_env_file(env_file: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not env_file.exists():
        return values
    for line in env_file.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        values[key] = value.strip().strip('"').strip("'")
    return values


def ensure_env(defectdojo_dir: Path) -> bool:
    defectdojo_dir.mkdir(parents=True, exist_ok=True)
    env_file = defectdojo_dir / ".env"
    if env_file.exists():
        env_file.chmod(0o600)
        values = read_env_file(env_file)
        additions = []
        if not values.get("DD_ADMIN_USER"):
            additions.append("DD_ADMIN_USER=admin")
        if not values.get("DD_ADMIN_PASSWORD"):
            additions.append(f"DD_ADMIN_PASSWORD={token_hex(16)}")
        if additions:
            with env_file.open("a") as handle:
                if env_file.stat().st_size > 0 and not env_file.read_text().endswith("\n"):
                    handle.write("\n")
                handle.write("\n".join(additions) + "\n")
        return False
    password = token_hex(24)
    admin_password = token_hex(16)
    content = "".join(
        [
            f"DD_DATABASE_PASSWORD={password}\n",
            f"DD_DATABASE_URL=postgresql://defectdojo:{password}@postgres:5432/defectdojo\n",
            f"DD_SECRET_KEY={token_hex(50)}\n",
            f"DD_CREDENTIAL_AES_256_KEY={token_hex(32)}\n",
            "DD_ALLOWED_HOSTS=localhost,127.0.0.1\n",
            "DD_ADMIN_USER=admin\n",
            f"DD_ADMIN_PASSWORD={admin_password}\n",
        ]
    )
    fd = os.open(env_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(content)
    return True


def extract_token(output: str) -> str:
    for line in reversed(output.splitlines()):
        token = line.strip()
        if token:
            return token
    raise RuntimeError("DefectDojo token command returned empty output")


def wait_for_uwsgi(defectdojo_dir: Path, runner: Runner, attempts: int = 60, delay: float = 2.0) -> None:
    for _ in range(attempts):
        try:
            runner(["docker", "compose", "exec", "-T", "uwsgi", "python", "manage.py", "check"], defectdojo_dir)
            return
        except RuntimeError:
            time.sleep(delay)
    raise RuntimeError("DefectDojo uwsgi did not become ready")


def open_api_request(request: urllib.request.Request, timeout: float) -> Any:
    return urllib.request.urlopen(request, timeout=timeout)


def wait_for_api(
    dd_url: str,
    token: str,
    *,
    attempts: int = 90,
    delay: float = 2.0,
    opener: UrlOpener = open_api_request,
) -> None:
    url = f"{dd_url.rstrip('/')}/api/v2/products/?limit=1"
    request = urllib.request.Request(url, headers={"Authorization": f"Token {token}", "Accept": "application/json"})
    last_error = "unknown"
    for _ in range(attempts):
        try:
            with opener(request, 10) as response:
                if 200 <= int(response.status) < 300:
                    return
                last_error = f"HTTP {response.status}"
        except urllib.error.HTTPError as exc:
            last_error = f"HTTP {exc.code}"
            if exc.fp:
                exc.fp.close()
            if exc.code in {401, 403}:
                raise RuntimeError(f"DefectDojo API authentication failed: {last_error}") from exc
        except Exception as exc:
            last_error = exc.__class__.__name__
        time.sleep(delay)
    raise RuntimeError(f"DefectDojo API did not become ready: {last_error}")


def get_api_token(defectdojo_dir: Path, runner: Runner, username: str = "admin") -> str:
    command = [
        "docker",
        "compose",
        "exec",
        "-T",
        "-e",
        f"DD_ADMIN_USER={username}",
        "uwsgi",
        "python",
        "manage.py",
        "shell",
        "-c",
        "import os; "
        "from django.contrib.auth import get_user_model; "
        "from rest_framework.authtoken.models import Token; "
        "u=get_user_model().objects.get(username=os.environ.get('DD_ADMIN_USER', 'admin')); "
        "t,_=Token.objects.get_or_create(user=u); print(t.key)",
    ]
    return extract_token(runner(command, defectdojo_dir))


def get_admin_credentials(defectdojo_dir: Path) -> dict[str, str]:
    values = read_env_file(defectdojo_dir / ".env")
    return {
        "DD_ADMIN_USER": values.get("DD_ADMIN_USER", "admin"),
        "DD_ADMIN_PASSWORD": values.get("DD_ADMIN_PASSWORD", ""),
    }


def set_admin_password(defectdojo_dir: Path, runner: Runner, username: str, password: str) -> None:
    if not password:
        return
    command = [
        "docker",
        "compose",
        "exec",
        "-T",
        "-e",
        f"DD_ADMIN_USER={username}",
        "-e",
        f"DD_ADMIN_PASSWORD={password}",
        "uwsgi",
        "python",
        "manage.py",
        "shell",
        "-c",
        "import os; "
        "from django.contrib.auth import get_user_model; "
        "u=get_user_model().objects.get(username=os.environ.get('DD_ADMIN_USER', 'admin')); "
        "u.set_password(os.environ['DD_ADMIN_PASSWORD']); u.save()",
    ]
    runner(command, defectdojo_dir)


def setup(
    defectdojo_dir: Path,
    *,
    env: dict[str, str] | None = None,
    runner: Runner = run_command,
    wait: bool = True,
) -> dict[str, str]:
    current_env = env if env is not None else os.environ
    existing_token = current_env.get("DD_API_TOKEN", "")
    dd_url = current_env.get("DD_URL", "http://localhost:8080")
    if existing_token:
        return {"DD_API_TOKEN": existing_token, "DD_URL": dd_url, "created_env": "false", "started": "false"}
    created_env = ensure_env(defectdojo_dir)
    admin = get_admin_credentials(defectdojo_dir)
    runner(["docker", "compose", "up", "-d"], defectdojo_dir)
    if wait:
        wait_for_uwsgi(defectdojo_dir, runner)
    token = get_api_token(defectdojo_dir, runner, admin["DD_ADMIN_USER"])
    set_admin_password(defectdojo_dir, runner, admin["DD_ADMIN_USER"], admin["DD_ADMIN_PASSWORD"])
    if wait:
        wait_for_api(dd_url, token)
    return {
        "DD_API_TOKEN": token,
        "DD_URL": dd_url,
        "DD_ADMIN_USER": admin["DD_ADMIN_USER"],
        "DD_ADMIN_PASSWORD": admin["DD_ADMIN_PASSWORD"],
        "created_env": str(created_env).lower(),
        "started": "true",
    }


def main() -> None:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).resolve().parents[2])
    defectdojo_dir = root / "defectdojo"
    try:
        result = setup(defectdojo_dir)
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc
    print(f"DD_URL={result['DD_URL']}")
    print(f"DD_API_TOKEN={result['DD_API_TOKEN']}")
    print(f"DD_ADMIN_USER={result.get('DD_ADMIN_USER', 'admin')}")
    print(f"DD_ADMIN_PASSWORD={result.get('DD_ADMIN_PASSWORD', '')}")


if __name__ == "__main__":
    main()
