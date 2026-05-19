#!/usr/bin/env python3
"""Import externally stored audit evidence into local DefectDojo.

This wrapper intentionally contains no audit results, findings, or scanner
artifacts.
Authentication uses DD_API_TOKEN only.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GENERIC_IMPORTER = ROOT / "audit-kit" / "scripts" / "import_defectdojo.py"


def die(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    reports_dir = os.getenv("REPORTS_DIR")
    if not reports_dir:
        die("REPORTS_DIR debe apuntar a evidencia externa; no se almacenan resultados en este repositorio")
    reports_path = Path(reports_dir).expanduser().resolve()
    if not reports_path.exists():
        die(f"REPORTS_DIR no existe: {reports_path}")
    if not os.getenv("DD_API_TOKEN"):
        die("DD_API_TOKEN no esta definido. Genere un token en DefectDojo: http://localhost:8080/api/key-v2")

    env = os.environ.copy()
    env.setdefault("DD_ENGAGEMENT_NAME", "OWASP Top 10:2025 - External Evidence")
    env["REPORTS_DIR"] = str(reports_path)
    raise SystemExit(subprocess.call([sys.executable, str(GENERIC_IMPORTER)], env=env))


if __name__ == "__main__":
    main()
