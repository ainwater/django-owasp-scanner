#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
MODEL = ROOT / "audit-kit" / "owasp-top10-2025.json"


def load_json(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text())
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def artifact(reports: Path, relative_path: str) -> dict[str, Any]:
    path = reports / relative_path
    item: dict[str, Any] = {"path": relative_path, "exists": path.exists(), "bytes": 0}
    if path.is_file():
        item["bytes"] = path.stat().st_size
        item["sha256"] = digest(path)
    return item


def status_for(reports: Path, paths: list[str], required: bool) -> str:
    checks = [(reports / path).is_file() and (reports / path).stat().st_size > 0 for path in paths]
    present = all(checks) if required else any(checks)
    if present:
        return "present"
    return "missing" if required else "optional_missing"


def evidence(reports: Path, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for item in items:
        paths = [str(path) for path in item.get("artifacts", [])]
        required = bool(item.get("required", False))
        result.append(
            {
                "id": str(item.get("id", "")),
                "required": required,
                "status": status_for(reports, paths, required),
                "artifacts": paths,
            }
        )
    return result


def artifact_groups(reports: Path) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for name in ["F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8"]:
        directory = reports / name
        files = []
        if directory.exists():
            for path in sorted(item for item in directory.rglob("*") if item.is_file()):
                files.append(artifact(reports, path.relative_to(reports).as_posix()))
        groups[name] = files
    return groups


def coverage(reports: Path, model: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for category in model.get("categories", []):
        automated = evidence(reports, category.get("automated_evidence", []))
        manual = evidence(reports, category.get("manual_evidence", []))
        rows.append(
            {
                "id": category.get("id", ""),
                "name": category.get("name", ""),
                "automated": automated,
                "manual": manual,
                "required_manual_missing": [item["id"] for item in manual if item["required"] and item["status"] == "missing"],
            }
        )
    return rows


def is_true(value: str) -> bool:
    return value.lower() in {"1", "true", "yes", "y", "si"}


def build(reports: Path) -> dict[str, Any]:
    metadata = load_json(reports / "metadata.json")
    model = load_json(MODEL)
    product = os.getenv("AUDIT_PRODUCT_NAME") or metadata.get("product") or "Django Application"
    timestamp = metadata.get("timestamp", "")
    dast = bool(metadata.get("target_url")) and is_true(os.getenv("AUDIT_DAST_AUTHORIZED", "false"))
    return {
        "schema_version": "1.0",
        "owasp_version": model.get("version", "OWASP Top 10:2025"),
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "product": product,
        "project": {
            "path": metadata.get("project", ""),
            "settings_module": metadata.get("settings_module", ""),
            "target_url": metadata.get("target_url", ""),
        },
        "run": {
            "output_dir": metadata.get("output_dir", ""),
            "reports_dir": str(reports),
            "timestamp": timestamp,
            "runner": "audit-kit/scripts/run_owasp_audit.sh",
        },
        "authorization": {
            "dast": dast,
            "zap": dast and is_true(os.getenv("AUDIT_RUN_ZAP", "true")),
            "nuclei": dast and is_true(os.getenv("AUDIT_RUN_NUCLEI", "true")),
            "active_dast": is_true(os.getenv("AUDIT_ACTIVE_DAST_AUTHORIZED", "false")),
            "trufflehog": is_true(os.getenv("AUDIT_RUN_TRUFFLEHOG", "false")),
            "defectdojo_import": bool(os.getenv("DD_API_TOKEN")) and not is_true(os.getenv("SKIP_DD_IMPORT", "false")),
        },
        "artifacts": artifact_groups(reports),
        "coverage": coverage(reports, model),
        "manual_signoff": [],
    }


def main() -> None:
    reports = Path(sys.argv[1] if len(sys.argv) > 1 else "reports").resolve()
    if not reports.exists():
        raise SystemExit(f"REPORTS_DIR no existe: {reports}")
    manifest = build(reports)
    output = reports / "evidence-manifest.json"
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(f"Manifest de evidencia: {output}")


if __name__ == "__main__":
    main()
