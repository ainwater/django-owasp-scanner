#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import coverage_gates


ROOT = Path(__file__).resolve().parents[2]
MODEL = ROOT / "audit-kit" / "owasp-top10-2025.json"


def load_json(path: Path, required: bool = False) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text())
    except Exception as exc:
        if required:
            raise RuntimeError(f"Failed to load required file {path}: {exc}") from exc
        return {}
    if not isinstance(data, dict):
        if required:
            raise RuntimeError(f"File {path} is not a JSON object")
        return {}
    return data


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


def artifact_groups(reports: Path) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    groups["root"] = [artifact(reports, name) for name in ["metadata.json", "summary.json", "coverage.json", "gates.json"]]
    for name in ["F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8", "status"]:
        directory = reports / name
        files = []
        if directory.exists():
            for path in sorted(item for item in directory.rglob("*") if item.is_file()):
                files.append(artifact(reports, path.relative_to(reports).as_posix()))
        groups[name] = files
    return groups


def is_true(value: str) -> bool:
    return value.lower() in {"1", "true", "yes", "y", "si"}


def relative_to_root(path_str: str) -> str:
    if not path_str:
        return ""
    path = Path(path_str)
    try:
        return path.relative_to(ROOT).as_posix()
    except ValueError:
        return path.name


def load_api_fuzzing_authorization(reports: Path) -> dict[str, Any]:
    results = load_json(reports / "F6" / "api-fuzzing-results.json")
    authorization = results.get("authorization", {})
    if not isinstance(authorization, dict):
        return {}
    return authorization


def build(reports: Path) -> dict[str, Any]:
    metadata = load_json(reports / "metadata.json")
    model = load_json(MODEL, required=True)
    gate_threshold = coverage_gates.parse_threshold(os.getenv("AUDIT_COVERAGE_THRESHOLD", "80"))
    coverage_result = coverage_gates.evaluate(reports, model, gate_threshold)
    coverage_gates.write_outputs(reports, coverage_result)
    product = os.getenv("AUDIT_PRODUCT_NAME") or metadata.get("product") or "Application"
    timestamp = metadata.get("timestamp", "")
    api_fuzzing_authorization = load_api_fuzzing_authorization(reports)
    dast = is_true(os.getenv("AUDIT_DAST_AUTHORIZED", "false")) and (
        bool(metadata.get("target_url")) or bool(api_fuzzing_authorization.get("dast", False))
    )
    active_dast = is_true(os.getenv("AUDIT_ACTIVE_DAST_AUTHORIZED", "false")) and bool(
        api_fuzzing_authorization.get("active_dast", False)
    )
    has_target = bool(metadata.get("target_url"))
    return {
        "schema_version": "1.0",
        "owasp_version": model.get("version", "OWASP Top 10:2025"),
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "product": product,
        "project": {
            "path": relative_to_root(metadata.get("project", "")),
            "settings_module": metadata.get("settings_module", ""),
            "target_url": metadata.get("target_url", ""),
        },
        "run": {
            "output_dir": relative_to_root(metadata.get("output_dir", "")),
            "reports_dir": relative_to_root(str(reports)),
            "timestamp": timestamp,
            "runner": "audit-kit/scripts/run_owasp_audit.sh",
        },
        "authorization": {
            "dast": dast,
            "zap": has_target and dast and is_true(os.getenv("AUDIT_RUN_ZAP", "true")),
            "nuclei": has_target and dast and is_true(os.getenv("AUDIT_RUN_NUCLEI", "true")),
            "active_dast": active_dast,
            "trufflehog": is_true(os.getenv("AUDIT_RUN_TRUFFLEHOG", "false")),
            "defectdojo_import": bool(os.getenv("DD_API_TOKEN")) and not is_true(os.getenv("SKIP_DD_IMPORT", "false")),
        },
        "artifacts": artifact_groups(reports),
        "coverage": coverage_result["categories"],
        "coverage_summary": coverage_result["summary"],
        "gates": coverage_result["gates"],
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
