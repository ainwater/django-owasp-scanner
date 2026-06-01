#!/usr/bin/env python3
from __future__ import annotations

import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def parse_scalar(value: str) -> Any:
    value = value.strip()
    if value in {"allow", "deny", "unknown"}:
        return value
    if value in {"true", "false"}:
        return value == "true"
    return value.strip('"\'')


def parse_simple_yaml(text: str) -> Any:
    if text.strip() == "[]":
        return []
    data: dict[str, Any] = {}
    current_list: str | None = None
    current_item: dict[str, Any] | None = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if not line.startswith(" ") and line.endswith(":"):
            current_list = line[:-1]
            data[current_list] = []
            current_item = None
            continue
        if not line.startswith(" ") and ":" in line:
            key, value = line.split(":", 1)
            data[key.strip()] = parse_scalar(value)
            current_list = None
            current_item = None
            continue
        if current_list is None:
            raise RuntimeError(f"Unsupported matrix line: {raw}")
        stripped = line.strip()
        if stripped.startswith("- "):
            item = stripped[2:]
            if ":" in item:
                key, value = item.split(":", 1)
                current_item = {key.strip(): parse_scalar(value)}
                data[current_list].append(current_item)
            else:
                current_item = None
                data[current_list].append(parse_scalar(item))
            continue
        if current_item is None or ":" not in stripped:
            raise RuntimeError(f"Unsupported matrix line: {raw}")
        key, value = stripped.split(":", 1)
        current_item[key.strip()] = parse_scalar(value)
    return data


def load_matrix(path: Path) -> dict[str, Any]:
    try:
        if path.suffix == ".json":
            data = json.loads(path.read_text())
        else:
            data = parse_simple_yaml(path.read_text())
    except Exception as exc:
        raise RuntimeError(f"Failed to load authorization matrix {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeError("authorization matrix must be a mapping")
    checks = data.get("checks")
    if not isinstance(checks, list):
        raise RuntimeError("authorization matrix requires checks list")
    if not checks:
        raise RuntimeError("authorization matrix checks must not be empty")
    return data


def required_text(check: dict[str, Any], field: str, cid: str) -> str:
    value = check.get(field)
    if not isinstance(value, str) or not value.strip():
        raise RuntimeError(f"check {cid} requires non-empty {field}")
    return value.strip()


def enum_value(check: dict[str, Any], field: str, allowed: set[str], cid: str) -> str:
    value = required_text(check, field, cid).lower()
    if value not in allowed:
        raise RuntimeError(f"check {cid} has invalid {field}: {value}")
    return value


def check_id(check: dict[str, Any], index: int) -> str:
    value = check.get("id")
    return str(value) if value else f"check-{index}"


def evaluate(matrix: dict[str, Any], source: Path) -> dict[str, Any]:
    checks = matrix["checks"]
    results = []
    findings = []
    for index, raw in enumerate(checks, 1):
        if not isinstance(raw, dict):
            raise RuntimeError(f"check {index} must be a mapping")
        cid = check_id(raw, index)
        endpoint = required_text(raw, "endpoint", cid)
        role = required_text(raw, "role", cid)
        tenant = required_text(raw, "tenant", cid)
        obj = required_text(raw, "object", cid)
        expected = enum_value(raw, "expected", {"allow", "deny"}, cid)
        observed = enum_value(raw, "observed", {"allow", "deny", "unknown"}, cid)
        status = "pass" if expected and expected == observed else "fail"
        result = {
            "id": cid,
            "endpoint": endpoint,
            "role": role,
            "tenant": tenant,
            "object": obj,
            "expected": expected,
            "observed": observed,
            "status": status,
        }
        results.append(result)
        if status == "fail":
            finding_type = "authorization_bypass" if expected == "deny" and observed == "allow" else "authorization_mismatch"
            findings.append({"check_id": cid, "type": finding_type, "endpoint": result["endpoint"]})
    passed = sum(1 for item in results if item["status"] == "pass")
    failed = len(results) - passed
    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "source": source.name,
        "status": "pass" if failed == 0 else "fail",
        "summary": {"total": len(results), "pass": passed, "fail": failed},
        "results": results,
        "findings": findings,
    }


def run(matrix_path: Path, reports: Path) -> int:
    matrix = load_matrix(matrix_path)
    result = evaluate(matrix, source=matrix_path)
    out_dir = reports / "F2"
    out_dir.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(matrix_path, out_dir / "authz-matrix.yml")
    (out_dir / "authz-results.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return 0 if result["status"] == "pass" else 1


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: authz_matrix.py MATRIX_PATH REPORTS_DIR")
    try:
        raise SystemExit(run(Path(sys.argv[1]), Path(sys.argv[2])))
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
