#!/usr/bin/env python3
from __future__ import annotations

import json
import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def load_review(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text())
    except OSError as exc:
        raise RuntimeError(f"Failed to load API fuzzing review {path.name}: {exc.strerror}") from exc
    except UnicodeError as exc:
        raise RuntimeError(f"Failed to decode API fuzzing review {path.name}: {exc.__class__.__name__}") from exc
    except Exception as exc:
        raise RuntimeError(f"Failed to load API fuzzing review {path.name}: {exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeError("api fuzzing review must be a JSON object")
    checks = data.get("checks")
    if not isinstance(checks, list):
        raise RuntimeError("api fuzzing review requires checks list")
    if not checks:
        raise RuntimeError("api fuzzing review requires at least one check")
    authorization = data.get("authorization", {})
    if not isinstance(authorization, dict):
        raise RuntimeError("api fuzzing review authorization must be a JSON object")
    normalize_authorization(data)
    return data


def checked_rows(review: dict[str, Any]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    rows: list[dict[str, Any]] = []
    for index, raw in enumerate(review["checks"], 1):
        if not isinstance(raw, dict):
            raise RuntimeError(f"check {index} must be a JSON object")
        check_id = raw.get("id")
        status = raw.get("status")
        method = raw.get("method")
        path = raw.get("path")
        evidence = raw.get("evidence")
        if not isinstance(check_id, str) or not check_id.strip():
            raise RuntimeError(f"check {index} requires id")
        check_id = check_id.strip()
        if check_id in seen:
            raise RuntimeError(f"duplicate check id: {check_id}")
        if status not in {"pass", "fail"}:
            raise RuntimeError(f"check {check_id} has invalid status")
        if not isinstance(method, str) or not method.strip():
            raise RuntimeError(f"check {check_id} requires method")
        if not isinstance(path, str) or not path.strip():
            raise RuntimeError(f"check {check_id} requires path")
        if not isinstance(evidence, str) or not evidence.strip():
            raise RuntimeError(f"check {check_id} requires evidence")
        seen.add(check_id)
        rows.append(
            {
                "id": check_id,
                "status": status,
                "method": method.strip(),
                "path": path.strip(),
                "evidence": evidence.strip(),
            }
        )
    return rows


def normalize_authorization(review: dict[str, Any]) -> dict[str, Any]:
    authorization = review.get("authorization", {})
    dast = authorization.get("dast", False)
    active_dast = authorization.get("active_dast", False)
    header_name = authorization.get("header_name", "")
    if not isinstance(dast, bool):
        raise RuntimeError("authorization.dast must be boolean")
    if not isinstance(active_dast, bool):
        raise RuntimeError("authorization.active_dast must be boolean")
    if not isinstance(header_name, str):
        raise RuntimeError("authorization.header_name must be a string")
    if not dast:
        raise RuntimeError("authorization.dast must be true")
    return {
        "dast": dast,
        "active_dast": active_dast,
        "header_name": header_name.strip(),
    }


def review_requires_active_dast(review: dict[str, Any]) -> bool:
    return normalize_authorization(review)["active_dast"]


def evaluate(review: dict[str, Any], source: Path) -> dict[str, Any]:
    checks = checked_rows(review)
    authorization = normalize_authorization(review)
    failed = [item["id"] for item in checks if item["status"] == "fail"]
    findings = [
        {
            "id": item["id"],
            "method": item["method"],
            "path": item["path"],
            "evidence": item["evidence"],
        }
        for item in checks
        if item["status"] == "fail"
    ]
    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "source": source.name,
        "status": "pass" if not failed else "fail",
        "summary": {"total": len(checks), "passed": len(checks) - len(failed), "failed": len(failed)},
        "authorization": authorization,
        "checks": checks,
        "failed_checks": failed,
        "findings": findings,
    }


def run(review_path: Path, reports: Path) -> int:
    review = load_review(review_path)
    result = evaluate(review, review_path)
    out_dir = reports / "F6"
    out_dir.mkdir(parents=True, exist_ok=True)
    evidence = {
        "source": result["source"],
        "schema": review.get("schema", "openapi3"),
        "target": review.get("target", ""),
        "authorization": result["authorization"],
        "checks": result["checks"],
    }
    (out_dir / "api-fuzzing.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    (out_dir / "api-fuzzing-results.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return 0 if result["status"] == "pass" else 1


def main_for_args(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--requires-active-dast", dest="requires_active_dast")
    parser.add_argument("args", nargs="*")
    parsed = parser.parse_args(argv)
    if parsed.requires_active_dast:
        try:
            review = load_review(Path(parsed.requires_active_dast))
        except RuntimeError as exc:
            raise SystemExit(2) from exc
        return 0 if review_requires_active_dast(review) else 1
    if len(parsed.args) != 2:
        raise SystemExit("usage: api_fuzzing.py REVIEW_JSON REPORTS_DIR")
    try:
        return run(Path(parsed.args[0]), Path(parsed.args[1]))
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc


def main() -> None:
    raise SystemExit(main_for_args(sys.argv[1:]))


if __name__ == "__main__":
    main()
