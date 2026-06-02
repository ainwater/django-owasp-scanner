#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


REQUIRED_CONTROLS = [
    "logout_invalidates_session",
    "session_rotation",
    "enumeration_resistance",
    "mfa_privileged",
    "brute_force_protection",
]


def load_review(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text())
    except OSError as exc:
        raise RuntimeError(f"Failed to load session review {path.name}: {exc.strerror}") from exc
    except UnicodeError as exc:
        raise RuntimeError(f"Failed to decode session review {path.name}: {exc.__class__.__name__}") from exc
    except Exception as exc:
        raise RuntimeError(f"Failed to load session review {path.name}: {exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeError("session review must be a JSON object")
    checks = data.get("checks")
    if not isinstance(checks, list):
        raise RuntimeError("session review requires checks list")
    return data


def checked_rows(review: dict[str, Any]) -> dict[str, dict[str, Any]]:
    rows: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(review["checks"], 1):
        if not isinstance(raw, dict):
            raise RuntimeError(f"check {index} must be a JSON object")
        control = raw.get("id")
        status = raw.get("status")
        evidence = raw.get("evidence")
        if not isinstance(control, str) or not control.strip():
            raise RuntimeError(f"check {index} requires id")
        if status not in {"pass", "fail", "not_applicable"}:
            raise RuntimeError(f"check {control} has invalid status")
        if not isinstance(evidence, str) or not evidence.strip():
            raise RuntimeError(f"check {control} requires evidence")
        if control.strip() in rows:
            raise RuntimeError(f"duplicate check id: {control.strip()}")
        rows[control.strip()] = {"id": control.strip(), "status": status, "evidence": evidence.strip()}
    return rows


def evaluate(review: dict[str, Any], source: Path) -> dict[str, Any]:
    rows_by_id = checked_rows(review)
    results = []
    findings = []
    failed_controls = []
    for control in REQUIRED_CONTROLS:
        row = rows_by_id.get(control)
        status = row["status"] if row else "fail"
        evidence = row["evidence"] if row else "missing required session evidence"
        item = {"id": control, "status": status, "evidence": evidence}
        results.append(item)
        if status != "pass":
            failed_controls.append(control)
            findings.append({"control": control, "evidence": evidence})
    passed = sum(1 for item in results if item["status"] == "pass")
    failed = len(results) - passed
    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "source": source.name,
        "status": "pass" if failed == 0 else "fail",
        "summary": {"total": len(results), "pass": passed, "fail": failed},
        "results": results,
        "failed_controls": failed_controls,
        "findings": findings,
    }


def run(review_path: Path, reports: Path) -> int:
    review = load_review(review_path)
    result = evaluate(review, source=review_path)
    out_dir = reports / "F2"
    out_dir.mkdir(parents=True, exist_ok=True)
    evidence = {"source": review_path.name, "checks": result["results"]}
    (out_dir / "session-security.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    (out_dir / "session-security-results.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return 0 if result["status"] == "pass" else 1


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: session_security.py REVIEW_JSON REPORTS_DIR")
    try:
        raise SystemExit(run(Path(sys.argv[1]), Path(sys.argv[2])))
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
