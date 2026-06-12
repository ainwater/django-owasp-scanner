#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def load_review(path: Path) -> dict[str, Any]:
    try:
        data = json.loads(path.read_text())
    except OSError as exc:
        raise RuntimeError(f"Failed to load supply chain review {path.name}: {exc.strerror}") from exc
    except UnicodeError as exc:
        raise RuntimeError(f"Failed to decode supply chain review {path.name}: {exc.__class__.__name__}") from exc
    except Exception as exc:
        raise RuntimeError(f"Failed to load supply chain review {path.name}: {exc}") from exc
    if not isinstance(data, dict):
        raise RuntimeError("supply chain review must be a JSON object")
    checks = data.get("checks")
    if not isinstance(checks, list):
        raise RuntimeError("supply chain review requires checks list")
    if not checks:
        raise RuntimeError("supply chain review requires at least one check")
    seen: set[str] = set()
    valid_statuses = {"pass", "fail", "warn"}
    for index, raw in enumerate(checks, 1):
        if not isinstance(raw, dict):
            raise RuntimeError(f"check {index} must be a JSON object")
        check_id = raw.get("id")
        status = raw.get("status")
        evidence = raw.get("evidence")
        if not isinstance(check_id, str) or not check_id.strip():
            raise RuntimeError(f"check {index} requires id")
        check_id = check_id.strip()
        if check_id in seen:
            raise RuntimeError(f"duplicate check id: {check_id}")
        seen.add(check_id)
        if status not in valid_statuses:
            raise RuntimeError(f"check {check_id} has invalid status: {status}")
        if not isinstance(evidence, str) or not evidence.strip():
            raise RuntimeError(f"check {check_id} requires evidence")
    return data


def evaluate(review: dict[str, Any], source: Path) -> dict[str, Any]:
    checks = []
    for raw in review["checks"]:
        checks.append({
            "id": raw["id"].strip(),
            "status": raw["status"],
            "evidence": raw["evidence"].strip(),
        })
    failed = [c["id"] for c in checks if c["status"] == "fail"]
    warned = [c["id"] for c in checks if c["status"] == "warn"]
    findings = [
        {"id": c["id"], "evidence": c["evidence"]}
        for c in checks
        if c["status"] != "pass"
    ]
    statuses = [c["status"] for c in checks]
    if "fail" in statuses:
        overall = "fail"
    elif "warn" in statuses:
        overall = "warn"
    else:
        overall = "pass"
    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "source": source.name,
        "status": overall,
        "summary": {
            "total": len(checks),
            "passed": len(checks) - len(failed) - len(warned),
            "warned": len(warned),
            "failed": len(failed),
        },
        "checks": checks,
        "failed_checks": failed,
        "warned_checks": warned,
        "findings": findings,
    }


def run(review_path: Path, reports: Path) -> int:
    review = load_review(review_path)
    result = evaluate(review, review_path)
    out_dir = reports / "F5"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "supply-chain-results.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    if result["status"] == "fail":
        return 1
    return 0


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: supply_chain_review.py REVIEW_JSON REPORTS_DIR")
    try:
        rc = run(Path(sys.argv[1]), Path(sys.argv[2]))
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc
    raise SystemExit(rc)


if __name__ == "__main__":
    main()
