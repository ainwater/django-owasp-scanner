#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


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


def evidence_status(reports: Path, paths: list[str], required: bool) -> str:
    if not paths:
        return "missing" if required else "optional_missing"
    present = [(reports / path).is_file() and (reports / path).stat().st_size > 0 for path in paths]
    if (all(present) if required else any(present)):
        return "present"
    return "missing" if required else "optional_missing"


def result_artifacts_pass(reports: Path, paths: list[str]) -> bool:
    for path in paths:
        if not path.endswith("-results.json"):
            continue
        result_path = reports / path
        if not result_path.is_file() or result_path.stat().st_size == 0:
            continue
        data = load_json(result_path)
        if data.get("status") != "pass":
            return False
    return True


def failed_result_artifacts(reports: Path, rows: list[dict[str, Any]]) -> list[str]:
    failed = []
    for row in rows:
        if not result_artifacts_pass(reports, row["artifacts"]):
            failed.append(row["id"])
    return failed


def evidence_rows(reports: Path, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for item in items:
        paths = [str(path) for path in item.get("artifacts", [])]
        required = bool(item.get("required", False))
        rows.append(
            {
                "id": str(item.get("id", "")),
                "required": required,
                "status": evidence_status(reports, paths, required),
                "artifacts": paths,
            }
        )
    return rows


def percent(present: int, total: int) -> int:
    if total == 0:
        return 100
    return (present * 100) // total


def parse_threshold(value: str) -> int:
    try:
        threshold = int(value)
    except ValueError as exc:
        raise ValueError("coverage threshold must be an integer") from exc
    if threshold < 0 or threshold > 100:
        raise ValueError("coverage threshold must be between 0 and 100")
    return threshold


def evaluate_category(reports: Path, category: dict[str, Any], threshold: int) -> dict[str, Any]:
    automated = evidence_rows(reports, category.get("automated_evidence", []))
    manual = evidence_rows(reports, category.get("manual_evidence", []))
    failed_results = failed_result_artifacts(reports, automated + manual)
    required_automated = [item for item in automated if item["required"]]
    required_manual = [item for item in manual if item["required"]]
    missing_automated = [item["id"] for item in required_automated if item["status"] == "missing"]
    missing_manual = [item["id"] for item in required_manual if item["status"] == "missing"]
    present_automated = len(required_automated) - len(missing_automated)
    present_manual = len(required_manual) - len(missing_manual)
    coverage = percent(present_automated, len(required_automated))
    return {
        "id": category.get("id", ""),
        "name": category.get("name", ""),
        "status": "pass" if coverage >= threshold else "fail",
        "coverage_percent": coverage,
        "required_present": present_automated,
        "required_total": len(required_automated),
        "missing_required": missing_automated,
        "required_manual_present": present_manual,
        "required_manual_total": len(required_manual),
        "failed_results": failed_results,
        "automated": automated,
        "manual": manual,
        "required_manual_missing": missing_manual,
    }


def evaluate(reports: Path, model: dict[str, Any], threshold: int = 80) -> dict[str, Any]:
    categories = [evaluate_category(reports, category, threshold) for category in model.get("categories", [])]
    required_total = sum(category["required_total"] for category in categories)
    required_present = sum(category["required_present"] for category in categories)
    required_manual_total = sum(category["required_manual_total"] for category in categories)
    required_manual_present = sum(category["required_manual_present"] for category in categories)
    coverage = percent(required_present, required_total)
    manual_coverage = percent(required_manual_present, required_manual_total)
    failed = [category["id"] for category in categories if category["status"] == "fail"]
    return {
        "summary": {
            "coverage_percent": coverage,
            "required_present": required_present,
            "required_total": required_total,
            "manual_coverage_percent": manual_coverage,
            "required_manual_present": required_manual_present,
            "required_manual_total": required_manual_total,
        },
        "gates": {
            "status": "pass" if coverage >= threshold and not failed else "fail",
            "threshold": threshold,
            "coverage_percent": coverage,
            "failed_categories": failed,
        },
        "categories": categories,
    }


def write_outputs(reports: Path, result: dict[str, Any]) -> None:
    (reports / "coverage.json").write_text(json.dumps(result["categories"], indent=2, sort_keys=True) + "\n")
    (reports / "gates.json").write_text(json.dumps(result["gates"], indent=2, sort_keys=True) + "\n")


def main() -> None:
    reports = Path(sys.argv[1] if len(sys.argv) > 1 else "reports").resolve()
    threshold = parse_threshold(sys.argv[2] if len(sys.argv) > 2 else "80")
    if not reports.exists():
        raise SystemExit(f"REPORTS_DIR no existe: {reports}")
    result = evaluate(reports, load_json(MODEL, required=True), threshold)
    write_outputs(reports, result)
    print(f"Coverage gates: {result['gates']['status']} ({result['summary']['coverage_percent']}%/{threshold}%)")
    if result["gates"]["status"] != "pass":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
