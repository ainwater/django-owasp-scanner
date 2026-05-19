#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path
from typing import Any


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except Exception:
        return None


def count_jsonl(path: Path) -> int:
    try:
        return sum(1 for line in path.read_text().splitlines() if line.strip())
    except Exception:
        return 0


def parse_statuses(status_dir: Path) -> dict[str, int]:
    counts: Counter[str] = Counter()
    for path in sorted(status_dir.glob("*.status")):
        fields = {}
        for line in path.read_text(errors="replace").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                fields[key] = value
        kind = fields.get("kind", "")
        rc = fields.get("exit_code", "")
        if kind == "skipped":
            counts["skipped"] += 1
        elif rc == "0":
            counts["ok"] += 1
        elif rc == "1":
            counts["findings"] += 1
        else:
            counts["errors"] += 1
    return dict(counts)


def bandit_summary(path: Path) -> dict[str, Any]:
    data = load_json(path)
    if not isinstance(data, dict):
        return {}
    severities = Counter(item.get("issue_severity", "UNKNOWN") for item in data.get("results", []))
    return {"findings": sum(severities.values()), "severity": dict(sorted(severities.items()))}


def ruff_summary(path: Path) -> dict[str, Any]:
    data = load_json(path)
    if not isinstance(data, list):
        return {}
    rules = Counter(item.get("code", "UNKNOWN") for item in data)
    return {"findings": len(data), "top_rules": dict(rules.most_common(8))}


def semgrep_summary(path: Path) -> dict[str, Any]:
    data = load_json(path)
    if not isinstance(data, dict):
        return {}
    results = data.get("results", [])
    severities = Counter(item.get("extra", {}).get("severity", "UNKNOWN") for item in results)
    return {"findings": len(results), "severity": dict(sorted(severities.items()))}


def pip_audit_summary(path: Path) -> dict[str, Any]:
    data = load_json(path)
    if not isinstance(data, dict):
        return {}
    dependencies = data.get("dependencies", [])
    vulns = 0
    packages = 0
    if isinstance(dependencies, list):
        for dep in dependencies:
            dep_vulns = dep.get("vulns", []) if isinstance(dep, dict) else []
            if dep_vulns:
                packages += 1
                vulns += len(dep_vulns)
    return {"vulnerabilities": vulns, "packages_with_vulnerabilities": packages}


def trivy_summary(path: Path) -> dict[str, Any]:
    data = load_json(path)
    if not isinstance(data, dict):
        return {}
    vulnerabilities = 0
    misconfigs = 0
    for result in data.get("Results", []):
        vulnerabilities += len(result.get("Vulnerabilities") or [])
        misconfigs += len(result.get("Misconfigurations") or [])
    return {"vulnerabilities": vulnerabilities, "misconfigurations": misconfigs}


def grype_summary(path: Path) -> dict[str, Any]:
    data = load_json(path)
    if not isinstance(data, dict):
        return {}
    return {"matches": len(data.get("matches", []))}


def syft_summary(path: Path) -> dict[str, Any]:
    data = load_json(path)
    if not isinstance(data, dict):
        return {}
    components = data.get("components")
    artifacts = data.get("artifacts")
    count = len(components) if isinstance(components, list) else len(artifacts or [])
    return {"components": count}


def checkov_summary(path: Path) -> dict[str, Any]:
    data = load_json(path)
    if not isinstance(data, dict):
        return {}
    summary = data.get("summary", {})
    if not isinstance(summary, dict):
        return {}
    return {
        "passed": int(summary.get("passed", 0) or 0),
        "failed": int(summary.get("failed", 0) or 0),
        "skipped": int(summary.get("skipped", 0) or 0),
        "parsing_errors": int(summary.get("parsing_errors", 0) or 0),
    }


def osv_summary(path: Path) -> dict[str, Any]:
    data = load_json(path)
    if not isinstance(data, dict):
        return {}
    vulnerabilities = 0
    packages = 0
    for result in data.get("results", []):
        for package in result.get("packages", []) if isinstance(result, dict) else []:
            vulns = package.get("vulnerabilities", [])
            if vulns:
                packages += 1
                vulnerabilities += len(vulns)
    return {"vulnerabilities": vulnerabilities, "packages_with_vulnerabilities": packages}


def zap_summary(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        root = ET.parse(path).getroot()
    except Exception:
        return {}
    risks = Counter()
    for alert in root.findall(".//alertitem"):
        risk = alert.findtext("riskdesc") or "Unknown"
        risks[risk.split("(", 1)[0].strip()] += 1
    return {"alerts": sum(risks.values()), "risk": dict(sorted(risks.items()))}


def detect_secrets_summary(path: Path) -> dict[str, Any]:
    data = load_json(path)
    if not isinstance(data, dict):
        return {}
    total = 0
    results = data.get("results", {})
    if isinstance(results, dict):
        total = sum(len(items) for items in results.values() if isinstance(items, list))
    return {"potential_secrets": total}


def gitleaks_summary(path: Path) -> dict[str, Any]:
    data = load_json(path)
    if isinstance(data, list):
        return {"potential_secrets": len(data)}
    return {}


def trufflehog_summary(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return {"potential_secrets": count_jsonl(path)}


def artifact_counts(reports: Path) -> dict[str, int]:
    counts = {}
    for directory in ["F1", "F2", "F3", "F4", "F5", "F6", "F7", "F8"]:
        path = reports / directory
        counts[directory] = sum(1 for item in path.rglob("*") if item.is_file()) if path.exists() else 0
    return counts


def build_summary(reports: Path) -> dict[str, Any]:
    return {
        "tool_status": parse_statuses(reports / "status"),
        "artifacts": artifact_counts(reports),
        "sast": {
            "bandit": bandit_summary(reports / "F4" / "bandit.json"),
            "ruff_security": ruff_summary(reports / "F4" / "ruff-security.json"),
            "semgrep_django": semgrep_summary(reports / "F4" / "semgrep-django.json"),
        },
        "sca": {
            "pip_audit": pip_audit_summary(reports / "F4" / "pip-audit.json"),
            "trivy": trivy_summary(reports / "F4" / "trivy.json"),
            "grype": grype_summary(reports / "F4" / "grype.json"),
            "osv_scanner": osv_summary(reports / "F4" / "osv-source.json"),
            "sbom": syft_summary(reports / "F4" / "sbom-cyclonedx.json"),
        },
        "iac": {"checkov": checkov_summary(reports / "F4" / "checkov.json")},
        "secret_scanners_review": {
            "gitleaks": gitleaks_summary(reports / "F4" / "gitleaks.json"),
            "detect_secrets": detect_secrets_summary(reports / "F4" / "detect-secrets.json"),
            "trufflehog": trufflehog_summary(reports / "F4" / "trufflehog.jsonl"),
        },
        "dast_tls": {
            "zap": zap_summary(reports / "F6" / "zap-baseline.xml"),
            "nuclei_matches": count_jsonl(reports / "F6" / "nuclei-full.jsonl"),
            "testssl_artifact": (reports / "F6" / "testssl-full.json").exists(),
            "sslyze_artifact": (reports / "F4" / "sslyze.json").exists(),
        },
    }


def compact(value: dict[str, Any]) -> str:
    return ", ".join(f"{key}={val}" for key, val in value.items()) if value else "sin datos"


def print_summary(summary: dict[str, Any]) -> None:
    print("\n══════════════════════════════════════")
    print("Resumen técnico")
    print("────────────────────")
    print(f"  Herramientas: {compact(summary['tool_status'])}")
    print(f"  SAST Bandit: {compact(summary['sast']['bandit'])}")
    print(f"  SAST Ruff: {compact(summary['sast']['ruff_security'])}")
    print(f"  SAST Semgrep: {compact(summary['sast']['semgrep_django'])}")
    print(f"  SCA pip-audit: {compact(summary['sca']['pip_audit'])}")
    print(f"  SCA Trivy: {compact(summary['sca']['trivy'])}")
    print(f"  SCA Grype: {compact(summary['sca']['grype'])}")
    print(f"  SCA OSV: {compact(summary['sca']['osv_scanner'])}")
    print(f"  SBOM Syft: {compact(summary['sca']['sbom'])}")
    print(f"  IaC Checkov: {compact(summary['iac']['checkov'])}")
    print(f"  DAST ZAP: {compact(summary['dast_tls']['zap'])}")
    print(f"  DAST Nuclei: matches={summary['dast_tls']['nuclei_matches']}")
    print(
        "  Secret scanners: "
        f"gitleaks={summary['secret_scanners_review']['gitleaks'].get('potential_secrets', 0)}, "
        f"detect-secrets={summary['secret_scanners_review']['detect_secrets'].get('potential_secrets', 0)}, "
        f"trufflehog={summary['secret_scanners_review']['trufflehog'].get('potential_secrets', 0)} "
        "(revision requerida; no auto-import)"
    )


def main() -> None:
    reports = Path(sys.argv[1] if len(sys.argv) > 1 else "reports").resolve()
    summary = build_summary(reports)
    (reports / "summary.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print_summary(summary)


if __name__ == "__main__":
    main()
