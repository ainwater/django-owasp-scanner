#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import time
from datetime import date
from pathlib import Path
from typing import Any

import requests


DD_URL = os.getenv("DD_URL", "http://localhost:8080").rstrip("/")
DD_API_TOKEN = os.getenv("DD_API_TOKEN", "")
DD_FORCE_IMPORT = os.getenv("DD_FORCE_IMPORT", "false").lower() in {"1", "true", "yes"}
REPORTS = Path(os.getenv("REPORTS_DIR", "reports")).resolve()
SCAN_DATE = os.getenv("DD_SCAN_DATE", date.today().isoformat())
PRODUCT_TYPE_ID = int(os.getenv("DD_PRODUCT_TYPE_ID", "1"))


def die(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    sys.exit(1)


def metadata() -> dict[str, Any]:
    path = REPORTS / "metadata.json"
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


META = metadata()
PRODUCT_NAME = os.getenv("DD_PRODUCT_NAME") or META.get("product") or "Application"
ENGAGEMENT_NAME = os.getenv("DD_ENGAGEMENT_NAME", "OWASP Top 10:2025 - Audit")
BLOCKED_AUTO_IMPORT_LABELS = {"gitleaks", "detect-secrets", "trufflehog"}
RETRY_STATUS_CODES = {502, 503, 504}
RETRY_ATTEMPTS = int(os.getenv("DD_RETRY_ATTEMPTS", "30"))
RETRY_DELAY = float(os.getenv("DD_RETRY_DELAY", "2"))


def request(session: requests.Session, method: str, path: str, **kwargs: Any) -> requests.Response:
    response = None
    for attempt in range(1, RETRY_ATTEMPTS + 1):
        try:
            response = session.request(method, f"{DD_URL}{path}", timeout=120, **kwargs)
        except requests.RequestException as exc:
            if attempt == RETRY_ATTEMPTS:
                die(f"{method} {path} failed: {exc.__class__.__name__}")
            time.sleep(RETRY_DELAY)
            continue
        if response.status_code not in RETRY_STATUS_CODES or attempt == RETRY_ATTEMPTS:
            break
        time.sleep(RETRY_DELAY)
    assert response is not None
    if response.status_code >= 400:
        body = response.text.replace("\n", " ")[:700]
        die(f"{method} {path} failed: HTTP {response.status_code}: {body}")
    return response


def authenticate() -> requests.Session:
    if not DD_API_TOKEN:
        die("DD_API_TOKEN no está definido. Genere un token en DefectDojo: http://localhost:8080/api/key-v2")
    session = requests.Session()
    session.headers.update({"Authorization": f"Token {DD_API_TOKEN}"})
    return session


def first_result(session: requests.Session, path: str, field: str, value: str) -> dict[str, Any] | None:
    response = request(session, "GET", path, params={field: value, "limit": 200})
    for item in response.json().get("results", []):
        if item.get(field) == value:
            return item
    return None


def ensure_product(session: requests.Session) -> dict[str, Any]:
    existing = first_result(session, "/api/v2/products/", "name", PRODUCT_NAME)
    if existing:
        return existing
    response = request(
        session,
        "POST",
        "/api/v2/products/",
        json={
            "name": PRODUCT_NAME,
            "description": f"OWASP Top 10:2025 audit for {PRODUCT_NAME}.",
            "prod_type": PRODUCT_TYPE_ID,
            "tags": ["owasp-2025", "django"],
        },
    )
    return response.json()


def ensure_engagement(session: requests.Session, product_id: int) -> dict[str, Any]:
    response = request(session, "GET", "/api/v2/engagements/", params={"product": product_id, "name": ENGAGEMENT_NAME, "limit": 200})
    for engagement in response.json().get("results", []):
        if engagement.get("name") == ENGAGEMENT_NAME and engagement.get("product") == product_id:
            return engagement
    response = request(
        session,
        "POST",
        "/api/v2/engagements/",
        json={
            "product": product_id,
            "name": ENGAGEMENT_NAME,
            "description": "Reusable OWASP Django Audit Kit import: raw scanner artifacts plus optional curated findings.",
            "target_start": SCAN_DATE,
            "target_end": SCAN_DATE,
            "engagement_type": "CI/CD",
            "status": "Completed",
            "deduplication_on_engagement": True,
            "tags": ["owasp-2025", "django", "audit-kit"],
        },
    )
    return response.json()


def scan_already_imported(session: requests.Session, engagement_id: int, scan_type: str) -> bool:
    response = request(session, "GET", "/api/v2/tests/", params={"engagement": engagement_id, "limit": 500})
    for test in response.json().get("results", []):
        if test.get("scan_type") == scan_type:
            return True
    return False


def content_type(path: Path) -> str:
    if path.suffix == ".xml":
        return "application/xml"
    if path.suffix in {".json", ".jsonl"}:
        return "application/json"
    return "text/plain"


def skipped_artifact_reason(path: Path) -> str:
    try:
        data = json.loads(path.read_text())
    except Exception:
        return ""
    if not isinstance(data, dict):
        return ""
    reason = data.get("error") or data.get("note")
    if not reason:
        return ""
    return str(reason).replace("\n", " ")[:300]


def import_scan(session: requests.Session, engagement_id: int, label: str, relative_path: str, scan_type: str, tags: list[str]) -> str:
    if label.lower() in BLOCKED_AUTO_IMPORT_LABELS:
        print(f"BLOCK {label}: secret-scanner artifacts require review and are not auto-imported")
        return "blocked"
    artifact = REPORTS / relative_path
    if not artifact.exists() or artifact.stat().st_size == 0:
        print(f"SKIP {label}: missing artifact {relative_path}")
        return "skipped"
    reason = skipped_artifact_reason(artifact)
    if reason:
        print(f"SKIP {label}: {reason}")
        return "skipped"
    if not DD_FORCE_IMPORT and scan_already_imported(session, engagement_id, scan_type):
        print(f"SKIP {label}: {scan_type} already imported; set DD_FORCE_IMPORT=true to re-import")
        return "skipped"
    with artifact.open("rb") as handle:
        response = None
        for attempt in range(1, RETRY_ATTEMPTS + 1):
            handle.seek(0)
            response = session.post(
                f"{DD_URL}/api/v2/import-scan/",
                data={
                    "engagement": str(engagement_id),
                    "scan_type": scan_type,
                    "scan_date": SCAN_DATE,
                    "minimum_severity": "Info",
                    "active": "true",
                    "verified": "false",
                    "close_old_findings": "false",
                    "deduplication_on_engagement": "true",
                    "tags": tags,
                },
                files={"file": (artifact.name, handle, content_type(artifact))},
                timeout=180,
            )
            if response.status_code not in RETRY_STATUS_CODES or attempt == RETRY_ATTEMPTS:
                break
            time.sleep(RETRY_DELAY)
    assert response is not None
    if response.status_code in (200, 201):
        print(f"OK import {label}: {scan_type}")
        return "ok"
    print(f"WARN import {label}: HTTP {response.status_code}: {response.text[:500].replace(chr(10), ' ')}")
    return "warn"


def ensure_curated_test(session: requests.Session, engagement_id: int) -> int:
    title = "Validated OWASP Findings"
    response = request(session, "GET", "/api/v2/tests/", params={"engagement": engagement_id, "title": title, "limit": 200})
    for test in response.json().get("results", []):
        if test.get("title") == title:
            return int(test["id"])
    response = request(
        session,
        "POST",
        "/api/v2/tests/",
        json={
            "engagement": engagement_id,
            "test_type": 7,
            "target_start": f"{SCAN_DATE}T00:00:00Z",
            "target_end": f"{SCAN_DATE}T23:59:00Z",
            "title": title,
            "description": "Validated findings curated from automated evidence and code review.",
            "percent_complete": 100,
            "scan_type": "Manual Code Review",
        },
    )
    return int(response.json()["id"])


def curated_findings() -> list[dict[str, Any]]:
    path = REPORTS / "curated-findings.json"
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
    except Exception as exc:
        die(f"invalid curated-findings.json: {exc}")
    if not isinstance(data, list):
        die("curated-findings.json must be a list")
    return data


def upsert_curated_findings(session: requests.Session, test_id: int) -> None:
    findings = curated_findings()
    if not findings:
        print("SKIP curated findings: no reports/curated-findings.json")
        return
    severity_numbers = {"Critical": "S0", "High": "S1", "Medium": "S2", "Low": "S3", "Info": "S4"}
    response = request(session, "GET", "/api/v2/findings/", params={"test": test_id, "limit": 500})
    existing = {finding["title"].strip().lower(): finding["id"] for finding in response.json().get("results", [])}
    created = 0
    updated = 0
    for finding in findings:
        severity = finding.get("severity", "Info")
        payload = {
            "test": test_id,
            "found_by": [7],
            "title": finding["title"],
            "date": SCAN_DATE,
            "severity": severity,
            "description": finding.get("description", ""),
            "mitigation": finding.get("mitigation", ""),
            "impact": finding.get("impact", ""),
            "references": finding.get("references", ""),
            "active": True,
            "verified": True,
            "false_p": False,
            "duplicate": False,
            "out_of_scope": False,
            "risk_accepted": False,
            "static_finding": bool(finding.get("static_finding", True)),
            "dynamic_finding": bool(finding.get("dynamic_finding", False)),
            "numerical_severity": severity_numbers.get(severity, "S4"),
            "cwe": int(finding.get("cwe", 0)),
            "tags": finding.get("tags", ["owasp-2025", "validated"]),
        }
        if finding.get("file_path"):
            payload["file_path"] = finding["file_path"]
        if finding.get("line"):
            payload["line"] = int(finding["line"])
        key = finding["title"].strip().lower()
        if key in existing:
            request(session, "PATCH", f"/api/v2/findings/{existing[key]}/", json=payload)
            updated += 1
        else:
            request(session, "POST", "/api/v2/findings/", json=payload)
            created += 1
    print(f"OK curated findings: created={created} updated={updated}")


def main() -> None:
    if not REPORTS.exists():
        die(f"REPORTS_DIR does not exist: {REPORTS}")
    session = authenticate()
    product = ensure_product(session)
    engagement = ensure_engagement(session, int(product["id"]))
    engagement_id = int(engagement["id"])
    imports = [
        ("Bandit", "F4/bandit.json", "Bandit Scan", ["owasp-2025", "bandit", "sast"]),
        ("Trivy", "F4/trivy.json", "Trivy Scan", ["owasp-2025", "trivy", "sca"]),
        ("Semgrep Django", "F4/semgrep-django.json", "Semgrep JSON Report", ["owasp-2025", "semgrep", "sast"]),
        ("pip-audit", "F4/pip-audit.json", "pip-audit Scan", ["owasp-2025", "pip-audit", "sca"]),
        ("Grype", "F4/grype.json", "Anchore Grype", ["owasp-2025", "grype", "sca"]),
        ("Checkov", "F4/checkov.json", "Checkov Scan", ["owasp-2025", "checkov", "iac"]),
        ("OSV Scanner", "F4/osv-source.json", "OSV Scan", ["owasp-2025", "osv", "sca"]),
        ("CycloneDX SBOM", "F4/sbom-cyclonedx.json", "CycloneDX Scan", ["owasp-2025", "cyclonedx", "sbom"]),
        ("SSLyze", "F4/sslyze.json", "SSLyze Scan (JSON)", ["owasp-2025", "sslyze", "tls"]),
        ("Nuclei", "F6/nuclei-full.json", "Nuclei Scan", ["owasp-2025", "nuclei", "dast"]),
        ("ZAP", "F6/zap-baseline.xml", "ZAP Scan", ["owasp-2025", "zap", "dast"]),
    ]
    import_status: dict[str, int] = {"ok": 0, "skipped": 0, "warn": 0, "blocked": 0}
    for label, relative_path, scan_type, tags in imports:
        status = import_scan(session, engagement_id, label, relative_path, scan_type, tags)
        import_status[status] = import_status.get(status, 0) + 1
    curated_test_id = ensure_curated_test(session, engagement_id)
    upsert_curated_findings(session, curated_test_id)
    print(
        "DefectDojo import summary: "
        f"ok={import_status.get('ok', 0)} "
        f"skipped={import_status.get('skipped', 0)} "
        f"warn={import_status.get('warn', 0)} "
        f"blocked={import_status.get('blocked', 0)}"
    )
    print(f"DefectDojo product: {DD_URL}/product/{product['id']}")
    print(f"DefectDojo findings: {DD_URL}/product/{product['id']}/findings")
    print(f"DefectDojo engagement: {DD_URL}/engagement/{engagement_id}")
    if import_status.get("warn", 0):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
