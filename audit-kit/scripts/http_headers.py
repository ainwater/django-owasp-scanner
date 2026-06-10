#!/usr/bin/env python3
from __future__ import annotations

import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def parse_raw_headers(text: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    set_cookie_count = 0
    known_errors = {"URLError", "HTTPError", "TimeoutError", "ConnectionError", "OSError"}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ": " not in line:
            first_word = line.split()[0] if line.split() else ""
            if first_word in known_errors:
                headers["_error"] = line
            continue
        key, _, value = line.partition(": ")
        key = key.strip().lower()
        value = value.strip()
        if key == "" or value == "":
            continue
        if key == "set-cookie" and key in headers:
            set_cookie_count += 1
            key = f"_set-cookie_{set_cookie_count}"
        headers[key] = value
    if not headers:
        raise RuntimeError("empty headers file, no parseable header lines found")
    return headers


def parse_hsts_max_age(value: str) -> int:
    match = re.search(r"max-age=(\d+)", value, re.IGNORECASE)
    return int(match.group(1)) if match else 0


def classify_severity(statuses: list[str]) -> str:
    if "fail" in statuses:
        return "fail"
    if "warn" in statuses:
        return "warn"
    return "pass"


def check_hsts(headers: dict[str, str], is_https: bool, has_error: bool) -> dict[str, Any]:
    header_name = "Strict-Transport-Security"
    value = headers.get("strict-transport-security", "")
    if has_error:
        return {
            "id": "hsts",
            "header": header_name,
            "status": "fail",
            "value": None,
            "finding": "Target unreachable, cannot verify HSTS",
        }
    if not value:
        return {
            "id": "hsts",
            "header": header_name,
            "status": "fail" if is_https else "warn",
            "value": None,
            "finding": "HSTS header missing" + (" on HTTPS" if is_https else " on HTTP"),
        }
    max_age = parse_hsts_max_age(value)
    if max_age == 0:
        return {
            "id": "hsts",
            "header": header_name,
            "status": "fail",
            "value": value,
            "finding": "HSTS max-age is 0, effectively disabling HSTS",
        }
    has_include = "includesubdomains" in value.lower()
    has_preload = "preload" in value.lower()
    if max_age >= 31536000:
        finding = f"HSTS max-age={max_age}s (>1y)"
        if has_include:
            finding += " with includeSubDomains"
        if has_preload:
            finding += " and preload"
        return {
            "id": "hsts",
            "header": header_name,
            "status": "pass",
            "value": value,
            "finding": finding,
        }
    return {
        "id": "hsts",
        "header": header_name,
        "status": "warn",
        "value": value,
        "finding": f"HSTS max-age={max_age}s is less than 1 year (31536000s)",
    }


def check_csp(headers: dict[str, str]) -> dict[str, Any]:
    header_name = "Content-Security-Policy"
    csp = headers.get("content-security-policy", "")
    csp_report_only = headers.get("content-security-policy-report-only", "")
    if csp:
        value = csp
        has_unsafe_inline = "unsafe-inline" in csp
        has_unsafe_eval = "unsafe-eval" in csp
        if has_unsafe_inline or has_unsafe_eval:
            directives = []
            if has_unsafe_inline:
                directives.append("unsafe-inline")
            if has_unsafe_eval:
                directives.append("unsafe-eval")
            return {
                "id": "csp",
                "header": header_name,
                "status": "warn",
                "value": value,
                "finding": f"CSP present but contains {' and '.join(directives)}",
            }
        return {
            "id": "csp",
            "header": header_name,
            "status": "pass",
            "value": value,
            "finding": "CSP present without unsafe-inline or unsafe-eval",
        }
    if csp_report_only:
        return {
            "id": "csp",
            "header": header_name,
            "status": "fail",
            "value": csp_report_only,
            "finding": "Only Content-Security-Policy-Report-Only present, not enforced",
        }
    return {
        "id": "csp",
        "header": header_name,
        "status": "fail",
        "value": None,
        "finding": "CSP header missing, no content security policy enforced",
    }


def check_x_content_type_options(headers: dict[str, str]) -> dict[str, Any]:
    header_name = "X-Content-Type-Options"
    value = headers.get("x-content-type-options", "")
    if value.lower() == "nosniff":
        return {
            "id": "x_content_type_options",
            "header": header_name,
            "status": "pass",
            "value": value,
            "finding": "X-Content-Type-Options set to nosniff",
        }
    return {
        "id": "x_content_type_options",
        "header": header_name,
        "status": "fail",
        "value": value or None,
        "finding": "X-Content-Type-Options missing, MIME sniffing possible",
    }


def check_x_frame_options(headers: dict[str, str]) -> dict[str, Any]:
    header_name = "X-Frame-Options"
    value = headers.get("x-frame-options", "")
    if value.upper() in {"DENY", "SAMEORIGIN"}:
        return {
            "id": "x_frame_options",
            "header": header_name,
            "status": "pass",
            "value": value,
            "finding": f"X-Frame-Options set to {value.upper()}",
        }
    return {
        "id": "x_frame_options",
        "header": header_name,
        "status": "warn",
        "value": value or None,
        "finding": "X-Frame-Options missing, clickjacking risk" if not value else f"X-Frame-Options has unexpected value: {value}",
    }


def check_referrer_policy(headers: dict[str, str]) -> dict[str, Any]:
    header_name = "Referrer-Policy"
    value = headers.get("referrer-policy", "")
    recommended = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}
    if not value:
        return {
            "id": "referrer_policy",
            "header": header_name,
            "status": "warn",
            "value": None,
            "finding": "Referrer-Policy missing, referrer information may leak",
        }
    if value.lower() == "unsafe-url":
        return {
            "id": "referrer_policy",
            "header": header_name,
            "status": "fail",
            "value": value,
            "finding": "Referrer-Policy set to unsafe-url, full URL leaked in referrer",
        }
    if value.lower() in recommended:
        return {
            "id": "referrer_policy",
            "header": header_name,
            "status": "pass",
            "value": value,
            "finding": f"Referrer-Policy set to recommended value: {value}",
        }
    return {
        "id": "referrer_policy",
        "header": header_name,
        "status": "pass",
        "value": value,
        "finding": f"Referrer-Policy present: {value}",
    }


def check_permissions_policy(headers: dict[str, str]) -> dict[str, Any]:
    header_name = "Permissions-Policy"
    value = headers.get("permissions-policy", "")
    if value:
        return {
            "id": "permissions_policy",
            "header": header_name,
            "status": "pass",
            "value": value,
            "finding": "Permissions-Policy present",
        }
    return {
        "id": "permissions_policy",
        "header": header_name,
        "status": "warn",
        "value": None,
        "finding": "Permissions-Policy missing, browser features unrestricted",
    }


def check_cors(headers: dict[str, str]) -> dict[str, Any]:
    header_name = "Access-Control-Allow-Origin"
    origin = headers.get("access-control-allow-origin", "")
    credentials = headers.get("access-control-allow-credentials", "")
    if not origin:
        return {
            "id": "cors",
            "header": header_name,
            "status": "pass",
            "value": None,
            "finding": "No CORS headers exposed",
        }
    if origin == "*" and credentials.lower() == "true":
        return {
            "id": "cors",
            "header": header_name,
            "status": "fail",
            "value": f"{origin} (credentials: {credentials})",
            "finding": "CORS allows wildcard origin with credentials, dangerous misconfiguration",
        }
    if origin == "*":
        return {
            "id": "cors",
            "header": header_name,
            "status": "warn",
            "value": origin,
            "finding": "CORS allows wildcard origin but without credentials",
        }
    return {
        "id": "cors",
        "header": header_name,
        "status": "pass",
        "value": origin,
        "finding": f"CORS allows specific origin: {origin}",
    }


def parse_cookie_attributes(value: str) -> dict[str, bool]:
    attrs: dict[str, bool] = {"Secure": False, "HttpOnly": False, "SameSite": False}
    if value == "[REDACTED]":
        attrs["_redacted"] = True
        return attrs
    parts = [p.strip() for p in value.split(";")]
    for part in parts[1:]:
        part_lower = part.lower()
        if part_lower == "secure":
            attrs["Secure"] = True
        elif part_lower == "httponly":
            attrs["HttpOnly"] = True
        elif part_lower.startswith("samesite"):
            attrs["SameSite"] = True
            samesite_value = part.split("=", 1)[1].strip() if "=" in part else ""
            attrs["SameSiteValue"] = samesite_value
    return attrs


def check_cookies(headers: dict[str, str]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    cookie_keys = ["set-cookie"] + sorted(
        [k for k in headers if k.startswith("_set-cookie_")],
        key=lambda k: int(k.rsplit("_", 1)[1]),
    )
    if not any(k in headers for k in cookie_keys):
        return [{
            "id": "cookies",
            "header": "Set-Cookie",
            "status": "pass",
            "value": None,
            "finding": "No Set-Cookie headers in response",
        }]
    for idx, key in enumerate(cookie_keys):
        if key not in headers:
            continue
        value = headers[key]
        check_id = "cookies" if idx == 0 else f"cookies_{idx}"
        attrs = parse_cookie_attributes(value)
        if attrs.get("_redacted"):
            results.append({
                "id": check_id,
                "header": "Set-Cookie",
                "status": "warn",
                "value": "[REDACTED]",
                "finding": "Set-Cookie value fully redacted, cookie attributes not analyzed",
            })
            continue
        missing = []
        if not attrs["Secure"]:
            missing.append("Secure")
        if not attrs["HttpOnly"]:
            missing.append("HttpOnly")
        if not attrs["SameSite"]:
            missing.append("SameSite")
        same_value = attrs.get("SameSiteValue", "")
        same_none_no_secure = same_value and same_value.lower() == "none" and not attrs["Secure"]
        if same_none_no_secure:
            return results + [{
                "id": check_id,
                "header": "Set-Cookie",
                "status": "fail",
                "value": value,
                "finding": "SameSite=None requires Secure flag",
            }]
        if "Secure" in missing:
            results.append({
                "id": check_id,
                "header": "Set-Cookie",
                "status": "fail",
                "value": value,
                "finding": f"Set-Cookie missing flags: {', '.join(missing)}",
            })
        elif missing:
            results.append({
                "id": check_id,
                "header": "Set-Cookie",
                "status": "warn",
                "value": value,
                "finding": f"Set-Cookie missing flags: {', '.join(missing)}",
            })
        else:
            results.append({
                "id": check_id,
                "header": "Set-Cookie",
                "status": "pass",
                "value": value,
                "finding": "Set-Cookie has Secure, HttpOnly, SameSite",
            })
    return results


def evaluate(url: str, headers: dict[str, str]) -> dict[str, Any]:
    has_error = "_error" in headers or headers.get("status", "").startswith("URLError") or any(
        k.startswith("urlerror") or k.startswith("httperror") or k.startswith("timeouterror")
        for k in headers
    )
    is_https = url.startswith("https://")

    hsts = check_hsts(headers, is_https, has_error)
    csp = check_csp(headers)
    x_content = check_x_content_type_options(headers)
    x_frame = check_x_frame_options(headers)
    referrer = check_referrer_policy(headers)
    permissions = check_permissions_policy(headers)
    cors = check_cors(headers)
    cookie_results = check_cookies(headers)

    checks = [hsts, csp, x_content, x_frame, referrer, permissions, cors] + cookie_results
    all_statuses = [c["status"] for c in checks]
    failed = [c["id"] for c in checks if c["status"] == "fail"]
    warned = [c["id"] for c in checks if c["status"] == "warn"]

    findings = [
        {"id": c["id"], "header": c["header"], "finding": c["finding"]}
        for c in checks
        if c["status"] in {"fail", "warn"}
    ]

    summary = {
        "total": len(checks),
        "passed": len(checks) - len(failed) - len(warned),
        "warned": len(warned),
        "failed": len(failed),
    }

    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "source": url,
        "status": classify_severity(all_statuses),
        "summary": summary,
        "checks": checks,
        "failed_checks": failed,
        "warned_checks": warned,
        "findings": findings,
    }


def run(url: str, raw_headers_file: Path, reports: Path) -> int:
    if not raw_headers_file.exists():
        raise RuntimeError(f"Raw headers file not found: {raw_headers_file}")
    text = raw_headers_file.read_text().strip()
    if not text:
        raise RuntimeError("Raw headers file is empty")
    headers = parse_raw_headers(text)
    result = evaluate(url, headers)
    out_dir = reports / "F6"
    out_dir.mkdir(parents=True, exist_ok=True)
    evidence = {
        "source": result["source"],
        "checks": result["checks"],
    }
    (out_dir / "web-policies.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
    (out_dir / "web-policies-results.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    if result["status"] == "fail":
        return 1
    return 0


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit("usage: http_headers.py TARGET_URL RAW_HEADERS_FILE REPORTS_DIR")
    try:
        rc = run(sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3]))
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc
    raise SystemExit(rc)


if __name__ == "__main__":
    main()
