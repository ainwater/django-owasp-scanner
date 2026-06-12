#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def load_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text())
    except Exception:
        return default


def parse_status(status_dir: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    if not status_dir.exists():
        return rows
    for path in sorted(status_dir.glob("*.status")):
        fields: dict[str, str] = {}
        for line in path.read_text(errors="replace").splitlines():
            if "=" in line:
                key, _, value = line.partition("=")
                fields[key] = value
        name = path.stem.rsplit(".", 1)[0] if "." in path.stem else path.stem
        kind = fields.get("kind", "unknown")
        rc = fields.get("exit_code", "")
        if kind == "skipped":
            status_text = "skipped"
        elif rc == "0":
            status_text = "pass"
        elif rc == "1":
            status_text = "findings"
        else:
            status_text = f"error (exit {rc})"
        rows.append({"tool": name, "kind": kind, "status": status_text})
    return rows


def status_icon(status: str) -> str:
    if status == "pass":
        return "✅"
    if status == "findings":
        return "⚠️"
    if status == "skipped":
        return "⏭️"
    return "❌"


def generate_markdown(metadata: dict[str, Any], gates: dict[str, Any], coverage: list[dict[str, Any]], summary: dict[str, Any], manifest: dict[str, Any], status_rows: list[dict[str, str]]) -> str:
    product = metadata.get("product") or manifest.get("product") or "Application"
    timestamp = metadata.get("timestamp") or manifest.get("run", {}).get("timestamp", "")
    target = metadata.get("target_url") or manifest.get("project", {}).get("target_url", "")
    coverage_pct = gates.get("coverage_percent", "N/A")
    threshold = gates.get("threshold", "N/A")
    gate_status = gates.get("status", "unknown")
    auth = manifest.get("authorization", {})
    dast = "yes" if auth.get("dast") else "no"
    zap = "yes" if auth.get("zap") else "no"
    active = "yes" if auth.get("active_dast") else "no"

    lines: list[str] = []
    lines.append(f"# OWASP Top 10:2025 Audit Report")
    lines.append("")
    lines.append(f"**Product:** {product}  ")
    lines.append(f"**Target:** {target or 'N/A'}  ")
    lines.append(f"**Date:** {timestamp or 'N/A'}  ")
    lines.append(f"**Runner:** audit-kit/scripts/run_owasp_audit.sh  ")
    lines.append("")

    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Coverage | {coverage_pct}% (threshold: {threshold}%) |")
    lines.append(f"| Gates | {gate_status} |")
    lines.append(f"| DAST Authorized | {dast} |")
    lines.append(f"| ZAP | {zap} |")
    lines.append(f"| Active DAST | {active} |")
    lines.append("")
    lines.append(f"OWASP Top 10:2025 coverage gates: **{gate_status.upper()}** at {coverage_pct}% coverage (minimum {threshold}%).")
    if gate_status == "fail":
        failed_categories = gates.get("failed_categories", [])
        lines.append(f"Failed categories: {', '.join(failed_categories)}" if failed_categories else "No failed categories.")
    lines.append("")

    lines.append("## Coverage by Category")
    lines.append("")
    lines.append("| Category | Status | Coverage | Required | Present | Missing |")
    lines.append("|----------|--------|----------|----------|---------|---------|")
    if isinstance(coverage, list):
        for cat in coverage:
            cat_id = cat.get("id", "")
            cat_name = cat.get("name", "")
            cat_status = cat.get("status", "unknown")
            cat_cov = cat.get("coverage_percent", 0)
            req_total = cat.get("required_total", 0)
            req_present = cat.get("required_present", 0)
            missing = ", ".join(cat.get("missing_required", [])) or "-"
            failed = ", ".join(cat.get("failed_results", [])) or "-"
            emoji = "✅" if cat_status == "pass" else "❌"
            lines.append(f"| {cat_id} - {cat_name} | {emoji} {cat_status} | {cat_cov}% | {req_total} | {req_present} | {missing} |")
            if cat.get("failed_results"):
                lines.append(f"| | | | | | Failed results: {failed} |")
    else:
        lines.append("| | | | | | (no coverage data) |")
    lines.append("")

    lines.append("## Tool Execution Summary")
    lines.append("")
    lines.append("| Tool | Status |")
    lines.append("|------|--------|")
    for row in status_rows:
        emoji = status_icon(row["status"])
        lines.append(f"| {row['tool']} | {emoji} {row['status']} |")
    if not status_rows:
        lines.append("| | (no status data) |")
    lines.append("")

    lines.append("## Authorization")
    lines.append("")
    lines.append(f"- **DAST authorized:** {dast}")
    lines.append(f"- **ZAP baseline:** {zap}")
    lines.append(f"- **Nuclei:** {'yes' if auth.get('nuclei') else 'no'}")
    lines.append(f"- **Active DAST:** {active}")
    lines.append(f"- **TruffleHog:** {'yes' if auth.get('trufflehog') else 'no'}")
    lines.append(f"- **DefectDojo import:** {'yes' if auth.get('defectdojo_import') else 'no'}")
    lines.append("")

    lines.append("## Automated Evidence")
    lines.append("")
    lines.append("*SAST, SCA, IaC, and DAST findings are available in the detailed scanner output under `reports/F4/`, `reports/F6/`.*")
    lines.append("")
    lines.append("Refer to `evidence-manifest.json` for the complete artifact inventory with SHA-256 hashes.")
    lines.append("")

    lines.append("## Recommendations")
    lines.append("")
    lines.append("1. Review all **failed coverage categories** above and address missing evidence.")
    lines.append("2. Examine **secret scanner results** in `reports/F4/gitleaks.json`, `detect-secrets.json`, and `trufflehog.jsonl`.")
    lines.append("3. Validate manual evidence for all applicable OWASP categories.")
    lines.append("4. Import results to **DefectDojo** for centralized vulnerability management: `python3 audit-kit/scripts/import_defectdojo.py`")
    lines.append("")
    lines.append("---")
    lines.append(f"*Report generated by OWASP Django Audit Kit on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}*")
    lines.append("")

    return "\n".join(lines)


def markdown_to_html(md: str) -> str:
    html = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OWASP Audit Report</title>
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; line-height: 1.6; color: #1a1a1a; }
h1 { border-bottom: 3px solid #2563eb; padding-bottom: 8px; }
h2 { border-bottom: 2px solid #e5e7eb; padding-bottom: 6px; margin-top: 32px; }
table { border-collapse: collapse; width: 100%; margin: 12px 0; }
th, td { border: 1px solid #e5e7eb; padding: 8px 12px; text-align: left; }
th { background: #f3f4f6; font-weight: 600; }
code { background: #f3f4f6; padding: 2px 6px; border-radius: 4px; }
hr { border: none; border-top: 1px solid #e5e7eb; margin: 32px 0; }
</style>
</head>
<body>
"""
    in_table = False
    in_code = False
    for line in md.splitlines():
        stripped = line.strip()
        if stripped.startswith("# ") and not in_code:
            html += f"<h1>{stripped[2:]}</h1>\n"
        elif stripped.startswith("## ") and not in_code:
            html += f"<h2>{stripped[3:]}</h2>\n"
        elif stripped.startswith("|") and not in_code:
            if not in_table:
                html += "<table>\n"
                in_table = True
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            is_sep = all(set(c) <= {" ", "-"} for c in cells)
            if is_sep:
                continue
            tag = "th" if in_table and html.rstrip().endswith("<table>") else "td"
            html += "<tr>" + "".join(f"<{tag}>{c}</{tag}>" for c in cells) + "</tr>\n"
        else:
            if in_table:
                html += "</table>\n"
                in_table = False
            if stripped.startswith("```"):
                in_code = not in_code
                html += "<pre><code>" if not in_code else "</code></pre>\n"
            elif stripped.startswith("---"):
                html += "<hr>\n"
            elif stripped.startswith("* ") and stripped.endswith("*"):
                html += f"<p><em>{stripped[2:-1]}</em></p>\n"
            elif stripped.startswith("**") and stripped.endswith("**"):
                html += f"<p><strong>{stripped[2:-2]}</strong></p>\n"
            elif stripped.startswith("- "):
                html += f"<li>{stripped[2:]}</li>\n"
            elif stripped:
                processed = stripped
                processed = processed.replace("**", "")
                html += f"<p>{processed}</p>\n"
    if in_table:
        html += "</table>\n"
    html += "</body>\n</html>\n"
    return html


def generate(reports: Path, fmt: str = "md") -> str:
    metadata = load_json(reports / "metadata.json", default={})
    gates = load_json(reports / "gates.json", default={})
    coverage = load_json(reports / "coverage.json", default=[])
    summary = load_json(reports / "summary.json", default={})
    manifest = load_json(reports / "evidence-manifest.json", default={})
    status_rows = parse_status(reports / "status")

    md = generate_markdown(metadata, gates, coverage, summary, manifest, status_rows)
    if fmt == "html":
        return markdown_to_html(md)
    return md


def run(reports: Path, output: Path) -> int:
    md = generate(reports, "md")
    html = generate(reports, "html")
    output.mkdir(parents=True, exist_ok=True)
    (output / "owasp-audit-report.md").write_text(md)
    (output / "owasp-audit-report.html").write_text(html)
    return 0


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: final_report.py REPORTS_DIR OUTPUT_DIR")
    try:
        rc = run(Path(sys.argv[1]), Path(sys.argv[2]))
        print(f"Final report written to {sys.argv[2]}/")
    except RuntimeError as exc:
        raise SystemExit(str(exc)) from exc
    raise SystemExit(rc)


if __name__ == "__main__":
    main()
