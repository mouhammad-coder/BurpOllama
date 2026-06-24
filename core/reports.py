"""Generate reports from durable standalone scan records."""

from __future__ import annotations

import json
from pathlib import Path

from reporter import generate_csv_report, generate_json_report, generate_sarif_report


def _findings(scan: dict) -> list[dict]:
    return (
        scan.get("triaged_findings")
        or scan.get("findings")
        or scan.get("raw_findings")
        or []
    )


def _artifact(finding: dict) -> dict:
    value = finding.get("evidence_artifact") or {}
    return value if isinstance(value, dict) else {}


def _artifact_value(finding: dict, key: str, fallback: str = "") -> str:
    artifact = _artifact(finding)
    value = artifact.get(key)
    if value is None and isinstance(artifact.get("metadata"), dict):
        value = artifact["metadata"].get(key)
    if value is None:
        value = finding.get(key, fallback)
    return str(value or fallback)


def _artifact_path(finding: dict) -> str:
    return _artifact_value(finding, "artifact_path", "not available")


def _severity(value: str) -> str:
    normalized = str(value or "Low").strip().lower()
    return {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Low",
        "informational": "Low",
    }.get(normalized, normalized.title() or "Low")


def _is_confirmed(finding: dict) -> bool:
    return str(finding.get("exploitability_status", "")).lower() == "confirmed"


def _needs_manual_review(finding: dict) -> bool:
    return str(finding.get("exploitability_status", "")).lower() in {
        "candidate",
        "needs_manual_validation",
    }


def _remediation(finding: dict) -> str:
    label = " ".join(
        str(finding.get(key, ""))
        for key in ("vuln_type", "title")
    ).lower()
    indicator = _artifact_value(finding, "matched_indicator", "").strip()
    header = indicator.split(":", 1)[0].strip() if indicator else "required"
    if "missing" in label and "header" in label:
        return "Add the {} response header.".format(header)
    if "cors" in label:
        return "Restrict ACAO to trusted origins."
    if "rate limit" in label or "rate-limit" in label:
        return "Implement rate limiting on this endpoint."
    if "ssrf" in label:
        return "Validate and whitelist server-side URL inputs."
    if "open redirect" in label or "redirect" in label:
        return "Validate redirect targets against an allowlist."
    if "jwt" in label or "alg=none" in label:
        return "Reject tokens with alg=none."
    if "cookie" in label or "session" in label:
        return "Set HttpOnly, Secure, and SameSite on session cookies."
    return "Validate the vulnerable behavior and apply a targeted server-side fix."


def render_marketplace_report(scan: dict, platform: str) -> str:
    target = str(scan.get("target") or "")
    findings = _findings(scan)
    confirmed = [finding for finding in findings if _is_confirmed(finding)]
    candidates = [finding for finding in findings if not _is_confirmed(finding) and _needs_manual_review(finding)]
    platform_name = "HackerOne" if platform == "hackerone" else "Bugcrowd"
    lines = [
        "# {} Submission Report".format(platform_name),
        "",
        "Target: {}".format(target or "not recorded"),
        "",
    ]
    if not confirmed:
        lines.extend([
            "No confirmed findings are ready for submission.",
            "",
        ])
    for finding in confirmed:
        artifact = _artifact(finding)
        indicator = _artifact_value(finding, "matched_indicator", finding.get("evidence", ""))
        location = _artifact_value(finding, "indicator_location", "evidence artifact")
        artifact_path = _artifact_path(finding)
        vuln_class = str(artifact.get("vuln_class") or finding.get("vuln_type") or "vulnerability")
        title = str(finding.get("title") or vuln_class)
        severity = _severity(finding.get("severity", "Low"))
        impact = str(artifact.get("impact") or finding.get("business_impact") or finding.get("impact") or "Impact requires review.")
        url = str(finding.get("url") or finding.get("affected_url") or target)
        lines.extend([
            "## [{}] {}".format(severity, title),
            "",
            "### Summary",
            "{} was observed at {} with indicator {}.".format(vuln_class, location, indicator),
            "",
            "### Severity",
            severity,
            "",
            "### Steps to Reproduce",
            "1. Navigate to: {}".format(url),
            "2. Observe: {} in {}".format(indicator, location),
            "3. Evidence artifact: {}".format(artifact_path),
            "",
            "### Impact",
            impact,
            "",
            "### Supporting Evidence",
            "- Artifact file: {}".format(artifact_path),
            "- Indicator: {}".format(indicator),
            "- Location: {}".format(location),
            "",
            "### Remediation",
            _remediation(finding),
            "",
        ])
    if candidates:
        lines.extend([
            "## Candidates Requiring Manual Validation",
            "",
        ])
        for finding in candidates:
            lines.append("- {} | URL: {} | Confidence: {} | Artifact: {}".format(
                finding.get("title") or finding.get("vuln_type") or "Finding",
                finding.get("url") or finding.get("affected_url") or target,
                finding.get("confidence", ""),
                _artifact_path(finding),
            ))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_report(scan: dict, report_format: str) -> str:
    report_format = str(report_format or "markdown").lower()
    findings = _findings(scan)
    recon = scan.get("recon", {})
    analysis = scan.get("analysis", {})
    if report_format == "markdown":
        return str(scan.get("report", ""))
    if report_format == "json":
        return json.dumps(
            generate_json_report(
                scan.get("target", ""),
                recon,
                findings,
                analysis,
                scope=scan.get("scope") or scan.get("scope_snapshot") or {},
            ),
            indent=2,
            ensure_ascii=False,
        )
    if report_format == "csv":
        return generate_csv_report(findings)
    if report_format == "sarif":
        return json.dumps(
            generate_sarif_report(
                scan.get("target", ""),
                findings,
            ),
            indent=2,
            ensure_ascii=False,
        )
    if report_format in {"hackerone", "bugcrowd"}:
        return render_marketplace_report(scan, report_format)
    raise ValueError("Unsupported report format: {}".format(report_format))


REPORT_FILENAMES = {
    "markdown": "report.md",
    "json": "report.json",
    "csv": "report.csv",
    "sarif": "report.sarif",
    "hackerone": "hackerone-report.md",
    "bugcrowd": "bugcrowd-report.md",
}


def write_report_bundle(
    scan: dict,
    output_root: str | Path,
    *,
    formats: tuple[str, ...] = (
        "markdown",
        "json",
        "csv",
        "sarif",
        "hackerone",
        "bugcrowd",
    ),
) -> dict[str, str]:
    directory = Path(output_root).expanduser() / str(scan.get("id", "scan"))
    directory.mkdir(parents=True, exist_ok=True)
    paths = {}
    for report_format in formats:
        body = render_report(scan, report_format)
        path = directory / REPORT_FILENAMES[report_format]
        path.write_text(body, encoding="utf-8")
        paths[report_format] = str(path)
    return paths
