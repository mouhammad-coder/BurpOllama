"""Generate reports from durable standalone scan records."""

from __future__ import annotations

import json
from pathlib import Path

from bounty_mode import build_bounty_mode, build_bounty_report
from reporter import generate_csv_report, generate_json_report, generate_sarif_report
from scope_policy import scope_policy


def _findings(scan: dict) -> list[dict]:
    return (
        scan.get("triaged_findings")
        or scan.get("findings")
        or scan.get("raw_findings")
        or []
    )


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
        coverage = analysis.get("coverage_v2") or analysis.get("coverage") or {}
        bounty = build_bounty_mode(
            scan,
            scan.get("scope") or scope_policy.to_dict(),
            scan.get("session_status", {}),
            coverage,
        )
        return build_bounty_report(bounty, platform=report_format)
    raise ValueError("Unsupported report format: {}".format(report_format))


REPORT_FILENAMES = {
    "markdown": "report.md",
    "json": "report.json",
    "csv": "report.csv",
    "sarif": "report.sarif",
    "hackerone": "report-hackerone.md",
    "bugcrowd": "report-bugcrowd.md",
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
