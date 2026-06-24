"""Nuclei exposure scan wrapper."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from finding_model import normalize_finding

from core.evidence import write_evidence_artifact
from core.integrations.tool_checker import check_tool


SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "informational": "INFO",
}


def _load_json_lines(path: Path, stdout: str) -> list[dict]:
    lines = []
    if path.exists():
        lines.extend(path.read_text(encoding="utf-8", errors="ignore").splitlines())
    if stdout:
        lines.extend(stdout.splitlines())
    items = []
    for line in lines:
        text = line.strip()
        if not text:
            continue
        try:
            value = json.loads(text)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            items.append(value)
    return items


def run_nuclei(target, output_dir, templates="exposures/", scan=None):
    if not check_tool("nuclei"):
        return []
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    output_path = directory / "nuclei.json"
    command = [
        "nuclei",
        "-u", str(target),
        "-t", str(templates),
        "-json",
        "-o", str(output_path),
    ]
    try:
        result = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=180,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if result.returncode != 0 and not output_path.exists() and not result.stdout:
        return []
    scan_data = scan or {"id": Path(output_dir).name or "nuclei-scan"}
    findings = []
    for item in _load_json_lines(output_path, result.stdout):
        info = item.get("info") if isinstance(item.get("info"), dict) else {}
        name = str(info.get("name") or item.get("template-id") or "Nuclei exposure candidate")
        severity = SEVERITY_MAP.get(str(info.get("severity") or "info").lower(), "INFO")
        url = str(item.get("matched-at") or item.get("host") or target)
        template = str(item.get("template-id") or item.get("template") or "")
        artifact = write_evidence_artifact(
            scan_data,
            title=name,
            url=url,
            raw_request="NUCLEI TEMPLATE {}".format(template),
            raw_response=json.dumps(item, ensure_ascii=False, sort_keys=True),
            matched_indicator=template or name,
            indicator_location="nuclei json output",
            agent="nuclei",
            vuln_class="Nuclei Exposure Candidate",
            impact=str(info.get("description") or "Nuclei reported a potential exposure requiring manual validation."),
            fp_check="Nuclei output is imported as a candidate only and must be reviewed by a human.",
            confirmed=False,
            filename_prefix="nuclei",
            metadata={"template": template, "nuclei_severity": info.get("severity", "")},
        )
        findings.append(normalize_finding({
            "source": "nuclei",
            "vuln_type": "Nuclei Exposure Candidate",
            "title": name,
            "severity": severity,
            "confidence": 60,
            "url": url,
            "method": "PASSIVE",
            "description": str(info.get("description") or name),
            "evidence": template or name,
            "evidence_artifact": artifact,
            "business_impact": str(info.get("description") or "Potential exposure requires review."),
            "remediation": "Review the Nuclei template result and remediate the confirmed exposure.",
            "exploitability_status": "candidate",
            "evidence_strength": "weak",
            "false_positive_risk": "medium",
            "redaction_status": "redacted",
        }, scan_id=str(scan_data.get("id", ""))))
    return findings
