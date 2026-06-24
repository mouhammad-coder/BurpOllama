"""Shared redaction helpers for external JavaScript secret scanners."""

from __future__ import annotations

import hashlib
import json
import re

from finding_model import normalize_finding

from core.evidence import write_evidence_artifact


def parse_json_lines(text: str) -> list[dict]:
    items = []
    for line in str(text or "").splitlines():
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            items.append(parsed)
    return items


def redacted_secret(detector_type: str, value: str) -> str:
    digest = hashlib.sha256(str(value or detector_type).encode("utf-8", errors="ignore")).hexdigest()[:4]
    safe_type = re.sub(r"[^A-Za-z0-9]+", "-", str(detector_type or "secret")).strip("-") or "secret"
    return "REDACTED-{}-{}".format(safe_type, digest)


def redact_text(text: str, raw_secret: str, replacement: str) -> str:
    output = str(text or "")
    if raw_secret:
        output = output.replace(str(raw_secret), replacement)
    return output[:2000]


def finding_from_secret_hit(scan_id, url, tool, detector_type, raw_secret, line, raw_payload, confidence):
    replacement = redacted_secret(detector_type, raw_secret)
    redacted_payload = redact_text(raw_payload, raw_secret, replacement)
    artifact = write_evidence_artifact(
        {"id": scan_id},
        title="Possible secret detected by {}".format(tool),
        url=str(url),
        raw_request="{} stdin scan for {}".format(tool, url),
        raw_response=redacted_payload,
        matched_indicator=replacement,
        indicator_location="line {}".format(line or "unknown"),
        agent=tool,
        vuln_class="JavaScript Secret Candidate",
        impact="Client-side secrets may expose third-party services if valid and insufficiently restricted.",
        fp_check="External scanner output is redacted and requires manual validation; no secret verification was performed.",
        confirmed=False,
        filename_prefix=tool,
        metadata={
            "detector_type": detector_type,
            "redacted_match": replacement,
            "line": line,
            "confidence": confidence,
            "tool": tool,
        },
    )
    return normalize_finding({
        "source": tool,
        "vuln_type": "JavaScript Secret Candidate",
        "title": "Possible secret detected by {}".format(tool),
        "severity": "MEDIUM",
        "confidence": 65,
        "url": str(url),
        "method": "PASSIVE",
        "description": "{} reported a possible {} secret in JavaScript content.".format(tool, detector_type),
        "evidence": replacement,
        "evidence_artifact": artifact,
        "business_impact": "Potential credential exposure requires manual validation and safe rotation guidance.",
        "remediation": "Remove secrets from client-side code and rotate any exposed values.",
        "cwe": "CWE-798",
        "exploitability_status": "needs_manual_validation",
        "evidence_strength": "weak",
        "false_positive_risk": "medium",
        "redaction_status": "redacted",
    }, scan_id=str(scan_id))
