"""TruffleHog JavaScript secret scanning wrapper."""

from __future__ import annotations

import json
import subprocess

from core.integrations.secret_utils import finding_from_secret_hit, parse_json_lines
from core.integrations.tool_checker import check_tool


def scan_js_content(js_content_str, scan_id, url):
    if not check_tool("trufflehog"):
        return []
    try:
        result = subprocess.run(
            ["trufflehog", "stdin", "--no-verification", "--json"],
            input=str(js_content_str or ""),
            text=True,
            capture_output=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    findings = []
    for item in parse_json_lines(result.stdout):
        detector = str(
            item.get("DetectorName")
            or item.get("detector_name")
            or item.get("DetectorType")
            or "secret"
        )
        raw = str(
            item.get("Raw")
            or item.get("Redacted")
            or item.get("RawV2")
            or item.get("SourceMetadata", "")
        )
        line = item.get("Line") or item.get("line") or ""
        confidence = item.get("Verified") if "Verified" in item else item.get("confidence", "")
        findings.append(finding_from_secret_hit(
            scan_id,
            url,
            "trufflehog",
            detector,
            raw,
            line,
            json.dumps(item, ensure_ascii=False, sort_keys=True),
            confidence,
        ))
    return findings
