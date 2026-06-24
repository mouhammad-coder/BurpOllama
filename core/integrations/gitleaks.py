"""Gitleaks JavaScript secret scanning wrapper."""

from __future__ import annotations

import json
import subprocess

from core.integrations.secret_utils import finding_from_secret_hit
from core.integrations.tool_checker import check_tool


def scan_js_content(js_content_str, scan_id, url):
    if not check_tool("gitleaks"):
        return []
    try:
        result = subprocess.run(
            ["gitleaks", "stdin", "--redact", "--report-format", "json"],
            input=str(js_content_str or ""),
            text=True,
            capture_output=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    try:
        parsed = json.loads(result.stdout or "[]")
    except json.JSONDecodeError:
        parsed = []
    if isinstance(parsed, dict):
        items = parsed.get("findings", [])
    else:
        items = parsed
    findings = []
    for item in items if isinstance(items, list) else []:
        if not isinstance(item, dict):
            continue
        detector = str(item.get("RuleID") or item.get("Description") or "secret")
        raw = str(item.get("Secret") or item.get("Match") or item.get("Fingerprint") or "")
        line = item.get("StartLine") or item.get("Line") or ""
        findings.append(finding_from_secret_hit(
            scan_id,
            url,
            "gitleaks",
            detector,
            raw,
            line,
            json.dumps(item, ensure_ascii=False, sort_keys=True),
            item.get("Entropy", ""),
        ))
    return findings
