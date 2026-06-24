"""Evidence artifact helpers used by proof gates and agents.

Artifacts are intentionally simple JSON files so the CLI can prove why a
finding is reportable without relying on in-memory strings alone.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any
from datetime import datetime, timezone


REQUIRED_EVIDENCE_FIELDS = {
    "scan_id",
    "agent",
    "vuln_class",
    "url",
    "raw_request",
    "raw_response",
    "matched_indicator",
    "indicator_location",
    "impact",
    "fp_check",
    "confirmed",
    "timestamp",
    "artifact_path",
}


def _safe_slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value or "")).strip("-")
    return slug[:80] or "evidence"


def artifact_dir(scan: dict[str, Any]) -> Path:
    return Path("evidence") / str(scan.get("id", "scan"))


def write_evidence_artifact(
    scan: dict[str, Any],
    *,
    title: str,
    url: str,
    raw_request: str,
    raw_response: str,
    matched_indicator: str,
    indicator_location: str,
    agent: str = "agent",
    vuln_class: str | None = None,
    impact: str = "Evidence collected for security review.",
    fp_check: str = "False-positive check not supplied.",
    confirmed: bool = False,
    filename_prefix: str = "evidence",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    directory = artifact_dir(scan)
    directory.mkdir(parents=True, exist_ok=True)
    scan_id = str(scan.get("id", "scan"))
    digest = hashlib.sha256(
        "\n".join([
            str(title or ""),
            str(url or ""),
            str(matched_indicator or ""),
            str(raw_request or ""),
            str(raw_response or ""),
        ]).encode("utf-8", errors="ignore")
    ).hexdigest()[:16]
    path = directory / "{}-{}.json".format(_safe_slug(filename_prefix), digest)
    artifact = {
        "scan_id": scan_id,
        "agent": agent,
        "vuln_class": vuln_class or title,
        "url": url,
        "raw_request": raw_request,
        "raw_response": raw_response,
        "matched_indicator": matched_indicator,
        "indicator_location": indicator_location,
        "impact": impact,
        "fp_check": fp_check,
        "confirmed": bool(confirmed),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "artifact_path": str(path),
        "path": str(path),
        "metadata": metadata or {},
    }
    path.write_text(
        json.dumps(artifact, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return {
        **artifact,
        "path": str(path),
    }


def valid_evidence_artifact(value: Any) -> tuple[bool, str]:
    if not isinstance(value, dict):
        return False, "missing_evidence_artifact"
    path = str(value.get("artifact_path") or value.get("path") or "").strip()
    if not path:
        return False, "missing_evidence_artifact_path"
    artifact_path = Path(path)
    if not artifact_path.exists() or not artifact_path.is_file():
        return False, "evidence_artifact_file_missing"
    missing = [
        field for field in sorted(REQUIRED_EVIDENCE_FIELDS)
        if field != "confirmed" and not str(value.get(field) or "").strip()
    ]
    if missing:
        return False, "evidence_artifact_missing:" + ",".join(missing)
    try:
        loaded = json.loads(artifact_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False, "evidence_artifact_unreadable"
    file_missing = [
        field for field in sorted(REQUIRED_EVIDENCE_FIELDS)
        if field != "confirmed" and not str(loaded.get(field) or "").strip()
    ]
    if file_missing:
        return False, "evidence_artifact_file_missing:" + ",".join(file_missing)
    if loaded.get("artifact_path") != str(artifact_path):
        return False, "evidence_artifact_path_mismatch"
    return True, ""
