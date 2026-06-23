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


REQUIRED_EVIDENCE_FIELDS = {
    "raw_request",
    "raw_response",
    "matched_indicator",
    "indicator_location",
}


def _safe_slug(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value or "")).strip("-")
    return slug[:80] or "evidence"


def artifact_dir(scan: dict[str, Any]) -> Path:
    output = Path(str(scan.get("options", {}).get("output") or "reports")).expanduser()
    return output / str(scan.get("id", "scan")) / "evidence"


def write_evidence_artifact(
    scan: dict[str, Any],
    *,
    title: str,
    url: str,
    raw_request: str,
    raw_response: str,
    matched_indicator: str,
    indicator_location: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    directory = artifact_dir(scan)
    directory.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(
        "\n".join([
            str(title or ""),
            str(url or ""),
            str(matched_indicator or ""),
            str(raw_request or ""),
            str(raw_response or ""),
        ]).encode("utf-8", errors="ignore")
    ).hexdigest()[:16]
    path = directory / "{}-{}.json".format(_safe_slug(title), digest)
    artifact = {
        "raw_request": raw_request,
        "raw_response": raw_response,
        "matched_indicator": matched_indicator,
        "indicator_location": indicator_location,
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
    path = str(value.get("path") or "").strip()
    if not path:
        return False, "missing_evidence_artifact_path"
    artifact_path = Path(path)
    if not artifact_path.exists() or not artifact_path.is_file():
        return False, "evidence_artifact_file_missing"
    missing = [
        field for field in sorted(REQUIRED_EVIDENCE_FIELDS)
        if not str(value.get(field) or "").strip()
    ]
    if missing:
        return False, "evidence_artifact_missing:" + ",".join(missing)
    try:
        loaded = json.loads(artifact_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False, "evidence_artifact_unreadable"
    file_missing = [
        field for field in sorted(REQUIRED_EVIDENCE_FIELDS)
        if not str(loaded.get(field) or "").strip()
    ]
    if file_missing:
        return False, "evidence_artifact_file_missing:" + ",".join(file_missing)
    return True, ""
