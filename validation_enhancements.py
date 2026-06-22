"""CVSS 4.0, report readiness, rejection codes, and structural deduplication."""

from __future__ import annotations

import re
from typing import Any

from impact_scoring_engine import calculate_official_cvss_40
from request_fingerprint import canonical_url, hamming_distance, simhash


REJECTION_CODES = {
    "INSUFFICIENT_EVIDENCE",
    "OUT_OF_SCOPE",
    "KNOWN_ISSUE",
    "MISSING_IMPACT",
    "DUPLICATE",
    "INFORMATIONAL_ONLY",
    "NEEDS_MANUAL_VALIDATION",
}

SECRET_PATTERNS = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bsk-(?:ant-)?[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{12,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b"),
)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _steps(value: Any) -> list[str]:
    if isinstance(value, list):
        return [_text(step) for step in value if _text(step)]
    text = _text(value)
    return [line.strip(" -\t") for line in text.splitlines() if line.strip()] if text else []


def calculate_cvss_40(finding: dict) -> dict:
    """Compatibility wrapper for existing validation and reporting consumers."""
    official = calculate_official_cvss_40(finding)
    return {
        "score": official["cvss_40_score"],
        "vector": official["cvss_40_vector"],
        **official,
    }


def contains_unredacted_secret(evidence: str) -> bool:
    value = _text(evidence)
    if not value or "[REDACTED]" in value or "<redacted>" in value.lower():
        return False
    return any(pattern.search(value) for pattern in SECRET_PATTERNS)


def _actual_response_evidence(evidence: str) -> bool:
    value = _text(evidence)
    if len(value) < 20:
        return False
    return bool(re.search(
        r"(?i)(HTTP/\d(?:\.\d)?\s+\d{3}|status(?:_code)?\s*[:=]\s*\d{3}|"
        r"response|header|body|access-control-|set-cookie|content-type|"
        r"\b200\b|\b201\b|\b401\b|\b403\b|\b500\b)",
        value,
    ))


def report_readiness(finding: dict, in_scope: bool) -> dict:
    steps = _steps(finding.get("reproduction_steps"))
    impact = _text(finding.get("business_impact"))
    evidence = _text(finding.get("evidence"))
    exploitability = _text(finding.get("exploitability_status")).lower()
    quality = float(finding.get("quality_score", 0) or 0)
    checks = {
        "reproduction_steps_3_plus": len(steps) >= 3,
        "business_impact_present": bool(impact),
        "actual_response_evidence": _actual_response_evidence(evidence),
        "exploitability_confirmed_or_probable": exploitability in {
            "confirmed", "probable"
        },
        "quality_score_75_plus": quality >= 75,
        "evidence_secrets_redacted": not contains_unredacted_secret(evidence),
        "affected_url_in_scope": bool(in_scope),
    }
    not_ready = (
        len(steps) == 0
        or not impact
        or exploitability in {"candidate", "needs_manual_validation"}
        or quality < 60
    )
    ready = all(checks.values())
    status = "READY" if ready else "NOT_READY" if not_ready else "NEEDS_IMPROVEMENT"
    return {
        "status": status,
        "ready": ready,
        "checks": checks,
        "failed": [name for name, passed in checks.items() if not passed],
    }


def rejection_reason_codes(
    finding: dict,
    *,
    in_scope: bool,
    duplicate: bool = False,
) -> list[str]:
    codes = []
    exploitability = _text(finding.get("exploitability_status")).lower()
    severity = _text(finding.get("severity")).upper()
    if not in_scope:
        codes.append("OUT_OF_SCOPE")
    if duplicate:
        codes.append("DUPLICATE")
    if finding.get("known_issue"):
        codes.append("KNOWN_ISSUE")
    if not _text(finding.get("business_impact")):
        codes.append("MISSING_IMPACT")
    if severity in {"INFO", "INFORMATIONAL"}:
        codes.append("INFORMATIONAL_ONLY")
    if exploitability in {"candidate", "needs_manual_validation"}:
        codes.append("NEEDS_MANUAL_VALIDATION")
    readiness = finding.get("report_readiness", {})
    if not readiness.get("checks", {}).get("actual_response_evidence", False):
        codes.append("INSUFFICIENT_EVIDENCE")
    return list(dict.fromkeys(code for code in codes if code in REJECTION_CODES))


def _finding_signature(finding: dict) -> int:
    material = " | ".join([
        _text(finding.get("vulnerability_class") or finding.get("vuln_type")).lower(),
        canonical_url(_text(finding.get("affected_url") or finding.get("url"))),
        _text(finding.get("description")),
        _text(finding.get("evidence")),
    ])
    return simhash(material)


def structural_duplicate(
    left: dict,
    right: dict,
    threshold: int = 7,
) -> bool:
    left_class = _text(
        left.get("vulnerability_class") or left.get("vuln_type")
    ).lower()
    right_class = _text(
        right.get("vulnerability_class") or right.get("vuln_type")
    ).lower()
    if left_class != right_class:
        return False
    left_url = canonical_url(_text(left.get("affected_url") or left.get("url")))
    right_url = canonical_url(_text(right.get("affected_url") or right.get("url")))
    if left_url == right_url:
        left_parameter = _text(left.get("parameter")).lower()
        right_parameter = _text(right.get("parameter")).lower()
        return not (
            left_parameter
            and right_parameter
            and left_parameter != right_parameter
        )
    return hamming_distance(
        _finding_signature(left), _finding_signature(right)
    ) <= threshold


def keep_best_similar(findings: list[dict]) -> tuple[list[dict], list[dict]]:
    kept: list[dict] = []
    discarded: list[dict] = []
    for finding in sorted(
        findings,
        key=lambda item: (
            float(item.get("quality_score", 0) or 0),
            float(item.get("cvss_40_score", 0) or 0),
            float(item.get("confidence", 0) or 0),
        ),
        reverse=True,
    ):
        duplicate_of = next(
            (existing for existing in kept if structural_duplicate(finding, existing)),
            None,
        )
        if duplicate_of:
            duplicate = dict(finding)
            duplicate["duplicate_of"] = duplicate_of.get("id", "")
            duplicate["rejection_reason_codes"] = list(dict.fromkeys(
                list(duplicate.get("rejection_reason_codes", [])) + ["DUPLICATE"]
            ))
            discarded.append(duplicate)
        else:
            kept.append(finding)
    return kept, discarded
