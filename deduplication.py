"""Exact and structural deduplication for vulnerability findings."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from report_quality_scorer import score_finding
from request_fingerprint import canonical_url, hamming_distance, simhash


EXPLOITABILITY_RANK = {
    "confirmed": 5,
    "probable": 4,
    "needs_manual_validation": 3,
    "candidate": 2,
    "false_positive": 1,
}


def _text(value: Any) -> str:
    return str(value or "").strip()


def _url(finding: dict) -> str:
    return _text(finding.get("affected_url") or finding.get("url"))


def _vuln_type(finding: dict) -> str:
    return _text(
        finding.get("vuln_type")
        or finding.get("vulnerability_class")
        or finding.get("title")
    ).lower()


def _parameter(finding: dict) -> str:
    return _text(finding.get("parameter") or finding.get("param")).lower()


def _dedup_key(finding: dict) -> str:
    raw = "{}|{}|{}|{}".format(
        _vuln_type(finding),
        canonical_url(_url(finding)),
        _text(finding.get("method") or "GET").upper(),
        _parameter(finding),
    )
    return hashlib.sha256(raw.encode("utf-8", errors="ignore")).hexdigest()


def _quality_score(finding: dict) -> int:
    value = finding.get("quality_score")
    try:
        if value is not None and str(value).strip() != "":
            return max(0, min(100, int(float(value))))
    except (TypeError, ValueError):
        pass
    try:
        return int(score_finding(finding).get("score", 0))
    except Exception:
        return 0


def _rank(finding: dict) -> tuple[int, int, int]:
    exploitability = _text(finding.get("exploitability_status")).lower()
    confidence = int(float(finding.get("confidence", 0) or 0))
    return (
        _quality_score(finding),
        EXPLOITABILITY_RANK.get(exploitability, 0),
        confidence,
    )


def deduplicate_findings(findings: list[dict]) -> list[dict]:
    """Merge exact finding duplicates and retain the strongest report."""
    groups: dict[str, list[dict]] = {}
    order: list[str] = []

    for finding in findings or []:
        if not isinstance(finding, dict):
            continue
        key = _dedup_key(finding)
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(finding)

    deduplicated = []
    for key in order:
        group = groups[key]
        best = max(group, key=_rank)
        retained = dict(best)
        retained["duplicate_count"] = sum(
            max(1, int(item.get("duplicate_count", 1) or 1))
            for item in group
        )
        retained["dedup_key"] = key
        deduplicated.append(retained)
    return deduplicated


def _similarity_text(finding: dict) -> str:
    url = canonical_url(_url(finding))
    parsed_parts = [
        _vuln_type(finding),
        url,
        _text(finding.get("method") or "GET").upper(),
        _parameter(finding),
        _text(finding.get("title")).lower(),
        _text(finding.get("description")).lower(),
        _text(finding.get("technical_impact")).lower(),
    ]
    evidence = finding.get("evidence")
    if isinstance(evidence, (dict, list)):
        try:
            evidence = json.dumps(evidence, sort_keys=True, default=str)
        except (TypeError, ValueError):
            evidence = str(evidence)
    parsed_parts.append(_text(evidence).lower()[:1000])
    return " ".join(part for part in parsed_parts if part)


def find_similar_findings(
    finding: dict,
    existing: list[dict],
    threshold: float = 0.85,
) -> list[dict]:
    """Return findings whose structural SimHash similarity meets threshold."""
    threshold = max(0.0, min(1.0, float(threshold)))
    target_hash = simhash(_similarity_text(finding))
    target_key = _dedup_key(finding)
    similar = []

    for candidate in existing or []:
        if not isinstance(candidate, dict) or candidate is finding:
            continue
        candidate_hash = simhash(_similarity_text(candidate))
        distance = hamming_distance(target_hash, candidate_hash)
        similarity = 1.0 - (distance / 64.0)
        if similarity >= threshold:
            enriched = dict(candidate)
            enriched["similarity_score"] = round(similarity, 4)
            enriched["exact_duplicate"] = _dedup_key(candidate) == target_key
            similar.append(enriched)

    return sorted(
        similar,
        key=lambda item: (
            item.get("similarity_score", 0),
            _quality_score(item),
        ),
        reverse=True,
    )
