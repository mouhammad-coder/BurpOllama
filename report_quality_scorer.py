"""Deterministic report-quality scoring for vulnerability findings."""

from __future__ import annotations

import json
import re
from typing import Any

from scope_policy import scope_policy


GENERIC_IMPACT = {
    "security issue",
    "potential security impact",
    "may impact users",
    "could be exploited",
    "unknown",
    "n/a",
    "none",
}
GENERIC_REMEDIATION = {
    "fix the issue",
    "apply security best practices",
    "validate input",
    "sanitize input",
    "update the application",
    "review security",
    "n/a",
    "none",
}
PLACEHOLDER_RE = re.compile(
    r"(?i)(?:\bTODO\b|\bTBD\b|\bFIXME\b|<insert\b|replace\s+me|your[_ -]?\w+|\.\.\.)"
)
HTTP_EVIDENCE_PATTERNS = (
    re.compile(r"(?im)^HTTP/\d(?:\.\d)?\s+[1-5]\d{2}\b"),
    re.compile(r"(?i)\bHTTP\s+[1-5]\d{2}\b"),
    re.compile(r'(?i)["\']?status_code["\']?\s*[:=]\s*[1-5]\d{2}\b'),
    re.compile(r"(?im)^(?:location|content-type|set-cookie|server|www-authenticate):\s*\S+"),
)
SECRET_PATTERNS = (
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    re.compile(
        r"(?i)\b(?:api[_-]?key|secret|password|passwd|access[_-]?token|"
        r"refresh[_-]?token|client[_-]?secret)\b\s*[=:]\s*[\"']?"
        r"(?!<redacted>|\*{4,})[A-Za-z0-9_./+=-]{12,}"
    ),
    re.compile(r"(?i)\bauthorization:\s*(?:bearer|basic)\s+(?!<redacted>)[A-Za-z0-9._~+/=-]{12,}"),
)
SPECIFIC_FIX_TERMS = {
    "allowlist", "denylist", "server-side", "parameterized", "prepared statement",
    "sameSite", "httponly", "content-security-policy", "encode", "escape",
    "rate limit", "lockout", "exact match", "single-use", "invalidate",
    "authorization", "ownership", "least privilege", "rotate", "revoke",
    "cryptographically", "transaction", "idempotency", "schema", "dto",
}


def _text(value: Any) -> str:
    if isinstance(value, (dict, list)):
        try:
            return json.dumps(value, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            pass
    return str(value or "").strip()


def _steps(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(step).strip() for step in value if str(step).strip()]
    text = _text(value)
    return [text] if text else []


def _is_concrete_impact(value: Any) -> bool:
    text = _text(value)
    normalized = re.sub(r"\s+", " ", text.lower()).strip(" .")
    if len(text) < 20 or normalized in GENERIC_IMPACT:
        return False
    impact_terms = (
        "account", "data", "financial", "payment", "phishing", "cookie",
        "token", "credential", "privilege", "unauthorized", "customer",
        "privacy", "fraud", "takeover", "xss", "code execution", "service",
        "business", "order", "balance", "discount", "admin",
    )
    return any(term in normalized for term in impact_terms)


def _has_http_response_snippet(value: Any) -> bool:
    if isinstance(value, dict):
        response = value.get("response")
        if isinstance(response, dict) and (
            response.get("status_code")
            or response.get("headers")
            or response.get("body")
        ):
            return True
        pairs = value.get("request_response_pairs") or value.get("request_response_pair")
        if isinstance(pairs, list) and any(
            isinstance(pair, dict) and isinstance(pair.get("response"), dict)
            for pair in pairs
        ):
            return True
    text = _text(value)
    return any(pattern.search(text) for pattern in HTTP_EVIDENCE_PATTERNS)


def _specific_remediation(value: Any) -> bool:
    text = _text(value)
    normalized = re.sub(r"\s+", " ", text.lower()).strip(" .")
    if len(text) < 20 or normalized in GENERIC_REMEDIATION:
        return False
    return any(term.lower() in normalized for term in SPECIFIC_FIX_TERMS)


def _scope_matches(url: str) -> bool:
    if not url:
        return False
    return scope_policy.validate_target(url, action="report")[0]


def _has_owasp_mapping(finding: dict) -> bool:
    return any(
        _text(finding.get(key))
        for key in (
            "owasp_top_10", "owasp_asvs_mapping", "owasp_wstg_mapping",
            "owasp", "owasp_mapping",
        )
    )


def _contains_unredacted_secret(evidence: Any) -> bool:
    text = _text(evidence)
    if not text:
        return False
    scrubbed = re.sub(
        r"(?i)(<redacted>|\*{4,}|REDACTED|xxxx+)",
        "",
        text,
    )
    return any(pattern.search(scrubbed) for pattern in SECRET_PATTERNS)


def _grade(score: int) -> str:
    if score >= 85:
        return "A"
    if score >= 70:
        return "B"
    if score >= 50:
        return "C"
    if score >= 30:
        return "D"
    return "F"


def score_finding(finding: dict) -> dict:
    """Score report completeness and safety from 0 to 100."""
    finding = finding or {}
    score = 0
    improvements: list[str] = []
    blocking_issues: list[str] = []

    steps = _steps(finding.get("reproduction_steps"))
    if len(steps) >= 3:
        score += 20
    else:
        improvements.append("Expand reproduction steps to at least 3 concrete steps")

    impact = _text(finding.get("business_impact"))
    if _is_concrete_impact(impact):
        score += 20
    else:
        improvements.append("Add concrete business impact")

    evidence = finding.get("evidence")
    if _has_http_response_snippet(evidence):
        score += 15
    else:
        improvements.append("Add an actual HTTP response snippet to evidence")

    exploitability = _text(finding.get("exploitability_status")).lower()
    if exploitability == "confirmed":
        score += 15
    else:
        improvements.append("Confirm exploitability with reproducible proof")

    if _specific_remediation(finding.get("remediation")):
        score += 10
    else:
        improvements.append("Provide a specific remediation")

    affected_url = _text(finding.get("affected_url") or finding.get("url"))
    scope_override = finding.get("_scope_match")
    scope_ok = scope_override if isinstance(scope_override, bool) else _scope_matches(affected_url)
    if scope_ok:
        score += 10
    else:
        blocking_issues.append("Affected URL is missing or outside configured scope")

    if re.search(r"(?i)\bCWE-\d+\b", _text(finding.get("cwe"))):
        score += 5
    else:
        improvements.append("Add a CWE reference")

    if _has_owasp_mapping(finding):
        score += 5
    else:
        improvements.append("Add an OWASP mapping")

    if _contains_unredacted_secret(evidence):
        score -= 20
        blocking_issues.append("Evidence contains possible unredacted secret")

    if any(PLACEHOLDER_RE.search(step) for step in steps):
        score -= 15
        blocking_issues.append("Reproduction steps contain placeholder text")

    if len(impact) < 20:
        score -= 10
        if "Add concrete business impact" not in improvements:
            improvements.append("Add concrete business impact")

    if _text(finding.get("severity")).upper() in {"INFO", "INFORMATIONAL", "LOW"}:
        score -= 10
        improvements.append("Validate higher-impact behavior before submission")

    if exploitability in {"false_positive", "candidate"}:
        score -= 25
        blocking_issues.append(
            "Finding is marked {}".format(exploitability.replace("_", " "))
        )

    score = max(0, min(100, score))
    grade = _grade(score)
    return {
        "score": score,
        "grade": grade,
        "ready_to_submit": score >= 70,
        "improvements": list(dict.fromkeys(improvements)),
        "blocking_issues": list(dict.fromkeys(blocking_issues)),
    }
