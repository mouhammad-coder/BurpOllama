"""
finding_quality.py - strict bounty-readiness gate.

Normal users see simple statuses only: READY, NEEDS PROOF, CANDIDATE, INFO.
The detailed failed checks are kept for the dashboard and Advanced Mode.
"""

from __future__ import annotations

import math
import re
from typing import Any

from scope_policy import scope_policy


HIGH_VALUE_CLASSES = {
    "idor", "bola", "broken access", "access control", "account takeover",
    "oauth", "jwt", "graphql", "ssrf", "secret", "api key", "token",
    "sensitive data", "upload", "mass assignment", "business logic",
    "rate limit", "cors", "xss", "sqli", "sql injection", "open redirect",
}

SECRET_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{16,}"),
    re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
]


def _text(f: dict[str, Any]) -> str:
    return " ".join(str(f.get(k, "")) for k in (
        "title", "vulnerability_class", "vuln_type", "description",
        "business_impact", "technical_impact", "evidence",
    )).lower()


def bounty_class(f: dict[str, Any]) -> bool:
    text = _text(f)
    return any(cls in text for cls in HIGH_VALUE_CLASSES)


def _url_allowed(url: str) -> bool:
    if not url:
        return False
    return scope_policy.validate_target(url, action="report")[0]


def _has_unredacted_secret(f: dict[str, Any]) -> bool:
    if f.get("redaction_status") not in ("redacted", "none", "not_required", ""):
        return True
    evidence = str(f.get("evidence", ""))[:2000]
    return any(p.search(evidence) for p in SECRET_PATTERNS)


def _entropy_ok(f: dict[str, Any]) -> bool:
    text = _text(f)
    if not any(x in text for x in ("secret", "token", "api key", "credential")):
        return True
    evidence = str(f.get("evidence", ""))
    candidates = re.findall(r"[A-Za-z0-9_\-]{20,}", evidence)
    if not candidates:
        return False
    for c in candidates[:5]:
        probs = [c.count(ch) / len(c) for ch in set(c)]
        entropy = -sum(p * math.log2(p) for p in probs)
        if entropy >= 3.5 and f.get("redaction_status") == "redacted":
            return True
    return False


def _class_specific_checks(f: dict[str, Any]) -> list[str]:
    text = _text(f)
    evidence = str(f.get("evidence", "")).lower()
    steps = " ".join(str(x) for x in f.get("reproduction_steps", [])).lower()
    failed = []
    if any(x in text for x in ("idor", "bola", "access control")):
        if not any(x in evidence + steps for x in ("session a", "session b", "two users", "user a", "user b")):
            failed.append("IDOR/BOLA needs Session A/B proof")
    if "ssrf" in text and not any(x in evidence for x in ("oob", "callback", "interaction", "dns hit")):
        failed.append("SSRF needs confirmed OOB callback")
    if "graphql" in text and not any(x in evidence + steps for x in ("unauthorized", "another user", "session b", "object")):
        failed.append("GraphQL auth needs unauthorized data access proof")
    if "jwt" in text and not any(x in evidence for x in ("accepted forged", "signature bypass", "key confusion", "alg none")):
        failed.append("JWT needs exploitable proof")
    if "cors" in text and not any(x in evidence for x in ("credentials", "sensitive", "account", "token")):
        failed.append("CORS needs real impact")
    if "xss" in text and not any(x in evidence for x in ("harmless marker", "alert", "dom marker", "reflected marker")):
        failed.append("XSS needs harmless marker proof")
    if "sqli" in text or "sql injection" in text:
        if not any(x in evidence for x in ("differential", "boolean", "safe delay", "syntax difference")):
            failed.append("SQLi needs safe differential proof")
    if "open redirect" in text and not any(x in evidence for x in ("external redirect", "location:", "https://example.org")):
        failed.append("Open redirect needs external redirect proof")
    if "rate" in text and not any(x in evidence + steps for x in ("strict cap", "otp", "password reset", "account lockout", "abuse impact")):
        failed.append("Rate-limit issue needs clear impact and strict caps")
    if any(x in text for x in ("secret", "token", "api key")) and not _entropy_ok(f):
        failed.append("Secrets need entropy/context validation and redaction")
    return failed


def evaluate_finding(f: dict[str, Any], seen_keys: set[str] | None = None) -> dict[str, Any]:
    failed = []
    affected_url = f.get("affected_url") or f.get("url") or ""
    evidence_url = f.get("evidence_url") or f.get("raw_evidence_url") or affected_url
    key = "{}|{}|{}|{}".format(
        f.get("vulnerability_class") or f.get("vuln_type") or f.get("title"),
        affected_url,
        f.get("method", "GET"),
        f.get("parameter", ""),
    ).lower()

    if not _url_allowed(affected_url):
        failed.append("Affected URL is outside allowed scope or blocked")
    if not _url_allowed(evidence_url):
        failed.append("Evidence URL is outside allowed scope or blocked")
    if f.get("evidence_strength") != "strong":
        failed.append("Proof is not strong")
    if int(f.get("confidence") or 0) < 90:
        failed.append("Confidence is not high enough")
    if not (f.get("business_impact") or f.get("technical_impact")):
        failed.append("Impact is not clear")
    if not f.get("reproduction_steps"):
        failed.append("Reproduction steps are missing")
    if not f.get("remediation"):
        failed.append("Remediation is missing")
    if _has_unredacted_secret(f):
        failed.append("Evidence may contain unredacted secrets")
    if seen_keys is not None:
        if key in seen_keys:
            failed.append("Duplicate check failed")
        else:
            seen_keys.add(key)
    if not f.get("title") or len(str(f.get("title"))) < 8 or len(str(f.get("evidence", ""))) < 10:
        failed.append("Report quality check failed")
    if f.get("exploitability_status") in ("candidate", "needs_manual_validation", "probable"):
        failed.append("Finding is candidate-only")
    if str(f.get("severity", "")).upper() == "INFO":
        failed.append("Informational finding")
    source = str(f.get("source", "")).lower()
    if "ai" in source and len(str(f.get("evidence", ""))) < 40:
        failed.append("Finding is based only on AI opinion")
    failed.extend(_class_specific_checks(f))

    text = _text(f)
    if str(f.get("severity", "")).upper() == "INFO":
        label = "INFO"
        bucket = "informational"
    elif not bounty_class(f):
        label = "CANDIDATE"
        bucket = "candidate"
    elif not failed:
        label = "READY"
        bucket = "ready"
    elif any(x in " ".join(failed).lower() for x in ("proof", "impact", "reproduction", "session", "oob", "exploitable", "marker", "differential")):
        label = "NEEDS PROOF"
        bucket = "needs_more_proof"
    else:
        label = "CANDIDATE"
        bucket = "candidate"

    if f.get("exploitability_status") == "false_positive" or f.get("verdict") == "KILL":
        label = "INFO"
        bucket = "false_positive"
        failed.append("False positive or ignored")

    return {
        "label": label,
        "bucket": bucket,
        "ready": label == "READY",
        "failed_checks": failed,
        "zero_false_positive_mode": True,
    }


def evaluate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[str] = set()
    out = []
    for f in findings or []:
        q = evaluate_finding(f, seen)
        enriched = dict(f)
        enriched["quality"] = q
        enriched["quality_label"] = q["label"]
        enriched["quality_bucket"] = q["bucket"]
        enriched["failed_quality_checks"] = q["failed_checks"]
        out.append(enriched)
    return out
