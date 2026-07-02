"""
finding_model.py - normalized finding contract and proof gate.

Scanner modules still emit simple dictionaries. This module upgrades them into
the platform finding schema while preserving legacy keys such as vuln_type/url.
"""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone
from typing import Any

from security_hardening import redact_secrets

EXPLOITABILITY_STATUSES = {
    "confirmed", "probable", "candidate", "needs_manual_validation", "false_positive"
}

ADVANCED_DEFAULT_MANUAL = {
    "idor", "bola", "business logic", "oauth", "request smuggling",
    "http desync", "race condition", "file upload", "graphql authorization",
    "mass assignment", "jwt key confusion",
}

STRONG_PROOF_TERMS = {
    "oob confirmed", "confirmed", "different user's", "unauthorized data",
    "server-side", "evaluated marker", "location:", "sql error",
    "sleep", "delay", "dns hit", "callback", "http 200",
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def evidence_id(evidence: str) -> str:
    return "EV-" + hashlib.sha256((evidence or "").encode("utf-8", errors="ignore")).hexdigest()[:16]


def _contains(text: str, terms: set[str]) -> bool:
    lower = (text or "").lower()
    return any(t in lower for t in terms)


class ProofGate:
    """
    Assigns exploitability_status and evidence fields conservatively.
    Advanced issues are candidates/manual-validation unless strong proof exists.
    """

    @staticmethod
    def evaluate(finding: dict[str, Any]) -> dict[str, Any]:
        text = " ".join(str(finding.get(k, "")) for k in (
            "title", "vuln_type", "vulnerability_class", "description",
            "evidence", "business_impact", "technical_impact",
        )).lower()
        confidence = int(float(finding.get("confidence", 50) or 50))
        verdict = str(finding.get("verdict", "")).upper()

        if verdict in {"KILL", "FP", "FALSE_POSITIVE"}:
            status = "false_positive"
        elif _contains(text, {"oob confirmed", "remote code execution", "sql injection — error-based"}):
            status = "confirmed"
        elif any(cls in text for cls in ADVANCED_DEFAULT_MANUAL):
            if confidence >= 90 and _contains(text, STRONG_PROOF_TERMS):
                status = "probable"
            else:
                status = "needs_manual_validation"
        elif confidence >= 90 and _contains(text, STRONG_PROOF_TERMS):
            status = "confirmed"
        elif confidence >= 75:
            status = "probable"
        else:
            status = "candidate"

        evidence_strength = "strong" if status == "confirmed" else (
            "moderate" if status == "probable" else "weak"
        )
        fp_risk = "low" if status == "confirmed" else (
            "medium" if status == "probable" else "high"
        )
        return {
            "exploitability_status": status,
            "evidence_strength": evidence_strength,
            "false_positive_risk": fp_risk,
        }


def infer_parameter(finding: dict[str, Any]) -> str:
    if finding.get("parameter"):
        return str(finding.get("parameter"))
    for key in ("param", "bypass_header"):
        if finding.get(key):
            return str(finding.get(key))
    evidence = str(finding.get("evidence", ""))
    m = re.search(r"(?:param(?:eter)?|field)[=':\s]+([A-Za-z0-9_.-]+)", evidence, re.I)
    return m.group(1) if m else ""


def normalize_finding(finding: dict[str, Any], scan_id: str = "") -> dict[str, Any]:
    f = dict(finding or {})
    created = f.get("created_at") or f.get("timestamp") or now_iso()
    vuln = f.get("vulnerability_class") or f.get("vuln_type") or f.get("title") or "Unknown"
    title = f.get("title") or vuln
    url = f.get("affected_url") or f.get("url") or ""
    evidence = redact_secrets(str(f.get("evidence", "")))
    proof = ProofGate.evaluate({**f, "title": title, "vulnerability_class": vuln})

    normalized = {
        "id": f.get("id") or evidence_id(title + url + evidence),
        "scan_id": f.get("scan_id") or scan_id,
        "title": title,
        "vulnerability_class": vuln,
        "affected_url": url,
        "method": f.get("method") or "GET",
        "parameter": infer_parameter(f),
        "severity": str(f.get("severity") or "INFO").upper(),
        "confidence": int(float(f.get("confidence", 50) or 50)),
        "exploitability_status": f.get("exploitability_status") or proof["exploitability_status"],
        "evidence_strength": f.get("evidence_strength") or proof["evidence_strength"],
        "false_positive_risk": f.get("false_positive_risk") or proof["false_positive_risk"],
        "business_impact": f.get("business_impact") or f.get("triage", {}).get("impact_statement", ""),
        "technical_impact": f.get("technical_impact") or f.get("description", ""),
        "reproduction_steps": f.get("reproduction_steps") or [
            "Send {} request to {}".format(f.get("method", "GET"), url),
            "Observe the evidence captured by BurpOllama.",
        ],
        "safe_manual_validation_steps": f.get("safe_manual_validation_steps") or [
            "Validate only within authorized scope.",
            "Use a low-rate request in a test account or approved environment.",
            "Do not access, exfiltrate, or modify real user data.",
        ],
        "remediation": f.get("remediation", ""),
        "references": f.get("references") or [],
        "cwe": f.get("cwe", ""),
        "owasp_top_10": f.get("owasp_top_10", ""),
        "owasp_asvs_mapping": f.get("owasp_asvs_mapping", ""),
        "owasp_wstg_mapping": f.get("owasp_wstg_mapping", ""),
        "raw_evidence_id": f.get("raw_evidence_id") or evidence_id(evidence),
        "redaction_status": f.get("redaction_status") or "redacted",
        "created_at": created,
        "updated_at": now_iso(),
    }

    # Preserve legacy keys for existing dashboard/report code.
    normalized.update(f)
    normalized.update({
        "title": normalized["title"],
        "vulnerability_class": normalized["vulnerability_class"],
        "affected_url": normalized["affected_url"],
        "url": normalized["affected_url"],
        "vuln_type": normalized["vulnerability_class"],
        "timestamp": normalized["created_at"],
        "exploitability_status": normalized["exploitability_status"],
        "evidence_strength": normalized["evidence_strength"],
        "false_positive_risk": normalized["false_positive_risk"],
        "evidence": evidence,
    })
    return normalized


def normalize_findings(findings: list[dict[str, Any]], scan_id: str = "") -> list[dict[str, Any]]:
    return [normalize_finding(f, scan_id=scan_id) for f in findings or []]
