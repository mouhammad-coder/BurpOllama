"""Deterministic CVSS++ real-impact scoring for bug-bounty prioritization."""

from __future__ import annotations

from cvss import CVSS4
from urllib.parse import urlparse


BASE_SCORES = {
    "sql injection": 9.0, "rce": 10.0, "command injection": 9.5,
    "idor": 7.0, "bola": 7.0, "broken access control": 7.5,
    "xss": 6.0, "stored xss": 7.0, "blind xss": 7.5,
    "ssrf": 8.0, "xxe": 7.5, "ssti": 8.5,
    "jwt": 7.0, "oauth": 7.0, "open redirect": 3.5,
    "csrf": 5.5, "path traversal": 6.5, "lfi": 7.5,
    "prototype pollution": 6.0, "mass assignment": 6.5,
    "nosql injection": 7.5, "crlf injection": 5.0,
    "host header injection": 5.5, "cache poisoning": 7.0,
    "default credentials": 9.0, "cors": 5.0,
    "subdomain takeover": 6.5, "secret": 8.0,
    "rate limit": 4.0, "security headers": 2.0,
}

SEVERITY_FALLBACK = {
    "CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0,
    "LOW": 3.0, "INFO": 1.0, "INFORMATIONAL": 1.0,
}


def calculate_official_cvss_40(finding: dict) -> dict:
    """
    Calculate an official CVSS 4.0 score using the cvss library.

    Finding metadata is mapped to the CVSS 4.0 base metrics, while all score
    computation and severity classification are delegated to CVSS4.
    """
    finding = finding or {}

    # AV: Attack Vector
    av = "N"

    # AC: Attack Complexity
    ac = (
        "L"
        if str(finding.get("exploitability_status", "")).lower() == "confirmed"
        else "H"
    )

    # AT: Attack Requirements
    at = "N"

    # PR: Privileges Required
    url = str(
        finding.get("affected_url") or finding.get("url", "")
    ).lower()
    pr = "H" if "admin" in url else ("L" if finding.get("requires_auth") else "N")

    # UI: User Interaction
    vt = str(finding.get("vuln_type", "")).lower()
    ui = "A" if any(
        keyword in vt for keyword in ("xss", "csrf", "clickjacking")
    ) else "N"

    # VC/VI/VA: impact to the vulnerable system
    vc = (
        "H"
        if any(keyword in vt for keyword in ("sqli", "idor", "ssrf", "rce", "secret"))
        else "L"
        if any(keyword in vt for keyword in ("xss", "cors", "redirect"))
        else "N"
    )
    vi = (
        "H"
        if any(keyword in vt for keyword in ("sqli", "rce", "command", "upload"))
        else "L"
        if any(keyword in vt for keyword in ("csrf", "idor", "mass assignment"))
        else "N"
    )
    va = (
        "L"
        if any(keyword in vt for keyword in ("dos", "rate limit", "regex"))
        else "N"
    )

    # SC/SI/SA: impact to subsequent systems
    sc = (
        "H"
        if any(keyword in vt for keyword in ("ssrf", "xxe", "rce"))
        else "N"
    )
    si = "N"
    sa = "N"

    vector = (
        "CVSS:4.0/AV:{}/AC:{}/AT:{}/PR:{}/UI:{}/"
        "VC:{}/VI:{}/VA:{}/SC:{}/SI:{}/SA:{}"
    ).format(av, ac, at, pr, ui, vc, vi, va, sc, si, sa)

    try:
        score = CVSS4(vector)
        return {
            "cvss_40_score": float(score.base_score),
            "cvss_40_vector": vector,
            "cvss_40_severity": score.severity,
            "cvss_40_official": True,
        }
    except Exception as exc:
        return {
            "cvss_40_score": 0.0,
            "cvss_40_vector": vector,
            "cvss_40_severity": "Unknown",
            "cvss_40_official": False,
            "cvss_40_error": str(exc),
        }


def _base_score(finding: dict) -> float:
    text = " ".join(str(finding.get(key, "")) for key in (
        "vuln_type", "title", "vulnerability_class", "description",
    )).lower()
    for name in sorted(BASE_SCORES, key=len, reverse=True):
        if name in text:
            return BASE_SCORES[name]
    return SEVERITY_FALLBACK.get(
        str(finding.get("severity", "INFO")).upper(), 1.0
    )


def _in_chain(finding: dict, chain_data: dict | None) -> bool:
    finding_id = str(finding.get("id", ""))
    if not finding_id or not isinstance(chain_data, dict):
        return False
    return any(
        finding_id in {
            str(item) for item in chain.get("affected_findings", [])
        }
        for chain in chain_data.get("chains", [])
        if isinstance(chain, dict)
    )


def _classification(score: float) -> str:
    if score >= 8.5:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def score_finding(finding: dict, chain_data: dict = None) -> dict:
    """Apply deterministic additive CVSS++ modifiers and clamp to 10.0."""
    finding = finding or {}
    base = _base_score(finding)
    modifiers: list[tuple[str, float]] = []
    status = str(finding.get("exploitability_status", "")).lower()
    url = str(finding.get("affected_url") or finding.get("url") or "")
    path = urlparse(url).path.lower()
    url_lower = url.lower()
    severity = str(finding.get("severity", "")).upper()
    confidence = float(finding.get("confidence", 0) or 0)

    if status == "confirmed":
        modifiers.append(("confirmed exploitability", 1.5))
    elif status == "probable":
        modifiers.append(("probable exploitability", 0.5))
    if "/user/" not in path and "/account/" not in path:
        modifiers.append(("no authentication path detected", 1.0))
    if any(term in url_lower for term in ("payment", "billing", "checkout", "invoice")):
        modifiers.append(("payment context", 2.0))
    if any(term in url_lower for term in ("admin", "manage", "console", "internal")):
        modifiers.append(("admin endpoint", 1.5))
    if any(term in url_lower for term in ("user", "account", "profile", "email")):
        modifiers.append(("user-data context", 1.0))
    if severity == "CRITICAL":
        modifiers.append(("critical severity", 1.0))
    chain_bonus = _in_chain(finding, chain_data)
    if chain_bonus:
        modifiers.append(("exploit-chain participation", 1.5))
    if confidence >= 90:
        modifiers.append(("high scanner confidence", 0.5))

    total_modifier = round(sum(value for _name, value in modifiers), 2)
    final = round(min(10.0, max(0.0, base + total_modifier)), 1)
    return {
        "cvss_plus_plus": final,
        "classification": _classification(final),
        "base_score": round(base, 1),
        "modifiers_applied": [
            f"{name}: +{value:.1f}" for name, value in modifiers
        ],
        "total_modifier": total_modifier,
        "chain_bonus_applied": chain_bonus,
    }
