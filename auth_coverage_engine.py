"""Authenticated-scan readiness and authorization coverage analysis.

The goal is to make a scan's authentication posture explicit without storing or
displaying secrets.  This module answers: are logged-in surfaces configured,
which auth-sensitive endpoints were discovered, what was likely tested, and
what should be done next before trusting a clean result.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlparse

from coverage_intelligence import endpoint_template


AUTH_SENSITIVE_RE = re.compile(
    r"(?i)/(api|v\d|user|users|account|accounts|profile|profiles|order|orders|"
    r"invoice|invoices|payment|payments|billing|admin|dashboard|settings|"
    r"graphql|rest|basket|cart|checkout|document|documents|ticket|tickets|"
    r"message|messages|organization|tenant|team|member|members)"
)

ID_PARAM_RE = re.compile(r"(?i)(^|_)(id|user|account|order|invoice|tenant|org|team|member)(_|$)")


def _as_list(value) -> list:
    return value if isinstance(value, list) else []


def _session_ready(session: dict | None) -> bool:
    data = session if isinstance(session, dict) else {}
    return bool(data.get("configured")) and not bool(data.get("expired"))


def _session_warning(label: str, session: dict | None) -> list[str]:
    data = session if isinstance(session, dict) else {}
    warnings = []
    if not data.get("configured"):
        warnings.append("{} is not configured.".format(label))
    if data.get("expired"):
        warnings.append("{} is expired.".format(label))
    if data.get("expiring_soon"):
        warnings.append("{} expires soon; refresh before long scans.".format(label))
    return warnings


def classify_auth_endpoint(url: str) -> dict:
    """Classify a URL for authorization-testing priority."""
    parsed = urlparse(str(url or ""))
    path = parsed.path or "/"
    params = parse_qs(parsed.query or "")
    reasons = []
    score = 0
    if AUTH_SENSITIVE_RE.search(path):
        reasons.append("auth-sensitive path")
        score += 45
    if re.search(r"/(?:\d+|[0-9a-f]{8}-[0-9a-f-]{27,})(?:/|$)", path, re.I):
        reasons.append("object identifier in path")
        score += 25
    id_params = [name for name in params if ID_PARAM_RE.search(name)]
    if id_params:
        reasons.append("identifier parameter(s): {}".format(", ".join(id_params[:4])))
        score += min(25, len(id_params) * 8)
    if any(term in path.lower() for term in ("admin", "billing", "payment", "tenant", "organization")):
        reasons.append("high-impact role or tenant boundary")
        score += 20
    if "graphql" in path.lower():
        reasons.append("GraphQL authorization surface")
        score += 20
    return {
        "url": str(url),
        "template": endpoint_template(str(url)),
        "score": min(100, score),
        "reasons": reasons,
        "auth_sensitive": bool(reasons),
    }


def analyze_auth_coverage(
    recon_data: dict | None,
    auth_stats: dict | None,
    findings: list[dict] | None = None,
    coverage_data: dict | None = None,
) -> dict:
    """Return a secret-safe authenticated testing readiness report."""

    recon = recon_data if isinstance(recon_data, dict) else {}
    stats = auth_stats if isinstance(auth_stats, dict) else {}
    coverage = coverage_data if isinstance(coverage_data, dict) else {}
    findings = [f for f in (findings or []) if isinstance(f, dict)]

    session_a = stats.get("session_a") if isinstance(stats.get("session_a"), dict) else {}
    session_b = stats.get("session_b") if isinstance(stats.get("session_b"), dict) else {}
    a_ready = _session_ready(session_a)
    b_ready = _session_ready(session_b)
    dual_ready = a_ready and b_ready
    single_ready = a_ready or b_ready

    urls = [str(url) for url in _as_list(recon.get("urls")) if str(url).strip()]
    classified = [classify_auth_endpoint(url) for url in urls]
    auth_targets = [item for item in classified if item["auth_sensitive"]]
    auth_targets.sort(key=lambda item: item["score"], reverse=True)
    unique_templates = sorted({item["template"] for item in auth_targets})

    auth_findings = []
    for finding in findings:
        blob = "{} {} {}".format(
            finding.get("vuln_type", ""),
            finding.get("title", ""),
            finding.get("description", ""),
        ).lower()
        if any(term in blob for term in ("idor", "bola", "auth", "authorization", "privilege", "session", "jwt", "oauth")):
            auth_findings.append({
                "id": finding.get("id", ""),
                "type": finding.get("vuln_type") or finding.get("title", ""),
                "severity": finding.get("severity", "INFO"),
                "url": finding.get("affected_url") or finding.get("url", ""),
                "status": finding.get("exploitability_status") or finding.get("verdict", ""),
            })

    tested_count = int(stats.get("tested", 0) or 0)
    violations = int(stats.get("violations", 0) or 0)
    auth_target_count = len(unique_templates)
    tested_percent = round(
        min(100.0, tested_count / max(1, auth_target_count) * 100),
        1,
    )

    warnings = []
    warnings.extend(_session_warning("Session A", session_a))
    warnings.extend(_session_warning("Session B", session_b))
    if not dual_ready and auth_target_count:
        warnings.append("Dual-session BOLA/IDOR proof is not ready for {} sensitive endpoint template(s).".format(auth_target_count))
    if coverage.get("skipped_due_to_missing_auth"):
        warnings.append("{} scan event(s) indicate missing authentication.".format(coverage.get("skipped_due_to_missing_auth")))
    if auth_target_count and tested_count == 0 and dual_ready:
        warnings.append("Dual sessions are configured, but no authorization-matrix endpoints have been tested yet.")

    next_steps = []
    if not single_ready:
        next_steps.append("Add at least one valid logged-in session so the crawler can reach authenticated pages.")
    if not dual_ready:
        next_steps.append("Add two different user sessions to prove IDOR/BOLA and role-boundary issues.")
    if session_a.get("expiring_soon") or session_b.get("expiring_soon"):
        next_steps.append("Refresh expiring session credentials before starting a DEEP scan.")
    if auth_targets:
        next_steps.append("Run authorization checks against the highest-priority templates first: {}".format(
            ", ".join(item["template"] for item in auth_targets[:3])
        ))
    if not auth_targets and urls:
        next_steps.append("Improve authenticated crawling; no obvious account/API/admin endpoints were discovered.")

    readiness_score = 0
    if single_ready:
        readiness_score += 25
    if dual_ready:
        readiness_score += 35
    readiness_score += min(25, int(tested_percent * 0.25))
    if auth_findings:
        readiness_score += 10
    if warnings:
        readiness_score -= min(20, len(warnings) * 5)
    readiness_score = max(0, min(100, readiness_score))

    if readiness_score >= 75:
        status = "ready"
    elif readiness_score >= 40:
        status = "partial"
    else:
        status = "not_ready"

    return {
        "version": "1.0",
        "status": status,
        "readiness_score": readiness_score,
        "sessions": {
            "single_session_ready": single_ready,
            "dual_session_ready": dual_ready,
            "mutations_allowed": bool(stats.get("mutations_allowed")),
            "session_a": session_a,
            "session_b": session_b,
        },
        "authorization_surface": {
            "sensitive_endpoint_templates": auth_target_count,
            "top_targets": auth_targets[:25],
            "tested_by_matrix": tested_count,
            "tested_percent": tested_percent,
            "violations": violations,
            "related_findings": auth_findings[:25],
        },
        "warnings": warnings,
        "next_steps": next_steps,
    }
