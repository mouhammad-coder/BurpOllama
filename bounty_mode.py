"""
bounty_mode.py - dashboard-first bug bounty prioritization and report builder.

This does not run new tests. It focuses existing scan output on valid,
high-impact, reportable findings and clearly separates confirmed proof from
candidate/manual-validation work.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from finding_model import normalize_finding, normalize_findings
from security_hardening import escape_markdown_table, safe_code_block
from zero_fp_gate import apply_zero_fp_gate


BOUNTY_CLASSES = {
    "idor", "bola", "broken access", "access control", "account takeover",
    "oauth", "jwt", "graphql authorization", "ssrf", "oob", "secret",
    "api key", "token", "upload", "business logic", "rate limit",
}


def _is_bounty_class(f: dict[str, Any]) -> bool:
    text = " ".join(str(f.get(k, "")) for k in (
        "title", "vulnerability_class", "vuln_type", "technical_impact",
        "business_impact", "description",
    )).lower()
    return any(cls in text for cls in BOUNTY_CLASSES)


def _why_bounty_worthy(f: dict[str, Any]) -> str:
    text = " ".join(str(f.get(k, "")) for k in ("title", "vulnerability_class", "technical_impact")).lower()
    if "idor" in text or "bola" in text or "access control" in text:
        return "Potential unauthorized access to another user, tenant, object, or privileged function."
    if "account takeover" in text or "oauth" in text or "jwt" in text:
        return "May affect authentication, authorization, session integrity, or account takeover risk."
    if "graphql" in text:
        return "GraphQL authorization flaws can expose broad object graphs through resolver-level access gaps."
    if "ssrf" in text or "oob" in text:
        return "Server-side outbound interaction can expose internal services or cloud metadata when proven."
    if "secret" in text or "token" in text or "api key" in text:
        return "Exposed credentials or tokens can create direct unauthorized access if validated and safely redacted."
    if "upload" in text:
        return "Upload abuse can lead to stored XSS, malware hosting, content-type bypass, or code execution chains."
    if "business logic" in text:
        return "Business logic issues can produce financial, authorization, entitlement, or workflow abuse impact."
    if "rate" in text:
        return "Rate-limit weaknesses matter when they affect auth, OTP, password reset, payments, or abuse-sensitive flows."
    return "High-impact class commonly accepted by bug bounty programs when proof and impact are concrete."


def _missing_proof(f: dict[str, Any]) -> list[str]:
    missing = []
    status = f.get("exploitability_status", "candidate")
    if status != "confirmed":
        missing.append("Confirmed exploitability proof")
    if f.get("evidence_strength") != "strong":
        missing.append("Strong reproducible evidence")
    if not f.get("business_impact"):
        missing.append("Concrete business impact")
    if not f.get("parameter") and any(k in (f.get("vulnerability_class", "").lower()) for k in ("idor", "oauth", "jwt", "graphql", "upload")):
        missing.append("Affected parameter or object identifier")
    if not f.get("reproduction_steps"):
        missing.append("Step-by-step reproduction")
    return missing


def _bounty_item(finding: dict[str, Any]) -> dict[str, Any]:
    original_quality = finding.get("quality", {})
    f = normalize_finding(finding)
    quality = original_quality or f.get("quality", {})
    return {
        "id": f.get("id", ""),
        "title": f.get("title", ""),
        "affected_asset": f.get("affected_url") or f.get("url", ""),
        "severity": f.get("severity", "INFO"),
        "confidence": f.get("confidence", 0),
        "proof_status": f.get("exploitability_status", "candidate"),
        "evidence_strength": f.get("evidence_strength", "weak"),
        "impact": f.get("business_impact") or f.get("technical_impact", ""),
        "steps_to_reproduce": f.get("reproduction_steps", []),
        "safe_manual_validation_steps": f.get("safe_manual_validation_steps", []),
        "evidence": f.get("evidence", ""),
        "why_bounty_worthy": _why_bounty_worthy(f),
        "missing_proof": _missing_proof(f),
        "remediation": f.get("remediation", ""),
        "cwe": f.get("cwe", ""),
        "owasp_top_10": f.get("owasp_top_10", ""),
        "quality_score": f.get("quality_score", 0),
        "grade": f.get("grade") or f.get("quality_grade", "F"),
        "quality_grade": f.get("grade") or f.get("quality_grade", "F"),
        "ready_to_submit": bool(
            int(f.get("quality_score", 0) or 0) >= 85
            and str(f.get("grade") or f.get("quality_grade", "")).upper() == "A"
        ),
        "quality": quality,
        "quality_label": quality.get("label", f.get("quality_label", "CANDIDATE")),
        "quality_bucket": quality.get("bucket", f.get("quality_bucket", "candidate")),
        "failed_quality_checks": quality.get("failed_checks", f.get("failed_quality_checks", [])),
        "raw": f,
    }


def build_bounty_mode(scan: dict, scope: dict, session_status: dict, coverage: dict) -> dict:
    findings = normalize_findings(scan.get("triaged_findings") or scan.get("raw_findings") or [])
    gated = apply_zero_fp_gate(
        findings,
        scope,
        scan.get("exploit_chains")
        or scan.get("analysis", {}).get("exploit_chains"),
        tech_stack=scan.get("recon", {}).get("tech_stack", []),
        scan_context={"recon": scan.get("recon", {})},
    )

    def gate_items(bucket: str, label: str, quality_bucket: str) -> list[dict[str, Any]]:
        out = []
        for finding in gated.get(bucket, []):
            if not _is_bounty_class(finding):
                continue
            enriched = dict(finding)
            item_label = finding.get("zero_fp_label") or label
            item_bucket = "ready" if item_label == "READY" else quality_bucket
            enriched["quality"] = {
                "label": item_label,
                "bucket": item_bucket,
                "failed_checks": finding.get("zero_fp_failed_checks", []),
            }
            out.append(_bounty_item(enriched))
        return out

    valid_bugs = gate_items("valid_bugs", "VALID", "valid")
    ready = [
        finding for finding in valid_bugs
        if finding.get("ready_to_submit")
    ]
    needs_more_proof = gate_items("needs_more_proof", "NEEDS PROOF", "needs_more_proof")
    informational = gate_items("informational", "INFO", "informational")
    false_positive = gate_items("false_positives_removed", "REMOVED", "false_positive")
    candidates = gate_items("candidates", "CANDIDATE", "candidate")
    high_value = coverage.get("high_risk_untested_urls") or coverage.get("top_untested") or []
    sessions_configured = bool(session_status.get("configured"))
    return {
        "generated_at": datetime.utcnow().isoformat(),
        "selected_scan": {
            "id": scan.get("id", ""),
            "target": scan.get("target", ""),
            "status": scan.get("status", ""),
            "phase": scan.get("phase", ""),
        },
        "scope_status": {
            "scan_mode": scope.get("scan_mode"),
            "passive_only_mode": scope.get("passive_only_mode"),
            "active_testing_enabled": scope.get("active_testing_enabled"),
            "authenticated_testing_enabled": scope.get("authenticated_testing_enabled"),
            "oob_testing_enabled": scope.get("oob_testing_enabled"),
            "cloud_ai_enabled": scope.get("cloud_ai_enabled"),
            "emergency_stop": scope.get("emergency_stop"),
            "allowed_domains": scope.get("allowed_domains", []),
            "blocked_domains": scope.get("blocked_domains", []),
        },
        "sessions": {
            "configured": sessions_configured,
            "session_a": session_status.get("session_a") or ("ready" if sessions_configured else "missing"),
            "session_b": session_status.get("session_b") or ("ready" if sessions_configured else "missing"),
            "stats": session_status,
        },
        "high_value_endpoints": high_value[:30],
        "zero_false_positive_mode": True,
        "ready_findings": ready,
        "valid_bugs": valid_bugs,
        "confirmed_bounty_findings": ready,
        "needs_more_proof": needs_more_proof,
        "informational_findings": informational,
        "false_positives_removed": false_positive,
        "candidate_bounty_findings": candidates,
        "skipped_websites": coverage.get("skipped_due_to_scope", []),
        "missing_proof": [
            {"id": f["id"], "title": f["title"], "missing": f["missing_proof"] + f.get("failed_quality_checks", [])}
            for f in needs_more_proof + candidates if f["missing_proof"] or f.get("failed_quality_checks")
        ],
        "manual_validation_steps": [
            {"id": f["id"], "title": f["title"], "steps": f["safe_manual_validation_steps"]}
            for f in candidates
        ],
    }


def _finding_markdown(f: dict[str, Any], platform: str) -> str:
    lines = [
        "## Summary",
        "",
        f["title"],
        "",
        "## Affected Asset",
        "",
        "`{}`".format(escape_markdown_table(f["affected_asset"])),
        "",
        "## Severity And Confidence",
        "",
        "- **Severity:** {}".format(escape_markdown_table(f["severity"])),
        "- **Confidence:** {}%".format(escape_markdown_table(f["confidence"])),
        "- **Proof status:** {}".format(escape_markdown_table(f["proof_status"])),
        "",
        "## Why This Is Bounty-Worthy",
        "",
        escape_markdown_table(f["why_bounty_worthy"]),
        "",
        "## Impact",
        "",
        safe_code_block(f["impact"]),
        "",
        "## Steps To Reproduce",
        "",
    ]
    for i, step in enumerate(f["steps_to_reproduce"] or [], 1):
        lines.append("{}. {}".format(i, escape_markdown_table(step)))
    lines.extend(["", "## Evidence", "", "```", safe_code_block(f["evidence"]), "```", ""])
    if f["missing_proof"]:
        lines.extend(["## Missing Proof / Validation Needed", ""])
        for item in f["missing_proof"]:
            lines.append("- {}".format(escape_markdown_table(item)))
        lines.append("")
    lines.extend(["## Safe Manual Validation", ""])
    for step in f["safe_manual_validation_steps"] or []:
        lines.append("- {}".format(escape_markdown_table(step)))
    lines.extend(["", "## Remediation", "", safe_code_block(f["remediation"]), ""])
    if platform.lower() == "bugcrowd":
        lines.extend(["## Vulnerability Classification", "", "- **CWE:** {}".format(escape_markdown_table(f.get("cwe", "")))])
    return "\n".join(lines)


def build_bounty_report(data: dict, platform: str = "hackerone") -> str:
    confirmed = data.get("ready_findings", data.get("confirmed_bounty_findings", []))
    lines = [
        "# BurpOllama Bounty Mode Report",
        "",
        "| Field | Value |",
        "|---|---|",
        "| Platform style | {} |".format(escape_markdown_table(platform)),
        "| Scan | `{}` |".format(escape_markdown_table(data.get("selected_scan", {}).get("id", ""))),
        "| Target | `{}` |".format(escape_markdown_table(data.get("selected_scan", {}).get("target", ""))),
        "| READY findings included | {} |".format(len(confirmed)),
        "| Zero False Positive Mode | ON |",
        "",
        "> Only READY findings are included in bounty reports.",
        "",
        "## READY Findings",
        "",
    ]
    if confirmed:
        for f in confirmed:
            lines.append(_finding_markdown(f, platform))
            lines.append("\n---\n")
    else:
        lines.append("No READY findings currently meet the bounty report threshold.")
    return "\n".join(lines)


def build_single_bounty_report(data: dict, finding_id: str, platform: str = "hackerone") -> str:
    for f in data.get("ready_findings", data.get("confirmed_bounty_findings", [])):
        if f.get("id") == finding_id:
            return _finding_markdown(f, platform)
    return ""
