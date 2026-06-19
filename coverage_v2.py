"""
coverage_v2.py - richer scan coverage accounting.
"""

from __future__ import annotations

from urllib.parse import urlparse

from coverage_intelligence import endpoint_risk, endpoint_template
from scope_policy import scope_policy


def compute_coverage_v2(
    scan_id: str,
    recon_data: dict,
    findings: list[dict],
    tested_urls: list[str] | None = None,
    logs: list[dict] | None = None,
) -> dict:
    discovered = list(dict.fromkeys(recon_data.get("urls", []) or []))
    tested = list(dict.fromkeys(tested_urls or [f.get("affected_url") or f.get("url", "") for f in findings if f.get("affected_url") or f.get("url")]))

    discovered_templates = {endpoint_template(u) for u in discovered}
    tested_templates = {endpoint_template(u) for u in tested if u}
    untested = [u for u in discovered if endpoint_template(u) not in tested_templates]

    skipped_scope = []
    for u in discovered:
        ok, reason = scope_policy.validate_target(u, action="active")
        if (not ok) and ("scope" in reason.lower() or "outside" in reason.lower() or "blocked" in reason.lower()):
            skipped_scope.append({"url": u, "reason": reason})

    log_text = "\n".join(str(l.get("msg", "")) for l in (logs or []))
    skipped_rate = log_text.lower().count("max_requests") + log_text.lower().count("rate limit")
    skipped_auth = log_text.lower().count("auth matrix skipped") + log_text.lower().count("missing auth")
    skipped_safety = log_text.lower().count("skipped by scopepolicy") + log_text.lower().count("passive-only")

    high_risk = []
    for u in untested:
        risk = endpoint_risk(u)
        if risk["score"] >= 40:
            high_risk.append({"url": u, **risk})
    high_risk.sort(key=lambda x: x["score"], reverse=True)

    total = max(1, len(discovered_templates))
    return {
        "scan_id": scan_id,
        "discovered_endpoints": len(discovered_templates),
        "tested_endpoints": len(discovered_templates & tested_templates),
        "untested_endpoints": max(0, len(discovered_templates - tested_templates)),
        "coverage_percent": round(len(discovered_templates & tested_templates) / total * 100, 1),
        "skipped_due_to_scope": skipped_scope[:100],
        "skipped_due_to_rate_limit": skipped_rate,
        "skipped_due_to_missing_auth": skipped_auth,
        "skipped_due_to_safety_mode": skipped_safety,
        "high_risk_untested_urls": high_risk[:50],
        "tested_assets": sorted({urlparse(u).netloc for u in tested if u}),
        "discovered_assets": sorted({urlparse(u).netloc for u in discovered if u}),
    }
