"""
coverage_intelligence.py - tested/untested surface quantification and priority.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from urllib.parse import urlparse, parse_qs


AUTH_HINTS = ("login", "logout", "session", "oauth", "saml", "token", "jwt", "password", "reset")
ADMIN_HINTS = ("admin", "manage", "internal", "debug", "actuator", "console", "ops")
SENSITIVE_HINTS = ("user", "account", "billing", "payment", "order", "profile", "invoice", "ssn")
WRITE_METHOD_HINTS = ("create", "update", "delete", "upload", "import", "export")


def endpoint_template(url: str) -> str:
    parsed = urlparse(url or "")
    path = re.sub(r"/\d+(?=/|$)", "/:id", parsed.path or "/")
    path = re.sub(r"/[0-9a-f]{8}-[0-9a-f-]{27,}(?=/|$)", "/:uuid", path, flags=re.I)
    return "{}://{}{}".format(parsed.scheme, parsed.netloc, path)


def endpoint_risk(url: str, tech: list[str] | None = None) -> dict:
    parsed = urlparse(url or "")
    blob = "{} {}".format(parsed.path, parsed.query).lower()
    score = 10
    reasons = []
    for label, hints, weight in (
        ("auth", AUTH_HINTS, 35),
        ("admin", ADMIN_HINTS, 30),
        ("sensitive-data", SENSITIVE_HINTS, 25),
        ("state-changing", WRITE_METHOD_HINTS, 15),
    ):
        if any(h in blob for h in hints):
            score += weight
            reasons.append(label)
    params = parse_qs(parsed.query)
    if params:
        score += min(20, len(params) * 4)
        reasons.append("parameterized")
    tech_blob = " ".join(tech or []).lower()
    if "graphql" in tech_blob or "graphql" in blob:
        score += 20
        reasons.append("graphql")
    if "swagger" in blob or "openapi" in blob:
        score += 15
        reasons.append("api-schema")
    return {"score": min(score, 100), "reasons": reasons}


def prioritize_urls(urls: list[str], live_hosts: list[dict] | None = None) -> list[str]:
    host_tech = {}
    for host in live_hosts or []:
        parsed = urlparse(host.get("url", ""))
        host_tech[parsed.netloc] = host.get("tech", [])
    return sorted(
        urls,
        key=lambda u: endpoint_risk(u, host_tech.get(urlparse(u).netloc, [])).get("score", 0),
        reverse=True,
    )


def compute_coverage(recon_data: dict, findings: list[dict], tested_urls: list[str] | None = None) -> dict:
    urls = recon_data.get("urls", []) or []
    templates = {endpoint_template(u) for u in urls}
    tested = {endpoint_template(u) for u in (tested_urls or [f.get("url", "") for f in findings]) if u}
    finding_templates = {endpoint_template(f.get("url", "")) for f in findings if f.get("url")}
    vuln_counts = Counter(f.get("vuln_type", "Unknown") for f in findings)

    risk_buckets = defaultdict(int)
    untested_priority = []
    for url in urls:
        tpl = endpoint_template(url)
        risk = endpoint_risk(url)
        bucket = "high" if risk["score"] >= 70 else ("medium" if risk["score"] >= 40 else "low")
        risk_buckets[bucket] += 1
        if tpl not in tested:
            untested_priority.append({"url": url, **risk})

    untested_priority.sort(key=lambda x: x["score"], reverse=True)
    total = max(1, len(templates))
    covered = len(templates & tested)
    return {
        "surface_templates": len(templates),
        "tested_templates": covered,
        "untested_templates": max(0, len(templates) - covered),
        "coverage_percent": round(covered / total * 100, 1),
        "finding_surface_percent": round(len(finding_templates) / total * 100, 1),
        "risk_buckets": dict(risk_buckets),
        "top_untested": untested_priority[:25],
        "vulnerability_probability": vuln_counts.most_common(20),
    }
