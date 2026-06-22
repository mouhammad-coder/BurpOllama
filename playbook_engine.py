"""Evidence-driven scan playbooks and gap analysis.

This module turns recon, findings, and coverage into a practical testing
playbook.  It is intentionally deterministic and offline: the output is safe to
show in the dashboard, use from the CLI, and store with scan artifacts.
"""

from __future__ import annotations

import re
from collections import Counter
from urllib.parse import parse_qs, urlparse

from coverage_intelligence import endpoint_risk


CRITICAL_BUG_BOUNTY_CLASSES = [
    "Access Control / IDOR",
    "Authentication and Session Management",
    "API Authorization",
    "Injection",
    "XSS and Client-Side Security",
    "SSRF and Server-Side Request Forgery",
    "Sensitive Data Exposure",
    "Business Logic",
    "File Upload and Path Traversal",
    "Rate Limiting and Abuse Controls",
    "Security Misconfiguration",
    "Cryptography and Token Security",
]


PLAYBOOKS = [
    {
        "id": "access-control-idor",
        "title": "Access Control / IDOR",
        "wstg": ["WSTG-ATHZ-01", "WSTG-ATHZ-02", "WSTG-ATHZ-03", "API1:BOLA"],
        "signals": ("user", "account", "profile", "order", "invoice", "basket", "cart", "admin"),
        "recommended_tests": [
            "Compare object access with two authorized sessions.",
            "Change numeric IDs, UUIDs, usernames, and account identifiers.",
            "Verify collection endpoints do not leak cross-tenant objects.",
            "Check admin and self-service APIs for role/tenant enforcement.",
        ],
        "requires_auth": True,
        "risk": 100,
    },
    {
        "id": "auth-session",
        "title": "Authentication and Session Management",
        "wstg": ["WSTG-ATHN-01", "WSTG-SESS-01", "WSTG-SESS-02", "WSTG-SESS-05"],
        "signals": ("login", "logout", "session", "password", "reset", "oauth", "saml", "jwt"),
        "recommended_tests": [
            "Verify logout invalidates server-side sessions.",
            "Check password reset and OAuth callback flows for token leakage.",
            "Inspect cookie flags, SameSite behavior, and session fixation.",
            "Confirm JWT signature, algorithm, expiry, issuer, and audience checks.",
        ],
        "requires_auth": False,
        "risk": 94,
    },
    {
        "id": "api-authorization",
        "title": "API Authorization",
        "wstg": ["WSTG-ATHZ-01", "API3:BOPLA", "API5:BFLA"],
        "signals": ("api", "graphql", "rest", "v1", "v2", "mutation"),
        "recommended_tests": [
            "Test every discovered API route with low-privilege and unauthenticated sessions.",
            "Compare GraphQL query and mutation results across roles.",
            "Review versioned APIs for older authorization behavior.",
            "Check mass-assignment fields such as role, isAdmin, plan, and tenant.",
        ],
        "requires_auth": True,
        "risk": 93,
    },
    {
        "id": "injection",
        "title": "Injection",
        "wstg": ["WSTG-INPV-05", "WSTG-INPV-07", "WSTG-INPV-12", "API8:Injection"],
        "signals": ("search", "query", "filter", "sort", "where", "sql", "cmd", "exec"),
        "recommended_tests": [
            "Prioritize parameterized search, filter, export, and report endpoints.",
            "Look for reflected database, parser, template, and command errors.",
            "Use time/OOB confirmation only where explicitly allowed.",
            "Validate impact with scoped, non-destructive proof.",
        ],
        "requires_auth": False,
        "risk": 91,
    },
    {
        "id": "xss-client",
        "title": "XSS and Client-Side Security",
        "wstg": ["WSTG-INPV-01", "WSTG-CLNT-01", "WSTG-CLNT-05", "WSTG-CLNT-10"],
        "signals": ("q=", "search", "redirect", "return", "callback", "message", "html"),
        "recommended_tests": [
            "Test reflected parameters with context-aware payloads.",
            "Review client-side routes and DOM sinks from downloaded JavaScript.",
            "Check CSP, frame protections, postMessage handlers, and source maps.",
            "Prefer harmless proof such as alert-free DOM marker execution.",
        ],
        "requires_auth": False,
        "risk": 82,
    },
    {
        "id": "ssrf",
        "title": "SSRF and Server-Side Request Forgery",
        "wstg": ["WSTG-INPV-19", "API7:SSRF"],
        "signals": ("url", "uri", "webhook", "callback", "fetch", "image", "avatar", "import"),
        "recommended_tests": [
            "Identify server-side URL fetchers and webhook validators.",
            "Use OOB confirmation only when the program allows it.",
            "Check internal-address filtering and DNS rebinding defenses manually.",
            "Validate impact with metadata-safe, non-sensitive destinations.",
        ],
        "requires_auth": False,
        "risk": 86,
    },
    {
        "id": "sensitive-exposure",
        "title": "Sensitive Data Exposure",
        "wstg": ["WSTG-CONF-04", "WSTG-CONF-05", "WSTG-INFO-05"],
        "signals": (".env", ".git", "backup", "config", "debug", "swagger", "openapi", "api-docs"),
        "recommended_tests": [
            "Verify exposed config, git, backup, logs, debug, and API docs paths.",
            "Validate secrets safely without disclosing or abusing them.",
            "Check JavaScript bundles for endpoints, tokens, and source maps.",
            "Confirm whether exposed data is production, scoped, and bounty-relevant.",
        ],
        "requires_auth": False,
        "risk": 84,
    },
    {
        "id": "business-logic",
        "title": "Business Logic",
        "wstg": ["WSTG-BUSL-01", "WSTG-BUSL-04", "WSTG-BUSL-08", "API6:Unrestricted Access"],
        "signals": ("checkout", "payment", "coupon", "cart", "basket", "order", "invite", "workflow"),
        "recommended_tests": [
            "Map multi-step flows and try safe step reordering or replay.",
            "Check coupons, carts, inventory, entitlement, invitation, and upgrade flows.",
            "Look for missing rate limits on expensive or abuse-prone actions.",
            "Use test accounts and avoid irreversible or financial actions.",
        ],
        "requires_auth": True,
        "risk": 88,
    },
    {
        "id": "file-path",
        "title": "File Upload and Path Traversal",
        "wstg": ["WSTG-BUSL-09", "WSTG-INPV-11", "WSTG-INPV-18"],
        "signals": ("upload", "file", "download", "path", "filename", "avatar", "import", "export"),
        "recommended_tests": [
            "Review upload type, extension, content, and storage-location controls.",
            "Check downloads and exports for traversal and authorization.",
            "Validate archive handling and metadata processing where allowed.",
            "Use benign files and non-destructive traversal checks.",
        ],
        "requires_auth": False,
        "risk": 80,
    },
    {
        "id": "rate-limit-abuse",
        "title": "Rate Limiting and Abuse Controls",
        "wstg": ["WSTG-ATHN-03", "WSTG-BUSL-04", "API4:Unrestricted Resource Consumption"],
        "signals": ("login", "otp", "mfa", "reset", "invite", "coupon", "search", "export"),
        "recommended_tests": [
            "Check login, OTP, password reset, invitation, and coupon brute-force controls.",
            "Identify expensive queries, exports, and unauthenticated API calls.",
            "Keep request volume inside the target program rules.",
            "Report missing controls with minimal, bounded evidence.",
        ],
        "requires_auth": False,
        "risk": 76,
    },
    {
        "id": "security-misconfiguration",
        "title": "Security Misconfiguration",
        "wstg": ["WSTG-CONF-01", "WSTG-CONF-02", "WSTG-CONF-06", "WSTG-CONF-07"],
        "signals": ("admin", "actuator", "console", "metrics", "status", "health", "debug"),
        "recommended_tests": [
            "Review security headers, CORS, debug endpoints, and framework consoles.",
            "Check exposed metrics, health, actuator, and admin panels.",
            "Validate WAF/CDN behavior without bypass or evasion attempts.",
            "Confirm misconfiguration impact beyond informational exposure.",
        ],
        "requires_auth": False,
        "risk": 72,
    },
    {
        "id": "crypto-token",
        "title": "Cryptography and Token Security",
        "wstg": ["WSTG-CRYP-01", "WSTG-SESS-10", "WSTG-ATHN-10"],
        "signals": ("token", "jwt", "signature", "crypto", "hash", "secret", "key"),
        "recommended_tests": [
            "Check JWT and signed tokens for weak algorithms and missing claims.",
            "Review token expiry, rotation, replay, and audience/issuer validation.",
            "Look for secrets in JavaScript, config, and public repositories.",
            "Never brute-force or abuse live secrets; validate safely.",
        ],
        "requires_auth": False,
        "risk": 78,
    },
]


def _safe_list(value) -> list:
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    return []


def _text_surface(recon_data: dict, findings: list[dict]) -> str:
    urls = _safe_list(recon_data.get("urls"))[:1000]
    js = _safe_list(recon_data.get("js_findings"))[:100]
    tech = recon_data.get("tech_stack") or recon_data.get("technologies") or []
    if isinstance(tech, dict):
        tech = list(tech.keys())
    finding_text = [
        "{} {} {}".format(
            f.get("vuln_type", ""),
            f.get("title", ""),
            f.get("url") or f.get("affected_url") or "",
        )
        for f in findings[:500]
        if isinstance(f, dict)
    ]
    return " ".join(
        [str(u) for u in urls]
        + [str(item.get("type", "")) + " " + str(item.get("file", "")) for item in js if isinstance(item, dict)]
        + [str(t) for t in _safe_list(tech)]
        + finding_text
    ).lower()


def _endpoint_stats(urls: list[str]) -> dict:
    hosts = Counter()
    params = Counter()
    high_risk = []
    for url in urls:
        parsed = urlparse(str(url))
        if parsed.netloc:
            hosts[parsed.netloc] += 1
        for param in parse_qs(parsed.query or ""):
            params[param] += 1
        risk = endpoint_risk(str(url))
        if risk.get("score", 0) >= 60:
            high_risk.append({"url": str(url), **risk})
    high_risk.sort(key=lambda item: item.get("score", 0), reverse=True)
    return {
        "hosts": hosts.most_common(10),
        "top_parameters": params.most_common(20),
        "high_risk_urls": high_risk[:20],
    }


def _finding_matches(playbook: dict, findings: list[dict]) -> list[dict]:
    signals = [str(item).lower() for item in playbook.get("signals", ())]
    matches = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        blob = "{} {} {} {}".format(
            finding.get("vuln_type", ""),
            finding.get("title", ""),
            finding.get("description", ""),
            finding.get("url") or finding.get("affected_url") or "",
        ).lower()
        if any(signal in blob for signal in signals) or playbook["title"].lower().split()[0] in blob:
            matches.append({
                "id": finding.get("id", ""),
                "type": finding.get("vuln_type") or finding.get("title", ""),
                "severity": finding.get("severity", "INFO"),
                "url": finding.get("affected_url") or finding.get("url", ""),
                "status": finding.get("exploitability_status") or finding.get("verdict", ""),
            })
    return matches[:10]


def build_scan_playbook(
    recon_data: dict | None,
    findings: list[dict] | None = None,
    coverage_data: dict | None = None,
    planner_data: dict | None = None,
) -> dict:
    """Return ranked playbooks, gaps, and next actions for a scan."""

    recon = recon_data if isinstance(recon_data, dict) else {}
    findings = [f for f in (findings or []) if isinstance(f, dict)]
    coverage = coverage_data if isinstance(coverage_data, dict) else {}
    planner = planner_data if isinstance(planner_data, dict) else {}

    urls = [str(u) for u in _safe_list(recon.get("urls")) if str(u).strip()]
    surface = _text_surface(recon, findings)
    endpoint_stats = _endpoint_stats(urls)
    completed_steps = {
        str(step.get("step", "")).lower()
        for step in _safe_list(planner.get("completed_steps"))
        if isinstance(step, dict)
    }

    ranked = []
    for playbook in PLAYBOOKS:
        signals = [s.lower() for s in playbook["signals"]]
        signal_hits = sum(1 for signal in signals if signal in surface)
        endpoint_hits = [
            item for item in endpoint_stats["high_risk_urls"]
            if any(signal in item["url"].lower() for signal in signals)
        ][:8]
        matches = _finding_matches(playbook, findings)
        tested = bool(matches) or any(
            token in " ".join(completed_steps)
            for token in (
                playbook["title"].lower(),
                playbook["id"].replace("-", " "),
                playbook["title"].split()[0].lower(),
            )
        )
        coverage_gap = int(
            coverage.get("untested_endpoints")
            or coverage.get("untested_templates")
            or 0
        )
        score = int(playbook["risk"])
        score += min(30, signal_hits * 7)
        score += min(18, len(endpoint_hits) * 4)
        if matches:
            score += 8
        if coverage_gap and endpoint_hits:
            score += 10
        if tested:
            score -= 18
        score = max(0, min(100, score))
        status = "tested" if tested else ("priority" if signal_hits or endpoint_hits else "candidate")
        ranked.append({
            "id": playbook["id"],
            "title": playbook["title"],
            "status": status,
            "priority_score": score,
            "wstg": list(playbook["wstg"]),
            "requires_auth": bool(playbook["requires_auth"]),
            "signals_found": signal_hits,
            "matching_findings": matches,
            "top_urls": endpoint_hits,
            "recommended_tests": list(playbook["recommended_tests"]),
        })

    ranked.sort(key=lambda item: (item["status"] == "tested", -item["priority_score"], item["title"]))
    priority = [item for item in ranked if item["status"] != "tested"][:8]
    tested_count = len([item for item in ranked if item["status"] == "tested"])
    coverage_percent = float(coverage.get("coverage_percent", 0) or 0)
    readiness_score = int(
        min(
            100,
            max(0, coverage_percent * 0.45)
            + min(35, tested_count * 3)
            + min(20, len(findings) * 2),
        )
    )
    gaps = []
    if coverage.get("untested_endpoints") or coverage.get("untested_templates"):
        gaps.append({
            "type": "coverage",
            "message": "{} endpoint template(s) remain untested.".format(
                coverage.get("untested_endpoints")
                or coverage.get("untested_templates")
            ),
        })
    if not any(item["status"] == "tested" and item["requires_auth"] for item in ranked):
        gaps.append({
            "type": "auth",
            "message": "No authenticated access-control playbook appears fully tested.",
        })
    if not findings:
        gaps.append({
            "type": "validation",
            "message": "No findings were produced; inspect crawl depth, auth, scope, and rate limits before trusting the result.",
        })

    return {
        "version": "1.0",
        "readiness_score": readiness_score,
        "summary": {
            "urls": len(urls),
            "hosts": endpoint_stats["hosts"],
            "top_parameters": endpoint_stats["top_parameters"][:10],
            "findings": len(findings),
            "coverage_percent": coverage_percent,
            "tested_playbooks": tested_count,
            "total_playbooks": len(PLAYBOOKS),
        },
        "critical_classes": list(CRITICAL_BUG_BOUNTY_CLASSES),
        "ranked_playbooks": ranked,
        "next_best_actions": [
            {
                "playbook": item["title"],
                "priority_score": item["priority_score"],
                "why": _action_reason(item),
                "first_steps": item["recommended_tests"][:3],
                "starter_urls": [url["url"] for url in item["top_urls"][:5]],
            }
            for item in priority
        ],
        "gaps": gaps,
    }


def _action_reason(item: dict) -> str:
    reasons = []
    if item.get("signals_found"):
        reasons.append("{} matching surface signal(s)".format(item["signals_found"]))
    if item.get("top_urls"):
        reasons.append("{} high-risk URL(s)".format(len(item["top_urls"])))
    if item.get("matching_findings"):
        reasons.append("{} related finding(s) need validation".format(len(item["matching_findings"])))
    return "; ".join(reasons) or "High-impact class that should be verified before declaring the target clean"


def build_program_playbook(program_scope: dict | None, tech_stack: list[str] | None = None) -> dict:
    """Build a lightweight pre-scan playbook from program scope and technologies."""

    scope = program_scope if isinstance(program_scope, dict) else {}
    allowed = scope.get("allowed_assets") or scope.get("in_scope") or []
    disallowed = scope.get("disallowed_assets") or scope.get("out_of_scope") or []
    tech = [str(t).lower() for t in (tech_stack or [])]
    fake_recon = {
        "urls": [
            str(asset.get("asset_identifier") if isinstance(asset, dict) else asset)
            for asset in allowed
        ],
        "tech_stack": tech,
    }
    playbook = build_scan_playbook(fake_recon, [], {}, {})
    playbook["program_scope_summary"] = {
        "allowed_assets": len(allowed),
        "disallowed_assets": len(disallowed),
        "scope_warning": (
            "Treat imported scope as advisory and verify written authorization before scanning."
        ),
    }
    return playbook
