"""Offline account-takeover chain correlation."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from urllib.parse import urlparse


def _text(finding: dict) -> str:
    return " ".join(str(finding.get(key, "")) for key in (
        "title", "vuln_type", "vulnerability_class", "description",
        "evidence", "technical_impact", "business_impact", "oauth_test",
        "jwt_test",
    )).lower()


def _url(item: Any) -> str:
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        return str(item.get("url") or item.get("affected_url") or "")
    return ""


def _recon_records(recon_data: dict) -> list[dict]:
    records = []
    for key in (
        "urls", "content_discovery", "openapi_endpoints",
        "schema_endpoints", "js_endpoints",
    ):
        for item in recon_data.get(key, []) or []:
            records.append(item if isinstance(item, dict) else {"url": str(item)})
    return [record for record in records if _url(record)]


def _matching(findings: list[dict], predicate) -> list[dict]:
    return [finding for finding in findings if predicate(finding, _text(finding))]


def _ids(findings: list[dict]) -> list[str]:
    return list(dict.fromkeys(
        str(finding.get("id", ""))
        for finding in findings if finding.get("id")
    ))


def _all_confirmed(findings: list[dict]) -> bool:
    return bool(findings) and all(
        str(finding.get("exploitability_status", "")).lower() == "confirmed"
        for finding in findings
    )


def _cookie_without_httponly(findings: list[dict]) -> tuple[dict | None, str]:
    for finding in findings:
        blob = " ".join(str(finding.get(key, "")) for key in (
            "evidence", "description", "headers", "response_headers",
        ))
        if "set-cookie" not in blob.lower():
            continue
        cookie_lines = re.findall(r"(?im)^set-cookie:\s*([^\r\n]+)", blob)
        if not cookie_lines:
            cookie_lines = re.findall(
                r"(?i)set-cookie[^:=]*[:=]\s*[\"']?([^\"'\r\n}]+)",
                blob,
            )
        for line in cookie_lines:
            if "httponly" in line.lower():
                continue
            match = re.match(r"\s*([^=;\s]+)=", line)
            return finding, (match.group(1) if match else "session cookie")
    return None, ""


def _authenticated_endpoints(records: list[dict]) -> list[str]:
    endpoints = []
    for record in records:
        url = _url(record)
        blob = "{} {}".format(
            urlparse(url).path, record.get("description", "")
        ).lower()
        if (
            record.get("auth_required")
            or record.get("authenticated")
            or any(hint in blob for hint in (
                "/api/user", "/api/account", "/profile", "/me",
                "/dashboard", "/settings", "/orders",
            ))
        ):
            endpoints.append(url)
    return list(dict.fromkeys(endpoints))


def _user_endpoints(records: list[dict]) -> list[str]:
    return list(dict.fromkeys(
        _url(record)
        for record in records
        if any(hint in urlparse(_url(record)).path.lower() for hint in (
            "/user", "/users", "/profile", "/account", "/me",
        ))
    ))


def _jwt_proof(finding: dict) -> dict:
    return {
        "forged_token": (
            finding.get("forged_token")
            or finding.get("exact_forged_token")
            or finding.get("forged_token_redacted")
            or ""
        ),
        "forged_token_sha256": finding.get("forged_token_sha256", ""),
        "jwt_test": finding.get("jwt_test", ""),
        "evidence": finding.get("evidence", ""),
    }


def _chain(
    title: str,
    severity: str,
    confidence: int,
    status: str,
    steps: list[str],
    components: list[dict],
    bounty_note: str,
    *,
    url: str = "",
    extra: dict | None = None,
) -> dict:
    component_ids = _ids(components)
    digest = hashlib.sha256(
        "{}|{}|{}".format(title, url, component_ids).encode()
    ).hexdigest()[:16]
    result = {
        "id": "ATO-{}".format(digest),
        "source": "ato-chain-detector",
        "title": title,
        "vuln_type": title,
        "vulnerability_class": "Account Takeover Chain",
        "url": url or next((_url(item) for item in components if _url(item)), ""),
        "affected_url": url or next((_url(item) for item in components if _url(item)), ""),
        "method": "CHAIN",
        "severity": severity,
        "combined_severity": severity,
        "confidence": confidence,
        "chain_type": "account_takeover",
        "chain_status": status,
        "exploitability_status": (
            "confirmed" if status == "confirmed_chain"
            else "needs_manual_validation"
        ),
        "evidence_strength": "strong" if status == "confirmed_chain" else "moderate",
        "false_positive_risk": "low" if status == "confirmed_chain" else "medium",
        "steps": steps,
        "reproduction_steps": steps,
        "individual_finding_ids": component_ids,
        "bounty_note": bounty_note,
        "description": bounty_note,
        "business_impact": "A successful chain could result in complete account takeover.",
        "technical_impact": bounty_note,
        "evidence": json.dumps({
            "component_finding_ids": component_ids,
            "steps": steps,
        }, ensure_ascii=False),
        "remediation": (
            "Break every prerequisite in the chain: enforce strict redirects and "
            "token handling, secure cookies, validate CORS credentials, and use "
            "strong JWT/OAuth verification."
        ),
        "redaction_status": "redacted",
    }
    if extra:
        result.update(extra)
    return result


def detect_ato_chains(findings: list[dict], recon_data: dict) -> list[dict]:
    """Correlate existing findings and recon surfaces into ATO chains."""
    findings = [finding for finding in (findings or []) if isinstance(finding, dict)]
    records = _recon_records(recon_data or {})
    urls = [_url(record) for record in records]
    chains = []

    redirects = _matching(findings, lambda _f, text: "open redirect" in text)
    reset_urls = [
        url for url in urls
        if re.search(r"(?i)/(?:password/)?reset|/forgot", urlparse(url).path)
    ]
    if redirects and reset_urls:
        steps = [
            "Trigger a password reset for the authorized victim test account at {}.".format(reset_urls[0]),
            "Use the confirmed open redirect at {} in the reset-link flow.".format(_url(redirects[0])),
            "Verify whether the redirect sends the reset token or reset URL to the attacker-controlled destination.",
        ]
        chains.append(_chain(
            "ATO Chain: Password reset link can be hijacked via open redirect",
            "CRITICAL", 75, "candidate_chain", steps, [redirects[0]],
            "The open redirect is positioned on a password-reset surface, creating a plausible reset-token theft path suitable for submission after one safe end-to-end confirmation.",
            url=reset_urls[0], extra={"password_reset_url": reset_urls[0]},
        ))

    confirmed_xss = _matching(findings, lambda finding, text: (
        "xss" in text
        and str(finding.get("exploitability_status", "")).lower() == "confirmed"
    ))
    cookie_finding, cookie_name = _cookie_without_httponly(findings)
    if confirmed_xss and cookie_finding:
        xss_url = _url(confirmed_xss[0])
        steps = [
            "Deliver the confirmed XSS proof at {} to the authorized victim test session.".format(xss_url),
            "Read the non-HttpOnly '{}' cookie from document.cookie using a harmless local proof.".format(cookie_name),
            "Demonstrate session impact only with the disposable authorized account, then invalidate the session.",
        ]
        chains.append(_chain(
            "ATO Chain: XSS can steal session cookie",
            "CRITICAL", 85, "confirmed_chain", steps,
            [confirmed_xss[0], cookie_finding],
            "Confirmed script execution plus a session cookie lacking HttpOnly forms a complete session-hijack chain with direct account takeover impact.",
            url=xss_url, extra={"xss_url": xss_url, "cookie_name": cookie_name},
        ))

    cors = _matching(findings, lambda _f, text: (
        "cors wildcard" in text
        or ("cors" in text and "access-control-allow-origin" in text and "*" in text)
    ))
    authenticated = _authenticated_endpoints(records)
    if cors and authenticated:
        steps = [
            "Authenticate to the disposable victim account.",
            "Host a proof page on an unrelated origin and request {} with credentials enabled.".format(authenticated[0]),
            "Verify whether the browser exposes authenticated response data cross-origin.",
        ]
        chains.append(_chain(
            "ATO Chain: CORS misconfiguration allows cross-origin credential theft",
            "HIGH", 70, "candidate_chain", steps, [cors[0]],
            "A wildcard CORS policy near authenticated API endpoints may enable cross-origin account data theft; browser-based credentialed proof is still required.",
            url=authenticated[0], extra={"authenticated_endpoint": authenticated[0]},
        ))

    weak_jwts = _matching(findings, lambda finding, text: (
        (
            finding.get("jwt_test") == "weak_secret"
            or "jwt weak signing secret" in text
            or ("weak secret" in text and "jwt" in text)
        )
        and str(finding.get("exploitability_status", "")).lower() == "confirmed"
    ))
    user_endpoints = _user_endpoints(records)
    if weak_jwts and user_endpoints:
        jwt_finding = weak_jwts[0]
        steps = [
            "Use the recovered weak JWT signing secret from finding {} in the authorized test environment.".format(jwt_finding.get("id", "")),
            "Forge a token whose user identifier targets the disposable test user.",
            "Send the forged token to {} and verify the server accepts the chosen identity.".format(user_endpoints[0]),
        ]
        chains.append(_chain(
            "ATO Chain: Forge JWT as any user ID",
            "CRITICAL", 95, "confirmed_chain", steps, [jwt_finding],
            "The signing secret is confirmed weak and a user-profile surface is available, forming a direct forged-identity account takeover path.",
            url=user_endpoints[0],
            extra={"user_endpoint": user_endpoints[0], "forged_token_proof": _jwt_proof(jwt_finding)},
        ))

    oauth_redirect = _matching(findings, lambda finding, text: (
        finding.get("oauth_test") == "redirect_uri_validation"
        or "oauth redirect uri validation bypass" in text
        or "oauth redirect uri misconfiguration" in text
    ))
    oauth_leak = _matching(findings, lambda finding, text: (
        finding.get("oauth_test") in {"referer_token_leakage", "implicit_fragment_leakage"}
        or "oauth token leakage" in text
        or "token in url fragment" in text
        or ("referrer" in text and "token" in text)
    ))
    if oauth_redirect and oauth_leak:
        components = [oauth_redirect[0], oauth_leak[0]]
        confirmed = _all_confirmed(components)
        steps = [
            "Start an OAuth authorization flow using the confirmed crafted redirect URI.",
            "Cause the authorization code or token-bearing URL to reach the attacker-controlled redirect destination.",
            "Verify the code/token is exposed through the redirect or referrer path, then revoke it immediately.",
        ]
        chains.append(_chain(
            "ATO Chain: Authorization code stolen via redirect + referrer",
            "HIGH", 88 if confirmed else 78,
            "confirmed_chain" if confirmed else "candidate_chain",
            steps, components,
            "Redirect URI validation failure combined with URL/referrer token leakage creates an end-to-end OAuth credential theft chain.",
            url=_url(oauth_redirect[0]),
        ))

    return chains
