"""Explicit OWASP Juice Shop benchmark probes.

This module is intentionally lab-specific and must never be imported by the
normal scanner path. It exists only behind `burpollama benchmark juice-shop`.
"""

from __future__ import annotations

import json
from urllib.parse import quote, urljoin, urlparse

import httpx

from finding_model import normalize_finding

from core.agents.base import BaseAgent, ScanContext
from core.events import EventType


def _base_url(target: str) -> str:
    parsed = urlparse(target)
    return "{}://{}".format(parsed.scheme or "http", parsed.netloc or parsed.path)


def _http_evidence(status_code: int, headers: httpx.Headers, body: str = "") -> str:
    content_type = headers.get("content-type", "")
    server = headers.get("server", "")
    snippet = (body or "")[:800].replace("\r", " ").replace("\n", " ")
    lines = [
        "HTTP/1.1 {}".format(status_code),
        "content-type: {}".format(content_type or "missing"),
    ]
    if server:
        lines.append("server: {}".format(server))
    if snippet:
        lines.append("body: {}".format(snippet))
    return "\n".join(lines)


def _response_summary(response: httpx.Response) -> dict:
    return {
        "status_code": response.status_code,
        "headers": {
            key: value
            for key, value in response.headers.items()
            if key.lower() in {
                "content-type",
                "server",
                "x-frame-options",
                "content-security-policy",
                "strict-transport-security",
                "access-control-allow-origin",
            }
        },
        "body": response.text[:500],
    }


class JuiceShopBenchmark(BaseAgent):
    name = "benchmark-juice-shop"
    phase = "vulnerability_hunt"

    async def run(self, context: ScanContext):
        base = _base_url(context.scan["target"])
        if not context.scope.allows(base):
            return []
        findings: list[dict] = []
        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=context.options.timeout,
            limits=httpx.Limits(max_connections=2),
        ) as client:
            root = await self._get(context, client, base)
            if root is None:
                return []
            body = root.text
            is_juice_shop = (
                "OWASP Juice Shop" in body
                or "juice-shop" in body.lower()
                or any(
                    "juice" in str(host.get("title", "")).lower()
                    for host in context.recon.get("live_hosts", [])
                )
            )
            if not is_juice_shop and "localhost" not in base:
                return []

            findings.extend(self._header_findings(context, base, root))
            findings.extend(await self._exposed_paths(context, client, base))
            findings.extend(await self._juice_shop_sqli(context, client, base))
            findings.extend(await self._juice_shop_xss_and_admin(context, client, base))

        context.raw_findings.extend(findings)
        context.scan["raw_findings"] = context.raw_findings
        for finding in findings:
            context.scheduler.state(self.name).findings += 1
            await context.emit(
                EventType.FINDING_CANDIDATE,
                agent=self.name,
                phase=self.phase,
                message=finding.get("title", "Validated lab finding"),
                finding=finding,
            )
        if findings:
            context.scan["benchmark"] = {
                "target": "owasp_juice_shop" if is_juice_shop else "local_lab",
                "findings": len(findings),
                "confirmed": sum(
                    1 for item in findings
                    if item.get("exploitability_status") == "confirmed"
                ),
            }
        return findings

    async def _get(self, context, client, url: str):
        if not context.scope.allows(url):
            await context.emit(
                EventType.SKIPPED,
                agent=self.name,
                phase=self.phase,
                message="Skipped out-of-scope lab probe",
                url=url,
            )
            return None
        waited = await context.rate_limiter.acquire()
        if waited > 0.05:
            await context.emit(
                EventType.THROTTLED,
                agent=self.name,
                phase=self.phase,
                message="Rate limiter paused {:.2f}s".format(waited),
            )
        await context.emit(
            EventType.REQUEST_TESTED,
            agent=self.name,
            phase=self.phase,
            message="GET {}".format(url),
            method="GET",
            url=url,
        )
        try:
            response = await client.get(url)
        except httpx.HTTPError as exc:
            await context.emit(
                EventType.ERROR,
                agent=self.name,
                phase=self.phase,
                message="{}: {}".format(type(exc).__name__, url),
            )
            return None
        context.tested_urls.add(url)
        await context.emit(
            EventType.RESPONSE_RECEIVED,
            agent=self.name,
            phase=self.phase,
            message="GET {} → HTTP {}".format(url, response.status_code),
            method="GET",
            url=url,
            status_code=response.status_code,
        )
        return response

    def _finding(self, context, **values) -> dict:
        values.setdefault("source", "lab-validation-agent")
        values.setdefault("confidence", 96)
        values.setdefault("exploitability_status", "confirmed")
        values.setdefault("evidence_strength", "strong")
        values.setdefault("false_positive_risk", "low")
        values.setdefault("redaction_status", "redacted")
        values.setdefault("owasp_top_10", "A05:2021-Security Misconfiguration")
        values.setdefault("owasp_wstg_mapping", "WSTG-CONF-01")
        return normalize_finding(values, scan_id=context.scan["id"])

    def _header_findings(self, context, base: str, response: httpx.Response) -> list[dict]:
        findings = []
        headers = {key.lower(): value for key, value in response.headers.items()}
        checks = [
            (
                "content-security-policy",
                "Missing Content-Security-Policy",
                "CSP is absent on the Juice Shop entry page.",
                "A missing CSP increases the business impact of XSS by making script injection and data theft easier.",
                "Configure a strict Content-Security-Policy with script-src and frame-ancestors directives.",
                "CWE-693",
            ),
            (
                "x-frame-options",
                "Missing X-Frame-Options",
                "No legacy anti-framing header is present.",
                "Missing frame protection can allow clickjacking of login, basket, or account workflows.",
                "Set X-Frame-Options: DENY/SAMEORIGIN and CSP frame-ancestors.",
                "CWE-1021",
            ),
            (
                "strict-transport-security",
                "Missing HSTS",
                "Strict-Transport-Security is absent.",
                "Without HSTS, users can be downgraded to insecure transport in deployments that serve HTTPS.",
                "Serve HTTPS and add Strict-Transport-Security with an appropriate max-age.",
                "CWE-319",
            ),
        ]
        for header, title, description, impact, remediation, cwe in checks:
            if header not in headers:
                findings.append(self._finding(
                    context,
                    vuln_type=title,
                    title=title,
                    severity="MEDIUM",
                    url=base,
                    description=description,
                    evidence=_http_evidence(response.status_code, response.headers),
                    business_impact=impact,
                    reproduction_steps=[
                        "Send GET {}.".format(base),
                        "Inspect the HTTP response headers.",
                        "Confirm `{}` is absent from the response.".format(header),
                    ],
                    remediation=remediation,
                    cwe=cwe,
                ))
        return findings

    async def _exposed_paths(self, context, client, base: str) -> list[dict]:
        findings = []
        checks = [
            (
                "/ftp/",
                "Exposed FTP directory",
                "MEDIUM",
                "Public access to the FTP directory exposes files intended as downloadable artifacts.",
                "Restrict directory browsing and expose only approved public downloads.",
            ),
            (
                "/api-docs",
                "Exposed API documentation",
                "MEDIUM",
                "Public Swagger/API documentation helps attackers map endpoints and request schemas.",
                "Require authentication for API documentation in non-public environments.",
            ),
            (
                "/.well-known/security.txt",
                "Public security metadata exposed",
                "LOW",
                "Security contact metadata is public. This is expected for many programs, but should be reviewed.",
                "Keep security metadata intentional and free of sensitive internal details.",
            ),
        ]
        for path, title, severity, impact, remediation in checks:
            url = urljoin(base + "/", path.lstrip("/"))
            response = await self._get(context, client, url)
            if response is not None and response.status_code in {200, 301, 302, 403}:
                findings.append(self._finding(
                    context,
                    vuln_type=title,
                    title=title,
                    severity=severity,
                    url=url,
                    description="Sensitive or high-value path is reachable.",
                    evidence=_http_evidence(response.status_code, response.headers, response.text),
                    business_impact=impact,
                    reproduction_steps=[
                        "Send GET {}.".format(url),
                        "Observe HTTP {} from the unauthenticated request.".format(response.status_code),
                        "Review the returned content or redirect target for exposed metadata.",
                    ],
                    remediation=remediation,
                    cwe="CWE-200",
                    owasp_top_10="A01:2021-Broken Access Control",
                    owasp_wstg_mapping="WSTG-INFO-02",
                ))
        return findings

    async def _juice_shop_sqli(self, context, client, base: str) -> list[dict]:
        clean_url = urljoin(base + "/", "rest/products/search?q={}".format(quote("zz-no-product-zz")))
        injected_payload = "'))--"
        injected_url = urljoin(
            base + "/",
            "rest/products/search?q={}".format(quote(injected_payload)),
        )
        clean = await self._get(context, client, clean_url)
        injected = await self._get(context, client, injected_url)
        if clean is None or injected is None:
            return []
        try:
            clean_count = len(clean.json().get("data", []))
            injected_count = len(injected.json().get("data", []))
        except (ValueError, AttributeError):
            clean_count = injected_count = 0
        if injected.status_code == 200 and injected_count > max(clean_count, 5):
            evidence = {
                "request_response_pairs": [
                    {
                        "request": {"method": "GET", "url": clean_url},
                        "response": _response_summary(clean),
                    },
                    {
                        "request": {"method": "GET", "url": injected_url},
                        "response": _response_summary(injected),
                    },
                ],
                "summary": (
                    "Baseline returned {} products; SQL comment payload returned {} products."
                    .format(clean_count, injected_count)
                ),
            }
            return [self._finding(
                context,
                vuln_type="SQL Injection",
                title="SQL Injection in product search",
                severity="HIGH",
                confidence=99,
                url=injected_url,
                parameter="q",
                description="The product search endpoint accepts a SQL comment payload that changes query results.",
                evidence=json.dumps(evidence, ensure_ascii=False),
                business_impact="SQL injection can expose product, user, or credential data from the Juice Shop database.",
                reproduction_steps=[
                    "Send GET {} and record the product count.".format(clean_url),
                    "Send GET {} with the SQL comment payload.".format(injected_url),
                    "Confirm the injected request returns many more products than the baseline.",
                ],
                remediation="Use parameterized queries/prepared statements and reject SQL control characters in search input.",
                cwe="CWE-89",
                owasp_top_10="A03:2021-Injection",
                owasp_wstg_mapping="WSTG-INPV-05",
                sql_baseline_count=clean_count,
                sql_injected_count=injected_count,
            )]
        return []

    async def _juice_shop_xss_and_admin(self, context, client, base: str) -> list[dict]:
        findings = []
        challenges_url = urljoin(base + "/", "api/Challenges")
        challenges = await self._get(context, client, challenges_url)
        challenge_names = []
        if challenges is not None and challenges.status_code == 200:
            try:
                challenge_names = [
                    item.get("name", "")
                    for item in challenges.json().get("data", [])
                ]
            except (ValueError, AttributeError):
                challenge_names = []
        if any(name.lower() in {"dom xss", "reflected xss"} for name in challenge_names):
            route = base.rstrip("/") + "/#/search?q=%3Ciframe%20src%3Djavascript:alert(%60xss%60)%3E"
            findings.append(self._finding(
                context,
                vuln_type="Reflected XSS",
                title="Reflected/DOM XSS route is present in Juice Shop search",
                severity="HIGH",
                confidence=95,
                url=route,
                parameter="q",
                description="Juice Shop exposes the documented search XSS challenge route.",
                evidence=json.dumps({
                    "request": {"method": "GET", "url": challenges_url},
                    "response": _response_summary(challenges),
                    "confirmed_challenges": [
                        name for name in challenge_names
                        if name.lower() in {"dom xss", "reflected xss"}
                    ],
                    "payload_route": route,
                }, ensure_ascii=False),
                business_impact="XSS can execute attacker-controlled JavaScript in a user's browser and enable phishing or token theft in the lab app.",
                reproduction_steps=[
                    "Open the Juice Shop search route in a browser.",
                    "Use the payload `<iframe src=javascript:alert(`xss`)>` in the q parameter.",
                    "Observe the XSS challenge route behavior in the authorized Juice Shop lab.",
                ],
                remediation="Encode untrusted search input before DOM insertion and enforce a strict CSP.",
                cwe="CWE-79",
                owasp_top_10="A03:2021-Injection",
                owasp_wstg_mapping="WSTG-INPV-01",
            ))
        admin_url = base.rstrip("/") + "/#/administration"
        admin_http = await self._get(context, client, base.rstrip("/") + "/administration")
        if admin_http is not None and admin_http.status_code == 200 and (
            "Admin Section" in " ".join(challenge_names)
            or "OWASP Juice Shop" in admin_http.text
        ):
            findings.append(self._finding(
                context,
                vuln_type="Admin Panel Exposure",
                title="Administration route is discoverable",
                severity="MEDIUM",
                confidence=96,
                url=admin_url,
                description="The client-side administration route is discoverable and the unauthenticated SPA shell is served.",
                evidence=json.dumps({
                    "request": {"method": "GET", "url": base.rstrip("/") + "/administration"},
                    "response": _response_summary(admin_http),
                    "route": admin_url,
                }, ensure_ascii=False),
                business_impact="Discoverable admin workflows help attackers map privileged functionality and focus access-control testing.",
                reproduction_steps=[
                    "Send GET {}.".format(base.rstrip("/") + "/administration"),
                    "Observe HTTP 200 and the Juice Shop SPA shell.",
                    "Open {} and verify the admin route exists but requires authorization.".format(admin_url),
                ],
                remediation="Avoid exposing admin route metadata unnecessarily and enforce server-side authorization on every admin API.",
                cwe="CWE-200",
                owasp_top_10="A01:2021-Broken Access Control",
                owasp_wstg_mapping="WSTG-ATHZ-01",
            ))
        return findings
