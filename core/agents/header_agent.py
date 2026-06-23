"""Safe passive HTTP header, cookie, and CORS observations."""

from __future__ import annotations

import httpx
from urllib.parse import urlparse

from finding_model import normalize_finding

from core.agents.base import BaseAgent, ScanContext
from core.events import EventType


class HeaderAgent(BaseAgent):
    name = "header"
    phase = "vulnerability_hunt"

    async def run(self, context: ScanContext):
        findings = []
        urls = context.recon.get("urls", [])[:30]
        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=context.options.timeout,
            limits=httpx.Limits(max_connections=context.options.concurrency),
        ) as client:
            for url in urls:
                await context.scheduler.checkpoint()
                if not context.scope.allows(url):
                    await context.emit(
                        EventType.SKIPPED,
                        agent=self.name,
                        phase=self.phase,
                        message="Skipped out-of-scope URL",
                        url=url,
                    )
                    continue
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
                response = None
                last_error = None
                for attempt in range(context.options.retries + 1):
                    try:
                        response = await client.get(url)
                        break
                    except httpx.HTTPError as exc:
                        last_error = exc
                        if attempt < context.options.retries:
                            await context.emit(
                                EventType.THROTTLED,
                                agent=self.name,
                                phase=self.phase,
                                message="Retrying {} after {}".format(
                                    url, type(exc).__name__
                                ),
                            )
                            await context.scheduler.checkpoint()
                if response is None:
                    await context.emit(
                        EventType.ERROR,
                        agent=self.name,
                        phase=self.phase,
                        message="{}: {}".format(
                            type(last_error).__name__ if last_error else "HTTPError",
                            url,
                        ),
                    )
                    continue
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
                content_type = response.headers.get("content-type", "").lower()
                if "text/html" in content_type:
                    missing = [
                        name for name in (
                            "content-security-policy",
                            "x-frame-options",
                            "x-content-type-options",
                        )
                        if name not in response.headers
                    ]
                    if missing:
                        findings.append(normalize_finding({
                            "source": "passive-header-agent",
                            "vuln_type": "Missing Security Headers",
                            "title": "Missing Security Headers",
                            "severity": "MEDIUM",
                            "confidence": 92,
                            "url": url,
                            "method": "GET",
                            "description": "Important browser security headers are absent.",
                            "evidence": "Absent: {}".format(", ".join(missing)),
                            "remediation": "Configure CSP, frame protections, and nosniff headers.",
                            "cwe": "CWE-16",
                            "exploitability_status": "probable",
                            "evidence_strength": "moderate",
                            "false_positive_risk": "low",
                            "redaction_status": "redacted",
                        }, scan_id=context.scan["id"]))
                acao = response.headers.get("access-control-allow-origin", "")
                if acao == "*":
                    findings.append(normalize_finding({
                        "source": "passive-header-agent",
                        "vuln_type": "CORS Wildcard Observation",
                        "title": "Wildcard CORS header observed",
                        "severity": "LOW",
                        "confidence": 65,
                        "url": url,
                        "method": "GET",
                        "description": "The response advertises a wildcard CORS origin.",
                        "evidence": "Access-Control-Allow-Origin: *",
                        "remediation": "Restrict allowed origins where sensitive data is returned.",
                        "exploitability_status": "candidate",
                        "evidence_strength": "weak",
                        "false_positive_risk": "medium",
                        "redaction_status": "redacted",
                    }, scan_id=context.scan["id"]))
                if (
                    urlparse(url).path.lower() == "/.env"
                    and response.status_code == 200
                    and "=" in response.text[:4000]
                ):
                    findings.append(normalize_finding({
                        "source": "passive-header-agent",
                        "vuln_type": "Environment File Exposed",
                        "title": "Environment configuration file is publicly accessible",
                        "severity": "HIGH",
                        "confidence": 98,
                        "url": url,
                        "method": "GET",
                        "description": "A .env-style configuration response is accessible without authentication.",
                        "evidence": "HTTP 200 with environment-style key/value content (secret values redacted).",
                        "business_impact": "Exposed configuration may reveal credentials, database access, or service secrets.",
                        "reproduction_steps": [
                            "Send GET /.env to the affected host.",
                            "Observe the unauthenticated HTTP 200 response.",
                            "Confirm environment-style keys are present without retaining secret values.",
                        ],
                        "remediation": "Block dotfiles at the web server and rotate any exposed secrets.",
                        "cwe": "CWE-200",
                        "exploitability_status": "confirmed",
                        "evidence_strength": "strong",
                        "false_positive_risk": "low",
                        "redaction_status": "redacted",
                    }, scan_id=context.scan["id"]))
        context.raw_findings.extend(findings)
        context.scan["raw_findings"] = context.raw_findings
        for finding in findings:
            context.scheduler.state(self.name).findings += 1
            await context.emit(
                EventType.FINDING_CANDIDATE,
                agent=self.name,
                phase=self.phase,
                message=finding.get("title", "Header finding"),
                finding=finding,
            )
        return findings
