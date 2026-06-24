"""Safe passive HTTP header, cookie, and CORS observations."""

from __future__ import annotations

import httpx
from pathlib import Path
from urllib.parse import urlparse

from finding_model import normalize_finding

from core.agents.base import BaseAgent, ScanContext
from core.evidence import write_evidence_artifact
from core.events import EventType


def _raw_response(response: httpx.Response, body_limit: int = 2000) -> str:
    headers = "\n".join(
        "{}: {}".format(key, value)
        for key, value in response.headers.items()
    )
    body = response.text[:body_limit] if response.text else ""
    return "HTTP/1.1 {}\n{}\n\n{}".format(
        response.status_code,
        headers,
        body,
    )


REQUEST_HEADERS = {
    "User-Agent": "BurpOllama Evidence Agent",
    "Accept": "*/*",
}


HEADER_IMPACT = {
    "content-security-policy": (
        "Missing CSP weakens browser-side injection defenses and can increase XSS impact."
    ),
    "x-frame-options": (
        "Missing frame protection can allow clickjacking on sensitive workflows."
    ),
    "x-content-type-options": (
        "Missing nosniff allows some browsers to MIME-sniff content unsafely."
    ),
}


def _raw_request(method: str, url: str, headers: dict | None = None) -> str:
    header_lines = "\n".join(
        "{}: {}".format(key, value)
        for key, value in (headers or REQUEST_HEADERS).items()
    )
    return "{} {} HTTP/1.1\n{}".format(method.upper(), url, header_lines)


def _artifact_saved(artifact: dict) -> bool:
    return bool(artifact.get("artifact_path")) and Path(
        str(artifact.get("artifact_path"))
    ).exists()


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
            headers=REQUEST_HEADERS,
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
                        reason="out_of_scope",
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
                context.recon.setdefault("http_observations", []).append({
                    "url": url,
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "set_cookie_headers": response.headers.get_list("set-cookie"),
                    "body": response.text[:5000] if response.text else "",
                })
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
                        lowered_headers = {
                            key.lower(): value for key, value in response.headers.items()
                        }
                        for header in missing:
                            title = "Missing {}".format(header)
                            fp_check = (
                                "{} absent from final response headers after redirects; "
                                "case-insensitive header lookup returned no value."
                            ).format(header)
                            artifact = write_evidence_artifact(
                                context.scan,
                                title=title,
                                url=url,
                                raw_request=_raw_request("GET", url),
                                raw_response=_raw_response(response, body_limit=0),
                                matched_indicator=header,
                                indicator_location="response headers",
                                agent=self.name,
                                vuln_class="Missing Security Headers",
                                impact=HEADER_IMPACT.get(
                                    header,
                                    "Missing browser security header weakens client-side defenses.",
                                ),
                                fp_check=fp_check,
                                confirmed=header not in lowered_headers,
                                filename_prefix="header",
                                metadata={
                                    "header": header,
                                    "status_code": response.status_code,
                                    "final_url": str(response.url),
                                },
                            )
                            confirmed = _artifact_saved(artifact) and header not in lowered_headers
                            findings.append(normalize_finding({
                                "source": "passive-header-agent",
                                "vuln_type": "Missing Security Headers",
                                "title": title,
                                "severity": "MEDIUM",
                                "confidence": 94 if confirmed else 65,
                                "url": url,
                                "method": "GET",
                                "description": "{} is absent from the HTTP response.".format(header),
                                "evidence": "Missing header: {}".format(header),
                                "evidence_artifact": artifact,
                                "business_impact": HEADER_IMPACT.get(header, ""),
                                "reproduction_steps": [
                                    "Send GET {}.".format(url),
                                    "Inspect the final HTTP response headers after redirects.",
                                    "Confirm `{}` is absent.".format(header),
                                ],
                                "remediation": "Configure `{}` with a value appropriate for this application.".format(header),
                                "cwe": "CWE-16",
                                "exploitability_status": "confirmed" if confirmed else "candidate",
                                "evidence_strength": "strong" if confirmed else "weak",
                                "false_positive_risk": "low" if confirmed else "medium",
                                "redaction_status": "redacted",
                            }, scan_id=context.scan["id"]))
                acao = response.headers.get("access-control-allow-origin", "")
                if acao == "*":
                    title = "Wildcard CORS header observed"
                    artifact = write_evidence_artifact(
                        context.scan,
                        title=title,
                        url=url,
                        raw_request=_raw_request("GET", url),
                        raw_response=_raw_response(response, body_limit=0),
                        matched_indicator="Access-Control-Allow-Origin: *",
                        indicator_location="response.headers.access-control-allow-origin",
                        agent=self.name,
                        vuln_class="CORS Wildcard Observation",
                        impact="Wildcard CORS can expose sensitive data when combined with credentialed flows.",
                        fp_check="Observed exact Access-Control-Allow-Origin wildcard in response headers.",
                        confirmed=False,
                        filename_prefix="header",
                    )
                    findings.append(normalize_finding({
                        "source": "passive-header-agent",
                        "vuln_type": "CORS Wildcard Observation",
                        "title": title,
                        "severity": "LOW",
                        "confidence": 65,
                        "url": url,
                        "method": "GET",
                        "description": "The response advertises a wildcard CORS origin.",
                        "evidence": "Access-Control-Allow-Origin: *",
                        "evidence_artifact": artifact,
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
                    title = "Environment configuration file is publicly accessible"
                    artifact = write_evidence_artifact(
                        context.scan,
                        title=title,
                        url=url,
                        raw_request=_raw_request("GET", url),
                        raw_response=_raw_response(response),
                        matched_indicator="environment-style key/value content",
                        indicator_location="response.body",
                        agent=self.name,
                        vuln_class="Environment File Exposed",
                        impact="Exposed configuration may reveal credentials, database access, or service secrets.",
                        fp_check="HTTP 200 response body contains environment-style key/value content.",
                        confirmed=True,
                        filename_prefix="header",
                        metadata={"status_code": response.status_code},
                    )
                    findings.append(normalize_finding({
                        "source": "passive-header-agent",
                        "vuln_type": "Environment File Exposed",
                        "title": title,
                        "severity": "HIGH",
                        "confidence": 98,
                        "url": url,
                        "method": "GET",
                        "description": "A .env-style configuration response is accessible without authentication.",
                        "evidence": "HTTP 200 with environment-style key/value content (secret values redacted).",
                        "evidence_artifact": artifact,
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
