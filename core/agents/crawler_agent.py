"""Crawler result and generic exposed-path evidence agent."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse

import httpx

from finding_model import normalize_finding

from core.agents.base import BaseAgent, ScanContext, observe_response
from core.evidence import write_evidence_artifact
from core.events import EventType


REQUEST_HEADERS = {
    "User-Agent": "BurpOllama Evidence Agent",
    "Accept": "*/*",
}

ADMIN_PATHS = {"/admin", "/administrator", "/admin/login", "/dashboard"}
SENSITIVE_PATHS = {"/.env", "/.git/head", "/backup.zip", "/openapi.json"}
DIRECTORY_HINTS = ("index of /", "parent directory", "directory listing")
SOFT_404_HINTS = ("not found", "page not found", "404", "does not exist")


def _raw_request(method: str, url: str) -> str:
    headers = "\n".join(
        "{}: {}".format(key, value) for key, value in REQUEST_HEADERS.items()
    )
    return "{} {} HTTP/1.1\n{}".format(method.upper(), url, headers)


def _raw_response(response: httpx.Response, body_limit: int = 512) -> str:
    headers = "\n".join(
        "{}: {}".format(key, value) for key, value in response.headers.items()
    )
    return "HTTP/1.1 {}\n{}\n\n{}".format(
        response.status_code,
        headers,
        (response.text or "")[:body_limit],
    )


def _artifact_saved(artifact: dict) -> bool:
    return bool(artifact.get("artifact_path")) and Path(
        str(artifact.get("artifact_path"))
    ).exists()


def _classify_path(url: str, response: httpx.Response) -> tuple[str, str, str, bool]:
    path = urlparse(url).path.lower()
    body = (response.text or "")[:4096]
    lower = body.lower()
    if path in ADMIN_PATHS and response.status_code in {200, 401, 403}:
        return (
            "Admin Panel Exposure",
            "admin path returned HTTP {}".format(response.status_code),
            "Admin route is reachable and should be reviewed for authorization coverage.",
            response.status_code in {200, 403} and not _soft_404(lower),
        )
    if path in SENSITIVE_PATHS and response.status_code == 200:
        if path == "/.env" and "=" in body:
            return (
                "Sensitive File Exposure",
                "HTTP 200 plus environment-style key/value content",
                "Exposed configuration can leak secrets or deployment details.",
                True,
            )
        if path == "/.git/head" and "ref:" in lower:
            return (
                "Sensitive File Exposure",
                "HTTP 200 plus Git HEAD marker",
                "Exposed Git metadata can reveal source control structure.",
                True,
            )
        if path.endswith(".zip") and len(body) > 20:
            return (
                "Backup File Exposure",
                "HTTP 200 plus non-empty backup response",
                "Public backup files can expose source code or data.",
                not _soft_404(lower),
            )
        if path == "/openapi.json" and "openapi" in lower:
            return (
                "API Schema Exposure",
                "HTTP 200 plus OpenAPI schema marker",
                "Public API schemas can aid endpoint and parameter mapping.",
                True,
            )
    if response.status_code == 200 and any(hint in lower for hint in DIRECTORY_HINTS):
        return (
            "Directory Listing Exposure",
            "HTTP 200 plus directory listing marker",
            "Directory listings can expose files not intended for public browsing.",
            True,
        )
    return "", "", "", False


def _soft_404(lower_body: str) -> bool:
    return any(hint in lower_body for hint in SOFT_404_HINTS)


class CrawlerAgent(BaseAgent):
    name = "crawler"
    phase = "reconnaissance"

    async def run(self, context: ScanContext):
        urls = context.recon.get("urls", [])
        for index, url in enumerate(urls, start=1):
            await context.emit(
                EventType.URL_DISCOVERED,
                agent=self.name,
                phase=self.phase,
                message="Crawled {}".format(url),
                url=url,
                current=index,
                total=len(urls),
            )
        findings = await self._collect_exposed_path_evidence(context, urls)
        context.raw_findings.extend(findings)
        context.scan["raw_findings"] = context.raw_findings
        for finding in findings:
            context.scheduler.state(self.name).findings += 1
            await context.emit(
                EventType.FINDING_CANDIDATE,
                agent=self.name,
                phase=self.phase,
                message=finding.get("title", "Exposed path finding"),
                finding=finding,
            )
        return urls

    async def _collect_exposed_path_evidence(self, context: ScanContext, urls: list[str]):
        findings = []
        interesting = [
            url for url in urls
            if urlparse(url).path.lower() in ADMIN_PATHS | SENSITIVE_PATHS
        ][:30]
        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=context.options.timeout,
            headers=REQUEST_HEADERS,
        ) as client:
            for url in interesting:
                if not context.scope.allows(url):
                    continue
                waited = await context.rate_limiter.acquire()
                if waited > 0.05:
                    await context.emit(
                        EventType.THROTTLED,
                        agent=self.name,
                        phase=self.phase,
                        message="Rate limiter paused {:.2f}s".format(waited),
                    )
                try:
                    response = await client.get(url)
                except httpx.HTTPError:
                    continue
                await observe_response(
                    context,
                    response.status_code,
                    agent=self.name,
                    phase=self.phase,
                    body_hint=getattr(response, "text", "")[:512],
                )
                context.tested_urls.add(url)
                title, indicator, impact, confirmed_signal = _classify_path(url, response)
                if not title:
                    continue
                fp_check = (
                    "Status/content combination is not a soft-404 and contains the expected exposure marker."
                    if confirmed_signal
                    else "Response may be a soft-404 or lacks a specific exposure marker."
                )
                artifact = write_evidence_artifact(
                    context.scan,
                    title=title,
                    url=url,
                    raw_request=_raw_request("GET", url),
                    raw_response=_raw_response(response),
                    matched_indicator=indicator,
                    indicator_location="status line, response headers, and first 512 bytes of body",
                    agent=self.name,
                    vuln_class=title,
                    impact=impact,
                    fp_check=fp_check,
                    confirmed=confirmed_signal,
                    filename_prefix="crawler",
                    metadata={
                        "status_code": response.status_code,
                        "content_type": response.headers.get("content-type", ""),
                    },
                )
                confirmed = confirmed_signal and _artifact_saved(artifact)
                findings.append(normalize_finding({
                    "source": "crawler-agent",
                    "vuln_type": title,
                    "title": title,
                    "severity": "MEDIUM" if "Admin" in title else "HIGH",
                    "confidence": 90 if confirmed else 60,
                    "url": url,
                    "method": "GET",
                    "description": "A high-value path returned evidence of exposure.",
                    "evidence": indicator,
                    "evidence_artifact": artifact,
                    "business_impact": impact,
                    "reproduction_steps": [
                        "Send GET {}.".format(url),
                        "Observe HTTP {} and response evidence.".format(response.status_code),
                        "Confirm the response is not a generic soft-404.",
                    ],
                    "remediation": "Restrict access, remove public exposure, or require authentication as appropriate.",
                    "cwe": "CWE-200",
                    "exploitability_status": "confirmed" if confirmed else "candidate",
                    "evidence_strength": "strong" if confirmed else "weak",
                    "false_positive_risk": "low" if confirmed else "medium",
                    "redaction_status": "redacted",
                }, scan_id=context.scan["id"]))
        return findings
