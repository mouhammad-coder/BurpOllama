"""Mode-gated XSS specialist with safe reflected-input evidence."""

from __future__ import annotations

import html
import secrets
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx

from finding_model import normalize_finding

from core.agents.base import BaseAgent, ScanContext
from core.evidence import write_evidence_artifact
from core.events import EventType


REQUEST_HEADERS = {
    "User-Agent": "BurpOllama Evidence Agent",
    "Accept": "text/html,application/xhtml+xml,*/*",
}


def _raw_request(method: str, url: str) -> str:
    headers = "\n".join(
        "{}: {}".format(key, value) for key, value in REQUEST_HEADERS.items()
    )
    return "{} {} HTTP/1.1\n{}".format(method.upper(), url, headers)


def _raw_response(response: httpx.Response, limit: int = 4096) -> str:
    headers = "\n".join(
        "{}: {}".format(key, value) for key, value in response.headers.items()
    )
    return "HTTP/1.1 {}\n{}\n\n{}".format(
        response.status_code,
        headers,
        (response.text or "")[:limit],
    )


def _artifact_saved(artifact: dict) -> bool:
    return bool(artifact.get("artifact_path")) and Path(
        str(artifact.get("artifact_path"))
    ).exists()


def _with_param(url: str, parameter: str, value: str) -> str:
    parsed = urlparse(url)
    params = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    out = []
    for key, original in params:
        if key == parameter:
            out.append((key, value))
            replaced = True
        else:
            out.append((key, original))
    if not replaced:
        out.append((parameter, value))
    return urlunparse(parsed._replace(query=urlencode(out)))


def _reflection_context(body: str, marker: str) -> tuple[str, str, bool]:
    offset = (body or "").find(marker)
    if offset < 0:
        return "", "response body context", False
    start = max(0, offset - 120)
    end = min(len(body), offset + len(marker) + 120)
    snippet = body[start:end]
    encoded = html.escape(marker) in body and marker not in body
    context = "response body context (HTML/JS/attr), offset {}".format(offset)
    return snippet, context, not encoded


class XSSAgent(BaseAgent):
    name = "xss"
    phase = "vulnerability_hunt"

    async def run(self, context: ScanContext):
        js_findings = context.recon.get("js_findings", [])
        if context.options.mode == "passive":
            await context.emit(
                EventType.LOG,
                agent=self.name,
                phase=self.phase,
                message=(
                    "{} passive JavaScript observation(s); active XSS probes skipped".format(
                        len(js_findings)
                    )
                ),
                level="info",
            )
            return []

        findings = []
        marker = "<burpollama-probe-{}>".format(secrets.token_hex(4))
        for url in context.recon.get("urls", [])[:50]:
            params = parse_qsl(urlparse(url).query, keep_blank_values=True)
            if not params:
                continue
            for parameter, _original in params[:3]:
                await context.scheduler.checkpoint()
                if not context.scope.allows(url):
                    continue
                probe_url = _with_param(url, parameter, marker)
                finding = await self._test_reflection(
                    context,
                    probe_url,
                    parameter,
                    marker,
                )
                if finding:
                    findings.append(finding)
        context.raw_findings.extend(findings)
        context.scan["raw_findings"] = context.raw_findings
        for finding in findings:
            context.scheduler.state(self.name).findings += 1
            await context.emit(
                EventType.FINDING_CANDIDATE,
                agent=self.name,
                phase=self.phase,
                message=finding.get("title", "XSS finding"),
                finding=finding,
            )
        return findings

    async def _test_reflection(
        self,
        context: ScanContext,
        probe_url: str,
        parameter: str,
        marker: str,
    ) -> dict | None:
        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=True,
            timeout=context.options.timeout,
            headers=REQUEST_HEADERS,
        ) as client:
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
                message="GET {}".format(probe_url),
                method="GET",
                url=probe_url,
            )
            response = await client.get(probe_url)
            context.tested_urls.add(probe_url)
            await context.emit(
                EventType.RESPONSE_RECEIVED,
                agent=self.name,
                phase=self.phase,
                message="GET {} → HTTP {}".format(probe_url, response.status_code),
                method="GET",
                url=probe_url,
                status_code=response.status_code,
            )
        snippet, location, unencoded = _reflection_context(response.text, marker)
        if not snippet:
            return None
        confirmed = bool(unencoded)
        artifact = write_evidence_artifact(
            context.scan,
            title="Reflected input observed",
            url=probe_url,
            raw_request=_raw_request("GET", probe_url),
            raw_response=_raw_response(response),
            matched_indicator=marker,
            indicator_location=location,
            agent=self.name,
            vuln_class="Reflected XSS",
            impact="Unencoded reflection may become exploitable XSS depending on context and browser parsing.",
            fp_check=(
                "Safe non-executing probe reflected unencoded in the response body."
                if confirmed
                else "Probe was reflected only in encoded or ambiguous form."
            ),
            confirmed=confirmed,
            filename_prefix="xss",
            metadata={
                "parameter": parameter,
                "response_snippet": snippet,
                "probe": marker,
            },
        )
        confirmed = confirmed and _artifact_saved(artifact)
        return normalize_finding({
            "source": "xss-agent",
            "vuln_type": "Reflected XSS",
            "title": "Unencoded reflected input in parameter `{}`".format(parameter),
            "severity": "MEDIUM",
            "confidence": 90 if confirmed else 60,
            "url": probe_url,
            "method": "GET",
            "parameter": parameter,
            "description": "A safe non-executing probe was reflected in the response.",
            "evidence": snippet,
            "evidence_artifact": artifact,
            "business_impact": "Reflected unencoded input can enable script execution if a payload reaches executable context.",
            "reproduction_steps": [
                "Send GET {}.".format(probe_url),
                "Inspect the response body.",
                "Confirm the probe `{}` appears unencoded.".format(marker),
            ],
            "remediation": "Contextually encode reflected input and deploy a restrictive Content-Security-Policy.",
            "cwe": "CWE-79",
            "exploitability_status": "confirmed" if confirmed else "candidate",
            "evidence_strength": "strong" if confirmed else "weak",
            "false_positive_risk": "low" if confirmed else "medium",
            "redaction_status": "redacted",
        }, scan_id=context.scan["id"])
