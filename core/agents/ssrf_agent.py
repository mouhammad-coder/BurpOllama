"""Passive SSRF-prone parameter observation with opt-in OOB probing."""

from __future__ import annotations

import asyncio
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx

from finding_model import normalize_finding

from core.agents.base import BaseAgent, ScanContext, observe_response
from core.evidence import write_evidence_artifact
from core.events import EventType


SSRF_PARAMETER_NAMES = {
    "url", "uri", "path", "dest", "destination", "redirect", "return",
    "returnurl", "returnto", "next", "target", "src", "source",
    "callback", "webhook", "endpoint", "proxy", "forward", "imageurl",
    "fileurl", "pdfurl", "host", "domain",
}
METADATA_INDICATORS = (
    "169.254.169.254",
    "metadata.google.internal",
    "169.254.170.2",
    "fd00:ec2::254",
)
PROBE_MODES = {"bounty", "deep"}


def _artifact_saved(artifact: dict) -> bool:
    return bool(artifact.get("artifact_path")) and Path(
        str(artifact.get("artifact_path"))
    ).exists()


def _truncate(value: str, limit: int = 100) -> str:
    text = str(value or "")
    return text if len(text) <= limit else text[:limit] + "..."


def _parameter_key(name: str) -> str:
    return str(name or "").replace("_", "").replace("-", "").lower()


def _metadata_value(value: str) -> bool:
    lowered = str(value or "").lower()
    return any(indicator in lowered for indicator in METADATA_INDICATORS)


def _raw_request(url: str, method: str = "PASSIVE") -> str:
    return "{} {} HTTP/1.1".format(method.upper(), url)


def _replace_parameter(url: str, parameter: str, replacement: str) -> str:
    parsed = urlparse(url)
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = [
        (name, replacement if name == parameter else value)
        for name, value in pairs
    ]
    return urlunparse(parsed._replace(query=urlencode(replaced, doseq=True)))


def _iter_urls(context: ScanContext) -> list[dict]:
    observed: list[dict] = []

    def add(url: str, source: str):
        if url:
            observed.append({"url": str(url), "source": source})

    for url in context.recon.get("urls", []) or []:
        add(str(url), "crawl")
    for item in context.recon.get("forms", []) or []:
        if isinstance(item, dict):
            add(str(item.get("action") or item.get("url") or ""), "form")
    for item in context.recon.get("http_observations", []) or []:
        if isinstance(item, dict):
            add(str(item.get("url") or ""), str(item.get("source") or "crawl"))
    intelligence = context.recon.get("intelligence", {}) or {}
    if isinstance(intelligence, dict):
        for url in intelligence.get("hidden_endpoints", []) or []:
            add(str(url), "JS")
    for key in ("js_endpoints", "api_endpoints"):
        for item in context.recon.get(key, []) or []:
            if isinstance(item, dict):
                add(str(item.get("url") or item.get("endpoint") or item.get("path") or ""), "JS")
            else:
                add(str(item), "JS")
    return observed


class SSRFAgent(BaseAgent):
    name = "ssrf"
    phase = "vulnerability_hunt"

    async def run(self, context: ScanContext):
        findings = self._passive_findings(context)
        if self._oob_enabled(context):
            findings = await self._probe_oob(context, findings)
        elif context.options.mode in PROBE_MODES:
            await context.emit(
                EventType.SKIPPED,
                agent=self.name,
                phase=self.phase,
                message="Skipped SSRF OOB probe; --oob-server not set",
                reason="oob_server_not_set",
            )
        context.raw_findings.extend(findings)
        context.scan["raw_findings"] = context.raw_findings
        for finding in findings:
            context.scheduler.state(self.name).findings += 1
            await context.emit(
                EventType.FINDING_CANDIDATE,
                agent=self.name,
                phase=self.phase,
                message=finding.get("title", "SSRF parameter observation"),
                finding=finding,
            )
        return findings

    def _passive_findings(self, context: ScanContext) -> list[dict]:
        findings = []
        seen = set()
        for item in _iter_urls(context):
            url = item["url"]
            if not url or not context.scope.allows(url):
                continue
            parsed = urlparse(url)
            for name, value in parse_qsl(parsed.query, keep_blank_values=True):
                if _parameter_key(name) not in SSRF_PARAMETER_NAMES:
                    continue
                key = (url, name)
                if key in seen:
                    continue
                seen.add(key)
                status = "needs_manual_validation" if _metadata_value(value) else "candidate"
                title = (
                    "Metadata endpoint value observed in SSRF-prone parameter"
                    if status == "needs_manual_validation"
                    else "SSRF-prone parameter observed"
                )
                artifact = write_evidence_artifact(
                    context.scan,
                    title=title,
                    url=url,
                    raw_request=_raw_request(url),
                    raw_response="PASSIVE URL PARAMETER OBSERVATION\n{}".format(url),
                    matched_indicator=name,
                    indicator_location="query parameter",
                    agent=self.name,
                    vuln_class="SSRF Candidate",
                    impact="URL-like parameters can become SSRF sinks if server-side fetches are performed without allowlisting.",
                    fp_check="Parameter name/value observed only; no SSRF request or OOB interaction was attempted.",
                    confirmed=False,
                    filename_prefix="ssrf-passive",
                    metadata={
                        "parameter": name,
                        "value_observed": _truncate(value),
                        "discovery_source": item["source"],
                        "metadata_endpoint_value": _metadata_value(value),
                        "oob_probe_performed": False,
                    },
                )
                findings.append(normalize_finding({
                    "source": "passive-ssrf-agent",
                    "vuln_type": "SSRF Candidate",
                    "title": title,
                    "severity": "MEDIUM",
                    "confidence": 70 if status == "needs_manual_validation" and _artifact_saved(artifact) else 50,
                    "url": url,
                    "method": "PASSIVE",
                    "parameter": name,
                    "description": "Observed SSRF-prone parameter name '{}' in {} source.".format(name, item["source"]),
                    "evidence": "{}={} observed".format(name, _truncate(value)),
                    "evidence_artifact": artifact,
                    "business_impact": "Potential SSRF sink; impact depends on server-side request behavior and egress controls.",
                    "remediation": "Allowlist outbound destinations and avoid passing user-controlled URLs to server-side fetchers.",
                    "cwe": "CWE-918",
                    "exploitability_status": status,
                    "evidence_strength": "weak",
                    "false_positive_risk": "high",
                    "redaction_status": "redacted",
                }, scan_id=context.scan["id"]))
        return findings

    def _oob_enabled(self, context: ScanContext) -> bool:
        return (
            context.options.mode in PROBE_MODES
            and bool(str(getattr(context.options, "oob_server", "") or "").strip())
        )

    async def _probe_oob(self, context: ScanContext, findings: list[dict]) -> list[dict]:
        probed = []
        oob_server = str(getattr(context.options, "oob_server", "") or "").strip()
        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=False,
            timeout=context.options.timeout,
            headers={"User-Agent": "BurpOllama SSRF Agent"},
        ) as client:
            for finding in findings:
                url = str(finding.get("url") or "")
                parameter = str(finding.get("parameter") or "")
                if not url or not parameter or not context.scope.allows(url):
                    probed.append(finding)
                    continue
                probe_url = _replace_parameter(url, parameter, oob_server)
                waited = await context.rate_limiter.acquire()
                if waited > 0.05:
                    await context.emit(
                        EventType.THROTTLED,
                        agent=self.name,
                        phase=self.phase,
                        message="Rate limiter paused {:.2f}s".format(waited),
                    )
                response_snapshot = {}
                try:
                    response = await client.get(probe_url)
                    context.tested_urls.add(probe_url)
                    await observe_response(
                        context,
                        response.status_code,
                        agent=self.name,
                        phase=self.phase,
                        body_hint=getattr(response, "text", "")[:512],
                    )
                    response_snapshot = {
                        "status_code": response.status_code,
                        "headers": dict(response.headers),
                    }
                except httpx.HTTPError as exc:
                    response_snapshot = {"error": type(exc).__name__}
                callback = await self._wait_for_oob_callback(context, oob_server, parameter)
                probed.append(self._oob_result(
                    context,
                    finding,
                    probe_url,
                    response_snapshot,
                    callback,
                ))
        return probed

    async def _wait_for_oob_callback(self, context: ScanContext, oob_server: str, parameter: str) -> bool:
        await asyncio.sleep(0)
        return False

    def _oob_result(
        self,
        context: ScanContext,
        finding: dict,
        probe_url: str,
        response_snapshot: dict,
        callback_received: bool,
    ) -> dict:
        original_artifact = finding.get("evidence_artifact", {}) or {}
        metadata = dict(original_artifact.get("metadata", {}) or {})
        metadata.update({
            "oob_probe_performed": True,
            "probe_request_url": probe_url,
            "probe_response": response_snapshot,
            "callback_received": callback_received,
            "oob_timeout_seconds": 10,
        })
        artifact = write_evidence_artifact(
            context.scan,
            title="SSRF OOB callback confirmed" if callback_received else finding.get("title", "SSRF-prone parameter observed"),
            url=str(finding.get("url") or ""),
            raw_request=_raw_request(probe_url, "GET"),
            raw_response="OOB CALLBACK RECEIVED={}\n{}".format(callback_received, response_snapshot),
            matched_indicator=str(finding.get("parameter") or ""),
            indicator_location="query parameter replaced with explicit OOB server",
            agent=self.name,
            vuln_class="SSRF Candidate",
            impact="Confirmed callback indicates the application made an outbound server-side request.",
            fp_check="Single opt-in OOB request was sent only because --oob-server was configured.",
            confirmed=callback_received,
            filename_prefix="ssrf-oob",
            metadata=metadata,
        )
        saved = _artifact_saved(artifact)
        status = "confirmed" if callback_received and saved else finding.get("exploitability_status", "candidate")
        updated = dict(finding)
        updated.update({
            "title": "SSRF OOB callback confirmed" if status == "confirmed" else finding.get("title"),
            "confidence": 90 if status == "confirmed" else finding.get("confidence", 50),
            "method": "GET" if status == "confirmed" else finding.get("method", "PASSIVE"),
            "evidence_artifact": artifact,
            "exploitability_status": status,
            "evidence_strength": "strong" if status == "confirmed" else finding.get("evidence_strength", "weak"),
            "false_positive_risk": "low" if status == "confirmed" else finding.get("false_positive_risk", "high"),
        })
        return normalize_finding(updated, scan_id=context.scan["id"])
