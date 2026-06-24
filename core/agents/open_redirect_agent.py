"""Passive open-redirect candidate observation from discovered URLs."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import parse_qsl, urlparse

from finding_model import normalize_finding

from core.agents.base import BaseAgent, ScanContext
from core.evidence import write_evidence_artifact
from core.events import EventType


REDIRECT_PARAMETER_NAMES = {
    "redirect", "return", "returnurl", "returnto", "next", "goto",
    "url", "dest", "destination", "target", "redir", "r", "forward",
    "continue", "back", "successurl", "failureurl", "cancelurl",
}


def _artifact_saved(artifact: dict) -> bool:
    return bool(artifact.get("artifact_path")) and Path(
        str(artifact.get("artifact_path"))
    ).exists()


def _truncate(value: str, limit: int = 200) -> str:
    text = str(value or "")
    return text if len(text) <= limit else text[:limit] + "..."


def _parameter_key(name: str) -> str:
    return str(name or "").replace("_", "").replace("-", "").lower()


def _raw_request(url: str) -> str:
    return "PASSIVE {} HTTP/1.1".format(url)


def _target_hosts(context: ScanContext) -> set[str]:
    hosts = set()
    for host in getattr(context.scope, "allowed_domains", []) or []:
        hosts.add(str(host).lower().lstrip("*."))
    target_host = urlparse(str(context.scan.get("target") or "")).hostname
    if target_host:
        hosts.add(target_host.lower())
    return hosts


def _same_or_subdomain(host: str, allowed_hosts: set[str]) -> bool:
    lowered = str(host or "").lower()
    return any(lowered == item or lowered.endswith("." + item) for item in allowed_hosts)


def _confidence_for_value(context: ScanContext, value: str) -> tuple[str, str]:
    text = str(value or "").strip()
    if text.startswith("//"):
        return "higher", "protocol-relative redirect target observed"
    if text.lower().startswith(("http://", "https://")):
        host = urlparse(text).hostname or ""
        if host and not _same_or_subdomain(host, _target_hosts(context)):
            return "higher", "absolute URL points outside target scope"
        return "low", "absolute URL points within target scope"
    if text.startswith("/"):
        return "low", "path-only redirect target observed"
    return "low", "relative or non-URL redirect target observed"


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


class OpenRedirectAgent(BaseAgent):
    name = "open-redirect"
    phase = "vulnerability_hunt"

    async def run(self, context: ScanContext):
        findings = self._passive_findings(context)
        context.raw_findings.extend(findings)
        context.scan["raw_findings"] = context.raw_findings
        for finding in findings:
            context.scheduler.state(self.name).findings += 1
            await context.emit(
                EventType.FINDING_CANDIDATE,
                agent=self.name,
                phase=self.phase,
                message=finding.get("title", "Open redirect parameter observation"),
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
                if _parameter_key(name) not in REDIRECT_PARAMETER_NAMES:
                    continue
                key = (url, name)
                if key in seen:
                    continue
                seen.add(key)
                confidence_label, reason = _confidence_for_value(context, value)
                artifact = write_evidence_artifact(
                    context.scan,
                    title="Open redirect candidate parameter observed",
                    url=url,
                    raw_request=_raw_request(url),
                    raw_response="PASSIVE URL PARAMETER OBSERVATION\n{}".format(url),
                    matched_indicator=name,
                    indicator_location="query parameter",
                    agent=self.name,
                    vuln_class="Open Redirect Candidate",
                    impact="Redirect-style parameters can allow external navigation if server-side validation is weak.",
                    fp_check="Parameter name/value observed only; no redirect target was changed or requested.",
                    confirmed=False,
                    filename_prefix="open-redirect-passive",
                    metadata={
                        "parameter": name,
                        "value": _truncate(value),
                        "discovery_source": item["source"],
                        "confidence": confidence_label,
                        "reason": reason,
                        "probe_performed": False,
                    },
                )
                saved = _artifact_saved(artifact)
                findings.append(normalize_finding({
                    "source": "passive-open-redirect-agent",
                    "vuln_type": "Open Redirect Candidate",
                    "title": "Open redirect candidate parameter observed",
                    "severity": "LOW",
                    "confidence": (70 if confidence_label == "higher" else 45) if saved else 30,
                    "url": url,
                    "method": "PASSIVE",
                    "parameter": name,
                    "description": "Observed redirect-prone parameter '{}' in {} source.".format(name, item["source"]),
                    "evidence": "{}={} ({})".format(name, _truncate(value), reason),
                    "evidence_artifact": artifact,
                    "business_impact": "Potential phishing or OAuth-flow abuse if the application redirects to arbitrary destinations.",
                    "remediation": "Use server-side allowlists for redirect destinations and prefer route identifiers over raw URLs.",
                    "cwe": "CWE-601",
                    "exploitability_status": "candidate",
                    "evidence_strength": "weak",
                    "false_positive_risk": "high",
                    "redaction_status": "redacted",
                }, scan_id=context.scan["id"]))
        return findings
