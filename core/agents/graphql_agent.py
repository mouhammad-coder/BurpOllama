"""Passive GraphQL endpoint observation with opt-in bounty introspection."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from finding_model import normalize_finding

from core.agents.base import BaseAgent, ScanContext
from core.evidence import write_evidence_artifact
from core.events import EventType


GRAPHQL_PATHS = {
    "/graphql",
    "/graphiql",
    "/graphql/console",
    "/api/graphql",
    "/gql",
    "/query",
    "/v1/graphql",
}
INTROSPECTION_QUERY = "{__schema{types{name}}}"
INTROSPECTION_BODY = {"query": INTROSPECTION_QUERY}


def _artifact_saved(artifact: dict) -> bool:
    return bool(artifact.get("artifact_path")) and Path(
        str(artifact.get("artifact_path"))
    ).exists()


def _raw_request(url: str, method: str = "PASSIVE", body: dict | None = None) -> str:
    request = "{} {} HTTP/1.1".format(method.upper(), url)
    if body is not None:
        request += "\nContent-Type: application/json\n\n{}".format(
            json.dumps(body, separators=(",", ":"))
        )
    return request


def _raw_observation_response(observation: dict, body_limit: int = 1500) -> str:
    status = observation.get("status_code") or observation.get("status") or ""
    headers = observation.get("headers") or {}
    if isinstance(headers, dict):
        header_lines = "\n".join("{}: {}".format(key, value) for key, value in headers.items())
    else:
        header_lines = "\n".join("{}: {}".format(key, value) for key, value in headers)
    body = _body_text(observation)[:body_limit]
    return "HTTP/1.1 {}\n{}\n\n{}".format(status, header_lines, body)


def _body_text(observation: dict) -> str:
    for key in ("body", "response_body", "text"):
        value = observation.get(key)
        if value is not None:
            return str(value)
    return ""


def _json_body(observation: dict) -> Any:
    if "json" in observation:
        return observation.get("json")
    body = _body_text(observation).strip()
    if not body:
        return None
    try:
        return json.loads(body)
    except (TypeError, ValueError):
        return None


def _is_graphql_path(url: str) -> bool:
    parsed = urlparse(str(url or ""))
    path = (parsed.path or "/").rstrip("/").lower() or "/"
    return path in GRAPHQL_PATHS


def _is_graphql_response(value: Any) -> bool:
    return isinstance(value, dict) and (
        "data" in value or isinstance(value.get("errors"), list)
    )


def _has_error_structure(value: Any) -> bool:
    if not isinstance(value, dict) or not isinstance(value.get("errors"), list):
        return False
    for error in value.get("errors") or []:
        if not isinstance(error, dict):
            continue
        if {"message", "locations", "path"}.issubset(error.keys()):
            return True
    return False


def _endpoint_key(url: str) -> str:
    parsed = urlparse(str(url or ""))
    return "{}://{}{}".format(
        (parsed.scheme or "https").lower(),
        (parsed.netloc or "").lower(),
        parsed.path or "/",
    )


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
    for observation in _observations(context):
        add(str(observation.get("url") or ""), str(observation.get("source") or "response"))
    return observed


def _observations(context: ScanContext) -> list[dict]:
    observed = []
    for key in ("http_observations", "observed_responses", "response_observations"):
        value = context.recon.get(key, [])
        if isinstance(value, list):
            observed.extend(item for item in value if isinstance(item, dict))
    return observed


class GraphQLAgent(BaseAgent):
    name = "graphql"
    phase = "vulnerability_hunt"

    async def run(self, context: ScanContext):
        findings, candidate_urls = self._passive_findings(context)
        if context.options.mode == "bounty":
            findings.extend(await self._check_introspection(context, candidate_urls))
        context.raw_findings.extend(findings)
        context.scan["raw_findings"] = context.raw_findings
        for finding in findings:
            context.scheduler.state(self.name).findings += 1
            await context.emit(
                EventType.FINDING_CANDIDATE,
                agent=self.name,
                phase=self.phase,
                message=finding.get("title", "GraphQL observation"),
                finding=finding,
            )
        return findings

    def _passive_findings(self, context: ScanContext) -> tuple[list[dict], list[str]]:
        findings = []
        candidate_urls: list[str] = []
        seen_candidates = set()
        seen_errors = set()

        def add_candidate(url: str, source: str, indicator: str, location: str, raw_response: str):
            if not url or not context.scope.allows(url):
                return
            key = (_endpoint_key(url), indicator, location)
            if key in seen_candidates:
                return
            seen_candidates.add(key)
            candidate_urls.append(url)
            title = "GraphQL endpoint candidate observed"
            artifact = write_evidence_artifact(
                context.scan,
                title=title,
                url=url,
                raw_request=_raw_request(url),
                raw_response=raw_response,
                matched_indicator=indicator,
                indicator_location=location,
                agent=self.name,
                vuln_class="GraphQL Endpoint Candidate",
                impact="GraphQL endpoints often concentrate data access and authorization checks behind one API surface.",
                fp_check="Candidate was identified from URL or response shape only; no introspection request was sent in passive mode.",
                confirmed=False,
                filename_prefix="graphql-candidate",
                metadata={
                    "discovery_source": source,
                    "introspection_performed": False,
                },
            )
            findings.append(normalize_finding({
                "source": "passive-graphql-agent",
                "vuln_type": "GraphQL Endpoint Candidate",
                "title": title,
                "severity": "INFO",
                "confidence": 65 if _artifact_saved(artifact) else 40,
                "url": url,
                "method": "PASSIVE",
                "description": "Observed a URL or JSON response shape consistent with GraphQL.",
                "evidence": "{} observed at {}".format(indicator, location),
                "evidence_artifact": artifact,
                "business_impact": "Unconfirmed GraphQL surface; review authorization and schema exposure controls.",
                "remediation": "Restrict GraphQL endpoints to intended clients and enforce resolver-level authorization.",
                "cwe": "CWE-200",
                "exploitability_status": "candidate",
                "evidence_strength": "weak",
                "false_positive_risk": "medium",
                "redaction_status": "redacted",
            }, scan_id=context.scan["id"]))

        for item in _iter_urls(context):
            url = item["url"]
            if _is_graphql_path(url):
                add_candidate(
                    url,
                    item["source"],
                    urlparse(url).path or "/",
                    "url path",
                    "PASSIVE URL OBSERVATION\n{}".format(url),
                )

        for observation in _observations(context):
            url = str(observation.get("url") or "")
            if not url or not context.scope.allows(url):
                continue
            parsed_body = _json_body(observation)
            if not _is_graphql_response(parsed_body):
                continue
            add_candidate(
                url,
                str(observation.get("source") or "response"),
                "data" if "data" in parsed_body else "errors",
                "json response body",
                _raw_observation_response(observation),
            )
            if not _has_error_structure(parsed_body):
                continue
            error_key = _endpoint_key(url)
            if error_key in seen_errors:
                continue
            seen_errors.add(error_key)
            title = "GraphQL error structure observed"
            artifact = write_evidence_artifact(
                context.scan,
                title=title,
                url=url,
                raw_request=_raw_request(url, str(observation.get("method") or "PASSIVE")),
                raw_response=_raw_observation_response(observation),
                matched_indicator="errors.message.locations.path",
                indicator_location="json response body",
                agent=self.name,
                vuln_class="GraphQL Error Observation",
                impact="Verbose GraphQL errors may disclose resolver paths, query structure, or implementation details useful for authorization review.",
                fp_check="Observed passively in a response body; no malformed query was sent.",
                confirmed=False,
                filename_prefix="graphql-error",
                metadata={
                    "error_count": len(parsed_body.get("errors") or []),
                    "active_probe_performed": False,
                },
            )
            findings.append(normalize_finding({
                "source": "passive-graphql-agent",
                "vuln_type": "GraphQL Error Observation",
                "title": title,
                "severity": "INFO",
                "confidence": 70 if _artifact_saved(artifact) else 40,
                "url": url,
                "method": "PASSIVE",
                "description": "GraphQL response includes structured error details.",
                "evidence": "errors/message/locations/path keys observed",
                "evidence_artifact": artifact,
                "business_impact": "Informational disclosure that can help target manual GraphQL authorization testing.",
                "remediation": "Return minimal production errors and log detailed resolver errors server-side.",
                "cwe": "CWE-209",
                "exploitability_status": "candidate",
                "evidence_strength": "weak",
                "false_positive_risk": "medium",
                "redaction_status": "redacted",
            }, scan_id=context.scan["id"]))

        unique_urls = []
        seen_endpoint_urls = set()
        for url in candidate_urls:
            key = _endpoint_key(url)
            if key in seen_endpoint_urls:
                continue
            seen_endpoint_urls.add(key)
            unique_urls.append(url)
        return findings, unique_urls

    async def _check_introspection(self, context: ScanContext, urls: list[str]) -> list[dict]:
        findings = []
        async with httpx.AsyncClient(
            verify=False,
            follow_redirects=False,
            timeout=context.options.timeout,
            headers={"User-Agent": "BurpOllama GraphQL Agent"},
        ) as client:
            for url in urls:
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
                    response = await client.post(url, json=INTROSPECTION_BODY)
                    context.tested_urls.add(url)
                except httpx.HTTPError as exc:
                    response_text = type(exc).__name__
                    status_code = "error"
                else:
                    response_text = response.text or ""
                    status_code = response.status_code
                if "__schema" not in response_text:
                    continue
                title = "GraphQL introspection enabled"
                raw_response = "HTTP/1.1 {}\n\n{}".format(status_code, response_text[:1024])
                artifact = write_evidence_artifact(
                    context.scan,
                    title=title,
                    url=url,
                    raw_request=_raw_request(url, "POST", INTROSPECTION_BODY),
                    raw_response=raw_response,
                    matched_indicator="__schema",
                    indicator_location="introspection response body",
                    agent=self.name,
                    vuln_class="GraphQL Introspection Enabled",
                    impact="Enabled introspection can disclose the schema, types, and fields available for attack-path mapping.",
                    fp_check="A single bounty-mode introspection POST returned __schema in the response.",
                    confirmed=True,
                    filename_prefix="graphql-introspection",
                    metadata={
                        "endpoint_url": url,
                        "request": INTROSPECTION_BODY,
                        "response_first_1kb": response_text[:1024],
                        "introspection_performed": True,
                    },
                )
                saved = _artifact_saved(artifact)
                findings.append(normalize_finding({
                    "source": "graphql-agent",
                    "vuln_type": "GraphQL Introspection Enabled",
                    "title": title,
                    "severity": "MEDIUM",
                    "confidence": 90 if saved else 60,
                    "url": url,
                    "method": "POST",
                    "description": "GraphQL schema introspection returned __schema.",
                    "evidence": "__schema present in introspection response",
                    "evidence_artifact": artifact,
                    "business_impact": "Attackers can map object types and fields before testing authorization flaws.",
                    "remediation": "Disable introspection in production unless explicitly required, or restrict it to authorized operators.",
                    "cwe": "CWE-200",
                    "exploitability_status": "confirmed" if saved else "candidate",
                    "evidence_strength": "strong" if saved else "weak",
                    "false_positive_risk": "low" if saved else "medium",
                    "redaction_status": "redacted",
                }, scan_id=context.scan["id"]))
        return findings
