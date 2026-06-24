"""Passive access-control candidate identification."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

from finding_model import normalize_finding

from core.agents.base import BaseAgent, ScanContext
from core.evidence import write_evidence_artifact
from core.events import EventType


UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$",
    re.I,
)
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{5,}$", re.I)
STATE_CHANGING = {"PUT", "DELETE", "PATCH"}


def _artifact_saved(artifact: dict) -> bool:
    return bool(artifact.get("artifact_path")) and Path(
        str(artifact.get("artifact_path"))
    ).exists()


def _raw_request(url: str, method: str = "PASSIVE") -> str:
    return "{} {} HTTP/1.1".format(method.upper(), url)


def _endpoint_key(url: str) -> str:
    parsed = urlparse(url)
    return "{}://{}{}".format(
        (parsed.scheme or "https").lower(),
        (parsed.netloc or "").lower(),
        parsed.path or "/",
    )


def _headers_have_auth(headers: dict | list | None) -> bool:
    if not headers:
        return False
    items = headers.items() if isinstance(headers, dict) else headers
    for key, value in items:
        lowered = str(key).lower()
        if lowered in {"authorization", "cookie"} and str(value or "").strip():
            return True
    return False


def _redacted_headers(headers: dict | list | None) -> dict:
    if not headers:
        return {}
    items = headers.items() if isinstance(headers, dict) else headers
    out = {}
    for key, value in items:
        name = str(key)
        out[name] = "<redacted>" if name.lower() in {"authorization", "cookie"} else str(value)
    return out


def _raw_observation(observation: dict) -> str:
    url = str(observation.get("url") or "")
    method = str(observation.get("method") or "GET").upper()
    headers = _redacted_headers(observation.get("headers"))
    header_lines = "\n".join("{}: {}".format(key, value) for key, value in headers.items())
    return "{} {} HTTP/1.1\n{}".format(method, url, header_lines)


def _classify_id(value: str) -> str:
    text = str(value or "").strip()
    if text.isdigit():
        return "numeric"
    if UUID_RE.match(text):
        return "uuid"
    if SLUG_RE.match(text) and any(ch.isdigit() for ch in text):
        return "slug"
    return ""


def _id_candidates(url: str) -> list[dict]:
    parsed = urlparse(url)
    found = []
    segments = [segment for segment in (parsed.path or "").split("/") if segment]
    for index, segment in enumerate(segments):
        id_type = _classify_id(segment)
        if not id_type:
            continue
        pattern_segments = list(segments)
        pattern_segments[index] = "{id}"
        found.append({
            "parameter": "path_segment_{}".format(index + 1),
            "value": segment,
            "id_type": id_type,
            "url_pattern": "/" + "/".join(pattern_segments),
        })
    for name, value in parse_qsl(parsed.query, keep_blank_values=True):
        id_type = _classify_id(value)
        if not id_type:
            continue
        found.append({
            "parameter": name,
            "value": value,
            "id_type": id_type,
            "url_pattern": "{}?{}={{id}}".format(parsed.path or "/", name),
        })
    return found


def _observations(context: ScanContext) -> list[dict]:
    observed = []
    for key in ("http_observations", "observed_responses", "response_observations", "requests"):
        value = context.recon.get(key, [])
        if isinstance(value, list):
            observed.extend(item for item in value if isinstance(item, dict))
    return observed


def _method_hints(context: ScanContext) -> dict[str, set[str]]:
    hints: dict[str, set[str]] = {}

    def add(url: str, method: str):
        if not url or not method:
            return
        hints.setdefault(_endpoint_key(url), set()).add(str(method).upper())

    for item in context.recon.get("method_observations", []) or []:
        if isinstance(item, dict):
            add(str(item.get("url") or ""), str(item.get("method") or ""))
    for item in context.recon.get("api_endpoints", []) or []:
        if isinstance(item, dict):
            add(str(item.get("url") or item.get("path") or ""), str(item.get("method") or ""))
    js_methods = context.recon.get("js_methods", {}) or {}
    if isinstance(js_methods, dict):
        for url, methods in js_methods.items():
            for method in methods if isinstance(methods, list) else [methods]:
                add(str(url), str(method))
    for content in (context.recon.get("js_contents", {}) or {}).values():
        if not isinstance(content, str):
            continue
        for method, url in re.findall(
            r"(?is)(?:method\s*:\s*['\"](PUT|DELETE|PATCH)['\"].{0,160}?(https?://[^'\"\s)]+|/[A-Za-z0-9_./{}:-]+))",
            content,
        ):
            add(url, method)
    return hints


class AccessControlAgent(BaseAgent):
    name = "access-control"
    phase = "vulnerability_hunt"

    async def run(self, context: ScanContext):
        findings = []
        findings.extend(self._object_id_findings(context))
        findings.extend(self._auth_gap_findings(context))
        findings.extend(self._method_findings(context))
        context.raw_findings.extend(findings)
        context.scan["raw_findings"] = context.raw_findings
        for finding in findings:
            context.scheduler.state(self.name).findings += 1
            await context.emit(
                EventType.FINDING_CANDIDATE,
                agent=self.name,
                phase=self.phase,
                message=finding.get("title", "Access-control observation"),
                finding=finding,
            )
        return findings

    def _object_id_findings(self, context: ScanContext) -> list[dict]:
        findings = []
        seen = set()
        for url in context.recon.get("urls", []):
            if not context.scope.allows(url):
                continue
            for candidate in _id_candidates(str(url)):
                key = (candidate["url_pattern"], candidate["parameter"], candidate["id_type"])
                if key in seen:
                    continue
                seen.add(key)
                title = "{} object identifier observed".format(candidate["id_type"].title())
                artifact = write_evidence_artifact(
                    context.scan,
                    title=title,
                    url=str(url),
                    raw_request=_raw_request(str(url)),
                    raw_response="PASSIVE URL OBSERVATION\n{}".format(str(url)),
                    matched_indicator=candidate["value"],
                    indicator_location=candidate["parameter"],
                    agent=self.name,
                    vuln_class="IDOR Candidate",
                    impact="Object identifiers can indicate an authorization boundary that needs manual Session A/B validation.",
                    fp_check="Identifier pattern observed only; no alternate object access was attempted.",
                    confirmed=False,
                    filename_prefix="access-object-id",
                    metadata=candidate,
                )
                findings.append(normalize_finding({
                    "source": "passive-access-control-agent",
                    "vuln_type": "IDOR Candidate",
                    "title": title,
                    "severity": "MEDIUM",
                    "confidence": 55 if _artifact_saved(artifact) else 35,
                    "url": str(url),
                    "method": "PASSIVE",
                    "parameter": candidate["parameter"],
                    "description": "A {} object identifier appears in an observed URL.".format(candidate["id_type"]),
                    "evidence": "{} identifier in {}".format(candidate["id_type"], candidate["url_pattern"]),
                    "evidence_artifact": artifact,
                    "business_impact": "Unconfirmed; cross-user access could expose another user's data.",
                    "remediation": "Enforce object-level authorization on every request.",
                    "exploitability_status": "needs_manual_validation",
                    "evidence_strength": "weak",
                    "false_positive_risk": "high",
                    "redaction_status": "redacted",
                    "safe_manual_validation_steps": [
                        "Configure Session A and Session B.",
                        "Request only objects owned by the test accounts.",
                        "Do not enumerate or access real user objects.",
                    ],
                }, scan_id=context.scan["id"]))
        return findings

    def _auth_gap_findings(self, context: ScanContext) -> list[dict]:
        findings = []
        by_endpoint: dict[str, dict[str, list[dict]]] = {}
        for observation in _observations(context):
            url = str(observation.get("url") or "")
            if not url or not context.scope.allows(url):
                continue
            bucket = "authenticated" if _headers_have_auth(observation.get("headers")) else "unauthenticated"
            by_endpoint.setdefault(_endpoint_key(url), {"authenticated": [], "unauthenticated": []})[bucket].append(observation)
        for endpoint, buckets in by_endpoint.items():
            if not buckets["authenticated"] or not buckets["unauthenticated"]:
                continue
            authed = buckets["authenticated"][0]
            unauthed = buckets["unauthenticated"][0]
            title = "Endpoint observed with and without auth headers"
            artifact = write_evidence_artifact(
                context.scan,
                title=title,
                url=str(unauthed.get("url") or endpoint),
                raw_request=_raw_observation(unauthed),
                raw_response="PASSIVE COMPARISON\nAuthenticated form:\n{}\n\nUnauthenticated form:\n{}".format(
                    _raw_observation(authed),
                    _raw_observation(unauthed),
                ),
                matched_indicator=endpoint,
                indicator_location="observed request headers",
                agent=self.name,
                vuln_class="Access Control Auth Coverage Gap",
                impact="The same endpoint appeared in authenticated and unauthenticated request forms and needs manual authorization validation.",
                fp_check="Both request forms were observed passively; no alternate-user data was accessed.",
                confirmed=True,
                filename_prefix="access-auth-gap",
                metadata={
                    "endpoint": endpoint,
                    "authenticated_headers": _redacted_headers(authed.get("headers")),
                    "unauthenticated_headers": _redacted_headers(unauthed.get("headers")),
                    "active_probe_performed": False,
                },
            )
            saved = _artifact_saved(artifact)
            findings.append(normalize_finding({
                "source": "passive-access-control-agent",
                "vuln_type": "Access Control Auth Coverage Gap",
                "title": title,
                "severity": "MEDIUM",
                "confidence": 78 if saved else 45,
                "url": str(unauthed.get("url") or endpoint),
                "method": "PASSIVE",
                "description": "An endpoint was observed in both authenticated and unauthenticated request forms.",
                "evidence": "Auth and no-auth forms observed for {}".format(endpoint),
                "evidence_artifact": artifact,
                "business_impact": "Potential missing auth check; human validation is required before reporting.",
                "remediation": "Require authentication and object-level authorization for protected endpoints.",
                "exploitability_status": "confirmed" if saved else "needs_manual_validation",
                "evidence_strength": "moderate" if saved else "weak",
                "false_positive_risk": "medium" if saved else "high",
                "redaction_status": "redacted",
            }, scan_id=context.scan["id"]))
        return findings

    def _method_findings(self, context: ScanContext) -> list[dict]:
        findings = []
        hints = _method_hints(context)
        seen = set()
        for observation in _observations(context):
            url = str(observation.get("url") or "")
            if not url or not context.scope.allows(url):
                continue
            method = str(observation.get("method") or "GET").upper()
            endpoint = _endpoint_key(url)
            state_methods = sorted(hints.get(endpoint, set()) & STATE_CHANGING)
            if method != "GET" or not state_methods or endpoint in seen:
                continue
            seen.add(endpoint)
            title = "State-changing methods observed for GET endpoint"
            artifact = write_evidence_artifact(
                context.scan,
                title=title,
                url=url,
                raw_request=_raw_observation(observation),
                raw_response="PASSIVE METHOD OBSERVATION\nGET observed for endpoint; JS/API hints list methods: {}".format(
                    ", ".join(state_methods)
                ),
                matched_indicator=", ".join(state_methods),
                indicator_location="JavaScript or API documentation",
                agent=self.name,
                vuln_class="Access Control Method Observation",
                impact="State-changing methods require independent authorization checks for the same resource path.",
                fp_check="Methods were observed in passive sources only; no PUT/DELETE/PATCH request was sent.",
                confirmed=False,
                filename_prefix="access-method",
                metadata={
                    "endpoint": endpoint,
                    "observed_get": True,
                    "state_changing_methods": state_methods,
                    "active_probe_performed": False,
                },
            )
            findings.append(normalize_finding({
                "source": "passive-access-control-agent",
                "vuln_type": "Access Control Method Observation",
                "title": title,
                "severity": "INFO",
                "confidence": 50 if _artifact_saved(artifact) else 30,
                "url": url,
                "method": "PASSIVE",
                "description": "Endpoint may accept state-changing methods; verify authorization on each method.",
                "evidence": "Observed methods: {}".format(", ".join(state_methods)),
                "evidence_artifact": artifact,
                "business_impact": "Informational authorization review item.",
                "remediation": "Apply consistent authorization checks to GET, PUT, DELETE, PATCH, and related handlers.",
                "exploitability_status": "candidate",
                "evidence_strength": "weak",
                "false_positive_risk": "medium",
                "redaction_status": "redacted",
            }, scan_id=context.scan["id"]))
        return findings
