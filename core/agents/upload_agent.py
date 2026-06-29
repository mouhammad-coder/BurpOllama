"""Passive file-upload endpoint observation."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import parse_qsl, urlparse

from finding_model import normalize_finding

from core.agents.base import BaseAgent, ScanContext
from core.evidence import write_evidence_artifact
from core.events import EventType


UPLOAD_PARAMETER_NAMES = {
    "file",
    "upload",
    "attachment",
    "document",
    "image",
    "photo",
    "avatar",
    "import",
    "csv",
    "pdf",
}
FILE_PATH_RE = re.compile(
    r"(?i)(?:/uploads?/|/files?/|/media/|/assets/|/tmp/|[A-Z]:\\|\\\\)[^\s\"'<>]{3,}"
)
SERVER_PATH_RE = re.compile(
    r"(?i)(?:/var/www|/home/[A-Za-z0-9_.-]+|/tmp/|/app/|/srv/|C:\\(?:inetpub|wwwroot|Users)\\)[^\s\"'<>]{0,160}"
)
ERROR_HINTS = ("error", "exception", "traceback", "stack trace", "failed", "cannot", "denied")


def _artifact_saved(artifact: dict) -> bool:
    return bool(artifact.get("artifact_path")) and Path(
        str(artifact.get("artifact_path"))
    ).exists()


def _parameter_key(name: str) -> str:
    return str(name or "").replace("_", "").replace("-", "").lower()


def _raw_request(url: str, method: str = "PASSIVE") -> str:
    return "{} {} HTTP/1.1".format(method.upper(), url)


def _body_text(observation: dict) -> str:
    for key in ("body", "response_body", "text"):
        value = observation.get(key)
        if value is not None:
            return str(value)
    return ""


def _headers(observation: dict) -> dict[str, str]:
    headers = {}
    for key in ("headers", "request_headers"):
        value = observation.get(key) or {}
        items = value.items() if isinstance(value, dict) else value
        for name, header_value in items:
            headers[str(name).lower()] = str(header_value)
    return headers


def _content_type(observation: dict) -> str:
    for key in ("content_type", "request_content_type"):
        if observation.get(key):
            return str(observation.get(key))
    return _headers(observation).get("content-type", "")


def _raw_observation_response(observation: dict, body_limit: int = 512) -> str:
    status = observation.get("status_code") or observation.get("status") or ""
    headers = observation.get("headers") or {}
    if isinstance(headers, dict):
        header_lines = "\n".join("{}: {}".format(key, value) for key, value in headers.items())
    else:
        header_lines = "\n".join("{}: {}".format(key, value) for key, value in headers)
    return "HTTP/1.1 {}\n{}\n\n{}".format(
        status,
        header_lines,
        _body_text(observation)[:body_limit],
    )


def _endpoint_key(url: str) -> str:
    parsed = urlparse(str(url or ""))
    return "{}://{}{}".format(
        (parsed.scheme or "https").lower(),
        (parsed.netloc or "").lower(),
        parsed.path or "/",
    )


def _scope_allows(context: ScanContext, url: str) -> bool:
    return bool(url) and context.scope.allows(url)


def _observations(context: ScanContext) -> list[dict]:
    observed = []
    for key in ("http_observations", "observed_responses", "response_observations", "requests"):
        value = context.recon.get(key, [])
        if isinstance(value, list):
            observed.extend(item for item in value if isinstance(item, dict))
    return observed


def _input_items(form: dict) -> list[dict]:
    items = []
    for key in ("inputs", "fields", "parameters"):
        value = form.get(key) or []
        if isinstance(value, dict):
            value = [{"name": name, **(meta if isinstance(meta, dict) else {})} for name, meta in value.items()]
        for item in value:
            if isinstance(item, dict):
                items.append(item)
            else:
                items.append({"name": str(item)})
    return items


def _accepted_types_from_form(form: dict, parameter: str = "") -> list[str]:
    accepted = []
    for key in ("accept", "accepted_types", "accepts"):
        value = form.get(key)
        if value:
            accepted.extend(_split_types(value))
    for item in _input_items(form):
        if parameter and str(item.get("name") or "") != parameter:
            continue
        for key in ("accept", "accepted_types", "accepts"):
            value = item.get(key)
            if value:
                accepted.extend(_split_types(value))
    return sorted(set(accepted))


def _split_types(value) -> list[str]:
    if isinstance(value, (list, tuple, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    return [item.strip() for item in str(value).split(",") if item.strip()]


def _candidate_from_form(form: dict) -> list[dict]:
    url = str(form.get("action") or form.get("url") or "")
    enctype = str(form.get("enctype") or form.get("encoding") or "").lower()
    inputs = _input_items(form)
    candidates = []
    if "multipart/form-data" in enctype:
        file_inputs = [
            item for item in inputs
            if str(item.get("type") or "").lower() == "file"
            or _parameter_key(str(item.get("name") or "")) in UPLOAD_PARAMETER_NAMES
        ]
        parameter = str((file_inputs[0] if file_inputs else {}).get("name") or "")
        candidates.append({
            "url": url,
            "detection_method": "multipart form enctype",
            "parameter": parameter,
            "accepted_types": _accepted_types_from_form(form, parameter),
            "raw_response": "PASSIVE FORM OBSERVATION\n{}".format(form),
        })
    for item in inputs:
        parameter = str(item.get("name") or "")
        is_file_input = str(item.get("type") or "").lower() == "file"
        is_upload_param = _parameter_key(parameter) in UPLOAD_PARAMETER_NAMES
        if not is_file_input and not is_upload_param:
            continue
        candidates.append({
            "url": url,
            "detection_method": "file input" if is_file_input else "upload parameter name",
            "parameter": parameter,
            "accepted_types": _accepted_types_from_form(form, parameter),
            "raw_response": "PASSIVE FORM OBSERVATION\n{}".format(form),
        })
    return candidates


def _candidate_from_url(url: str, source: str) -> list[dict]:
    candidates = []
    parsed = urlparse(str(url or ""))
    for name, _value in parse_qsl(parsed.query, keep_blank_values=True):
        if _parameter_key(name) not in UPLOAD_PARAMETER_NAMES:
            continue
        candidates.append({
            "url": str(url),
            "detection_method": "{} upload parameter".format(source),
            "parameter": name,
            "accepted_types": [],
            "raw_response": "PASSIVE URL OBSERVATION\n{}".format(url),
        })
    return candidates


def _response_signals(url: str, parameter: str, observations: list[dict]) -> dict:
    endpoint = _endpoint_key(url)
    signals = {
        "file_path_observed": False,
        "reflected_filename": False,
        "response_snippet": "",
        "matched_file_path": "",
        "server_path": "",
    }
    parsed = urlparse(str(url or ""))
    parameter_values = {
        name: value for name, value in parse_qsl(parsed.query, keep_blank_values=True)
    }
    filename = Path(parameter_values.get(parameter, "")).name if parameter else ""
    for observation in observations:
        obs_url = str(observation.get("url") or "")
        if obs_url and _endpoint_key(obs_url) != endpoint:
            continue
        body = _body_text(observation)
        if not body:
            continue
        snippet = body[:512]
        file_path = FILE_PATH_RE.search(body)
        server_path = SERVER_PATH_RE.search(body)
        if file_path:
            signals["file_path_observed"] = True
            signals["matched_file_path"] = file_path.group(0)[:180]
            signals["response_snippet"] = snippet
        if filename and filename in body:
            signals["reflected_filename"] = True
            signals["response_snippet"] = snippet
        if server_path and any(hint in body.lower() for hint in ERROR_HINTS):
            signals["server_path"] = server_path.group(0)[:180]
            signals["response_snippet"] = snippet
    return signals


class UploadAgent(BaseAgent):
    name = "upload"
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
                message=finding.get("title", "Upload observation"),
                finding=finding,
            )
        return findings

    def _passive_findings(self, context: ScanContext) -> list[dict]:
        findings = []
        observations = _observations(context)
        seen_candidates = set()

        def add_candidate(candidate: dict):
            url = str(candidate.get("url") or "")
            if not _scope_allows(context, url):
                return
            parameter = str(candidate.get("parameter") or "")
            detection_method = str(candidate.get("detection_method") or "upload observation")
            key = (_endpoint_key(url), detection_method, parameter)
            if key in seen_candidates:
                return
            seen_candidates.add(key)
            signals = _response_signals(url, parameter, observations)
            confidence = 75 if signals["file_path_observed"] or signals["reflected_filename"] else 55
            title = "File upload endpoint candidate observed"
            metadata = {
                "detection_method": detection_method,
                "parameter_name": parameter,
                "accepted_types": candidate.get("accepted_types") or [],
                "active_upload_sent": False,
                "file_path_observed": signals["file_path_observed"],
                "reflected_filename": signals["reflected_filename"],
                "response_snippet_first_512": signals["response_snippet"],
            }
            artifact = write_evidence_artifact(
                context.scan,
                title=title,
                url=url,
                raw_request=_raw_request(url),
                raw_response=signals["response_snippet"] or str(candidate.get("raw_response") or ""),
                matched_indicator=parameter or detection_method,
                indicator_location=detection_method,
                agent=self.name,
                vuln_class="File Upload Endpoint Candidate",
                impact="Upload endpoints can become high-impact surfaces when file type, storage, parsing, or access controls are weak.",
                fp_check="Endpoint was observed passively; no file upload request was sent.",
                confirmed=False,
                filename_prefix="upload-candidate",
                metadata=metadata,
            )
            findings.append(normalize_finding({
                "source": "passive-upload-agent",
                "vuln_type": "File Upload Endpoint Candidate",
                "title": title,
                "severity": "MEDIUM",
                "confidence": confidence if _artifact_saved(artifact) else 35,
                "url": url,
                "method": "PASSIVE",
                "parameter": parameter,
                "description": "Observed a likely file upload endpoint through passive crawl/request metadata.",
                "evidence": "{} observed for parameter '{}'".format(detection_method, parameter or "unknown"),
                "evidence_artifact": artifact,
                "business_impact": "Unconfirmed upload surface; manual validation should check type restrictions, storage location, and authorization.",
                "remediation": "Restrict accepted file types, validate content server-side, store outside web root, and enforce authorization on upload/download paths.",
                "cwe": "CWE-434",
                "exploitability_status": "candidate",
                "evidence_strength": "weak",
                "false_positive_risk": "medium",
                "redaction_status": "redacted",
            }, scan_id=context.scan["id"]))
            if signals["server_path"]:
                findings.append(self._server_path_finding(context, url, parameter, signals))

        for form in context.recon.get("forms", []) or []:
            if isinstance(form, dict):
                for candidate in _candidate_from_form(form):
                    add_candidate(candidate)
        for url in context.recon.get("urls", []) or []:
            for candidate in _candidate_from_url(str(url), "url"):
                add_candidate(candidate)
        for item in context.recon.get("api_endpoints", []) or []:
            url = str(item.get("url") or item.get("endpoint") or item.get("path") or "") if isinstance(item, dict) else str(item)
            for candidate in _candidate_from_url(url, "api endpoint"):
                add_candidate(candidate)
        for observation in observations:
            url = str(observation.get("url") or "")
            for candidate in _candidate_from_url(url, "observed request"):
                add_candidate(candidate)
            if "multipart/form-data" in _content_type(observation).lower():
                add_candidate({
                    "url": url,
                    "detection_method": "multipart request content-type",
                    "parameter": str(observation.get("parameter") or ""),
                    "accepted_types": _split_types(observation.get("accepted_types") or []),
                    "raw_response": _raw_observation_response(observation),
                })
        return findings

    def _server_path_finding(
        self,
        context: ScanContext,
        url: str,
        parameter: str,
        signals: dict,
    ) -> dict:
        title = "Upload response disclosed server path"
        artifact = write_evidence_artifact(
            context.scan,
            title=title,
            url=url,
            raw_request=_raw_request(url),
            raw_response=signals["response_snippet"],
            matched_indicator=signals["server_path"],
            indicator_location="response body error",
            agent=self.name,
            vuln_class="Upload Server Path Disclosure",
            impact="Server filesystem paths in upload errors can reveal deployment layout and parser behavior.",
            fp_check="Observed passively in an error response; no upload request was sent.",
            confirmed=False,
            filename_prefix="upload-path",
            metadata={
                "parameter_name": parameter,
                "response_snippet_first_512": signals["response_snippet"],
                "active_upload_sent": False,
            },
        )
        return normalize_finding({
            "source": "passive-upload-agent",
            "vuln_type": "Upload Server Path Disclosure",
            "title": title,
            "severity": "INFO",
            "confidence": 70 if _artifact_saved(artifact) else 35,
            "url": url,
            "method": "PASSIVE",
            "parameter": parameter,
            "description": "Upload-related response disclosed a server filesystem path in an error.",
            "evidence": "Server path disclosed: {}".format(signals["server_path"]),
            "evidence_artifact": artifact,
            "business_impact": "Informational disclosure that can help guide manual upload parser and storage testing.",
            "remediation": "Return generic upload errors to clients and log filesystem details server-side.",
            "cwe": "CWE-209",
            "exploitability_status": "candidate",
            "evidence_strength": "weak",
            "false_positive_risk": "medium",
            "redaction_status": "redacted",
        }, scan_id=context.scan["id"])
