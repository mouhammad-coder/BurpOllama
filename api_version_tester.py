"""API version and hidden-environment differential testing."""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse

import httpx

from finding_model import normalize_finding


TIMEOUT = httpx.Timeout(12.0)
VERSION_RE = re.compile(r"(?i)(/v(?P<vnum>\d+)(?=/)|/api/(?P<anum>\d+)(?=/))")
HIDDEN_API_PATHS = (
    "/api/internal/", "/api/private/", "/api/beta/",
    "/api/dev/", "/api/test/",
)
EXISTS_STATUSES = {200, 401, 403}


def _endpoint_url(item: Any) -> str:
    if isinstance(item, str):
        return item
    if isinstance(item, dict):
        return str(item.get("url") or item.get("affected_url") or "")
    return ""


def _json_fields(value: Any, prefix: str = "") -> set[str]:
    fields: set[str] = set()
    if isinstance(value, dict):
        for key, nested in value.items():
            path = "{}.{}".format(prefix, key) if prefix else str(key)
            fields.add(path)
            fields.update(_json_fields(nested, path))
    elif isinstance(value, list) and value:
        fields.update(_json_fields(value[0], "{}[]".format(prefix)))
    return fields


def _response_data(response: httpx.Response | None) -> dict:
    if response is None:
        return {}
    try:
        payload = response.json()
        fields = sorted(_json_fields(payload))
    except ValueError:
        fields = []
    return {
        "status_code": response.status_code,
        "content_type": response.headers.get("content-type", "").split(";", 1)[0],
        "response_size": len(response.content or b""),
        "json_fields": fields,
        "response_excerpt": (response.text or "")[:800],
        "retry_after": response.headers.get("retry-after", ""),
    }


async def _get(client: httpx.AsyncClient, policy, url: str) -> httpx.Response | None:
    allowed, _reason = policy.record_request(url, action="active")
    if not allowed:
        return None
    try:
        return await client.get(
            url,
            follow_redirects=False,
            timeout=TIMEOUT,
        )
    except httpx.HTTPError:
        return None


def _version_candidates(url: str) -> list[str]:
    parsed = urlparse(url)
    match = VERSION_RE.search(parsed.path)
    if not match:
        return []
    version = int(match.group("vnum") or match.group("anum"))
    matched = match.group(0)
    suffix = parsed.path[match.end():]
    prefix = "/v" if match.group("vnum") is not None else "/api/"
    candidates = []

    for old_version in range(version - 1, -1, -1):
        replacement = (
            "{}{}".format(prefix, old_version)
            if prefix == "/v"
            else "/api/{}".format(old_version)
        )
        old_path = parsed.path[:match.start()] + replacement + suffix
        candidates.append(urlunparse(parsed._replace(path=old_path)))

    unversioned_suffix = suffix if suffix.startswith("/") else "/" + suffix
    root_prefix = parsed.path[:match.start()]
    candidates.append(urlunparse(parsed._replace(
        path=(root_prefix.rstrip("/") + unversioned_suffix) or "/"
    )))
    candidates.append(urlunparse(parsed._replace(
        path=(root_prefix.rstrip("/") + "/api" + unversioned_suffix)
    )))
    return list(dict.fromkeys(candidate for candidate in candidates if candidate != url))


def _finding(
    finding_type: str,
    current_url: str,
    old_url: str,
    current_data: dict,
    old_data: dict,
    *,
    severity: str,
    confidence: int,
    exploitability: str,
    cwe: str,
    description: str,
    extra: dict | None = None,
) -> dict:
    evidence = {
        "current_version_url": current_url,
        "old_version_url": old_url,
        "current_response": current_data,
        "old_response": old_data,
        "status_code_comparison": {
            "current": current_data.get("status_code"),
            "old": old_data.get("status_code"),
        },
        "data_field_comparison": {
            "current_fields": current_data.get("json_fields", []),
            "old_fields": old_data.get("json_fields", []),
            "additional_old_fields": sorted(
                set(old_data.get("json_fields", []))
                - set(current_data.get("json_fields", []))
            ),
        },
    }
    finding = {
        "source": "api-version-tester",
        "title": finding_type.replace("_", " ").title(),
        "vuln_type": finding_type,
        "vulnerability_class": finding_type,
        "severity": severity,
        "confidence": confidence,
        "url": old_url,
        "affected_url": old_url,
        "method": "GET",
        "description": description,
        "evidence": json.dumps(evidence, ensure_ascii=False),
        "current_version_url": current_url,
        "old_version_url": old_url,
        "status_code_comparison": evidence["status_code_comparison"],
        "data_field_comparison": evidence["data_field_comparison"],
        "exploitability_status": exploitability,
        "evidence_strength": "strong" if exploitability == "confirmed" else "moderate",
        "false_positive_risk": "low" if exploitability == "confirmed" else "medium",
        "business_impact": (
            "An older or hidden API route may bypass current authorization, data-minimization, "
            "or abuse-prevention controls."
        ),
        "technical_impact": description,
        "remediation": (
            "Retire unsupported API versions, enforce identical authentication and authorization "
            "middleware across versions, minimize response fields, and apply shared rate limits."
        ),
        "cwe": cwe,
        "reproduction_steps": [
            "Request the current endpoint and record its status and JSON field set.",
            "Request the old or hidden endpoint shown in old_version_url using the same session.",
            "Compare authorization, returned fields, and rate-limit behavior.",
        ],
        "safe_manual_validation_steps": [
            "Use only approved test accounts and read-only requests.",
            "Do not enumerate real users or exceed configured request limits.",
            "Confirm the difference persists before reporting.",
        ],
        "redaction_status": "redacted",
    }
    if extra:
        finding.update(extra)
    return normalize_finding(finding)


async def _rate_limit_difference(
    client: httpx.AsyncClient,
    policy,
    current_url: str,
    old_url: str,
    current_initial: httpx.Response,
    old_initial: httpx.Response,
) -> tuple[bool, list[int], list[int]]:
    current_statuses = [current_initial.status_code]
    old_statuses = [old_initial.status_code]
    if (
        current_initial.status_code == 429
        or current_initial.headers.get("retry-after")
    ):
        return (
            old_initial.status_code != 429,
            current_statuses,
            old_statuses,
        )
    sensitive_path = urlparse(current_url).path.lower()
    if not any(hint in sensitive_path for hint in (
        "login", "auth", "otp", "verify", "reset", "forgot",
        "search", "payment", "checkout", "register", "signup",
    )):
        return False, current_statuses, old_statuses
    # Bounded paired sampling. Only a relative difference is reported.
    for _ in range(5):
        current = await _get(client, policy, current_url)
        old = await _get(client, policy, old_url)
        if current is None or old is None:
            break
        current_statuses.append(current.status_code)
        old_statuses.append(old.status_code)
        if 429 in current_statuses and all(status != 429 for status in old_statuses):
            return True, current_statuses, old_statuses
    return (
        429 in current_statuses and all(status != 429 for status in old_statuses),
        current_statuses,
        old_statuses,
    )


async def test_api_versions(
    base_url: str,
    discovered_endpoints: list,
    client: httpx.AsyncClient,
    scope_policy,
) -> list[dict]:
    """Compare current, older, unversioned, and hidden API routes."""
    policy = scope_policy
    if (
        not policy.config.active_testing_enabled
        or policy.config.passive_only_mode
    ):
        return []

    base_parsed = urlparse(base_url)
    base_origin = "{}://{}".format(base_parsed.scheme, base_parsed.netloc)
    endpoints = list(dict.fromkeys(
        _endpoint_url(item)
        for item in (discovered_endpoints or [])
        if _endpoint_url(item)
        and urlparse(_endpoint_url(item)).netloc == base_parsed.netloc
        and VERSION_RE.search(urlparse(_endpoint_url(item)).path)
    ))
    findings = []
    seen_pairs = set()

    for current_url in endpoints[:40]:
        current = await _get(client, policy, current_url)
        if current is None:
            continue
        current_data = _response_data(current)
        for old_url in _version_candidates(current_url)[:8]:
            pair = (current_url, old_url)
            if pair in seen_pairs or not policy.validate_target(old_url, action="active")[0]:
                continue
            seen_pairs.add(pair)
            old = await _get(client, policy, old_url)
            if old is None or old.status_code not in EXISTS_STATUSES:
                continue
            old_data = _response_data(old)

            if current.status_code in {401, 403} and old.status_code == 200:
                findings.append(_finding(
                    "version_auth_bypass",
                    current_url,
                    old_url,
                    current_data,
                    old_data,
                    severity="HIGH",
                    confidence=96,
                    exploitability="confirmed",
                    cwe="CWE-285",
                    description="The older/unversioned API returned HTTP 200 while the current endpoint required authentication.",
                ))
                continue

            additional_fields = (
                set(old_data.get("json_fields", []))
                - set(current_data.get("json_fields", []))
            )
            if old.status_code == 200 and additional_fields:
                findings.append(_finding(
                    "version_data_exposure",
                    current_url,
                    old_url,
                    current_data,
                    old_data,
                    severity="HIGH",
                    confidence=84,
                    exploitability="probable",
                    cwe="CWE-200",
                    description="The older/unversioned API returned additional JSON fields not present in the current version.",
                    extra={"additional_exposed_fields": sorted(additional_fields)},
                ))

            rate_bypass, current_statuses, old_statuses = await _rate_limit_difference(
                client, policy, current_url, old_url, current, old
            )
            if rate_bypass:
                findings.append(_finding(
                    "version_rate_limit_bypass",
                    current_url,
                    old_url,
                    current_data,
                    old_data,
                    severity="HIGH",
                    confidence=82,
                    exploitability="probable",
                    cwe="CWE-770",
                    description="The current API version returned HTTP 429 while the older route remained unthrottled under the same bounded request sequence.",
                    extra={
                        "current_rate_statuses": current_statuses,
                        "old_rate_statuses": old_statuses,
                    },
                ))

    # Hidden environment-style API roots.
    current_api_url = urljoin(base_origin + "/", "api/")
    current_api_response = await _get(client, policy, current_api_url)
    current_api_data = _response_data(current_api_response)
    for hidden_path in HIDDEN_API_PATHS:
        hidden_url = urljoin(base_origin + "/", hidden_path.lstrip("/"))
        if not policy.validate_target(hidden_url, action="active")[0]:
            continue
        response = await _get(client, policy, hidden_url)
        if response is None or response.status_code not in EXISTS_STATUSES:
            continue
        data = _response_data(response)
        if response.status_code == 200:
            protected_current = bool(
                current_api_response
                and current_api_response.status_code in {401, 403}
            )
            findings.append(_finding(
                "version_auth_bypass",
                current_api_url,
                hidden_url,
                current_api_data,
                data,
                severity="HIGH",
                confidence=94 if protected_current else 75,
                exploitability=(
                    "confirmed" if protected_current
                    else "needs_manual_validation"
                ),
                cwe="CWE-285",
                description=(
                    "A hidden internal/private/beta/dev/test API path returned HTTP 200 "
                    "while the main API root required authentication."
                    if protected_current else
                    "A hidden internal/private/beta/dev/test API path is publicly reachable "
                    "and requires manual authorization review."
                ),
                extra={"hidden_api_path": hidden_path},
            ))

    deduped = []
    seen = set()
    for finding in findings:
        key = (
            finding.get("vuln_type"),
            finding.get("current_version_url"),
            finding.get("old_version_url"),
        )
        if key not in seen:
            seen.add(key)
            deduped.append(finding)
    return deduped
